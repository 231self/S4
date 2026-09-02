use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_smithy_http_client::proxy::ProxyConfig;
use aws_smithy_http_client::tls::{self, rustls_provider::CryptoMode};
use aws_smithy_http_client::{Builder as SmithyHttpClientBuilder, ConnectorBuilder};
use aws_smithy_runtime_api::client::http::SharedHttpClient;
use axum::http::HeaderMap;
use reqwest::Url;

use crate::customer_headers;
use crate::s3_safety::{s3_retry_config, s3_timeout_config};
use crate::service_storage::ServiceStorage;
use crate::store::MemoryStore;
use crate::transaction::WorkspaceDestinationBinding;
use crate::workspace_storage::{
    BackendConfigVersionId, CapabilityAttestationId, RuntimeBackendConfig, WorkspaceId,
    WorkspaceOperationLease, WorkspaceStorageRepository, WorkspaceStorageRouting,
    WorkspaceStreamingBackendIdentity,
};

pub use crate::workspace_storage::S3ProviderFamily as WorkspaceS3Provider;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageOperation {
    Get,
    Head,
    Put,
    Delete,
    List,
    Multipart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    PresignedHttp,
    PerUserS3,
    Managed,
    GlobalS3,
    Memory,
}

impl WorkspaceS3Provider {
    fn classify(host: &str) -> Option<Self> {
        let labels = host.split('.').collect::<Vec<_>>();
        let aws_standard = matches!(labels.as_slice(), ["s3", "amazonaws", "com"])
            || matches!(labels.as_slice(), ["s3-external-1", "amazonaws", "com"])
            || matches!(labels.as_slice(), ["s3", region, "amazonaws", "com"] if aws_s3_region(region, false))
            || matches!(labels.as_slice(), ["s3", "dualstack", region, "amazonaws", "com"] if aws_s3_region(region, false))
            || matches!(labels.as_slice(), ["s3-fips", region, "amazonaws", "com"] if aws_s3_region(region, false))
            || matches!(labels.as_slice(), ["s3-fips", "dualstack", region, "amazonaws", "com"] if aws_s3_region(region, false))
            || matches!(labels.as_slice(), [legacy, "amazonaws", "com"] if legacy
                .strip_prefix("s3-")
                .is_some_and(|region| aws_s3_region(region, false)));
        let aws_china = matches!(labels.as_slice(), ["s3", region, "amazonaws", "com", "cn"] if aws_s3_region(region, true))
            || matches!(labels.as_slice(), ["s3", "dualstack", region, "amazonaws", "com", "cn"] if aws_s3_region(region, true))
            || matches!(labels.as_slice(), ["s3-fips", region, "amazonaws", "com", "cn"] if aws_s3_region(region, true))
            || matches!(labels.as_slice(), ["s3-fips", "dualstack", region, "amazonaws", "com", "cn"] if aws_s3_region(region, true));
        if aws_standard || aws_china {
            return Some(Self::Aws);
        }
        if host == "storage.googleapis.com" {
            return Some(Self::Gcs);
        }
        if matches!(labels.as_slice(), ["s3", region, "backblazeb2", "com"] if valid_b2_region(region)) {
            return Some(Self::B2);
        }
        if host.ends_with(".r2.cloudflarestorage.com") && labels.len() == 4 {
            return Some(Self::R2);
        }
        if host.ends_with(".digitaloceanspaces.com") && labels.len() == 3 {
            return Some(Self::DigitalOcean);
        }
        if (host == "s3.wasabisys.com" || (host.ends_with(".wasabisys.com") && labels.len() == 4))
            && labels.first().is_some_and(|label| *label == "s3")
        {
            return Some(Self::Wasabi);
        }
        None
    }
}

fn valid_b2_region(region: &str) -> bool {
    let mut labels = region.split('-');
    let (Some(country), Some(area), Some(cluster), None) =
        (labels.next(), labels.next(), labels.next(), labels.next())
    else {
        return false;
    };
    country.len() == 2
        && country.bytes().all(|byte| byte.is_ascii_lowercase())
        && !area.is_empty()
        && area.bytes().all(|byte| byte.is_ascii_lowercase())
        && cluster.len() == 3
        && cluster.bytes().all(|byte| byte.is_ascii_digit())
}

fn aws_s3_region(region: &str, china_partition: bool) -> bool {
    const STANDARD: &[&str] = &[
        "af-south-1",
        "ap-east-1",
        "ap-east-2",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ap-southeast-5",
        "ap-southeast-6",
        "ap-southeast-7",
        "ca-central-1",
        "ca-west-1",
        "eu-central-1",
        "eu-central-2",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "il-central-1",
        "me-central-1",
        "me-south-1",
        "mx-central-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-gov-east-1",
        "us-gov-west-1",
        "us-west-1",
        "us-west-2",
    ];
    const CHINA: &[&str] = &["cn-north-1", "cn-northwest-1"];
    if china_partition {
        CHINA.contains(&region)
    } else {
        STANDARD.contains(&region)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceS3Streaming {
    pub provider: WorkspaceS3Provider,
    pub identity: WorkspaceStreamingBackendIdentity,
    pub routing_epoch: u64,
}

#[derive(Clone)]
pub enum ResolvedBackend {
    PresignedHttp(Url),
    S3 {
        kind: BackendKind,
        client: Client,
        workspace_streaming: Option<WorkspaceS3Streaming>,
    },
    Managed(Arc<ServiceStorage>),
    Memory(Arc<MemoryStore>),
}

impl ResolvedBackend {
    pub fn kind(&self) -> BackendKind {
        match self {
            Self::PresignedHttp(_) => BackendKind::PresignedHttp,
            Self::S3 { kind, .. } => *kind,
            Self::Managed(_) => BackendKind::Managed,
            Self::Memory(_) => BackendKind::Memory,
        }
    }
}

/// Backend selection plus the workspace routing fence captured with it.
///
/// Presigned and explicit single-tenant overrides have no workspace routing
/// fence. Hosted managed commit paths must use this selection and require a
/// stable persisted fence before publishing authority.
#[derive(Clone)]
pub struct ResolvedBackendSelection {
    pub backend: ResolvedBackend,
    pub workspace_routing: Option<WorkspaceStorageRouting>,
}

fn workspace_s3_http_client() -> SharedHttpClient {
    SmithyHttpClientBuilder::new().build_with_connector_fn(|settings, runtime_components| {
        let mut connector =
            ConnectorBuilder::default().tls_provider(tls::Provider::Rustls(CryptoMode::AwsLc));
        connector.set_connector_settings(settings.cloned());
        if let Some(components) = runtime_components {
            connector.set_sleep_impl(components.sleep_impl());
        }
        connector.set_proxy_config(Some(ProxyConfig::disabled()));
        connector.build()
    })
}

#[derive(Clone)]
pub struct BackendResolver {
    workspace_storage: Arc<dyn WorkspaceStorageRepository>,
    managed: Arc<ServiceStorage>,
    global_s3: Option<Client>,
    memory: Arc<MemoryStore>,
    explicit_single_tenant: bool,
    workspace_endpoint_policy: WorkspaceEndpointPolicy,
}

impl BackendResolver {
    pub fn new(
        workspace_storage: Arc<dyn WorkspaceStorageRepository>,
        managed: Arc<ServiceStorage>,
        global_s3: Option<Client>,
        memory: Arc<MemoryStore>,
        explicit_single_tenant: bool,
        workspace_endpoint_policy: WorkspaceEndpointPolicy,
    ) -> Self {
        Self {
            workspace_storage,
            managed,
            global_s3,
            memory,
            explicit_single_tenant,
            workspace_endpoint_policy,
        }
    }

    pub async fn resolve(
        &self,
        workspace_id: &WorkspaceId,
        headers: &HeaderMap,
        operation: StorageOperation,
    ) -> Result<ResolvedBackend, String> {
        Ok(self
            .resolve_with_routing(workspace_id, headers, operation)
            .await?
            .backend)
    }

    pub async fn resolve_with_routing(
        &self,
        workspace_id: &WorkspaceId,
        headers: &HeaderMap,
        _operation: StorageOperation,
    ) -> Result<ResolvedBackendSelection, String> {
        let managed_requested = customer_headers::aliased(headers, customer_headers::STORAGE_MODE)
            .map_err(|_| "conflicting storage mode headers".to_string())?
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("managed"));

        // The request-level shortcut is a single-tenant development feature.
        // Hosted routing must consult persisted workspace state first so a BYO
        // workspace cannot be redirected into S4-managed storage by a header.
        if self.explicit_single_tenant && managed_requested {
            if self.managed.is_empty() {
                return Err("managed storage is not configured (no S4_SERVICE_BUCKETS)".to_string());
            }
            return Ok(ResolvedBackendSelection {
                backend: ResolvedBackend::Managed(self.managed.clone()),
                workspace_routing: None,
            });
        }

        if let Some(raw_url) = customer_headers::aliased(headers, customer_headers::BACKEND_URL)
            .map_err(|_| "conflicting backend URL headers".to_string())?
            .and_then(|value| value.to_str().ok())
        {
            let url =
                Url::parse(raw_url).map_err(|_| "invalid presigned backend URL".to_string())?;
            return Ok(ResolvedBackendSelection {
                backend: ResolvedBackend::PresignedHttp(url),
                workspace_routing: None,
            });
        }

        let resolution = self
            .workspace_storage
            .get_runtime_resolution(workspace_id)
            .await
            .map_err(|_| "workspace storage is unavailable".to_string())?;
        if resolution.routing.is_transitioning() {
            return Err("workspace storage is transitioning".to_string());
        }
        let workspace_routing = Some(resolution.routing);

        match resolution.config {
            Some(RuntimeBackendConfig::Managed) => {
                if self.managed.is_empty() {
                    return Err(
                        "workspace requires managed storage, but S4_SERVICE_BUCKETS is not configured"
                            .to_string(),
                    );
                }
                return Ok(ResolvedBackendSelection {
                    backend: ResolvedBackend::Managed(self.managed.clone()),
                    workspace_routing,
                });
            }
            Some(RuntimeBackendConfig::S3Compatible {
                endpoint,
                access_key,
                secret_key,
                region,
            }) => {
                let endpoint = self
                    .workspace_endpoint_policy
                    .validate(&endpoint)
                    .await
                    .map_err(|_| "workspace storage is unavailable".to_string())?;
                let workspace_streaming = workspace_streaming_binding(
                    &endpoint,
                    resolution.streaming.as_ref(),
                    resolution.routing,
                );
                let credentials =
                    Credentials::new(access_key, secret_key, None, None, "s4-backend");
                // Tenant-selected destinations must never inherit process proxy
                // settings. DNS is intentionally resolved again by the SDK: in
                // multi-tenant mode the hostname belongs to an operator-trusted
                // provider, so a tenant cannot control it after this validation.
                let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(Region::new(region))
                    .endpoint_url(endpoint.as_str())
                    .credentials_provider(credentials)
                    .retry_config(s3_retry_config())
                    .timeout_config(s3_timeout_config())
                    .http_client(workspace_s3_http_client())
                    .load()
                    .await;
                let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
                    .force_path_style(true)
                    .build();
                return Ok(ResolvedBackendSelection {
                    backend: ResolvedBackend::S3 {
                        kind: BackendKind::PerUserS3,
                        client: Client::from_conf(s3_config),
                        workspace_streaming,
                    },
                    workspace_routing,
                });
            }
            None => {}
        }

        if !self.managed.is_empty() {
            return Ok(ResolvedBackendSelection {
                backend: ResolvedBackend::Managed(self.managed.clone()),
                workspace_routing,
            });
        }
        if !self.explicit_single_tenant {
            return Err("workspace storage is unavailable".to_string());
        }
        if let Some(client) = &self.global_s3 {
            return Ok(ResolvedBackendSelection {
                backend: ResolvedBackend::S3 {
                    kind: BackendKind::GlobalS3,
                    client: client.clone(),
                    workspace_streaming: None,
                },
                workspace_routing,
            });
        }
        Ok(ResolvedBackendSelection {
            backend: ResolvedBackend::Memory(self.memory.clone()),
            workspace_routing,
        })
    }

    /// Reconstructs the exact historical BYO client referenced by a durable
    /// operation. Current workspace config is deliberately not consulted.
    pub async fn resolve_historical_workspace_s3(
        &self,
        workspace_id: &WorkspaceId,
        binding: &WorkspaceDestinationBinding,
    ) -> Result<ResolvedBackend, String> {
        let config_version = BackendConfigVersionId::new(binding.backend_config_version.clone())
            .map_err(|_| "workspace storage recovery identity is invalid".to_string())?;
        let attestation_id =
            CapabilityAttestationId::new(binding.capability_attestation_id.clone())
                .map_err(|_| "workspace storage recovery identity is invalid".to_string())?;
        let resolution = self
            .workspace_storage
            .get_runtime_resolution_by_version(workspace_id, &config_version)
            .await
            .map_err(|_| "historical workspace storage is unavailable".to_string())?;
        let identity = resolution
            .streaming
            .as_ref()
            .ok_or_else(|| "historical workspace storage is unattested".to_string())?;
        if identity.config_version != config_version
            || identity.attestation.id != attestation_id
            || resolution.routing.stable_epoch() != Some(binding.routing_epoch)
        {
            return Err("historical workspace storage identity changed".to_string());
        }
        let RuntimeBackendConfig::S3Compatible {
            endpoint,
            access_key,
            secret_key,
            region,
        } = resolution
            .config
            .ok_or_else(|| "historical workspace storage config is missing".to_string())?
        else {
            return Err("historical workspace storage kind changed".to_string());
        };
        let endpoint = self
            .workspace_endpoint_policy
            .validate(&endpoint)
            .await
            .map_err(|_| "historical workspace storage endpoint is unavailable".to_string())?;
        let workspace_streaming =
            workspace_streaming_binding(&endpoint, Some(identity), resolution.routing)
                .ok_or_else(|| "historical workspace storage attestation is invalid".to_string())?;
        let credentials = Credentials::new(access_key, secret_key, None, None, "s4-recovery");
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(region))
            .endpoint_url(endpoint.as_str())
            .credentials_provider(credentials)
            .retry_config(s3_retry_config())
            .timeout_config(s3_timeout_config())
            .http_client(workspace_s3_http_client())
            .load()
            .await;
        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(true)
            .build();
        Ok(ResolvedBackend::S3 {
            kind: BackendKind::PerUserS3,
            client: Client::from_conf(s3_config),
            workspace_streaming: Some(workspace_streaming),
        })
    }

    /// Startup/periodic reconciliation hook for a nonterminal journal row.
    /// Private adapters call this before handing the exact backend to an
    /// `OperationReconciler`.
    pub async fn recover_workspace_operation(
        &self,
        workspace_id: &WorkspaceId,
        operation_id: uuid::Uuid,
        binding: &WorkspaceDestinationBinding,
        journal_claim_owner: &str,
        ttl: Duration,
    ) -> Result<(ResolvedBackend, WorkspaceOperationLease), String> {
        let config_version = BackendConfigVersionId::new(binding.backend_config_version.clone())
            .map_err(|_| "workspace storage recovery identity is invalid".to_string())?;
        let attestation_id =
            CapabilityAttestationId::new(binding.capability_attestation_id.clone())
                .map_err(|_| "workspace storage recovery identity is invalid".to_string())?;
        let expected = WorkspaceOperationLease {
            operation_id,
            lease_id: binding.routing_lease_id,
            config_version,
            attestation_id,
            routing_epoch: binding.routing_epoch,
            fencing_token: binding.routing_fencing_token,
            // Expiry is deliberately not journaled. The repository compares
            // its durable expiry while CASing the persisted identity above.
            expires_at_ms: 0,
        };
        let lease = self
            .workspace_storage
            .recover_streaming_operation_lease(workspace_id, &expected, journal_claim_owner, ttl)
            .await
            .map_err(|_| "workspace storage recovery lease is unavailable".to_string())?;
        if lease.operation_id != operation_id
            || lease.lease_id != binding.routing_lease_id
            || lease.config_version.as_str() != binding.backend_config_version
            || lease.attestation_id.as_str() != binding.capability_attestation_id
            || lease.routing_epoch != binding.routing_epoch
            || lease.fencing_token <= binding.routing_fencing_token
        {
            return Err("workspace storage recovery fence changed".to_string());
        }
        let backend = self
            .resolve_historical_workspace_s3(workspace_id, binding)
            .await?;
        Ok((backend, lease))
    }
}

fn workspace_streaming_binding(
    endpoint: &Url,
    identity: Option<&WorkspaceStreamingBackendIdentity>,
    routing: WorkspaceStorageRouting,
) -> Option<WorkspaceS3Streaming> {
    if endpoint.scheme() != "https" || endpoint.port().is_some() || endpoint.path() != "/" {
        return None;
    }
    let provider = WorkspaceS3Provider::classify(endpoint.host_str()?)?;
    let identity = identity?.clone();
    identity.attestation.validate().ok()?;
    if identity.attestation.provider != provider {
        return None;
    }
    let routing_epoch = routing.stable_epoch()?;
    if routing_epoch == 0 {
        return None;
    }
    Some(WorkspaceS3Streaming {
        provider,
        identity,
        routing_epoch,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TrustedHostPattern {
    Exact(String),
    Suffix(String),
}

impl TrustedHostPattern {
    fn parse(value: String) -> Result<Self, String> {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            return Err("workspace endpoint allowlist contains an empty entry".to_string());
        }
        if let Some(suffix) = value.strip_prefix("*.") {
            if suffix.contains('*') || psl::domain_str(suffix).is_none() {
                return Err("workspace endpoint allowlist contains a broad wildcard".to_string());
            }
            validate_dns_name(suffix)?;
            return Ok(Self::Suffix(suffix.to_string()));
        }
        if value.contains('*') {
            return Err("workspace endpoint allowlist contains an invalid wildcard".to_string());
        }
        validate_dns_name(&value)?;
        Ok(Self::Exact(value))
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(allowed) => host == allowed,
            Self::Suffix(suffix) => host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.')),
        }
    }
}

/// Policy for persisted S3-compatible workspace endpoints.
///
/// This is deliberately separate from [`PresignedHttpPolicy`]: persisted
/// credentials and presigned, expiring URLs have different trust boundaries.
#[derive(Clone)]
pub struct WorkspaceEndpointPolicy {
    explicit_single_tenant: bool,
    trusted_hosts: Vec<TrustedHostPattern>,
    private_allowed_hosts: HashSet<String>,
    resolver: Arc<dyn AddressResolver>,
}

impl WorkspaceEndpointPolicy {
    pub fn new(
        explicit_single_tenant: bool,
        trusted_hosts: impl IntoIterator<Item = String>,
        private_allowed_hosts: impl IntoIterator<Item = String>,
        resolver: Arc<dyn AddressResolver>,
    ) -> Result<Self, String> {
        let trusted_hosts = trusted_hosts
            .into_iter()
            .map(TrustedHostPattern::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let private_allowed_hosts = private_allowed_hosts
            .into_iter()
            .map(normalize_private_allowlist_host)
            .collect::<Result<HashSet<_>, _>>()?;
        if !explicit_single_tenant && !private_allowed_hosts.is_empty() {
            return Err(
                "S4_WORKSPACE_ENDPOINT_PRIVATE_ALLOWLIST requires explicit single-tenant mode"
                    .to_string(),
            );
        }
        Ok(Self {
            explicit_single_tenant,
            trusted_hosts,
            private_allowed_hosts,
            resolver,
        })
    }

    pub fn from_env(explicit_single_tenant: bool) -> Result<Self, String> {
        let trusted_hosts = parse_allowlist_env("S4_WORKSPACE_ENDPOINT_ALLOWLIST")?;
        let private_allowed_hosts = parse_allowlist_env("S4_WORKSPACE_ENDPOINT_PRIVATE_ALLOWLIST")?;
        Self::new(
            explicit_single_tenant,
            trusted_hosts,
            private_allowed_hosts,
            Arc::new(TokioAddressResolver),
        )
    }

    pub async fn validate(&self, endpoint: &str) -> Result<Url, String> {
        if !endpoint.is_ascii() {
            return Err("workspace endpoint must use an ASCII hostname".to_string());
        }
        let authority = endpoint
            .split_once("://")
            .map(|(_, remainder)| remainder)
            .unwrap_or_default()
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err("workspace endpoint host must be lowercase".to_string());
        }
        let url = Url::parse(endpoint)
            .map_err(|_| "workspace endpoint must be an absolute HTTP(S) URL".to_string())?;
        match url.scheme() {
            "https" => {}
            "http" if self.explicit_single_tenant => {}
            "http" => return Err("workspace endpoints require HTTPS".to_string()),
            _ => return Err("workspace endpoint URL scheme is not supported".to_string()),
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "workspace endpoint userinfo, query strings, and fragments are forbidden"
                    .to_string(),
            );
        }

        let host = normalize_endpoint_host(
            url.host_str()
                .ok_or_else(|| "workspace endpoint must have a host".to_string())?,
        )?;
        let literal_ip = host.parse::<IpAddr>().ok();
        if literal_ip.is_none() {
            validate_dns_name(&host)?;
        }
        if !self.explicit_single_tenant {
            if literal_ip.is_some() {
                return Err(
                    "multi-tenant workspace endpoints require a trusted provider hostname"
                        .to_string(),
                );
            }
            if !self
                .trusted_hosts
                .iter()
                .any(|allowed| allowed.matches(&host))
            {
                return Err(
                    "workspace endpoint host is not in S4_WORKSPACE_ENDPOINT_ALLOWLIST".to_string(),
                );
            }
        }

        let port = url
            .port_or_known_default()
            .ok_or_else(|| "workspace endpoint has no usable port".to_string())?;
        let addresses = self
            .resolver
            .resolve(&host, port)
            .await
            .map_err(|_| "workspace endpoint DNS resolution failed".to_string())?;
        if addresses.is_empty() {
            return Err("workspace endpoint DNS resolution returned no addresses".to_string());
        }
        if addresses.iter().any(|address| is_ipv4_mapped(address.ip())) {
            return Err("workspace endpoint uses a forbidden IPv4-mapped IPv6 address".to_string());
        }
        if addresses
            .iter()
            .any(|address| is_forbidden_endpoint_ip(address.ip()))
            && (!self.explicit_single_tenant || !self.private_allowed_hosts.contains(&host))
        {
            return Err("workspace endpoint resolves to a forbidden address range".to_string());
        }
        Ok(url)
    }
}

fn parse_allowlist_env(name: &str) -> Result<Vec<String>, String> {
    let Ok(value) = std::env::var(name) else {
        return Ok(Vec::new());
    };
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                Err(format!("{name} contains an empty entry"))
            } else {
                Ok(entry.to_string())
            }
        })
        .collect()
}

fn normalize_endpoint_host(host: &str) -> Result<String, String> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_ascii_lowercase();
    if host.ends_with('.') {
        return Err("workspace endpoint host must not have a trailing dot".to_string());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_ipv4_mapped(ip) {
            return Err("workspace endpoint uses a forbidden IPv4-mapped IPv6 address".to_string());
        }
        return Ok(ip.to_string());
    }
    Ok(host)
}

fn normalize_private_allowlist_host(value: String) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("workspace private endpoint allowlist contains an empty entry".to_string());
    }
    if value.contains('*')
        || value.contains('/')
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
    {
        return Err("workspace private endpoint allowlist entries must be exact hosts".to_string());
    }
    let host = normalize_endpoint_host(value)?;
    if host.parse::<IpAddr>().is_err() {
        validate_dns_name(&host)?;
    }
    Ok(host)
}

fn validate_dns_name(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.parse::<IpAddr>().is_ok()
        || host.ends_with('.')
    {
        return Err("workspace endpoint allowlist contains an invalid hostname".to_string());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("workspace endpoint allowlist contains an invalid hostname".to_string());
        }
    }
    Ok(())
}

#[async_trait]
pub trait AddressResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

#[derive(Debug)]
pub struct TokioAddressResolver;

#[async_trait]
impl AddressResolver for TokioAddressResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

#[derive(Clone)]
pub struct PresignedHttpPolicy {
    allowed_hosts: Vec<TrustedHostPattern>,
    private_allowed_hosts: HashSet<String>,
    allow_http: bool,
    minimum_validity: Duration,
    resolver: Arc<dyn AddressResolver>,
}

impl PresignedHttpPolicy {
    pub fn new(
        allowed_hosts: impl IntoIterator<Item = String>,
        private_allowed_hosts: impl IntoIterator<Item = String>,
        allow_http: bool,
        minimum_validity: Duration,
        resolver: Arc<dyn AddressResolver>,
    ) -> Result<Self, String> {
        Ok(Self {
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(TrustedHostPattern::parse)
                .collect::<Result<Vec<_>, _>>()?,
            private_allowed_hosts: private_allowed_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            allow_http,
            minimum_validity,
            resolver,
        })
    }

    pub fn from_env() -> Result<Self, String> {
        let allowed_hosts = parse_allowlist_env("S4_PRESIGNED_HTTP_ALLOWLIST")?;
        let allow_http = std::env::var("S4_PRESIGNED_HTTP_ALLOW_HTTP")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
        let minimum_validity = std::env::var("S4_PRESIGNED_HTTP_MIN_VALIDITY_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));
        let private_allowed_hosts = std::env::var("S4_PRESIGNED_HTTP_PRIVATE_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        Self::new(
            allowed_hosts,
            private_allowed_hosts,
            allow_http,
            minimum_validity,
            Arc::new(TokioAddressResolver),
        )
    }

    #[cfg(test)]
    fn for_test(
        allowed_hosts: impl IntoIterator<Item = String>,
        allow_http: bool,
        resolver: Arc<dyn AddressResolver>,
    ) -> Self {
        let allowed_hosts: Vec<String> = allowed_hosts.into_iter().collect();
        Self::new(
            allowed_hosts.clone(),
            allowed_hosts,
            allow_http,
            Duration::ZERO,
            resolver,
        )
        .unwrap()
    }

    pub async fn client_for(&self, url: &Url) -> Result<reqwest::Client, String> {
        self.client_for_operation(url, self.minimum_validity, false)
            .await
    }

    /// Destination requests are always HTTPS, even when a self-hosted
    /// administrator has enabled HTTP for development read sources.
    pub async fn client_for_destination(
        &self,
        url: &Url,
        minimum_validity: Duration,
    ) -> Result<reqwest::Client, String> {
        self.client_for_operation(url, minimum_validity, true).await
    }

    async fn client_for_operation(
        &self,
        url: &Url,
        minimum_validity: Duration,
        require_https: bool,
    ) -> Result<reqwest::Client, String> {
        let host = url
            .host_str()
            .ok_or_else(|| "presigned URL must have a host".to_string())?
            .to_ascii_lowercase();
        if !self.host_allowed(&host) {
            return Err("presigned URL host is not in S4_PRESIGNED_HTTP_ALLOWLIST".to_string());
        }
        match url.scheme() {
            "https" => {}
            "http" if self.allow_http && !require_https => {}
            "http" => return Err("presigned HTTP sources require HTTPS".to_string()),
            _ => return Err("presigned source URL scheme is not supported".to_string()),
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err("presigned URL userinfo and fragments are forbidden".to_string());
        }
        validate_expiry(url, minimum_validity)?;

        let port = url
            .port_or_known_default()
            .ok_or_else(|| "presigned URL has no usable port".to_string())?;
        let addresses = self
            .resolver
            .resolve(&host, port)
            .await
            .map_err(|_| "presigned URL DNS resolution failed".to_string())?;
        if addresses.is_empty() {
            return Err("presigned URL DNS resolution returned no addresses".to_string());
        }

        let private_exception = self.private_allowed_hosts.contains(&host);
        if addresses.iter().any(|address| is_ipv4_mapped(address.ip()))
            || (!private_exception
                && addresses
                    .iter()
                    .any(|address| is_forbidden_endpoint_ip(address.ip())))
        {
            return Err("presigned URL resolves to a forbidden address range".to_string());
        }
        let pinned = addresses[0];
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve(&host, pinned)
            .build()
            .map_err(|_| "presigned HTTP client construction failed".to_string())
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.private_allowed_hosts.contains(host)
            || self
                .allowed_hosts
                .iter()
                .any(|allowed| allowed.matches(host))
    }
}

fn validate_expiry(url: &Url, minimum_validity: Duration) -> Result<(), String> {
    let query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.into_owned()))
        .collect();
    let get = |name: &str| {
        query
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    };

    let expires_at =
        if let (Some(date), Some(valid_for)) = (get("x-amz-date"), get("x-amz-expires")) {
            let signed_at = parse_amz_timestamp(date)
                .ok_or_else(|| "presigned URL has an invalid X-Amz-Date".to_string())?;
            let valid_for = valid_for
                .parse::<u64>()
                .map_err(|_| "presigned URL has an invalid X-Amz-Expires".to_string())?;
            signed_at.checked_add(Duration::from_secs(valid_for))
        } else if let Some(expires) = get("expires") {
            let timestamp = expires
                .parse::<u64>()
                .map_err(|_| "presigned URL has an invalid Expires value".to_string())?;
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(timestamp))
        } else {
            return Err("presigned source URL must contain an explicit expiry".to_string());
        }
        .ok_or_else(|| "presigned URL expiry overflows".to_string())?;

    let required_until = SystemTime::now()
        .checked_add(minimum_validity)
        .ok_or_else(|| "presigned URL validity calculation overflowed".to_string())?;
    if expires_at <= required_until {
        return Err("presigned source URL expires too soon".to_string());
    }
    Ok(())
}

fn parse_amz_timestamp(value: &str) -> Option<SystemTime> {
    let bytes = value.as_bytes();
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
        return None;
    }
    let pair = |index: usize| -> Option<u64> {
        Some(
            bytes[index].checked_sub(b'0')? as u64 * 10
                + bytes[index + 1].checked_sub(b'0')? as u64,
        )
    };
    let year = pair(0)? * 100 + pair(2)?;
    let month = pair(4)?;
    let day = pair(6)?;
    let hour = pair(9)?;
    let minute = pair(11)?;
    let second = pair(13)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let adjusted_year = if month <= 2 {
        year as i64 - 1
    } else {
        year as i64
    };
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = (month as i64 + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds =
        days.checked_mul(86_400)? + hour as i64 * 3_600 + minute as i64 * 60 + second as i64;
    (seconds >= 0).then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds as u64))
}

fn is_ipv4_mapped(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
}

const IPV4_FORBIDDEN_RANGES: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 2), 32),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

const IPV4_PUBLIC_EXCEPTIONS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(192, 0, 0, 9), 32),
    (Ipv4Addr::new(192, 0, 0, 10), 32),
];

const IPV6_FORBIDDEN_RANGES: &[(Ipv6Addr, u8)] = &[
    // Current IANA reserved address-space allocations.
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 8),
    (Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 8),
    (Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0x0400, 0, 0, 0, 0, 0, 0, 0), 6),
    (Ipv6Addr::new(0x0800, 0, 0, 0, 0, 0, 0, 0), 5),
    (Ipv6Addr::new(0x1000, 0, 0, 0, 0, 0, 0, 0), 4),
    (Ipv6Addr::new(0x4000, 0, 0, 0, 0, 0, 0, 0), 3),
    (Ipv6Addr::new(0x6000, 0, 0, 0, 0, 0, 0, 0), 3),
    (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 3),
    (Ipv6Addr::new(0xa000, 0, 0, 0, 0, 0, 0, 0), 3),
    (Ipv6Addr::new(0xc000, 0, 0, 0, 0, 0, 0, 0), 3),
    (Ipv6Addr::new(0xe000, 0, 0, 0, 0, 0, 0, 0), 4),
    (Ipv6Addr::new(0xf000, 0, 0, 0, 0, 0, 0, 0), 5),
    (Ipv6Addr::new(0xf800, 0, 0, 0, 0, 0, 0, 0), 6),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xfe00, 0, 0, 0, 0, 0, 0, 0), 9),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    // Non-global entries in the current IANA special-purpose registry.
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96),
    (Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64),
    (Ipv6Addr::new(0x0100, 0, 0, 1, 0, 0, 0, 0), 64),
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
    (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16),
];

const IPV6_PUBLIC_EXCEPTIONS: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
    (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1), 128),
    (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2), 128),
    (Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 3), 128),
    (Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2001, 4, 0x0112, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28),
    (Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 0), 28),
];

fn is_forbidden_endpoint_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            in_ipv4_ranges(ip, IPV4_FORBIDDEN_RANGES) && !in_ipv4_ranges(ip, IPV4_PUBLIC_EXCEPTIONS)
        }
        IpAddr::V6(ip) => {
            in_ipv6_ranges(ip, IPV6_FORBIDDEN_RANGES) && !in_ipv6_ranges(ip, IPV6_PUBLIC_EXCEPTIONS)
        }
    }
}

fn in_ipv4_ranges(ip: Ipv4Addr, ranges: &[(Ipv4Addr, u8)]) -> bool {
    let bits = u32::from(ip);
    ranges.iter().any(|(network, prefix)| {
        let shift = Ipv4Addr::BITS - u32::from(*prefix);
        bits >> shift == u32::from(*network) >> shift
    })
}

fn in_ipv6_ranges(ip: Ipv6Addr, ranges: &[(Ipv6Addr, u8)]) -> bool {
    let bits = u128::from(ip);
    ranges.iter().any(|(network, prefix)| {
        let shift = Ipv6Addr::BITS - u32::from(*prefix);
        bits >> shift == u128::from(*network) >> shift
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::extract::State;
    use axum::http::{StatusCode, Uri};
    use axum::routing::any;

    async fn capture_request_path(
        State(paths): State<Arc<std::sync::Mutex<Vec<String>>>>,
        uri: Uri,
    ) -> StatusCode {
        paths.lock().unwrap().push(uri.path().to_string());
        StatusCode::OK
    }

    struct StaticResolver {
        addresses: Vec<SocketAddr>,
        calls: AtomicUsize,
    }

    struct FailingResolver;

    #[async_trait]
    impl AddressResolver for StaticResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.addresses.clone())
        }
    }

    #[async_trait]
    impl AddressResolver for FailingResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Err(std::io::Error::other("test DNS failure"))
        }
    }

    struct FailingWorkspaceStorageRepository;

    struct PersistedWorkspaceStorageRepository {
        resolution: crate::workspace_storage::WorkspaceStorageResolution,
    }

    #[async_trait]
    impl WorkspaceStorageRepository for FailingWorkspaceStorageRepository {
        async fn resolve_workspace(
            &self,
            _user_id: &str,
        ) -> Result<WorkspaceId, crate::workspace_storage::WorkspaceStorageError> {
            Err(crate::workspace_storage::WorkspaceStorageError::Repository(
                "database details must not escape".to_string(),
            ))
        }

        async fn get_runtime_config(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Option<RuntimeBackendConfig>, crate::workspace_storage::WorkspaceStorageError>
        {
            Err(crate::workspace_storage::WorkspaceStorageError::Repository(
                "database details must not escape".to_string(),
            ))
        }

        async fn get_public_config(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<
            crate::workspace_storage::BackendConfigResponse,
            crate::workspace_storage::WorkspaceStorageError,
        > {
            Err(crate::workspace_storage::WorkspaceStorageError::Repository(
                "database details must not escape".to_string(),
            ))
        }

        async fn put_config(
            &self,
            _workspace_id: &WorkspaceId,
            _request: crate::workspace_storage::BackendConfigRequest,
        ) -> Result<
            crate::workspace_storage::BackendConfigResponse,
            crate::workspace_storage::WorkspaceStorageError,
        > {
            Err(crate::workspace_storage::WorkspaceStorageError::Repository(
                "database details must not escape".to_string(),
            ))
        }
    }

    #[async_trait]
    impl WorkspaceStorageRepository for PersistedWorkspaceStorageRepository {
        async fn resolve_workspace(
            &self,
            user_id: &str,
        ) -> Result<WorkspaceId, crate::workspace_storage::WorkspaceStorageError> {
            WorkspaceId::new(user_id)
        }

        async fn get_runtime_config(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Option<RuntimeBackendConfig>, crate::workspace_storage::WorkspaceStorageError>
        {
            panic!("backend routing must use the atomic runtime resolution")
        }

        async fn get_runtime_resolution(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<
            crate::workspace_storage::WorkspaceStorageResolution,
            crate::workspace_storage::WorkspaceStorageError,
        > {
            Ok(self.resolution.clone())
        }

        async fn get_public_config(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<
            crate::workspace_storage::BackendConfigResponse,
            crate::workspace_storage::WorkspaceStorageError,
        > {
            Ok(crate::workspace_storage::BackendConfigResponse::unconfigured())
        }

        async fn put_config(
            &self,
            _workspace_id: &WorkspaceId,
            _request: crate::workspace_storage::BackendConfigRequest,
        ) -> Result<
            crate::workspace_storage::BackendConfigResponse,
            crate::workspace_storage::WorkspaceStorageError,
        > {
            Ok(crate::workspace_storage::BackendConfigResponse::unconfigured())
        }
    }

    fn future_url(host: &str) -> Url {
        let expires = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        Url::parse(&format!("https://{host}/object?Expires={expires}")).unwrap()
    }

    fn workspace_policy(explicit_single_tenant: bool) -> WorkspaceEndpointPolicy {
        WorkspaceEndpointPolicy::new(
            explicit_single_tenant,
            Vec::<String>::new(),
            Vec::<String>::new(),
            Arc::new(StaticResolver {
                addresses: vec!["93.184.216.34:443".parse().unwrap()],
                calls: AtomicUsize::new(0),
            }),
        )
        .unwrap()
    }

    fn workspace_policy_with(
        explicit_single_tenant: bool,
        trusted_hosts: &[&str],
        private_allowed_hosts: &[&str],
        addresses: &[&str],
    ) -> WorkspaceEndpointPolicy {
        WorkspaceEndpointPolicy::new(
            explicit_single_tenant,
            trusted_hosts.iter().map(|host| (*host).to_string()),
            private_allowed_hosts.iter().map(|host| (*host).to_string()),
            Arc::new(StaticResolver {
                addresses: addresses
                    .iter()
                    .map(|address| address.parse().unwrap())
                    .collect(),
                calls: AtomicUsize::new(0),
            }),
        )
        .unwrap()
    }

    #[test]
    fn expiry_overflow_is_rejected_without_panicking() {
        let url = Url::parse(&format!(
            "https://objects.example/object?Expires={}",
            u64::MAX
        ))
        .unwrap();
        assert!(validate_expiry(&url, Duration::ZERO).is_err());
    }

    async fn test_s3_client() -> Client {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url("https://s3.example")
            .credentials_provider(Credentials::new("key", "secret", None, None, "test"))
            .load()
            .await;
        Client::new(&config)
    }

    async fn assert_operations_resolve_to(
        resolver: &BackendResolver,
        headers: &HeaderMap,
        expected: BackendKind,
    ) {
        for operation in [
            StorageOperation::Get,
            StorageOperation::Head,
            StorageOperation::Put,
            StorageOperation::Delete,
            StorageOperation::List,
            StorageOperation::Multipart,
        ] {
            assert_eq!(
                resolver
                    .resolve(&WorkspaceId::new("workspace").unwrap(), headers, operation)
                    .await
                    .unwrap()
                    .kind(),
                expected,
                "operation {operation:?}",
            );
        }
    }

    #[tokio::test]
    async fn resolver_uses_one_priority_matrix_for_every_operation() {
        use crate::service_storage::ServiceBackend;
        use crate::workspace_storage::{
            BackendConfigRequest, BackendType, InMemoryWorkspaceStorageRepository,
        };

        let memory = Arc::new(MemoryStore::new());
        let repository = Arc::new(InMemoryWorkspaceStorageRepository::new());
        let empty_managed = Arc::new(ServiceStorage::new(Vec::new()));
        let resolver = BackendResolver::new(
            repository.clone(),
            empty_managed.clone(),
            None,
            memory.clone(),
            true,
            workspace_policy(true),
        );
        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::Memory).await;

        let global = test_s3_client().await;
        let resolver = BackendResolver::new(
            repository.clone(),
            empty_managed,
            Some(global.clone()),
            memory.clone(),
            true,
            workspace_policy(true),
        );
        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::GlobalS3).await;

        let managed = Arc::new(ServiceStorage::new(vec![ServiceBackend {
            provider: "test".to_string(),
            provider_instance_id: None,
            provider_account_id: None,
            credential_epoch: None,
            endpoint: "https://managed.example".to_string(),
            region: "us-east-1".to_string(),
            bucket: "managed".to_string(),
            access_key: "key".to_string(),
            secret_key: "secret".to_string(),
        }]));
        let resolver = BackendResolver::new(
            repository.clone(),
            managed.clone(),
            Some(global.clone()),
            memory.clone(),
            true,
            workspace_policy(true),
        );
        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::Managed).await;

        let workspace = WorkspaceId::new("workspace").unwrap();
        repository
            .put_config(
                &workspace,
                BackendConfigRequest {
                    backend_type: BackendType::S3Compatible,
                    endpoint: "https://user.example".to_string(),
                    access_key: "key".to_string(),
                    secret_key: "secret".to_string(),
                    region: "us-east-1".to_string(),
                    role_arn: String::new(),
                },
            )
            .await
            .unwrap();
        let resolver = BackendResolver::new(
            repository.clone(),
            managed.clone(),
            Some(global.clone()),
            memory.clone(),
            false,
            workspace_policy_with(false, &["user.example"], &[], &["93.184.216.34:443"]),
        );
        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::PerUserS3).await;

        // Hosted persisted BYO state is authoritative. A request header cannot
        // redirect the workspace into managed storage; unknown values are also
        // ignored.
        let mut managed_override = HeaderMap::new();
        managed_override.insert("x-s4-storage-mode", "managed".parse().unwrap());
        assert_operations_resolve_to(&resolver, &managed_override, BackendKind::PerUserS3).await;
        let mut unknown_mode = HeaderMap::new();
        unknown_mode.insert("x-s4-storage-mode", "archive".parse().unwrap());
        assert_operations_resolve_to(&resolver, &unknown_mode, BackendKind::PerUserS3).await;

        // Preserve the request-level shortcut only in explicit single-tenant
        // development mode.
        let development = BackendResolver::new(
            repository,
            managed,
            Some(global),
            memory.clone(),
            true,
            workspace_policy(true),
        );
        assert_operations_resolve_to(&development, &managed_override, BackendKind::Managed).await;

        // x-s4-storage-mode: managed errors when no managed backend is configured.
        let no_managed = BackendResolver::new(
            Arc::new(InMemoryWorkspaceStorageRepository::new()),
            Arc::new(ServiceStorage::new(Vec::new())),
            None,
            memory.clone(),
            true,
            workspace_policy(true),
        );
        assert!(
            no_managed
                .resolve(&workspace, &managed_override, StorageOperation::Put)
                .await
                .is_err()
        );

        let mut presigned = HeaderMap::new();
        presigned.insert(
            "x-s4-backend-url",
            "https://objects.example/object?Expires=9999999999"
                .parse()
                .unwrap(),
        );
        assert_operations_resolve_to(&resolver, &presigned, BackendKind::PresignedHttp).await;
    }

    #[tokio::test]
    async fn explicit_managed_config_is_fail_closed_without_service_storage() {
        use crate::service_storage::ServiceBackend;
        use crate::workspace_storage::{
            BackendConfigRequest, BackendType, InMemoryWorkspaceStorageRepository,
        };

        let workspace = WorkspaceId::new("workspace").unwrap();
        let repository = Arc::new(InMemoryWorkspaceStorageRepository::new());
        repository
            .put_config(
                &workspace,
                BackendConfigRequest {
                    backend_type: BackendType::Managed,
                    endpoint: String::new(),
                    access_key: String::new(),
                    secret_key: String::new(),
                    region: String::new(),
                    role_arn: String::new(),
                },
            )
            .await
            .unwrap();
        let memory = Arc::new(MemoryStore::new());
        let global = test_s3_client().await;
        let unavailable = BackendResolver::new(
            repository.clone(),
            Arc::new(ServiceStorage::new(Vec::new())),
            Some(global),
            memory.clone(),
            false,
            workspace_policy(false),
        );
        for operation in [
            StorageOperation::Get,
            StorageOperation::Head,
            StorageOperation::Put,
            StorageOperation::Delete,
            StorageOperation::List,
            StorageOperation::Multipart,
        ] {
            assert!(
                unavailable
                    .resolve(&workspace, &HeaderMap::new(), operation)
                    .await
                    .is_err(),
                "explicit managed config must not fall through for {operation:?}",
            );
        }

        let managed = Arc::new(ServiceStorage::new(vec![ServiceBackend {
            provider: "test".to_string(),
            provider_instance_id: None,
            provider_account_id: None,
            credential_epoch: None,
            endpoint: "https://managed.example".to_string(),
            region: "us-east-1".to_string(),
            bucket: "managed".to_string(),
            access_key: "key".to_string(),
            secret_key: "secret".to_string(),
        }]));
        let available = BackendResolver::new(
            repository,
            managed,
            None,
            memory,
            false,
            workspace_policy(false),
        );
        assert_operations_resolve_to(&available, &HeaderMap::new(), BackendKind::Managed).await;
    }

    #[tokio::test]
    async fn multi_tenant_workspace_never_falls_through_to_global_or_memory_storage() {
        use crate::workspace_storage::{
            BackendConfigRequest, BackendType, InMemoryWorkspaceStorageRepository,
        };

        let repository = Arc::new(InMemoryWorkspaceStorageRepository::new());
        let configured = WorkspaceId::new("configured-workspace").unwrap();
        repository
            .put_config(
                &configured,
                BackendConfigRequest {
                    backend_type: BackendType::S3Compatible,
                    endpoint: "https://tenant.storage.example".to_string(),
                    access_key: "key".to_string(),
                    secret_key: "secret".to_string(),
                    region: "us-east-1".to_string(),
                    role_arn: String::new(),
                },
            )
            .await
            .unwrap();
        let resolver = BackendResolver::new(
            repository,
            Arc::new(ServiceStorage::new(Vec::new())),
            Some(test_s3_client().await),
            Arc::new(MemoryStore::new()),
            false,
            workspace_policy_with(false, &["*.storage.example"], &[], &["93.184.216.34:443"]),
        );

        assert_eq!(
            resolver
                .resolve(&configured, &HeaderMap::new(), StorageOperation::Get)
                .await
                .unwrap()
                .kind(),
            BackendKind::PerUserS3
        );
        let unconfigured = WorkspaceId::new("other-workspace").unwrap();
        let Err(error) = resolver
            .resolve(&unconfigured, &HeaderMap::new(), StorageOperation::Get)
            .await
        else {
            panic!("unconfigured tenant must not reach process-global storage");
        };
        assert_eq!(error, "workspace storage is unavailable");
    }

    #[tokio::test]
    async fn multi_tenant_unconfigured_workspace_defaults_to_managed_storage() {
        use crate::service_storage::ServiceBackend;
        use crate::workspace_storage::InMemoryWorkspaceStorageRepository;

        let managed = Arc::new(ServiceStorage::new(vec![ServiceBackend {
            provider: "test".to_string(),
            provider_instance_id: None,
            provider_account_id: None,
            credential_epoch: None,
            endpoint: "https://managed.example".to_string(),
            region: "us-east-1".to_string(),
            bucket: "managed".to_string(),
            access_key: "key".to_string(),
            secret_key: "secret".to_string(),
        }]));
        let resolver = BackendResolver::new(
            Arc::new(InMemoryWorkspaceStorageRepository::new()),
            managed,
            Some(test_s3_client().await),
            Arc::new(MemoryStore::new()),
            false,
            workspace_policy(false),
        );

        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::Managed).await;
    }

    #[tokio::test]
    async fn explicit_single_tenant_mode_preserves_global_and_memory_fallbacks() {
        use crate::workspace_storage::InMemoryWorkspaceStorageRepository;

        let repository = Arc::new(InMemoryWorkspaceStorageRepository::new());
        let memory = Arc::new(MemoryStore::new());
        let global = BackendResolver::new(
            repository.clone(),
            Arc::new(ServiceStorage::new(Vec::new())),
            Some(test_s3_client().await),
            memory.clone(),
            true,
            workspace_policy(true),
        );
        assert_operations_resolve_to(&global, &HeaderMap::new(), BackendKind::GlobalS3).await;

        let local = BackendResolver::new(
            repository,
            Arc::new(ServiceStorage::new(Vec::new())),
            None,
            memory,
            true,
            workspace_policy(true),
        );
        assert_operations_resolve_to(&local, &HeaderMap::new(), BackendKind::Memory).await;
    }

    #[tokio::test]
    async fn workspace_repository_failure_is_bounded_and_fail_closed() {
        use crate::service_storage::ServiceBackend;

        let resolver = BackendResolver::new(
            Arc::new(FailingWorkspaceStorageRepository),
            Arc::new(ServiceStorage::new(vec![ServiceBackend {
                provider: "test".to_string(),
                provider_instance_id: None,
                provider_account_id: None,
                credential_epoch: None,
                endpoint: "https://managed.example".to_string(),
                region: "us-east-1".to_string(),
                bucket: "managed".to_string(),
                access_key: "key".to_string(),
                secret_key: "secret".to_string(),
            }])),
            Some(test_s3_client().await),
            Arc::new(MemoryStore::new()),
            false,
            workspace_policy(false),
        );
        let workspace = WorkspaceId::new("workspace").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-s4-storage-mode", "managed".parse().unwrap());
        let Err(error) = resolver
            .resolve(&workspace, &headers, StorageOperation::Get)
            .await
        else {
            panic!("hosted managed header must not bypass a repository failure");
        };
        assert_eq!(error, "workspace storage is unavailable");
    }

    #[tokio::test]
    async fn hosted_selection_captures_one_atomic_config_and_epoch_snapshot() {
        use crate::service_storage::ServiceBackend;
        use crate::workspace_storage::{
            WorkspaceStorageResolution, WorkspaceStorageTransitionState,
        };

        let repository = Arc::new(PersistedWorkspaceStorageRepository {
            resolution: WorkspaceStorageResolution::persisted(
                Some(RuntimeBackendConfig::S3Compatible {
                    endpoint: "https://tenant.storage.example".to_string(),
                    access_key: "key".to_string(),
                    secret_key: "secret".to_string(),
                    region: "us-east-1".to_string(),
                }),
                17,
                WorkspaceStorageTransitionState::Stable,
            ),
        });
        let resolver = BackendResolver::new(
            repository,
            Arc::new(ServiceStorage::new(vec![ServiceBackend {
                provider: "test".to_string(),
                provider_instance_id: None,
                provider_account_id: None,
                credential_epoch: None,
                endpoint: "https://managed.example".to_string(),
                region: "us-east-1".to_string(),
                bucket: "managed".to_string(),
                access_key: "key".to_string(),
                secret_key: "secret".to_string(),
            }])),
            None,
            Arc::new(MemoryStore::new()),
            false,
            workspace_policy_with(false, &["*.storage.example"], &[], &["93.184.216.34:443"]),
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-s4-storage-mode", "managed".parse().unwrap());

        let selection = resolver
            .resolve_with_routing(
                &WorkspaceId::new("workspace").unwrap(),
                &headers,
                StorageOperation::Put,
            )
            .await
            .unwrap();
        assert_eq!(selection.backend.kind(), BackendKind::PerUserS3);
        assert_eq!(
            selection.workspace_routing,
            Some(WorkspaceStorageRouting::Persisted {
                routing_epoch: 17,
                transition_state: WorkspaceStorageTransitionState::Stable,
            })
        );
    }

    #[tokio::test]
    async fn hosted_provider_families_receive_fenced_immutable_streaming_profiles() {
        use crate::transaction::{
            BackendCapabilities, CompletionReconciliation, ConditionalReadCapability,
            IncompleteUploadDiscovery, ListCapability, MultipartResponseCapability,
            ResponseChecksumCapability, VersioningCapability,
        };
        use crate::workspace_storage::{
            BackendConfigVersionId, CapabilityAttestationId, S3CapabilityAttestation,
            S3StreamingPermissions, WorkspaceStorageTransitionState,
            WorkspaceStreamingBackendIdentity,
        };

        fn identity(
            provider: WorkspaceS3Provider,
            version: &str,
        ) -> WorkspaceStreamingBackendIdentity {
            WorkspaceStreamingBackendIdentity {
                config_version: BackendConfigVersionId::new(version).unwrap(),
                attestation: S3CapabilityAttestation {
                    id: CapabilityAttestationId::new(format!("attestation-{version}")).unwrap(),
                    provider,
                    capabilities: BackendCapabilities {
                        incomplete_upload_discovery:
                            IncompleteUploadDiscovery::ExactKeyAndStartTime,
                        abort_incomplete_upload: true,
                        cleanup_sla: Some(Duration::from_secs(60)),
                        lifecycle_rule: false,
                        versioning: VersioningCapability::Optional,
                        conditional_reads: ConditionalReadCapability::Etag,
                        response_checksums: ResponseChecksumCapability::Unsupported,
                        list_operations: ListCapability::V1AndV2,
                        multipart_responses: MultipartResponseCapability::Standard,
                        completion_reconciliation:
                            CompletionReconciliation::HeadWithOperationIdentity,
                    },
                    permissions: S3StreamingPermissions {
                        put_object: true,
                        create_multipart_upload: true,
                        upload_part: true,
                        complete_multipart_upload: true,
                        abort_multipart_upload: true,
                        list_multipart_uploads: true,
                        list_parts: true,
                        head_object: true,
                        read_operation_metadata: true,
                        list_object_versions: true,
                        delete_object_version: true,
                    },
                    exact_version_recovery: provider == WorkspaceS3Provider::B2,
                },
            }
        }

        for (endpoint, expected_provider) in [
            ("https://s3.amazonaws.com", WorkspaceS3Provider::Aws),
            ("https://storage.googleapis.com", WorkspaceS3Provider::Gcs),
            (
                "https://s3.us-east-005.backblazeb2.com",
                WorkspaceS3Provider::B2,
            ),
            (
                "https://account.r2.cloudflarestorage.com",
                WorkspaceS3Provider::R2,
            ),
            (
                "https://nyc3.digitaloceanspaces.com",
                WorkspaceS3Provider::DigitalOcean,
            ),
            (
                "https://s3.us-east-1.wasabisys.com",
                WorkspaceS3Provider::Wasabi,
            ),
        ] {
            let url = Url::parse(endpoint).unwrap();
            let config_identity = identity(expected_provider, "config-v1");
            let first = workspace_streaming_binding(
                &url,
                Some(&config_identity),
                WorkspaceStorageRouting::Persisted {
                    routing_epoch: 17,
                    transition_state: WorkspaceStorageTransitionState::Stable,
                },
            )
            .unwrap();
            let retry = workspace_streaming_binding(
                &url,
                Some(&config_identity),
                WorkspaceStorageRouting::Persisted {
                    routing_epoch: 17,
                    transition_state: WorkspaceStorageTransitionState::Stable,
                },
            )
            .unwrap();
            assert_eq!(first, retry, "{endpoint}");
            assert_eq!(first.provider, expected_provider, "{endpoint}");
            first
                .identity
                .attestation
                .capabilities
                .streaming_eligibility()
                .unwrap();

            let next_identity = identity(expected_provider, "config-v2");
            let changed_version = workspace_streaming_binding(
                &url,
                Some(&next_identity),
                WorkspaceStorageRouting::Persisted {
                    routing_epoch: 17,
                    transition_state: WorkspaceStorageTransitionState::Stable,
                },
            )
            .unwrap();
            let changed_routing = workspace_streaming_binding(
                &url,
                Some(&config_identity),
                WorkspaceStorageRouting::Persisted {
                    routing_epoch: 18,
                    transition_state: WorkspaceStorageTransitionState::Stable,
                },
            )
            .unwrap();
            assert_ne!(first.identity, changed_version.identity);
            assert_ne!(first.routing_epoch, changed_routing.routing_epoch);
        }
    }

    #[test]
    fn workspace_streaming_profiles_refuse_unknown_or_unfenced_endpoints() {
        use crate::workspace_storage::WorkspaceStorageTransitionState;

        for endpoint in [
            "https://objects.example",
            "https://ec2.us-east-1.amazonaws.com",
            "https://bucket.s3.us-east-1.amazonaws.com",
            "https://evilbackblazeb2.com",
            "https://account.r2.cloudflarestorage.com/prefix",
            "https://s3.us-east-1.wasabisys.com:8443",
        ] {
            assert!(
                workspace_streaming_binding(
                    &Url::parse(endpoint).unwrap(),
                    None,
                    WorkspaceStorageRouting::Persisted {
                        routing_epoch: 1,
                        transition_state: WorkspaceStorageTransitionState::Stable,
                    },
                )
                .is_none(),
                "{endpoint}",
            );
        }
        assert!(
            workspace_streaming_binding(
                &Url::parse("https://s3.amazonaws.com").unwrap(),
                None,
                WorkspaceStorageRouting::Unfenced,
            )
            .is_none()
        );
    }

    #[test]
    fn hosted_endpoint_grammar_accepts_only_data_plane_origins() {
        for (host, provider) in [
            ("s3.amazonaws.com", WorkspaceS3Provider::Aws),
            ("s3.us-east-1.amazonaws.com", WorkspaceS3Provider::Aws),
            ("s3-us-west-2.amazonaws.com", WorkspaceS3Provider::Aws),
            ("s3-external-1.amazonaws.com", WorkspaceS3Provider::Aws),
            (
                "s3.dualstack.eu-west-1.amazonaws.com",
                WorkspaceS3Provider::Aws,
            ),
            (
                "s3-fips.us-gov-west-1.amazonaws.com",
                WorkspaceS3Provider::Aws,
            ),
            (
                "s3-fips.dualstack.us-gov-west-1.amazonaws.com",
                WorkspaceS3Provider::Aws,
            ),
            ("s3.cn-north-1.amazonaws.com.cn", WorkspaceS3Provider::Aws),
            ("storage.googleapis.com", WorkspaceS3Provider::Gcs),
            ("s3.us-east-005.backblazeb2.com", WorkspaceS3Provider::B2),
            ("account.r2.cloudflarestorage.com", WorkspaceS3Provider::R2),
            (
                "nyc3.digitaloceanspaces.com",
                WorkspaceS3Provider::DigitalOcean,
            ),
            ("s3.us-east-1.wasabisys.com", WorkspaceS3Provider::Wasabi),
        ] {
            assert_eq!(
                WorkspaceS3Provider::classify(host),
                Some(provider),
                "{host}"
            );
        }

        for host in [
            "bucket.s3.us-east-1.amazonaws.com",
            "bucket.s3-accesspoint.us-east-1.amazonaws.com",
            "name-123.s3-accesspoint.us-east-1.amazonaws.com",
            "name-123.s3-object-lambda.us-east-1.amazonaws.com",
            "name-123.s3-outposts.us-east-1.amazonaws.com",
            "s3-control.us-east-1.amazonaws.com",
            "bucket.s3-accelerate.amazonaws.com",
            "bucket.s3-accelerate.dualstack.amazonaws.com",
            "s3-accelerate.amazonaws.com",
            "s3-website-us-east-1.amazonaws.com",
            "s3-website.us-east-1.amazonaws.com",
            "s3-evil.amazonaws.com",
            "s3-mars-1.amazonaws.com",
            "s3.evil.amazonaws.com",
            "s3.dualstack.evil.amazonaws.com",
            "s3-fips.evil.amazonaws.com",
            "s3-external-2.amazonaws.com",
            "ec2.us-east-1.amazonaws.com",
            "r2.cloudflarestorage.com",
            "bucket.account.r2.cloudflarestorage.com",
            "bucket.nyc3.digitaloceanspaces.com",
            "s3.foo.us-east-005.backblazeb2.com",
            "s3.evil.backblazeb2.com",
            "s3.us-east-5.backblazeb2.com",
            "s3.us-east-0005.backblazeb2.com",
            "s3.u-east-005.backblazeb2.com",
            "s3.us-ea5t-005.backblazeb2.com",
        ] {
            assert_eq!(WorkspaceS3Provider::classify(host), None, "{host}");
        }
    }

    #[tokio::test]
    async fn persisted_mode_transition_fences_new_routing() {
        use crate::service_storage::ServiceBackend;
        use crate::workspace_storage::{
            WorkspaceStorageResolution, WorkspaceStorageTransitionState,
        };

        for transition_state in [
            WorkspaceStorageTransitionState::TransitioningToManaged,
            WorkspaceStorageTransitionState::TransitioningToS3Compatible,
        ] {
            let resolver = BackendResolver::new(
                Arc::new(PersistedWorkspaceStorageRepository {
                    resolution: WorkspaceStorageResolution::persisted(
                        Some(RuntimeBackendConfig::Managed),
                        18,
                        transition_state,
                    ),
                }),
                Arc::new(ServiceStorage::new(vec![ServiceBackend {
                    provider: "test".to_string(),
                    provider_instance_id: None,
                    provider_account_id: None,
                    credential_epoch: None,
                    endpoint: "https://managed.example".to_string(),
                    region: "us-east-1".to_string(),
                    bucket: "managed".to_string(),
                    access_key: "key".to_string(),
                    secret_key: "secret".to_string(),
                }])),
                None,
                Arc::new(MemoryStore::new()),
                false,
                workspace_policy(false),
            );
            let mut headers = HeaderMap::new();
            headers.insert("x-s4-storage-mode", "managed".parse().unwrap());

            let Err(error) = resolver
                .resolve(
                    &WorkspaceId::new("workspace").unwrap(),
                    &headers,
                    StorageOperation::Put,
                )
                .await
            else {
                panic!("mode transition must fence new requests");
            };
            assert_eq!(error, "workspace storage is transitioning");
        }
    }

    #[test]
    fn byo_s3_custom_endpoint_uses_path_style_and_ignores_environment_proxies() {
        const CHILD_ENV: &str = "S4_TEST_WORKSPACE_S3_NO_PROXY_CHILD";
        const TEST_NAME: &str = "backend::tests::byo_s3_custom_endpoint_uses_path_style_and_ignores_environment_proxies";
        if std::env::var_os(CHILD_ENV).is_none() {
            let poison_proxy = "http://127.0.0.1:1";
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_ENV, "1")
                .env("HTTP_PROXY", poison_proxy)
                .env("http_proxy", poison_proxy)
                .env("HTTPS_PROXY", poison_proxy)
                .env("https_proxy", poison_proxy)
                .env("NO_PROXY", "")
                .env("no_proxy", "")
                .status()
                .unwrap();
            assert!(status.success(), "proxy-poisoned child test failed");
            return;
        }

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use crate::workspace_storage::{
                BackendConfigRequest, BackendType, InMemoryWorkspaceStorageRepository,
            };

            let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
            let app = Router::new()
                .fallback(any(capture_request_path))
                .with_state(paths.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

            let workspace = WorkspaceId::new("workspace").unwrap();
            let repository = Arc::new(InMemoryWorkspaceStorageRepository::new());
            repository
                .put_config(
                    &workspace,
                    BackendConfigRequest {
                        backend_type: BackendType::S3Compatible,
                        endpoint,
                        access_key: "key".to_string(),
                        secret_key: "secret".to_string(),
                        region: "us-east-1".to_string(),
                        role_arn: String::new(),
                    },
                )
                .await
                .unwrap();
            let resolver = BackendResolver::new(
                repository,
                Arc::new(ServiceStorage::new(Vec::new())),
                None,
                Arc::new(MemoryStore::new()),
                true,
                WorkspaceEndpointPolicy::new(
                    true,
                    Vec::<String>::new(),
                    ["127.0.0.1".to_string()],
                    Arc::new(TokioAddressResolver),
                )
                .unwrap(),
            );
            let ResolvedBackend::S3 { client, .. } = resolver
                .resolve(&workspace, &HeaderMap::new(), StorageOperation::Head)
                .await
                .unwrap()
            else {
                panic!("expected BYO S3 backend");
            };
            client
                .head_bucket()
                .bucket("bucket.with.dots")
                .send()
                .await
                .unwrap();

            assert_eq!(paths.lock().unwrap().as_slice(), ["/bucket.with.dots/"]);
            server.abort();

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("https://{}", listener.local_addr().unwrap());
            let direct_connection = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream);
            });
            let workspace = WorkspaceId::new("https-workspace").unwrap();
            let repository = Arc::new(InMemoryWorkspaceStorageRepository::new());
            repository
                .put_config(
                    &workspace,
                    BackendConfigRequest {
                        backend_type: BackendType::S3Compatible,
                        endpoint,
                        access_key: "key".to_string(),
                        secret_key: "secret".to_string(),
                        region: "us-east-1".to_string(),
                        role_arn: String::new(),
                    },
                )
                .await
                .unwrap();
            let resolver = BackendResolver::new(
                repository,
                Arc::new(ServiceStorage::new(Vec::new())),
                None,
                Arc::new(MemoryStore::new()),
                true,
                WorkspaceEndpointPolicy::new(
                    true,
                    Vec::<String>::new(),
                    ["127.0.0.1".to_string()],
                    Arc::new(TokioAddressResolver),
                )
                .unwrap(),
            );
            let ResolvedBackend::S3 { client, .. } = resolver
                .resolve(&workspace, &HeaderMap::new(), StorageOperation::Head)
                .await
                .unwrap()
            else {
                panic!("expected BYO S3 backend");
            };
            assert!(client.head_bucket().bucket("bucket").send().await.is_err());
            tokio::time::timeout(Duration::from_secs(1), direct_connection)
                .await
                .expect("HTTPS request used the poisoned proxy instead of the endpoint")
                .unwrap();
        });
    }

    #[tokio::test]
    async fn workspace_policy_uses_exact_and_dot_boundary_suffix_matching() {
        let policy = workspace_policy_with(
            false,
            &["objects.example", "*.storage.example", "*.backblazeb2.com"],
            &[],
            &["93.184.216.34:443"],
        );
        for endpoint in [
            "https://objects.example",
            "https://tenant.storage.example",
            "https://s3.us-east-005.backblazeb2.com",
        ] {
            assert!(policy.validate(endpoint).await.is_ok(), "{endpoint}");
        }
        for endpoint in [
            "https://other.objects.example",
            "https://evilstorage.example",
            "https://storage.example",
        ] {
            assert!(policy.validate(endpoint).await.is_err(), "{endpoint}");
        }
    }

    #[tokio::test]
    async fn multi_tenant_workspace_policy_requires_https_and_clean_urls() {
        let policy =
            workspace_policy_with(false, &["objects.example"], &[], &["93.184.216.34:443"]);
        for endpoint in [
            "http://objects.example",
            "https://user@objects.example",
            "https://objects.example?token=secret",
            "https://objects.example#fragment",
            "https://Objects.example",
            "https://s3.US-east-005.backblazeb2.com",
            "https://s3.us-\u{00e9}ast-005.backblazeb2.com",
        ] {
            assert!(policy.validate(endpoint).await.is_err(), "{endpoint}");
        }
    }

    #[tokio::test]
    async fn workspace_policy_requires_successful_public_dns_resolution() {
        let empty = workspace_policy_with(false, &["objects.example"], &[], &[]);
        assert!(empty.validate("https://objects.example").await.is_err());

        let failed = WorkspaceEndpointPolicy::new(
            false,
            ["objects.example".to_string()],
            Vec::<String>::new(),
            Arc::new(FailingResolver),
        )
        .unwrap();
        assert!(failed.validate("https://objects.example").await.is_err());

        let private = workspace_policy_with(false, &["objects.example"], &[], &["10.0.0.1:443"]);
        assert!(private.validate("https://objects.example").await.is_err());
    }

    #[tokio::test]
    async fn private_and_http_workspace_endpoints_require_explicit_single_tenant_operator_trust() {
        let public_http = workspace_policy_with(true, &[], &[], &["93.184.216.34:80"]);
        assert!(public_http.validate("http://objects.example").await.is_ok());

        let private_denied = workspace_policy_with(true, &[], &[], &["127.0.0.1:9000"]);
        assert!(
            private_denied
                .validate("http://minio.internal:9000")
                .await
                .is_err()
        );
        let private_allowed =
            workspace_policy_with(true, &[], &["minio.internal"], &["127.0.0.1:9000"]);
        assert!(
            private_allowed
                .validate("http://minio.internal:9000")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn workspace_policy_rejects_dns_rebinding_and_mapped_ipv6() {
        let rebound = workspace_policy_with(
            false,
            &["objects.example"],
            &[],
            &["93.184.216.34:443", "169.254.169.254:443"],
        );
        assert!(rebound.validate("https://objects.example").await.is_err());

        let mapped = workspace_policy_with(
            true,
            &[],
            &["objects.internal"],
            &["[::ffff:127.0.0.1]:443"],
        );
        assert!(mapped.validate("https://objects.internal").await.is_err());
        assert!(mapped.validate("https://[::ffff:127.0.0.1]").await.is_err());
    }

    #[test]
    fn workspace_policy_rejects_empty_broad_and_ip_allowlist_entries() {
        for entry in [
            "",
            "*",
            "*.com",
            "*.co.uk",
            "*.storage.example.",
            "storage.example.",
            "b\u{fc}cket.example",
            "127.0.0.1",
            "::1",
            "foo..example",
            "foo_example.com",
            "https://storage.example",
        ] {
            assert!(
                WorkspaceEndpointPolicy::new(
                    false,
                    [entry.to_string()],
                    Vec::<String>::new(),
                    Arc::new(TokioAddressResolver),
                )
                .is_err(),
                "workspace pattern {entry:?}",
            );
            assert!(
                PresignedHttpPolicy::new(
                    [entry.to_string()],
                    Vec::<String>::new(),
                    false,
                    Duration::ZERO,
                    Arc::new(TokioAddressResolver),
                )
                .is_err(),
                "presigned pattern {entry:?}",
            );
        }
        assert!(
            WorkspaceEndpointPolicy::new(
                true,
                Vec::<String>::new(),
                ["*.internal".to_string()],
                Arc::new(TokioAddressResolver),
            )
            .is_err()
        );
        assert!(
            WorkspaceEndpointPolicy::new(
                false,
                ["objects.example".to_string()],
                ["objects.example".to_string()],
                Arc::new(TokioAddressResolver),
            )
            .is_err()
        );
    }

    #[test]
    fn trusted_host_patterns_normalize_and_keep_strict_dns_boundaries() {
        let exact = TrustedHostPattern::parse(" Objects.Example ".to_string()).unwrap();
        assert!(exact.matches("objects.example"));
        assert!(!exact.matches("other.objects.example"));

        let provider = TrustedHostPattern::parse("*.BackblazeB2.com".to_string()).unwrap();
        assert!(provider.matches("s3.us-east-005.backblazeb2.com"));
        assert!(!provider.matches("backblazeb2.com"));
        assert!(!provider.matches("evilbackblazeb2.com"));
        assert!(!provider.matches("backblazeb2.com.evil.example"));

        let presigned = PresignedHttpPolicy::new(
            ["*.BackblazeB2.com".to_string()],
            Vec::<String>::new(),
            false,
            Duration::ZERO,
            Arc::new(TokioAddressResolver),
        )
        .unwrap();
        assert!(presigned.host_allowed("s3.us-east-005.backblazeb2.com"));
        assert!(!presigned.host_allowed("backblazeb2.com"));
    }

    #[test]
    fn every_forbidden_ip_prefix_boundary_is_classified() {
        for (network, prefix) in IPV4_FORBIDDEN_RANGES {
            let host_bits = Ipv4Addr::BITS - u32::from(*prefix);
            let host_mask = u32::MAX.checked_shr(u32::from(*prefix)).unwrap_or(0);
            let last = Ipv4Addr::from(u32::from(*network) | host_mask);
            assert!(
                is_forbidden_endpoint_ip(IpAddr::V4(*network)),
                "{network}/{prefix} network"
            );
            assert!(
                is_forbidden_endpoint_ip(IpAddr::V4(last)),
                "{network}/{prefix} last address ({host_bits} host bits)"
            );
        }

        for (network, prefix) in IPV6_FORBIDDEN_RANGES {
            let host_bits = Ipv6Addr::BITS - u32::from(*prefix);
            let host_mask = u128::MAX.checked_shr(u32::from(*prefix)).unwrap_or(0);
            let last = Ipv6Addr::from(u128::from(*network) | host_mask);
            assert!(
                is_forbidden_endpoint_ip(IpAddr::V6(*network)),
                "{network}/{prefix} network"
            );
            assert!(
                is_forbidden_endpoint_ip(IpAddr::V6(last)),
                "{network}/{prefix} last address ({host_bits} host bits)"
            );
        }
    }

    #[test]
    fn current_special_purpose_examples_are_forbidden() {
        for (address, purpose) in [
            ("0.0.0.0", "this network"),
            ("10.0.0.1", "private"),
            ("100.64.0.1", "shared"),
            ("127.0.0.1", "loopback"),
            ("169.254.169.254", "link local"),
            ("192.0.2.1", "documentation"),
            ("198.18.0.1", "benchmarking"),
            ("224.0.0.1", "multicast"),
            ("240.0.0.1", "reserved"),
            ("::", "unspecified"),
            ("::1", "loopback"),
            ("::ffff:8.8.8.8", "IPv4-mapped IPv6"),
            ("64:ff9b:1::1", "non-global translation"),
            ("100::1", "discard"),
            ("100:0:0:1::1", "dummy"),
            ("2001:2::1", "benchmarking"),
            ("2001:db8::1", "documentation"),
            ("2002::1", "6to4"),
            ("3fff:fff::1", "documentation"),
            ("5f00::1", "segment routing"),
            ("fc00::1", "unique local"),
            ("fe80::1", "link local"),
            ("ff02::1", "multicast"),
        ] {
            assert!(
                is_forbidden_endpoint_ip(address.parse().unwrap()),
                "{purpose}: {address}"
            );
        }
    }

    #[test]
    fn globally_reachable_controls_remain_public() {
        for (address, purpose) in [
            ("8.8.8.8", "ordinary IPv4"),
            ("93.184.216.34", "ordinary IPv4"),
            ("192.0.0.9", "PCP anycast"),
            ("192.0.0.10", "TURN anycast"),
            ("192.31.196.1", "AS112-v4"),
            ("192.52.193.1", "AMT-v4"),
            ("192.175.48.1", "direct AS112-v4"),
            ("64:ff9b::808:808", "global translation"),
            ("2001:1::1", "PCP anycast"),
            ("2001:1::2", "TURN anycast"),
            ("2001:1::3", "DNS-SD anycast"),
            ("2001:3::1", "AMT-v6"),
            ("2001:4:112::1", "AS112-v6"),
            ("2001:20::1", "ORCHIDv2"),
            ("2001:30::1", "DETs"),
            ("2606:4700:4700::1111", "ordinary IPv6"),
            ("2620:4f:8000::1", "direct AS112-v6"),
            ("3fff:1000::1", "outside documentation prefix"),
        ] {
            assert!(
                !is_forbidden_endpoint_ip(address.parse().unwrap()),
                "{purpose}: {address}"
            );
        }
    }

    #[tokio::test]
    async fn policy_requires_https_allowlist_and_expiry() {
        let resolver = Arc::new(StaticResolver {
            addresses: vec!["93.184.216.34:443".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let policy =
            PresignedHttpPolicy::for_test(["objects.example".to_string()], false, resolver);
        assert!(
            policy
                .client_for(&future_url("objects.example"))
                .await
                .is_ok()
        );
        assert!(
            policy
                .client_for(&future_url("other.example"))
                .await
                .is_err()
        );
        assert!(
            policy
                .client_for(&Url::parse("http://objects.example/x?Expires=9999999999").unwrap())
                .await
                .is_err()
        );
        assert!(
            policy
                .client_for(&Url::parse("https://objects.example/x").unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn presigned_http_get_requires_the_operator_flag() {
        let url = Url::parse("http://objects.example/object?Expires=9999999999").unwrap();
        let resolver = Arc::new(StaticResolver {
            addresses: vec!["93.184.216.34:80".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let denied =
            PresignedHttpPolicy::for_test(["objects.example".to_string()], false, resolver.clone());
        assert!(denied.client_for(&url).await.is_err());

        let allowed =
            PresignedHttpPolicy::for_test(["objects.example".to_string()], true, resolver);
        assert!(allowed.client_for(&url).await.is_ok());
    }

    #[tokio::test]
    async fn presigned_http_put_and_delete_are_always_rejected() {
        let url = Url::parse("http://objects.example/object?Expires=9999999999").unwrap();
        let policy = PresignedHttpPolicy::for_test(
            ["objects.example".to_string()],
            true,
            Arc::new(StaticResolver {
                addresses: vec!["93.184.216.34:80".parse().unwrap()],
                calls: AtomicUsize::new(0),
            }),
        );

        for method in ["PUT", "DELETE"] {
            assert!(
                policy
                    .client_for_destination(&url, Duration::ZERO)
                    .await
                    .is_err(),
                "HTTP {method} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn private_and_metadata_addresses_need_exact_admin_exception() {
        for address in ["127.0.0.1:443", "10.0.0.1:443", "169.254.169.254:443"] {
            assert!(is_forbidden_endpoint_ip(
                address.parse::<SocketAddr>().unwrap().ip()
            ));
        }
        assert!(!is_forbidden_endpoint_ip("93.184.216.34".parse().unwrap()));

        let resolver = Arc::new(StaticResolver {
            addresses: vec!["127.0.0.1:443".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let denied = PresignedHttpPolicy::for_test(Vec::<String>::new(), false, resolver.clone());
        assert!(denied.client_for(&future_url("localhost")).await.is_err());

        let allowed = PresignedHttpPolicy::for_test(["localhost".to_string()], false, resolver);
        assert!(allowed.client_for(&future_url("localhost")).await.is_ok());

        let mapped = PresignedHttpPolicy::new(
            Vec::<String>::new(),
            ["objects.internal".to_string()],
            false,
            Duration::ZERO,
            Arc::new(StaticResolver {
                addresses: vec!["[::ffff:127.0.0.1]:443".parse().unwrap()],
                calls: AtomicUsize::new(0),
            }),
        )
        .unwrap();
        assert!(
            mapped
                .client_for(&future_url("objects.internal"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn resolution_occurs_once_and_the_validated_address_is_pinned() {
        let resolver = Arc::new(StaticResolver {
            addresses: vec!["93.184.216.34:443".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let policy =
            PresignedHttpPolicy::for_test(["objects.example".to_string()], false, resolver.clone());
        policy
            .client_for(&future_url("objects.example"))
            .await
            .unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mixed_public_private_dns_answers_are_rejected_without_private_exception() {
        let resolver = Arc::new(StaticResolver {
            addresses: vec![
                "93.184.216.34:443".parse().unwrap(),
                "169.254.169.254:443".parse().unwrap(),
            ],
            calls: AtomicUsize::new(0),
        });
        let policy = PresignedHttpPolicy::new(
            ["*.storage.example.com".to_string()],
            Vec::<String>::new(),
            false,
            Duration::ZERO,
            resolver,
        )
        .unwrap();
        assert!(
            policy
                .client_for(&future_url("objects.storage.example.com"))
                .await
                .is_err()
        );
    }
}
