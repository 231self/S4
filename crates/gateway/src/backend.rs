use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use axum::http::HeaderMap;
use reqwest::Url;

use crate::service_storage::ServiceStorage;
use crate::store::{BackendRegistry, MemoryStore};

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

#[derive(Clone)]
pub enum ResolvedBackend {
    PresignedHttp(Url),
    S3 { kind: BackendKind, client: Client },
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

#[derive(Clone)]
pub struct BackendResolver {
    backends: Arc<BackendRegistry>,
    managed: Arc<ServiceStorage>,
    global_s3: Option<Client>,
    memory: Arc<MemoryStore>,
}

impl BackendResolver {
    pub fn new(
        backends: Arc<BackendRegistry>,
        managed: Arc<ServiceStorage>,
        global_s3: Option<Client>,
        memory: Arc<MemoryStore>,
    ) -> Self {
        Self {
            backends,
            managed,
            global_s3,
            memory,
        }
    }

    pub async fn resolve(
        &self,
        user_id: &str,
        headers: &HeaderMap,
        _operation: StorageOperation,
    ) -> Result<ResolvedBackend, String> {
        if let Some(raw_url) = headers
            .get("x-s4-backend-url")
            .and_then(|value| value.to_str().ok())
        {
            let url =
                Url::parse(raw_url).map_err(|_| "invalid presigned backend URL".to_string())?;
            return Ok(ResolvedBackend::PresignedHttp(url));
        }

        if let Some(config) = self.backends.get(user_id)
            && config.is_configured()
            && !config.endpoint.is_empty()
        {
            let credentials = Credentials::new(
                config.access_key,
                config.secret_key,
                None,
                None,
                "s4-backend",
            );
            let region = if config.region.is_empty() {
                "us-east-1".to_string()
            } else {
                config.region
            };
            let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(Region::new(region))
                .endpoint_url(config.endpoint)
                .credentials_provider(credentials)
                .load()
                .await;
            return Ok(ResolvedBackend::S3 {
                kind: BackendKind::PerUserS3,
                client: Client::new(&sdk_config),
            });
        }

        if !self.managed.is_empty() {
            return Ok(ResolvedBackend::Managed(self.managed.clone()));
        }
        if let Some(client) = &self.global_s3 {
            return Ok(ResolvedBackend::S3 {
                kind: BackendKind::GlobalS3,
                client: client.clone(),
            });
        }
        Ok(ResolvedBackend::Memory(self.memory.clone()))
    }
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
    allowed_hosts: HashSet<String>,
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
    ) -> Self {
        Self {
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            private_allowed_hosts: private_allowed_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            allow_http,
            minimum_validity,
            resolver,
        }
    }

    pub fn from_env() -> Self {
        let allowed_hosts: Vec<String> = std::env::var("S4_PRESIGNED_HTTP_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(|host| host.to_ascii_lowercase())
            .collect();
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
    }

    pub async fn client_for(&self, url: &Url) -> Result<reqwest::Client, String> {
        let host = url
            .host_str()
            .ok_or_else(|| "presigned URL must have a host".to_string())?
            .to_ascii_lowercase();
        if !self.host_allowed(&host) {
            return Err("presigned URL host is not in S4_PRESIGNED_HTTP_ALLOWLIST".to_string());
        }
        match url.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            "http" => return Err("presigned HTTP sources require HTTPS".to_string()),
            _ => return Err("presigned source URL scheme is not supported".to_string()),
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err("presigned URL userinfo and fragments are forbidden".to_string());
        }
        validate_expiry(url, self.minimum_validity)?;

        let port = url
            .port_or_known_default()
            .ok_or_else(|| "presigned URL has no usable port".to_string())?;
        let addresses = self
            .resolver
            .resolve(&host, port)
            .await
            .map_err(|error| format!("presigned URL DNS resolution failed: {error}"))?;
        if addresses.is_empty() {
            return Err("presigned URL DNS resolution returned no addresses".to_string());
        }

        let private_exception = self.private_allowed_hosts.contains(&host);
        if !private_exception && addresses.iter().any(|address| !is_public_ip(address.ip())) {
            return Err("presigned URL resolves to a forbidden address range".to_string());
        }
        let pinned = addresses[0];
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve(&host, pinned)
            .build()
            .map_err(|error| format!("presigned HTTP client construction failed: {error}"))
    }

    fn host_allowed(&self, host: &str) -> bool {
        self.allowed_hosts.contains(host)
            || self.allowed_hosts.iter().any(|allowed| {
                allowed
                    .strip_prefix("*.")
                    .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
            })
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

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !matches!(
        octets,
        [0, ..]
            | [10, ..]
            | [100, 64..=127, ..]
            | [127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 0, 0, ..]
            | [192, 0, 2, ..]
            | [192, 88, 99, ..]
            | [192, 168, ..]
            | [198, 18..=19, ..]
            | [198, 51, 100, ..]
            | [203, 0, 113, ..]
            | [224..=255, ..]
    )
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(ipv4);
    }
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StaticResolver {
        addresses: Vec<SocketAddr>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl AddressResolver for StaticResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.addresses.clone())
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
                    .resolve("user", headers, operation)
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
        use crate::store::BackendConfig;

        let memory = Arc::new(MemoryStore::new());
        let registry = Arc::new(BackendRegistry::new());
        let empty_managed = Arc::new(ServiceStorage::new(Vec::new()));
        let resolver = BackendResolver::new(
            registry.clone(),
            empty_managed.clone(),
            None,
            memory.clone(),
        );
        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::Memory).await;

        let global = test_s3_client().await;
        let resolver = BackendResolver::new(
            registry.clone(),
            empty_managed,
            Some(global.clone()),
            memory.clone(),
        );
        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::GlobalS3).await;

        let managed = Arc::new(ServiceStorage::new(vec![ServiceBackend {
            provider: "test".to_string(),
            endpoint: "https://managed.example".to_string(),
            region: "us-east-1".to_string(),
            bucket: "managed".to_string(),
            access_key: "key".to_string(),
            secret_key: "secret".to_string(),
        }]));
        let resolver = BackendResolver::new(
            registry.clone(),
            managed.clone(),
            Some(global.clone()),
            memory.clone(),
        );
        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::Managed).await;

        registry.set(
            "user",
            BackendConfig {
                backend_type: "s3_compatible".to_string(),
                role_arn: String::new(),
                external_id: String::new(),
                endpoint: "https://user.example".to_string(),
                access_key: "key".to_string(),
                secret_key: "secret".to_string(),
                region: "us-east-1".to_string(),
            },
        );
        let resolver = BackendResolver::new(registry, managed, Some(global), memory);
        assert_operations_resolve_to(&resolver, &HeaderMap::new(), BackendKind::PerUserS3).await;

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
    async fn private_and_metadata_addresses_need_exact_admin_exception() {
        for address in ["127.0.0.1:443", "10.0.0.1:443", "169.254.169.254:443"] {
            assert!(!is_public_ip(address.parse::<SocketAddr>().unwrap().ip()));
        }
        assert!(is_public_ip("93.184.216.34".parse().unwrap()));

        let resolver = Arc::new(StaticResolver {
            addresses: vec!["127.0.0.1:443".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let denied = PresignedHttpPolicy::for_test(Vec::<String>::new(), false, resolver.clone());
        assert!(denied.client_for(&future_url("localhost")).await.is_err());

        let allowed = PresignedHttpPolicy::for_test(["localhost".to_string()], false, resolver);
        assert!(allowed.client_for(&future_url("localhost")).await.is_ok());
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
            ["*.example".to_string()],
            Vec::<String>::new(),
            false,
            Duration::ZERO,
            resolver,
        );
        assert!(
            policy
                .client_for(&future_url("objects.example"))
                .await
                .is_err()
        );
    }
}
