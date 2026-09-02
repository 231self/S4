use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::transaction::{BackendCapabilities, OperationRecord, VersioningCapability};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WorkspaceId(String);

impl WorkspaceId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkspaceStorageError> {
        let value = value.into();
        if !(1..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(WorkspaceStorageError::InvalidConfig(
                "workspace id must be 1-128 ASCII characters from [A-Za-z0-9._-]".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    S3Compatible,
    AwsRole,
    Managed,
}

/// Dashboard request DTO. Secrets are accepted only on writes and are never
/// reused as a response type. JSON uses `backend_type`: `managed` needs no
/// other fields; `s3_compatible` needs `endpoint`, `access_key`, `secret_key`,
/// and `region`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BackendConfigRequest {
    pub backend_type: BackendType,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub role_arn: String,
}

/// Redacted dashboard representation. Credential material is intentionally
/// absent from this type, so a GET cannot serialize it by mistake. Its exact
/// JSON keys are `configured`, `backend_type`, `endpoint`, `region`,
/// `role_arn`, `access_key_configured`, and `secret_key_configured`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct BackendConfigResponse {
    pub configured: bool,
    pub backend_type: Option<BackendType>,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub role_arn: Option<String>,
    pub access_key_configured: bool,
    pub secret_key_configured: bool,
}

impl BackendConfigResponse {
    pub fn unconfigured() -> Self {
        Self {
            configured: false,
            backend_type: None,
            endpoint: None,
            region: None,
            role_arn: None,
            access_key_configured: false,
            secret_key_configured: false,
        }
    }
}

/// Decrypted runtime configuration. This type deliberately implements neither
/// `Serialize` nor `ToSchema`.
#[derive(Clone)]
pub enum RuntimeBackendConfig {
    S3Compatible {
        endpoint: String,
        access_key: String,
        secret_key: String,
        region: String,
    },
    Managed,
}

impl RuntimeBackendConfig {
    pub fn redacted(&self) -> BackendConfigResponse {
        match self {
            Self::S3Compatible {
                endpoint,
                access_key,
                secret_key,
                region,
            } => BackendConfigResponse {
                configured: true,
                backend_type: Some(BackendType::S3Compatible),
                endpoint: Some(endpoint.clone()),
                region: Some(region.clone()),
                role_arn: None,
                access_key_configured: !access_key.is_empty(),
                secret_key_configured: !secret_key.is_empty(),
            },
            Self::Managed => BackendConfigResponse {
                configured: true,
                backend_type: Some(BackendType::Managed),
                endpoint: None,
                region: None,
                role_arn: None,
                access_key_configured: false,
                secret_key_configured: false,
            },
        }
    }
}

fn validate_opaque_identity(kind: &str, value: String) -> Result<String, WorkspaceStorageError> {
    if !(1..=160).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(WorkspaceStorageError::InvalidConfig(format!(
            "{kind} must be 1-160 ASCII characters from [A-Za-z0-9._:-]"
        )));
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BackendConfigVersionId(String);

impl BackendConfigVersionId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkspaceStorageError> {
        validate_opaque_identity("backend config version", value.into()).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityAttestationId(String);

impl CapabilityAttestationId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkspaceStorageError> {
        validate_opaque_identity("capability attestation id", value.into()).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S3ProviderFamily {
    Aws,
    Gcs,
    B2,
    R2,
    DigitalOcean,
    Wasabi,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct S3StreamingPermissions {
    pub put_object: bool,
    pub create_multipart_upload: bool,
    pub upload_part: bool,
    pub complete_multipart_upload: bool,
    pub abort_multipart_upload: bool,
    pub list_multipart_uploads: bool,
    pub list_parts: bool,
    pub head_object: bool,
    pub read_operation_metadata: bool,
    pub list_object_versions: bool,
    pub delete_object_version: bool,
}

impl S3StreamingPermissions {
    fn validates_streaming(self, exact_version_recovery: bool) -> bool {
        self.put_object
            && self.create_multipart_upload
            && self.upload_part
            && self.complete_multipart_upload
            && self.abort_multipart_upload
            && self.list_multipart_uploads
            && self.list_parts
            && self.head_object
            && self.read_operation_metadata
            && (!exact_version_recovery
                || (self.list_object_versions && self.delete_object_version))
    }
}

/// Operator-issued statement about one immutable backend configuration.
///
/// The public engine never manufactures this from an endpoint. Hosted adapters
/// must persist it only after provider conformance and credential-permission
/// checks have succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3CapabilityAttestation {
    pub id: CapabilityAttestationId,
    pub provider: S3ProviderFamily,
    pub capabilities: BackendCapabilities,
    pub permissions: S3StreamingPermissions,
    pub exact_version_recovery: bool,
}

impl S3CapabilityAttestation {
    pub fn validate(&self) -> Result<(), WorkspaceStorageError> {
        self.capabilities.streaming_eligibility().map_err(|_| {
            WorkspaceStorageError::UnsupportedConfig(
                "provider capability attestation is not streaming-eligible".to_string(),
            )
        })?;
        if !self
            .permissions
            .validates_streaming(self.exact_version_recovery)
        {
            return Err(WorkspaceStorageError::UnsupportedConfig(
                "provider permission attestation is incomplete".to_string(),
            ));
        }
        if self.provider == S3ProviderFamily::B2
            && (!self.exact_version_recovery
                || self.capabilities.versioning == VersioningCapability::Unsupported)
        {
            return Err(WorkspaceStorageError::UnsupportedConfig(
                "B2 streaming requires exact version recovery attestation".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceStreamingBackendIdentity {
    pub config_version: BackendConfigVersionId,
    pub attestation: S3CapabilityAttestation,
}

/// Durable routing authority held for the lifetime of one provider mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceOperationLease {
    pub operation_id: Uuid,
    pub lease_id: Uuid,
    pub config_version: BackendConfigVersionId,
    pub attestation_id: CapabilityAttestationId,
    pub routing_epoch: u64,
    pub fencing_token: u64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceOperationOutcome {
    Committed,
    ProvenAborted,
}

/// Persisted state of a workspace storage-mode transition.
///
/// Managed mutations may only commit against a `Stable` routing epoch. The
/// directional states let an adapter fence new work while it reconciles work
/// captured under the previous epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceStorageTransitionState {
    Stable,
    TransitioningToManaged,
    TransitioningToS3Compatible,
}

/// Routing fence returned atomically with the runtime backend configuration.
///
/// `Unfenced` is the compatibility default for repositories that have not yet
/// persisted routing epochs. It is intentionally explicit so managed commit
/// code cannot mistake a synthetic epoch for a durable fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceStorageRouting {
    Unfenced,
    Persisted {
        routing_epoch: u64,
        transition_state: WorkspaceStorageTransitionState,
    },
}

impl WorkspaceStorageRouting {
    /// Epoch that a managed mutation may capture for a fenced commit.
    pub fn stable_epoch(self) -> Option<u64> {
        match self {
            Self::Persisted {
                routing_epoch,
                transition_state: WorkspaceStorageTransitionState::Stable,
            } => Some(routing_epoch),
            Self::Unfenced | Self::Persisted { .. } => None,
        }
    }

    pub fn is_transitioning(self) -> bool {
        matches!(self, Self::Persisted { .. }) && self.stable_epoch().is_none()
    }
}

/// Atomic runtime snapshot used to select a backend and capture its routing
/// fence. Credential-bearing configuration remains non-serializable.
#[derive(Clone)]
pub struct WorkspaceStorageResolution {
    pub config: Option<RuntimeBackendConfig>,
    pub routing: WorkspaceStorageRouting,
    pub streaming: Option<WorkspaceStreamingBackendIdentity>,
}

impl WorkspaceStorageResolution {
    pub fn unfenced(config: Option<RuntimeBackendConfig>) -> Self {
        Self {
            config,
            routing: WorkspaceStorageRouting::Unfenced,
            streaming: None,
        }
    }

    pub fn persisted(
        config: Option<RuntimeBackendConfig>,
        routing_epoch: u64,
        transition_state: WorkspaceStorageTransitionState,
    ) -> Self {
        Self {
            config,
            routing: WorkspaceStorageRouting::Persisted {
                routing_epoch,
                transition_state,
            },
            streaming: None,
        }
    }

    pub fn persisted_attested(
        config: RuntimeBackendConfig,
        routing_epoch: u64,
        streaming: WorkspaceStreamingBackendIdentity,
    ) -> Self {
        Self {
            config: Some(config),
            routing: WorkspaceStorageRouting::Persisted {
                routing_epoch,
                transition_state: WorkspaceStorageTransitionState::Stable,
            },
            streaming: Some(streaming),
        }
    }
}

impl TryFrom<BackendConfigRequest> for RuntimeBackendConfig {
    type Error = WorkspaceStorageError;

    fn try_from(request: BackendConfigRequest) -> Result<Self, Self::Error> {
        match request.backend_type {
            BackendType::AwsRole => Err(WorkspaceStorageError::UnsupportedConfig(
                "aws_role backend authentication is not implemented".to_string(),
            )),
            BackendType::Managed => {
                if [
                    request.endpoint,
                    request.access_key,
                    request.secret_key,
                    request.region,
                    request.role_arn,
                ]
                .iter()
                .any(|value| !value.trim().is_empty())
                {
                    return Err(WorkspaceStorageError::InvalidConfig(
                        "managed backend configuration must not include endpoint, region, role, or credentials"
                            .to_string(),
                    ));
                }
                Ok(Self::Managed)
            }
            BackendType::S3Compatible => {
                for (name, value) in [
                    ("endpoint", request.endpoint.as_str()),
                    ("access_key", request.access_key.as_str()),
                    ("secret_key", request.secret_key.as_str()),
                    ("region", request.region.as_str()),
                ] {
                    if value.trim().is_empty() {
                        return Err(WorkspaceStorageError::InvalidConfig(format!(
                            "{name} is required for s3_compatible backends"
                        )));
                    }
                }
                let endpoint = reqwest::Url::parse(&request.endpoint).map_err(|_| {
                    WorkspaceStorageError::InvalidConfig(
                        "endpoint must be an absolute HTTP(S) URL".to_string(),
                    )
                })?;
                if !matches!(endpoint.scheme(), "http" | "https")
                    || endpoint.host_str().is_none()
                    || !endpoint.username().is_empty()
                    || endpoint.password().is_some()
                    || endpoint.query().is_some()
                    || endpoint.fragment().is_some()
                {
                    return Err(WorkspaceStorageError::InvalidConfig(
                        "endpoint must be an absolute HTTP(S) origin without credentials, query, or fragment"
                            .to_string(),
                    ));
                }
                Ok(Self::S3Compatible {
                    endpoint: request.endpoint,
                    access_key: request.access_key,
                    secret_key: request.secret_key,
                    region: request.region,
                })
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceStorageError {
    #[error("invalid workspace storage configuration: {0}")]
    InvalidConfig(String),
    #[error("unsupported workspace storage configuration: {0}")]
    UnsupportedConfig(String),
    #[error("workspace storage repository failed: {0}")]
    Repository(String),
    #[error("workspace streaming admission outcome is ambiguous: {0}")]
    AmbiguousAdmission(String),
}

/// Public injection seam for private workspace mapping and encrypted backend
/// persistence. Implementations may map many users to one opaque workspace.
#[async_trait]
pub trait WorkspaceStorageRepository: Send + Sync + 'static {
    async fn resolve_workspace(&self, user_id: &str) -> Result<WorkspaceId, WorkspaceStorageError>;

    async fn get_runtime_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<RuntimeBackendConfig>, WorkspaceStorageError>;

    /// Returns configuration and its routing fence from one repository
    /// snapshot. Persisted adapters should override this when they add routing
    /// epochs; the default preserves existing adapters while marking them as
    /// explicitly unfenced.
    async fn get_runtime_resolution(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<WorkspaceStorageResolution, WorkspaceStorageError> {
        Ok(WorkspaceStorageResolution::unfenced(
            self.get_runtime_config(workspace_id).await?,
        ))
    }

    /// Loads an immutable historical config version, including credentials.
    /// Implementations must retain versions while any operation lease or
    /// nonterminal journal row references them.
    async fn get_runtime_resolution_by_version(
        &self,
        _workspace_id: &WorkspaceId,
        _config_version: &BackendConfigVersionId,
    ) -> Result<WorkspaceStorageResolution, WorkspaceStorageError> {
        Err(WorkspaceStorageError::UnsupportedConfig(
            "historical workspace backend resolution is not implemented".to_string(),
        ))
    }

    /// Atomically verifies the active config/attestation/epoch, creates its
    /// route lease, and inserts `operation` as an INTENT journal row with the
    /// returned lease identity bound into its destination. The supplied
    /// operation must not already contain a workspace binding. Config
    /// transition or retirement must conflict while the lease or journal row
    /// is nonterminal. An unknown transaction result must return
    /// `AmbiguousAdmission`; callers preserve billing and recover by operation
    /// ID instead of releasing a lease that may have committed.
    async fn admit_streaming_operation(
        &self,
        _workspace_id: &WorkspaceId,
        _operation: &OperationRecord,
        _config_version: &BackendConfigVersionId,
        _attestation_id: &CapabilityAttestationId,
        _routing_epoch: u64,
        _ttl: Duration,
    ) -> Result<WorkspaceOperationLease, WorkspaceStorageError> {
        Err(WorkspaceStorageError::UnsupportedConfig(
            "atomic durable workspace streaming admission is not implemented".to_string(),
        ))
    }

    async fn renew_streaming_operation_lease(
        &self,
        _workspace_id: &WorkspaceId,
        _lease: &WorkspaceOperationLease,
        _ttl: Duration,
    ) -> Result<WorkspaceOperationLease, WorkspaceStorageError> {
        Err(WorkspaceStorageError::UnsupportedConfig(
            "durable workspace streaming operation leases are not implemented".to_string(),
        ))
    }

    async fn assert_streaming_operation_lease(
        &self,
        _workspace_id: &WorkspaceId,
        _lease: &WorkspaceOperationLease,
    ) -> Result<(), WorkspaceStorageError> {
        Err(WorkspaceStorageError::UnsupportedConfig(
            "durable workspace streaming operation leases are not implemented".to_string(),
        ))
    }

    /// Reclaims an expired exact durable lease after process loss.
    ///
    /// The implementation must atomically verify that the operation journal is
    /// nonterminal and owned by `journal_claim_owner`, compare every field in
    /// `expected` identity (including lease ID and fencing token), reject an unexpired
    /// route lease, advance its fencing token, and persist that new token in the
    /// operation journal binding. It must never substitute the current config
    /// for the operation's historical version.
    async fn recover_streaming_operation_lease(
        &self,
        _workspace_id: &WorkspaceId,
        _expected: &WorkspaceOperationLease,
        _journal_claim_owner: &str,
        _ttl: Duration,
    ) -> Result<WorkspaceOperationLease, WorkspaceStorageError> {
        Err(WorkspaceStorageError::UnsupportedConfig(
            "durable workspace streaming operation recovery is not implemented".to_string(),
        ))
    }

    /// Settles the route lease after the journal reaches the matching terminal
    /// state. Implementations must verify that journal state and every persisted
    /// lease identity field (expiry is not journaled) in the same transaction.
    /// Repeating the same settlement is an idempotent success; conflicting
    /// identities or outcomes fail closed.
    async fn release_streaming_operation_lease(
        &self,
        _workspace_id: &WorkspaceId,
        _lease: &WorkspaceOperationLease,
        _outcome: WorkspaceOperationOutcome,
    ) -> Result<(), WorkspaceStorageError> {
        Err(WorkspaceStorageError::UnsupportedConfig(
            "durable workspace streaming operation leases are not implemented".to_string(),
        ))
    }

    async fn get_public_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError>;

    async fn put_config(
        &self,
        workspace_id: &WorkspaceId,
        request: BackendConfigRequest,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError>;
}

#[derive(Default)]
pub struct InMemoryWorkspaceStorageRepository {
    configs: RwLock<HashMap<WorkspaceId, RuntimeBackendConfig>>,
}

impl InMemoryWorkspaceStorageRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WorkspaceStorageRepository for InMemoryWorkspaceStorageRepository {
    async fn resolve_workspace(&self, user_id: &str) -> Result<WorkspaceId, WorkspaceStorageError> {
        WorkspaceId::new(user_id)
    }

    async fn get_runtime_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<RuntimeBackendConfig>, WorkspaceStorageError> {
        Ok(self.configs.read().await.get(workspace_id).cloned())
    }

    async fn get_public_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
        Ok(self
            .configs
            .read()
            .await
            .get(workspace_id)
            .map(RuntimeBackendConfig::redacted)
            .unwrap_or_else(BackendConfigResponse::unconfigured))
    }

    async fn put_config(
        &self,
        workspace_id: &WorkspaceId,
        request: BackendConfigRequest,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
        let config = RuntimeBackendConfig::try_from(request)?;
        let response = config.redacted();
        self.configs
            .write()
            .await
            .insert(workspace_id.clone(), config);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;

    use crate::transaction::{
        CompletionReconciliation, ConditionalReadCapability, IncompleteUploadDiscovery,
        ListCapability, MultipartResponseCapability, ResponseChecksumCapability,
    };

    fn attested_identity(
        provider: S3ProviderFamily,
        version: &str,
    ) -> WorkspaceStreamingBackendIdentity {
        WorkspaceStreamingBackendIdentity {
            config_version: BackendConfigVersionId::new(version).unwrap(),
            attestation: S3CapabilityAttestation {
                id: CapabilityAttestationId::new(format!("attestation-{version}")).unwrap(),
                provider,
                capabilities: BackendCapabilities {
                    incomplete_upload_discovery: IncompleteUploadDiscovery::ExactKeyAndStartTime,
                    abort_incomplete_upload: true,
                    cleanup_sla: Some(Duration::from_secs(60)),
                    lifecycle_rule: false,
                    versioning: VersioningCapability::Optional,
                    conditional_reads: ConditionalReadCapability::Etag,
                    response_checksums: ResponseChecksumCapability::Unsupported,
                    list_operations: ListCapability::V1AndV2,
                    multipart_responses: MultipartResponseCapability::Standard,
                    completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
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
                exact_version_recovery: provider == S3ProviderFamily::B2,
            },
        }
    }

    fn attested_resolution(version: &str, epoch: u64) -> WorkspaceStorageResolution {
        WorkspaceStorageResolution::persisted_attested(
            RuntimeBackendConfig::S3Compatible {
                endpoint: "https://s3.us-east-1.amazonaws.com".to_string(),
                access_key: format!("access-{version}"),
                secret_key: format!("secret-{version}"),
                region: "us-east-1".to_string(),
            },
            epoch,
            attested_identity(S3ProviderFamily::Aws, version),
        )
    }

    #[derive(Default)]
    struct DurableContractRepository {
        versions: RwLock<HashMap<String, WorkspaceStorageResolution>>,
        active: RwLock<Option<(String, u64)>>,
        leases: RwLock<HashMap<Uuid, WorkspaceOperationLease>>,
        settled: RwLock<HashMap<Uuid, WorkspaceOperationOutcome>>,
        admitted_operations: RwLock<HashMap<Uuid, OperationRecord>>,
        lose_next_admission_response: AtomicBool,
        fence: AtomicU64,
    }

    impl DurableContractRepository {
        fn same_lease_identity(
            stored: &WorkspaceOperationLease,
            expected: &WorkspaceOperationLease,
        ) -> bool {
            stored.operation_id == expected.operation_id
                && stored.lease_id == expected.lease_id
                && stored.config_version == expected.config_version
                && stored.attestation_id == expected.attestation_id
                && stored.routing_epoch == expected.routing_epoch
                && stored.fencing_token == expected.fencing_token
        }

        async fn install(&self, version: &str, epoch: u64) {
            self.versions
                .write()
                .await
                .insert(version.to_string(), attested_resolution(version, epoch));
            if self.active.read().await.is_none() {
                *self.active.write().await = Some((version.to_string(), epoch));
            }
        }

        async fn activate(&self, version: &str, epoch: u64) -> Result<(), WorkspaceStorageError> {
            if !self.leases.read().await.is_empty() {
                return Err(WorkspaceStorageError::Repository(
                    "open operations fence config transition".to_string(),
                ));
            }
            if !self.versions.read().await.contains_key(version) {
                return Err(WorkspaceStorageError::Repository(
                    "config version does not exist".to_string(),
                ));
            }
            *self.active.write().await = Some((version.to_string(), epoch));
            Ok(())
        }

        async fn force_active_for_test(&self, version: &str, epoch: u64) {
            *self.active.write().await = Some((version.to_string(), epoch));
        }
    }

    #[async_trait]
    impl WorkspaceStorageRepository for DurableContractRepository {
        async fn resolve_workspace(
            &self,
            user_id: &str,
        ) -> Result<WorkspaceId, WorkspaceStorageError> {
            WorkspaceId::new(user_id)
        }

        async fn get_runtime_config(
            &self,
            workspace_id: &WorkspaceId,
        ) -> Result<Option<RuntimeBackendConfig>, WorkspaceStorageError> {
            Ok(self.get_runtime_resolution(workspace_id).await?.config)
        }

        async fn get_runtime_resolution(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<WorkspaceStorageResolution, WorkspaceStorageError> {
            let (version, _) =
                self.active.read().await.clone().ok_or_else(|| {
                    WorkspaceStorageError::Repository("no active config".to_string())
                })?;
            self.versions
                .read()
                .await
                .get(&version)
                .cloned()
                .ok_or_else(|| WorkspaceStorageError::Repository("missing config".to_string()))
        }

        async fn get_runtime_resolution_by_version(
            &self,
            _workspace_id: &WorkspaceId,
            config_version: &BackendConfigVersionId,
        ) -> Result<WorkspaceStorageResolution, WorkspaceStorageError> {
            self.versions
                .read()
                .await
                .get(config_version.as_str())
                .cloned()
                .ok_or_else(|| {
                    WorkspaceStorageError::Repository("historical config missing".to_string())
                })
        }

        async fn admit_streaming_operation(
            &self,
            _workspace_id: &WorkspaceId,
            operation: &OperationRecord,
            config_version: &BackendConfigVersionId,
            attestation_id: &CapabilityAttestationId,
            routing_epoch: u64,
            ttl: Duration,
        ) -> Result<WorkspaceOperationLease, WorkspaceStorageError> {
            if operation.state != crate::transaction::OperationState::Intent
                || operation.destination.workspace_binding.is_some()
            {
                return Err(WorkspaceStorageError::Repository(
                    "invalid atomic admission intent".to_string(),
                ));
            }
            let active = self.active.read().await.clone();
            if active.as_ref() != Some(&(config_version.as_str().to_string(), routing_epoch)) {
                return Err(WorkspaceStorageError::Repository(
                    "routing identity changed".to_string(),
                ));
            }
            let resolution = self
                .versions
                .read()
                .await
                .get(config_version.as_str())
                .cloned()
                .ok_or_else(|| WorkspaceStorageError::Repository("missing config".to_string()))?;
            if resolution
                .streaming
                .as_ref()
                .map(|value| &value.attestation.id)
                != Some(attestation_id)
            {
                return Err(WorkspaceStorageError::Repository(
                    "attestation changed".to_string(),
                ));
            }
            let lease = WorkspaceOperationLease {
                operation_id: operation.id,
                lease_id: Uuid::now_v7(),
                config_version: config_version.clone(),
                attestation_id: attestation_id.clone(),
                routing_epoch,
                fencing_token: self.fence.fetch_add(1, Ordering::SeqCst) + 1,
                expires_at_ms: now_ms().saturating_add(i64::try_from(ttl.as_millis()).unwrap()),
            };
            self.leases
                .write()
                .await
                .insert(operation.id, lease.clone());
            self.admitted_operations
                .write()
                .await
                .insert(operation.id, operation.clone());
            if self
                .lose_next_admission_response
                .swap(false, Ordering::AcqRel)
            {
                return Err(WorkspaceStorageError::AmbiguousAdmission(
                    "injected post-commit response loss".to_string(),
                ));
            }
            Ok(lease)
        }

        async fn renew_streaming_operation_lease(
            &self,
            _workspace_id: &WorkspaceId,
            lease: &WorkspaceOperationLease,
            ttl: Duration,
        ) -> Result<WorkspaceOperationLease, WorkspaceStorageError> {
            let active = self.active.read().await.clone();
            if active.as_ref()
                != Some(&(
                    lease.config_version.as_str().to_string(),
                    lease.routing_epoch,
                ))
            {
                return Err(WorkspaceStorageError::Repository(
                    "routing epoch advanced".to_string(),
                ));
            }
            let mut leases = self.leases.write().await;
            let stored = leases.get_mut(&lease.operation_id).ok_or_else(|| {
                WorkspaceStorageError::Repository("operation lease missing".to_string())
            })?;
            if stored.lease_id != lease.lease_id || stored.fencing_token != lease.fencing_token {
                return Err(WorkspaceStorageError::Repository(
                    "operation lease was fenced".to_string(),
                ));
            }
            if stored.expires_at_ms <= now_ms() {
                return Err(WorkspaceStorageError::Repository(
                    "operation lease expired".to_string(),
                ));
            }
            stored.expires_at_ms = now_ms().saturating_add(i64::try_from(ttl.as_millis()).unwrap());
            Ok(stored.clone())
        }

        async fn assert_streaming_operation_lease(
            &self,
            workspace_id: &WorkspaceId,
            lease: &WorkspaceOperationLease,
        ) -> Result<(), WorkspaceStorageError> {
            let leases = self.leases.read().await;
            let stored = leases.get(&lease.operation_id).ok_or_else(|| {
                WorkspaceStorageError::Repository("operation lease missing".to_string())
            })?;
            if stored != lease || stored.expires_at_ms <= now_ms() {
                return Err(WorkspaceStorageError::Repository(
                    "operation lease was fenced or expired".to_string(),
                ));
            }
            let _ = workspace_id;
            Ok(())
        }

        async fn recover_streaming_operation_lease(
            &self,
            _workspace_id: &WorkspaceId,
            expected: &WorkspaceOperationLease,
            journal_claim_owner: &str,
            ttl: Duration,
        ) -> Result<WorkspaceOperationLease, WorkspaceStorageError> {
            if journal_claim_owner.is_empty() {
                return Err(WorkspaceStorageError::Repository(
                    "journal operation is not claimed".to_string(),
                ));
            }
            let mut leases = self.leases.write().await;
            let lease = leases.get_mut(&expected.operation_id).ok_or_else(|| {
                WorkspaceStorageError::Repository("operation lease missing".to_string())
            })?;
            if !Self::same_lease_identity(lease, expected) {
                return Err(WorkspaceStorageError::Repository(
                    "historical operation identity changed".to_string(),
                ));
            }
            if lease.expires_at_ms > now_ms() {
                return Err(WorkspaceStorageError::Repository(
                    "operation lease is still active".to_string(),
                ));
            }
            lease.fencing_token = self.fence.fetch_add(1, Ordering::SeqCst) + 1;
            lease.expires_at_ms = now_ms().saturating_add(i64::try_from(ttl.as_millis()).unwrap());
            Ok(lease.clone())
        }

        async fn release_streaming_operation_lease(
            &self,
            _workspace_id: &WorkspaceId,
            lease: &WorkspaceOperationLease,
            outcome: WorkspaceOperationOutcome,
        ) -> Result<(), WorkspaceStorageError> {
            if let Some(settled) = self.settled.read().await.get(&lease.operation_id) {
                return if *settled == outcome {
                    Ok(())
                } else {
                    Err(WorkspaceStorageError::Repository(
                        "operation lease outcome changed".to_string(),
                    ))
                };
            }
            let mut leases = self.leases.write().await;
            if !leases
                .get(&lease.operation_id)
                .is_some_and(|stored| Self::same_lease_identity(stored, lease))
            {
                return Err(WorkspaceStorageError::Repository(
                    "operation lease was fenced".to_string(),
                ));
            }
            leases.remove(&lease.operation_id);
            self.settled
                .write()
                .await
                .insert(lease.operation_id, outcome);
            Ok(())
        }

        async fn get_public_config(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
            Ok(BackendConfigResponse::unconfigured())
        }

        async fn put_config(
            &self,
            _workspace_id: &WorkspaceId,
            _request: BackendConfigRequest,
        ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
            Err(WorkspaceStorageError::UnsupportedConfig(
                "test repository mutation uses install".to_string(),
            ))
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64
    }

    #[tokio::test]
    async fn durable_streaming_contract_fences_versions_and_recovers_exact_history() {
        let repository = DurableContractRepository::default();
        repository.install("config-v1", 1).await;
        repository.install("config-v2", 2).await;
        let workspace = WorkspaceId::new("workspace-a").unwrap();
        let identity = attested_identity(S3ProviderFamily::Aws, "config-v1");
        let operation_id = Uuid::now_v7();
        let lease = repository
            .admit_streaming_operation(
                &workspace,
                &OperationRecord::direct_intent(
                    crate::transaction::DirectOperationScope {
                        operation_id,
                        tenant_id: workspace.as_str().to_string(),
                    },
                    crate::transaction::ObjectDestination {
                        backend_id: "PerUserS3".to_string(),
                        bucket: "bucket".to_string(),
                        logical_key: "key".to_string(),
                        physical_key: "key".to_string(),
                        workspace_binding: None,
                    },
                    crate::transaction::ExpectedObject::default(),
                ),
                &identity.config_version,
                &identity.attestation.id,
                1,
                Duration::from_millis(20),
            )
            .await
            .unwrap();

        assert!(repository.activate("config-v2", 2).await.is_err());
        assert_eq!(
            repository
                .get_runtime_resolution_by_version(&workspace, &identity.config_version)
                .await
                .unwrap()
                .streaming
                .unwrap(),
            identity
        );
        assert!(
            repository
                .recover_streaming_operation_lease(
                    &workspace,
                    &lease,
                    "reconciler-a",
                    Duration::from_secs(30),
                )
                .await
                .is_err(),
            "an active route lease must never be stolen"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
        let recovered = repository
            .recover_streaming_operation_lease(
                &workspace,
                &lease,
                "reconciler-a",
                Duration::from_secs(30),
            )
            .await
            .unwrap();
        assert_eq!(recovered.lease_id, lease.lease_id);
        assert!(recovered.fencing_token > lease.fencing_token);

        repository.force_active_for_test("config-v2", 2).await;
        assert!(
            repository
                .renew_streaming_operation_lease(&workspace, &recovered, Duration::from_secs(30))
                .await
                .is_err()
        );
        repository.force_active_for_test("config-v1", 1).await;
        let restored = repository
            .renew_streaming_operation_lease(&workspace, &recovered, Duration::from_secs(30))
            .await
            .unwrap();
        repository
            .release_streaming_operation_lease(
                &workspace,
                &restored,
                WorkspaceOperationOutcome::Committed,
            )
            .await
            .unwrap();
        repository
            .release_streaming_operation_lease(
                &workspace,
                &restored,
                WorkspaceOperationOutcome::Committed,
            )
            .await
            .unwrap();
        repository.activate("config-v2", 2).await.unwrap();
    }

    #[tokio::test]
    async fn expired_route_recovery_is_exact_cas_and_has_one_concurrent_winner() {
        let repository = Arc::new(DurableContractRepository::default());
        repository.install("config-v1", 1).await;
        let workspace = WorkspaceId::new("workspace-a").unwrap();
        let identity = attested_identity(S3ProviderFamily::Aws, "config-v1");
        let lease = repository
            .admit_streaming_operation(
                &workspace,
                &OperationRecord::direct_intent(
                    crate::transaction::DirectOperationScope {
                        operation_id: Uuid::now_v7(),
                        tenant_id: workspace.as_str().to_string(),
                    },
                    crate::transaction::ObjectDestination {
                        backend_id: "PerUserS3".to_string(),
                        bucket: "bucket".to_string(),
                        logical_key: "key".to_string(),
                        physical_key: "key".to_string(),
                        workspace_binding: None,
                    },
                    crate::transaction::ExpectedObject::default(),
                ),
                &identity.config_version,
                &identity.attestation.id,
                1,
                Duration::from_millis(20),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;

        let first_repository = repository.clone();
        let first_workspace = workspace.clone();
        let first_expected = lease.clone();
        let first = tokio::spawn(async move {
            first_repository
                .recover_streaming_operation_lease(
                    &first_workspace,
                    &first_expected,
                    "reconciler-a",
                    Duration::from_secs(30),
                )
                .await
        });
        let second_repository = repository.clone();
        let second_workspace = workspace.clone();
        let second_expected = lease.clone();
        let second = tokio::spawn(async move {
            second_repository
                .recover_streaming_operation_lease(
                    &second_workspace,
                    &second_expected,
                    "reconciler-b",
                    Duration::from_secs(30),
                )
                .await
        });
        let (first, second) = tokio::join!(first, second);
        let winners = [first.unwrap(), second.unwrap()]
            .into_iter()
            .filter(Result::is_ok)
            .count();
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn atomic_admission_has_no_route_only_orphan_on_unknown_response() {
        let repository = DurableContractRepository::default();
        repository.install("config-v1", 1).await;
        repository
            .lose_next_admission_response
            .store(true, Ordering::Release);
        let workspace = WorkspaceId::new("workspace-a").unwrap();
        let identity = attested_identity(S3ProviderFamily::Aws, "config-v1");
        let operation = OperationRecord::direct_intent(
            crate::transaction::DirectOperationScope {
                operation_id: Uuid::now_v7(),
                tenant_id: workspace.as_str().to_string(),
            },
            crate::transaction::ObjectDestination {
                backend_id: "PerUserS3".to_string(),
                bucket: "bucket".to_string(),
                logical_key: "key".to_string(),
                physical_key: "key".to_string(),
                workspace_binding: None,
            },
            crate::transaction::ExpectedObject::default(),
        );

        assert!(matches!(
            repository
                .admit_streaming_operation(
                    &workspace,
                    &operation,
                    &identity.config_version,
                    &identity.attestation.id,
                    1,
                    Duration::from_secs(30),
                )
                .await,
            Err(WorkspaceStorageError::AmbiguousAdmission(_))
        ));
        assert!(repository.leases.read().await.contains_key(&operation.id));
        assert!(
            repository
                .admitted_operations
                .read()
                .await
                .contains_key(&operation.id)
        );
    }

    #[tokio::test]
    async fn legacy_repository_defaults_keep_per_user_streaming_fail_closed() {
        let repository = InMemoryWorkspaceStorageRepository::new();
        let workspace = WorkspaceId::new("workspace-a").unwrap();
        let version = BackendConfigVersionId::new("config-v1").unwrap();
        let attestation = CapabilityAttestationId::new("attestation-v1").unwrap();
        assert!(
            repository
                .admit_streaming_operation(
                    &workspace,
                    &OperationRecord::direct_intent(
                        crate::transaction::DirectOperationScope {
                            operation_id: Uuid::now_v7(),
                            tenant_id: workspace.as_str().to_string(),
                        },
                        crate::transaction::ObjectDestination {
                            backend_id: "PerUserS3".to_string(),
                            bucket: "bucket".to_string(),
                            logical_key: "key".to_string(),
                            physical_key: "key".to_string(),
                            workspace_binding: None,
                        },
                        crate::transaction::ExpectedObject::default(),
                    ),
                    &version,
                    &attestation,
                    1,
                    Duration::from_secs(30),
                )
                .await
                .is_err()
        );
        assert!(
            repository
                .get_runtime_resolution_by_version(&workspace, &version)
                .await
                .is_err()
        );
    }

    #[test]
    fn b2_attestation_requires_exact_version_and_limited_key_permissions() {
        let mut identity = attested_identity(S3ProviderFamily::B2, "b2-v1");
        assert!(identity.attestation.validate().is_ok());
        assert_eq!(
            identity.attestation.capabilities.response_checksums,
            ResponseChecksumCapability::Unsupported,
            "B2 attestation must not claim unsupported response checksum semantics"
        );
        identity.attestation.permissions.list_object_versions = false;
        assert!(identity.attestation.validate().is_err());
        identity.attestation.permissions.list_object_versions = true;
        identity.attestation.permissions.delete_object_version = false;
        assert!(identity.attestation.validate().is_err());
        identity.attestation.permissions.delete_object_version = true;
        identity.attestation.exact_version_recovery = false;
        assert!(identity.attestation.validate().is_err());
    }

    #[test]
    fn workspace_ids_are_bounded_canonical_ascii() {
        let maximum = "a".repeat(128);
        for valid in ["a", "Workspace_01.prod", maximum.as_str()] {
            assert_eq!(WorkspaceId::new(valid).unwrap().as_str(), valid);
        }
        let too_long = "a".repeat(129);
        for invalid in [
            "",
            "workspace/child",
            "workspace\\child",
            "workspace child",
            "workspace\nchild",
            "workspace\0child",
            "w\u{f6}rkspace",
            too_long.as_str(),
        ] {
            assert!(
                matches!(
                    WorkspaceId::new(invalid),
                    Err(WorkspaceStorageError::InvalidConfig(_))
                ),
                "accepted invalid workspace id {invalid:?}",
            );
        }
    }

    #[tokio::test]
    async fn distinct_canonical_workspace_ids_do_not_collide() {
        let repository = InMemoryWorkspaceStorageRepository::new();
        let dotted = WorkspaceId::new("tenant.prod").unwrap();
        let dashed = WorkspaceId::new("tenant-prod").unwrap();
        repository
            .put_config(&dotted, valid_request())
            .await
            .unwrap();

        assert!(
            repository
                .get_runtime_config(&dotted)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            repository
                .get_runtime_config(&dashed)
                .await
                .unwrap()
                .is_none()
        );
        assert!(WorkspaceId::new("tenant/prod").is_err());
    }

    fn valid_request() -> BackendConfigRequest {
        BackendConfigRequest {
            backend_type: BackendType::S3Compatible,
            endpoint: "https://objects.example".to_string(),
            access_key: "access".to_string(),
            secret_key: "secret".to_string(),
            region: "us-east-1".to_string(),
            role_arn: String::new(),
        }
    }

    #[tokio::test]
    async fn in_memory_repository_is_async_redacted_and_defaults_to_no_config() {
        let repository = InMemoryWorkspaceStorageRepository::new();
        let workspace = repository.resolve_workspace("user-1").await.unwrap();
        assert_eq!(workspace.as_str(), "user-1");
        assert_eq!(
            repository.get_public_config(&workspace).await.unwrap(),
            BackendConfigResponse::unconfigured()
        );

        let response = repository
            .put_config(&workspace, valid_request())
            .await
            .unwrap();
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["configured"], true);
        assert!(json.get("access_key").is_none());
        assert!(json.get("secret_key").is_none());
        assert!(
            repository
                .get_runtime_config(&workspace)
                .await
                .unwrap()
                .is_some()
        );
        let resolution = repository.get_runtime_resolution(&workspace).await.unwrap();
        assert_eq!(resolution.routing, WorkspaceStorageRouting::Unfenced);
        assert!(resolution.config.is_some());
    }

    #[test]
    fn persisted_runtime_resolution_carries_epoch_and_transition_state() {
        let resolution = WorkspaceStorageResolution::persisted(
            Some(RuntimeBackendConfig::Managed),
            42,
            WorkspaceStorageTransitionState::Stable,
        );
        assert_eq!(
            resolution.routing,
            WorkspaceStorageRouting::Persisted {
                routing_epoch: 42,
                transition_state: WorkspaceStorageTransitionState::Stable,
            }
        );
        assert!(!resolution.routing.is_transitioning());
        assert_eq!(resolution.routing.stable_epoch(), Some(42));
        assert_eq!(WorkspaceStorageRouting::Unfenced.stable_epoch(), None);

        for transition_state in [
            WorkspaceStorageTransitionState::TransitioningToManaged,
            WorkspaceStorageTransitionState::TransitioningToS3Compatible,
        ] {
            let routing = WorkspaceStorageResolution::persisted(None, 43, transition_state).routing;
            assert!(routing.is_transitioning());
            assert_eq!(routing.stable_epoch(), None);
        }
    }

    #[tokio::test]
    async fn incomplete_and_unsupported_configs_are_rejected() {
        let repository = InMemoryWorkspaceStorageRepository::new();
        let workspace = repository.resolve_workspace("user-1").await.unwrap();
        let mut incomplete = valid_request();
        incomplete.secret_key.clear();
        assert!(matches!(
            repository.put_config(&workspace, incomplete).await,
            Err(WorkspaceStorageError::InvalidConfig(_))
        ));

        let mut unsupported = valid_request();
        unsupported.backend_type = BackendType::AwsRole;
        unsupported.role_arn = "arn:aws:iam::123456789012:role/s4".to_string();
        assert!(matches!(
            repository.put_config(&workspace, unsupported).await,
            Err(WorkspaceStorageError::UnsupportedConfig(_))
        ));
    }

    #[tokio::test]
    async fn managed_config_has_no_credentials_and_an_exact_redacted_shape() {
        let repository = InMemoryWorkspaceStorageRepository::new();
        let workspace = repository.resolve_workspace("user-1").await.unwrap();
        let response = repository
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
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "configured": true,
                "backend_type": "managed",
                "endpoint": null,
                "region": null,
                "role_arn": null,
                "access_key_configured": false,
                "secret_key_configured": false,
            })
        );
        assert!(matches!(
            repository.get_runtime_config(&workspace).await.unwrap(),
            Some(RuntimeBackendConfig::Managed)
        ));

        assert!(matches!(
            repository
                .put_config(
                    &workspace,
                    BackendConfigRequest {
                        backend_type: BackendType::Managed,
                        endpoint: "https://must-not-be-used.example".to_string(),
                        access_key: String::new(),
                        secret_key: String::new(),
                        region: String::new(),
                        role_arn: String::new(),
                    },
                )
                .await,
            Err(WorkspaceStorageError::InvalidConfig(_))
        ));
    }
}
