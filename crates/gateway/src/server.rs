//! Composable engine server: axum handlers + router + state construction.
//!
//! The engine is policy-free. Authorization (rate limits, quotas, billing)
//! and metering are injected through [`crate::control::ControlPlane`], held
//! in [`AppState`]. The OSS self-host binary builds this with
//! [`crate::control::NoopControlPlane`]; the private SaaS crate builds it with
//! its own control-plane implementation.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::types::ChecksumMode;
use aws_smithy_types::date_time::Format as DateTimeFormat;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri, header},
    response::{Html, IntoResponse},
    routing::{any, delete, get, head, post, put},
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use maskura_customer_config::{aliases as customer_env, resolve as resolve_customer_env};
use md5::Md5;
use rand::{RngCore, rngs::OsRng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::backend::{
    BackendKind, BackendResolver, PresignedHttpPolicy, ResolvedBackend, StorageOperation,
    WorkspaceEndpointPolicy,
};
use crate::control::{
    AuthenticatedRequestContext, AuthorizationDecision, AuthorizationError, AuthorizationGrant,
    ControlPlane, MeteringError, PipelineAttempt, RequestKind, StreamingWriteMode,
    UsageAuthorization, UsageEvent, UsageRoute,
};
use crate::customer_headers;
use crate::integrity::{BodyVerifier, IntegrityError};
use crate::key_cipher::{KeyWrapping, SecretCipher};
use crate::managed::{
    AuthorityListQuery, InMemoryManagedRepository, LogicalObjectKey, ManagedRepository,
    ManagedStreamingMode, PLACEMENT_VERSION_V1, PostgresManagedRepository, validate_mode,
};
use crate::multipart_staging::{
    ARTIFACT_PREFIX, AbortMutationError, COMPLETION_LEASE, CleanupAudit, CompletePart,
    CompletionAcquire, CompletionLease, EncryptedPartReader, EncryptedPartWriter,
    MAX_ACTIVE_UPLOADS, MultipartCompletionResult, MultipartIdentity, MultipartLifecycle,
    MultipartPart, MultipartRepository, MultipartSnapshot, MultipartUpload,
    PostgresMultipartRepository, S3StagingArtifactStore, StagedArtifact, StagingArtifactStore,
    StagingError, StagingQuotaLimits, completion_fingerprint, now_ms,
};
use crate::object::{
    BodyLimits, ChunkedBytesBody, ObjectMetadata, OpenedObject, filter_presigned_response_headers,
    harden_object_response_headers,
};
use crate::plugin_registry::{
    PipelineLimits, PipelineSnapshot, PluginCapabilities, PluginRegistry, StreamingPipelineSession,
};
use crate::read_spool::EncryptedReadSpool;
use crate::s3_error;
use crate::s3_safety::{S3Failure, record_s3_failure, s3_retry_config, s3_timeout_config};
use crate::service_storage::{ServiceStorage, parse_service_backends};
use crate::sigv4::{RequestAuthorization, SigV4Error, SigV4Policy, SigningKeyCache};
use crate::store::{
    FileKeyStore, KeyRepository, KeyStore, MAX_PUBLIC_KEY_PEM_BYTES, MemoryStore, PostgresKeyStore,
    canonicalize_credential_label, canonicalize_public_key_pem, sha256_hash,
    validate_credential_ttl,
};
use crate::transaction::{
    AbortSignal, AwsS3TransactionBackend, BackendCapabilities, BackendError, BackendErrorKind,
    CompatibilitySpoolConfig, CompatibilitySpoolTransaction, CompletionReconciliation,
    ConditionalReadCapability, DirectOperationScope, DirectS3Sink, EvidenceRecord, ExpectedObject,
    IncompleteUploadDiscovery, JournalError, ListCapability, MemorySinkTransaction,
    MultipartResponseCapability, ObjectDestination, ObjectSinkTransaction, OperationJournal,
    OperationReconciler, OperationRecord, OperationState, ProviderMutationFence,
    ResponseChecksumCapability, SpoolQuota, StoredObjectMeta, TransactionError,
    VersioningCapability, WorkspaceDestinationBinding,
};
use crate::workspace_storage::{
    BackendConfigRequest, BackendConfigResponse, BackendType, WorkspaceId, WorkspaceOperationLease,
    WorkspaceOperationOutcome, WorkspaceStorageError, WorkspaceStorageRepository,
};
use crate::{Format, Gateway};

#[derive(Clone)]
pub struct AppState {
    pub gateway: Arc<Gateway>,
    pub store: Arc<MemoryStore>,
    pub keys: Arc<dyn KeyRepository>,
    pub workspace_storage: Arc<dyn WorkspaceStorageRepository>,
    pub plugins: Arc<PluginRegistry>,
    pub service_storage: Arc<ServiceStorage>,
    pub s3_client: Option<Client>,
    pub supabase_url: String,
    pub jwt_decoder: Option<Arc<jsonwebtoken::DecodingKey>>,
    pub auth_disabled: bool,
    pub explicit_single_tenant: bool,
    pub workspace_endpoint_policy: WorkspaceEndpointPolicy,
    pub control: Arc<dyn ControlPlane>,
    pub legacy_max_object_bytes: usize,
    pub streaming_read_mode: StreamingReadMode,
    pub streaming_write_mode: StreamingWriteMode,
    pub source_body_limits: BodyLimits,
    pub max_pipeline_output_bytes: u64,
    pub presigned_http_policy: PresignedHttpPolicy,
    pub sigv4_cache: Arc<SigningKeyCache>,
    pub sigv4_policy: SigV4Policy,
    pub operation_journal: Option<Arc<dyn OperationJournal>>,
    pub s3_streaming_capabilities: Option<BackendCapabilities>,
    pub managed_streaming_capabilities: Option<BackendCapabilities>,
    pub spool_config: CompatibilitySpoolConfig,
    pub spool_quota: Arc<SpoolQuota>,
    /// Unsafe transformed reads are allowed only with encrypted durable staging.
    pub transformed_read_spool_enabled: bool,
    /// Enables the opt-in Avro OCF processing path. Disabled by default.
    pub binary_avro_enabled: bool,
    pub dev_memory_max_object_bytes: usize,
    pub dev_memory_streaming_enabled: bool,
    demo_pipelines: DemoPipelines,
    demo_limiter: Arc<DemoLimiter>,
    multipart_staging: Option<Arc<MultipartStaging>>,
    multipart_mode: MultipartMode,
    continuation_token_key: [u8; 32],
}

pub struct Auth {
    context: AuthenticatedRequestContext,
    credential_policy_id: String,
    public_key_pem: Option<String>,
    stable_key: Option<Vec<u8>>,
}

impl Auth {
    fn user_id(&self) -> &str {
        &self.context.user_id
    }

    fn workspace_id(&self) -> &crate::workspace_storage::WorkspaceId {
        &self.context.workspace_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationIdentity {
    receipt_id: Uuid,
    operation_id: Uuid,
}

struct OperationUsage<'a> {
    grant: &'a AuthorizationGrant,
    source_bytes: u64,
    output_bytes: u64,
}

#[derive(Clone, Copy)]
struct AuthorizedOperation<'a> {
    auth: &'a Auth,
    grant: &'a AuthorizationGrant,
}

#[derive(Clone, Copy)]
struct AuthorizedUsage<'a> {
    grant: &'a AuthorizationGrant,
}

impl OperationUsage<'_> {
    fn event(&self) -> UsageEvent {
        UsageEvent::from_grant(self.grant, self.source_bytes, self.output_bytes)
    }
}

fn operation_id_for_receipt(receipt_id: Uuid) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_X500, receipt_id.as_bytes())
}

fn request_operation_identity() -> OperationIdentity {
    let receipt_id = Uuid::now_v7();
    OperationIdentity {
        receipt_id,
        operation_id: operation_id_for_receipt(receipt_id),
    }
}

impl OperationIdentity {
    fn authorization(
        self,
        bucket: &str,
        route: UsageRoute,
        kind: RequestKind,
        max_processed_bytes: u64,
    ) -> UsageAuthorization {
        UsageAuthorization::new(
            self.operation_id,
            self.receipt_id,
            bucket,
            route,
            kind,
            max_processed_bytes,
        )
    }

    fn pipeline_authorization(
        self,
        bucket: &str,
        route: UsageRoute,
        kind: RequestKind,
        max_processed_bytes: u64,
        resolution: &crate::pipeline::PipelineResolution,
    ) -> UsageAuthorization {
        self.authorization(bucket, route, kind, max_processed_bytes)
            .with_pipeline(&resolution.locator)
    }
}

fn object_max_processed_bytes(state: &AppState) -> u64 {
    state
        .source_body_limits
        .max_bytes
        .max(state.max_pipeline_output_bytes)
}

fn multipart_completion_operation_identity(
    upload_id: &str,
    request_fingerprint: &str,
) -> OperationIdentity {
    let identity = format!("{upload_id}\0{request_fingerprint}");
    OperationIdentity {
        receipt_id: Uuid::new_v5(&Uuid::NAMESPACE_OID, identity.as_bytes()),
        operation_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, identity.as_bytes()),
    }
}

fn client_metering_id_rejection(
    headers: &HeaderMap,
    key: &str,
) -> Option<axum::response::Response> {
    if [
        "x-maskura-metering-id",
        "x-maskura-operation-id",
        "x-maskura-usage-id",
        "x-s4-metering-id",
        "x-s4-operation-id",
        "x-s4-usage-id",
    ]
    .into_iter()
    .any(|name| headers.contains_key(name))
    {
        return Some(s3_error::invalid_request(
            key,
            "The request contains an unsupported header.",
        ));
    }
    None
}

fn metering_error_response(key: &str, error: MeteringError) -> axum::response::Response {
    match error {
        MeteringError::Unavailable => {
            s3_error::service_unavailable(key, "Usage metering is temporarily unavailable.")
        }
        MeteringError::IdempotencyConflict => s3_error::invalid_request(
            key,
            "The usage receipt conflicts with an existing usage event.",
        ),
        MeteringError::Rejected => s3_error::payment_required(key, "The usage event was rejected."),
    }
}

async fn authorize_request(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    authorization: &UsageAuthorization,
    key: &str,
) -> Result<AuthorizationGrant, axum::response::Response> {
    match control.authorize(context, authorization).await {
        Ok(AuthorizationDecision::Granted(grant)) if grant.matches(authorization) => Ok(grant),
        Ok(AuthorizationDecision::Granted(_)) => Err(s3_error::service_unavailable(
            key,
            "Authorization returned an invalid grant.",
        )),
        Ok(AuthorizationDecision::Blocked(reason)) => {
            Err(s3_error::payment_required(key, reason.message))
        }
        Err(AuthorizationError::Unavailable) => Err(s3_error::service_unavailable(
            key,
            "Authorization is temporarily unavailable.",
        )),
    }
}

async fn release_failure(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    grant: &AuthorizationGrant,
    key: &str,
    response: axum::response::Response,
) -> axum::response::Response {
    match control.release(context, grant.operation_id()).await {
        Ok(()) => response,
        Err(AuthorizationError::Unavailable) => {
            warn!(
                operation_id = %grant.operation_id(),
                "usage reservation was not released"
            );
            s3_error::service_unavailable(
                key,
                "Authorization is temporarily unavailable while releasing the operation.",
            )
        }
    }
}

async fn record_usage(
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    event: &UsageEvent,
    key: &str,
) -> Result<(), axum::response::Response> {
    control.record(context, event).await.map_err(|error| {
        warn!(event_id = %event.receipt_id(), ?error, "usage event was not recorded");
        metering_error_response(key, error)
    })
}

#[allow(clippy::too_many_arguments)]
async fn record_failed_pipeline_attempt(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    operation_id: Uuid,
    bucket: &str,
    direction: crate::pipeline::PipelineDirection,
    resolution: Option<&crate::pipeline::PipelineResolution>,
    error_code: &'static str,
    duration_ms: u64,
) {
    let components =
        resolution.map(|value| crate::pipeline::component_digest_evidence(&value.steps));
    let attempt = PipelineAttempt::failed(
        operation_id,
        bucket,
        direction,
        resolution,
        components,
        error_code,
        0,
        duration_ms,
    );
    warn!(
        operation_id = %attempt.operation_id(),
        bucket = attempt.bucket(),
        direction = ?attempt.direction(),
        revision = attempt.revision(),
        fingerprint = attempt.fingerprint(),
        components = attempt.components(),
        error_code = attempt.error_code(),
        fuel_consumed = attempt.fuel_consumed(),
        duration_ms = attempt.duration_ms(),
        "pipeline attempt failed without customer usage"
    );
    if control
        .record_pipeline_attempt(context, &attempt)
        .await
        .is_err()
    {
        warn!(operation_id = %operation_id, error_code, "pipeline attempt evidence was not recorded");
    }
}

async fn record_operation(
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    usage: OperationUsage<'_>,
    key: &str,
) -> Result<(), axum::response::Response> {
    let event = usage.event();
    record_operation_with_event(control, context, event, key).await
}

async fn record_operation_with_event(
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    event: UsageEvent,
    key: &str,
) -> Result<(), axum::response::Response> {
    record_usage(control, context, &event, key).await
}

async fn record_durable_operation_with_event(
    journal: Option<&Arc<dyn OperationJournal>>,
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    event: UsageEvent,
    key: &str,
) -> Result<(), axum::response::Response> {
    persist_usage_evidence(journal, &event)
        .await
        .map_err(|error| {
            warn!(
                operation_id = %event.operation_id(),
                error = %error,
                "failed to persist usage evidence"
            );
            s3_error::service_unavailable(key, "Usage evidence could not be persisted.")
        })?;
    record_operation_with_event(control, context, event, key).await
}

fn multipart_completion_event(
    grant: &AuthorizationGrant,
    result: &MultipartCompletionResult,
) -> UsageEvent {
    let event = UsageEvent::from_grant(grant, result.source_bytes, result.size_bytes);
    match &result.pipeline_evidence {
        Some(evidence) => event.with_pipeline_evidence(evidence.clone()),
        None => event,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct DurableUsageEvidence {
    receipt_id: Uuid,
    occurred_at: chrono::DateTime<chrono::Utc>,
    rate_version: i32,
    source_bytes: u64,
    output_bytes: u64,
    processed_bytes: u64,
    route: String,
    kind: String,
    bucket: String,
    #[serde(default)]
    pipeline_evidence: Option<crate::control::PipelineEvidence>,
}

impl From<&UsageEvent> for DurableUsageEvidence {
    fn from(event: &UsageEvent) -> Self {
        Self {
            receipt_id: event.receipt_id(),
            occurred_at: event.occurred_at(),
            rate_version: event.rate_version(),
            source_bytes: event.source_bytes(),
            output_bytes: event.output_bytes(),
            processed_bytes: event.processed_bytes(),
            route: event.route().as_str().to_string(),
            kind: event.kind().as_str().to_string(),
            bucket: event.bucket().to_string(),
            pipeline_evidence: event.pipeline_evidence().cloned(),
        }
    }
}

fn usage_evidence_id(receipt_id: Uuid) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, receipt_id.as_bytes())
}

/// Persist the complete canonical usage event before entering a provider
/// commit window. Exact retries use one deterministic evidence identity.
async fn persist_usage_evidence(
    journal: Option<&Arc<dyn OperationJournal>>,
    event: &UsageEvent,
) -> Result<(), JournalError> {
    let Some(journal) = journal else {
        return Ok(());
    };
    // A process may have a Postgres journal because DATABASE_URL is set while
    // writing to the development memory sink. That sink has no operation row;
    // skip evidence rather than violating the evidence foreign key.
    if journal.get(event.operation_id()).await?.is_none() {
        return Ok(());
    }
    append_usage_evidence(journal, event).await
}

async fn persist_transaction_usage_evidence(
    journal: Option<&Arc<dyn OperationJournal>>,
    durable_operation_id: Option<Uuid>,
    event: &UsageEvent,
) -> Result<(), JournalError> {
    let Some(durable_operation_id) = durable_operation_id else {
        return Ok(());
    };
    if durable_operation_id != event.operation_id() {
        return Err(JournalError::Corrupt(
            "sink operation does not match usage evidence operation".to_string(),
        ));
    }
    let journal = journal.ok_or_else(|| {
        JournalError::Persistence("durable sink has no operation journal".to_string())
    })?;
    if journal.get(durable_operation_id).await?.is_none() {
        return Err(JournalError::Corrupt(format!(
            "durable sink operation {durable_operation_id} has no journal intent"
        )));
    }
    append_usage_evidence(journal, event).await
}

async fn append_usage_evidence(
    journal: &Arc<dyn OperationJournal>,
    event: &UsageEvent,
) -> Result<(), JournalError> {
    let mut evidence = EvidenceRecord::new(
        event.operation_id(),
        "usage",
        serde_json::to_value(DurableUsageEvidence::from(event))
            .map_err(|error| JournalError::Persistence(error.to_string()))?,
    );
    evidence.id = usage_evidence_id(event.receipt_id());
    journal.append_evidence(evidence).await
}

async fn load_usage_evidence(
    journal: &Arc<dyn OperationJournal>,
    operation_id: Uuid,
    receipt_id: Uuid,
) -> Result<DurableUsageEvidence, JournalError> {
    let expected_id = usage_evidence_id(receipt_id);
    let record = journal
        .evidence(operation_id)
        .await?
        .into_iter()
        .find(|record| record.id == expected_id && record.kind == "usage")
        .ok_or_else(|| {
            JournalError::Corrupt(format!(
                "operation {operation_id} is missing deterministic usage evidence"
            ))
        })?;
    let evidence: DurableUsageEvidence = serde_json::from_value(record.detail)
        .map_err(|error| JournalError::Corrupt(error.to_string()))?;
    if evidence.receipt_id != receipt_id {
        return Err(JournalError::Corrupt(format!(
            "operation {operation_id} usage evidence has the wrong receipt"
        )));
    }
    Ok(evidence)
}

fn admitted_response_bytes(response: &axum::response::Response) -> Option<u64> {
    let mut lengths = response.headers().get_all(header::CONTENT_LENGTH).iter();
    if let Some(length) = lengths.next() {
        if lengths.next().is_some() {
            return None;
        }
        return length.to_str().ok()?.parse().ok();
    }
    http_body::Body::size_hint(response.body()).exact()
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.parse().ok()
}

/// Launch policy: persist the admitted representation size before releasing a
/// streaming body. This intentionally never relies on body drop or background
/// best effort. Responses without a trustworthy size fail closed.
#[allow(clippy::too_many_arguments)]
async fn metered_read_response(
    control: Arc<dyn ControlPlane>,
    auth: &Auth,
    grant: &AuthorizationGrant,
    key: &str,
    source_bytes: Option<u64>,
    response: axum::response::Response,
    pipeline_evidence: Option<crate::control::PipelineEvidence>,
) -> axum::response::Response {
    if !response.status().is_success() {
        return release_failure(control.as_ref(), &auth.context, grant, key, response).await;
    }
    let Some(bytes) = admitted_response_bytes(&response) else {
        let response = s3_error::service_unavailable(
            key,
            "The response size is unavailable for usage metering.",
        );
        return release_failure(control.as_ref(), &auth.context, grant, key, response).await;
    };
    let source_bytes = source_bytes.unwrap_or(bytes);
    if source_bytes.max(bytes) > grant.max_processed_bytes() {
        return release_failure(
            control.as_ref(),
            &auth.context,
            grant,
            key,
            s3_error::entity_too_large(key),
        )
        .await;
    }
    let event = UsageEvent::from_grant(grant, source_bytes, bytes);
    let event = match pipeline_evidence {
        Some(evidence) => event.with_pipeline_evidence(evidence),
        None => event,
    };
    if let Err(response) = record_usage(control, &auth.context, &event, key).await {
        return response;
    }
    response
}

struct MultipartStaging {
    repository: Arc<dyn MultipartRepository>,
    artifacts: Arc<dyn StagingArtifactStore>,
    directory: PathBuf,
    wrapping: Arc<dyn KeyWrapping>,
}

const LEGACY_MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const WORKSPACE_OPERATION_LEASE_TTL: Duration = Duration::from_secs(120);
const DEMO_MAX_RECORDS: usize = 10;
const DEMO_MAX_INPUT_BYTES: usize = 64 * 1024;
const DEMO_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const DEMO_MAX_RAW_BODY_BYTES: usize = 512 * 1024;
const DEMO_MAX_CONCURRENCY: usize = 4;
const DEMO_MAX_STARTS_PER_MINUTE: usize = 30;
const DEMO_MAX_CUMULATIVE_FUEL: u64 = 50_000_000;
const DEMO_MAX_WALL_TIME: Duration = Duration::from_secs(2);
const SIMPLE_CREDENTIAL_MUTATION_BODY_BYTES: usize = 1024;
const CREATE_KEY_BODY_BYTES: usize = MAX_PUBLIC_KEY_PEM_BYTES + 1024;
const SET_PUBLIC_KEY_BODY_BYTES: usize = MAX_PUBLIC_KEY_PEM_BYTES + 512;

#[derive(Clone)]
struct DemoPipelines {
    safe: PipelineSnapshot,
    join: Option<PipelineSnapshot>,
}

struct DemoPipelineTemplate {
    registry: PluginRegistry,
    pii_id: String,
    stable_id: Option<String>,
}

impl DemoPipelineTemplate {
    fn instantiate(&self) -> anyhow::Result<DemoPipelines> {
        let registry = self.registry.isolated_clone()?;
        if let Some(stable_id) = &self.stable_id {
            registry.set_enabled(stable_id, false);
        }
        let safe = registry.snapshot().constrained(demo_pipeline_limits())?;
        let join = if let Some(stable_id) = &self.stable_id {
            registry.set_enabled(stable_id, true);
            registry.reorder(vec![stable_id.clone(), self.pii_id.clone()]);
            Some(registry.snapshot().constrained(demo_pipeline_limits())?)
        } else {
            None
        };
        Ok(DemoPipelines { safe, join })
    }
}

/// Immutable startup pipeline artifacts that can produce isolated gateway
/// state without recompiling the same Wasm components.
#[doc(hidden)]
pub struct StatePipelineTemplate {
    engine: Arc<s4_wasm_runtime::FilterEngine>,
    plugins: PluginRegistry,
    demo: DemoPipelineTemplate,
    max_pipeline_output_bytes: u64,
}

impl StatePipelineTemplate {
    #[doc(hidden)]
    pub fn from_env() -> anyhow::Result<Self> {
        let source_body_limits = source_body_limits_from_env()?;
        let explicit_component_path = component_path()?;
        let component_bytes = std::fs::read(&explicit_component_path)?;
        let pipeline_fuel = resolve_customer_env(customer_env::WASM_FUEL)?
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(crate::plugin_registry::DEFAULT_PIPELINE_FUEL);
        let engine = Arc::new(s4_wasm_runtime::FilterEngine::with_fuel(
            &component_bytes,
            pipeline_fuel,
        )?);
        let default_pipeline_limits = PipelineLimits::default();
        let max_pipeline_output_bytes =
            resolve_customer_env(customer_env::MAX_PIPELINE_OUTPUT_BYTES)?
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(default_pipeline_limits.max_output_bytes)
                .min(default_pipeline_limits.max_output_bytes);
        let pipeline_limits = PipelineLimits {
            max_input_bytes: default_pipeline_limits
                .max_input_bytes
                .min(source_body_limits.max_bytes),
            max_output_bytes: max_pipeline_output_bytes,
            max_cumulative_fuel: pipeline_fuel,
            ..default_pipeline_limits
        };
        let plugins = PluginRegistry::with_options(
            pipeline_fuel,
            pipeline_limits,
            s4_wasm_runtime::ExecutorConfig::default(),
        )?;
        let prefix_safe_hashes = prefix_safe_component_hashes()?;

        use sha2::Digest as _;
        let default_hash = hex::encode(sha2::Sha256::digest(&component_bytes));
        plugins.import_with_capabilities(
            "pii-default",
            &component_bytes,
            PluginCapabilities {
                prefix_safe_for_read: prefix_safe_hashes.contains(&default_hash),
            },
        )?;

        if let Some(plugin_dir) = resolve_customer_env(customer_env::PLUGINS_DIR)? {
            let dir = std::path::Path::new(&plugin_dir);
            if dir.exists() {
                plugins.load_from_dir_with_capabilities_excluding(
                    dir,
                    &prefix_safe_hashes,
                    Some(&explicit_component_path),
                )?;
            }
        }

        let stable_demo_component = bundled_stable_component()?;
        let demo = build_demo_pipeline_template(
            &component_bytes,
            stable_demo_component.as_deref(),
            pipeline_fuel,
        )?;
        Ok(Self {
            engine,
            plugins,
            demo,
            max_pipeline_output_bytes,
        })
    }

    fn instantiate(&self) -> anyhow::Result<(Gateway, Arc<PluginRegistry>, DemoPipelines)> {
        let plugins = Arc::new(self.plugins.isolated_clone()?);
        let gateway = Gateway::with_shared_registry(Arc::clone(&self.engine), plugins.clone());
        Ok((gateway, plugins, self.demo.instantiate()?))
    }
}

/// The process's single `AppState` shares this anonymous admission policy across
/// all router clones and both processing routes. A noisy anonymous client can
/// exhaust the shared allowance; edge or identity-aware limiting is the
/// follow-up availability control.
struct DemoLimiter {
    concurrency: Arc<tokio::sync::Semaphore>,
    starts: Mutex<VecDeque<Instant>>,
    max_starts: usize,
    window: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DemoLimitError {
    Concurrent,
    Rate,
}

impl DemoLimiter {
    fn new() -> Self {
        Self::with_limits(
            DEMO_MAX_CONCURRENCY,
            DEMO_MAX_STARTS_PER_MINUTE,
            Duration::from_secs(60),
        )
    }

    fn with_limits(concurrency: usize, max_starts: usize, window: Duration) -> Self {
        Self {
            concurrency: Arc::new(tokio::sync::Semaphore::new(concurrency)),
            starts: Mutex::new(VecDeque::with_capacity(max_starts)),
            max_starts,
            window,
        }
    }

    fn try_start(&self) -> Result<tokio::sync::OwnedSemaphorePermit, DemoLimitError> {
        let permit = self
            .concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| DemoLimitError::Concurrent)?;
        let now = Instant::now();
        let mut starts = self.starts.lock().unwrap();
        starts.retain(|started| now.saturating_duration_since(*started) < self.window);
        if starts.len() >= self.max_starts {
            return Err(DemoLimitError::Rate);
        }
        starts.push_back(now);
        Ok(permit)
    }
}

fn demo_pipeline_limits() -> PipelineLimits {
    PipelineLimits {
        max_intermediate_record_bytes: DEMO_MAX_OUTPUT_BYTES,
        max_plugin_finish_bytes: DEMO_MAX_OUTPUT_BYTES,
        max_input_bytes: DEMO_MAX_INPUT_BYTES as u64,
        max_output_bytes: DEMO_MAX_OUTPUT_BYTES as u64,
        max_expansion_factor: 8,
        max_expansion_slack_bytes: 1024,
        max_plugins: 2,
        max_cumulative_fuel: DEMO_MAX_CUMULATIVE_FUEL,
        max_wall_time: DEMO_MAX_WALL_TIME,
    }
}

fn build_demo_pipeline_template(
    pii_component: &[u8],
    stable_component: Option<&[u8]>,
    engine_fuel: u64,
) -> anyhow::Result<DemoPipelineTemplate> {
    let registry = PluginRegistry::with_fuel(engine_fuel);
    let pii = registry.import("pii-default", pii_component)?;
    let stable_id = if let Some(component) = stable_component {
        let stable = match registry.import("stable-encrypt", component) {
            Ok(stable) => stable,
            Err(error) => {
                warn!("stable-encrypt unavailable for the stateless demo: {error}");
                return Ok(DemoPipelineTemplate {
                    registry,
                    pii_id: pii.id,
                    stable_id: None,
                });
            }
        };
        registry.reorder(vec![stable.id.clone(), pii.id.clone()]);
        Some(stable.id)
    } else {
        None
    };
    Ok(DemoPipelineTemplate {
        registry,
        pii_id: pii.id,
        stable_id,
    })
}

#[cfg(test)]
fn build_demo_pipelines(
    pii_component: &[u8],
    stable_component: Option<&[u8]>,
    engine_fuel: u64,
) -> anyhow::Result<DemoPipelines> {
    build_demo_pipeline_template(pii_component, stable_component, engine_fuel)?.instantiate()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamingReadMode {
    #[default]
    Off,
    Passthrough,
    Transformed,
}

impl StreamingReadMode {
    fn from_env() -> anyhow::Result<Self> {
        Ok(
            match resolve_customer_env(customer_env::STREAMING_READ_MODE)?.as_deref() {
                Some("passthrough") => Self::Passthrough,
                Some("transformed") => Self::Transformed,
                Some("off") | None => Self::Off,
                Some(value) => {
                    warn!("invalid MASKURA_STREAMING_READ_MODE={value:?}; using off");
                    Self::Off
                }
            },
        )
    }

    fn streams_passthrough(self) -> bool {
        matches!(self, Self::Passthrough | Self::Transformed)
    }
}

fn transformed_read_spool_enabled() -> anyhow::Result<bool> {
    Ok(resolve_customer_env(customer_env::TRANSFORMED_READ_SPOOL)?
        .is_some_and(|value| value.eq_ignore_ascii_case("encrypted")))
}

fn binary_avro_enabled() -> anyhow::Result<bool> {
    Ok(resolve_customer_env(customer_env::ENABLE_AVRO)?
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true")))
}

/// Imported plugins are unsafe by default. Operators may opt known component
/// digests into direct reads at process start; dashboard callers cannot raise
/// this capability and a digest cannot be re-registered with different flags.
fn prefix_safe_component_hashes() -> anyhow::Result<HashSet<String>> {
    Ok(
        resolve_customer_env(customer_env::PREFIX_SAFE_COMPONENT_HASHES)?
            .into_iter()
            .flat_map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter_map(|hash| {
                let valid = hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit());
                if !valid {
                    warn!("ignoring invalid MASKURA_PREFIX_SAFE_COMPONENT_HASHES entry");
                    None
                } else {
                    Some(hash.to_ascii_lowercase())
                }
            })
            .collect(),
    )
}

fn streaming_write_mode() -> anyhow::Result<StreamingWriteMode> {
    Ok(
        match resolve_customer_env(customer_env::STREAMING_WRITE_MODE)?.as_deref() {
            Some("single") => StreamingWriteMode::Single,
            Some("all") => StreamingWriteMode::All,
            Some("off") | None => StreamingWriteMode::Off,
            Some(value) => {
                warn!("invalid MASKURA_STREAMING_WRITE_MODE={value:?}; using off");
                StreamingWriteMode::Off
            }
        },
    )
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MultipartMode {
    #[default]
    Reject,
    Staged,
}

fn multipart_mode() -> anyhow::Result<MultipartMode> {
    Ok(
        match resolve_customer_env(customer_env::MULTIPART_MODE)?.as_deref() {
            Some("staged") => MultipartMode::Staged,
            Some("reject") | None => MultipartMode::Reject,
            Some(value) => {
                warn!("invalid MASKURA_MULTIPART_MODE={value:?}; using reject");
                MultipartMode::Reject
            }
        },
    )
}

fn configured_s3_streaming_capabilities() -> anyhow::Result<Option<BackendCapabilities>> {
    let Some(provider) = resolve_customer_env(customer_env::STREAMING_S3_PROVIDER)? else {
        return Ok(None);
    };
    if !matches!(provider.as_str(), "aws" | "minio" | "r2" | "b2") {
        warn!("unknown MASKURA_STREAMING_S3_PROVIDER={provider:?}; direct streaming disabled");
        return Ok(None);
    }
    Ok(Some(BackendCapabilities {
        incomplete_upload_discovery: IncompleteUploadDiscovery::ExactKeyAndStartTime,
        abort_incomplete_upload: true,
        cleanup_sla: Some(Duration::from_secs(5 * 60)),
        lifecycle_rule: true,
        versioning: VersioningCapability::Optional,
        conditional_reads: ConditionalReadCapability::VersionAndEtag,
        response_checksums: ResponseChecksumCapability::Standard,
        list_operations: ListCapability::V1AndV2,
        multipart_responses: MultipartResponseCapability::Standard,
        completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
    }))
}

fn configured_managed_streaming_capabilities() -> Option<BackendCapabilities> {
    let configured = std::env::var("S4_MANAGED_STREAMING_TRANSACTIONAL")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    configured.then_some(BackendCapabilities {
        incomplete_upload_discovery: IncompleteUploadDiscovery::ExactKeyAndStartTime,
        abort_incomplete_upload: true,
        cleanup_sla: Some(Duration::from_secs(5 * 60)),
        lifecycle_rule: true,
        versioning: VersioningCapability::Optional,
        conditional_reads: ConditionalReadCapability::VersionAndEtag,
        response_checksums: ResponseChecksumCapability::Standard,
        list_operations: ListCapability::V1AndV2,
        multipart_responses: MultipartResponseCapability::Standard,
        completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
    })
}

fn legacy_max_object_bytes() -> anyhow::Result<usize> {
    let configured = match resolve_customer_env(customer_env::LEGACY_MAX_OBJECT_BYTES)? {
        Some(raw) => match raw.parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => {
                warn!(
                    "invalid MASKURA_LEGACY_MAX_OBJECT_BYTES={raw:?}; using {LEGACY_MAX_OBJECT_BYTES}"
                );
                LEGACY_MAX_OBJECT_BYTES
            }
        },
        None => LEGACY_MAX_OBJECT_BYTES,
    };
    let bounded = configured.min(LEGACY_MAX_OBJECT_BYTES);
    if bounded != configured {
        warn!(
            "MASKURA_LEGACY_MAX_OBJECT_BYTES={configured} exceeds the immutable 16 MiB limit; using {bounded}"
        );
    }
    Ok(bounded)
}

/// Derive the deterministic-encryption key for an API key secret:
/// two 32-byte HMAC-SHA256 outputs (`"s4-stable-encrypt"` + counter) giving
/// the 64-byte key AES-256-SIV requires. The plugin receives only this
/// derived key, never the raw secret.
fn derive_stable_key(secret: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut out = Vec::with_capacity(64);
    for i in 1..=2u8 {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(b"s4-stable-encrypt");
        mac.update(&[i]);
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out
}

#[derive(Serialize, ToSchema)]
struct ApiKeyResponse {
    key_id: String,
    secret: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
}

#[derive(Serialize)]
struct InternalErrorResponse {
    error: String,
}

#[derive(Serialize, ToSchema)]
struct ListKeyResponse {
    key_id: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ObjectResponse {
    key: String,
    size: usize,
}

#[derive(Deserialize, ToSchema)]
struct CreateKeyRequest {
    label: String,
    #[serde(default)]
    expires_in: u64,
    #[serde(default)]
    public_key_pem: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct DeleteKeyRequest {
    key_id: String,
}

#[derive(Serialize, ToSchema)]
struct McpTokenResponse {
    token_hash: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct McpTokenCreatedResponse {
    token: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct CreateMcpTokenRequest {
    label: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize, ToSchema)]
struct DeleteMcpTokenRequest {
    token_hash: String,
}

#[derive(serde::Deserialize, Default)]
struct S3Query {
    #[serde(rename = "uploads")]
    uploads: Option<String>,
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
    #[serde(rename = "part-number-marker")]
    part_number_marker: Option<u32>,
    #[serde(rename = "max-parts")]
    max_parts: Option<u32>,
    #[serde(rename = "list-type")]
    list_type: Option<String>,
    prefix: Option<String>,
    delimiter: Option<String>,
    #[serde(rename = "continuation-token")]
    continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    start_after: Option<String>,
    #[serde(rename = "max-keys")]
    max_keys: Option<u32>,
    #[serde(rename = "encoding-type")]
    encoding_type: Option<String>,
    #[allow(dead_code)]
    marker: Option<String>,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Maskura Gateway API",
        version = "0.3.5",
        description = "Pluggable processing gateway for S3-compatible storage. Manage plugins and API keys, proxy S3 requests through a Wasm plugin pipeline."
    ),
    paths(get_keys, create_key, delete_key, get_backend, put_backend, list_objects),
    components(schemas(ApiKeyResponse, ListKeyResponse, CreateKeyRequest, DeleteKeyRequest, ObjectResponse, BackendConfigRequest, BackendConfigResponse)),
    tags(
        (name = "keys", description = "API key management"),
        (name = "objects", description = "Object store listing")
    )
)]
struct ApiDoc;

/// Escape a value for inclusion in an S3 XML document.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// URL-encode a key for `encoding-type=url` list responses (S3 url-encoding:
/// everything except unreserved `A-Za-z0-9-_.~`).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn backend_resolver(state: &AppState) -> BackendResolver {
    BackendResolver::new(
        state.workspace_storage.clone(),
        state.service_storage.clone(),
        state.s3_client.clone(),
        state.store.clone(),
        state.explicit_single_tenant,
        state.workspace_endpoint_policy.clone(),
    )
}

async fn resolve_backend(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    operation: StorageOperation,
) -> Result<ResolvedBackend, String> {
    backend_resolver(state)
        .resolve(auth.workspace_id(), headers, operation)
        .await
}

fn backend_resolution_error_response(key: &str) -> axum::response::Response {
    warn!(key, "workspace backend resolution failed");
    s3_error::service_unavailable(key, "workspace storage is unavailable")
}

#[derive(Debug)]
enum OpenObjectError {
    NotFound,
    InvalidRange { object_length: u64 },
    Rejected(String),
    Backend(String),
    S3(S3Failure),
    PresignedTransport(PresignedTransportFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresignedTransportFailure {
    Timeout,
    Connect,
    Request,
}

impl PresignedTransportFailure {
    fn from_reqwest(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_connect() {
            Self::Connect
        } else {
            Self::Request
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Request => "request",
        }
    }
}

fn open_error_response(key: &str, error: OpenObjectError) -> axum::response::Response {
    match error {
        OpenObjectError::NotFound => s3_error::no_such_key(key),
        OpenObjectError::InvalidRange { object_length } => {
            s3_error::invalid_range(key, object_length)
        }
        OpenObjectError::Rejected(detail) => {
            warn!("presigned source rejected for {key}: {detail}");
            s3_error::access_denied(key)
        }
        OpenObjectError::Backend(detail) => {
            warn!("backend read failed for {key}: {detail}");
            s3_error::internal_error(key, &detail)
        }
        OpenObjectError::S3(failure) => s3_error::internal_error(key, failure.client_message()),
        OpenObjectError::PresignedTransport(failure) => {
            warn!(
                key,
                category = failure.as_str(),
                "presigned source transport failed"
            );
            s3_error::internal_error(key, "presigned backend request failed")
        }
    }
}

fn insert_header(metadata: &mut ObjectMetadata, name: &'static str, value: Option<&str>) {
    if let Some(value) = value {
        metadata.insert(HeaderName::from_static(name), value);
    }
}

fn insert_number<T: ToString>(metadata: &mut ObjectMetadata, name: &'static str, value: Option<T>) {
    if let Some(value) = value {
        metadata.insert(HeaderName::from_static(name), value.to_string());
    }
}

fn s3_response_body(
    body: aws_sdk_s3::primitives::ByteStream,
    operation: &'static str,
) -> axum::body::Body {
    axum::body::Body::new(body.into_inner().map_err(move |_| {
        std::io::Error::other(crate::s3_safety::record_s3_body_failure(operation))
    }))
}

fn s3_get_metadata(output: &aws_sdk_s3::operation::get_object::GetObjectOutput) -> ObjectMetadata {
    let mut metadata = ObjectMetadata {
        version_id: output.version_id.clone(),
        ..ObjectMetadata::default()
    };
    insert_number(&mut metadata, "content-length", output.content_length);
    insert_header(&mut metadata, "accept-ranges", output.accept_ranges());
    insert_header(&mut metadata, "content-range", output.content_range());
    insert_header(&mut metadata, "content-type", output.content_type());
    insert_header(&mut metadata, "content-encoding", output.content_encoding());
    insert_header(
        &mut metadata,
        "content-disposition",
        output.content_disposition(),
    );
    insert_header(&mut metadata, "content-language", output.content_language());
    insert_header(&mut metadata, "cache-control", output.cache_control());
    insert_header(&mut metadata, "etag", output.e_tag());
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc32",
        output.checksum_crc32(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc32c",
        output.checksum_crc32_c(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc64nvme",
        output.checksum_crc64_nvme(),
    );
    insert_header(&mut metadata, "x-amz-checksum-sha1", output.checksum_sha1());
    insert_header(
        &mut metadata,
        "x-amz-checksum-sha256",
        output.checksum_sha256(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-sha512",
        output.checksum_sha512(),
    );
    insert_header(&mut metadata, "x-amz-checksum-md5", output.checksum_md5());
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash64",
        output.checksum_xxhash64(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash3",
        output.checksum_xxhash3(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash128",
        output.checksum_xxhash128(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-type",
        output.checksum_type().map(|value| value.as_str()),
    );
    insert_header(&mut metadata, "x-amz-version-id", output.version_id());
    insert_number(&mut metadata, "x-amz-mp-parts-count", output.parts_count);
    insert_number(&mut metadata, "x-amz-missing-meta", output.missing_meta);
    insert_header(&mut metadata, "x-amz-expiration", output.expiration());
    insert_header(&mut metadata, "x-amz-restore", output.restore());
    insert_header(
        &mut metadata,
        "x-amz-website-redirect-location",
        output.website_redirect_location(),
    );
    if let Some(last_modified) = output.last_modified()
        && let Ok(value) = last_modified.fmt(DateTimeFormat::HttpDate)
    {
        metadata.insert(header::LAST_MODIFIED, value);
    }
    if let Some(user_metadata) = output.metadata() {
        for (name, value) in user_metadata {
            if let Ok(name) = HeaderName::from_bytes(format!("x-amz-meta-{name}").as_bytes()) {
                metadata.append(name, value);
            }
        }
    }
    metadata
}

fn s3_head_metadata(
    output: &aws_sdk_s3::operation::head_object::HeadObjectOutput,
) -> ObjectMetadata {
    let mut metadata = ObjectMetadata {
        version_id: output.version_id.clone(),
        ..ObjectMetadata::default()
    };
    insert_number(&mut metadata, "content-length", output.content_length);
    insert_header(&mut metadata, "accept-ranges", output.accept_ranges());
    insert_header(&mut metadata, "content-range", output.content_range());
    insert_header(&mut metadata, "content-type", output.content_type());
    insert_header(&mut metadata, "content-encoding", output.content_encoding());
    insert_header(
        &mut metadata,
        "content-disposition",
        output.content_disposition(),
    );
    insert_header(&mut metadata, "content-language", output.content_language());
    insert_header(&mut metadata, "cache-control", output.cache_control());
    insert_header(&mut metadata, "etag", output.e_tag());
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc32",
        output.checksum_crc32(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc32c",
        output.checksum_crc32_c(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc64nvme",
        output.checksum_crc64_nvme(),
    );
    insert_header(&mut metadata, "x-amz-checksum-sha1", output.checksum_sha1());
    insert_header(
        &mut metadata,
        "x-amz-checksum-sha256",
        output.checksum_sha256(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-sha512",
        output.checksum_sha512(),
    );
    insert_header(&mut metadata, "x-amz-checksum-md5", output.checksum_md5());
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash64",
        output.checksum_xxhash64(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash3",
        output.checksum_xxhash3(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash128",
        output.checksum_xxhash128(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-type",
        output.checksum_type().map(|value| value.as_str()),
    );
    insert_header(&mut metadata, "x-amz-version-id", output.version_id());
    insert_number(&mut metadata, "x-amz-mp-parts-count", output.parts_count);
    insert_number(&mut metadata, "x-amz-missing-meta", output.missing_meta);
    insert_header(&mut metadata, "x-amz-expiration", output.expiration());
    insert_header(&mut metadata, "x-amz-restore", output.restore());
    insert_header(
        &mut metadata,
        "x-amz-website-redirect-location",
        output.website_redirect_location(),
    );
    if let Some(last_modified) = output.last_modified()
        && let Ok(value) = last_modified.fmt(DateTimeFormat::HttpDate)
    {
        metadata.insert(header::LAST_MODIFIED, value);
    }
    if let Some(user_metadata) = output.metadata() {
        for (name, value) in user_metadata {
            if let Ok(name) = HeaderName::from_bytes(format!("x-amz-meta-{name}").as_bytes()) {
                metadata.append(name, value);
            }
        }
    }
    metadata
}

fn forwarded_read_headers(headers: &HeaderMap) -> HeaderMap {
    let mut forwarded = HeaderMap::new();
    for name in [
        header::RANGE,
        header::IF_MATCH,
        header::IF_NONE_MATCH,
        header::IF_MODIFIED_SINCE,
        header::IF_UNMODIFIED_SINCE,
        HeaderName::from_static("x-amz-checksum-mode"),
    ] {
        for value in headers.get_all(&name) {
            forwarded.append(name.clone(), value.clone());
        }
    }
    forwarded
}

async fn open_http_object(
    state: &AppState,
    url: reqwest::Url,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<OpenedObject, OpenObjectError> {
    let client = state
        .presigned_http_policy
        .client_for(&url)
        .await
        .map_err(OpenObjectError::Rejected)?;
    let method = if head_only {
        reqwest::Method::HEAD
    } else {
        reqwest::Method::GET
    };
    let response = client
        .request(method, url)
        .headers(forwarded_read_headers(headers))
        .send()
        .await
        .map_err(|error| {
            OpenObjectError::PresignedTransport(PresignedTransportFailure::from_reqwest(&error))
        })?;
    if response.status().is_redirection() {
        return Err(OpenObjectError::Rejected(
            "presigned HTTP source redirects are forbidden".to_string(),
        ));
    }
    let response: axum::http::Response<reqwest::Body> = response.into();
    let (parts, body) = response.into_parts();
    let mut response_headers = parts.headers;
    filter_presigned_response_headers(&mut response_headers);
    let version_id = response_headers
        .get("x-amz-version-id")
        .or_else(|| response_headers.get("x-goog-generation"))
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let metadata = ObjectMetadata {
        headers: response_headers,
        version_id,
    };
    let body = if head_only {
        axum::body::Body::empty()
    } else {
        axum::body::Body::new(body)
    };
    Ok(OpenedObject::new(
        parts.status,
        metadata,
        body,
        state.source_body_limits,
    ))
}

fn memory_range(
    data: &bytes::Bytes,
    range: Option<&str>,
) -> Result<(bytes::Bytes, Option<String>), OpenObjectError> {
    let length = data.len();
    let invalid_range = || OpenObjectError::InvalidRange {
        object_length: length as u64,
    };
    let Some(range) = range else {
        return Ok((data.clone(), None));
    };
    let spec = range
        .strip_prefix("bytes=")
        .filter(|spec| !spec.contains(','))
        .ok_or_else(invalid_range)?;
    let (start, end) = spec.split_once('-').ok_or_else(invalid_range)?;
    if length == 0 {
        return Err(invalid_range());
    }
    let (start, end) = if start.is_empty() {
        let suffix = end.parse::<usize>().map_err(|_| invalid_range())?;
        if suffix == 0 {
            return Err(invalid_range());
        }
        (length.saturating_sub(suffix), length - 1)
    } else {
        let start = start.parse::<usize>().map_err(|_| invalid_range())?;
        let end = if end.is_empty() {
            length - 1
        } else {
            end.parse::<usize>().map_err(|_| invalid_range())?
        };
        if start >= length || start > end {
            return Err(invalid_range());
        }
        (start, end.min(length - 1))
    };
    Ok((
        data.slice(start..=end),
        Some(format!("bytes {start}-{end}/{length}")),
    ))
}

async fn open_backend_object(
    state: &AppState,
    backend: ResolvedBackend,
    auth: &Auth,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<OpenedObject, OpenObjectError> {
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    match backend {
        ResolvedBackend::PresignedHttp(url) => {
            open_http_object(state, url, headers, head_only).await
        }
        ResolvedBackend::S3 { client, .. } => {
            let checksum_mode = headers
                .get("x-amz-checksum-mode")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("enabled"));
            if head_only {
                let mut request = client.head_object().bucket(bucket).key(key);
                if checksum_mode {
                    request = request.checksum_mode(ChecksumMode::Enabled);
                }
                let output = request.send().await.map_err(|error| {
                    if error
                        .as_service_error()
                        .is_some_and(|service| service.is_not_found())
                    {
                        OpenObjectError::NotFound
                    } else {
                        OpenObjectError::S3(record_s3_failure("head_object", &error))
                    }
                })?;
                return Ok(OpenedObject::new(
                    StatusCode::OK,
                    s3_head_metadata(&output),
                    axum::body::Body::empty(),
                    state.source_body_limits,
                ));
            }
            let mut request = client.get_object().bucket(bucket).key(key);
            if let Some(range) = range {
                request = request.range(range);
            }
            if checksum_mode {
                request = request.checksum_mode(ChecksumMode::Enabled);
            }
            let output = request.send().await.map_err(|error| {
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_no_such_key())
                {
                    OpenObjectError::NotFound
                } else {
                    OpenObjectError::S3(record_s3_failure("get_object", &error))
                }
            })?;
            let status = if output.content_range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let metadata = s3_get_metadata(&output);
            let body = s3_response_body(output.body, "get_object_body");
            Ok(OpenedObject::new(
                status,
                metadata,
                body,
                state.source_body_limits,
            ))
        }
        ResolvedBackend::Managed(storage) => {
            let logical = managed_logical_key(auth, bucket, key);
            let workspace_id = auth.workspace_id().as_str();
            if head_only {
                let output = if storage.managed_mode() == ManagedStreamingMode::Off
                    || (storage.managed_mode() == ManagedStreamingMode::Observe
                        && !storage
                            .has_authority(&logical)
                            .await
                            .map_err(|error| OpenObjectError::Backend(error.to_string()))?)
                {
                    storage
                        .head_output(&format!("{workspace_id}/{bucket}/{key}"))
                        .await
                } else {
                    storage
                        .head_authoritative(&logical)
                        .await
                        .map_err(|error| OpenObjectError::Backend(error.to_string()))?
                }
                .ok_or(OpenObjectError::NotFound)?;
                return Ok(OpenedObject::new(
                    StatusCode::OK,
                    s3_head_metadata(&output),
                    axum::body::Body::empty(),
                    state.source_body_limits,
                ));
            }
            let output = if storage.managed_mode() == ManagedStreamingMode::Off
                || (storage.managed_mode() == ManagedStreamingMode::Observe
                    && !storage
                        .has_authority(&logical)
                        .await
                        .map_err(|error| OpenObjectError::Backend(error.to_string()))?)
            {
                storage
                    .open(&format!("{workspace_id}/{bucket}/{key}"), range)
                    .await
            } else {
                storage
                    .open_authoritative(&logical, range)
                    .await
                    .map_err(|error| OpenObjectError::Backend(error.to_string()))?
            }
            .ok_or(OpenObjectError::NotFound)?;
            let status = if output.content_range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let metadata = s3_get_metadata(&output);
            let body = s3_response_body(output.body, "managed_get_object_body");
            Ok(OpenedObject::new(
                status,
                metadata,
                body,
                state.source_body_limits,
            ))
        }
        ResolvedBackend::Memory(store) => {
            if head_only {
                let (size, content_type, etag) = store
                    .metadata(bucket, key)
                    .ok_or(OpenObjectError::NotFound)?;
                let mut metadata = ObjectMetadata::default();
                metadata.insert(header::CONTENT_LENGTH, size.to_string());
                metadata.insert(header::CONTENT_TYPE, content_type);
                metadata.insert(header::ETAG, etag);
                metadata.insert(header::ACCEPT_RANGES, "bytes");
                return Ok(OpenedObject::new(
                    StatusCode::OK,
                    metadata,
                    axum::body::Body::empty(),
                    state.source_body_limits,
                ));
            }
            let object = store.get(bucket, key).ok_or(OpenObjectError::NotFound)?;
            let (data, content_range) = memory_range(&object.data, range)?;
            let mut metadata = ObjectMetadata::default();
            metadata.insert(header::CONTENT_LENGTH, data.len().to_string());
            metadata.insert(header::CONTENT_TYPE, object.content_type);
            metadata.insert(header::ETAG, object.etag);
            metadata.insert(header::ACCEPT_RANGES, "bytes");
            if let Some(content_range) = content_range {
                metadata.insert(header::CONTENT_RANGE, content_range);
            }
            let status = if range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let body = axum::body::Body::new(ChunkedBytesBody::new(
                data,
                state.source_body_limits.max_frame_bytes,
            ));
            Ok(OpenedObject::new(
                status,
                metadata,
                body,
                state.source_body_limits,
            ))
        }
    }
}

struct HeaderAuthentication {
    auth: Auth,
    body_verifier: Option<BodyVerifier>,
}

impl HeaderAuthentication {
    fn without_body(auth: Auth) -> Self {
        Self {
            auth,
            body_verifier: None,
        }
    }

    fn verify_body(mut self, body: &[u8]) -> Result<Auth, IntegrityError> {
        if let Some(mut verifier) = self.body_verifier.take() {
            verifier.push(body)?;
            verifier.finish()?;
        }
        Ok(self.auth)
    }
}

#[derive(Debug)]
enum HeaderAuthError {
    Denied,
    InvalidPayload(IntegrityError),
    CredentialStoreUnavailable(String),
    Unavailable(String),
}

async fn authenticated_request(
    state: &AppState,
    user_id: String,
    credential_policy_id: String,
    public_key_pem: Option<String>,
    stable_key: Option<Vec<u8>>,
) -> Result<Auth, HeaderAuthError> {
    let workspace_id = state
        .workspace_storage
        .resolve_workspace(&user_id)
        .await
        .map_err(|error| HeaderAuthError::Unavailable(error.to_string()))?;
    Ok(Auth {
        context: AuthenticatedRequestContext {
            user_id,
            workspace_id,
        },
        credential_policy_id,
        public_key_pem,
        stable_key,
    })
}

impl From<SigV4Error> for HeaderAuthError {
    fn from(error: SigV4Error) -> Self {
        match error {
            SigV4Error::Payload(error) => Self::InvalidPayload(error),
            _ => Self::Denied,
        }
    }
}

fn authentication_error_response(key: &str, error: HeaderAuthError) -> axum::response::Response {
    match error {
        HeaderAuthError::Denied => s3_error::signature_mismatch(key),
        HeaderAuthError::InvalidPayload(error) => {
            s3_error::invalid_request(key, &error.to_string())
        }
        HeaderAuthError::CredentialStoreUnavailable(error) => {
            warn!("credential storage unavailable during authentication: {error}");
            s3_error::service_unavailable(key, "credential storage is temporarily unavailable")
        }
        HeaderAuthError::Unavailable(error) => {
            warn!("workspace resolution failed: {error}");
            s3_error::service_unavailable(key, "workspace storage is temporarily unavailable")
        }
    }
}

async fn authenticate_headers(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    keys: &Arc<dyn KeyRepository>,
    state: &AppState,
) -> Result<HeaderAuthentication, HeaderAuthError> {
    customer_headers::validate_all(headers).map_err(|_| HeaderAuthError::Denied)?;
    if let Some(sigv4) = RequestAuthorization::parse(uri, headers).map_err(HeaderAuthError::from)? {
        // AUTH_DISABLED is an explicit local-only bypass retained for the
        // development S3 front door. Production always takes the strict
        // authorization and integrity path below.
        if state.auth_disabled {
            return Ok(HeaderAuthentication::without_body(
                authenticated_request(
                    state,
                    "demo-user".to_string(),
                    "local-demo".to_string(),
                    None,
                    None,
                )
                .await?,
            ));
        }
        let key = keys
            .get_key(sigv4.access_key())
            .await
            .map_err(|error| HeaderAuthError::CredentialStoreUnavailable(error.to_string()))?
            .ok_or(HeaderAuthError::Denied)?;
        if key_expired(key.expires_at.as_deref()) {
            return Err(HeaderAuthError::Denied);
        }
        let secret = keys
            .decrypt_secret(sigv4.access_key())
            .await
            .map_err(|error| HeaderAuthError::CredentialStoreUnavailable(error.to_string()))?
            .ok_or(HeaderAuthError::Denied)?;
        let body_verifier = sigv4
            .authorize(
                method,
                uri,
                headers,
                &secret,
                &state.sigv4_cache,
                &state.sigv4_policy,
                SystemTime::now(),
            )
            .map_err(HeaderAuthError::from)?;
        return Ok(HeaderAuthentication {
            auth: authenticated_request(
                state,
                key.user_id.clone(),
                key.key_id.clone(),
                key.public_key_pem.clone(),
                Some(derive_stable_key(&secret)),
            )
            .await?,
            body_verifier: Some(body_verifier),
        });
    }

    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
    match auth {
        Some(a) if a.starts_with("Bearer ") => {
            let token = &a[7..];
            // MCP bearer token (s4m_...): a self-contained credential.
            if token.starts_with("s4m_") {
                let user_id = keys.resolve_mcp_token(token).await.map_err(|error| {
                    HeaderAuthError::CredentialStoreUnavailable(error.to_string())
                })?;
                if let Some(user_id) = user_id {
                    return Ok(HeaderAuthentication::without_body(
                        authenticated_request(
                            state,
                            user_id,
                            format!("mcp:{}", sha256_hash(token)),
                            None,
                            None,
                        )
                        .await?,
                    ));
                }
                return Err(HeaderAuthError::Denied);
            }
            // Try API key format: Bearer s4_xxx:s4s_xxx
            if let Some((ak, sk)) = token.split_once(':') {
                let (user_id, public_key_pem) = keys
                    .resolve_credentials(ak, sk)
                    .await
                    .map_err(|error| {
                        HeaderAuthError::CredentialStoreUnavailable(error.to_string())
                    })?
                    .ok_or(HeaderAuthError::Denied)?;
                return Ok(HeaderAuthentication::without_body(
                    authenticated_request(
                        state,
                        user_id,
                        ak.to_string(),
                        public_key_pem,
                        Some(derive_stable_key(sk)),
                    )
                    .await?,
                ));
            }
            // Try JWT
            if state.jwt_decoder.is_some() {
                let uid = get_user_id(headers, state);
                if uid != "demo-user" {
                    return Ok(HeaderAuthentication::without_body(
                        authenticated_request(state, uid, "jwt".to_string(), None, None).await?,
                    ));
                }
            }
            return Err(HeaderAuthError::Denied);
        }
        _ => {}
    };
    // Canonical and legacy MCP headers resolve to one credential value.
    if let Some(tok) = customer_headers::validated(headers, customer_headers::MCP_TOKEN)
        .and_then(|v| v.to_str().ok())
    {
        let user_id = if tok.starts_with("s4m_") {
            keys.resolve_mcp_token(tok)
                .await
                .map_err(|error| HeaderAuthError::CredentialStoreUnavailable(error.to_string()))?
        } else {
            None
        };
        if let Some(user_id) = user_id {
            return Ok(HeaderAuthentication::without_body(
                authenticated_request(
                    state,
                    user_id,
                    format!("mcp:{}", sha256_hash(tok)),
                    None,
                    None,
                )
                .await?,
            ));
        }
        return Err(HeaderAuthError::Denied);
    }
    let ak = customer_headers::validated(headers, customer_headers::ACCESS_KEY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sk = customer_headers::validated(headers, customer_headers::SECRET_KEY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let resolved = keys
        .resolve_credentials(ak, sk)
        .await
        .map_err(|error| HeaderAuthError::CredentialStoreUnavailable(error.to_string()))?;
    if let Some((user_id, public_key_pem)) = resolved {
        return Ok(HeaderAuthentication::without_body(
            authenticated_request(
                state,
                user_id,
                ak.to_string(),
                public_key_pem,
                Some(derive_stable_key(sk)),
            )
            .await?,
        ));
    }
    // Allow access in demo mode only when auth is explicitly disabled or
    // when using an in-memory keystore with no keys (dev/first-run mode).
    // Never allow unauthenticated access when keys are persisted — this
    // prevents an empty database from becoming an open door in production.
    if state.auth_disabled {
        return Ok(HeaderAuthentication::without_body(
            authenticated_request(
                state,
                "demo-user".to_string(),
                "local-demo".to_string(),
                None,
                None,
            )
            .await?,
        ));
    }
    Err(HeaderAuthError::Denied)
}

async fn authenticate(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    keys: &Arc<dyn KeyRepository>,
    state: &AppState,
) -> Result<Auth, HeaderAuthError> {
    authenticate_headers(method, uri, headers, keys, state)
        .await?
        .verify_body(body)
        .map_err(HeaderAuthError::InvalidPayload)
}

fn key_expired(expires_at: Option<&str>) -> bool {
    if let Some(exp) = expires_at {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if exp.parse::<u64>().is_ok_and(|ts| now >= ts) {
            return true;
        }
    }
    false
}

fn get_user_id(headers: &HeaderMap, state: &AppState) -> String {
    match get_user_claims(headers, state) {
        Some(claims) => claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("demo-user")
            .to_string(),
        None => "demo-user".to_string(),
    }
}

fn supabase_jwt_validation(
    algorithm: jsonwebtoken::Algorithm,
    issuer: &str,
) -> jsonwebtoken::Validation {
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&["authenticated"]);
    validation.validate_exp = true;
    validation
}

/// Resolve and validate the authenticated user's Supabase claims.
pub async fn require_user_claims(
    headers: &HeaderMap,
    state: &AppState,
) -> Option<serde_json::Value> {
    if state.auth_disabled {
        return Some(serde_json::json!({
            "sub": "demo-user",
            "email": "",
            "app_metadata": { "provider": "demo" },
        }));
    }
    if let Some(claims) = verify_jwks_claims(headers, state).await {
        return Some(claims);
    }
    get_user_claims(headers, state)
}

/// Resolve the authenticated user id, or `None` when the request is not
/// authenticated. When auth is disabled (local/demo mode) this is permissive
/// and returns the demo user. When auth is enabled (production SaaS) an
/// unauthenticated request returns `None` so callers can reject with 401.
/// Accepts both ES256 (Supabase OAuth access tokens, via JWKS) and HS256
/// (email/password sessions, via the JWT secret).
pub async fn require_user_id(headers: &HeaderMap, state: &AppState) -> Option<String> {
    let claims = require_user_claims(headers, state).await?;
    let sub = claims.get("sub")?.as_str()?;
    if sub.is_empty() {
        return None;
    }
    Some(sub.to_string())
}

/// Verify a Supabase ES256 access token against the project JWKS and return
/// its `sub`. Uses the async client (safe in tokio handlers).
#[allow(clippy::type_complexity)]
async fn verify_jwks_claims(headers: &HeaderMap, state: &AppState) -> Option<serde_json::Value> {
    use std::sync::OnceLock;
    use std::time::Instant;

    static CACHE: OnceLock<std::sync::Mutex<Option<(String, Vec<serde_json::Value>, Instant)>>> =
        OnceLock::new();

    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok())?;
    let token = auth.strip_prefix("Bearer ")?;
    let header = jsonwebtoken::decode_header(token).ok()?;
    let kid = header.kid.as_deref()?;
    let issuer = format!("{}/auth/v1", state.supabase_url.trim_end_matches('/'));
    let jwks_url = format!("{}/.well-known/jwks.json", issuer);

    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(None));
    {
        let stale = {
            let guard = cache.lock().ok()?;
            match &*guard {
                Some((url, _, at)) => {
                    url != &jwks_url || at.elapsed() > Duration::from_secs(6 * 60 * 60)
                }
                None => true,
            }
        };
        if stale {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .ok()?;
            let resp = client.get(&jwks_url).send().await.ok()?;
            let body: serde_json::Value = resp.json().await.ok()?;
            let keys = body.get("keys")?.as_array()?.clone();
            let mut guard = cache.lock().ok()?;
            *guard = Some((jwks_url, keys, Instant::now()));
        }
    }
    let guard = cache.lock().ok()?;
    let (_, keys, _) = guard.as_ref()?;
    let key = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))?;
    let x = key.get("x")?.as_str()?;
    let y = key.get("y")?.as_str()?;
    let pem = engine_ec_pem(x, y)?;

    let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes()).ok()?;
    let validation = supabase_jwt_validation(jsonwebtoken::Algorithm::ES256, &issuer);
    let data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation).ok()?;
    Some(data.claims)
}

/// Build an EC public-key PEM (SPKI) from base64url JWK x/y coordinates.
fn engine_ec_pem(x: &str, y: &str) -> Option<String> {
    use base64::Engine;
    let xb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .ok()?;
    let yb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y)
        .ok()?;
    if xb.len() != 32 || yb.len() != 32 {
        return None;
    }
    let alg_id = [
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let mut bit_string = vec![0x00];
    bit_string.push(0x04);
    bit_string.extend_from_slice(&xb);
    bit_string.extend_from_slice(&yb);
    let bit_len = bit_string.len();
    let mut bit_tlv = vec![0x03];
    bit_tlv.push(if bit_len < 128 {
        bit_len as u8
    } else {
        return None;
    });
    bit_tlv.extend_from_slice(&bit_string);
    let body_len = alg_id.len() + bit_tlv.len();
    let mut spki = vec![0x30];
    spki.push(if body_len < 128 {
        body_len as u8
    } else {
        return None;
    });
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&bit_tlv);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
    Some(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        b64.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// Decode and validate the Supabase JWT, returning its claims.
fn get_user_claims(headers: &HeaderMap, state: &AppState) -> Option<serde_json::Value> {
    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let token = match auth {
        Some(a) if a.starts_with("Bearer ") => &a[7..],
        _ => return None,
    };

    let key = state.jwt_decoder.as_ref()?;
    let issuer = format!("{}/auth/v1", state.supabase_url.trim_end_matches('/'));
    let validation = supabase_jwt_validation(jsonwebtoken::Algorithm::HS256, &issuer);
    match jsonwebtoken::decode::<serde_json::Value>(token, key, &validation) {
        Ok(data) => Some(data.claims),
        Err(e) => {
            warn!("JWT validation failed: {e}");
            None
        }
    }
}

async fn get_me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let Some(claims) = require_user_claims(&headers, &state).await else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    let Some(user_id) = claims.get("sub").and_then(|v| v.as_str()) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    let email = claims
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = claims
        .get("app_metadata")
        .and_then(|m| m.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("email")
        .to_string();
    let keys = match state.keys.list_for_user(user_id).await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::error!(user_id, error = %error, "credential storage unavailable");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    Json(serde_json::json!({
        "user_id": user_id,
        "email": email,
        "provider": provider,
        "keys": keys.len(),
    }))
    .into_response()
}

/// Interactive demo: run the WASM PII pipeline over the submitted text and
/// return the redacted output without writing request data to storage.
#[derive(Deserialize, ToSchema)]
struct DemoRedactRequest {
    text: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum DemoMode {
    Safe,
    Join,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DemoProcessRequest {
    records: Vec<serde_json::Value>,
    mode: DemoMode,
}

#[derive(Serialize)]
struct DemoProcessedRecord {
    record: usize,
    body: String,
}

#[derive(Serialize)]
struct DemoProcessResponse {
    mode: DemoMode,
    records: Vec<DemoProcessedRecord>,
}

#[derive(Serialize)]
struct DemoErrorResponse {
    code: &'static str,
    message: &'static str,
}

fn harden_demo_response(mut response: axum::response::Response) -> axum::response::Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "private, no-store".parse().expect("static cache control"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        "nosniff".parse().expect("static content type option"),
    );
    response
}

struct BoundedDemoJsonWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl BoundedDemoJsonWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(DEMO_MAX_OUTPUT_BYTES),
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedDemoJsonWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > DEMO_MAX_OUTPUT_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::other("demo JSON response exceeds limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_demo_json<T: Serialize>(value: &T) -> axum::response::Response {
    let mut writer = BoundedDemoJsonWriter::new();
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => {
            let mut response = axum::response::Response::new(axum::body::Body::from(writer.bytes));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                "application/json".parse().expect("static content type"),
            );
            harden_demo_response(response)
        }
        Err(_) if writer.exceeded => demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "output_too_large",
            "Demo output exceeds 64 KiB",
        ),
        Err(_) => demo_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_failed",
            "Demo processing failed",
        ),
    }
}

fn demo_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> axum::response::Response {
    harden_demo_response((status, Json(DemoErrorResponse { code, message })).into_response())
}

fn demo_limit_response(error: DemoLimitError) -> axum::response::Response {
    match error {
        DemoLimitError::Concurrent => demo_error(
            StatusCode::TOO_MANY_REQUESTS,
            "demo_busy",
            "Too many demo operations are running",
        ),
        DemoLimitError::Rate => demo_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Demo rate limit exceeded",
        ),
    }
}

fn start_demo_operation(
    state: &AppState,
) -> Result<tokio::sync::OwnedSemaphorePermit, DemoLimitError> {
    state.demo_limiter.try_start()
}

fn demo_pipeline(state: &AppState, mode: DemoMode) -> Option<PipelineSnapshot> {
    match mode {
        DemoMode::Safe => Some(state.demo_pipelines.safe.clone()),
        DemoMode::Join => state.demo_pipelines.join.clone(),
    }
}

fn demo_request_stable_key() -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; 64]);
    OsRng.fill_bytes(key.as_mut_slice());
    key
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DemoBodyError {
    Invalid,
    TooLarge,
    Deadline,
}

fn demo_body_error(error: DemoBodyError) -> axum::response::Response {
    match error {
        DemoBodyError::Invalid => demo_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid demo request",
        ),
        DemoBodyError::TooLarge => demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "input_too_large",
            "Demo request body is too large",
        ),
        DemoBodyError::Deadline => demo_error(
            StatusCode::REQUEST_TIMEOUT,
            "demo_timeout",
            "Demo operation timed out",
        ),
    }
}

async fn decode_demo_json<T: DeserializeOwned>(
    request: Request,
    deadline: Instant,
) -> Result<T, DemoBodyError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| value == "application/json" || value.ends_with("+json"));
    if content_type.is_none() {
        return Err(DemoBodyError::Invalid);
    }

    let mut body = request.into_body();
    let mut bytes = Vec::new();
    loop {
        let frame = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), body.frame())
            .await
            .map_err(|_| DemoBodyError::Deadline)?;
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(|_| DemoBodyError::Invalid)?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > DEMO_MAX_RAW_BODY_BYTES {
                return Err(DemoBodyError::TooLarge);
            }
            bytes.extend_from_slice(data);
        }
    }
    let decoded = serde_json::from_slice(&bytes).map_err(|_| DemoBodyError::Invalid)?;
    if Instant::now() >= deadline {
        return Err(DemoBodyError::Deadline);
    }
    Ok(decoded)
}

fn demo_pipeline_error(error: &s4_error::S4Error) -> axum::response::Response {
    match error.code() {
        s4_error::codes::LIMIT_INPUT_BYTES | s4_error::codes::RECORD_TOO_LARGE => demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "input_too_large",
            "Demo input exceeds 64 KiB",
        ),
        s4_error::codes::LIMIT_OUTPUT_BYTES
        | s4_error::codes::LIMIT_EXPANSION
        | s4_error::codes::LIMIT_INTERMEDIATE_BYTES
        | s4_error::codes::LIMIT_FINISH_BYTES => demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "output_too_large",
            "Demo output exceeds 64 KiB",
        ),
        s4_error::codes::WASM_DEADLINE | s4_error::codes::WASM_CANCELLED => demo_error(
            StatusCode::REQUEST_TIMEOUT,
            "demo_timeout",
            "Demo operation timed out",
        ),
        _ => demo_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_failed",
            "Demo processing failed",
        ),
    }
}

fn demo_deadline_error() -> s4_error::S4Error {
    s4_error::S4Error::new(
        s4_error::codes::WASM_DEADLINE,
        "demo operation deadline exceeded",
    )
}

async fn execute_demo_records(
    snapshot: PipelineSnapshot,
    session: s4_wasm_runtime::Session,
    records: Vec<crate::record::Record>,
    deadline: Instant,
) -> Result<(Vec<crate::record::Record>, Vec<crate::record::Record>), s4_error::S4Error> {
    let cancellation = s4_wasm_runtime::CancellationToken::new();
    let mut pipeline = snapshot
        .start_streaming_session_with_deadline(session, cancellation, deadline)
        .await?;
    let mut output = Vec::with_capacity(records.len());
    for record in records {
        if Instant::now() >= deadline {
            let _ = pipeline.cancel_and_wait().await;
            return Err(demo_deadline_error());
        }
        match pipeline.process(record).await {
            Ok(Some(record)) => output.push(record),
            Ok(None) => {
                let _ = pipeline.cancel_and_wait().await;
                return Err(s4_error::S4Error::new(
                    s4_error::codes::WASM_REJECT,
                    "demo pipeline dropped a record",
                ));
            }
            Err(error) => {
                let _ = pipeline.cancel_and_wait().await;
                return Err(error);
            }
        }
    }
    let (trailing, _fuel) = pipeline.finish().await?;
    Ok((output, trailing))
}

fn append_demo_output(
    output: &mut Vec<u8>,
    record: crate::record::Record,
    max_output_bytes: Option<usize>,
) -> Result<(), s4_error::S4Error> {
    let added = record.payload.len().saturating_add(record.separator.len());
    if max_output_bytes.is_some_and(|limit| output.len().saturating_add(added) > limit) {
        return Err(s4_error::S4Error::new(
            s4_error::codes::LIMIT_OUTPUT_BYTES,
            "demo output exceeds limit",
        ));
    }
    output.extend_from_slice(&record.payload);
    output.extend_from_slice(&record.separator);
    Ok(())
}

async fn demo_redact(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    let _permit = match start_demo_operation(&state) {
        Ok(permit) => permit,
        Err(error) => return demo_limit_response(error),
    };
    let deadline = Instant::now() + DEMO_MAX_WALL_TIME;
    let body: DemoRedactRequest = match decode_demo_json(request, deadline).await {
        Ok(body) => body,
        Err(error) => return demo_body_error(error),
    };
    if body.text.len() > DEMO_MAX_INPUT_BYTES {
        return demo_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "input_too_large",
            "Demo input exceeds 64 KiB",
        );
    }
    let limits = crate::record::DecoderLimits::default();
    let mut decoder = match crate::record::RecordDecoder::new(Format::Text, limits) {
        Ok(decoder) => decoder,
        Err(error) => return demo_pipeline_error(&error),
    };
    if let Err(error) = decoder.push(body.text.as_bytes()) {
        return demo_pipeline_error(&error);
    }
    let mut records = Vec::new();
    loop {
        match decoder.next_record() {
            Ok(Some(record)) => records.push(record),
            Ok(None) => break,
            Err(error) => return demo_pipeline_error(&error),
        }
    }
    if let Err(error) = decoder.finish() {
        return demo_pipeline_error(&error);
    }
    loop {
        match decoder.next_record() {
            Ok(Some(record)) => records.push(record),
            Ok(None) => break,
            Err(error) => return demo_pipeline_error(&error),
        }
    }
    let records_processed = records.len();
    let session = s4_wasm_runtime::Session {
        format: Format::Text.as_str().to_string(),
        content_type: "text/plain".to_string(),
        policy_version: 0,
        operation: s4_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: None,
        stable_key: None,
        stable_fields: None,
    };
    match execute_demo_records(
        state.demo_pipelines.safe.clone(),
        session,
        records,
        deadline,
    )
    .await
    {
        Ok((records, trailing)) => {
            let mut bytes = Vec::new();
            for record in records.into_iter().chain(trailing) {
                if let Err(error) =
                    append_demo_output(&mut bytes, record, Some(DEMO_MAX_OUTPUT_BYTES))
                {
                    return demo_pipeline_error(&error);
                }
            }
            if Instant::now() >= deadline {
                return demo_pipeline_error(&demo_deadline_error());
            }
            bounded_demo_json(&serde_json::json!({
                "redacted": String::from_utf8_lossy(&bytes),
                "records_processed": records_processed,
            }))
        }
        Err(error) => demo_pipeline_error(&error),
    }
}

async fn demo_process(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> axum::response::Response {
    let _permit = match start_demo_operation(&state) {
        Ok(permit) => permit,
        Err(error) => return demo_limit_response(error),
    };
    let deadline = Instant::now() + DEMO_MAX_WALL_TIME;
    let DemoProcessRequest { records, mode } = match decode_demo_json(request, deadline).await {
        Ok(body) => body,
        Err(error) => return demo_body_error(error),
    };
    if records.is_empty() || records.len() > DEMO_MAX_RECORDS {
        return demo_error(
            StatusCode::BAD_REQUEST,
            "invalid_record_count",
            "Demo requests require 1-10 records",
        );
    }

    let mut canonical_records = Vec::with_capacity(records.len());
    let mut input_bytes = 0usize;
    for record in &records {
        if Instant::now() >= deadline {
            return demo_pipeline_error(&demo_deadline_error());
        }
        let canonical = match serde_json::to_vec(record) {
            Ok(canonical) => canonical,
            Err(_) => {
                return demo_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Invalid demo request",
                );
            }
        };
        input_bytes = input_bytes.saturating_add(canonical.len());
        if input_bytes > DEMO_MAX_INPUT_BYTES {
            return demo_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "input_too_large",
                "Demo input exceeds 64 KiB",
            );
        }
        // Demo records are returned as independent values rather than one
        // concatenated JSON document. Model that framing explicitly as JSONL
        // while the pipeline runs, then strip the known separator below.
        canonical_records.push(crate::record::Record::new(
            canonical,
            bytes::Bytes::from_static(b"\n"),
        ));
    }

    let snapshot = match demo_pipeline(&state, mode) {
        Some(snapshot) => snapshot,
        None => {
            return demo_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "join_unavailable",
                "Join demo mode is unavailable",
            );
        }
    };
    let stable_key = match mode {
        DemoMode::Safe => None,
        DemoMode::Join => Some(demo_request_stable_key()),
    };
    let session = s4_wasm_runtime::Session {
        format: Format::Jsonl.as_str().to_string(),
        content_type: "application/x-ndjson".to_string(),
        policy_version: 0,
        operation: s4_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: None,
        stable_key: stable_key.as_ref().map(|key| key.as_slice().to_vec()),
        stable_fields: matches!(mode, DemoMode::Join).then(|| "email".to_string()),
    };
    let (output, trailing) =
        match execute_demo_records(snapshot, session, canonical_records, deadline).await {
            Ok(output) => output,
            Err(error) => return demo_pipeline_error(&error),
        };
    if !trailing.is_empty() {
        return demo_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pipeline_failed",
            "Demo processing failed",
        );
    }
    let mut output_bytes = 0usize;
    let mut processed = Vec::with_capacity(output.len());
    for (index, record) in output.into_iter().enumerate() {
        if record.separator.as_ref() != b"\n" {
            return demo_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "pipeline_failed",
                "Demo processing failed",
            );
        }
        output_bytes = output_bytes.saturating_add(record.payload.len());
        if output_bytes > DEMO_MAX_OUTPUT_BYTES {
            return demo_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "output_too_large",
                "Demo output exceeds 64 KiB",
            );
        }
        let body = match String::from_utf8(record.payload.to_vec()) {
            Ok(body) => body,
            Err(_) => {
                return demo_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "pipeline_failed",
                    "Demo processing failed",
                );
            }
        };
        processed.push(DemoProcessedRecord {
            record: index + 1,
            body,
        });
    }
    if Instant::now() >= deadline {
        return demo_pipeline_error(&demo_deadline_error());
    }
    bounded_demo_json(&DemoProcessResponse {
        mode,
        records: processed,
    })
}

async fn legacy_demo_gone() -> axum::response::Response {
    harden_demo_response(StatusCode::GONE.into_response())
}

fn s3_xml_ok(xml: String) -> axum::response::Response {
    let mut response = axum::response::Response::new(axum::body::Body::from(xml));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/xml".parse().expect("static content type"),
    );
    harden_object_response_headers(response.headers_mut());
    response
}

fn wants_transformed_read(headers: &HeaderMap) -> bool {
    customer_headers::validated(headers, customer_headers::PROCESS)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("read") || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[derive(Debug)]
enum StreamingPutError {
    Integrity(IntegrityError),
    Pipeline(s4_error::S4Error),
    Transaction(TransactionError),
    InputTooLarge,
    SourceFrameTooLarge,
    Transport,
    InvalidRequest(String),
    Unsupported(String),
    PreserveReservation(Box<StreamingPutError>),
}

impl StreamingPutError {
    fn preserves_reservation(&self) -> bool {
        matches!(self, Self::PreserveReservation(_))
    }
}

impl From<s4_error::S4Error> for StreamingPutError {
    fn from(error: s4_error::S4Error) -> Self {
        Self::Pipeline(error)
    }
}

impl From<TransactionError> for StreamingPutError {
    fn from(error: TransactionError) -> Self {
        Self::Transaction(error)
    }
}

fn streaming_put_error_response(key: &str, error: StreamingPutError) -> axum::response::Response {
    match error {
        StreamingPutError::PreserveReservation(error) => streaming_put_error_response(key, *error),
        StreamingPutError::Integrity(
            IntegrityError::PayloadHashMismatch | IntegrityError::SignatureMismatch,
        ) => s3_error::signature_mismatch(key),
        StreamingPutError::Integrity(
            error @ (IntegrityError::InvalidChecksum(_)
            | IntegrityError::MissingChecksum
            | IntegrityError::DecodedLengthMismatch),
        ) => s3_error::bad_digest(key, &error.to_string()),
        StreamingPutError::Integrity(error) => s3_error::invalid_request(key, &error.to_string()),
        StreamingPutError::Pipeline(error) => pipeline_error_response(key, &error),
        StreamingPutError::Transaction(
            TransactionError::CapacityExceeded | TransactionError::TooManyParts,
        ) => s3_error::entity_too_large(key),
        StreamingPutError::Transaction(TransactionError::Spool(detail)) => {
            s3_error::internal_error(key, &detail)
        }
        StreamingPutError::Transaction(TransactionError::Backend(error))
            if error.kind == BackendErrorKind::Definitive =>
        {
            s3_error::service_unavailable(key, "The destination rejected the write request.")
        }
        StreamingPutError::Transaction(error) => s3_error::internal_error(key, &error.to_string()),
        StreamingPutError::InputTooLarge | StreamingPutError::SourceFrameTooLarge => {
            s3_error::entity_too_large(key)
        }
        StreamingPutError::Transport => {
            s3_error::invalid_request(key, "request body stream failed")
        }
        StreamingPutError::InvalidRequest(detail) => s3_error::invalid_request(key, &detail),
        StreamingPutError::Unsupported(detail) => {
            warn!("streaming PUT rejected for {key}: {detail}");
            s3_error::not_implemented(key)
        }
    }
}

fn pipeline_error_response(key: &str, error: &s4_error::S4Error) -> axum::response::Response {
    match error.code() {
        s4_error::codes::WASM_ADMISSION => s3_error::slow_down(key),
        s4_error::codes::LIMIT_INPUT_BYTES
        | s4_error::codes::LIMIT_OUTPUT_BYTES
        | s4_error::codes::LIMIT_EXPANSION
        | s4_error::codes::LIMIT_INTERMEDIATE_BYTES
        | s4_error::codes::LIMIT_FINISH_BYTES
        | s4_error::codes::RECORD_TOO_LARGE => s3_error::entity_too_large(key),
        s4_error::codes::DECODE_JSON
        | s4_error::codes::DECODE_JSONL
        | s4_error::codes::DECODE_CSV
        | s4_error::codes::DECODE_ENCODING
        | s4_error::codes::WASM_REJECT
        | s4_error::codes::UNSUPPORTED_FORMAT
        | s4_error::codes::CONFIG_INVALID
        | s4_error::codes::POLICY_EXPIRED
        | s4_error::codes::POLICY_TAMPERED => {
            s3_error::invalid_request(key, "The processing pipeline rejected the request.")
        }
        _ => s3_error::internal_error(key, error.code()),
    }
}

async fn streaming_put_failure_response(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    grant: &AuthorizationGrant,
    key: &str,
    error: StreamingPutError,
) -> axum::response::Response {
    let preserve_reservation = error.preserves_reservation();
    let response = streaming_put_error_response(key, error);
    if preserve_reservation {
        response
    } else {
        release_failure(control, context, grant, key, response).await
    }
}

fn streaming_format(headers: &HeaderMap) -> Result<(Format, String), StreamingPutError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .ok_or_else(|| StreamingPutError::InvalidRequest("Content-Type is required".to_string()))?
        .to_str()
        .map_err(|_| StreamingPutError::InvalidRequest("invalid Content-Type".to_string()))?;
    streaming_format_content_type(content_type)
}

fn streaming_format_content_type(
    content_type: &str,
) -> Result<(Format, String), StreamingPutError> {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let format = match media_type.as_str() {
        "text/plain" => Format::Text,
        "application/x-ndjson" | "application/jsonlines" => Format::Jsonl,
        "application/json" => Format::Json,
        "text/csv" => Format::Csv,
        "text/tab-separated-values" => Format::Tsv,
        _ => {
            return Err(StreamingPutError::Unsupported(format!(
                "unsupported streaming Content-Type {media_type:?}"
            )));
        }
    };
    Ok((format, media_type))
}

struct WorkspaceMutationFence {
    repository: Arc<dyn WorkspaceStorageRepository>,
    workspace_id: WorkspaceId,
    lease: tokio::sync::Mutex<WorkspaceOperationLease>,
    ttl: Duration,
    stopped: std::sync::atomic::AtomicBool,
    cancelled: tokio::sync::Notify,
}

impl WorkspaceMutationFence {
    fn new(
        repository: Arc<dyn WorkspaceStorageRepository>,
        workspace_id: WorkspaceId,
        lease: WorkspaceOperationLease,
        ttl: Duration,
    ) -> Arc<Self> {
        let fence = Arc::new(Self {
            repository,
            workspace_id,
            lease: tokio::sync::Mutex::new(lease),
            ttl,
            stopped: std::sync::atomic::AtomicBool::new(false),
            cancelled: tokio::sync::Notify::new(),
        });
        let weak = Arc::downgrade(&fence);
        tokio::spawn(async move {
            loop {
                let Some(interval) = weak.upgrade().map(|fence| fence.heartbeat_interval()) else {
                    return;
                };
                tokio::time::sleep(interval).await;
                let Some(fence) = weak.upgrade() else {
                    return;
                };
                if fence.stopped.load(std::sync::atomic::Ordering::Acquire)
                    || fence.heartbeat().await.is_err()
                {
                    return;
                }
            }
        });
        fence
    }

    fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Release);
        self.cancelled.notify_waiters();
    }

    async fn terminal_lease(&self) -> WorkspaceOperationLease {
        self.lease.lock().await.clone()
    }

    fn lost(&self) -> BackendError {
        BackendError::ambiguous("workspace routing lease was lost")
    }
}

#[async_trait::async_trait]
impl ProviderMutationFence for WorkspaceMutationFence {
    fn heartbeat_interval(&self) -> Duration {
        (self.ttl / 4).max(Duration::from_millis(1))
    }

    async fn assert_current(&self) -> Result<(), BackendError> {
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return Err(self.lost());
        }
        let lease = self.lease.lock().await;
        self.repository
            .assert_streaming_operation_lease(&self.workspace_id, &lease)
            .await
            .map_err(|_| self.lost())
    }

    async fn heartbeat(&self) -> Result<(), BackendError> {
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return Err(self.lost());
        }
        let mut lease = self.lease.lock().await;
        *lease = self
            .repository
            .renew_streaming_operation_lease(&self.workspace_id, &lease, self.ttl)
            .await
            .map_err(|_| {
                self.stopped
                    .store(true, std::sync::atomic::Ordering::Release);
                self.cancelled.notify_waiters();
                self.lost()
            })?;
        drop(lease);
        Ok(())
    }

    async fn cancelled(&self) {
        loop {
            let cancelled = self.cancelled.notified();
            if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            cancelled.await;
        }
    }
}

struct WorkspaceLeasedSink {
    inner: DirectS3Sink,
    fence: Arc<WorkspaceMutationFence>,
}

impl WorkspaceLeasedSink {
    async fn release(&self, outcome: WorkspaceOperationOutcome) -> Result<(), TransactionError> {
        self.fence.stop();
        let lease = self.fence.terminal_lease().await;
        self.fence
            .repository
            .release_streaming_operation_lease(&self.fence.workspace_id, &lease, outcome)
            .await
            .map_err(|_| {
                TransactionError::Publication(
                    "workspace routing lease terminal update failed".to_string(),
                )
            })
    }
}

#[async_trait::async_trait]
impl ObjectSinkTransaction for WorkspaceLeasedSink {
    fn commit_state(&self) -> crate::transaction::SinkCommitState {
        self.inner.commit_state()
    }

    fn durable_operation_id(&self) -> Option<Uuid> {
        self.inner.durable_operation_id()
    }

    async fn write(&mut self, chunk: bytes::Bytes) -> Result<(), TransactionError> {
        self.inner.write(chunk).await
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        self.inner
            .verify_output(expected_size, expected_sha256)
            .await
    }

    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        self.fence.assert_current().await.map_err(|_| {
            TransactionError::Publication("workspace routing fence changed".to_string())
        })?;
        let stored = self.inner.complete().await?;
        self.release(WorkspaceOperationOutcome::Committed).await?;
        Ok(stored)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        self.fence
            .assert_current()
            .await
            .map_err(TransactionError::Backend)?;
        self.inner.abort().await?;
        self.release(WorkspaceOperationOutcome::ProvenAborted).await
    }
}

fn direct_journal_allowed(
    kind: BackendKind,
    journal: Option<&Arc<dyn OperationJournal>>,
    auth_disabled: bool,
    explicit_single_tenant: bool,
) -> bool {
    journal.is_some_and(|journal| {
        journal.is_durable()
            || (kind == BackendKind::GlobalS3
                && cfg!(debug_assertions)
                && auth_disabled
                && explicit_single_tenant)
    })
}

async fn begin_streaming_sink(
    state: &AppState,
    backend: ResolvedBackend,
    operation: AuthorizedOperation<'_>,
    bucket: &str,
    key: &str,
    content_type: &str,
) -> Result<Box<dyn ObjectSinkTransaction>, StreamingPutError> {
    validate_streaming_backend(state, &backend)?;
    match backend {
        ResolvedBackend::S3 {
            kind,
            client,
            workspace_streaming,
        } => {
            let journal = state.operation_journal.clone().ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "direct S3 streaming needs a durable operation journal".to_string(),
                )
            })?;
            if !direct_journal_allowed(
                kind,
                Some(&journal),
                state.auth_disabled,
                state.explicit_single_tenant,
            ) {
                return Err(StreamingPutError::Unsupported(
                    "direct S3 streaming needs a durable operation journal".to_string(),
                ));
            }
            let expected = ExpectedObject {
                metadata: std::collections::BTreeMap::from([(
                    "content-type".to_string(),
                    content_type.to_string(),
                )]),
                ..ExpectedObject::default()
            };
            let scope = direct_operation_scope(operation);
            let (capabilities, backend_id, workspace_lease) = match kind {
                BackendKind::PerUserS3 => {
                    let binding = workspace_streaming.ok_or_else(|| {
                        StreamingPutError::Unsupported(
                            "workspace S3 streaming needs an immutable operator attestation and durable routing lease contract"
                                .to_string(),
                        )
                    })?;
                    let workspace_id = operation.auth.workspace_id().clone();
                    let provisional = OperationRecord::direct_intent(
                        scope.clone(),
                        ObjectDestination {
                            backend_id: "PerUserS3".to_string(),
                            bucket: bucket.to_string(),
                            logical_key: key.to_string(),
                            physical_key: key.to_string(),
                            workspace_binding: None,
                        },
                        expected.clone(),
                    );
                    let lease = state
                        .workspace_storage
                        .admit_streaming_operation(
                            &workspace_id,
                            &provisional,
                            &binding.identity.config_version,
                            &binding.identity.attestation.id,
                            binding.routing_epoch,
                            WORKSPACE_OPERATION_LEASE_TTL,
                        )
                        .await
                        .map_err(|error| match error {
                            WorkspaceStorageError::AmbiguousAdmission(_) => {
                                StreamingPutError::PreserveReservation(Box::new(
                                    StreamingPutError::Unsupported(
                                        "workspace S3 streaming admission outcome is pending recovery"
                                            .to_string(),
                                    ),
                                ))
                            }
                            _ => StreamingPutError::Unsupported(
                                "workspace S3 streaming atomic admission is unavailable".to_string(),
                            ),
                        })?;
                    (
                        binding.identity.attestation.capabilities,
                        "PerUserS3".to_string(),
                        Some((binding, workspace_id, lease)),
                    )
                }
                BackendKind::GlobalS3 => (
                    state.s3_streaming_capabilities.ok_or_else(|| {
                        StreamingPutError::Unsupported(
                            "direct global S3 streaming needs MASKURA_STREAMING_S3_PROVIDER"
                                .to_string(),
                        )
                    })?,
                    format!("{kind:?}"),
                    None,
                ),
                _ => {
                    return Err(StreamingPutError::Unsupported(
                        "direct S3 streaming backend kind is unsupported".to_string(),
                    ));
                }
            };
            let destination = ObjectDestination {
                backend_id,
                bucket: bucket.to_string(),
                logical_key: key.to_string(),
                physical_key: key.to_string(),
                workspace_binding: workspace_lease.as_ref().map(|(binding, _, lease)| {
                    WorkspaceDestinationBinding {
                        backend_config_version: binding
                            .identity
                            .config_version
                            .as_str()
                            .to_string(),
                        capability_attestation_id: binding
                            .identity
                            .attestation
                            .id
                            .as_str()
                            .to_string(),
                        routing_epoch: lease.routing_epoch,
                        routing_lease_id: lease.lease_id,
                        routing_fencing_token: lease.fencing_token,
                    }
                }),
            };
            let exact_b2 = workspace_lease.as_ref().is_some_and(|(binding, _, _)| {
                binding.provider == crate::backend::WorkspaceS3Provider::B2
                    && binding.identity.attestation.exact_version_recovery
            });
            let mutation_fence = workspace_lease.as_ref().map(|(_, workspace_id, lease)| {
                WorkspaceMutationFence::new(
                    state.workspace_storage.clone(),
                    workspace_id.clone(),
                    lease.clone(),
                    WORKSPACE_OPERATION_LEASE_TTL,
                )
            });
            let mut transaction_backend = if exact_b2 {
                AwsS3TransactionBackend::new_b2(client, capabilities)
            } else {
                AwsS3TransactionBackend::new(client, capabilities)
            };
            if let Some(fence) = &mutation_fence {
                transaction_backend = transaction_backend
                    .with_mutation_fence(fence.clone() as Arc<dyn ProviderMutationFence>);
            }
            let backend = Arc::new(transaction_backend);
            let (abort_signal, mut abort_receiver) = AbortSignal::channel(1);
            let reconciler = OperationReconciler::new(
                journal.clone(),
                backend.clone(),
                format!("request-{}", uuid::Uuid::now_v7()),
            )
            .map_err(TransactionError::from)?;
            tokio::spawn(async move {
                while let Some(operation_id) = abort_receiver.recv().await {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if let Err(error) = reconciler
                        .reconcile_operation(operation_id, Duration::from_secs(1))
                        .await
                    {
                        warn!("streaming transaction cleanup failed: {error}");
                    }
                }
            });
            let sink = if workspace_lease.is_some() {
                DirectS3Sink::new_direct_admitted(
                    journal,
                    backend,
                    scope,
                    destination,
                    expected,
                    3,
                    abort_signal,
                )
                .await
            } else {
                DirectS3Sink::new_direct(
                    journal,
                    backend,
                    scope,
                    destination,
                    expected,
                    3,
                    abort_signal,
                )
                .await
            };
            match (sink, workspace_lease) {
                (Ok(inner), Some(_)) => Ok(Box::new(WorkspaceLeasedSink {
                    inner,
                    fence: mutation_fence.expect("workspace lease created a mutation fence"),
                })),
                (Ok(inner), None) => Ok(Box::new(inner)),
                (Err(error), Some(_)) => {
                    if let Some(fence) = mutation_fence {
                        fence.stop();
                    }
                    Err(StreamingPutError::PreserveReservation(Box::new(
                        StreamingPutError::Transaction(error),
                    )))
                }
                (Err(error), None) => Err(error.into()),
            }
        }
        ResolvedBackend::PresignedHttp(_) => Err(StreamingPutError::Unsupported(
            "presigned streaming cannot durably align the authorization and transaction journals"
                .to_string(),
        )),
        ResolvedBackend::Memory(store) if state.dev_memory_streaming_enabled => {
            Ok(Box::new(MemorySinkTransaction::new(
                store,
                bucket,
                key,
                content_type,
                state.dev_memory_max_object_bytes,
            )?))
        }
        ResolvedBackend::Memory(_) => Err(StreamingPutError::Unsupported(
            "development memory streaming is not enabled".to_string(),
        )),
        ResolvedBackend::Managed(storage) => {
            let journal = state.operation_journal.clone().ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "managed streaming needs a durable operation journal".to_string(),
                )
            })?;
            if !journal.is_durable() {
                return Err(StreamingPutError::Unsupported(
                    "managed streaming needs a durable operation journal".to_string(),
                ));
            }
            if storage.managed_mode() != ManagedStreamingMode::Enforce {
                return Err(StreamingPutError::Unsupported(
                    "managed streaming requires enforce mode".to_string(),
                ));
            }
            storage
                .validate_managed_launch_configuration()
                .map_err(|detail| {
                    StreamingPutError::Unsupported(format!(
                        "managed streaming configuration is invalid: {detail}"
                    ))
                })?;
            let capabilities = state.managed_streaming_capabilities.ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "managed streaming capabilities are not configured".to_string(),
                )
            })?;
            let repository = storage.authority_repository().cloned().ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "managed streaming has no authority repository".to_string(),
                )
            })?;
            let tenant_id = operation.auth.workspace_id().as_str().to_string();
            let logical = LogicalObjectKey::new(&tenant_id, bucket, key);
            let existing = repository.get(&logical).await.map_err(|error| {
                StreamingPutError::Transaction(TransactionError::Publication(error.to_string()))
            })?;
            let (expected_authority_cas, prior_logical_size) = match existing.as_ref() {
                Some(authority) => (
                    Some(authority.cas_version),
                    if authority.tombstone {
                        0
                    } else {
                        authority.size
                    },
                ),
                None => (None, 0),
            };
            let grant = operation.grant;
            let sink = storage
                .begin_managed_put_sink(
                    journal,
                    capabilities,
                    logical,
                    content_type,
                    grant.operation_id(),
                    grant.receipt_id(),
                    crate::transaction::unix_time_ms(),
                    grant.rate_version(),
                    grant.max_processed_bytes(),
                    expected_authority_cas,
                    prior_logical_size,
                )
                .await?;
            Ok(sink)
        }
    }
}

fn direct_operation_scope(operation: AuthorizedOperation<'_>) -> DirectOperationScope {
    DirectOperationScope {
        operation_id: operation.grant.operation_id(),
        tenant_id: operation.auth.workspace_id().as_str().to_string(),
    }
}

fn validate_streaming_backend(
    state: &AppState,
    backend: &ResolvedBackend,
) -> Result<(), StreamingPutError> {
    match backend {
        ResolvedBackend::S3 {
            kind: BackendKind::PerUserS3,
            workspace_streaming: Some(_),
            ..
        } if direct_journal_allowed(
            BackendKind::PerUserS3,
            state.operation_journal.as_ref(),
            state.auth_disabled,
            state.explicit_single_tenant,
        ) => Ok(()),
        ResolvedBackend::S3 {
            kind: BackendKind::GlobalS3,
            ..
        } if state.s3_streaming_capabilities.is_some()
            && direct_journal_allowed(
                BackendKind::GlobalS3,
                state.operation_journal.as_ref(),
                state.auth_disabled,
                state.explicit_single_tenant,
            ) => Ok(()),
        ResolvedBackend::S3 {
            kind: BackendKind::PerUserS3,
            ..
        } => Err(StreamingPutError::Unsupported(
            "workspace S3 streaming needs a trusted provider capability profile, stable routing fence, and durable operation journal"
                .to_string(),
        )),
        ResolvedBackend::S3 { .. } => Err(StreamingPutError::Unsupported(
            "direct global S3 streaming needs configured capabilities and a durable operation journal"
                .to_string(),
        )),
        ResolvedBackend::Memory(_) if state.dev_memory_streaming_enabled => Ok(()),
        ResolvedBackend::Memory(_) => Err(StreamingPutError::Unsupported(
            "development memory streaming is not enabled".to_string(),
        )),
        ResolvedBackend::PresignedHttp(_) => Err(StreamingPutError::Unsupported(
            "presigned streaming cannot durably align authorization and destination commit"
                .to_string(),
        )),
        ResolvedBackend::Managed(storage)
            if state.operation_journal.as_ref().is_some_and(|journal| journal.is_durable())
                && state.managed_streaming_capabilities.is_some()
                && storage.managed_mode() == ManagedStreamingMode::Enforce
                && storage
                    .authority_repository()
                    .is_some_and(|repository| repository.is_durable())
                && storage.validate_managed_launch_configuration().is_ok() =>
        {
            Ok(())
        }
        ResolvedBackend::Managed(_) => Err(StreamingPutError::Unsupported(
            "managed streaming needs a durable operation journal and authority ledger in enforce mode"
                .to_string(),
        )),
    }
}

async fn write_stream_record(
    sink: &Arc<tokio::sync::Mutex<Box<dyn ObjectSinkTransaction>>>,
    record: crate::record::Record,
    output_hasher: &mut sha2::Sha256,
    output_bytes: &mut u64,
) -> Result<(), StreamingPutError> {
    use sha2::Digest as _;
    for chunk in [record.payload, record.separator] {
        if chunk.is_empty() {
            continue;
        }
        *output_bytes = output_bytes
            .checked_add(chunk.len() as u64)
            .ok_or(StreamingPutError::InputTooLarge)?;
        output_hasher.update(&chunk);
        sink.lock().await.write(chunk).await?;
    }
    Ok(())
}

struct SinkAbortGuard {
    sink: Arc<tokio::sync::Mutex<Box<dyn ObjectSinkTransaction>>>,
    armed: bool,
}

impl SinkAbortGuard {
    fn new(sink: Box<dyn ObjectSinkTransaction>) -> Self {
        Self {
            sink: Arc::new(tokio::sync::Mutex::new(sink)),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SinkAbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let sink = Arc::clone(&self.sink);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = sink.lock().await.abort().await;
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn streaming_single_put(
    state: &AppState,
    mut authentication: HeaderAuthentication,
    backend: ResolvedBackend,
    usage: AuthorizedUsage<'_>,
    snapshot: PipelineSnapshot,
    headers: &HeaderMap,
    mut body: axum::body::Body,
    key: &str,
) -> Result<
    (
        Auth,
        StoredObjectMeta,
        u64,
        u64,
        Option<crate::control::PipelineEvidence>,
    ),
    StreamingPutError,
> {
    use http_body_util::BodyExt as _;
    use sha2::Digest as _;
    let grant = usage.grant;

    if authentication.body_verifier.is_none() && headers.contains_key(header::CONTENT_ENCODING) {
        return Err(StreamingPutError::InvalidRequest(
            "Content-Encoding is unsupported for transformed streaming".to_string(),
        ));
    }
    if is_avro_content_type(headers) {
        if !state.binary_avro_enabled {
            return Err(StreamingPutError::Unsupported(
                "Avro processing is disabled; set MASKURA_ENABLE_AVRO=true".to_string(),
            ));
        }
        return streaming_avro_single_put(
            state,
            authentication,
            backend,
            usage,
            headers,
            body,
            key,
        )
        .await;
    }
    let (format, content_type) = streaming_format(headers)?;
    let sink = begin_streaming_sink(
        state,
        backend,
        AuthorizedOperation {
            auth: &authentication.auth,
            grant,
        },
        grant.bucket(),
        key,
        &content_type,
    )
    .await?;
    let mut sink_guard = SinkAbortGuard::new(sink);
    let sink = Arc::clone(&sink_guard.sink);
    let stable_fields = customer_headers::validated(headers, customer_headers::STABLE_FIELDS)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let session = s4_wasm_runtime::Session {
        format: format.as_str().to_string(),
        content_type: content_type.clone(),
        policy_version: 0,
        operation: s4_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: authentication.auth.public_key_pem.clone(),
        stable_key: authentication.auth.stable_key.clone(),
        stable_fields,
    };
    let cancellation = s4_wasm_runtime::CancellationToken::new();
    let pipeline_started = std::time::Instant::now();
    let mut pipeline = match snapshot
        .clone()
        .start_streaming_session(session, cancellation.clone())
        .await
    {
        Ok(pipeline) => Some(pipeline),
        Err(error) => {
            let _ = sink.lock().await.abort().await;
            sink_guard.disarm();
            return Err(error.into());
        }
    };
    let decoder_limits = crate::record::DecoderLimits {
        max_source_frame_bytes: state.source_body_limits.max_frame_bytes,
        ..crate::record::DecoderLimits::default()
    };
    let mut decoder = crate::record::RecordDecoder::new(format, decoder_limits)?;
    let mut input_bytes = 0_u64;
    let mut output_bytes = 0_u64;
    let mut output_hasher = sha2::Sha256::new();

    let processing = async {
        while let Some(frame) = body
            .frame()
            .await
            .transpose()
            .map_err(|_| StreamingPutError::Transport)?
        {
            let data = frame.into_data().map_err(|frame| {
                if frame.into_trailers().is_ok() {
                    StreamingPutError::Integrity(IntegrityError::Framing(
                        "HTTP trailers are not valid outside aws-chunked framing",
                    ))
                } else {
                    StreamingPutError::Transport
                }
            })?;
            if data.len() > state.source_body_limits.max_frame_bytes {
                return Err(StreamingPutError::SourceFrameTooLarge);
            }
            let decoded = if let Some(verifier) = &mut authentication.body_verifier {
                verifier.push(&data).map_err(StreamingPutError::Integrity)?
            } else {
                vec![data]
            };
            for chunk in decoded {
                input_bytes = input_bytes
                    .checked_add(chunk.len() as u64)
                    .ok_or(StreamingPutError::InputTooLarge)?;
                if input_bytes > state.source_body_limits.max_bytes {
                    return Err(StreamingPutError::InputTooLarge);
                }
                decoder.push(&chunk)?;
                while let Some(record) = decoder.next_record()? {
                    if let Some(record) = pipeline
                        .as_mut()
                        .expect("pipeline remains available until finish")
                        .process(record)
                        .await?
                    {
                        write_stream_record(&sink, record, &mut output_hasher, &mut output_bytes)
                            .await?;
                    }
                }
            }
        }
        if let Some(verifier) = authentication.body_verifier.take() {
            let verified = verifier.finish().map_err(StreamingPutError::Integrity)?;
            if verified != input_bytes {
                return Err(StreamingPutError::Integrity(
                    IntegrityError::DecodedLengthMismatch,
                ));
            }
        }
        decoder.finish()?;
        while let Some(record) = decoder.next_record()? {
            if let Some(record) = pipeline
                .as_mut()
                .expect("pipeline remains available until finish")
                .process(record)
                .await?
            {
                write_stream_record(&sink, record, &mut output_hasher, &mut output_bytes).await?;
            }
        }
        let finishing = pipeline
            .take()
            .expect("pipeline remains available until finish");
        let (records, pipeline_fuel) = finishing.finish().await?;
        for record in records {
            write_stream_record(&sink, record, &mut output_hasher, &mut output_bytes).await?;
        }
        let pipeline_evidence = snapshot.pipeline_evidence(
            pipeline_fuel,
            pipeline_started.elapsed().as_millis() as u64,
            "none",
        );
        let output_digest = hex::encode(output_hasher.finalize());
        let mut sink = sink.lock().await;
        sink.verify_output(output_bytes, &output_digest).await?;
        let mut usage_event = UsageEvent::from_grant(grant, input_bytes, output_bytes);
        if let Some(evidence) = &pipeline_evidence {
            usage_event = usage_event.with_pipeline_evidence(evidence.clone());
        }
        persist_transaction_usage_evidence(
            state.operation_journal.as_ref(),
            sink.durable_operation_id(),
            &usage_event,
        )
        .await
        .map_err(TransactionError::from)?;
        sink.record_usage_evidence(&usage_event).await?;
        let stored = sink.complete().await?;
        Ok((stored, output_bytes, pipeline_evidence))
    }
    .await;

    match processing {
        Ok((stored, output_bytes, pipeline_evidence)) => {
            sink_guard.disarm();
            Ok((
                authentication.auth,
                stored,
                input_bytes,
                output_bytes,
                pipeline_evidence,
            ))
        }
        Err(error) => {
            cancellation.cancel();
            if let Some(pipeline) = pipeline.take() {
                let _ = pipeline.cancel_and_wait().await;
            }
            let preserve_reservation = sink.lock().await.commit_state().preserves_reservation();
            if !preserve_reservation && let Err(abort_error) = sink.lock().await.abort().await {
                warn!(
                    "streaming sink abort failed for /{}/{key}: {abort_error}",
                    grant.bucket()
                );
            }
            sink_guard.disarm();
            if preserve_reservation {
                Err(StreamingPutError::PreserveReservation(Box::new(error)))
            } else {
                Err(error)
            }
        }
    }
}

fn avro_media_type(content_type: &str) -> Option<String> {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(
        media_type.as_str(),
        "application/avro" | "application/x-avro" | "application/vnd.apache.avro+binary"
    )
    .then_some(media_type)
}

fn is_avro_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(avro_media_type)
        .is_some()
}

fn avro_pump(
    auth: &Auth,
    headers: &HeaderMap,
    limits: crate::avro::AvroLimits,
) -> Result<
    crate::binary_pump::BinaryPump<
        crate::binary_reductor::CommonTypeBinaryReductor,
        crate::binary_pump::EnvelopeBinaryTransform,
    >,
    s4_error::S4Error,
> {
    let targets = customer_headers::validated(headers, customer_headers::ENCRYPT_FIELDS)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| {
                    s4_error::S4Error::new(
                        s4_error::codes::CONFIG_INVALID,
                        "invalid x-maskura-encrypt-fields",
                    )
                })
                .and_then(crate::binary_pump::parse_envelope_targets)
        })
        .transpose()?
        .unwrap_or_default();
    let transform =
        crate::binary_pump::EnvelopeBinaryTransform::new(targets, auth.public_key_pem.as_deref())?;
    Ok(crate::binary_pump::BinaryPump::new(
        crate::binary_reductor::CommonTypeBinaryReductor::default(),
        transform,
        limits.ir,
    ))
}

async fn streaming_avro_single_put(
    state: &AppState,
    mut authentication: HeaderAuthentication,
    backend: ResolvedBackend,
    usage: AuthorizedUsage<'_>,
    headers: &HeaderMap,
    mut body: axum::body::Body,
    key: &str,
) -> Result<
    (
        Auth,
        StoredObjectMeta,
        u64,
        u64,
        Option<crate::control::PipelineEvidence>,
    ),
    StreamingPutError,
> {
    use http_body_util::BodyExt as _;
    use sha2::Digest as _;
    let grant = usage.grant;

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| StreamingPutError::InvalidRequest("Content-Type is required".to_string()))?
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let sink = begin_streaming_sink(
        state,
        backend,
        AuthorizedOperation {
            auth: &authentication.auth,
            grant,
        },
        grant.bucket(),
        key,
        &content_type,
    )
    .await?;
    let mut sink_guard = SinkAbortGuard::new(sink);
    let processing = async {
        let mut input = Vec::new();
        let mut input_bytes = 0_u64;
        while let Some(frame) = body
            .frame()
            .await
            .transpose()
            .map_err(|_| StreamingPutError::Transport)?
        {
            let data = frame
                .into_data()
                .map_err(|_| StreamingPutError::Transport)?;
            if data.len() > state.source_body_limits.max_frame_bytes {
                return Err(StreamingPutError::SourceFrameTooLarge);
            }
            let decoded = if let Some(verifier) = &mut authentication.body_verifier {
                verifier.push(&data).map_err(StreamingPutError::Integrity)?
            } else {
                vec![data]
            };
            for chunk in decoded {
                input_bytes = input_bytes
                    .checked_add(chunk.len() as u64)
                    .ok_or(StreamingPutError::InputTooLarge)?;
                if input_bytes > state.source_body_limits.max_bytes {
                    return Err(StreamingPutError::InputTooLarge);
                }
                input.extend_from_slice(&chunk);
            }
        }
        if let Some(verifier) = authentication.body_verifier.take() {
            let verified = verifier.finish().map_err(StreamingPutError::Integrity)?;
            if verified != input_bytes {
                return Err(StreamingPutError::Integrity(
                    IntegrityError::DecodedLengthMismatch,
                ));
            }
        }

        let limits = crate::avro::AvroLimits {
            max_source_bytes: state.source_body_limits.max_bytes.min(64 * 1024 * 1024) as usize,
            ..crate::avro::AvroLimits::default()
        };
        let mut pump = avro_pump(&authentication.auth, headers, limits)?;
        let output = crate::avro::process_ocf(input.as_slice(), limits, &mut pump)?;
        let output_bytes =
            u64::try_from(output.len()).map_err(|_| StreamingPutError::InputTooLarge)?;
        let digest = hex::encode(sha2::Sha256::digest(&output));
        let stored = {
            let mut sink = sink_guard.sink.lock().await;
            sink.write(bytes::Bytes::from(output)).await?;
            sink.verify_output(output_bytes, &digest).await?;
            let usage_event = UsageEvent::from_grant(grant, input_bytes, output_bytes);
            persist_transaction_usage_evidence(
                state.operation_journal.as_ref(),
                sink.durable_operation_id(),
                &usage_event,
            )
            .await
            .map_err(TransactionError::from)?;
            sink.record_usage_evidence(&usage_event).await?;
            sink.complete().await?
        };
        Ok((stored, input_bytes, output_bytes))
    }
    .await;

    match processing {
        Ok((stored, input_bytes, output_bytes)) => {
            sink_guard.disarm();
            Ok((authentication.auth, stored, input_bytes, output_bytes, None))
        }
        Err(error) => {
            let preserve_reservation = sink_guard
                .sink
                .lock()
                .await
                .commit_state()
                .preserves_reservation();
            if !preserve_reservation {
                let _ = sink_guard.sink.lock().await.abort().await;
            }
            sink_guard.disarm();
            if preserve_reservation {
                Err(StreamingPutError::PreserveReservation(Box::new(error)))
            } else {
                Err(error)
            }
        }
    }
}

#[derive(Debug)]
enum VerifiedBodyError {
    Integrity(IntegrityError),
    TooLarge,
    Transport,
}

async fn read_verified_body(
    mut authentication: HeaderAuthentication,
    mut body: axum::body::Body,
    max_decoded_bytes: usize,
) -> Result<(Auth, bytes::Bytes), VerifiedBodyError> {
    let mut decoded = bytes::BytesMut::new();
    while let Some(frame) = body
        .frame()
        .await
        .transpose()
        .map_err(|_| VerifiedBodyError::Transport)?
    {
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => {
                if frame.into_trailers().is_ok() {
                    return Err(VerifiedBodyError::Integrity(IntegrityError::Framing(
                        "HTTP trailers are not valid outside aws-chunked framing",
                    )));
                }
                continue;
            }
        };
        if data.len() > max_decoded_bytes {
            return Err(VerifiedBodyError::TooLarge);
        }
        let chunks = if let Some(verifier) = &mut authentication.body_verifier {
            verifier.push(&data).map_err(VerifiedBodyError::Integrity)?
        } else {
            vec![data]
        };
        for chunk in chunks {
            if decoded.len().saturating_add(chunk.len()) > max_decoded_bytes {
                return Err(VerifiedBodyError::TooLarge);
            }
            decoded.extend_from_slice(&chunk);
        }
    }
    if let Some(verifier) = authentication.body_verifier.take() {
        verifier.finish().map_err(VerifiedBodyError::Integrity)?;
    }
    Ok((authentication.auth, decoded.freeze()))
}

fn multipart_identity(auth: &Auth, bucket: &str, key: &str, upload_id: &str) -> MultipartIdentity {
    MultipartIdentity {
        tenant_id: auth.workspace_id().as_str().to_string(),
        credential_policy_id: auth.credential_policy_id.clone(),
        bucket: bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
    }
}

fn managed_logical_key(auth: &Auth, bucket: &str, key: &str) -> LogicalObjectKey {
    LogicalObjectKey::new(auth.workspace_id().as_str(), bucket, key)
}

fn staged_multipart(state: &AppState) -> Option<&Arc<MultipartStaging>> {
    (state.streaming_write_mode == StreamingWriteMode::All
        && state.multipart_mode == MultipartMode::Staged)
        .then_some(state.multipart_staging.as_ref())
        .flatten()
}

fn multipart_snapshot(
    headers: &HeaderMap,
    backend: &ResolvedBackend,
    plugin_snapshot: serde_json::Value,
    max_bytes: u64,
) -> MultipartSnapshot {
    let mut metadata: std::collections::BTreeMap<String, String> = headers
        .iter()
        .filter_map(|(name, value)| {
            name.as_str()
                .strip_prefix("x-amz-meta-")
                .zip(value.to_str().ok())
                .map(|(name, value)| (name.to_string(), value.to_string()))
        })
        .collect();
    for name in [header::CONTENT_TYPE, header::CONTENT_ENCODING] {
        if let Some(value) = headers.get(&name).and_then(|value| value.to_str().ok()) {
            metadata.insert(name.to_string(), value.to_string());
        }
    }
    let tags = headers
        .get("x-amz-tagging")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split('&')
                .filter_map(|pair| {
                    pair.split_once('=')
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let destination = match backend {
        ResolvedBackend::S3 { .. } => serde_json::json!({"kind":"s3"}),
        ResolvedBackend::Managed(_) => serde_json::json!({"kind":"managed"}),
        ResolvedBackend::Memory(_) => serde_json::json!({"kind":"memory"}),
        ResolvedBackend::PresignedHttp(_) => serde_json::json!({"kind":"presigned-http"}),
    };
    MultipartSnapshot {
        metadata,
        tags,
        checksum_mode: headers
            .get("x-amz-checksum-algorithm")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
        destination,
        plugin_snapshot,
        max_staged_bytes: max_bytes,
    }
}

#[derive(Debug)]
enum MultipartPipelineRestoreError {
    LegacyRawSnapshot,
    Invalid(s4_error::S4Error),
}

fn restore_multipart_pipeline(
    snapshot: &serde_json::Value,
) -> Result<crate::pipeline::PipelineResolution, MultipartPipelineRestoreError> {
    let resolution =
        serde_json::from_value::<crate::pipeline::PipelineResolution>(snapshot.clone())
            .map_err(|_| MultipartPipelineRestoreError::LegacyRawSnapshot)?;
    resolution
        .verify_fingerprint(crate::pipeline::PipelineDirection::Write)
        .map_err(MultipartPipelineRestoreError::Invalid)?;
    Ok(resolution)
}

fn staged_part_reservation(headers: &HeaderMap) -> Result<u64, StagingError> {
    // SigV4 streaming carries the decoded length separately; reserving the
    // HTTP framing length would under/over-account the persisted plaintext.
    headers
        .get("x-amz-decoded-content-length")
        .or_else(|| headers.get(header::CONTENT_LENGTH))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|bytes| *bytes > 0)
        .ok_or(StagingError::InvalidPart)
}

fn create_multipart_xml(bucket: &str, key: &str, upload_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id)
    )
}

fn list_parts_xml(
    bucket: &str,
    key: &str,
    upload_id: &str,
    parts: &[MultipartPart],
    truncated: bool,
) -> String {
    let part_xml: String = parts.iter().map(|part| format!("<Part><PartNumber>{}</PartNumber><ETag>{}</ETag><Size>{}</Size><ChecksumSHA256>{}</ChecksumSHA256></Part>", part.part_number, xml_escape(&part.etag), part.size_bytes, part.checksum_sha256)).collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><IsTruncated>{}</IsTruncated>{part_xml}</ListPartsResult>",
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id),
        truncated
    )
}

const MAX_COMPLETE_XML_BYTES: usize = 1024 * 1024;
const MAX_MULTIPART_COMPLETION_SECS: u64 = 240;

fn complete_multipart_xml(bucket: &str, key: &str, result: &MultipartCompletionResult) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Location>/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>",
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(result.etag.as_deref().unwrap_or_default()),
    )
}

/// Strictly parses the small CompleteMultipartUpload grammar instead of using a
/// general XML resolver. DTDs and entities are rejected before tokenization;
/// S3's part ETags and SHA-256 checksums need no entity expansion.
fn parse_complete_multipart_xml(body: &[u8]) -> Result<Vec<CompletePart>, String> {
    if body.len() > MAX_COMPLETE_XML_BYTES {
        return Err("CompleteMultipartUpload XML exceeds 1 MiB".to_string());
    }
    let input = std::str::from_utf8(body)
        .map_err(|_| "CompleteMultipartUpload XML must be UTF-8".to_string())?;
    if input.contains("<!") || input.contains('&') {
        return Err("CompleteMultipartUpload XML entities and DTDs are prohibited".to_string());
    }
    let mut stack = Vec::<String>::new();
    let mut parts = Vec::new();
    let mut current_number = None;
    let mut current_etag = None;
    let mut current_checksum = None;
    let mut cursor = 0;
    let mut root_started = false;
    let mut root_closed = false;
    while cursor < input.len() {
        let open = input[cursor..]
            .find('<')
            .map(|index| cursor + index)
            .ok_or_else(|| "malformed CompleteMultipartUpload XML".to_string())?;
        let text = input[cursor..open].trim();
        if !text.is_empty() {
            match stack.last().map(String::as_str) {
                Some("PartNumber") => {
                    if current_number.is_some() {
                        return Err("duplicate PartNumber value".to_string());
                    }
                    current_number = Some(
                        text.parse::<u32>()
                            .ok()
                            .filter(|number| *number > 0)
                            .ok_or_else(|| "invalid PartNumber".to_string())?,
                    );
                }
                Some("ETag") => {
                    if current_etag.replace(text.to_string()).is_some() {
                        return Err("duplicate ETag value".to_string());
                    }
                }
                Some("ChecksumSHA256") => {
                    if current_checksum.replace(text.to_string()).is_some() {
                        return Err("duplicate ChecksumSHA256 value".to_string());
                    }
                }
                _ => return Err("unexpected XML character data".to_string()),
            }
        }
        let close = input[open..]
            .find('>')
            .map(|index| open + index)
            .ok_or_else(|| "malformed CompleteMultipartUpload XML".to_string())?;
        let raw = input[open + 1..close].trim();
        cursor = close + 1;
        if root_closed {
            return Err("multiple CompleteMultipartUpload XML roots".to_string());
        }
        if raw.starts_with('?') && raw.ends_with('?') {
            if !stack.is_empty() || !parts.is_empty() {
                return Err("XML declaration is not at the beginning".to_string());
            }
            continue;
        }
        if let Some(raw) = raw.strip_prefix('/') {
            let name = raw.trim().rsplit(':').next().unwrap_or_default();
            if stack.last().map(String::as_str) != Some(name) {
                return Err("mismatched CompleteMultipartUpload XML element".to_string());
            }
            stack.pop();
            if name == "CompleteMultipartUpload" {
                root_closed = true;
            }
            if name == "Part" {
                let part_number = current_number
                    .take()
                    .ok_or_else(|| "Part is missing PartNumber".to_string())?;
                let etag = current_etag
                    .take()
                    .filter(|etag| !etag.is_empty())
                    .ok_or_else(|| "Part is missing ETag".to_string())?;
                parts.push(CompletePart {
                    part_number,
                    etag,
                    checksum_sha256: current_checksum.take(),
                });
            }
            continue;
        }
        if raw.ends_with('/') {
            return Err(
                "self-closing CompleteMultipartUpload XML elements are not allowed".to_string(),
            );
        }
        let name = raw
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .rsplit(':')
            .next()
            .unwrap_or_default();
        let allowed = match (stack.len(), name) {
            (0, "CompleteMultipartUpload") if !root_started => true,
            (1, "Part") if stack.last().map(String::as_str) == Some("CompleteMultipartUpload") => {
                current_number = None;
                current_etag = None;
                current_checksum = None;
                true
            }
            (2, "PartNumber" | "ETag" | "ChecksumSHA256")
                if stack.last().map(String::as_str) == Some("Part") =>
            {
                true
            }
            _ => false,
        };
        if !allowed {
            return Err("unexpected CompleteMultipartUpload XML element".to_string());
        }
        if name == "CompleteMultipartUpload" {
            root_started = true;
        }
        stack.push(name.to_string());
    }
    if !root_started || !root_closed || !stack.is_empty() || parts.is_empty() {
        return Err("malformed CompleteMultipartUpload XML".to_string());
    }
    if parts
        .windows(2)
        .any(|pair| pair[0].part_number >= pair[1].part_number)
    {
        return Err("parts must be sorted and nonduplicate".to_string());
    }
    Ok(parts)
}

async fn cleanup_staged_parts(
    staging: &MultipartStaging,
    upload_id: &str,
    parts: Vec<MultipartPart>,
    kind: &str,
) -> bool {
    let mut complete = true;
    for part in parts {
        let result = staging.artifacts.delete(&part.artifact_key).await;
        let detail = match result {
            Ok(()) => match staging
                .repository
                .confirm_artifact_deleted(&part.artifact_key)
                .await
            {
                Ok(()) => {
                    serde_json::json!({"part_number":part.part_number,"attempt":part.attempt})
                }
                Err(error) => {
                    complete = false;
                    serde_json::json!({"part_number":part.part_number,"attempt":part.attempt,"error":error.to_string()})
                }
            },
            Err(error) => {
                complete = false;
                serde_json::json!({"part_number":part.part_number,"attempt":part.attempt,"error":error.to_string()})
            }
        };
        if let Err(error) = staging
            .repository
            .audit(CleanupAudit {
                id: Uuid::now_v7(),
                upload_id: upload_id.to_string(),
                kind: kind.to_string(),
                detail,
                created_at_ms: now_ms(),
            })
            .await
        {
            warn!("multipart cleanup audit failed: {error}");
        }
    }
    complete
}

#[derive(Debug)]
enum MultipartCompletionError {
    Staging(StagingError),
    Streaming(StreamingPutError),
    Invalid(String),
    PreserveReservation(Box<MultipartCompletionError>),
}

impl MultipartCompletionError {
    fn preserves_reservation(&self) -> bool {
        matches!(self, Self::PreserveReservation(_))
    }

    fn into_cause(self) -> Self {
        match self {
            Self::PreserveReservation(error) => *error,
            error => error,
        }
    }
}

impl From<StagingError> for MultipartCompletionError {
    fn from(error: StagingError) -> Self {
        Self::Staging(error)
    }
}

impl From<StreamingPutError> for MultipartCompletionError {
    fn from(error: StreamingPutError) -> Self {
        Self::Streaming(error)
    }
}

impl From<s4_error::S4Error> for MultipartCompletionError {
    fn from(error: s4_error::S4Error) -> Self {
        Self::Streaming(error.into())
    }
}

impl From<TransactionError> for MultipartCompletionError {
    fn from(error: TransactionError) -> Self {
        Self::Streaming(error.into())
    }
}

async fn renew_and_fence_completion(
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    lease: &CompletionLease,
) -> Result<(), StagingError> {
    let now = now_ms();
    staging
        .repository
        .renew_completion(
            identity,
            lease.fencing_token,
            now + COMPLETION_LEASE.as_millis() as i64,
        )
        .await?;
    staging
        .repository
        .check_completion_lease(identity, lease.fencing_token, now_ms())
        .await
}

async fn write_completed_record(
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    lease: &CompletionLease,
    sink: &mut Box<dyn ObjectSinkTransaction>,
    record: crate::record::Record,
    output_hasher: &mut sha2::Sha256,
    output_bytes: &mut u64,
) -> Result<(), MultipartCompletionError> {
    use sha2::Digest as _;

    for chunk in [record.payload, record.separator] {
        if chunk.is_empty() {
            continue;
        }
        renew_and_fence_completion(staging, identity, lease).await?;
        *output_bytes = output_bytes
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| MultipartCompletionError::Invalid("output is too large".to_string()))?;
        output_hasher.update(&chunk);
        sink.write(chunk).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn complete_staged_multipart(
    state: &AppState,
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    upload: &MultipartUpload,
    lease: &CompletionLease,
    operation: AuthorizedOperation<'_>,
    backend: ResolvedBackend,
    resolution: &crate::pipeline::PipelineResolution,
) -> Result<MultipartCompletionResult, MultipartCompletionError> {
    use sha2::Digest as _;

    let destination_kind = match &backend {
        ResolvedBackend::S3 { .. } => "s3",
        ResolvedBackend::Managed(_) => "managed",
        ResolvedBackend::Memory(_) => "memory",
        ResolvedBackend::PresignedHttp(_) => "presigned-http",
    };
    if upload
        .snapshot
        .destination
        .get("kind")
        .and_then(serde_json::Value::as_str)
        != Some(destination_kind)
    {
        return Err(MultipartCompletionError::Invalid(
            "multipart destination changed since initiation".to_string(),
        ));
    }
    // Completion executes the exact persisted resolution, never the current
    // assignment. Legacy raw PluginInfo snapshots are rejected explicitly:
    // their process-local UUID identities cannot be proven restart-safe.
    let snapshot = state.gateway.snapshot_for(resolution).await?;
    let pipeline_started = std::time::Instant::now();
    let content_type = upload
        .snapshot
        .metadata
        .get("content-type")
        .ok_or_else(|| {
            MultipartCompletionError::Invalid("multipart Content-Type is missing".to_string())
        })?;
    if let Some(avro_media) = avro_media_type(content_type) {
        if !state.binary_avro_enabled {
            return Err(MultipartCompletionError::Streaming(
                StreamingPutError::Unsupported(
                    "Avro processing is disabled; set MASKURA_ENABLE_AVRO=true".to_string(),
                ),
            ));
        }
        return complete_staged_avro_multipart(
            state,
            staging,
            identity,
            upload,
            lease,
            operation,
            backend,
            &avro_media,
        )
        .await;
    }
    let (format, content_type) = streaming_format_content_type(content_type)?;
    renew_and_fence_completion(staging, identity, lease).await?;
    let mut sink = begin_streaming_sink(
        state,
        backend,
        operation,
        &identity.bucket,
        &identity.key,
        &content_type,
    )
    .await?;
    let cancellation = s4_wasm_runtime::CancellationToken::new();
    let session = s4_wasm_runtime::Session {
        format: format.as_str().to_string(),
        content_type,
        policy_version: 0,
        operation: s4_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: operation.auth.public_key_pem.clone(),
        stable_key: operation.auth.stable_key.clone(),
        stable_fields: None,
    };
    let mut pipeline = Some(
        snapshot
            .clone()
            .start_streaming_session(session, cancellation.clone())
            .await?,
    );
    let limits = crate::record::DecoderLimits {
        max_source_frame_bytes: state.source_body_limits.max_frame_bytes,
        ..crate::record::DecoderLimits::default()
    };
    let mut decoder = crate::record::RecordDecoder::new(format, limits)?;
    let mut input_bytes = 0_u64;
    let mut output_bytes = 0_u64;
    let mut output_hasher = sha2::Sha256::new();

    let processing = async {
        for part in &lease.selected_parts {
            renew_and_fence_completion(staging, identity, lease).await?;
            let body = staging.artifacts.get(&part.artifact_key).await?;
            renew_and_fence_completion(staging, identity, lease).await?;
            let mut reader = EncryptedPartReader::open(
                body.into_async_read(),
                identity,
                part,
                &upload.snapshot,
                staging.wrapping.clone(),
            )
            .await?;
            let mut part_bytes = 0_u64;
            let mut part_sha256 = sha2::Sha256::new();
            let mut part_md5 = Md5::new();
            loop {
                renew_and_fence_completion(staging, identity, lease).await?;
                let Some(chunk) = reader.next_chunk().await? else {
                    break;
                };
                part_bytes = part_bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
                    MultipartCompletionError::Invalid("multipart part is too large".to_string())
                })?;
                input_bytes = input_bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
                    MultipartCompletionError::Invalid("multipart input is too large".to_string())
                })?;
                if part_bytes > part.size_bytes || input_bytes > state.source_body_limits.max_bytes
                {
                    return Err(MultipartCompletionError::Invalid(
                        "multipart input exceeds its limit".to_string(),
                    ));
                }
                part_sha256.update(&chunk);
                part_md5.update(&chunk);
                decoder.push(&chunk)?;
                while let Some(record) = decoder.next_record()? {
                    if let Some(record) = pipeline
                        .as_mut()
                        .expect("pipeline is present until finish")
                        .process(record)
                        .await?
                    {
                        write_completed_record(
                            staging,
                            identity,
                            lease,
                            &mut sink,
                            record,
                            &mut output_hasher,
                            &mut output_bytes,
                        )
                        .await?;
                    }
                }
            }
            if part_bytes != part.size_bytes
                || hex::encode(part_sha256.finalize()) != part.checksum_sha256
                || format!("\"{}\"", hex::encode(part_md5.finalize())) != part.etag
            {
                return Err(MultipartCompletionError::Invalid(
                    "staged multipart artifact does not match its committed part".to_string(),
                ));
            }
            // JSON is a whole-document format: parts carry independent
            // documents, so flush a completed document at each part boundary
            // instead of concatenating every part into one JSON value.
            decoder.end_of_segment()?;
            while let Some(record) = decoder.next_record()? {
                if let Some(record) = pipeline
                    .as_mut()
                    .expect("pipeline is present until finish")
                    .process(record)
                    .await?
                {
                    write_completed_record(
                        staging,
                        identity,
                        lease,
                        &mut sink,
                        record,
                        &mut output_hasher,
                        &mut output_bytes,
                    )
                    .await?;
                }
            }
        }
        decoder.finish()?;
        while let Some(record) = decoder.next_record()? {
            if let Some(record) = pipeline
                .as_mut()
                .expect("pipeline is present until finish")
                .process(record)
                .await?
            {
                write_completed_record(
                    staging,
                    identity,
                    lease,
                    &mut sink,
                    record,
                    &mut output_hasher,
                    &mut output_bytes,
                )
                .await?;
            }
        }
        let finishing = pipeline.take().expect("pipeline is present until finish");
        let (records, pipeline_fuel) = finishing.finish().await?;
        for record in records {
            write_completed_record(
                staging,
                identity,
                lease,
                &mut sink,
                record,
                &mut output_hasher,
                &mut output_bytes,
            )
            .await?;
        }
        let pipeline_evidence = snapshot.pipeline_evidence(
            pipeline_fuel,
            pipeline_started.elapsed().as_millis() as u64,
            "none",
        );
        let checksum_sha256 = hex::encode(output_hasher.finalize());
        renew_and_fence_completion(staging, identity, lease).await?;
        sink.verify_output(output_bytes, &checksum_sha256).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let precommit_result = MultipartCompletionResult {
            etag: None,
            checksum_sha256: checksum_sha256.clone(),
            version_id: None,
            source_bytes: input_bytes,
            size_bytes: output_bytes,
            pipeline_evidence: pipeline_evidence.clone(),
        };
        let usage_event = multipart_completion_event(operation.grant, &precommit_result);
        persist_transaction_usage_evidence(
            state.operation_journal.as_ref(),
            sink.durable_operation_id(),
            &usage_event,
        )
        .await
        .map_err(TransactionError::from)
        .map_err(StreamingPutError::from)?;
        sink.record_usage_evidence(&usage_event).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let stored = sink.complete().await?;
        let result = MultipartCompletionResult {
            etag: stored.etag,
            checksum_sha256,
            version_id: stored.version_id,
            source_bytes: input_bytes,
            size_bytes: output_bytes,
            pipeline_evidence,
        };
        renew_and_fence_completion(staging, identity, lease).await?;
        staging
            .repository
            .complete_completion(identity, lease.fencing_token, result.clone(), now_ms())
            .await?;
        Ok(result)
    }
    .await;
    if let Err(error) = &processing {
        cancellation.cancel();
        if let Some(pipeline) = pipeline.take() {
            let _ = pipeline.cancel_and_wait().await;
        }
        // Never allow a stale worker to issue an abort. The durable Phase 5
        // journal reconciles ambiguous destination outcomes after a crash.
        if !sink.commit_state().preserves_reservation()
            && renew_and_fence_completion(staging, identity, lease)
                .await
                .is_ok()
        {
            let _ = sink.abort().await;
        }
        let _ = error;
    }
    processing.map_err(|error| {
        if sink.commit_state().preserves_reservation() {
            MultipartCompletionError::PreserveReservation(Box::new(error))
        } else {
            error
        }
    })
}

fn multipart_completion_error_response(
    key: &str,
    error: MultipartCompletionError,
) -> axum::response::Response {
    match error.into_cause() {
        MultipartCompletionError::Staging(StagingError::Fenced) => {
            s3_error::service_unavailable(key, "multipart completion lease was lost")
        }
        MultipartCompletionError::Staging(StagingError::InvalidPart) => {
            s3_error::invalid_part(key, "staged part validation failed")
        }
        MultipartCompletionError::Staging(error) => {
            s3_error::internal_error(key, &error.to_string())
        }
        MultipartCompletionError::Streaming(error) => streaming_put_error_response(key, error),
        MultipartCompletionError::Invalid(error) => s3_error::invalid_request(key, &error),
        MultipartCompletionError::PreserveReservation(_) => unreachable!("cause is unwrapped"),
    }
}

async fn multipart_completion_failure_response(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    grant: &AuthorizationGrant,
    key: &str,
    error: MultipartCompletionError,
) -> axum::response::Response {
    let preserve_reservation = error.preserves_reservation();
    let response = multipart_completion_error_response(key, error);
    if preserve_reservation {
        response
    } else {
        release_failure(control, context, grant, key, response).await
    }
}

enum ExistingDirectCompletion {
    New,
    Committed(Box<OperationRecord>),
    ProvenAborted,
    Pending,
    Conflict,
}

fn persisted_workspace_lease(
    operation: &OperationRecord,
) -> Result<(WorkspaceId, WorkspaceOperationLease), TransactionError> {
    let workspace = WorkspaceId::new(operation.tenant_id.clone().ok_or_else(|| {
        TransactionError::Publication("workspace operation has no tenant identity".to_string())
    })?)
    .map_err(|_| {
        TransactionError::Publication("workspace recovery identity is invalid".to_string())
    })?;
    let binding = operation
        .destination
        .workspace_binding
        .as_ref()
        .ok_or_else(|| {
            TransactionError::Publication(
                "workspace operation has no versioned destination binding".to_string(),
            )
        })?;
    let lease = WorkspaceOperationLease {
        operation_id: operation.id,
        lease_id: binding.routing_lease_id,
        config_version: crate::workspace_storage::BackendConfigVersionId::new(
            binding.backend_config_version.clone(),
        )
        .map_err(|_| {
            TransactionError::Publication("workspace recovery identity is invalid".to_string())
        })?,
        attestation_id: crate::workspace_storage::CapabilityAttestationId::new(
            binding.capability_attestation_id.clone(),
        )
        .map_err(|_| {
            TransactionError::Publication("workspace recovery identity is invalid".to_string())
        })?,
        routing_epoch: binding.routing_epoch,
        fencing_token: binding.routing_fencing_token,
        expires_at_ms: 0,
    };
    Ok((workspace, lease))
}

async fn settle_terminal_workspace_lease(
    repository: &Arc<dyn WorkspaceStorageRepository>,
    operation: &OperationRecord,
) -> Result<(), TransactionError> {
    let outcome = match operation.state {
        OperationState::Committed => WorkspaceOperationOutcome::Committed,
        OperationState::ProvenAborted => WorkspaceOperationOutcome::ProvenAborted,
        _ => {
            return Err(TransactionError::Publication(
                "workspace route settlement requires a terminal journal row".to_string(),
            ));
        }
    };
    let (workspace, lease) = persisted_workspace_lease(operation)?;
    repository
        .release_streaming_operation_lease(&workspace, &lease, outcome)
        .await
        .map_err(|_| {
            TransactionError::Publication(
                "workspace recovery lease terminal update failed".to_string(),
            )
        })
}

async fn reconcile_existing_direct_completion(
    state: &AppState,
    backend: &ResolvedBackend,
    operation_id: Uuid,
    workspace_id: &str,
    bucket: &str,
    key: &str,
) -> Result<ExistingDirectCompletion, TransactionError> {
    let Some(journal) = state.operation_journal.clone() else {
        return Ok(ExistingDirectCompletion::New);
    };
    let Some(mut operation) = journal.get(operation_id).await? else {
        return Ok(ExistingDirectCompletion::New);
    };
    let backend_id = match backend {
        ResolvedBackend::S3 {
            kind: BackendKind::PerUserS3,
            ..
        } => "PerUserS3",
        ResolvedBackend::S3 {
            kind: BackendKind::GlobalS3,
            ..
        } => "GlobalS3",
        _ => return Ok(ExistingDirectCompletion::Conflict),
    };
    if operation.tenant_id.as_deref() != Some(workspace_id)
        || operation.destination.backend_id != backend_id
        || operation.destination.bucket != bucket
        || operation.destination.logical_key != key
        || operation.destination.physical_key != key
    {
        return Ok(ExistingDirectCompletion::Conflict);
    }

    if operation.state.is_terminal() {
        if backend_id == "PerUserS3" {
            settle_terminal_workspace_lease(&state.workspace_storage, &operation).await?;
        }
    } else {
        let owner = format!("workspace-retry-{}", Uuid::now_v7());
        let now = crate::transaction::unix_time_ms();
        let Some(claimed) = journal
            .claim_reconcilable_operation(
                operation_id,
                &owner,
                now,
                now.saturating_add(WORKSPACE_OPERATION_LEASE_TTL.as_millis() as i64),
            )
            .await?
        else {
            return Ok(ExistingDirectCompletion::Pending);
        };

        let (transaction_backend, recovered_fence) = match backend {
            ResolvedBackend::S3 {
                kind: BackendKind::PerUserS3,
                ..
            } => {
                let binding = claimed
                    .destination
                    .workspace_binding
                    .as_ref()
                    .ok_or_else(|| {
                        TransactionError::Publication(
                            "workspace operation has no versioned destination binding".to_string(),
                        )
                    })?;
                let workspace = WorkspaceId::new(workspace_id.to_string()).map_err(|_| {
                    TransactionError::Publication(
                        "workspace recovery identity is invalid".to_string(),
                    )
                })?;
                let (historical, lease) = backend_resolver(state)
                    .recover_workspace_operation(
                        &workspace,
                        operation_id,
                        binding,
                        &owner,
                        WORKSPACE_OPERATION_LEASE_TTL,
                    )
                    .await
                    .map_err(TransactionError::Publication)?;
                let ResolvedBackend::S3 {
                    client,
                    workspace_streaming: Some(streaming),
                    ..
                } = historical
                else {
                    return Ok(ExistingDirectCompletion::Conflict);
                };
                let fence = WorkspaceMutationFence::new(
                    state.workspace_storage.clone(),
                    workspace,
                    lease,
                    WORKSPACE_OPERATION_LEASE_TTL,
                );
                let transaction_backend = if streaming.provider
                    == crate::backend::WorkspaceS3Provider::B2
                    && streaming.identity.attestation.exact_version_recovery
                {
                    AwsS3TransactionBackend::new_b2(
                        client,
                        streaming.identity.attestation.capabilities,
                    )
                } else {
                    AwsS3TransactionBackend::new(
                        client,
                        streaming.identity.attestation.capabilities,
                    )
                }
                .with_mutation_fence(fence.clone() as Arc<dyn ProviderMutationFence>);
                (transaction_backend, Some(fence))
            }
            ResolvedBackend::S3 {
                kind: BackendKind::GlobalS3,
                client,
                ..
            } => {
                let Some(capabilities) = state.s3_streaming_capabilities else {
                    return Ok(ExistingDirectCompletion::Conflict);
                };
                (
                    AwsS3TransactionBackend::new(client.clone(), capabilities),
                    None,
                )
            }
            _ => return Ok(ExistingDirectCompletion::Conflict),
        };
        let reconciler =
            OperationReconciler::new(journal.clone(), Arc::new(transaction_backend), owner)?;
        reconciler.reconcile_claimed(claimed).await?;
        operation = journal.get(operation_id).await?.ok_or_else(|| {
            TransactionError::Publication(
                "direct completion journal row disappeared during reconciliation".to_string(),
            )
        })?;
        if operation.state.is_terminal()
            && let Some(fence) = recovered_fence
        {
            let outcome = if operation.state == OperationState::Committed {
                WorkspaceOperationOutcome::Committed
            } else {
                WorkspaceOperationOutcome::ProvenAborted
            };
            let leased = WorkspaceLeasedSinkRelease { fence };
            leased.release(outcome).await?;
        }
    }
    Ok(match operation.state {
        OperationState::Committed => ExistingDirectCompletion::Committed(Box::new(operation)),
        OperationState::ProvenAborted => ExistingDirectCompletion::ProvenAborted,
        OperationState::Intent
        | OperationState::Open
        | OperationState::Completing
        | OperationState::CommitUnknown
        | OperationState::Aborting => ExistingDirectCompletion::Pending,
    })
}

struct WorkspaceLeasedSinkRelease {
    fence: Arc<WorkspaceMutationFence>,
}

impl WorkspaceLeasedSinkRelease {
    async fn release(&self, outcome: WorkspaceOperationOutcome) -> Result<(), TransactionError> {
        self.fence.stop();
        let lease = self.fence.terminal_lease().await;
        self.fence
            .repository
            .release_streaming_operation_lease(&self.fence.workspace_id, &lease, outcome)
            .await
            .map_err(|_| {
                TransactionError::Publication(
                    "workspace recovery lease terminal update failed".to_string(),
                )
            })
    }
}

/// Startup/periodic hook for private adapters to reconcile one durable BYO
/// operation after process loss. The operation's historical config version is
/// loaded before any provider request; current credentials are never used as a
/// fallback.
pub async fn reconcile_workspace_streaming_operation(
    state: &AppState,
    operation_id: Uuid,
) -> Result<bool, String> {
    let journal = state
        .operation_journal
        .as_ref()
        .ok_or_else(|| "durable operation journal is unavailable".to_string())?;
    let operation = journal
        .get(operation_id)
        .await
        .map_err(|_| "durable operation lookup failed".to_string())?
        .ok_or_else(|| "durable operation was not found".to_string())?;
    if operation.state.is_terminal() {
        settle_terminal_workspace_lease(&state.workspace_storage, &operation)
            .await
            .map_err(|_| "workspace terminal route settlement failed".to_string())?;
        return Ok(true);
    }
    let workspace_id = operation
        .tenant_id
        .as_deref()
        .ok_or_else(|| "workspace operation has no tenant identity".to_string())?;
    let workspace = WorkspaceId::new(workspace_id.to_string())
        .map_err(|_| "workspace operation identity is invalid".to_string())?;
    let owner = format!("workspace-periodic-{}", Uuid::now_v7());
    let now = crate::transaction::unix_time_ms();
    let Some(claimed) = journal
        .claim_reconcilable_operation(
            operation_id,
            &owner,
            now,
            now.saturating_add(WORKSPACE_OPERATION_LEASE_TTL.as_millis() as i64),
        )
        .await
        .map_err(|_| "workspace operation journal claim failed".to_string())?
    else {
        return Ok(false);
    };
    let binding = claimed
        .destination
        .workspace_binding
        .as_ref()
        .ok_or_else(|| "workspace operation has no versioned destination binding".to_string())?;
    let (historical, lease) = backend_resolver(state)
        .recover_workspace_operation(
            &workspace,
            operation_id,
            binding,
            &owner,
            WORKSPACE_OPERATION_LEASE_TTL,
        )
        .await?;
    let ResolvedBackend::S3 {
        client,
        workspace_streaming: Some(streaming),
        ..
    } = historical
    else {
        return Err("historical workspace storage kind changed".to_string());
    };
    let fence = WorkspaceMutationFence::new(
        state.workspace_storage.clone(),
        workspace,
        lease,
        WORKSPACE_OPERATION_LEASE_TTL,
    );
    let transaction_backend = if streaming.provider == crate::backend::WorkspaceS3Provider::B2
        && streaming.identity.attestation.exact_version_recovery
    {
        AwsS3TransactionBackend::new_b2(client, streaming.identity.attestation.capabilities)
    } else {
        AwsS3TransactionBackend::new(client, streaming.identity.attestation.capabilities)
    }
    .with_mutation_fence(fence.clone() as Arc<dyn ProviderMutationFence>);
    let reconciler =
        OperationReconciler::new(journal.clone(), Arc::new(transaction_backend), owner)
            .map_err(|_| "workspace operation provider capabilities changed".to_string())?;
    reconciler
        .reconcile_claimed(claimed)
        .await
        .map_err(|_| "workspace operation reconciliation failed".to_string())?;
    let operation = journal
        .get(operation_id)
        .await
        .map_err(|_| "workspace operation reload failed".to_string())?
        .ok_or_else(|| "workspace operation disappeared during reconciliation".to_string())?;
    if operation.state.is_terminal() {
        let outcome = if operation.state == OperationState::Committed {
            WorkspaceOperationOutcome::Committed
        } else {
            WorkspaceOperationOutcome::ProvenAborted
        };
        WorkspaceLeasedSinkRelease { fence }
            .release(outcome)
            .await
            .map_err(|_| "workspace terminal route settlement failed".to_string())?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn recovered_multipart_result(
    journal: Option<&Arc<dyn OperationJournal>>,
    operation: OperationRecord,
    lease: &CompletionLease,
    receipt_id: Uuid,
) -> Result<MultipartCompletionResult, MultipartCompletionError> {
    let journal = journal.ok_or_else(|| {
        MultipartCompletionError::Invalid(
            "committed direct operation has no durable journal".to_string(),
        )
    })?;
    let durable = load_usage_evidence(journal, operation.id, receipt_id)
        .await
        .map_err(TransactionError::from)
        .map_err(StreamingPutError::from)?;
    let stored = operation.committed.ok_or_else(|| {
        MultipartCompletionError::Invalid(
            "committed direct operation is missing destination metadata".to_string(),
        )
    })?;
    let size_bytes = operation.expected.size.ok_or_else(|| {
        MultipartCompletionError::Invalid(
            "committed direct operation is missing expected output size".to_string(),
        )
    })?;
    let checksum_sha256 = operation.expected.digest.ok_or_else(|| {
        MultipartCompletionError::Invalid(
            "committed direct operation is missing expected output checksum".to_string(),
        )
    })?;
    let source_bytes = lease
        .selected_parts
        .iter()
        .try_fold(0_u64, |total, part| total.checked_add(part.size_bytes))
        .ok_or_else(|| {
            MultipartCompletionError::Invalid("multipart source size overflow".to_string())
        })?;
    if durable.source_bytes != source_bytes
        || durable.output_bytes != size_bytes
        || durable.processed_bytes != source_bytes.max(size_bytes)
        || durable.bucket != operation.destination.bucket
        || durable.route != UsageRoute::CompleteMultipartUpload.as_str()
        || durable.kind != RequestKind::Write.as_str()
    {
        return Err(MultipartCompletionError::Invalid(
            "committed direct operation usage evidence does not match recovery state".to_string(),
        ));
    }
    Ok(MultipartCompletionResult {
        etag: stored.etag,
        checksum_sha256,
        version_id: stored.version_id,
        source_bytes,
        size_bytes,
        pipeline_evidence: durable.pipeline_evidence,
    })
}

#[allow(clippy::too_many_arguments)]
async fn complete_staged_avro_multipart(
    state: &AppState,
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    upload: &MultipartUpload,
    lease: &CompletionLease,
    operation: AuthorizedOperation<'_>,
    backend: ResolvedBackend,
    content_type: &str,
) -> Result<MultipartCompletionResult, MultipartCompletionError> {
    use sha2::Digest as _;

    renew_and_fence_completion(staging, identity, lease).await?;
    let mut sink = begin_streaming_sink(
        state,
        backend,
        operation,
        &identity.bucket,
        &identity.key,
        content_type,
    )
    .await?;
    // Route admission can block; a stale completion worker must stop before it
    // polls any selected artifact.
    renew_and_fence_completion(staging, identity, lease).await?;

    let max_source_bytes = state.source_body_limits.max_bytes.min(64 * 1024 * 1024) as usize;
    let mut input = Vec::new();
    let mut input_bytes = 0_u64;
    for part in &lease.selected_parts {
        renew_and_fence_completion(staging, identity, lease).await?;
        let body = staging.artifacts.get(&part.artifact_key).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let mut reader = EncryptedPartReader::open(
            body.into_async_read(),
            identity,
            part,
            &upload.snapshot,
            staging.wrapping.clone(),
        )
        .await?;
        let mut part_bytes = 0_u64;
        let mut part_sha256 = sha2::Sha256::new();
        let mut part_md5 = Md5::new();
        loop {
            renew_and_fence_completion(staging, identity, lease).await?;
            let Some(chunk) = reader.next_chunk().await? else {
                break;
            };
            part_bytes = part_bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
                MultipartCompletionError::Invalid("multipart part is too large".to_string())
            })?;
            input_bytes = input_bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
                MultipartCompletionError::Invalid("multipart input is too large".to_string())
            })?;
            if part_bytes > part.size_bytes || input_bytes as usize > max_source_bytes {
                return Err(MultipartCompletionError::Invalid(
                    "multipart input exceeds its limit".to_string(),
                ));
            }
            part_sha256.update(&chunk);
            part_md5.update(&chunk);
            input.extend_from_slice(&chunk);
        }
        if part_bytes != part.size_bytes
            || hex::encode(part_sha256.finalize()) != part.checksum_sha256
            || format!("\"{}\"", hex::encode(part_md5.finalize())) != part.etag
        {
            return Err(MultipartCompletionError::Invalid(
                "staged multipart artifact does not match its committed part".to_string(),
            ));
        }
    }
    let limits = crate::avro::AvroLimits {
        max_source_bytes,
        ..crate::avro::AvroLimits::default()
    };
    let headers = HeaderMap::new();
    let mut pump = avro_pump(operation.auth, &headers, limits)?;
    let mut decoding = tokio::task::spawn_blocking(move || {
        crate::avro::process_ocf(input.as_slice(), limits, &mut pump)
    });
    let output = loop {
        tokio::select! {
            result = &mut decoding => {
                break result
                    .map_err(|_| MultipartCompletionError::Invalid(
                        "Avro decoding worker failed".to_string(),
                    ))??;
            }
            () = tokio::time::sleep((COMPLETION_LEASE / 3).max(Duration::from_millis(1))) => {
                if let Err(error) = renew_and_fence_completion(staging, identity, lease).await {
                    decoding.abort();
                    return Err(error.into());
                }
            }
        }
    };
    let output_bytes = u64::try_from(output.len())
        .map_err(|_| MultipartCompletionError::Invalid("Avro output is too large".to_string()))?;
    let output_digest = hex::encode(sha2::Sha256::digest(&output));
    let result = async {
        renew_and_fence_completion(staging, identity, lease).await?;
        sink.write(bytes::Bytes::from(output)).await?;
        sink.verify_output(output_bytes, &output_digest).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let precommit_result = MultipartCompletionResult {
            etag: None,
            checksum_sha256: output_digest.clone(),
            version_id: None,
            source_bytes: input_bytes,
            size_bytes: output_bytes,
            pipeline_evidence: None,
        };
        let usage_event = multipart_completion_event(operation.grant, &precommit_result);
        persist_transaction_usage_evidence(
            state.operation_journal.as_ref(),
            sink.durable_operation_id(),
            &usage_event,
        )
        .await
        .map_err(TransactionError::from)
        .map_err(StreamingPutError::from)?;
        sink.record_usage_evidence(&usage_event).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let stored = sink.complete().await?;
        let result = MultipartCompletionResult {
            etag: stored.etag,
            checksum_sha256: output_digest,
            version_id: stored.version_id,
            source_bytes: input_bytes,
            size_bytes: output_bytes,
            pipeline_evidence: None,
        };
        renew_and_fence_completion(staging, identity, lease).await?;
        staging
            .repository
            .complete_completion(identity, lease.fencing_token, result.clone(), now_ms())
            .await?;
        Ok(result)
    }
    .await;

    if result.is_err()
        && renew_and_fence_completion(staging, identity, lease)
            .await
            .is_ok()
    {
        let _ = sink.abort().await;
    }
    result
}

async fn reconcile_staged_artifacts(staging: &MultipartStaging) -> Result<(), StagingError> {
    for candidate in staging.repository.cleanup_candidates(now_ms(), 256).await? {
        if staging
            .artifacts
            .delete(&candidate.artifact_key)
            .await
            .is_ok()
        {
            staging
                .repository
                .confirm_artifact_deleted(&candidate.artifact_key)
                .await?;
            staging
                .repository
                .audit(CleanupAudit {
                    id: Uuid::now_v7(),
                    upload_id: candidate.upload_id,
                    kind: "reconcile_attempt".to_string(),
                    detail: serde_json::json!({"artifact_key": candidate.artifact_key}),
                    created_at_ms: now_ms(),
                })
                .await?;
        }
    }
    let known = staging.repository.known_artifact_keys().await?;
    let cutoff = now_ms() - crate::multipart_staging::RECONCILIATION_GRACE.as_millis() as i64;
    for StagedArtifact {
        key,
        modified_at_ms,
    } in staging.artifacts.list(ARTIFACT_PREFIX).await?
    {
        // An object is never written before its PENDING record commits. The
        // grace period avoids deleting an in-flight S3 PUT during a scan.
        if !known.contains_key(&key) && modified_at_ms <= cutoff {
            let _ = staging.artifacts.delete(&key).await;
        }
    }
    Ok(())
}

async fn s3_upload_part(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    params: S3Query,
    request: Request,
) -> axum::response::Response {
    let (parts, mut body) = request.into_parts();
    let (Some(part_number), Some(upload_id)) = (params.part_number, params.upload_id) else {
        return s3_error::invalid_request(&key, "partNumber and uploadId are required");
    };
    let mut authentication = match authenticate_headers(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &state.keys,
        &state,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&parts.headers, &key) {
        return response;
    }
    if state
        .control
        .streaming_write_mode(&authentication.auth.context)
        .await
        .unwrap_or(state.streaming_write_mode)
        < StreamingWriteMode::All
    {
        return s3_error::multipart_not_supported(&key);
    }
    let Some(staging) = staged_multipart(&state).cloned() else {
        return s3_error::multipart_not_supported(&key);
    };
    let multipart_backend = match resolve_backend(
        &state,
        &authentication.auth,
        &parts.headers,
        StorageOperation::Multipart,
    )
    .await
    {
        Ok(backend) => backend,
        Err(_) => return backend_resolution_error_response(&key),
    };
    if let Err(error) = validate_streaming_backend(&state, &multipart_backend) {
        return streaming_put_error_response(&key, error);
    }
    let identity = multipart_identity(&authentication.auth, &bucket, &key, &upload_id);
    let upload = match staging.repository.get_authorized(&identity).await {
        Ok(upload) => upload,
        Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
        Err(error) => return s3_error::internal_error(&key, &error.to_string()),
    };
    if let ResolvedBackend::Managed(storage) = &multipart_backend {
        let Some(epoch) = upload.namespace_epoch else {
            return s3_error::service_unavailable(&key, "managed multipart upload has no epoch");
        };
        if let Err(error) = storage
            .assert_managed_multipart(
                &upload_id,
                authentication.auth.workspace_id().as_str(),
                epoch,
                false,
            )
            .await
        {
            return s3_error::service_unavailable(&key, &error.to_string());
        }
    }
    if upload.lifecycle != MultipartLifecycle::Open || upload.expires_at_ms <= now_ms() {
        return s3_error::no_such_upload(&key);
    }
    let reserved_bytes = match staged_part_reservation(&parts.headers) {
        Ok(bytes) => bytes,
        Err(_) => {
            return s3_error::invalid_request(
                &key,
                "multipart parts require a positive decoded Content-Length",
            );
        }
    };
    // This is the durable quota/CAS point. It must occur before consuming a
    // body frame, opening a temp file, or creating an object-store artifact.
    let pending = match staging
        .repository
        .begin_part(&identity, part_number, reserved_bytes, now_ms())
        .await
    {
        Ok(pending) => pending,
        Err(StagingError::QuotaExceeded) => return s3_error::slow_down(&key),
        Err(StagingError::NotFound | StagingError::NotOpen) => {
            return s3_error::no_such_upload(&key);
        }
        Err(StagingError::InvalidPart) => {
            return s3_error::invalid_request(&key, "invalid multipart part");
        }
        Err(error) => return s3_error::internal_error(&key, &error.to_string()),
    };
    let mut writer = match EncryptedPartWriter::begin(
        &staging.directory,
        &identity,
        part_number,
        pending.attempt,
        &upload.snapshot,
        pending.reserved_bytes,
        staging.wrapping.clone(),
    )
    .await
    {
        Ok(writer) => writer,
        Err(error) => {
            let _ = staging
                .repository
                .discard_pending(&identity, &pending)
                .await;
            return s3_error::internal_error(&key, &error.to_string());
        }
    };
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => {
                let _ = staging
                    .repository
                    .discard_pending(&identity, &pending)
                    .await;
                return s3_error::invalid_request(&key, "request body transport failed");
            }
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.len() > state.source_body_limits.max_frame_bytes {
            let _ = staging
                .repository
                .discard_pending(&identity, &pending)
                .await;
            return s3_error::invalid_request(
                &key,
                "multipart body frame exceeds configured limit",
            );
        }
        let decoded = match &mut authentication.body_verifier {
            Some(verifier) => match verifier.push(&data) {
                Ok(decoded) => decoded,
                Err(error) => {
                    let _ = staging
                        .repository
                        .discard_pending(&identity, &pending)
                        .await;
                    return s3_error::bad_digest(&key, &error.to_string());
                }
            },
            None => vec![data],
        };
        for chunk in decoded {
            if let Err(error) = writer.write(chunk).await {
                let _ = staging
                    .repository
                    .discard_pending(&identity, &pending)
                    .await;
                return s3_error::internal_error(&key, &error.to_string());
            }
        }
    }
    if let Some(verifier) = authentication.body_verifier.take()
        && let Err(error) = verifier.finish()
    {
        let _ = staging
            .repository
            .discard_pending(&identity, &pending)
            .await;
        return s3_error::bad_digest(&key, &error.to_string());
    }
    let finished = match writer.finish().await {
        Ok(value) => value,
        Err(error) => {
            let _ = staging
                .repository
                .discard_pending(&identity, &pending)
                .await;
            return s3_error::internal_error(&key, &error.to_string());
        }
    };
    if let Some(expected) = parts
        .headers
        .get("content-md5")
        .and_then(|value| value.to_str().ok())
    {
        let actual = hex::decode(finished.etag.trim_matches('"')).unwrap_or_default();
        if B64.decode(expected).ok().as_deref() != Some(actual.as_slice()) {
            finished.remove().await;
            let _ = staging
                .repository
                .discard_pending(&identity, &pending)
                .await;
            return s3_error::bad_digest(&key, "Content-MD5 does not match the uploaded part");
        }
    }
    if let Err(error) = staging
        .artifacts
        .put_file(&pending.artifact_key, &finished.path)
        .await
    {
        finished.remove().await;
        return s3_error::internal_error(&key, &error.to_string());
    }
    finished.remove().await;
    let part = MultipartPart {
        upload_id: upload_id.clone(),
        part_number,
        attempt: pending.attempt,
        artifact_key: pending.artifact_key.clone(),
        etag: finished.etag,
        checksum_sha256: finished.checksum_sha256,
        size_bytes: finished.size_bytes,
        created_at_ms: now_ms(),
    };
    match staging
        .repository
        .commit_part(&identity, &pending, part)
        .await
    {
        Ok(previous) => {
            if !previous.is_empty() {
                cleanup_staged_parts(&staging, &upload_id, previous, "part_replaced").await;
            }
            let mut response = axum::response::Response::builder().status(StatusCode::OK);
            response = response.header(
                header::ETAG,
                staging
                    .repository
                    .list_parts(&identity, part_number.saturating_sub(1), 1)
                    .await
                    .ok()
                    .and_then(|parts| parts.0.first().map(|part| part.etag.clone()))
                    .unwrap_or_default(),
            );
            response.body(axum::body::Body::empty()).unwrap()
        }
        Err(error) => {
            // The DB outcome can be unknown after a connection failure. Leave
            // the PENDING outbox record and ciphertext for reconciliation.
            s3_error::internal_error(&key, &error.to_string())
        }
    }
}

async fn s3_put(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    request: Request,
) -> impl IntoResponse {
    if params.part_number.is_some() || params.upload_id.is_some() {
        return s3_upload_part(state, bucket, key, params, request).await;
    }
    let (parts, request_body) = request.into_parts();
    let header_auth = match authenticate_headers(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &state.keys,
        &state,
    )
    .await
    {
        Ok(authentication) => authentication,
        Err(error) => return authentication_error_response(&key, error),
    };
    let auth = &header_auth.auth;
    let auth_context = auth.context.clone();
    if let Some(response) = client_metering_id_rejection(&parts.headers, &key) {
        return response;
    }
    let operation = request_operation_identity();
    let resolution_started = Instant::now();
    let resolution = match state
        .gateway
        .resolve(
            auth.workspace_id().as_str(),
            &bucket,
            crate::pipeline::PipelineDirection::Write,
        )
        .await
    {
        Ok(resolution) => resolution,
        Err(error) => {
            record_failed_pipeline_attempt(
                state.control.as_ref(),
                &auth.context,
                operation.operation_id,
                &bucket,
                crate::pipeline::PipelineDirection::Write,
                None,
                error.code(),
                resolution_started.elapsed().as_millis() as u64,
            )
            .await;
            return pipeline_error_response(&key, &error);
        }
    };
    let authorization = operation.pipeline_authorization(
        &bucket,
        UsageRoute::PutObject,
        RequestKind::Write,
        object_max_processed_bytes(&state),
        &resolution,
    );
    let grant = match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
        .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let snapshot = match state.gateway.snapshot_for(&resolution).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            record_failed_pipeline_attempt(
                state.control.as_ref(),
                &auth.context,
                operation.operation_id,
                &bucket,
                crate::pipeline::PipelineDirection::Write,
                Some(&resolution),
                error.code(),
                resolution_started.elapsed().as_millis() as u64,
            )
            .await;
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                pipeline_error_response(&key, &error),
            )
            .await;
        }
    };
    let tenant_write_mode = state
        .control
        .streaming_write_mode(&auth.context)
        .await
        .unwrap_or(state.streaming_write_mode);
    let effective_write_mode = state.streaming_write_mode.min(tenant_write_mode);
    let backend = match resolve_backend(&state, auth, &parts.headers, StorageOperation::Put).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth_context,
                &grant,
                &key,
                backend_resolution_error_response(&key),
            )
            .await;
        }
    };
    if let Err(error) = validate_streaming_backend(&state, &backend) {
        let response = streaming_put_error_response(&key, error);
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            response,
        )
        .await;
    }
    if let ResolvedBackend::Managed(storage) = &backend {
        match storage.managed_mode() {
            ManagedStreamingMode::Observe => {
                let response = s3_error::service_unavailable(
                    &key,
                    "managed mutations are disabled in observe mode",
                );
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            ManagedStreamingMode::Enforce if effective_write_mode < StreamingWriteMode::Single => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::not_implemented(&key),
                )
                .await;
            }
            ManagedStreamingMode::Off | ManagedStreamingMode::Enforce => {}
        }
    }
    // Legacy buffered PUT was removed in Phase 12. A write-mode below `single`
    // rejects without polling the request body; there is no fallback to a
    // whole-object buffer.
    if effective_write_mode < StreamingWriteMode::Single {
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            s3_error::not_implemented(&key),
        )
        .await;
    }
    match streaming_single_put(
        &state,
        header_auth,
        backend,
        AuthorizedUsage { grant: &grant },
        snapshot,
        &parts.headers,
        request_body,
        &key,
    )
    .await
    {
        Ok((auth, stored, source_bytes, output_bytes, pipeline_evidence)) => {
            let usage = OperationUsage {
                grant: &grant,
                source_bytes,
                output_bytes,
            };
            let event = match pipeline_evidence {
                Some(evidence) => usage.event().with_pipeline_evidence(evidence),
                None => usage.event(),
            };
            if let Err(response) =
                record_operation_with_event(state.control.clone(), &auth.context, event, &key).await
            {
                return response;
            }
            info!(
                "streaming PUT /{bucket}/{key} committed ({output_bytes} stored bytes, user={})",
                auth.user_id()
            );
            let mut response = axum::response::Response::builder().status(StatusCode::OK);
            if let Some(etag) = stored.etag {
                response = response.header(header::ETAG, etag);
            }
            if let Some(version_id) = stored.version_id {
                response = response.header("x-amz-version-id", version_id);
            }
            response.body(axum::body::Body::empty()).unwrap()
        }
        Err(error) => {
            let error_code = match &error {
                StreamingPutError::Pipeline(error) => error.code(),
                StreamingPutError::PreserveReservation(error) => match error.as_ref() {
                    StreamingPutError::Pipeline(error) => error.code(),
                    _ => s4_error::codes::INTERNAL,
                },
                _ => s4_error::codes::INTERNAL,
            };
            record_failed_pipeline_attempt(
                state.control.as_ref(),
                &auth_context,
                operation.operation_id,
                &bucket,
                crate::pipeline::PipelineDirection::Write,
                Some(&resolution),
                error_code,
                resolution_started.elapsed().as_millis() as u64,
            )
            .await;
            streaming_put_failure_response(
                state.control.as_ref(),
                &auth_context,
                &grant,
                &key,
                error,
            )
            .await
        }
    }
}

#[derive(Debug)]
enum TransformedReadError {
    InvalidRequest(String),
    Capacity(String),
    Source(String),
    Pipeline(s4_error::S4Error),
    Spool(TransactionError),
}

impl From<s4_error::S4Error> for TransformedReadError {
    fn from(error: s4_error::S4Error) -> Self {
        Self::Pipeline(error)
    }
}

impl From<TransactionError> for TransformedReadError {
    fn from(error: TransactionError) -> Self {
        Self::Spool(error)
    }
}

fn transformed_read_error_response(
    key: &str,
    error: TransformedReadError,
) -> axum::response::Response {
    match error {
        TransformedReadError::InvalidRequest(detail) => s3_error::invalid_request(key, &detail),
        TransformedReadError::Capacity(detail) => s3_error::service_unavailable(key, &detail),
        TransformedReadError::Source(detail) => s3_error::internal_error(key, &detail),
        TransformedReadError::Spool(TransactionError::CapacityExceeded) => {
            s3_error::service_unavailable(
                key,
                "encrypted transformed-read staging capacity is unavailable",
            )
        }
        TransformedReadError::Spool(error) => s3_error::internal_error(key, &error.to_string()),
        TransformedReadError::Pipeline(error) => pipeline_error_response(key, &error),
    }
}

/// A transformed representation has different validators and range semantics
/// from its source. Keep only descriptive representation metadata.
fn transformed_response_headers(
    metadata: &ObjectMetadata,
    content_length: Option<u64>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for name in [
        header::CONTENT_TYPE,
        header::CONTENT_DISPOSITION,
        header::CONTENT_LANGUAGE,
    ] {
        for value in metadata.headers.get_all(&name) {
            headers.append(name.clone(), value.clone());
        }
    }
    if let Some(content_length) = content_length
        && let Ok(value) = content_length.to_string().parse()
    {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    harden_object_response_headers(&mut headers);
    headers
}

fn avro_read_preflight(
    headers: &HeaderMap,
    params: &S3Query,
    metadata: &ObjectMetadata,
) -> Option<TransformedReadError> {
    if headers.contains_key(header::RANGE) {
        return Some(TransformedReadError::InvalidRequest(
            "Range is not supported for transformed reads".to_string(),
        ));
    }
    if params.part_number.is_some() {
        return Some(TransformedReadError::InvalidRequest(
            "part-number reads are not supported for transformed reads".to_string(),
        ));
    }
    if let Some(encoding) = metadata.headers.get(header::CONTENT_ENCODING)
        && !encoding
            .to_str()
            .map(|value| value.eq_ignore_ascii_case("identity"))
            .unwrap_or(false)
    {
        return Some(TransformedReadError::InvalidRequest(
            "Content-Encoding is unsupported for transformed reads".to_string(),
        ));
    }
    None
}

fn transformed_read_preflight(
    headers: &HeaderMap,
    params: &S3Query,
    metadata: &ObjectMetadata,
) -> Result<(Format, String), TransformedReadError> {
    if headers.contains_key(header::RANGE) {
        return Err(TransformedReadError::InvalidRequest(
            "Range is not supported for transformed reads".to_string(),
        ));
    }
    if params.part_number.is_some() {
        return Err(TransformedReadError::InvalidRequest(
            "part-number reads are not supported for transformed reads".to_string(),
        ));
    }
    if let Some(encoding) = metadata.headers.get(header::CONTENT_ENCODING) {
        let encoding = encoding.to_str().map_err(|_| {
            TransformedReadError::InvalidRequest("invalid source Content-Encoding".to_string())
        })?;
        if !encoding.eq_ignore_ascii_case("identity") {
            return Err(TransformedReadError::InvalidRequest(
                "Content-Encoding is unsupported for transformed reads".to_string(),
            ));
        }
    }
    let content_type = metadata
        .headers
        .get(header::CONTENT_TYPE)
        .ok_or_else(|| {
            TransformedReadError::InvalidRequest(
                "Content-Type is required for transformed reads".to_string(),
            )
        })?
        .to_str()
        .map_err(|_| {
            TransformedReadError::InvalidRequest("invalid source Content-Type".to_string())
        })?;
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let format = match media_type.as_str() {
        "text/plain" => Format::Text,
        "application/x-ndjson" | "application/jsonlines" => Format::Jsonl,
        "application/json" => Format::Json,
        "text/csv" => Format::Csv,
        "text/tab-separated-values" => Format::Tsv,
        _ => {
            return Err(TransformedReadError::InvalidRequest(format!(
                "unsupported transformed-read Content-Type {media_type:?}"
            )));
        }
    };
    Ok((format, media_type))
}

/// An unversioned source is safe to transform only if both metadata responses
/// carry the same strong validator. Weak ETags are cache validators, not an
/// assertion that the bytes consumed by GET match the bytes inspected by HEAD.
fn transformed_source_matches_preflight(
    preflight: &ObjectMetadata,
    source: &ObjectMetadata,
) -> bool {
    (is_immutable_version_id(preflight.version_id.as_deref())
        && preflight.version_id == source.version_id)
        || strong_etag(preflight)
            .zip(strong_etag(source))
            .is_some_and(|(left, right)| left == right)
}

fn conditional_read_status(headers: &HeaderMap, metadata: &ObjectMetadata) -> Option<StatusCode> {
    let etag = metadata.headers.get(header::ETAG)?.to_str().ok()?;
    let matches = |condition: &str| {
        condition
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == "*" || candidate == etag)
    };
    if let Some(condition) = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        (!matches(condition)).then_some(StatusCode::PRECONDITION_FAILED)
    } else if let Some(condition) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        matches(condition).then_some(StatusCode::NOT_MODIFIED)
    } else {
        None
    }
}

fn conditional_read_response(
    mut object: OpenedObject,
    status: StatusCode,
) -> axum::response::Response {
    let etag = object.metadata.headers[header::ETAG].clone();
    let version_id = object.metadata.version_id.clone();
    object.status = status;
    object.metadata.headers.clear();
    object.metadata.headers.insert(header::ETAG, etag);
    if let Some(version_id) = version_id
        && let Ok(value) = version_id.parse()
    {
        object.metadata.headers.insert("x-amz-version-id", value);
    }
    object.cancellation.cancel();
    object.body = axum::body::Body::empty();
    object.into_response()
}

fn is_immutable_version_id(version_id: Option<&str>) -> bool {
    matches!(version_id, Some(version_id) if !version_id.is_empty() && version_id != "null")
}

fn strong_etag(metadata: &ObjectMetadata) -> Option<&str> {
    let etag = metadata.headers.get(header::ETAG)?.to_str().ok()?;
    let etag = etag.trim();
    (etag.len() > 2 && etag.starts_with('"') && etag.ends_with('"') && !etag.starts_with("W/"))
        .then_some(etag)
}

fn schedule_spool_cleanup(config: CompatibilitySpoolConfig) {
    // A zero duration is useful for direct cleanup tests but must not create a
    // busy loop if a future caller reuses it for the service configuration.
    let interval = config.stale_after.max(Duration::from_secs(60));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match CompatibilitySpoolTransaction::cleanup_stale(&config).await {
                Ok(removed) if removed > 0 => {
                    info!(removed, "removed stale spool files");
                }
                Ok(_) => {}
                Err(error) => warn!("failed to remove stale spool files: {error}"),
            }
        }
    });
}

fn transformed_session(
    auth: &Auth,
    headers: &HeaderMap,
    format: Format,
    content_type: String,
) -> s4_wasm_runtime::Session {
    s4_wasm_runtime::Session {
        format: format.as_str().to_string(),
        content_type,
        policy_version: 0,
        operation: s4_wasm_runtime::Operation::Read,
        config_json: None,
        public_key_pem: auth.public_key_pem.clone(),
        stable_key: auth.stable_key.clone(),
        stable_fields: customer_headers::validated(headers, customer_headers::STABLE_FIELDS)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
    }
}

async fn collect_opened_object(
    object: &mut OpenedObject,
    max_bytes: usize,
) -> Result<Vec<u8>, TransformedReadError> {
    let mut output = Vec::new();
    while let Some(frame) = object.body.frame().await {
        let frame = frame.map_err(|error| TransformedReadError::Source(error.to_string()))?;
        let data = frame.into_data().map_err(|frame| {
            if frame.into_trailers().is_ok() {
                TransformedReadError::Source(
                    "source trailers are not valid for transformed reads".to_string(),
                )
            } else {
                TransformedReadError::Source("source returned a non-data frame".to_string())
            }
        })?;
        if output.len().saturating_add(data.len()) > max_bytes {
            object.cancellation.cancel();
            return Err(TransformedReadError::Source(
                "Avro source exceeds the configured byte limit".to_string(),
            ));
        }
        output.extend_from_slice(&data);
    }
    Ok(output)
}

async fn serve_spooled_bytes(
    state: &AppState,
    bytes: Vec<u8>,
    source_cancellation: s4_wasm_runtime::CancellationToken,
) -> Result<(axum::body::Body, u64), TransformedReadError> {
    let mut spool = EncryptedReadSpool::begin(
        state.spool_config.directory.clone(),
        state.spool_config.max_object_bytes,
        Arc::clone(&state.spool_quota),
    )
    .await?;
    if let Err(error) = spool.write(bytes::Bytes::from(bytes)).await {
        spool.abort().await;
        return Err(TransformedReadError::from(error));
    }
    spool
        .into_body(source_cancellation)
        .await
        .map_err(TransformedReadError::from)
}

async fn avro_transformed_read_response(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    response_metadata: ObjectMetadata,
    mut object: OpenedObject,
    key: &str,
) -> (axum::response::Response, Option<u64>) {
    if !state.transformed_read_spool_enabled {
        object.cancellation.cancel();
        return (
            transformed_read_error_response(
                key,
                TransformedReadError::Capacity(
                    "unsafe transformed reads require MASKURA_TRANSFORMED_READ_SPOOL=encrypted"
                        .to_string(),
                ),
            ),
            None,
        );
    }
    let max_source_bytes = state.source_body_limits.max_bytes.min(64 * 1024 * 1024) as usize;
    let source = match collect_opened_object(&mut object, max_source_bytes).await {
        Ok(source) => source,
        Err(error) => return (transformed_read_error_response(key, error), None),
    };
    let limits = crate::avro::AvroLimits {
        max_source_bytes,
        ..crate::avro::AvroLimits::default()
    };
    let mut pump = match avro_pump(auth, headers, limits) {
        Ok(pump) => pump,
        Err(error) => {
            return (
                transformed_read_error_response(key, TransformedReadError::Pipeline(error)),
                None,
            );
        }
    };
    let output = match crate::avro::process_ocf(source.as_slice(), limits, &mut pump) {
        Ok(output) => output,
        Err(error) => {
            return (
                transformed_read_error_response(key, TransformedReadError::Pipeline(error)),
                None,
            );
        }
    };
    let (body, content_length) =
        match serve_spooled_bytes(state, output, object.cancellation.clone()).await {
            Ok(result) => result,
            Err(error) => return (transformed_read_error_response(key, error), None),
        };
    let mut response = axum::response::Response::builder().status(StatusCode::OK);
    response
        .headers_mut()
        .unwrap()
        .extend(transformed_response_headers(
            &response_metadata,
            Some(content_length),
        ));
    (response.body(body).unwrap(), Some(object.counters.bytes()))
}

async fn process_transformed_source<F, Fut>(
    mut object: OpenedObject,
    mut pipeline: StreamingPipelineSession,
    format: Format,
    max_source_frame_bytes: usize,
    mut emit: F,
) -> Result<u64, TransformedReadError>
where
    F: FnMut(bytes::Bytes) -> Fut,
    Fut: std::future::Future<Output = Result<(), TransformedReadError>>,
{
    let cancellation = object.cancellation.clone();
    let decoder_limits = crate::record::DecoderLimits {
        max_source_frame_bytes,
        ..crate::record::DecoderLimits::default()
    };
    // CountedBody enforces the configured source-frame bound before this point;
    // the decoder sees the same frame without copying it as a whole object.
    let mut decoder = crate::record::RecordDecoder::new(format, decoder_limits)?;
    let result = async {
        while let Some(frame) = object.body.frame().await {
            let frame = frame.map_err(|error| TransformedReadError::Source(error.to_string()))?;
            let data = frame.into_data().map_err(|frame| {
                if frame.into_trailers().is_ok() {
                    TransformedReadError::Source(
                        "source trailers are not valid for transformed reads".to_string(),
                    )
                } else {
                    TransformedReadError::Source("source returned a non-data frame".to_string())
                }
            })?;
            decoder.push(&data)?;
            while let Some(record) = decoder.next_record()? {
                if let Some(record) = pipeline.process(record).await? {
                    if !record.payload.is_empty() {
                        emit(record.payload).await?;
                    }
                    if !record.separator.is_empty() {
                        emit(record.separator).await?;
                    }
                }
            }
        }
        decoder.finish()?;
        while let Some(record) = decoder.next_record()? {
            if let Some(record) = pipeline.process(record).await? {
                if !record.payload.is_empty() {
                    emit(record.payload).await?;
                }
                if !record.separator.is_empty() {
                    emit(record.separator).await?;
                }
            }
        }
        let (records, fuel_consumed) = pipeline.finish().await?;
        for record in records {
            if !record.payload.is_empty() {
                emit(record.payload).await?;
            }
            if !record.separator.is_empty() {
                emit(record.separator).await?;
            }
        }
        Ok(fuel_consumed)
    }
    .await;
    if result.is_err() {
        cancellation.cancel();
        // Dropping an un-finished session interrupts a current guest call. The
        // worker owns it here, so no retry or raw fallback is possible.
    }
    result
}

enum DirectReadEvent {
    Data(bytes::Bytes),
    Failed(TransformedReadError),
    Done {
        source_bytes: u64,
        output_bytes: u64,
        evidence: Option<crate::control::PipelineEvidence>,
    },
}

const DIRECT_READ_SETTLEMENT_ATTEMPTS: usize = 3;

type DirectSettlementFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), MeteringError>> + Send + 'static>,
>;

fn direct_settlement_future(
    control: Arc<dyn ControlPlane>,
    context: AuthenticatedRequestContext,
    event: UsageEvent,
) -> DirectSettlementFuture {
    Box::pin(async move {
        let mut last_error = MeteringError::Unavailable;
        for attempt in 1..=DIRECT_READ_SETTLEMENT_ATTEMPTS {
            match control.record(&context, &event).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last_error = error;
                    warn!(
                        operation_id = %event.operation_id(),
                        receipt_id = %event.receipt_id(),
                        attempt,
                        "direct transformed-read settlement retry failed"
                    );
                }
            }
        }
        Err(last_error)
    })
}

struct DirectReadBody {
    first: Option<bytes::Bytes>,
    receiver: tokio::sync::mpsc::Receiver<DirectReadEvent>,
    source_cancellation: s4_wasm_runtime::CancellationToken,
    pipeline_cancellation: s4_wasm_runtime::CancellationToken,
    control: Arc<dyn ControlPlane>,
    context: AuthenticatedRequestContext,
    grant: AuthorizationGrant,
    failure_operation: OperationIdentity,
    failure_bucket: String,
    failure_resolution: crate::pipeline::PipelineResolution,
    settlement: Option<DirectSettlementFuture>,
    disclosed: bool,
    reservation_owned: bool,
    done: bool,
}

impl http_body::Body for DirectReadBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(settlement) = &mut self.settlement {
            return match settlement.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(())) => {
                    self.settlement = None;
                    self.reservation_owned = false;
                    self.done = true;
                    std::task::Poll::Ready(None)
                }
                std::task::Poll::Ready(Err(_)) => {
                    self.settlement = None;
                    self.done = true;
                    std::task::Poll::Ready(Some(Err(std::io::Error::other(
                        "direct transformed-read usage settlement failed",
                    ))))
                }
                std::task::Poll::Pending => std::task::Poll::Pending,
            };
        }
        if let Some(bytes) = self.first.take() {
            self.disclosed = true;
            return std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))));
        }
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(DirectReadEvent::Data(bytes))) => {
                self.disclosed = true;
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
            }
            std::task::Poll::Ready(Some(DirectReadEvent::Failed(error))) => {
                self.done = true;
                let control = self.control.clone();
                let context = self.context.clone();
                let operation = self.failure_operation;
                let bucket = self.failure_bucket.clone();
                let resolution = self.failure_resolution.clone();
                let error_code = match &error {
                    TransformedReadError::Pipeline(error) => error.code(),
                    _ => s4_error::codes::INTERNAL,
                };
                tokio::spawn(async move {
                    record_failed_pipeline_attempt(
                        control.as_ref(),
                        &context,
                        operation.operation_id,
                        &bucket,
                        crate::pipeline::PipelineDirection::Read,
                        Some(&resolution),
                        error_code,
                        0,
                    )
                    .await;
                });
                if !self.disclosed {
                    let control = self.control.clone();
                    let context = self.context.clone();
                    let operation_id = self.grant.operation_id();
                    tokio::spawn(async move {
                        let _ = control.release(&context, operation_id).await;
                    });
                    self.reservation_owned = false;
                }
                std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "direct transformed-read pipeline failed",
                ))))
            }
            std::task::Poll::Ready(Some(DirectReadEvent::Done {
                source_bytes,
                output_bytes,
                evidence,
            })) => {
                if source_bytes.max(output_bytes) > self.grant.max_processed_bytes() {
                    self.done = true;
                    return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                        "direct transformed-read exceeded its authorized size",
                    ))));
                }
                let event = UsageEvent::from_grant(&self.grant, source_bytes, output_bytes);
                let event = match evidence {
                    Some(evidence) => event.with_pipeline_evidence(evidence),
                    None => event,
                };
                self.settlement = Some(direct_settlement_future(
                    self.control.clone(),
                    self.context.clone(),
                    event,
                ));
                self.poll_frame(cx)
            }
            std::task::Poll::Ready(None) => {
                self.done = true;
                self.source_cancellation.cancel();
                self.pipeline_cancellation.cancel();
                std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "transformed read worker terminated unexpectedly",
                ))))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl Drop for DirectReadBody {
    fn drop(&mut self) {
        if !self.done {
            self.source_cancellation.cancel();
            self.pipeline_cancellation.cancel();
            if self.reservation_owned && !self.disclosed {
                let control = self.control.clone();
                let context = self.context.clone();
                let operation_id = self.grant.operation_id();
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        let _ = control.release(&context, operation_id).await;
                    });
                }
                self.reservation_owned = false;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn transformed_read_response(
    state: &AppState,
    auth: &Auth,
    operation: OperationIdentity,
    grant: &AuthorizationGrant,
    resolution: &crate::pipeline::PipelineResolution,
    headers: &HeaderMap,
    snapshot: PipelineSnapshot,
    preflight: (Format, String),
    response_metadata: ObjectMetadata,
    object: OpenedObject,
    key: &str,
    pipeline_evidence: &mut Option<crate::control::PipelineEvidence>,
) -> (axum::response::Response, Option<u64>, bool) {
    let (format, content_type) = preflight;
    *pipeline_evidence = None;
    let pipeline_started = std::time::Instant::now();
    let source_cancellation = object.cancellation.clone();
    let source_counters = object.counters.clone();
    let pipeline_cancellation = s4_wasm_runtime::CancellationToken::new();
    let pipeline = match snapshot
        .clone()
        .start_streaming_session(
            transformed_session(auth, headers, format, content_type),
            pipeline_cancellation.clone(),
        )
        .await
    {
        Ok(pipeline) => pipeline,
        Err(error) => {
            return (
                transformed_read_error_response(key, error.into()),
                None,
                false,
            );
        }
    };
    let direct = snapshot
        .capabilities()
        .iter()
        .all(|capabilities| capabilities.prefix_safe_for_read);
    if direct {
        let max_source_frame_bytes = state.source_body_limits.max_frame_bytes;
        let output_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let worker_output_bytes = output_bytes.clone();
        let worker_source_counters = source_counters.clone();
        let worker_snapshot = snapshot.clone();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            let result = process_transformed_source(
                object,
                pipeline,
                format,
                max_source_frame_bytes,
                |bytes| {
                    let sender = sender.clone();
                    let output_bytes = worker_output_bytes.clone();
                    async move {
                        output_bytes
                            .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        sender
                            .send(DirectReadEvent::Data(bytes))
                            .await
                            .map_err(|_| {
                                TransformedReadError::Source(
                                    "client cancelled transformed read".to_string(),
                                )
                            })
                    }
                },
            )
            .await;
            let event = match result {
                Ok(fuel_consumed) => DirectReadEvent::Done {
                    source_bytes: worker_source_counters.bytes(),
                    output_bytes: worker_output_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    evidence: worker_snapshot.pipeline_evidence(
                        fuel_consumed,
                        pipeline_started.elapsed().as_millis() as u64,
                        "none",
                    ),
                },
                Err(error) => DirectReadEvent::Failed(error),
            };
            let _ = sender.send(event).await;
        });
        let first_event = receiver.recv().await;
        if let Some(DirectReadEvent::Failed(error)) = first_event {
            return (transformed_read_error_response(key, error), None, false);
        }
        if first_event.is_none() {
            source_cancellation.cancel();
            pipeline_cancellation.cancel();
            return (
                transformed_read_error_response(
                    key,
                    TransformedReadError::Pipeline(s4_error::S4Error::new(
                        s4_error::codes::INTERNAL,
                        "transformed read worker terminated unexpectedly",
                    )),
                ),
                None,
                false,
            );
        }
        let (first, content_length, settlement) = match first_event {
            Some(DirectReadEvent::Data(bytes)) => (Some(bytes), None, None),
            Some(DirectReadEvent::Done {
                source_bytes,
                output_bytes,
                evidence,
            }) => {
                let event = UsageEvent::from_grant(grant, source_bytes, output_bytes);
                let event = match evidence {
                    Some(evidence) => event.with_pipeline_evidence(evidence),
                    None => event,
                };
                (
                    None,
                    Some(output_bytes),
                    Some(direct_settlement_future(
                        state.control.clone(),
                        auth.context.clone(),
                        event,
                    )),
                )
            }
            Some(DirectReadEvent::Failed(_)) | None => unreachable!("handled above"),
        };
        let mut response = axum::response::Response::builder().status(StatusCode::OK);
        response
            .headers_mut()
            .unwrap()
            .extend(transformed_response_headers(
                &response_metadata,
                content_length,
            ));
        return (
            response
                .body(axum::body::Body::new(DirectReadBody {
                    first,
                    receiver,
                    source_cancellation,
                    pipeline_cancellation,
                    control: state.control.clone(),
                    context: auth.context.clone(),
                    grant: grant.clone(),
                    failure_operation: operation,
                    failure_bucket: grant.bucket().to_string(),
                    failure_resolution: resolution.clone(),
                    settlement,
                    disclosed: false,
                    reservation_owned: true,
                    done: false,
                }))
                .unwrap(),
            None,
            true,
        );
    }
    if !state.transformed_read_spool_enabled {
        source_cancellation.cancel();
        return (
            transformed_read_error_response(
                key,
                TransformedReadError::Capacity(
                    "unsafe transformed reads require MASKURA_TRANSFORMED_READ_SPOOL=encrypted"
                        .to_string(),
                ),
            ),
            None,
            false,
        );
    }
    let spool = match EncryptedReadSpool::begin(
        state.spool_config.directory.clone(),
        state.spool_config.max_object_bytes,
        Arc::clone(&state.spool_quota),
    )
    .await
    {
        Ok(spool) => spool,
        Err(error) => {
            return (
                transformed_read_error_response(key, error.into()),
                None,
                false,
            );
        }
    };
    let (spool_sender, mut spool_receiver) = tokio::sync::mpsc::channel(2);
    let spool_writer = tokio::spawn(async move {
        let mut spool = spool;
        while let Some(bytes) = spool_receiver.recv().await {
            if let Err(error) = spool.write(bytes).await {
                spool.abort().await;
                return Err(TransformedReadError::from(error));
            }
        }
        Ok(spool)
    });
    let output_sender = spool_sender.clone();
    let result = process_transformed_source(
        object,
        pipeline,
        format,
        state.source_body_limits.max_frame_bytes,
        move |bytes| {
            let sender = output_sender.clone();
            async move {
                sender.send(bytes).await.map_err(|_| {
                    TransformedReadError::Capacity(
                        "encrypted transformed-read staging failed".to_string(),
                    )
                })
            }
        },
    )
    .await;
    drop(spool_sender);
    let pipeline_fuel = match result {
        Ok(fuel) => fuel,
        Err(error) => {
            let _ = spool_writer.await;
            return (transformed_read_error_response(key, error), None, false);
        }
    };
    let spool = match spool_writer.await {
        Ok(Ok(spool)) => spool,
        Ok(Err(error)) => return (transformed_read_error_response(key, error), None, false),
        Err(error) => {
            return (
                transformed_read_error_response(
                    key,
                    TransformedReadError::Capacity(format!(
                        "encrypted transformed-read staging task failed: {error}"
                    )),
                ),
                None,
                false,
            );
        }
    };
    *pipeline_evidence = snapshot.pipeline_evidence(
        pipeline_fuel,
        pipeline_started.elapsed().as_millis() as u64,
        "encrypted",
    );
    let (body, content_length) = match spool.into_body(source_cancellation).await {
        Ok(result) => result,
        Err(error) => {
            return (
                transformed_read_error_response(key, error.into()),
                None,
                false,
            );
        }
    };
    let mut response = axum::response::Response::builder().status(StatusCode::OK);
    response
        .headers_mut()
        .unwrap()
        .extend(transformed_response_headers(
            &response_metadata,
            Some(content_length),
        ));
    (
        response.body(body).unwrap(),
        Some(source_counters.bytes()),
        false,
    )
}

async fn s3_get(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&headers, &key) {
        return response;
    }
    let transformed_read = wants_transformed_read(&headers);
    if params.upload_id.is_some() {
        let backend =
            match resolve_backend(&state, &auth, &headers, StorageOperation::Multipart).await {
                Ok(backend) => backend,
                Err(_) => return backend_resolution_error_response(&key),
            };
        let Some(staging) = staged_multipart(&state).cloned() else {
            return s3_error::multipart_not_supported(&key);
        };
        let identity = multipart_identity(
            &auth,
            &bucket,
            &key,
            params.upload_id.as_deref().unwrap_or_default(),
        );
        if let ResolvedBackend::Managed(storage) = &backend {
            let upload = match staging.repository.get_authorized(&identity).await {
                Ok(upload) => upload,
                Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
                Err(error) => return s3_error::internal_error(&key, &error.to_string()),
            };
            let Some(epoch) = upload.namespace_epoch else {
                return s3_error::service_unavailable(
                    &key,
                    "managed multipart upload has no namespace epoch",
                );
            };
            if let Err(error) = storage
                .assert_managed_multipart(
                    &identity.upload_id,
                    auth.workspace_id().as_str(),
                    epoch,
                    false,
                )
                .await
            {
                return s3_error::service_unavailable(&key, &error.to_string());
            }
        }
        let limit = params.max_parts.unwrap_or(1000).clamp(1, 1000) as usize;
        return match staging
            .repository
            .list_parts(&identity, params.part_number_marker.unwrap_or(0), limit)
            .await
        {
            Ok((parts, truncated)) => s3_xml_ok(list_parts_xml(
                &bucket,
                &key,
                &identity.upload_id,
                &parts,
                truncated,
            )),
            Err(StagingError::NotFound) => s3_error::no_such_upload(&key),
            Err(error) => s3_error::internal_error(&key, &error.to_string()),
        };
    }
    let operation = request_operation_identity();
    let resolution_started = Instant::now();
    let resolution = if transformed_read {
        match state
            .gateway
            .resolve(
                auth.workspace_id().as_str(),
                &bucket,
                crate::pipeline::PipelineDirection::Read,
            )
            .await
        {
            Ok(resolution) => Some(resolution),
            Err(error) => {
                record_failed_pipeline_attempt(
                    state.control.as_ref(),
                    &auth.context,
                    operation.operation_id,
                    &bucket,
                    crate::pipeline::PipelineDirection::Read,
                    None,
                    error.code(),
                    resolution_started.elapsed().as_millis() as u64,
                )
                .await;
                return pipeline_error_response(&key, &error);
            }
        }
    } else {
        None
    };
    let authorization = match &resolution {
        Some(resolution) => operation.pipeline_authorization(
            &bucket,
            UsageRoute::GetObject,
            RequestKind::Read,
            object_max_processed_bytes(&state),
            resolution,
        ),
        None => operation.authorization(
            &bucket,
            UsageRoute::GetObject,
            RequestKind::Read,
            object_max_processed_bytes(&state),
        ),
    };
    let grant = match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
        .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let pipeline_snapshot = if let Some(resolution) = &resolution {
        match state.gateway.snapshot_for(resolution).await {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                record_failed_pipeline_attempt(
                    state.control.as_ref(),
                    &auth.context,
                    operation.operation_id,
                    &bucket,
                    crate::pipeline::PipelineDirection::Read,
                    Some(resolution),
                    error.code(),
                    resolution_started.elapsed().as_millis() as u64,
                )
                .await;
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    pipeline_error_response(&key, &error),
                )
                .await;
            }
        }
    } else {
        None
    };
    if transformed_read && state.streaming_read_mode != StreamingReadMode::Transformed {
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            s3_error::transformed_read_not_supported(&key),
        )
        .await;
    }
    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Get).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                backend_resolution_error_response(&key),
            )
            .await;
        }
    };
    // A transformed representation must be admitted from authoritative object
    // metadata before a source GET can start delivering bytes. Passthrough keeps
    // its existing one-request behavior below.
    if transformed_read {
        if matches!(&backend, ResolvedBackend::PresignedHttp(_)) {
            let response = transformed_read_error_response(
                &key,
                TransformedReadError::InvalidRequest(
                    "transformed reads require stored object metadata".to_string(),
                ),
            );
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                response,
            )
            .await;
        }
        let metadata = match open_backend_object(
            &state,
            backend.clone(),
            &auth,
            &bucket,
            &key,
            &headers,
            true,
        )
        .await
        {
            Ok(object) => object.metadata,
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    open_error_response(&key, error),
                )
                .await;
            }
        };
        if is_avro_content_type(&metadata.headers) {
            if let Some(error) = avro_read_preflight(&headers, &params, &metadata) {
                return transformed_read_error_response(&key, error);
            }
            if !state.binary_avro_enabled {
                return transformed_read_error_response(
                    &key,
                    TransformedReadError::InvalidRequest(
                        "Avro processing is disabled; set MASKURA_ENABLE_AVRO=true".to_string(),
                    ),
                );
            }
            let object =
                match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, false)
                    .await
                {
                    Ok(object) => object,
                    Err(error) => return open_error_response(&key, error),
                };
            let source_bytes = content_length(&object.metadata.headers);
            let response_metadata = object.metadata.clone();
            let (response, completed_source_bytes) = avro_transformed_read_response(
                &state,
                &auth,
                &headers,
                response_metadata,
                object,
                &key,
            )
            .await;
            return metered_read_response(
                state.control.clone(),
                &auth,
                &grant,
                &key,
                source_bytes.or(completed_source_bytes),
                response,
                None,
            )
            .await;
        }
        let preflight = match transformed_read_preflight(&headers, &params, &metadata) {
            Ok(preflight) => preflight,
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    transformed_read_error_response(&key, error),
                )
                .await;
            }
        };
        let object =
            match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, false).await
            {
                Ok(object) => object,
                Err(error) => {
                    return release_failure(
                        state.control.as_ref(),
                        &auth.context,
                        &grant,
                        &key,
                        open_error_response(&key, error),
                    )
                    .await;
                }
            };
        let source_preflight = match transformed_read_preflight(&headers, &params, &object.metadata)
        {
            Ok(preflight) => preflight,
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    transformed_read_error_response(&key, error),
                )
                .await;
            }
        };
        if source_preflight.0 != preflight.0
            || source_preflight.1 != preflight.1
            || !transformed_source_matches_preflight(&metadata, &object.metadata)
        {
            object.cancellation.cancel();
            let response = transformed_read_error_response(
                &key,
                TransformedReadError::Source(
                    "source metadata changed after transformed-read preflight".to_string(),
                ),
            );
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                response,
            )
            .await;
        }
        if let Some(status) = conditional_read_status(&headers, &object.metadata) {
            let response = conditional_read_response(object, status);
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                response,
            )
            .await;
        }
        let source_bytes = content_length(&object.metadata.headers);
        let response_metadata = object.metadata.clone();
        let mut pipeline_evidence = None;
        let (response, completed_source_bytes, direct) = transformed_read_response(
            &state,
            &auth,
            operation,
            &grant,
            resolution
                .as_ref()
                .expect("transformed reads resolve an immutable pipeline"),
            &headers,
            pipeline_snapshot.expect("transformed reads resolve a pipeline snapshot"),
            preflight,
            response_metadata,
            object,
            &key,
            &mut pipeline_evidence,
        )
        .await;
        if direct {
            return response;
        }
        if !response.status().is_success() {
            record_failed_pipeline_attempt(
                state.control.as_ref(),
                &auth.context,
                operation.operation_id,
                &bucket,
                crate::pipeline::PipelineDirection::Read,
                resolution.as_ref(),
                s4_error::codes::INTERNAL,
                resolution_started.elapsed().as_millis() as u64,
            )
            .await;
        }
        return metered_read_response(
            state.control.clone(),
            &auth,
            &grant,
            &key,
            source_bytes.or(completed_source_bytes),
            response,
            pipeline_evidence,
        )
        .await;
    }
    let object =
        match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, false).await {
            Ok(object) => object,
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    open_error_response(&key, error),
                )
                .await;
            }
        };
    if let Some(status) = conditional_read_status(&headers, &object.metadata) {
        let response = conditional_read_response(object, status);
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            response,
        )
        .await;
    }

    if state.streaming_read_mode.streams_passthrough() {
        return metered_read_response(
            state.control.clone(),
            &auth,
            &grant,
            &key,
            None,
            object.into_response(),
            None,
        )
        .await;
    }

    // Legacy whole-object GET buffering was removed in Phase 12. With reads
    // administratively disabled, reject without collecting the object body;
    // dropping `object` cancels the source before any byte is buffered.
    release_failure(
        state.control.as_ref(),
        &auth.context,
        &grant,
        &key,
        s3_error::not_implemented(&key),
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use axum::body::Body;
    use bytes::Bytes;
    use http_body::{Frame, SizeHint};

    use super::*;

    fn test_grant(authorization: &UsageAuthorization) -> AuthorizationGrant {
        AuthorizationGrant::new(
            authorization,
            chrono::DateTime::parse_from_rfc3339("2026-08-31T12:34:56Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            7,
        )
    }

    #[derive(Default)]
    struct TerminalLeaseRepository {
        settled: tokio::sync::Mutex<Option<(Uuid, WorkspaceOperationOutcome)>>,
        settlements: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl WorkspaceStorageRepository for TerminalLeaseRepository {
        async fn resolve_workspace(
            &self,
            user_id: &str,
        ) -> Result<WorkspaceId, WorkspaceStorageError> {
            WorkspaceId::new(user_id)
        }

        async fn get_runtime_config(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Option<crate::workspace_storage::RuntimeBackendConfig>, WorkspaceStorageError>
        {
            Ok(None)
        }

        async fn release_streaming_operation_lease(
            &self,
            _workspace_id: &WorkspaceId,
            lease: &WorkspaceOperationLease,
            outcome: WorkspaceOperationOutcome,
        ) -> Result<(), WorkspaceStorageError> {
            let mut settled = self.settled.lock().await;
            if let Some(existing) = *settled {
                return if existing == (lease.operation_id, outcome) {
                    Ok(())
                } else {
                    Err(WorkspaceStorageError::Repository(
                        "terminal lease settlement conflict".to_string(),
                    ))
                };
            }
            *settled = Some((lease.operation_id, outcome));
            self.settlements.fetch_add(1, Ordering::SeqCst);
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
                "test repository is immutable".to_string(),
            ))
        }
    }

    fn terminal_workspace_operation(state: OperationState) -> OperationRecord {
        let operation_id = Uuid::now_v7();
        let mut operation = OperationRecord::direct_intent(
            DirectOperationScope {
                operation_id,
                tenant_id: "workspace-a".to_string(),
            },
            ObjectDestination {
                backend_id: "PerUserS3".to_string(),
                bucket: "bucket".to_string(),
                logical_key: "key".to_string(),
                physical_key: "key".to_string(),
                workspace_binding: Some(WorkspaceDestinationBinding {
                    backend_config_version: "config-v1".to_string(),
                    capability_attestation_id: "attestation-v1".to_string(),
                    routing_epoch: 7,
                    routing_lease_id: Uuid::now_v7(),
                    routing_fencing_token: 11,
                }),
            },
            ExpectedObject::default(),
        );
        operation.state = state;
        if state == OperationState::Committed {
            operation.committed = Some(StoredObjectMeta::default());
        }
        operation
    }

    #[tokio::test]
    async fn terminal_journal_crash_window_releases_workspace_lease_idempotently() {
        for state in [OperationState::Committed, OperationState::ProvenAborted] {
            let repository = Arc::new(TerminalLeaseRepository::default());
            let operation = terminal_workspace_operation(state);
            let repository_trait: Arc<dyn WorkspaceStorageRepository> = repository.clone();

            // Simulates process loss after the journal terminal transition but
            // before the request worker settles its routing lease.
            settle_terminal_workspace_lease(&repository_trait, &operation)
                .await
                .unwrap();
            settle_terminal_workspace_lease(&repository_trait, &operation)
                .await
                .unwrap();

            assert_eq!(repository.settlements.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn avro_content_types_are_distinguished_from_text_formats() {
        for content_type in [
            "application/avro",
            "application/x-avro; charset=binary",
            "application/vnd.apache.avro+binary",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
            assert!(is_avro_content_type(&headers));
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(!is_avro_content_type(&headers));
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct UsageCall {
        context: AuthenticatedRequestContext,
        event: UsageEvent,
    }

    #[derive(Default)]
    struct RecordingControlPlane {
        calls: std::sync::Mutex<Vec<UsageCall>>,
        releases: std::sync::Mutex<Vec<Uuid>>,
        failure: Option<MeteringError>,
    }

    #[async_trait::async_trait]
    impl ControlPlane for RecordingControlPlane {
        async fn authorize(
            &self,
            _context: &AuthenticatedRequestContext,
            authorization: &UsageAuthorization,
        ) -> Result<AuthorizationDecision, AuthorizationError> {
            Ok(AuthorizationDecision::Granted(test_grant(authorization)))
        }

        async fn release(
            &self,
            _context: &AuthenticatedRequestContext,
            operation_id: Uuid,
        ) -> Result<(), AuthorizationError> {
            self.releases.lock().unwrap().push(operation_id);
            Ok(())
        }

        async fn record(
            &self,
            context: &AuthenticatedRequestContext,
            event: &UsageEvent,
        ) -> Result<(), MeteringError> {
            self.calls.lock().unwrap().push(UsageCall {
                context: context.clone(),
                event: event.clone(),
            });
            self.failure.map_or(Ok(()), Err)
        }
    }

    struct PrivateAddressResolver;

    #[async_trait::async_trait]
    impl crate::backend::AddressResolver for PrivateAddressResolver {
        async fn resolve(
            &self,
            _host: &str,
            port: u16,
        ) -> std::io::Result<Vec<std::net::SocketAddr>> {
            Ok(vec![std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                port,
            )])
        }
    }

    #[derive(Default)]
    struct CountingWorkspaceStorageRepository {
        put_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl WorkspaceStorageRepository for CountingWorkspaceStorageRepository {
        async fn resolve_workspace(
            &self,
            user_id: &str,
        ) -> Result<WorkspaceId, WorkspaceStorageError> {
            WorkspaceId::new(user_id)
        }

        async fn get_runtime_config(
            &self,
            _workspace_id: &WorkspaceId,
        ) -> Result<Option<crate::workspace_storage::RuntimeBackendConfig>, WorkspaceStorageError>
        {
            Ok(None)
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
            self.put_calls.fetch_add(1, Ordering::SeqCst);
            Ok(BackendConfigResponse::unconfigured())
        }
    }

    #[test]
    fn startup_storage_boundary_requires_explicit_single_tenant_or_managed_storage() {
        assert!(explicit_single_tenant_mode(true, false));
        assert!(explicit_single_tenant_mode(false, true));
        assert!(!explicit_single_tenant_mode(false, false));

        assert!(validate_storage_boundary_startup(false, true, true).is_err());
        assert!(validate_storage_boundary_startup(false, false, false).is_err());
        assert!(validate_storage_boundary_startup(false, false, true).is_ok());
        assert!(validate_storage_boundary_startup(true, true, false).is_ok());
        assert!(validate_storage_boundary_startup(true, false, false).is_ok());
    }

    #[test]
    fn non_durable_journal_is_global_local_debug_only() {
        let journal: Arc<dyn OperationJournal> =
            Arc::new(crate::transaction::InMemoryOperationJournal::new());
        assert_eq!(
            direct_journal_allowed(BackendKind::GlobalS3, Some(&journal), true, true),
            cfg!(debug_assertions)
        );
        assert!(!direct_journal_allowed(
            BackendKind::GlobalS3,
            Some(&journal),
            false,
            true
        ));
        assert!(!direct_journal_allowed(
            BackendKind::GlobalS3,
            Some(&journal),
            true,
            false
        ));
        assert!(!direct_journal_allowed(
            BackendKind::PerUserS3,
            Some(&journal),
            true,
            true
        ));
    }

    async fn insert_test_usage_intent(journal: &Arc<dyn OperationJournal>, operation_id: Uuid) {
        journal
            .insert_intent(OperationRecord::direct_intent(
                DirectOperationScope {
                    operation_id,
                    tenant_id: "workspace-test".to_string(),
                },
                ObjectDestination {
                    backend_id: "test".to_string(),
                    bucket: "bucket".to_string(),
                    logical_key: "key".to_string(),
                    physical_key: "key".to_string(),
                    workspace_binding: None,
                },
                ExpectedObject::default(),
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn persist_usage_evidence_writes_durable_journal_record() {
        let journal: Arc<dyn OperationJournal> =
            Arc::new(crate::transaction::InMemoryOperationJournal::new());
        let authorization = UsageAuthorization::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "bucket",
            UsageRoute::PutObject,
            RequestKind::Write,
            64,
        );
        let pipeline_evidence = crate::control::PipelineEvidence {
            revision: "revision-7".to_string(),
            fingerprint: "fingerprint".to_string(),
            components: "component-a,component-b".to_string(),
            fuel_consumed: 123,
            duration_ms: 45,
            spool_mode: "encrypted".to_string(),
        };
        let event = UsageEvent::from_grant(&test_grant(&authorization), 64, 32)
            .with_pipeline_evidence(pipeline_evidence);
        insert_test_usage_intent(&journal, event.operation_id()).await;
        persist_usage_evidence(Some(&journal), &event)
            .await
            .unwrap();

        let evidence = journal.evidence(event.operation_id()).await.unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, "usage");
        assert_eq!(
            evidence[0].detail["receipt_id"].as_str().unwrap(),
            event.receipt_id().to_string()
        );
        assert_eq!(evidence[0].detail["source_bytes"].as_u64(), Some(64));
        assert_eq!(evidence[0].detail["output_bytes"].as_u64(), Some(32));
        assert_eq!(evidence[0].detail["processed_bytes"].as_u64(), Some(64));
        assert_eq!(
            evidence[0].detail["occurred_at"],
            serde_json::json!(event.occurred_at())
        );
        assert_eq!(evidence[0].detail["rate_version"].as_i64(), Some(7));
        assert_eq!(evidence[0].detail["route"].as_str(), Some("PutObject"));
        assert_eq!(evidence[0].detail["kind"].as_str(), Some("write"));
        assert_eq!(evidence[0].detail["bucket"].as_str(), Some("bucket"));
        assert_eq!(
            evidence[0].detail["pipeline_evidence"],
            serde_json::json!({
                "revision": "revision-7",
                "fingerprint": "fingerprint",
                "components": "component-a,component-b",
                "fuel_consumed": 123,
                "duration_ms": 45,
                "spool_mode": "encrypted",
            })
        );
    }

    #[tokio::test]
    async fn precommit_usage_evidence_failure_is_not_suppressed() {
        let concrete = Arc::new(crate::transaction::InMemoryOperationJournal::new());
        concrete.fail_next_evidence_appends(1);
        let journal: Arc<dyn OperationJournal> = concrete;
        let authorization = UsageAuthorization::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "bucket",
            UsageRoute::PutObject,
            RequestKind::Write,
            8,
        );
        let event = UsageEvent::from_grant(&test_grant(&authorization), 8, 8);
        insert_test_usage_intent(&journal, event.operation_id()).await;

        assert!(
            persist_usage_evidence(Some(&journal), &event)
                .await
                .is_err()
        );
        assert!(
            journal
                .evidence(event.operation_id())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn postgres_journal_does_not_receive_evidence_for_dev_memory_sink() {
        let concrete = Arc::new(crate::transaction::InMemoryOperationJournal::new());
        // This models Postgres' evidence FK: any accidental append is a hard
        // failure because a memory sink has no object_operations row.
        concrete.fail_next_evidence_appends(1);
        let journal: Arc<dyn OperationJournal> = concrete;
        let sink = MemorySinkTransaction::new(
            Arc::new(MemoryStore::new()),
            "bucket",
            "key",
            "text/plain",
            1024,
        )
        .unwrap();
        let authorization = UsageAuthorization::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "bucket",
            UsageRoute::PutObject,
            RequestKind::Write,
            8,
        );
        let event = UsageEvent::from_grant(&test_grant(&authorization), 8, 8);

        persist_transaction_usage_evidence(Some(&journal), sink.durable_operation_id(), &event)
            .await
            .unwrap();
        assert!(
            journal
                .evidence(event.operation_id())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn multipart_crash_recovery_restores_exact_precommit_pipeline_evidence() {
        let journal: Arc<dyn OperationJournal> =
            Arc::new(crate::transaction::InMemoryOperationJournal::new());
        let identity = multipart_completion_operation_identity("upload-a", "fingerprint-a");
        let authorization = identity.authorization(
            "bucket-a",
            UsageRoute::CompleteMultipartUpload,
            RequestKind::Write,
            128,
        );
        let grant = test_grant(&authorization);
        let pipeline_evidence = crate::control::PipelineEvidence {
            revision: "revision-a".to_string(),
            fingerprint: "fingerprint-a".to_string(),
            components: "component-a".to_string(),
            fuel_consumed: 77,
            duration_ms: 9,
            spool_mode: "none".to_string(),
        };
        let precommit_result = MultipartCompletionResult {
            etag: None,
            checksum_sha256: "output-sha".to_string(),
            version_id: None,
            source_bytes: 32,
            size_bytes: 24,
            pipeline_evidence: Some(pipeline_evidence.clone()),
        };
        insert_test_usage_intent(&journal, identity.operation_id).await;
        persist_usage_evidence(
            Some(&journal),
            &multipart_completion_event(&grant, &precommit_result),
        )
        .await
        .unwrap();

        let mut operation = OperationRecord::direct_intent(
            DirectOperationScope {
                operation_id: identity.operation_id,
                tenant_id: "workspace-a".to_string(),
            },
            ObjectDestination {
                backend_id: "S3".to_string(),
                bucket: "bucket-a".to_string(),
                logical_key: "key-a".to_string(),
                physical_key: "key-a".to_string(),
                workspace_binding: None,
            },
            ExpectedObject {
                digest: Some("output-sha".to_string()),
                size: Some(24),
                metadata: Default::default(),
            },
        );
        operation.state = OperationState::Committed;
        operation.committed = Some(StoredObjectMeta {
            etag: Some("\"etag-a\"".to_string()),
            version_id: Some("version-a".to_string()),
            ..StoredObjectMeta::default()
        });
        let lease = CompletionLease {
            fencing_token: 1,
            selected_parts: vec![MultipartPart {
                upload_id: "upload-a".to_string(),
                part_number: 1,
                attempt: 1,
                artifact_key: "artifact-a".to_string(),
                etag: "\"part-a\"".to_string(),
                checksum_sha256: "part-sha".to_string(),
                size_bytes: 32,
                created_at_ms: now_ms(),
            }],
            cleanup_parts: Vec::new(),
        };

        let recovered =
            recovered_multipart_result(Some(&journal), operation, &lease, identity.receipt_id)
                .await
                .unwrap();
        assert_eq!(recovered.pipeline_evidence, Some(pipeline_evidence));
        assert_eq!(recovered.source_bytes, 32);
        assert_eq!(recovered.size_bytes, 24);
        assert_eq!(recovered.checksum_sha256, "output-sha");
    }

    #[tokio::test]
    async fn dashboard_rejects_workspace_endpoint_before_persistence() {
        let repository = CountingWorkspaceStorageRepository::default();
        let policy = WorkspaceEndpointPolicy::new(
            false,
            ["objects.example".to_string()],
            Vec::<String>::new(),
            Arc::new(PrivateAddressResolver),
        )
        .unwrap();
        let result = validate_and_put_workspace_backend(
            &repository,
            &policy,
            &WorkspaceId::new("workspace").unwrap(),
            BackendConfigRequest {
                backend_type: BackendType::S3Compatible,
                endpoint: "https://objects.example".to_string(),
                access_key: "access".to_string(),
                secret_key: "secret".to_string(),
                region: "us-east-1".to_string(),
                role_arn: String::new(),
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(WorkspaceStorageError::InvalidConfig(_))
        ));
        assert_eq!(repository.put_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn metered_read_records_admitted_bytes_before_returning_the_body() {
        let control = Arc::new(RecordingControlPlane::default());
        let operation = OperationIdentity {
            receipt_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
        };
        let auth = Auth {
            context: AuthenticatedRequestContext {
                user_id: "user-a".to_string(),
                workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
            },
            credential_policy_id: "test".to_string(),
            public_key_pem: None,
            stable_key: None,
        };
        let authorization =
            operation.authorization("bucket-a", UsageRoute::GetObject, RequestKind::Read, 1024);
        let grant = test_grant(&authorization);
        let response = metered_read_response(
            control.clone(),
            &auth,
            &grant,
            "key-a",
            None,
            axum::response::Response::new(Body::from("range")),
            None,
        )
        .await;
        assert_eq!(
            *control.calls.lock().unwrap(),
            vec![UsageCall {
                context: auth.context.clone(),
                event: UsageEvent::from_grant(&grant, 5, 5),
            }]
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"range");
    }

    #[tokio::test]
    async fn metered_read_failure_replaces_the_stream_with_a_generic_s3_error() {
        let control = Arc::new(RecordingControlPlane {
            failure: Some(MeteringError::Unavailable),
            ..RecordingControlPlane::default()
        });
        let auth = Auth {
            context: AuthenticatedRequestContext {
                user_id: "user-a".to_string(),
                workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
            },
            credential_policy_id: "test".to_string(),
            public_key_pem: None,
            stable_key: None,
        };
        let operation = OperationIdentity {
            receipt_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
        };
        let authorization =
            operation.authorization("bucket-a", UsageRoute::GetObject, RequestKind::Read, 1024);
        let grant = test_grant(&authorization);
        let response = metered_read_response(
            control,
            &auth,
            &grant,
            "key-a",
            None,
            axum::response::Response::new(Body::from("range")),
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("<Code>ServiceUnavailable</Code>"));
        assert!(!body.contains("database"));
    }

    #[test]
    fn operation_identities_are_server_generated_and_completion_is_stable() {
        let first = request_operation_identity();
        let second = request_operation_identity();
        assert_eq!(first.receipt_id.get_version_num(), 7);
        assert_eq!(first.operation_id.get_version_num(), 5);
        assert_eq!(
            first.operation_id,
            operation_id_for_receipt(first.receipt_id)
        );
        assert_ne!(first.receipt_id, first.operation_id);
        assert_ne!(first.receipt_id, second.receipt_id);
        assert_ne!(first.operation_id, second.operation_id);
        let multipart = multipart_completion_operation_identity("upload-1", "fingerprint-a");
        assert_eq!(
            multipart,
            multipart_completion_operation_identity("upload-1", "fingerprint-a")
        );
        assert_ne!(
            multipart,
            multipart_completion_operation_identity("upload-2", "fingerprint-a")
        );
        assert_ne!(
            multipart,
            multipart_completion_operation_identity("upload-1", "fingerprint-b")
        );
        assert_eq!(multipart.receipt_id.get_version_num(), 5);
        assert_eq!(multipart.operation_id.get_version_num(), 5);
        assert_ne!(multipart.receipt_id, multipart.operation_id);
    }

    #[test]
    fn managed_and_multipart_namespaces_use_workspace_identity_not_user_identity() {
        let auth = Auth {
            context: AuthenticatedRequestContext {
                user_id: "user-a".to_string(),
                workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-b").unwrap(),
            },
            credential_policy_id: "credential".to_string(),
            public_key_pem: None,
            stable_key: None,
        };

        let logical = managed_logical_key(&auth, "bucket", "key");
        let multipart = multipart_identity(&auth, "bucket", "key", "upload");
        assert_eq!(logical.tenant_id, "workspace-b");
        assert_eq!(multipart.tenant_id, "workspace-b");
        assert_ne!(logical.tenant_id, auth.user_id());
    }

    #[test]
    fn direct_handler_scope_uses_authorization_operation_and_workspace() {
        let auth = Auth {
            context: AuthenticatedRequestContext {
                user_id: "user-a".to_string(),
                workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-b").unwrap(),
            },
            credential_policy_id: "credential".to_string(),
            public_key_pem: None,
            stable_key: None,
        };
        let operation = request_operation_identity();
        let authorization =
            operation.authorization("bucket", UsageRoute::PutObject, RequestKind::Write, 64);
        let grant = test_grant(&authorization);

        let scope = direct_operation_scope(AuthorizedOperation {
            auth: &auth,
            grant: &grant,
        });

        assert_eq!(scope.operation_id, authorization.operation_id());
        assert_eq!(scope.tenant_id, "workspace-b");
    }

    #[tokio::test]
    async fn multipart_success_and_exact_replay_meter_with_one_stable_identity() {
        let control = Arc::new(RecordingControlPlane::default());
        let journal: Arc<dyn OperationJournal> =
            Arc::new(crate::transaction::InMemoryOperationJournal::new());
        let context = AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
        };
        let operation = multipart_completion_operation_identity("upload-a", "fingerprint-a");
        let authorization = operation.authorization(
            "bucket-a",
            UsageRoute::CompleteMultipartUpload,
            RequestKind::Write,
            64,
        );
        insert_test_usage_intent(&journal, operation.operation_id).await;
        let grant = test_grant(&authorization);

        let result = MultipartCompletionResult {
            etag: Some("\"etag\"".to_string()),
            checksum_sha256: "sha".to_string(),
            version_id: None,
            source_bytes: 32,
            size_bytes: 24,
            pipeline_evidence: None,
        };
        for _ in 0..2 {
            record_durable_operation_with_event(
                Some(&journal),
                control.clone(),
                &context,
                multipart_completion_event(&grant, &result),
                "key-a",
            )
            .await
            .unwrap();
        }

        {
            let calls = control.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0], calls[1]);
            assert_eq!(calls[0].event.operation_id(), authorization.operation_id());
            assert_eq!(calls[0].event.route(), UsageRoute::CompleteMultipartUpload);
            assert_eq!(calls[0].event.processed_bytes(), 32);
        }
        let evidence = journal.evidence(operation.operation_id).await.unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(evidence.iter().all(|record| record.kind == "usage"));
        let receipt_id = operation.receipt_id.to_string();
        assert!(
            evidence
                .iter()
                .all(|record| record.detail["receipt_id"].as_str() == Some(receipt_id.as_str()))
        );
    }

    #[tokio::test]
    async fn commit_unknown_failure_does_not_release_reservation() {
        let control = RecordingControlPlane::default();
        let context = AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
        };
        let operation = request_operation_identity();
        let authorization =
            operation.authorization("bucket", UsageRoute::PutObject, RequestKind::Write, 64);
        let grant = test_grant(&authorization);

        let response = streaming_put_failure_response(
            &control,
            &context,
            &grant,
            "key",
            StreamingPutError::PreserveReservation(Box::new(StreamingPutError::Transaction(
                TransactionError::CompletionAmbiguous,
            ))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(control.releases.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn pipeline_failure_taxonomy_is_stable_bounded_and_opaque() {
        for (code, status, s3_code) in [
            (
                s4_error::codes::WASM_ADMISSION,
                StatusCode::SERVICE_UNAVAILABLE,
                "SlowDown",
            ),
            (
                s4_error::codes::CONFIG_INVALID,
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
            ),
            (
                s4_error::codes::POLICY_TAMPERED,
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
            ),
            (
                s4_error::codes::COMPONENT_LOAD,
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
            ),
            (
                s4_error::codes::INTERNAL,
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
            ),
        ] {
            let response = pipeline_error_response(
                "key",
                &s4_error::S4Error::new(code, "PRINTABLE_GRANTED_SECRET"),
            );
            assert_eq!(response.status(), status);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body = String::from_utf8_lossy(&body);
            assert!(body.contains(&format!("<Code>{s3_code}</Code>")));
            assert!(!body.contains("PRINTABLE_GRANTED_SECRET"));
        }
    }

    #[tokio::test]
    async fn definitive_provider_failure_has_stable_opaque_s3_response() {
        let response = streaming_put_error_response(
            "key",
            StreamingPutError::Transaction(TransactionError::Backend(
                crate::transaction::BackendError::definitive(
                    "PRINTABLE_PROVIDER_AUTHORIZATION_DETAIL",
                ),
            )),
        );
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("<Code>ServiceUnavailable</Code>"));
        assert!(!body.contains("PRINTABLE_PROVIDER_AUTHORIZATION_DETAIL"));
    }

    #[test]
    fn multipart_pipeline_restore_accepts_new_static_and_rejects_legacy_or_tampered_state() {
        let limits = PipelineLimits::default();
        let resolution = crate::pipeline::PipelineResolution {
            locator: crate::pipeline::PipelineLocator {
                revision: "static".to_string(),
                fingerprint: crate::pipeline::resolution_fingerprint(
                    crate::pipeline::PipelineDirection::Write,
                    &[],
                    true,
                    limits,
                ),
            },
            steps: Vec::new(),
            policy_generation: None,
            explicit_passthrough: true,
            limits,
        };
        let snapshot = serde_json::to_value(&resolution).unwrap();
        assert_eq!(restore_multipart_pipeline(&snapshot).unwrap(), resolution);

        let legacy = serde_json::json!([{
            "id": Uuid::new_v4(),
            "name": "legacy",
            "version": "0.1.0",
            "enabled": true,
            "description": ""
        }]);
        assert!(matches!(
            restore_multipart_pipeline(&legacy),
            Err(MultipartPipelineRestoreError::LegacyRawSnapshot)
        ));

        let mut tampered = snapshot;
        tampered["explicit_passthrough"] = serde_json::Value::Bool(false);
        assert!(matches!(
            restore_multipart_pipeline(&tampered),
            Err(MultipartPipelineRestoreError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn multipart_post_commit_failure_does_not_release_reservation() {
        let control = RecordingControlPlane::default();
        let context = AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
        };
        let operation = multipart_completion_operation_identity("upload-a", "fingerprint-a");
        let authorization = operation.authorization(
            "bucket",
            UsageRoute::CompleteMultipartUpload,
            RequestKind::Write,
            64,
        );
        let grant = test_grant(&authorization);

        let response = multipart_completion_failure_response(
            &control,
            &context,
            &grant,
            "key",
            MultipartCompletionError::PreserveReservation(Box::new(
                MultipartCompletionError::Staging(StagingError::Fenced),
            )),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(control.releases.lock().unwrap().is_empty());
    }

    struct PollTrackingBody {
        polls: Arc<AtomicUsize>,
        data: Option<Bytes>,
    }

    struct GeneratedLineBody {
        remaining: u64,
        frame_bytes: usize,
    }

    impl http_body::Body for PollTrackingBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
        }
    }

    impl http_body::Body for GeneratedLineBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.remaining == 0 {
                return Poll::Ready(None);
            }
            let len = self.remaining.min(self.frame_bytes as u64) as usize;
            self.remaining -= len as u64;
            let mut data = vec![b'x'; len];
            data[len - 1] = b'\n';
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(data)))))
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(self.remaining)
        }
    }

    fn metadata(
        version_id: Option<&str>,
        etag: Option<&str>,
        content_type: &str,
    ) -> ObjectMetadata {
        let mut metadata = ObjectMetadata {
            version_id: version_id.map(str::to_owned),
            ..ObjectMetadata::default()
        };
        metadata.insert(header::CONTENT_TYPE, content_type);
        if let Some(etag) = etag {
            metadata.insert(header::ETAG, etag);
        }
        metadata
    }

    #[test]
    fn transformed_source_binding_requires_a_version_or_matching_strong_etag() {
        let versioned = metadata(Some("v1"), None, "text/plain");
        assert!(transformed_source_matches_preflight(
            &versioned,
            &metadata(Some("v1"), None, "text/plain")
        ));
        assert!(!transformed_source_matches_preflight(
            &versioned,
            &metadata(Some("v2"), None, "text/plain")
        ));
        let suspended = metadata(Some("null"), None, "text/plain");
        assert!(
            !transformed_source_matches_preflight(
                &suspended,
                &metadata(Some("null"), None, "text/plain")
            ),
            "S3 versioning-suspended null versions are mutable and need a matching ETag"
        );

        let unversioned = metadata(None, Some("\"source-a\""), "text/plain");
        assert!(transformed_source_matches_preflight(
            &unversioned,
            &metadata(None, Some("\"source-a\""), "text/plain")
        ));
        assert!(!transformed_source_matches_preflight(
            &unversioned,
            &metadata(None, Some("\"source-b\""), "text/plain")
        ));
        assert!(!transformed_source_matches_preflight(
            &unversioned,
            &metadata(None, Some("W/\"source-a\""), "text/plain")
        ));
        assert!(!transformed_source_matches_preflight(
            &metadata(None, None, "text/plain"),
            &metadata(None, None, "text/plain")
        ));
    }

    #[test]
    fn transformed_preflight_rejects_source_header_changes_without_polling_source() {
        let polls = Arc::new(AtomicUsize::new(0));
        let object = OpenedObject::new(
            StatusCode::OK,
            metadata(None, Some("\"source-a\""), "application/octet-stream"),
            Body::new(PollTrackingBody {
                polls: Arc::clone(&polls),
                data: Some(Bytes::from_static(b"must not be read")),
            }),
            BodyLimits::default(),
        );
        let params = S3Query::default();
        assert!(transformed_read_preflight(&HeaderMap::new(), &params, &object.metadata).is_err());
        assert_eq!(polls.load(Ordering::SeqCst), 0);

        let before = metadata(None, Some("\"source-a\""), "text/plain");
        let after = metadata(None, Some("\"source-a\""), "application/json");
        assert!(transformed_read_preflight(&HeaderMap::new(), &params, &before).is_ok());
        assert!(transformed_read_preflight(&HeaderMap::new(), &params, &after).is_ok());
        assert_ne!(
            transformed_read_preflight(&HeaderMap::new(), &params, &before).unwrap(),
            transformed_read_preflight(&HeaderMap::new(), &params, &after).unwrap(),
            "the GET representation cannot change source format after HEAD"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transformed_source_returns_post_finish_fuel_for_spooled_evidence() {
        let component = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/components/noop.component.wasm"),
        )
        .expect("noop.component.wasm; run just build-filters");
        let registry = PluginRegistry::new();
        registry.import("noop", &component).unwrap();
        let pipeline = registry
            .snapshot()
            .start_streaming_session(
                s4_wasm_runtime::Session {
                    format: "text".to_string(),
                    content_type: "text/plain".to_string(),
                    policy_version: 0,
                    operation: s4_wasm_runtime::Operation::Read,
                    config_json: None,
                    public_key_pem: None,
                    stable_key: None,
                    stable_fields: None,
                },
                s4_wasm_runtime::CancellationToken::new(),
            )
            .await
            .unwrap();
        let object = OpenedObject::new(
            StatusCode::OK,
            metadata(None, Some("\"source-a\""), "text/plain"),
            Body::from("line\n"),
            BodyLimits::default(),
        );

        let fuel =
            process_transformed_source(object, pipeline, Format::Text, 1024, |_| async { Ok(()) })
                .await
                .unwrap();
        assert!(
            fuel > 0,
            "completed pipeline evidence must use measured fuel"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn successful_drop_all_direct_read_keeps_measured_finish_evidence() {
        let component = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/test-components/test-filter.component.wasm"),
        )
        .expect("test-filter.component.wasm; run just build-filters");
        let registry = Arc::new(PluginRegistry::new());
        registry
            .import_with_capabilities(
                "dropper",
                &component,
                PluginCapabilities {
                    prefix_safe_for_read: true,
                },
            )
            .unwrap();
        let resolver = crate::pipeline::StaticPipelineResolver::new(registry.clone());
        let resolution = crate::pipeline::PipelineResolver::resolve(
            &resolver,
            "workspace-a",
            "bucket-a",
            crate::pipeline::PipelineDirection::Read,
        )
        .await
        .unwrap();
        let snapshot = registry
            .snapshot_for(&resolution, registry.as_ref())
            .await
            .unwrap();
        let mut pipeline = snapshot
            .clone()
            .start_streaming_session(
                s4_wasm_runtime::Session {
                    format: "text".to_string(),
                    content_type: "text/plain".to_string(),
                    policy_version: 0,
                    operation: s4_wasm_runtime::Operation::Read,
                    config_json: None,
                    public_key_pem: None,
                    stable_key: None,
                    stable_fields: None,
                },
                s4_wasm_runtime::CancellationToken::new(),
            )
            .await
            .unwrap();

        assert!(
            pipeline
                .process(crate::record::Record::new("drop", "\n"))
                .await
                .unwrap()
                .is_none()
        );
        let (_, fuel_consumed) = pipeline.finish().await.unwrap();
        let evidence = snapshot
            .pipeline_evidence(fuel_consumed, 5, "none")
            .unwrap();
        assert_eq!(evidence.fuel_consumed, fuel_consumed);
        assert!(evidence.fuel_consumed > 0);
        assert_eq!(evidence.duration_ms, 5);
        assert_eq!(evidence.spool_mode, "none");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transformed_record_pipeline_has_fixed_rss_for_a_gibibyte_source() {
        const GIB: u64 = 1024 * 1024 * 1024;
        const FRAME_BYTES: usize = 64 * 1024;
        // Unit tests run in parallel with Wasmtime initialization elsewhere in
        // this process. This still catches whole-object buffering while leaving
        // room for unrelated allocator arena growth.
        const MAX_RSS_GROWTH: u64 = 256 * 1024 * 1024;

        let before = peak_rss_bytes();
        let registry = PluginRegistry::new();
        let pipeline = registry
            .snapshot()
            .start_streaming_session(
                s4_wasm_runtime::Session {
                    format: "text".to_string(),
                    content_type: "text/plain".to_string(),
                    policy_version: 0,
                    operation: s4_wasm_runtime::Operation::Write,
                    config_json: None,
                    public_key_pem: None,
                    stable_key: None,
                    stable_fields: None,
                },
                s4_wasm_runtime::CancellationToken::new(),
            )
            .await
            .unwrap();
        let object = OpenedObject::new(
            StatusCode::OK,
            metadata(None, Some("\"source-a\""), "text/plain"),
            Body::new(GeneratedLineBody {
                remaining: GIB,
                frame_bytes: FRAME_BYTES,
            }),
            BodyLimits {
                max_frame_bytes: FRAME_BYTES,
                max_bytes: GIB,
            },
        );
        let output_bytes = Arc::new(AtomicU64::new(0));
        process_transformed_source(object, pipeline, Format::Text, FRAME_BYTES, {
            let output_bytes = Arc::clone(&output_bytes);
            move |bytes| {
                let output_bytes = Arc::clone(&output_bytes);
                async move {
                    output_bytes.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .await
        .unwrap();
        let after = peak_rss_bytes();

        assert_eq!(output_bytes.load(Ordering::SeqCst), GIB);
        assert!(
            after.saturating_sub(before) <= MAX_RSS_GROWTH,
            "transformed 1 GiB stream grew peak RSS by {} MiB (limit {} MiB)",
            after.saturating_sub(before) / (1024 * 1024),
            MAX_RSS_GROWTH / (1024 * 1024),
        );
    }

    fn peak_rss_bytes() -> u64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes the provided rusage on success, and
        // the pointer remains valid for the duration of the call.
        let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        assert_eq!(result, 0, "getrusage failed");
        // SAFETY: a successful getrusage initialized the value.
        let usage = unsafe { usage.assume_init() };
        #[cfg(target_os = "macos")]
        {
            usage.ru_maxrss as u64
        }
        #[cfg(not(target_os = "macos"))]
        {
            usage.ru_maxrss as u64 * 1024
        }
    }
}

async fn s3_head(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&headers, &key) {
        return response;
    }
    let operation = request_operation_identity();
    let authorization =
        operation.authorization(&bucket, UsageRoute::HeadObject, RequestKind::Read, 0);
    let grant = match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
        .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    if wants_transformed_read(&headers) {
        let response = s3_error::invalid_request(
            &key,
            "HEAD is not supported for transformed reads until transformed metadata is available",
        );
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            response,
        )
        .await;
    }

    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Head).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                backend_resolution_error_response(&key),
            )
            .await;
        }
    };
    match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, true).await {
        Ok(object) => {
            if let Some(status) = conditional_read_status(&headers, &object.metadata) {
                let response = conditional_read_response(object, status);
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            let Some(object_bytes) = content_length(&object.metadata.headers) else {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::service_unavailable(
                        &key,
                        "The object size is unavailable for HEAD accounting.",
                    ),
                )
                .await;
            };
            if object_bytes > state.source_body_limits.max_bytes {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::entity_too_large(&key),
                )
                .await;
            }
            let response = object.into_response();
            if !response.status().is_success() {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    grant: &grant,
                    source_bytes: 0,
                    output_bytes: 0,
                },
                &key,
            )
            .await
            {
                return response;
            }
            response
        }
        Err(error) => {
            release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                open_error_response(&key, error),
            )
            .await
        }
    }
}

async fn s3_delete(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&headers, &key) {
        return response;
    }
    let operation = request_operation_identity();
    let authorization = operation.authorization(
        &bucket,
        if params.upload_id.is_some() {
            UsageRoute::AbortMultipartUpload
        } else {
            UsageRoute::DeleteObject
        },
        RequestKind::Write,
        0,
    );
    let grant = match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
        .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    info!("DELETE /{bucket}/{key} user={}", auth.user_id());

    if params.upload_id.is_some() {
        let backend =
            match resolve_backend(&state, &auth, &headers, StorageOperation::Multipart).await {
                Ok(backend) => backend,
                Err(_) => {
                    return release_failure(
                        state.control.as_ref(),
                        &auth.context,
                        &grant,
                        &key,
                        backend_resolution_error_response(&key),
                    )
                    .await;
                }
            };
        let Some(staging) = staged_multipart(&state).cloned() else {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                s3_error::multipart_not_supported(&key),
            )
            .await;
        };
        let upload_id = params.upload_id.as_deref().unwrap_or_default();
        let identity = multipart_identity(&auth, &bucket, &key, upload_id);
        let upload = match staging.repository.get_authorized(&identity).await {
            Ok(upload) => upload,
            Err(StagingError::NotFound) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::no_such_upload(&key),
                )
                .await;
            }
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::internal_error(&key, &error.to_string()),
                )
                .await;
            }
        };
        if let ResolvedBackend::Managed(storage) = &backend {
            let Some(epoch) = upload.namespace_epoch else {
                let response = s3_error::service_unavailable(
                    &key,
                    "managed multipart upload has no namespace epoch",
                );
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            };
            if let Err(error) = storage
                .assert_managed_multipart(upload_id, auth.workspace_id().as_str(), epoch, true)
                .await
            {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::service_unavailable(&key, &error.to_string()),
                )
                .await;
            }
        }
        return match staging.repository.abort(&identity, now_ms()).await {
            Ok(parts) => {
                cleanup_staged_parts(&staging, upload_id, parts, "abort").await;
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        grant: &grant,
                        source_bytes: 0,
                        output_bytes: 0,
                    },
                    &key,
                )
                .await
                {
                    return response;
                }
                StatusCode::NO_CONTENT.into_response()
            }
            Err(AbortMutationError::PreMutation(StagingError::NotFound)) => {
                release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::no_such_upload(&key),
                )
                .await
            }
            Err(AbortMutationError::PreMutation(StagingError::NotOpen)) => {
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        grant: &grant,
                        source_bytes: 0,
                        output_bytes: 0,
                    },
                    &key,
                )
                .await
                {
                    return response;
                }
                StatusCode::NO_CONTENT.into_response()
            }
            Err(AbortMutationError::PreMutation(error)) => {
                release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::internal_error(&key, &error.to_string()),
                )
                .await
            }
            Err(AbortMutationError::MutationUnknown(error)) => {
                s3_error::internal_error(&key, &error.to_string())
            }
        };
    }

    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Delete).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                backend_resolution_error_response(&key),
            )
            .await;
        }
    };
    match backend {
        ResolvedBackend::PresignedHttp(url) => {
            let client = match state
                .presigned_http_policy
                .client_for_destination(&url, Duration::from_secs(30))
                .await
            {
                Ok(client) => client,
                Err(error) => {
                    return release_failure(
                        state.control.as_ref(),
                        &auth.context,
                        &grant,
                        &key,
                        open_error_response(&key, OpenObjectError::Rejected(error)),
                    )
                    .await;
                }
            };
            match client.delete(url).send().await {
                Ok(response) if response.status().is_success() => {
                    if let Err(response) = record_operation(
                        state.control.clone(),
                        &auth.context,
                        OperationUsage {
                            grant: &grant,
                            source_bytes: 0,
                            output_bytes: 0,
                        },
                        &key,
                    )
                    .await
                    {
                        return response;
                    }
                    StatusCode::NO_CONTENT.into_response()
                }
                Ok(response) => s3_error::internal_error(
                    &key,
                    &format!("presigned DELETE returned {}", response.status()),
                ),
                Err(error) => {
                    let failure = PresignedTransportFailure::from_reqwest(&error);
                    warn!(
                        key,
                        category = failure.as_str(),
                        "presigned DELETE transport failed"
                    );
                    s3_error::internal_error(&key, "presigned backend request failed")
                }
            }
        }
        ResolvedBackend::S3 { client, .. } => match client
            .delete_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => {
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        grant: &grant,
                        source_bytes: 0,
                        output_bytes: 0,
                    },
                    &key,
                )
                .await
                {
                    return response;
                }
                StatusCode::NO_CONTENT.into_response()
            }
            Err(error) => {
                let failure = record_s3_failure("delete_object", &error);
                s3_error::internal_error(&key, failure.client_message())
            }
        },
        ResolvedBackend::Managed(storage) => {
            if storage.managed_mode() == ManagedStreamingMode::Observe {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::service_unavailable(
                        &key,
                        "managed mutations are disabled in observe mode",
                    ),
                )
                .await;
            }
            let result = match storage.managed_mode() {
                ManagedStreamingMode::Off => storage
                    .delete(&format!("{}/{bucket}/{key}", auth.workspace_id().as_str()))
                    .await
                    .map_err(|error| error.to_string()),
                ManagedStreamingMode::Observe => unreachable!("handled above"),
                ManagedStreamingMode::Enforce => storage
                    .tombstone_authoritative(&managed_logical_key(&auth, &bucket, &key))
                    .await
                    .map_err(|error| error.to_string()),
            };
            if let Err(error) = result {
                return s3_error::internal_error(&key, &error.to_string());
            }
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    grant: &grant,
                    source_bytes: 0,
                    output_bytes: 0,
                },
                &key,
            )
            .await
            {
                return response;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        ResolvedBackend::Memory(store) => {
            store.delete(&bucket, &key);
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    grant: &grant,
                    source_bytes: 0,
                    output_bytes: 0,
                },
                &key,
            )
            .await
            {
                return response;
            }
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

async fn s3_post(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    request: Request,
) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    if let Some(upload_id) = params.upload_id.as_deref() {
        let authentication = match authenticate_headers(
            parts.method.as_str(),
            &parts.uri,
            &parts.headers,
            &state.keys,
            &state,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return authentication_error_response(&key, error),
        };
        if let Some(response) = client_metering_id_rejection(&parts.headers, &key) {
            return response;
        }
        let Some(staging) = staged_multipart(&state).cloned() else {
            return s3_error::multipart_not_supported(&key);
        };
        let identity = multipart_identity(&authentication.auth, &bucket, &key, upload_id);
        let upload = match staging.repository.get_authorized(&identity).await {
            Ok(upload) => upload,
            Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
        };
        let persisted_resolution = match restore_multipart_pipeline(
            &upload.snapshot.plugin_snapshot,
        ) {
            Ok(resolution) => resolution,
            Err(MultipartPipelineRestoreError::LegacyRawSnapshot) => {
                return s3_error::invalid_request(
                    &key,
                    "Legacy multipart pipeline snapshots cannot be resumed safely; abort and restart the upload.",
                );
            }
            Err(MultipartPipelineRestoreError::Invalid(error)) => {
                return pipeline_error_response(&key, &error);
            }
        };
        let backend = match resolve_backend(
            &state,
            &authentication.auth,
            &parts.headers,
            StorageOperation::Multipart,
        )
        .await
        {
            Ok(backend) => backend,
            Err(_) => return backend_resolution_error_response(&key),
        };
        if let Err(error) = validate_streaming_backend(&state, &backend) {
            return streaming_put_error_response(&key, error);
        }
        let (auth, body) =
            match read_verified_body(authentication, body, MAX_COMPLETE_XML_BYTES).await {
                Ok(value) => value,
                Err(VerifiedBodyError::TooLarge) => {
                    return s3_error::invalid_request(
                        &key,
                        "CompleteMultipartUpload XML exceeds 1 MiB",
                    );
                }
                Err(VerifiedBodyError::Integrity(error)) => {
                    return s3_error::bad_digest(&key, &error.to_string());
                }
                Err(VerifiedBodyError::Transport) => {
                    return s3_error::invalid_request(
                        &key,
                        "CompleteMultipartUpload request body failed",
                    );
                }
            };
        if state
            .control
            .streaming_write_mode(&auth.context)
            .await
            .unwrap_or(state.streaming_write_mode)
            < StreamingWriteMode::All
        {
            return s3_error::multipart_not_supported(&key);
        }
        let selected = match parse_complete_multipart_xml(&body) {
            Ok(parts) => parts,
            Err(error) if error.contains("sorted") => {
                return s3_error::invalid_part_order(&key);
            }
            Err(error) => {
                return s3_error::invalid_request(&key, &error);
            }
        };
        if let ResolvedBackend::Managed(storage) = &backend {
            let Some(epoch) = upload.namespace_epoch else {
                let response = s3_error::service_unavailable(
                    &key,
                    "managed multipart upload has no namespace epoch",
                );
                return response;
            };
            if let Err(error) = storage
                .assert_managed_multipart(upload_id, auth.workspace_id().as_str(), epoch, false)
                .await
            {
                return s3_error::service_unavailable(&key, &error.to_string());
            }
        }
        let fingerprint = match completion_fingerprint(&upload, &selected) {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                return s3_error::internal_error(&key, &error.to_string());
            }
        };
        // Exact retries share an operation; conflicting canonical requests do not.
        let operation = multipart_completion_operation_identity(upload_id, &fingerprint);
        let authorization = operation.pipeline_authorization(
            &bucket,
            UsageRoute::CompleteMultipartUpload,
            RequestKind::Write,
            object_max_processed_bytes(&state),
            &persisted_resolution,
        );
        let grant =
            match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
                .await
            {
                Ok(grant) => grant,
                Err(response) => return response,
            };
        let lease = match staging
            .repository
            .acquire_completion(
                &identity,
                &fingerprint,
                &selected,
                &format!("complete-{}", Uuid::now_v7()),
                now_ms() + COMPLETION_LEASE.as_millis() as i64,
                now_ms(),
            )
            .await
        {
            Ok(CompletionAcquire::Replayed(result)) => {
                if let Err(response) = record_durable_operation_with_event(
                    state.operation_journal.as_ref(),
                    state.control.clone(),
                    &auth.context,
                    multipart_completion_event(&grant, &result),
                    &key,
                )
                .await
                {
                    return response;
                }
                let mut response = s3_xml_ok(complete_multipart_xml(&bucket, &key, &result));
                if let Some(version) = result.version_id
                    && let Ok(version) = version.parse()
                {
                    response.headers_mut().insert("x-amz-version-id", version);
                }
                return response;
            }
            Ok(CompletionAcquire::Busy) => {
                // This exact operation may still be committing in another worker.
                return s3_error::slow_down(&key);
            }
            Ok(CompletionAcquire::Acquired(lease)) => lease,
            Err(StagingError::InvalidPart) => {
                let response = s3_error::invalid_part(
                    &key,
                    "submitted part is missing or does not match its staged ETag/checksum",
                );
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            Err(StagingError::CompletionConflict) => {
                let response =
                    s3_error::invalid_request(&key, "conflicting CompleteMultipartUpload request");
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            Err(StagingError::NotFound | StagingError::NotOpen) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::no_such_upload(&key),
                )
                .await;
            }
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::internal_error(&key, &error.to_string()),
                )
                .await;
            }
        };
        let recovered = match reconcile_existing_direct_completion(
            &state,
            &backend,
            grant.operation_id(),
            auth.workspace_id().as_str(),
            &bucket,
            &key,
        )
        .await
        {
            Ok(ExistingDirectCompletion::New) => None,
            Ok(ExistingDirectCompletion::Committed(operation)) => Some(*operation),
            Ok(ExistingDirectCompletion::ProvenAborted) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::service_unavailable(
                        &key,
                        "The previous multipart completion attempt was proven aborted.",
                    ),
                )
                .await;
            }
            Ok(ExistingDirectCompletion::Pending) | Err(_) => {
                return s3_error::service_unavailable(
                    &key,
                    "The previous multipart completion outcome is still being reconciled.",
                );
            }
            Ok(ExistingDirectCompletion::Conflict) => {
                return s3_error::invalid_request(
                    &key,
                    "The multipart completion backend or routing identity changed.",
                );
            }
        };
        let result = if let Some(recovered_operation) = recovered {
            let result = match recovered_multipart_result(
                state.operation_journal.as_ref(),
                recovered_operation,
                &lease,
                operation.receipt_id,
            )
            .await
            {
                Ok(result) => result,
                Err(error) => return multipart_completion_error_response(&key, error),
            };
            if let Err(error) = staging
                .repository
                .complete_completion(&identity, lease.fencing_token, result.clone(), now_ms())
                .await
            {
                return multipart_completion_error_response(
                    &key,
                    MultipartCompletionError::Staging(error),
                );
            }
            result
        } else {
            let complete = tokio::time::timeout(
                Duration::from_secs(MAX_MULTIPART_COMPLETION_SECS),
                complete_staged_multipart(
                    &state,
                    &staging,
                    &identity,
                    &upload,
                    &lease,
                    AuthorizedOperation {
                        auth: &auth,
                        grant: &grant,
                    },
                    backend,
                    &persisted_resolution,
                ),
            )
            .await;
            match complete {
                Ok(Ok(result)) => result,
                Ok(Err(error)) => {
                    return multipart_completion_failure_response(
                        state.control.as_ref(),
                        &auth.context,
                        &grant,
                        &key,
                        error,
                    )
                    .await;
                }
                Err(_) => {
                    return s3_error::service_unavailable(
                        &key,
                        "multipart completion exceeded the configured hosted time limit",
                    );
                }
            }
        };
        cleanup_staged_parts(&staging, upload_id, lease.cleanup_parts, "complete").await;
        if let Err(response) = record_durable_operation_with_event(
            state.operation_journal.as_ref(),
            state.control.clone(),
            &auth.context,
            multipart_completion_event(&grant, &result),
            &key,
        )
        .await
        {
            return response;
        }
        let mut response = s3_xml_ok(complete_multipart_xml(&bucket, &key, &result));
        if let Some(version) = result.version_id
            && let Ok(version) = version.parse()
        {
            response.headers_mut().insert("x-amz-version-id", version);
        }
        return response;
    }
    let auth = match authenticate(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &[],
        &state.keys,
        &state,
    )
    .await
    {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&parts.headers, &key) {
        return response;
    }
    info!("POST /{bucket}/{key} user={}", auth.user_id());

    if params.uploads.is_some() {
        let resolution_started = Instant::now();
        let resolution = match state
            .gateway
            .resolve(
                auth.workspace_id().as_str(),
                &bucket,
                crate::pipeline::PipelineDirection::Write,
            )
            .await
        {
            Ok(resolution) => resolution,
            Err(error) => {
                let operation = request_operation_identity();
                record_failed_pipeline_attempt(
                    state.control.as_ref(),
                    &auth.context,
                    operation.operation_id,
                    &bucket,
                    crate::pipeline::PipelineDirection::Write,
                    None,
                    error.code(),
                    resolution_started.elapsed().as_millis() as u64,
                )
                .await;
                return pipeline_error_response(&key, &error);
            }
        };
        let backend =
            match resolve_backend(&state, &auth, &parts.headers, StorageOperation::Multipart).await
            {
                Ok(backend) => backend,
                Err(_) => return backend_resolution_error_response(&key),
            };
        if let Err(error) = validate_streaming_backend(&state, &backend) {
            return streaming_put_error_response(&key, error);
        }
        if let ResolvedBackend::Managed(storage) = &backend
            && let Err(error) = storage
                .assert_namespace_active(auth.workspace_id().as_str())
                .await
        {
            return s3_error::service_unavailable(&key, &error.to_string());
        }
        let Some(staging) = staged_multipart(&state).cloned() else {
            return s3_error::multipart_not_supported(&key);
        };
        if state
            .control
            .streaming_write_mode(&auth.context)
            .await
            .unwrap_or(state.streaming_write_mode)
            < StreamingWriteMode::All
        {
            return s3_error::multipart_not_supported(&key);
        }
        // Freeze and serialize policy before creating managed multipart state.
        // Resolver or serialization failures therefore cannot orphan a managed
        // registration without a corresponding staging upload.
        let plugin_snapshot = match serde_json::to_value(&resolution) {
            Ok(snapshot) => snapshot,
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
        };
        let upload_id = Uuid::now_v7().to_string();
        let managed_registration = if let ResolvedBackend::Managed(storage) = &backend {
            match storage
                .begin_managed_multipart(&upload_id, auth.workspace_id().as_str())
                .await
            {
                Ok(epoch) => Some((storage.clone(), epoch)),
                Err(error) => return s3_error::service_unavailable(&key, &error.to_string()),
            }
        } else {
            None
        };
        let now = now_ms();
        let upload = MultipartUpload {
            identity: multipart_identity(&auth, &bucket, &key, &upload_id),
            namespace_epoch: managed_registration.as_ref().map(|(_, epoch)| *epoch),
            snapshot: multipart_snapshot(
                &parts.headers,
                &backend,
                plugin_snapshot,
                state.source_body_limits.max_bytes,
            ),
            lifecycle: MultipartLifecycle::Open,
            staged_bytes: 0,
            reserved_bytes: 0,
            created_at_ms: now,
            expires_at_ms: now + 24 * 60 * 60 * 1000,
            updated_at_ms: now,
            tombstone_until_ms: None,
            complete_request_fingerprint: None,
            completion_lease_owner: None,
            completion_lease_expires_at_ms: None,
            completion_fencing_token: 0,
            completion_result: None,
        };
        return match staging.repository.create(upload).await {
            Ok(()) => {
                if let Some((storage, epoch)) = &managed_registration
                    && let Err(error) = storage
                        .confirm_managed_multipart(&upload_id, auth.workspace_id().as_str(), *epoch)
                        .await
                {
                    let identity = multipart_identity(&auth, &bucket, &key, &upload_id);
                    let _ = staging.repository.abort(&identity, now_ms()).await;
                    let _ = staging.repository.delete_terminal_upload(&identity).await;
                    let _ = storage
                        .finish_managed_multipart(&upload_id, auth.workspace_id().as_str(), *epoch)
                        .await;
                    return s3_error::service_unavailable(&key, &error.to_string());
                }
                s3_xml_ok(create_multipart_xml(&bucket, &key, &upload_id))
            }
            Err(error) => {
                if let Some((storage, epoch)) = managed_registration {
                    let _ = storage
                        .finish_managed_multipart(&upload_id, auth.workspace_id().as_str(), epoch)
                        .await;
                }
                match error {
                    StagingError::QuotaExceeded => s3_error::slow_down(&key),
                    error => s3_error::internal_error(&key, &error.to_string()),
                }
            }
        };
    }
    s3_error::not_implemented(&key)
}

/// ListObjectsV2/ListObjectsV1 — `GET /{bucket}`.
async fn s3_list_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&bucket, error),
    };
    if let Some(response) = client_metering_id_rejection(&headers, &bucket) {
        return response;
    }
    let operation = request_operation_identity();
    let authorization =
        operation.authorization(&bucket, UsageRoute::ListObjects, RequestKind::Read, 0);
    let grant = match authorize_request(
        state.control.as_ref(),
        &auth.context,
        &authorization,
        &bucket,
    )
    .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::List).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &bucket,
                backend_resolution_error_response(&bucket),
            )
            .await;
        }
    };
    let response = match backend {
        ResolvedBackend::S3 { client, .. } => match list_from_s3(&client, &bucket, &params).await {
            Ok(xml) => s3_xml_ok(xml),
            Err(failure) => s3_error::internal_error(&bucket, failure.client_message()),
        },
        ResolvedBackend::Memory(store) => {
            match list_from_memory(&store, &bucket, &params, &state.continuation_token_key) {
                Ok(xml) => s3_xml_ok(xml),
                Err(error) => s3_error::invalid_request(&bucket, &error),
            }
        }
        ResolvedBackend::Managed(storage) => match list_from_managed(
            &storage,
            auth.workspace_id().as_str(),
            &bucket,
            &params,
            &state.continuation_token_key,
        )
        .await
        {
            Ok(xml) => s3_xml_ok(xml),
            Err(ManagedListError::InvalidRequest(error)) => {
                s3_error::invalid_request(&bucket, &error)
            }
            Err(ManagedListError::Unavailable) => {
                s3_error::service_unavailable(&bucket, "managed listing is temporarily unavailable")
            }
        },
        ResolvedBackend::PresignedHttp(url) => {
            match open_http_object(&state, url, &headers, false).await {
                Ok(object) => object.into_response(),
                Err(error) => open_error_response(&bucket, error),
            }
        }
    };
    if !response.status().is_success() {
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &bucket,
            response,
        )
        .await;
    }
    if let Err(response) = record_operation(
        state.control.clone(),
        &auth.context,
        OperationUsage {
            grant: &grant,
            source_bytes: 0,
            output_bytes: 0,
        },
        &bucket,
    )
    .await
    {
        return response;
    }
    response
}

/// Forward a ListObjectsV2 request to an S3 backend.
async fn list_from_s3(s3: &Client, bucket: &str, params: &S3Query) -> Result<String, S3Failure> {
    if params.list_type.as_deref() != Some("2") {
        return list_from_s3_v1(s3, bucket, params).await;
    }
    let mut req = s3.list_objects_v2().bucket(bucket);
    if let Some(p) = params.prefix.as_deref() {
        req = req.prefix(p);
    }
    if let Some(d) = params.delimiter.as_deref() {
        req = req.delimiter(d);
    }
    if let Some(t) = params.continuation_token.as_deref() {
        req = req.continuation_token(t);
    }
    if let Some(s) = params.start_after.as_deref() {
        req = req.start_after(s);
    }
    if let Some(m) = params.max_keys {
        req = req.max_keys(m.min(1000) as i32);
    }
    let out = req
        .send()
        .await
        .map_err(|error| record_s3_failure("list_objects_v2", &error))?;

    let encoding = params.encoding_type.as_deref() == Some("url");
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        xml_escape(params.prefix.as_deref().unwrap_or(""))
    ));
    if let Some(d) = params.delimiter.as_deref() {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    xml.push_str(&format!(
        "<KeyCount>{}</KeyCount>",
        out.key_count().unwrap_or(0)
    ));
    xml.push_str(&format!(
        "<MaxKeys>{}</MaxKeys>",
        out.max_keys().unwrap_or(1000)
    ));
    xml.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        out.is_truncated().unwrap_or(false)
    ));
    if let Some(token) = out.continuation_token() {
        xml.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(token)
        ));
    }
    if let Some(token) = out.next_continuation_token() {
        xml.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            xml_escape(token)
        ));
    }
    if let Some(start) = params.start_after.as_deref() {
        xml.push_str(&format!("<StartAfter>{}</StartAfter>", xml_escape(start)));
    }
    for c in out.contents().iter() {
        let k = c.key().unwrap_or_default();
        let display = if encoding {
            url_encode(k)
        } else {
            k.to_string()
        };
        let etag = c.e_tag().unwrap_or_default();
        let size = c.size().unwrap_or(0);
        let lm = c.last_modified().map(|d| d.to_string()).unwrap_or_default();
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{lm}</LastModified><ETag>{}</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&display),
            xml_escape(etag)
        ));
    }
    for cp in out.common_prefixes() {
        if let Some(p) = cp.prefix() {
            let display = if encoding {
                url_encode(p)
            } else {
                p.to_string()
            };
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(&display)
            ));
        }
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}

async fn list_from_s3_v1(s3: &Client, bucket: &str, params: &S3Query) -> Result<String, S3Failure> {
    let mut request = s3.list_objects().bucket(bucket);
    if let Some(prefix) = params.prefix.as_deref() {
        request = request.prefix(prefix);
    }
    if let Some(delimiter) = params.delimiter.as_deref() {
        request = request.delimiter(delimiter);
    }
    if let Some(marker) = params.marker.as_deref() {
        request = request.marker(marker);
    }
    if let Some(max_keys) = params.max_keys {
        request = request.max_keys(max_keys.min(1000) as i32);
    }
    let output = request
        .send()
        .await
        .map_err(|error| record_s3_failure("list_objects_v1", &error))?;
    let encoding = params.encoding_type.as_deref() == Some("url");
    let display = |value: &str| {
        if encoding {
            url_encode(value)
        } else {
            value.to_string()
        }
    };
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        xml_escape(params.prefix.as_deref().unwrap_or(""))
    ));
    if let Some(delimiter) = params.delimiter.as_deref() {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(delimiter)));
    }
    if let Some(marker) = params.marker.as_deref() {
        xml.push_str(&format!("<Marker>{}</Marker>", xml_escape(marker)));
    }
    xml.push_str(&format!(
        "<MaxKeys>{}</MaxKeys>",
        output.max_keys().unwrap_or(1000)
    ));
    xml.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        output.is_truncated().unwrap_or(false)
    ));
    if let Some(marker) = output.next_marker() {
        xml.push_str(&format!("<NextMarker>{}</NextMarker>", xml_escape(marker)));
    }
    for content in output.contents() {
        let key = content.key().unwrap_or_default();
        let last_modified = content
            .last_modified()
            .map(|value| value.to_string())
            .unwrap_or_default();
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{last_modified}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&display(key)),
            xml_escape(content.e_tag().unwrap_or_default()),
            content.size().unwrap_or(0),
        ));
    }
    for common_prefix in output.common_prefixes() {
        if let Some(prefix) = common_prefix.prefix() {
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(&display(prefix))
            ));
        }
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}

fn encode_memory_continuation(
    key: &[u8; 32],
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    last: &str,
) -> String {
    let payload = serde_json::to_vec(&(bucket, prefix, delimiter, last))
        .expect("continuation tuple is serializable");
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(&payload);
    let mut encoded = mac.finalize().into_bytes().to_vec();
    encoded.extend(payload);
    URL_SAFE_NO_PAD.encode(encoded)
}

fn decode_memory_continuation(
    key: &[u8; 32],
    token: &str,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
) -> Result<String, String> {
    let encoded = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| "invalid continuation token".to_string())?;
    if encoded.len() < 32 {
        return Err("invalid continuation token".to_string());
    }
    let (tag, payload) = encoded.split_at(32);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(payload);
    mac.verify_slice(tag)
        .map_err(|_| "invalid continuation token".to_string())?;
    let (token_bucket, token_prefix, token_delimiter, last): (
        String,
        String,
        Option<String>,
        String,
    ) = serde_json::from_slice(payload).map_err(|_| "invalid continuation token".to_string())?;
    (token_bucket == bucket && token_prefix == prefix && token_delimiter.as_deref() == delimiter)
        .then_some(last)
        .ok_or_else(|| "continuation token does not match this listing".to_string())
}

#[derive(Debug)]
enum ManagedListError {
    InvalidRequest(String),
    Unavailable,
}

fn encode_managed_continuation(
    key: &[u8; 32],
    tenant_id: &str,
    bucket: &str,
    prefix: &str,
    last: &str,
) -> String {
    let payload = serde_json::to_vec(&(tenant_id, bucket, prefix, last))
        .expect("managed continuation tuple is serializable");
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(&payload);
    let mut encoded = mac.finalize().into_bytes().to_vec();
    encoded.extend(payload);
    URL_SAFE_NO_PAD.encode(encoded)
}

fn decode_managed_continuation(
    key: &[u8; 32],
    token: &str,
    tenant_id: &str,
    bucket: &str,
    prefix: &str,
) -> Result<String, ManagedListError> {
    let encoded = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ManagedListError::InvalidRequest("invalid continuation token".to_string()))?;
    if encoded.len() < 32 {
        return Err(ManagedListError::InvalidRequest(
            "invalid continuation token".to_string(),
        ));
    }
    let (tag, payload) = encoded.split_at(32);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(payload);
    mac.verify_slice(tag)
        .map_err(|_| ManagedListError::InvalidRequest("invalid continuation token".to_string()))?;
    let (token_tenant, token_bucket, token_prefix, last): (String, String, String, String) =
        serde_json::from_slice(payload).map_err(|_| {
            ManagedListError::InvalidRequest("invalid continuation token".to_string())
        })?;
    (token_tenant == tenant_id && token_bucket == bucket && token_prefix == prefix)
        .then_some(last)
        .ok_or_else(|| {
            ManagedListError::InvalidRequest(
                "continuation token does not match this listing".to_string(),
            )
        })
}

#[cfg(test)]
#[test]
fn managed_list_continuation_is_bound_to_tenant_and_query() {
    let key = [7_u8; 32];
    let token = encode_managed_continuation(&key, "tenant-a", "bucket", "logs/", "logs/a");
    assert_eq!(
        decode_managed_continuation(&key, &token, "tenant-a", "bucket", "logs/").unwrap(),
        "logs/a"
    );
    assert!(matches!(
        decode_managed_continuation(&key, &token, "tenant-b", "bucket", "logs/"),
        Err(ManagedListError::InvalidRequest(_))
    ));
    assert!(matches!(
        decode_managed_continuation(&key, &token, "tenant-a", "bucket", "other/"),
        Err(ManagedListError::InvalidRequest(_))
    ));
}

/// ListObjects against the managed authority ledger. The ledger is the sole
/// logical namespace: service-provider generation keys are never listed.
async fn list_from_managed(
    storage: &ServiceStorage,
    tenant_id: &str,
    bucket: &str,
    params: &S3Query,
    continuation_key: &[u8; 32],
) -> Result<String, ManagedListError> {
    if params
        .delimiter
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(ManagedListError::InvalidRequest(
            "managed listing does not support delimiter".to_string(),
        ));
    }
    let prefix = params.prefix.as_deref().unwrap_or("");
    let is_v2 = params.list_type.as_deref() == Some("2");
    let max_keys = params.max_keys.unwrap_or(1000).clamp(0, 1000) as u64;
    let after = match params.continuation_token.as_deref() {
        Some(token) if is_v2 => Some(decode_managed_continuation(
            continuation_key,
            token,
            tenant_id,
            bucket,
            prefix,
        )?),
        Some(_) => {
            return Err(ManagedListError::InvalidRequest(
                "continuation-token requires list-type=2".to_string(),
            ));
        }
        None => params
            .start_after
            .as_deref()
            .or(params.marker.as_deref())
            .map(ToOwned::to_owned),
    };
    let page = storage
        .list_authority(AuthorityListQuery {
            tenant_id: tenant_id.to_string(),
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            after: after.clone(),
            max_keys,
        })
        .await
        .map_err(|_| ManagedListError::Unavailable)?;
    let truncated = page.next_after.is_some();
    let encoding = params.encoding_type.as_deref() == Some("url");
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
    xml.push_str(&format!("<KeyCount>{}</KeyCount>", page.objects.len()));
    xml.push_str(&format!("<MaxKeys>{max_keys}</MaxKeys>"));
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    if let Some(token) = params.continuation_token.as_deref() {
        xml.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(token)
        ));
    } else if let Some(position) = &after {
        let element = if is_v2 { "StartAfter" } else { "Marker" };
        xml.push_str(&format!("<{element}>{}</{element}>", xml_escape(position)));
    }
    if let Some(next_after) = &page.next_after {
        let next = if is_v2 {
            encode_managed_continuation(continuation_key, tenant_id, bucket, prefix, next_after)
        } else {
            next_after.clone()
        };
        let element = if is_v2 {
            "NextContinuationToken"
        } else {
            "NextMarker"
        };
        xml.push_str(&format!("<{element}>{}</{element}>", xml_escape(&next)));
    }
    for authority in page.objects {
        let key = if encoding {
            url_encode(&authority.logical.key)
        } else {
            authority.logical.key
        };
        let last_modified = chrono::DateTime::from_timestamp_millis(authority.updated_at_ms)
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string());
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{last_modified}</LastModified><ETag>\"{}\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&key),
            xml_escape(&authority.digest),
            authority.size,
        ));
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}

/// ListObjectsV2 against the in-memory store.
fn list_from_memory(
    store: &MemoryStore,
    bucket: &str,
    params: &S3Query,
    continuation_key: &[u8; 32],
) -> Result<String, String> {
    let prefix = params.prefix.as_deref().unwrap_or("");
    let delimiter = params.delimiter.as_deref();
    let max_keys = params.max_keys.unwrap_or(1000).min(1000) as usize;
    let encoding = params.encoding_type.as_deref() == Some("url");
    let resume_after = match params.continuation_token.as_deref() {
        Some(token) => Some(decode_memory_continuation(
            continuation_key,
            token,
            bucket,
            prefix,
            delimiter,
        )?),
        None => params
            .start_after
            .as_deref()
            .or(params.marker.as_deref())
            .map(ToOwned::to_owned),
    };

    let bucket_prefix = format!("{bucket}/");
    let mut keys: Vec<String> = store
        .list_keys()
        .into_iter()
        .filter_map(|full| full.strip_prefix(&bucket_prefix).map(|k| k.to_string()))
        .filter(|k| k.starts_with(prefix))
        .collect();
    keys.sort();
    enum Output {
        Content((String, String, u64)),
        Common(String),
    }
    let mut outputs: Vec<Output> = Vec::new();
    let mut prev_common: Option<String> = None;
    for k in keys {
        if let Some(delim) = delimiter.filter(|d| !d.is_empty())
            && let Some(rel) = k.strip_prefix(prefix)
            && let Some(idx) = rel.find(delim)
        {
            let cp = format!("{prefix}{}", &rel[..=idx]);
            if prev_common.as_deref() != Some(cp.as_str()) {
                prev_common = Some(cp.clone());
                outputs.push(Output::Common(cp));
            }
            continue;
        }
        prev_common = None;
        let (etag, size) = store
            .metadata(bucket, &k)
            .map(|(size, _, etag)| (etag, size as u64))
            .unwrap_or_default();
        outputs.push(Output::Content((k, etag, size)));
    }

    // Continue from the previous *listed output*, not the raw object key. A
    // delimiter page can end at `logs/` while raw keys `logs/a` still sort
    // after it; filtering only raw keys would repeat that CommonPrefix forever.
    if let Some(resume_after) = &resume_after {
        outputs.retain(|output| match output {
            Output::Content((key, _, _)) => key > resume_after,
            Output::Common(prefix) => prefix > resume_after,
        });
    }

    let mut contents: Vec<(String, String, u64)> = Vec::new();
    let mut commons: Vec<String> = Vec::new();
    let mut seen = 0usize;
    for out in outputs.iter().take(max_keys) {
        match out {
            Output::Content(entry) => contents.push(entry.clone()),
            Output::Common(cp) => commons.push(cp.clone()),
        }
        seen += 1;
    }
    // S3 permits max-keys=0. It returns an empty non-resumable page rather
    // than manufacturing a cursor that cannot advance.
    let truncated = max_keys > 0 && outputs.len() > seen;
    let next_token = if truncated && seen > 0 {
        outputs.get(seen - 1).map(|out| match out {
            Output::Content((k, _, _)) => k.clone(),
            Output::Common(cp) => cp.clone(),
        })
    } else {
        None
    };

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
    if let Some(d) = delimiter {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    let is_v2 = params.list_type.as_deref() == Some("2");
    xml.push_str(&format!(
        "<KeyCount>{}</KeyCount>",
        contents.len() + commons.len()
    ));
    xml.push_str(&format!("<MaxKeys>{max_keys}</MaxKeys>"));
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    if let Some(t) = params.continuation_token.as_deref() {
        let elem = if is_v2 {
            format!("<ContinuationToken>{}</ContinuationToken>", xml_escape(t))
        } else {
            format!("<Marker>{}</Marker>", xml_escape(t))
        };
        xml.push_str(&elem);
    } else if let Some(t) = &resume_after {
        let elem = if is_v2 {
            format!("<StartAfter>{}</StartAfter>", xml_escape(t))
        } else {
            format!("<Marker>{}</Marker>", xml_escape(t))
        };
        xml.push_str(&elem);
    }
    if let Some(t) = next_token {
        let elem = if is_v2 {
            format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                xml_escape(&encode_memory_continuation(
                    continuation_key,
                    bucket,
                    prefix,
                    delimiter,
                    &t,
                ))
            )
        } else {
            format!("<NextMarker>{}</NextMarker>", xml_escape(&t))
        };
        xml.push_str(&elem);
    }
    for (k, etag, size) in &contents {
        let display = if encoding { url_encode(k) } else { k.clone() };
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>1970-01-01T00:00:00.000Z</LastModified><ETag>{}</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&display),
            xml_escape(etag)
        ));
    }
    for cp in &commons {
        let display = if encoding { url_encode(cp) } else { cp.clone() };
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            xml_escape(&display)
        ));
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}

/// `GET /` — serve the dashboard to browsers, ListBuckets to S3 clients.
async fn root(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let is_s3 = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|a| a.starts_with("AWS4-"))
        .unwrap_or(false)
        || headers.contains_key(customer_headers::ACCESS_KEY.canonical)
        || headers.contains_key(customer_headers::ACCESS_KEY.legacy)
        || uri.query().is_some_and(|query| {
            query
                .split('&')
                .any(|pair| pair.starts_with("X-Amz-Algorithm="))
        });
    if !is_s3 {
        return Html(dashboard_html()).into_response();
    }
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response("", error).into_response(),
    };
    match list_buckets(&state, &auth, &headers).await {
        Ok(xml) => s3_xml_ok(xml).into_response(),
        Err(_) => backend_resolution_error_response(""),
    }
}

async fn list_buckets(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
) -> anyhow::Result<String> {
    let mut names: Vec<String> = Vec::new();
    match resolve_backend(state, auth, headers, StorageOperation::List)
        .await
        .map_err(anyhow::Error::msg)?
    {
        ResolvedBackend::S3 { client, .. } => {
            let out = client
                .list_buckets()
                .send()
                .await
                .map_err(|error| record_s3_failure("list_buckets", &error))?;
            for bucket in out.buckets() {
                if let Some(name) = bucket.name() {
                    names.push(name.to_string());
                }
            }
        }
        ResolvedBackend::Memory(store) => {
            let mut set = std::collections::BTreeSet::new();
            for full in store.list_keys() {
                if let Some((bucket, _)) = full.split_once('/') {
                    set.insert(bucket.to_string());
                }
            }
            names.extend(set);
        }
        ResolvedBackend::Managed(_) | ResolvedBackend::PresignedHttp(_) => {}
    }
    names.sort();
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>maskura</ID><DisplayName>Maskura</DisplayName></Owner><Buckets>"#,
    );
    for n in names {
        xml.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>1970-01-01T00:00:00.000Z</CreationDate></Bucket>",
            xml_escape(&n)
        ));
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml)
}

/// CreateBucket is not allowed — buckets map to configured backends.
async fn s3_bucket_put(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(error) =
        authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await
    {
        return authentication_error_response(&bucket, error);
    }
    s3_error::bucket_not_allowed(&bucket)
}

/// DeleteBucket is not allowed for the same reason as CreateBucket.
async fn s3_bucket_delete(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(error) =
        authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await
    {
        return authentication_error_response(&bucket, error);
    }
    s3_error::bucket_not_allowed(&bucket)
}

fn dashboard_html() -> String {
    let html = include_str!("../static/dashboard.html");
    let auth_disabled = std::env::var("AUTH_DISABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let supabase_url =
        std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:54321".to_string());
    let anon_key = std::env::var("SUPABASE_ANON_KEY")
        .unwrap_or_else(|_| "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH".to_string());
    let has_supabase = anon_key.starts_with("sb_");

    let supabase_script = if has_supabase {
        format!(
            "<script src=\"https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js\"></script>\n<script>var supabase = window.supabase.createClient('{supabase_url}', '{anon_key}');\nvar HAS_SUPABASE = true;</script>"
        )
    } else {
        "<script>var HAS_SUPABASE = false;</script>".to_string()
    };

    // Local mode (AUTH_DISABLED=true): skip the auth modal entirely, go
    // straight into the dashboard as the local demo user.
    let boot = if auth_disabled || !has_supabase {
        "isDemo = true; onAuthReady();".to_string()
    } else {
        "supabase.auth.getSession().then(function(r) { if (r.data.session) { session = r.data.session; sessionToken = session.access_token; onAuthReady(); } });".to_string()
    };

    let auth_flag = format!(
        "<script>var AUTH_DISABLED = {};</script>",
        if auth_disabled { "true" } else { "false" }
    );

    html.replace("<!--SUPABASE-->", &format!("{auth_flag}{supabase_script}"))
        .replace("/*BOOT*/", &boot)
}

async fn health() -> impl IntoResponse {
    "ok"
}

fn invalid_credential_mutation_response() -> axum::response::Response {
    (StatusCode::BAD_REQUEST, "invalid credential mutation").into_response()
}

/// List API keys for the authenticated user
#[utoipa::path(
    get,
    path = "/dashboard/api/keys",
    responses((status = 200, description = "API keys", body = Vec<ListKeyResponse>)),
    tag = "keys"
)]
async fn get_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let keys = match state.keys.list_for_user(&uid).await {
        Ok(keys) => keys,
        Err(error) => {
            tracing::error!(user_id = uid, error = %error, "API key listing failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let resp: Vec<ListKeyResponse> = keys
        .into_iter()
        .map(|k| ListKeyResponse {
            key_id: k.key_id,
            label: k.label,
            created_at: k.created_at,
            expires_at: k.expires_at,
            public_key_pem: k.public_key_pem,
        })
        .collect();
    Json(resp).into_response()
}

/// Create a new API key
#[utoipa::path(
    post,
    path = "/dashboard/api/keys",
    request_body = CreateKeyRequest,
    responses((status = 200, description = "Created key with secret", body = ApiKeyResponse)),
    tag = "keys"
)]
async fn create_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let label = match canonicalize_credential_label(&body.label) {
        Ok(label) => label,
        Err(_) => return invalid_credential_mutation_response(),
    };
    if validate_credential_ttl(body.expires_in).is_err() {
        return invalid_credential_mutation_response();
    }
    let public_key_pem = match body
        .public_key_pem
        .as_deref()
        .map(canonicalize_public_key_pem)
        .transpose()
    {
        Ok(public_key_pem) => public_key_pem,
        Err(_) => return invalid_credential_mutation_response(),
    };
    let result = state
        .keys
        .create_key(&uid, &label, body.expires_in, public_key_pem)
        .await;
    let (secret, created) = match result {
        Ok(created) => created,
        Err(error) => {
            tracing::error!(
                user_id = uid,
                error = %error,
                "API key creation persistence failed"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(InternalErrorResponse {
                    error: "internal_error".to_string(),
                }),
            )
                .into_response();
        }
    };
    Json(ApiKeyResponse {
        key_id: created.key_id,
        secret,
        label: created.label,
        created_at: created.created_at,
        expires_at: created.expires_at,
        public_key_pem: created.public_key_pem,
    })
    .into_response()
}

/// Revoke an API key
#[utoipa::path(
    delete,
    path = "/dashboard/api/keys",
    request_body = DeleteKeyRequest,
    responses((status = 204, description = "Key revoked"), (status = 404, description = "Key not found")),
    tag = "keys"
)]
async fn delete_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteKeyRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.keys.delete_key(&body.key_id, &uid).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "key not found").into_response(),
        Err(error) => {
            tracing::error!(user_id = uid, error = %error, "API key deletion failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// List MCP bearer tokens for the authenticated user (hashes only).
#[utoipa::path(
    get,
    path = "/dashboard/api/mcp-tokens",
    responses((status = 200, description = "MCP tokens", body = Vec<McpTokenResponse>)),
    tag = "mcp"
)]
async fn get_mcp_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let tokens = match state.keys.list_mcp_tokens(&uid).await {
        Ok(tokens) => tokens,
        Err(error) => {
            tracing::error!(user_id = uid, error = %error, "MCP token listing failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let resp: Vec<McpTokenResponse> = tokens
        .into_iter()
        .map(|t| McpTokenResponse {
            token_hash: t.token_hash,
            label: t.label,
            created_at: t.created_at,
            expires_at: t.expires_at,
        })
        .collect();
    Json(resp).into_response()
}

/// Create an MCP bearer token (`s4m_...`). The plaintext token is returned
/// once and only its hash is stored.
#[utoipa::path(
    post,
    path = "/dashboard/api/mcp-tokens",
    request_body = CreateMcpTokenRequest,
    responses((status = 200, description = "Created MCP token", body = McpTokenCreatedResponse)),
    tag = "mcp"
)]
async fn create_mcp_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateMcpTokenRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let label = match canonicalize_credential_label(&body.label) {
        Ok(label) => label,
        Err(_) => return invalid_credential_mutation_response(),
    };
    if validate_credential_ttl(body.expires_in).is_err() {
        return invalid_credential_mutation_response();
    }
    let (token, created) = match state
        .keys
        .create_mcp_token(&uid, &label, body.expires_in)
        .await
    {
        Ok(created) => created,
        Err(error) => {
            tracing::error!(user_id = uid, error = %error, "MCP token creation persistence failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    Json(McpTokenCreatedResponse {
        token,
        label,
        created_at: created.created_at,
        expires_at: created.expires_at,
    })
    .into_response()
}

/// Revoke an MCP bearer token.
#[utoipa::path(
    delete,
    path = "/dashboard/api/mcp-tokens",
    request_body = DeleteMcpTokenRequest,
    responses((status = 204, description = "Token revoked"), (status = 404, description = "Token not found")),
    tag = "mcp"
)]
async fn delete_mcp_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteMcpTokenRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.keys.delete_mcp_token(&body.token_hash, &uid).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "token not found").into_response(),
        Err(error) => {
            tracing::error!(user_id = uid, error = %error, "MCP token deletion failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/dashboard/api/backend",
    responses(
        (status = 200, description = "Redacted workspace backend configuration", body = BackendConfigResponse),
        (status = 401, description = "Not authenticated")
    ),
    tag = "backend"
)]
async fn get_backend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let workspace = match state.workspace_storage.resolve_workspace(&uid).await {
        Ok(workspace) => workspace,
        Err(error) => return workspace_storage_error_response(error),
    };
    match state.workspace_storage.get_public_config(&workspace).await {
        Ok(config) => Json(config).into_response(),
        Err(error) => workspace_storage_error_response(error),
    }
}

fn workspace_storage_error_response(error: WorkspaceStorageError) -> axum::response::Response {
    let (status, code, message) = match &error {
        WorkspaceStorageError::InvalidConfig(_) | WorkspaceStorageError::UnsupportedConfig(_) => (
            StatusCode::BAD_REQUEST,
            "invalid_backend_config",
            error.to_string(),
        ),
        WorkspaceStorageError::Repository(_) | WorkspaceStorageError::AmbiguousAdmission(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "workspace_storage_unavailable",
            "workspace storage is temporarily unavailable".to_string(),
        ),
    };
    (
        status,
        Json(serde_json::json!({
            "code": code,
            "message": message,
        })),
    )
        .into_response()
}

async fn validate_and_put_workspace_backend(
    repository: &dyn WorkspaceStorageRepository,
    endpoint_policy: &WorkspaceEndpointPolicy,
    workspace: &WorkspaceId,
    config: BackendConfigRequest,
) -> Result<BackendConfigResponse, WorkspaceStorageError> {
    if config.backend_type == BackendType::S3Compatible {
        endpoint_policy
            .validate(&config.endpoint)
            .await
            .map_err(WorkspaceStorageError::InvalidConfig)?;
    }
    repository.put_config(workspace, config).await
}

#[utoipa::path(
    put,
    path = "/dashboard/api/backend",
    request_body = BackendConfigRequest,
    responses(
        (status = 200, description = "Redacted saved workspace backend configuration", body = BackendConfigResponse),
        (status = 400, description = "Incomplete or unsupported configuration"),
        (status = 401, description = "A real authenticated user is required")
    ),
    tag = "backend"
)]
async fn put_backend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(config): Json<BackendConfigRequest>,
) -> impl IntoResponse {
    if state.auth_disabled {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let workspace = match state.workspace_storage.resolve_workspace(&uid).await {
        Ok(workspace) => workspace,
        Err(error) => return workspace_storage_error_response(error),
    };
    match validate_and_put_workspace_backend(
        state.workspace_storage.as_ref(),
        &state.workspace_endpoint_policy,
        &workspace,
        config,
    )
    .await
    {
        Ok(config) => Json(config).into_response(),
        Err(error) => workspace_storage_error_response(error),
    }
}

async fn get_plugins(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.plugins.list())
}

#[derive(Deserialize)]
struct SetPublicKeyRequest {
    key_id: String,
    public_key_pem: String,
}

enum PublicKeyMutationActor {
    ApiKey { access_key: String, user_id: String },
    DashboardUser(String),
}

fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, StatusCode> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    value
        .map(|value| value.to_str().map_err(|_| StatusCode::UNAUTHORIZED))
        .transpose()
}

fn unique_customer_header(
    headers: &HeaderMap,
    alias: customer_headers::HeaderAlias,
) -> Result<Option<&str>, StatusCode> {
    customer_headers::aliased_unique(headers, alias)
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .map(|value| value.to_str().map_err(|_| StatusCode::UNAUTHORIZED))
        .transpose()
}

async fn authenticate_public_key_mutation(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<PublicKeyMutationActor, StatusCode> {
    let authorization = unique_header(headers, "authorization")?;
    let access_key = unique_customer_header(headers, customer_headers::ACCESS_KEY)?;
    let secret_key = unique_customer_header(headers, customer_headers::SECRET_KEY)?;
    let mcp_token = unique_customer_header(headers, customer_headers::MCP_TOKEN)?;
    let api_headers_supplied = access_key.is_some() || secret_key.is_some();
    if (api_headers_supplied && authorization.is_some())
        || (mcp_token.is_some() && (api_headers_supplied || authorization.is_some()))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if mcp_token.is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if access_key.is_some() || secret_key.is_some() {
        let access_key = access_key
            .filter(|value| !value.is_empty())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let secret_key = secret_key
            .filter(|value| !value.is_empty())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let resolved = state
            .keys
            .resolve_credentials(access_key, secret_key)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "credential storage unavailable");
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        let (user_id, _) = resolved.ok_or(StatusCode::UNAUTHORIZED)?;
        return Ok(PublicKeyMutationActor::ApiKey {
            access_key: access_key.to_string(),
            user_id,
        });
    }

    let token = authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if let Some((access_key, secret_key)) = token.split_once(':') {
        if access_key.is_empty() || secret_key.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let resolved = state
            .keys
            .resolve_credentials(access_key, secret_key)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "credential storage unavailable");
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        let (user_id, _) = resolved.ok_or(StatusCode::UNAUTHORIZED)?;
        return Ok(PublicKeyMutationActor::ApiKey {
            access_key: access_key.to_string(),
            user_id,
        });
    }

    if state.auth_disabled || token.starts_with("s4m_") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    require_user_id(headers, state)
        .await
        .map(PublicKeyMutationActor::DashboardUser)
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn set_public_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SetPublicKeyRequest>,
) -> impl IntoResponse {
    let actor = match authenticate_public_key_mutation(&state, &headers).await {
        Ok(actor) => actor,
        Err(status) => return status.into_response(),
    };
    let uid = match actor {
        PublicKeyMutationActor::ApiKey {
            access_key,
            user_id,
        } => {
            if body.key_id != access_key {
                return (StatusCode::NOT_FOUND, "key not found").into_response();
            }
            user_id
        }
        PublicKeyMutationActor::DashboardUser(user_id) => user_id,
    };
    let public_key_pem = match canonicalize_public_key_pem(&body.public_key_pem) {
        Ok(public_key_pem) => public_key_pem,
        Err(_) => return invalid_credential_mutation_response(),
    };
    match state
        .keys
        .set_public_key(&body.key_id, &uid, &public_key_pem)
        .await
    {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "key not found").into_response(),
        Err(error) => {
            tracing::error!(user_id = uid, error = %error, "public key persistence failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn create_plugin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let name = match customer_headers::aliased(&headers, customer_headers::PLUGIN_NAME) {
        Ok(Some(value)) => match value.to_str() {
            Ok(value) => value.to_string(),
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid plugin name").into_response(),
        },
        Ok(None) => "imported".to_string(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "conflicting plugin name headers").into_response();
        }
    };
    match state.plugins.import(&name, &body) {
        Ok(info) => (StatusCode::CREATED, Json(info)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct PluginUpdate {
    enabled: Option<bool>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct PluginReorder {
    order: Vec<String>,
}

async fn reorder_plugins(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PluginReorder>,
) -> impl IntoResponse {
    state.plugins.reorder(body.order);
    StatusCode::OK.into_response()
}

async fn update_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(update): Json<PluginUpdate>,
) -> impl IntoResponse {
    let found = update
        .enabled
        .is_some_and(|enabled| state.plugins.set_enabled(&id, enabled).is_some())
        || update
            .name
            .is_some_and(|name| state.plugins.set_name(&id, &name).is_some());
    if let Some(info) = state.plugins.get_info(&id) {
        Json(info).into_response()
    } else if found {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "plugin not found").into_response()
    }
}

async fn delete_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.plugins.remove(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "plugin not found").into_response()
    }
}

/// List all objects in the store
#[utoipa::path(
    get,
    path = "/dashboard/api/objects",
    responses((status = 200, description = "Objects", body = Vec<ObjectResponse>)),
    tag = "objects"
)]
async fn list_objects(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let objects: Vec<ObjectResponse> = state
        .store
        .list_keys()
        .into_iter()
        .map(|k| {
            let parts: Vec<&str> = k.splitn(2, '/').collect();
            let bucket = parts[0];
            let obj_key = parts.get(1).unwrap_or(&"");
            let size = state
                .store
                .metadata(bucket, obj_key)
                .map(|(size, _, _)| size)
                .unwrap_or(0);
            ObjectResponse { key: k, size }
        })
        .collect();
    Json(objects)
}

fn component_path() -> anyhow::Result<PathBuf> {
    Ok(resolve_customer_env(customer_env::FILTER_COMPONENT)?
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("..");
            p.push("..");
            p.push("target");
            p.push("components");
            p.push("pii-default.component.wasm");
            p
        }))
}

fn bundled_stable_component() -> anyhow::Result<Option<Vec<u8>>> {
    let directory = match resolve_customer_env(customer_env::PLUGINS_DIR)? {
        Some(directory) => PathBuf::from(directory),
        None => {
            warn!("join demo disabled because MASKURA_PLUGINS_DIR is not configured");
            return Ok(None);
        }
    };
    let path = directory.join("stable-encrypt.component.wasm");
    match std::fs::read(&path) {
        Ok(component) => Ok(Some(component)),
        Err(error) => {
            warn!(
                "join demo disabled because {} is unavailable: {error}",
                path.display()
            );
            Ok(None)
        }
    }
}

fn enabled_env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn explicit_single_tenant_mode(auth_disabled: bool, configured_single_tenant: bool) -> bool {
    auth_disabled || configured_single_tenant
}

fn validate_storage_boundary_startup(
    explicit_single_tenant: bool,
    has_global_s3_endpoint: bool,
    has_service_backends: bool,
) -> anyhow::Result<()> {
    if !explicit_single_tenant && has_global_s3_endpoint {
        anyhow::bail!("S3_ENDPOINT is forbidden in multi-tenant mode");
    }
    if !explicit_single_tenant && !has_service_backends {
        anyhow::bail!("multi-tenant mode requires a non-empty S4_SERVICE_BUCKETS");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct MultipartStartupDependencies {
    durable_wrapping: bool,
    database: bool,
    endpoint: bool,
    bucket: bool,
    access_key: bool,
    secret_key: bool,
    region: bool,
    directory: bool,
    tenant_quota: bool,
    global_quota: bool,
    streaming_all: bool,
}

fn validate_multipart_startup(
    mode: MultipartMode,
    dependencies: MultipartStartupDependencies,
) -> anyhow::Result<()> {
    if mode != MultipartMode::Staged {
        return Ok(());
    }
    let checks = [
        (dependencies.durable_wrapping, "durable key wrapping"),
        (dependencies.database, "DATABASE_URL"),
        (dependencies.endpoint, "S4_MULTIPART_STAGING_ENDPOINT"),
        (dependencies.bucket, "S4_MULTIPART_STAGING_BUCKET"),
        (
            dependencies.access_key,
            "S4_MULTIPART_STAGING_ACCESS_KEY_ID",
        ),
        (
            dependencies.secret_key,
            "S4_MULTIPART_STAGING_SECRET_ACCESS_KEY",
        ),
        (dependencies.region, "S4_MULTIPART_STAGING_REGION"),
        (dependencies.directory, "S4_MULTIPART_STAGING_DIR"),
        (
            dependencies.tenant_quota,
            "S4_MULTIPART_STAGING_TENANT_QUOTA_BYTES",
        ),
        (
            dependencies.global_quota,
            "S4_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES",
        ),
        (
            dependencies.streaming_all,
            "MASKURA_STREAMING_WRITE_MODE=all",
        ),
    ];
    let missing = checks
        .into_iter()
        .filter_map(|(configured, name)| (!configured).then_some(name))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!(
            "staged multipart requires complete durable startup dependencies: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn staged_multipart_startup_requires_every_production_dependency() {
    let complete = MultipartStartupDependencies {
        durable_wrapping: true,
        database: true,
        endpoint: true,
        bucket: true,
        access_key: true,
        secret_key: true,
        region: true,
        directory: true,
        tenant_quota: true,
        global_quota: true,
        streaming_all: true,
    };
    validate_multipart_startup(MultipartMode::Staged, complete).unwrap();
    validate_multipart_startup(
        MultipartMode::Reject,
        MultipartStartupDependencies {
            durable_wrapping: false,
            ..complete
        },
    )
    .unwrap();

    let missing_one: [fn(&mut MultipartStartupDependencies); 11] = [
        |value| value.durable_wrapping = false,
        |value| value.database = false,
        |value| value.endpoint = false,
        |value| value.bucket = false,
        |value| value.access_key = false,
        |value| value.secret_key = false,
        |value| value.region = false,
        |value| value.directory = false,
        |value| value.tenant_quota = false,
        |value| value.global_quota = false,
        |value| value.streaming_all = false,
    ];
    for remove in missing_one {
        let mut incomplete = complete;
        remove(&mut incomplete);
        assert!(validate_multipart_startup(MultipartMode::Staged, incomplete).is_err());
    }
}

fn nonempty_env(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

fn source_body_limits_from_env() -> anyhow::Result<BodyLimits> {
    Ok(BodyLimits {
        max_frame_bytes: resolve_customer_env(customer_env::SOURCE_MAX_FRAME_BYTES)?
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(crate::object::DEFAULT_MAX_SOURCE_FRAME_BYTES),
        max_bytes: resolve_customer_env(customer_env::MAX_OBJECT_BYTES)?
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(crate::object::DEFAULT_MAX_SOURCE_BYTES)
            .min(crate::object::DEFAULT_MAX_SOURCE_BYTES),
    })
}

/// Build the engine state from environment variables, injecting the given
/// control plane and key-wrapping backend. This is the shared construction
/// path for both the OSS self-host binary (`NoopControlPlane` +
/// [`crate::key_cipher::default_wrapping`]) and the private SaaS control
/// plane (KMS/Vault-backed wrapping).
pub async fn build_state(
    control: Arc<dyn ControlPlane>,
    wrapping: Arc<dyn KeyWrapping>,
    workspace_storage: Arc<dyn WorkspaceStorageRepository>,
) -> anyhow::Result<Arc<AppState>> {
    let pipeline_template = StatePipelineTemplate::from_env()?;
    build_state_with_pipeline_template(control, wrapping, workspace_storage, &pipeline_template)
        .await
}

/// Build isolated state from startup artifacts that have already compiled the
/// configured Wasm components.
#[doc(hidden)]
pub async fn build_state_with_pipeline_template(
    control: Arc<dyn ControlPlane>,
    wrapping: Arc<dyn KeyWrapping>,
    workspace_storage: Arc<dyn WorkspaceStorageRepository>,
    pipeline_template: &StatePipelineTemplate,
) -> anyhow::Result<Arc<AppState>> {
    maskura_customer_config::validate(customer_env::GATEWAY_CUSTOMER_SETTINGS)?;
    let s3_endpoint = std::env::var("S3_ENDPOINT").ok();
    let auth_disabled = enabled_env_flag("AUTH_DISABLED");
    let explicit_single_tenant = explicit_single_tenant_mode(
        auth_disabled,
        resolve_customer_env(customer_env::SINGLE_TENANT)?
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true")),
    );
    let service_backends = std::env::var("S4_SERVICE_BUCKETS")
        .ok()
        .map(|value| parse_service_backends(&value))
        .transpose()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_default();
    validate_storage_boundary_startup(
        explicit_single_tenant,
        s3_endpoint.is_some(),
        !service_backends.is_empty(),
    )?;
    let workspace_endpoint_policy =
        WorkspaceEndpointPolicy::from_env(explicit_single_tenant).map_err(anyhow::Error::msg)?;

    let source_body_limits = source_body_limits_from_env()?;
    let max_pipeline_output_bytes = pipeline_template.max_pipeline_output_bytes;
    let (gateway, plugins, demo_pipelines) = pipeline_template.instantiate()?;

    // Envelope encryption for API key secrets (needed to verify SigV4).
    // The wrapping backend is injected by the caller so the engine stays
    // policy-free: OSS uses `default_wrapping()`, SaaS injects KMS/Vault.
    let cipher = Arc::new(SecretCipher::new(wrapping.clone()));

    let s3_client = match &s3_endpoint {
        Some(endpoint) => {
            let access_key = std::env::var("S3_ACCESS_KEY_ID")
                .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
                .ok();
            let secret_key = std::env::var("S3_SECRET_ACCESS_KEY")
                .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
                .ok();
            let region = std::env::var("S3_REGION")
                .or_else(|_| std::env::var("AWS_REGION"))
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .unwrap_or_else(|_| "us-east-1".to_string());
            match (access_key, secret_key) {
                (Some(ak), Some(sk)) => {
                    let creds = Credentials::new(ak, sk, None, None, "env");
                    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                        .region(Region::new(region))
                        .endpoint_url(endpoint)
                        .credentials_provider(creds)
                        .retry_config(s3_retry_config())
                        .timeout_config(s3_timeout_config())
                        .load()
                        .await;
                    let s3_config = aws_sdk_s3::config::Builder::from(&config)
                        .force_path_style(true)
                        .build();
                    Some(Client::from_conf(s3_config))
                }
                _ => {
                    warn!(
                        "S3_ENDPOINT is set but S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY are missing; falling back to in-memory storage"
                    );
                    None
                }
            }
        }
        None => None,
    };

    let supabase_url =
        std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:54321".to_string());
    let supabase_jwt_secret = std::env::var("SUPABASE_JWT_SECRET").ok();

    let jwt_decoder = supabase_jwt_secret
        .map(|secret| Arc::new(jsonwebtoken::DecodingKey::from_secret(secret.as_bytes())));

    let managed_mode_value = std::env::var("S4_MANAGED_STREAMING_MODE").ok();
    let managed_mode = ManagedStreamingMode::from_value(managed_mode_value.as_deref())?;
    let managed_placement_version = std::env::var("S4_MANAGED_PLACEMENT_VERSION")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(PLACEMENT_VERSION_V1);
    let multipart_mode = multipart_mode()?;
    let multipart_tenant_quota_bytes = std::env::var("S4_MULTIPART_STAGING_TENANT_QUOTA_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            source_body_limits
                .max_bytes
                .saturating_mul(MAX_ACTIVE_UPLOADS as u64)
        });
    let multipart_global_quota_bytes = std::env::var("S4_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| multipart_tenant_quota_bytes.saturating_mul(4));
    let multipart_quotas = (multipart_mode == MultipartMode::Staged)
        .then(|| {
            StagingQuotaLimits::new(multipart_tenant_quota_bytes, multipart_global_quota_bytes)
                .map_err(|_| {
                    anyhow::anyhow!("invalid multipart staging tenant/global quota configuration")
                })
        })
        .transpose()?;
    let streaming_write_mode = streaming_write_mode()?;
    validate_multipart_startup(
        multipart_mode,
        MultipartStartupDependencies {
            durable_wrapping: wrapping.is_durable(),
            database: nonempty_env("DATABASE_URL"),
            endpoint: nonempty_env("S4_MULTIPART_STAGING_ENDPOINT"),
            bucket: nonempty_env("S4_MULTIPART_STAGING_BUCKET"),
            access_key: nonempty_env("S4_MULTIPART_STAGING_ACCESS_KEY_ID"),
            secret_key: nonempty_env("S4_MULTIPART_STAGING_SECRET_ACCESS_KEY"),
            region: nonempty_env("S4_MULTIPART_STAGING_REGION"),
            directory: nonempty_env("S4_MULTIPART_STAGING_DIR"),
            tenant_quota: nonempty_env("S4_MULTIPART_STAGING_TENANT_QUOTA_BYTES"),
            global_quota: nonempty_env("S4_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES"),
            streaming_all: streaming_write_mode >= StreamingWriteMode::All,
        },
    )?;
    let s3_streaming_capabilities = configured_s3_streaming_capabilities()?;
    let managed_streaming_capabilities = configured_managed_streaming_capabilities();
    let spool_max_object_bytes = resolve_customer_env(customer_env::SPOOL_MAX_OBJECT_BYTES)?
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(source_body_limits.max_bytes)
        .min(source_body_limits.max_bytes);
    let spool_quota_bytes = resolve_customer_env(customer_env::SPOOL_QUOTA_BYTES)?
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= spool_max_object_bytes)
        .unwrap_or(spool_max_object_bytes.saturating_mul(2));
    let spool_config = CompatibilitySpoolConfig {
        directory: resolve_customer_env(customer_env::SPOOL_DIR)?
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("s4-spool")),
        max_object_bytes: spool_max_object_bytes,
        stale_after: Duration::from_secs(24 * 60 * 60),
    };
    let removed_spools = CompatibilitySpoolTransaction::cleanup_stale(&spool_config).await?;
    if removed_spools > 0 {
        info!(removed_spools, "removed stale spool files");
    }
    schedule_spool_cleanup(spool_config.clone());
    let spool_quota = Arc::new(SpoolQuota::new(spool_quota_bytes));
    let dev_memory_max_object_bytes =
        resolve_customer_env(customer_env::DEV_MEMORY_MAX_OBJECT_BYTES)?
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(LEGACY_MAX_OBJECT_BYTES)
            .min(64 * 1024 * 1024);
    let dev_memory_streaming_enabled = explicit_single_tenant
        || resolve_customer_env(customer_env::DEV_MEMORY_STREAMING)?
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));

    // API key persistence: Postgres (Supabase) when DATABASE_URL is set,
    // a JSON file when MASKURA_KEYS_FILE (or its legacy alias) is set, a default JSON file in local
    // mode (AUTH_DISABLED=true), and otherwise the in-memory KeyStore.
    let mut operation_journal: Option<Arc<dyn OperationJournal>> = None;
    let mut postgres_pool = None;
    let keys: Arc<dyn KeyRepository> = if let Ok(database_url) = std::env::var("DATABASE_URL") {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        crate::run_engine_migrations(&pool)
            .await
            .expect("failed to run migrations");
        info!("Key store: Postgres (migrations applied)");
        operation_journal = Some(Arc::new(crate::transaction::PostgresOperationJournal::new(
            pool.clone(),
        )));
        postgres_pool = Some(pool.clone());
        Arc::new(PostgresKeyStore::with_cipher(pool, cipher.clone()))
    } else if let Some(keys_file) = resolve_customer_env(customer_env::KEYS_FILE)? {
        info!("Key store: file ({keys_file})");
        Arc::new(FileKeyStore::with_cipher(
            PathBuf::from(keys_file),
            cipher.clone(),
        )?)
    } else if auth_disabled {
        let path = FileKeyStore::default_path();
        info!("Key store: file ({}) (local mode)", path.display());
        Arc::new(FileKeyStore::with_cipher(path, cipher)?)
    } else {
        info!("Key store: in-memory (set DATABASE_URL or MASKURA_KEYS_FILE for persistence)");
        Arc::new(KeyStore::with_cipher(cipher))
    };
    #[cfg(debug_assertions)]
    if operation_journal.is_none() && auth_disabled {
        info!(
            "Operation journal: in-memory (dev local mode; streaming S3 PUT uses a non-durable journal)"
        );
        operation_journal = Some(Arc::new(crate::transaction::InMemoryOperationJournal::new()));
    }
    let managed_repository: Arc<dyn ManagedRepository> = if let Some(pool) = postgres_pool.clone() {
        Arc::new(PostgresManagedRepository::new(pool))
    } else {
        Arc::new(InMemoryManagedRepository::new())
    };
    let multipart_staging = if multipart_mode == MultipartMode::Staged && wrapping.is_durable() {
        if let Some(pool) = postgres_pool.clone() {
            let endpoint = std::env::var("S4_MULTIPART_STAGING_ENDPOINT").ok();
            let bucket = std::env::var("S4_MULTIPART_STAGING_BUCKET").ok();
            let access_key = std::env::var("S4_MULTIPART_STAGING_ACCESS_KEY_ID").ok();
            let secret_key = std::env::var("S4_MULTIPART_STAGING_SECRET_ACCESS_KEY").ok();
            match (endpoint, bucket, access_key, secret_key) {
                (Some(endpoint), Some(bucket), Some(access_key), Some(secret_key)) => {
                    let region = std::env::var("S4_MULTIPART_STAGING_REGION")
                        .unwrap_or_else(|_| "us-east-1".to_string());
                    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                        .region(Region::new(region))
                        .endpoint_url(endpoint)
                        .credentials_provider(Credentials::new(
                            access_key,
                            secret_key,
                            None,
                            None,
                            "multipart-staging",
                        ))
                        .retry_config(s3_retry_config())
                        .timeout_config(s3_timeout_config())
                        .load()
                        .await;
                    Some(Arc::new(MultipartStaging {
                        repository: Arc::new(PostgresMultipartRepository::with_quotas(
                            pool,
                            multipart_quotas.expect("staged multipart has validated quotas"),
                        )),
                        artifacts: Arc::new(S3StagingArtifactStore::new(
                            Client::new(&config),
                            bucket,
                        )),
                        directory: std::env::var("S4_MULTIPART_STAGING_DIR")
                            .map(PathBuf::from)
                            .unwrap_or_else(|_| spool_config.directory.join("multipart")),
                        wrapping: wrapping.clone(),
                    }))
                }
                _ => {
                    warn!(
                        "staged multipart requested without a complete Maskura-controlled staging backend; transformed multipart remains rejected"
                    );
                    None
                }
            }
        } else {
            warn!(
                "staged multipart requested without DATABASE_URL; transformed multipart remains rejected"
            );
            None
        }
    } else if multipart_mode == MultipartMode::Staged {
        warn!(
            "staged multipart requested with ephemeral key wrapping; transformed multipart remains rejected"
        );
        None
    } else {
        None
    };
    if let Some(staging) = &multipart_staging {
        let removed = EncryptedPartWriter::cleanup_stale(
            &staging.directory,
            Duration::from_secs(24 * 60 * 60),
        )
        .await?;
        if removed > 0 {
            info!(removed, "removed orphaned encrypted multipart spool files");
        }
        reconcile_staged_artifacts(staging).await?;
    }
    validate_mode(
        managed_mode,
        managed_repository.as_ref(),
        auth_disabled || cfg!(debug_assertions),
    )
    .await?;
    if managed_mode != ManagedStreamingMode::Off && managed_streaming_capabilities.is_none() {
        anyhow::bail!(
            "managed observe/enforce mode requires S4_MANAGED_STREAMING_TRANSACTIONAL=true"
        );
    }
    let service_storage = Arc::new(
        ServiceStorage::with_management(
            service_backends,
            managed_repository,
            managed_mode,
            managed_placement_version,
        )
        .with_managed_capabilities(managed_streaming_capabilities),
    );
    if multipart_staging.is_some() && managed_mode != ManagedStreamingMode::Off {
        service_storage
            .reconcile_managed_multipart_activities(256)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    }
    if managed_mode == ManagedStreamingMode::Enforce
        && let (Some(journal), Some(capabilities)) =
            (operation_journal.clone(), managed_streaming_capabilities)
    {
        service_storage
            .reconcile_managed_write_intents(
                journal,
                capabilities,
                Duration::from_millis(crate::managed::PHYSICAL_WRITE_LEASE_MS as u64),
                256,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    }

    // Local mode: ensure a demo key exists and print it so SDK demos and
    // `aws s3 --endpoint-url` work out of the box.
    if auth_disabled {
        let existing = keys.list_for_user("demo-user").await?;
        if existing.is_empty() {
            let (secret, created) = keys
                .create_key("demo-user", "local-default", 0, None)
                .await?;
            println!("MASKURA_ACCESS_KEY={}", created.key_id);
            println!("MASKURA_SECRET_KEY={secret}");
        } else if let Some(k) = existing.into_iter().find(|k| k.label == "local-default")
            && let Some(secret) = keys.decrypt_secret(&k.key_id).await?
        {
            println!("MASKURA_ACCESS_KEY={}", k.key_id);
            println!("MASKURA_SECRET_KEY={secret}");
        }
    }

    let mut continuation_token_key = [0; 32];
    OsRng.fill_bytes(&mut continuation_token_key);
    let state = Arc::new(AppState {
        gateway: Arc::new(gateway),
        store: Arc::new(MemoryStore::new()),
        keys,
        workspace_storage,
        plugins,
        service_storage,
        s3_client,
        supabase_url,
        jwt_decoder,
        auth_disabled,
        explicit_single_tenant,
        workspace_endpoint_policy,
        control,
        legacy_max_object_bytes: legacy_max_object_bytes()?,
        streaming_read_mode: StreamingReadMode::from_env()?,
        streaming_write_mode,
        source_body_limits,
        max_pipeline_output_bytes,
        presigned_http_policy: PresignedHttpPolicy::from_env().map_err(anyhow::Error::msg)?,
        sigv4_cache: Arc::new(SigningKeyCache::standard()),
        sigv4_policy: SigV4Policy::from_env(),
        operation_journal,
        s3_streaming_capabilities,
        managed_streaming_capabilities,
        spool_config,
        spool_quota,
        transformed_read_spool_enabled: transformed_read_spool_enabled()?,
        binary_avro_enabled: binary_avro_enabled()?,
        dev_memory_max_object_bytes,
        dev_memory_streaming_enabled,
        demo_pipelines,
        demo_limiter: Arc::new(DemoLimiter::new()),
        multipart_staging,
        multipart_mode,
        continuation_token_key,
    });
    if managed_mode != ManagedStreamingMode::Off
        && let (Some(journal), Some(capabilities)) = (
            state.operation_journal.clone(),
            state.managed_streaming_capabilities,
        )
    {
        let storage = state.service_storage.clone();
        tokio::spawn(async move {
            let owner = format!("managed-repair-{}", uuid::Uuid::now_v7());
            loop {
                if let Err(error) = storage
                    .reconcile_managed_write_intents(
                        journal.clone(),
                        capabilities,
                        Duration::from_millis(crate::managed::PHYSICAL_WRITE_LEASE_MS as u64),
                        64,
                    )
                    .await
                {
                    warn!("managed write-intent reconciliation failed: {error}");
                }
                if let Err(error) = storage
                    .repair_due(journal.clone(), capabilities, &owner, 16)
                    .await
                {
                    warn!("managed repair worker failed: {error}");
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    }
    if let Some(staging) = state.multipart_staging.clone() {
        let storage = state.service_storage.clone();
        tokio::spawn(async move {
            loop {
                match staging.repository.reap_expired(now_ms(), 64).await {
                    Ok(parts) if !parts.is_empty() => {
                        let upload_ids: HashSet<_> =
                            parts.iter().map(|part| part.upload_id.clone()).collect();
                        for upload_id in upload_ids {
                            let selected: Vec<_> = parts
                                .iter()
                                .filter(|part| part.upload_id == upload_id)
                                .cloned()
                                .collect();
                            cleanup_staged_parts(&staging, &upload_id, selected, "expiry_reap")
                                .await;
                        }
                    }
                    Ok(_) => {}
                    Err(error) => warn!("multipart expiry reconciliation failed: {error}"),
                }
                if let Err(error) = reconcile_staged_artifacts(&staging).await {
                    warn!("multipart artifact reconciliation failed: {error}");
                }
                match staging
                    .repository
                    .retire_terminal_uploads(now_ms(), 64)
                    .await
                {
                    Ok(retired) => {
                        for upload in retired {
                            if let Some(epoch) = upload.namespace_epoch {
                                let _ = storage
                                    .finish_managed_multipart(
                                        &upload.upload_id,
                                        &upload.tenant_id,
                                        epoch,
                                    )
                                    .await;
                            }
                        }
                    }
                    Err(error) => warn!("multipart terminal retirement failed: {error}"),
                }
                if storage.managed_mode() != ManagedStreamingMode::Off
                    && let Err(error) = storage.reconcile_managed_multipart_activities(64).await
                {
                    warn!("managed multipart registration reconciliation failed: {error}");
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }
    Ok(state)
}

/// Build the axum router for the engine. The SaaS crate merges its own
/// control-plane routes (workspaces, billing, dashboard) onto this.
pub fn build_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/", get(root))
        .route("/dashboard/api/keys", get(get_keys))
        .route(
            "/dashboard/api/keys",
            post(create_key).layer(DefaultBodyLimit::max(CREATE_KEY_BODY_BYTES)),
        )
        .route(
            "/dashboard/api/keys",
            delete(delete_key).layer(DefaultBodyLimit::max(SIMPLE_CREDENTIAL_MUTATION_BODY_BYTES)),
        )
        .route(
            "/dashboard/api/keys/public-key",
            put(set_public_key).layer(DefaultBodyLimit::max(SET_PUBLIC_KEY_BODY_BYTES)),
        )
        .route("/dashboard/api/mcp-tokens", get(get_mcp_tokens))
        .route(
            "/dashboard/api/mcp-tokens",
            post(create_mcp_token)
                .layer(DefaultBodyLimit::max(SIMPLE_CREDENTIAL_MUTATION_BODY_BYTES)),
        )
        .route(
            "/dashboard/api/mcp-tokens",
            delete(delete_mcp_token)
                .layer(DefaultBodyLimit::max(SIMPLE_CREDENTIAL_MUTATION_BODY_BYTES)),
        )
        .route("/dashboard/api/me", get(get_me))
        .route("/dashboard/api/demo/redact", post(demo_redact))
        .route("/dashboard/api/demo/process", post(demo_process))
        .route("/dashboard/api/backend", get(get_backend))
        .route("/dashboard/api/backend", put(put_backend))
        .route("/{bucket}", get(s3_list_objects))
        .route("/{bucket}", put(s3_bucket_put))
        .route("/{bucket}", delete(s3_bucket_delete))
        .route("/{bucket}/{*key}", put(s3_put))
        .route("/{bucket}/{*key}", get(s3_get))
        .route("/{bucket}/{*key}", head(s3_head))
        .route("/{bucket}/{*key}", delete(s3_delete))
        .route("/{bucket}/{*key}", post(s3_post));
    if state.auth_disabled {
        router = router
            .route("/dashboard/api/plugins", get(get_plugins))
            .route("/dashboard/api/plugins", post(create_plugin))
            .route("/dashboard/api/plugins/reorder", put(reorder_plugins))
            .route("/dashboard/api/plugins/{id}", put(update_plugin))
            .route("/dashboard/api/plugins/{id}", delete(delete_plugin))
            .route("/dashboard/api/objects", get(list_objects));
    }
    let router = router.layer(CorsLayer::permissive());
    router
        // Remove at the next major release. Registration after CORS lets OPTIONS return 410.
        .route("/dashboard/api/demo/store", any(legacy_demo_gone))
        .route("/dashboard/api/demo/read", any(legacy_demo_gone))
        .with_state(state)
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
}

#[cfg(test)]
mod auth_tests {
    use super::supabase_jwt_validation;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, decode, encode};

    #[test]
    fn accepts_supabase_authenticated_audience() {
        let secret = b"test-secret";
        let issuer = "https://example.supabase.co/auth/v1";
        let claims = serde_json::json!({
            "sub": "user-123",
            "iss": issuer,
            "aud": "authenticated",
            "exp": u64::MAX,
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("encode token");
        let validation = supabase_jwt_validation(Algorithm::HS256, issuer);

        let decoded =
            decode::<serde_json::Value>(&token, &DecodingKey::from_secret(secret), &validation)
                .expect("valid Supabase token");

        assert_eq!(decoded.claims["sub"], "user-123");
    }
}

#[cfg(test)]
mod demo_limiter_tests {
    use std::path::Path;
    use std::time::Duration;

    use super::{ApiDoc, DemoLimitError, DemoLimiter, build_demo_pipelines};
    use utoipa::OpenApi;

    #[test]
    fn rejects_a_fifth_concurrent_operation_without_counting_it_as_a_start() {
        let limiter = DemoLimiter::with_limits(4, 5, Duration::from_secs(60));
        let permits: Vec<_> = (0..4)
            .map(|_| limiter.try_start().expect("first four operations start"))
            .collect();
        assert!(matches!(
            limiter.try_start(),
            Err(DemoLimitError::Concurrent)
        ));

        drop(permits);
        assert!(limiter.try_start().is_ok());
    }

    #[test]
    fn rejects_more_than_thirty_starts_in_the_window() {
        let limiter = DemoLimiter::with_limits(4, 30, Duration::from_secs(60));
        for _ in 0..30 {
            drop(limiter.try_start().expect("operation starts within limit"));
        }
        assert!(matches!(limiter.try_start(), Err(DemoLimitError::Rate)));
    }

    #[test]
    fn dedicated_demo_snapshots_are_ordered_and_join_fails_closed() {
        let components = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/components");
        let pii = std::fs::read(components.join("pii-default.component.wasm"))
            .expect("pii-default.component.wasm; run just build-filters");
        let stable = std::fs::read(components.join("stable-encrypt.component.wasm"))
            .expect("stable-encrypt.component.wasm; run just build-filters");

        let unavailable = build_demo_pipelines(&pii, None, 1_000_000_000).unwrap();
        assert!(unavailable.join.is_none());
        assert_eq!(
            unavailable
                .safe
                .plugin_infos()
                .into_iter()
                .map(|plugin| plugin.name)
                .collect::<Vec<_>>(),
            ["pii-default"]
        );

        let malformed = build_demo_pipelines(&pii, Some(b"not a component"), 1_000_000_000)
            .expect("safe demo remains available when stable-encrypt is malformed");
        assert!(malformed.join.is_none());

        let available = build_demo_pipelines(&pii, Some(&stable), 1_000_000_000).unwrap();
        assert_eq!(
            available
                .join
                .expect("valid bundled stable component enables join")
                .plugin_infos()
                .into_iter()
                .map(|plugin| plugin.name)
                .collect::<Vec<_>>(),
            ["stable-encrypt", "pii-default"]
        );
    }

    #[test]
    fn stateless_demo_process_is_not_published_in_openapi() {
        let document = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert_eq!(document["info"]["title"], "Maskura Gateway API");
        assert!(
            document["paths"]
                .get("/dashboard/api/demo/process")
                .is_none()
        );
        for schema in [
            "DemoMode",
            "DemoProcessRequest",
            "DemoProcessedRecord",
            "DemoProcessResponse",
            "DemoErrorResponse",
        ] {
            assert!(document["components"]["schemas"].get(schema).is_none());
        }
    }
}

#[cfg(test)]
mod multipart_completion_tests {
    use super::parse_complete_multipart_xml;

    #[test]
    fn complete_xml_is_strict_ordered_and_entity_free() {
        let parts = parse_complete_multipart_xml(
            br#"<?xml version="1.0"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"one"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"two"</ETag><ChecksumSHA256>abc</ChecksumSHA256></Part></CompleteMultipartUpload>"#,
        )
        .unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].checksum_sha256.as_deref(), Some("abc"));
        assert!(parse_complete_multipart_xml(
            br#"<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>"two"</ETag></Part><Part><PartNumber>1</PartNumber><ETag>"one"</ETag></Part></CompleteMultipartUpload>"#,
        )
        .is_err());
        assert!(parse_complete_multipart_xml(
            br#"<!DOCTYPE x [<!ENTITY boom "boom">]><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>&boom;</ETag></Part></CompleteMultipartUpload>"#,
        )
        .is_err());
    }

    #[test]
    fn complete_xml_accepts_quoted_hex_etags() {
        let parts = parse_complete_multipart_xml(
            br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"c56e589acfa9d79113ff4c36f72d0228"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"cde8de78ea9269548adfcd9f7505ae9b"</ETag></Part></CompleteMultipartUpload>"#,
        )
        .expect("two-part complete XML with quoted hex ETags must parse");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].etag, "\"c56e589acfa9d79113ff4c36f72d0228\"");
    }
}

#[cfg(test)]
mod s3_provider_capability_tests {
    use super::configured_s3_streaming_capabilities;

    #[test]
    fn provider_selection_is_exact_and_fail_closed() {
        for provider in ["aws", "minio", "r2", "b2"] {
            unsafe { std::env::set_var("S4_STREAMING_S3_PROVIDER", provider) }
            let capabilities = configured_s3_streaming_capabilities().unwrap();
            assert!(
                capabilities.is_some(),
                "provider {provider} must enable direct S3 streaming"
            );
            let capabilities = capabilities.expect("capabilities present");
            assert!(capabilities.supports_conditional_reads());
            assert!(capabilities.supports_response_checksums());
        }
        unsafe { std::env::set_var("S4_STREAMING_S3_PROVIDER", "wasabi") }
        assert!(configured_s3_streaming_capabilities().unwrap().is_none());
        unsafe { std::env::remove_var("S4_STREAMING_S3_PROVIDER") }
        assert!(configured_s3_streaming_capabilities().unwrap().is_none());
    }
}
