//! Composable engine server: axum handlers + router + state construction.
//!
//! The engine is policy-free. Authorization (rate limits, quotas, billing)
//! and metering are injected through [`crate::control::ControlPlane`], held
//! in [`AppState`]. The OSS self-host binary builds this with
//! [`crate::control::NoopControlPlane`]; the private SaaS crate builds it with
//! its own control-plane implementation.

use std::collections::{HashSet, VecDeque};
use std::path::{Path as FsPath, PathBuf};
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
    BackendResolver, PresignedHttpPolicy, ResolvedBackend, StorageOperation,
    WorkspaceEndpointPolicy,
};
use crate::control::{
    AuthenticatedRequestContext, ControlPlane, MeteringError, RequestKind, StreamingWriteMode,
    UsageEvent, UsageRoute,
};
use crate::integrity::{BodyVerifier, IntegrityError};
use crate::key_cipher::{KeyWrapping, SecretCipher};
use crate::managed::{
    InMemoryManagedRepository, LogicalObjectKey, ManagedRepository, ManagedStreamingMode,
    PLACEMENT_VERSION_V1, PostgresManagedRepository, validate_mode,
};
use crate::multipart_staging::{
    ARTIFACT_PREFIX, COMPLETION_LEASE, CleanupAudit, CompletePart, CompletionAcquire,
    CompletionLease, EncryptedPartReader, EncryptedPartWriter, MAX_ACTIVE_UPLOADS,
    MultipartCompletionResult, MultipartIdentity, MultipartLifecycle, MultipartPart,
    MultipartRepository, MultipartSnapshot, MultipartUpload, PostgresMultipartRepository,
    S3StagingArtifactStore, StagedArtifact, StagingArtifactStore, StagingError, StagingQuotaLimits,
    completion_fingerprint, now_ms,
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
    AbortSignal, AwsS3TransactionBackend, BackendCapabilities, CompatibilitySpoolConfig,
    CompatibilitySpoolTransaction, CompatibilitySpoolUploader, CompletionReconciliation,
    ConditionalReadCapability, DirectS3Sink, ExpectedObject, IncompleteUploadDiscovery,
    ListCapability, MemorySinkTransaction, MultipartResponseCapability, ObjectDestination,
    ObjectSinkTransaction, OperationJournal, OperationReconciler, ResponseChecksumCapability,
    SpoolQuota, StoredObjectMeta, TransactionError, VersioningCapability,
};
use crate::workspace_storage::{
    BackendConfigRequest, BackendConfigResponse, BackendType, WorkspaceId, WorkspaceStorageError,
    WorkspaceStorageRepository,
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
enum MeteringIdError {
    Duplicate,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OperationIdentity {
    receipt_id: Uuid,
    operation_id: Uuid,
}

struct OperationUsage<'a> {
    operation: OperationIdentity,
    bucket: &'a str,
    kind: RequestKind,
    route: UsageRoute,
    source_bytes: u64,
    output_bytes: u64,
}

impl OperationUsage<'_> {
    fn event(&self) -> UsageEvent {
        UsageEvent::new(
            self.operation.receipt_id,
            self.operation.operation_id,
            self.bucket,
            self.kind,
            self.route,
            self.source_bytes,
            self.output_bytes,
        )
    }
}

fn parse_metering_id(headers: &HeaderMap) -> Result<Option<Uuid>, MeteringIdError> {
    let mut values = headers.get_all("x-s4-metering-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(MeteringIdError::Duplicate);
    }
    let value = value.to_str().map_err(|_| MeteringIdError::Invalid)?;
    Uuid::parse_str(value)
        .map(Some)
        .map_err(|_| MeteringIdError::Invalid)
}

fn operation_id_for_receipt(receipt_id: Uuid) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_X500, receipt_id.as_bytes())
}

fn request_operation_identity(headers: &HeaderMap) -> Result<OperationIdentity, MeteringIdError> {
    let receipt_id = parse_metering_id(headers)?.unwrap_or_else(Uuid::now_v7);
    Ok(OperationIdentity {
        receipt_id,
        operation_id: operation_id_for_receipt(receipt_id),
    })
}

fn multipart_completion_operation_identity(upload_id: &str) -> OperationIdentity {
    OperationIdentity {
        receipt_id: Uuid::new_v5(&Uuid::NAMESPACE_OID, upload_id.as_bytes()),
        operation_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, upload_id.as_bytes()),
    }
}

fn metering_id_error_response(key: &str, error: MeteringIdError) -> axum::response::Response {
    let detail = match error {
        MeteringIdError::Duplicate => "x-s4-metering-id must appear exactly once",
        MeteringIdError::Invalid => "x-s4-metering-id must be a valid UUID",
    };
    s3_error::invalid_request(key, detail)
}

fn metering_error_response(key: &str, error: MeteringError) -> axum::response::Response {
    match error {
        MeteringError::Unavailable => s3_error::service_unavailable(
            key,
            "Usage metering is temporarily unavailable; retry with the same x-s4-metering-id.",
        ),
        MeteringError::IdempotencyConflict => s3_error::invalid_request(
            key,
            "The x-s4-metering-id conflicts with an existing usage event.",
        ),
        MeteringError::Rejected => s3_error::payment_required(key, "The usage event was rejected."),
    }
}

async fn record_usage(
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    event: &UsageEvent,
    key: &str,
) -> Result<(), axum::response::Response> {
    control.record(context, event).await.map_err(|error| {
        warn!(event_id = %event.id, ?error, "usage event was not recorded");
        metering_error_response(key, error)
    })
}

async fn record_operation(
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    usage: OperationUsage<'_>,
    key: &str,
) -> Result<(), axum::response::Response> {
    let event = usage.event();
    record_usage(control, context, &event, key).await
}

fn admitted_response_bytes(response: &axum::response::Response) -> Option<u64> {
    if matches!(
        response.status(),
        StatusCode::NOT_MODIFIED | StatusCode::PRECONDITION_FAILED
    ) {
        return Some(0);
    }
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
async fn metered_read_response(
    control: Arc<dyn ControlPlane>,
    auth: &Auth,
    operation: OperationIdentity,
    bucket: &str,
    key: &str,
    source_bytes: Option<u64>,
    response: axum::response::Response,
) -> axum::response::Response {
    if !response.status().is_success() && response.status() != StatusCode::NOT_MODIFIED {
        return response;
    }
    let Some(bytes) = admitted_response_bytes(&response) else {
        return s3_error::service_unavailable(
            key,
            "The response size is unavailable for usage metering.",
        );
    };
    let event = UsageEvent::new(
        operation.receipt_id,
        operation.operation_id,
        bucket,
        RequestKind::Read,
        UsageRoute::GetObject,
        source_bytes.unwrap_or(bytes),
        bytes,
    );
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

fn build_demo_pipelines(
    pii_component: &[u8],
    stable_component: Option<&[u8]>,
    engine_fuel: u64,
) -> anyhow::Result<DemoPipelines> {
    let registry = PluginRegistry::with_fuel(engine_fuel);
    let pii = registry.import("pii-default", pii_component)?;
    let safe = registry.snapshot().constrained(demo_pipeline_limits())?;
    let join = stable_component.and_then(|component| {
        let stable = match registry.import("stable-encrypt", component) {
            Ok(stable) => stable,
            Err(error) => {
                warn!("stable-encrypt unavailable for the stateless demo: {error}");
                return None;
            }
        };
        registry.reorder(vec![stable.id, pii.id.clone()]);
        match registry.snapshot().constrained(demo_pipeline_limits()) {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                warn!("join demo pipeline constraints are invalid: {error}");
                None
            }
        }
    });
    Ok(DemoPipelines { safe, join })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamingReadMode {
    #[default]
    Off,
    Passthrough,
    Transformed,
}

impl StreamingReadMode {
    fn from_env() -> Self {
        match std::env::var("S4_STREAMING_READ_MODE").as_deref() {
            Ok("passthrough") => Self::Passthrough,
            Ok("transformed") => Self::Transformed,
            Ok("off") | Err(_) => Self::Off,
            Ok(value) => {
                warn!("invalid S4_STREAMING_READ_MODE={value:?}; using off");
                Self::Off
            }
        }
    }

    fn streams_passthrough(self) -> bool {
        matches!(self, Self::Passthrough | Self::Transformed)
    }
}

fn transformed_read_spool_enabled() -> bool {
    std::env::var("S4_TRANSFORMED_READ_SPOOL")
        .is_ok_and(|value| value.eq_ignore_ascii_case("encrypted"))
}

/// Imported plugins are unsafe by default. Operators may opt known component
/// digests into direct reads at process start; dashboard callers cannot raise
/// this capability and a digest cannot be re-registered with different flags.
fn prefix_safe_component_hashes() -> HashSet<String> {
    std::env::var("S4_PREFIX_SAFE_COMPONENT_HASHES")
        .ok()
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
                warn!("ignoring invalid S4_PREFIX_SAFE_COMPONENT_HASHES entry");
                None
            } else {
                Some(hash.to_ascii_lowercase())
            }
        })
        .collect()
}

fn streaming_write_mode() -> StreamingWriteMode {
    match std::env::var("S4_STREAMING_WRITE_MODE").as_deref() {
        Ok("single") => StreamingWriteMode::Single,
        Ok("all") => StreamingWriteMode::All,
        Ok("off") | Err(_) => StreamingWriteMode::Off,
        Ok(value) => {
            warn!("invalid S4_STREAMING_WRITE_MODE={value:?}; using off");
            StreamingWriteMode::Off
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MultipartMode {
    #[default]
    Reject,
    Staged,
}

fn multipart_mode() -> MultipartMode {
    match std::env::var("S4_MULTIPART_MODE").as_deref() {
        Ok("staged") => MultipartMode::Staged,
        Ok("reject") | Err(_) => MultipartMode::Reject,
        Ok(value) => {
            warn!("invalid S4_MULTIPART_MODE={value:?}; using reject");
            MultipartMode::Reject
        }
    }
}

fn configured_s3_streaming_capabilities() -> Option<BackendCapabilities> {
    let provider = std::env::var("S4_STREAMING_S3_PROVIDER").ok()?;
    if !matches!(provider.as_str(), "aws" | "minio" | "r2" | "b2") {
        warn!("unknown S4_STREAMING_S3_PROVIDER={provider:?}; direct streaming disabled");
        return None;
    }
    Some(BackendCapabilities {
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

fn legacy_max_object_bytes() -> usize {
    let configured = match std::env::var("S4_LEGACY_MAX_OBJECT_BYTES") {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => {
                warn!(
                    "invalid S4_LEGACY_MAX_OBJECT_BYTES={raw:?}; using {LEGACY_MAX_OBJECT_BYTES}"
                );
                LEGACY_MAX_OBJECT_BYTES
            }
        },
        Err(_) => LEGACY_MAX_OBJECT_BYTES,
    };
    let bounded = configured.min(LEGACY_MAX_OBJECT_BYTES);
    if bounded != configured {
        warn!(
            "S4_LEGACY_MAX_OBJECT_BYTES={configured} exceeds the immutable 16 MiB limit; using {bounded}"
        );
    }
    bounded
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
        title = "S4 Gateway API",
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
    // x-s4-mcp-token header: MCP bearer token.
    if let Some(tok) = headers.get("x-s4-mcp-token").and_then(|v| v.to_str().ok()) {
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
    let ak = headers
        .get("x-s4-access-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sk = headers
        .get("x-s4-secret-key")
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
    let trailing = pipeline.finish().await?;
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
        canonical_records.push(crate::record::Record::new(canonical, bytes::Bytes::new()));
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
        format: Format::Json.as_str().to_string(),
        content_type: "application/json".to_string(),
        policy_version: 0,
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
        if !record.separator.is_empty() {
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
    headers
        .get("x-s4-process")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("read") || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

struct PresignedSpoolUploader {
    client: reqwest::Client,
    url: reqwest::Url,
    max_attempts: usize,
}

#[async_trait::async_trait]
impl CompatibilitySpoolUploader for PresignedSpoolUploader {
    async fn upload_file(
        &self,
        path: &FsPath,
        content_length: u64,
    ) -> Result<StoredObjectMeta, TransactionError> {
        let mut last_error = None;
        for _ in 0..self.max_attempts.max(1) {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|error| TransactionError::Spool(error.to_string()))?;
            let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
            match self
                .client
                .put(self.url.clone())
                .header(header::CONTENT_LENGTH, content_length)
                .body(body)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    return Ok(StoredObjectMeta {
                        etag: response
                            .headers()
                            .get(header::ETAG)
                            .and_then(|value| value.to_str().ok())
                            .map(ToOwned::to_owned),
                        version_id: response
                            .headers()
                            .get("x-amz-version-id")
                            .and_then(|value| value.to_str().ok())
                            .map(ToOwned::to_owned),
                        superseded_version_ids: Vec::new(),
                        version_history_complete: true,
                    });
                }
                Ok(response) => {
                    last_error = Some(format!(
                        "presigned destination returned HTTP {}",
                        response.status()
                    ));
                }
                Err(error) => {
                    let failure = PresignedTransportFailure::from_reqwest(&error);
                    warn!(
                        category = failure.as_str(),
                        "presigned destination transport failed"
                    );
                    last_error = Some("presigned destination request failed".to_string());
                }
            }
        }
        Err(TransactionError::Spool(last_error.unwrap_or_else(|| {
            "presigned destination retry budget exhausted".to_string()
        })))
    }
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
        StreamingPutError::Integrity(
            IntegrityError::PayloadHashMismatch | IntegrityError::SignatureMismatch,
        ) => s3_error::signature_mismatch(key),
        StreamingPutError::Integrity(
            error @ (IntegrityError::InvalidChecksum(_)
            | IntegrityError::MissingChecksum
            | IntegrityError::DecodedLengthMismatch),
        ) => s3_error::bad_digest(key, &error.to_string()),
        StreamingPutError::Integrity(error) => s3_error::invalid_request(key, &error.to_string()),
        StreamingPutError::Pipeline(error)
            if matches!(
                error.code(),
                s4_error::codes::LIMIT_INPUT_BYTES
                    | s4_error::codes::LIMIT_OUTPUT_BYTES
                    | s4_error::codes::LIMIT_EXPANSION
                    | s4_error::codes::LIMIT_INTERMEDIATE_BYTES
                    | s4_error::codes::LIMIT_FINISH_BYTES
                    | s4_error::codes::RECORD_TOO_LARGE
            ) =>
        {
            s3_error::entity_too_large(key)
        }
        StreamingPutError::Pipeline(error) if error.code() == s4_error::codes::WASM_ADMISSION => {
            s3_error::slow_down(key)
        }
        StreamingPutError::Pipeline(error)
            if matches!(
                error.code(),
                s4_error::codes::DECODE_JSON
                    | s4_error::codes::DECODE_JSONL
                    | s4_error::codes::DECODE_CSV
                    | s4_error::codes::DECODE_ENCODING
                    | s4_error::codes::WASM_REJECT
                    | s4_error::codes::UNSUPPORTED_FORMAT
            ) =>
        {
            s3_error::invalid_request(key, error.message())
        }
        StreamingPutError::Pipeline(error) => s3_error::internal_error(key, error.message()),
        StreamingPutError::Transaction(
            TransactionError::CapacityExceeded | TransactionError::TooManyParts,
        ) => s3_error::entity_too_large(key),
        StreamingPutError::Transaction(TransactionError::Spool(detail)) => {
            s3_error::service_unavailable(key, &detail)
        }
        StreamingPutError::Transaction(error) => {
            s3_error::service_unavailable(key, &error.to_string())
        }
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

async fn begin_streaming_sink(
    state: &AppState,
    backend: ResolvedBackend,
    auth: &Auth,
    bucket: &str,
    key: &str,
    content_type: &str,
) -> Result<Box<dyn ObjectSinkTransaction>, StreamingPutError> {
    match backend {
        ResolvedBackend::S3 { kind, client } => {
            let capabilities = state.s3_streaming_capabilities.ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "direct S3 streaming needs S4_STREAMING_S3_PROVIDER".to_string(),
                )
            })?;
            let journal = state.operation_journal.clone().ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "direct S3 streaming needs a durable operation journal".to_string(),
                )
            })?;
            let destination = ObjectDestination {
                backend_id: format!("{kind:?}"),
                bucket: bucket.to_string(),
                logical_key: key.to_string(),
                physical_key: key.to_string(),
            };
            let expected = ExpectedObject {
                metadata: std::collections::BTreeMap::from([(
                    "content-type".to_string(),
                    content_type.to_string(),
                )]),
                ..ExpectedObject::default()
            };
            let backend = Arc::new(AwsS3TransactionBackend::new(client, capabilities));
            let (abort_signal, mut abort_receiver) = AbortSignal::channel(1);
            let reconciler = OperationReconciler::new(
                journal.clone(),
                backend.clone(),
                format!("request-{}", uuid::Uuid::now_v7()),
            )
            .map_err(TransactionError::from)?;
            tokio::spawn(async move {
                while abort_receiver.recv().await.is_some() {
                    if let Err(error) = reconciler.reconcile_due(Duration::ZERO, 16).await {
                        warn!("streaming transaction cleanup failed: {error}");
                    }
                }
            });
            Ok(Box::new(
                DirectS3Sink::new(journal, backend, destination, expected, 3, abort_signal).await?,
            ))
        }
        ResolvedBackend::PresignedHttp(url) => {
            let client = state
                .presigned_http_policy
                .client_for_destination(&url, Duration::from_secs(30))
                .await
                .map_err(StreamingPutError::InvalidRequest)?;
            let uploader = Arc::new(PresignedSpoolUploader {
                client,
                url,
                max_attempts: 3,
            });
            Ok(Box::new(
                CompatibilitySpoolTransaction::begin(
                    state.spool_config.clone(),
                    Arc::clone(&state.spool_quota),
                    uploader,
                )
                .await?,
            ))
        }
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
            let capabilities = state.managed_streaming_capabilities.ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "managed streaming needs S4_MANAGED_STREAMING_TRANSACTIONAL=true".to_string(),
                )
            })?;
            let journal = state.operation_journal.clone().ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "managed streaming needs a durable operation journal".to_string(),
                )
            })?;
            storage
                .begin_authoritative_sink(
                    journal,
                    capabilities,
                    managed_logical_key(auth, bucket, key),
                    content_type,
                )
                .await
                .map_err(StreamingPutError::from)
        }
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

async fn streaming_single_put(
    state: &AppState,
    mut authentication: HeaderAuthentication,
    backend: ResolvedBackend,
    headers: &HeaderMap,
    mut body: axum::body::Body,
    bucket: &str,
    key: &str,
) -> Result<(Auth, StoredObjectMeta, u64, u64), StreamingPutError> {
    use http_body_util::BodyExt as _;
    use sha2::Digest as _;

    if authentication.body_verifier.is_none() && headers.contains_key(header::CONTENT_ENCODING) {
        return Err(StreamingPutError::InvalidRequest(
            "Content-Encoding is unsupported for transformed streaming".to_string(),
        ));
    }
    let (format, content_type) = streaming_format(headers)?;
    let sink = begin_streaming_sink(
        state,
        backend,
        &authentication.auth,
        bucket,
        key,
        &content_type,
    )
    .await?;
    let mut sink_guard = SinkAbortGuard::new(sink);
    let sink = Arc::clone(&sink_guard.sink);
    let stable_fields = headers
        .get("x-s4-stable-fields")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let session = s4_wasm_runtime::Session {
        format: format.as_str().to_string(),
        content_type: content_type.clone(),
        policy_version: 0,
        public_key_pem: authentication.auth.public_key_pem.clone(),
        stable_key: authentication.auth.stable_key.clone(),
        stable_fields,
    };
    let cancellation = s4_wasm_runtime::CancellationToken::new();
    let snapshot = state.gateway.pipeline_snapshot().ok_or_else(|| {
        StreamingPutError::Unsupported("streaming requires a plugin registry".to_string())
    })?;
    let mut pipeline = match snapshot
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
        for record in finishing.finish().await? {
            write_stream_record(&sink, record, &mut output_hasher, &mut output_bytes).await?;
        }
        let output_digest = hex::encode(output_hasher.finalize());
        let mut sink = sink.lock().await;
        sink.verify_output(output_bytes, &output_digest).await?;
        let stored = sink.complete().await?;
        Ok((stored, output_bytes))
    }
    .await;

    match processing {
        Ok((stored, output_bytes)) => {
            sink_guard.disarm();
            Ok((authentication.auth, stored, input_bytes, output_bytes))
        }
        Err(error) => {
            cancellation.cancel();
            if let Some(pipeline) = pipeline.take() {
                let _ = pipeline.cancel_and_wait().await;
            }
            if let Err(abort_error) = sink.lock().await.abort().await {
                warn!("streaming sink abort failed for /{bucket}/{key}: {abort_error}");
            }
            sink_guard.disarm();
            Err(error)
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
    plugins: &PluginRegistry,
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
        plugin_snapshot: serde_json::to_value(plugins.list())
            .unwrap_or_else(|_| serde_json::json!([])),
        max_staged_bytes: max_bytes,
    }
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

async fn complete_staged_multipart(
    state: &AppState,
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    upload: &MultipartUpload,
    lease: &CompletionLease,
    auth: &Auth,
    backend: ResolvedBackend,
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
    // The Phase 10 snapshot records the ordered plugin identities. Until
    // component snapshots are independently persisted, reject a changed
    // registry rather than silently transforming with a different policy.
    if serde_json::to_value(state.plugins.list()).ok()
        != Some(upload.snapshot.plugin_snapshot.clone())
    {
        return Err(MultipartCompletionError::Invalid(
            "multipart plugin snapshot is no longer available".to_string(),
        ));
    }
    let content_type = upload
        .snapshot
        .metadata
        .get("content-type")
        .ok_or_else(|| {
            MultipartCompletionError::Invalid("multipart Content-Type is missing".to_string())
        })?;
    let (format, content_type) = streaming_format_content_type(content_type)?;
    renew_and_fence_completion(staging, identity, lease).await?;
    let mut sink = begin_streaming_sink(
        state,
        backend,
        auth,
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
        public_key_pem: auth.public_key_pem.clone(),
        stable_key: auth.stable_key.clone(),
        stable_fields: None,
    };
    let snapshot = state.gateway.pipeline_snapshot().ok_or_else(|| {
        MultipartCompletionError::Invalid("streaming pipeline is unavailable".to_string())
    })?;
    let mut pipeline = Some(
        snapshot
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
        for record in finishing.finish().await? {
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
        let checksum_sha256 = hex::encode(output_hasher.finalize());
        renew_and_fence_completion(staging, identity, lease).await?;
        sink.verify_output(output_bytes, &checksum_sha256).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let stored = sink.complete().await?;
        let result = MultipartCompletionResult {
            etag: stored.etag,
            checksum_sha256,
            version_id: stored.version_id,
            source_bytes: input_bytes,
            size_bytes: output_bytes,
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
        if renew_and_fence_completion(staging, identity, lease)
            .await
            .is_ok()
        {
            let _ = sink.abort().await;
        }
        let _ = error;
    }
    processing
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
    if let Some(reason) = state
        .control
        .authorize(&authentication.auth.context, RequestKind::Write)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
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
    let operation = match request_operation_identity(&parts.headers) {
        Ok(operation) => operation,
        Err(error) => return metering_id_error_response(&key, error),
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.context, RequestKind::Write)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }
    let tenant_write_mode = state
        .control
        .streaming_write_mode(&auth.context)
        .await
        .unwrap_or(state.streaming_write_mode);
    let effective_write_mode = state.streaming_write_mode.min(tenant_write_mode);
    let backend = match resolve_backend(&state, auth, &parts.headers, StorageOperation::Put).await {
        Ok(backend) => backend,
        Err(_) => return backend_resolution_error_response(&key),
    };
    if let ResolvedBackend::Managed(storage) = &backend {
        match storage.managed_mode() {
            ManagedStreamingMode::Observe => {
                return s3_error::service_unavailable(
                    &key,
                    "managed mutations are disabled in observe mode",
                );
            }
            ManagedStreamingMode::Enforce if effective_write_mode < StreamingWriteMode::Single => {
                return s3_error::not_implemented(&key);
            }
            ManagedStreamingMode::Off | ManagedStreamingMode::Enforce => {}
        }
    }
    // Legacy buffered PUT was removed in Phase 12. A write-mode below `single`
    // rejects without polling the request body; there is no fallback to a
    // whole-object buffer.
    if effective_write_mode < StreamingWriteMode::Single {
        return s3_error::not_implemented(&key);
    }
    match streaming_single_put(
        &state,
        header_auth,
        backend,
        &parts.headers,
        request_body,
        &bucket,
        &key,
    )
    .await
    {
        Ok((auth, stored, source_bytes, output_bytes)) => {
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    operation,
                    bucket: &bucket,
                    kind: RequestKind::Write,
                    route: UsageRoute::PutObject,
                    source_bytes,
                    output_bytes,
                },
                &key,
            )
            .await
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
        Err(error) => streaming_put_error_response(&key, error),
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
        TransformedReadError::Spool(error) => {
            s3_error::service_unavailable(key, &error.to_string())
        }
        TransformedReadError::Pipeline(error)
            if matches!(
                error.code(),
                s4_error::codes::LIMIT_INPUT_BYTES
                    | s4_error::codes::LIMIT_OUTPUT_BYTES
                    | s4_error::codes::LIMIT_EXPANSION
                    | s4_error::codes::LIMIT_INTERMEDIATE_BYTES
                    | s4_error::codes::LIMIT_FINISH_BYTES
                    | s4_error::codes::RECORD_TOO_LARGE
            ) =>
        {
            s3_error::entity_too_large(key)
        }
        TransformedReadError::Pipeline(error)
            if matches!(
                error.code(),
                s4_error::codes::DECODE_JSON
                    | s4_error::codes::DECODE_JSONL
                    | s4_error::codes::DECODE_CSV
                    | s4_error::codes::DECODE_ENCODING
                    | s4_error::codes::WASM_REJECT
                    | s4_error::codes::UNSUPPORTED_FORMAT
            ) =>
        {
            s3_error::invalid_request(key, error.message())
        }
        TransformedReadError::Pipeline(error) => s3_error::internal_error(key, error.message()),
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
        public_key_pem: auth.public_key_pem.clone(),
        stable_key: auth.stable_key.clone(),
        stable_fields: headers
            .get("x-s4-stable-fields")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
    }
}

async fn process_transformed_source<F, Fut>(
    mut object: OpenedObject,
    mut pipeline: StreamingPipelineSession,
    format: Format,
    max_source_frame_bytes: usize,
    mut emit: F,
) -> Result<(), TransformedReadError>
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
        for record in pipeline.finish().await? {
            if !record.payload.is_empty() {
                emit(record.payload).await?;
            }
            if !record.separator.is_empty() {
                emit(record.separator).await?;
            }
        }
        Ok(())
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
    Done,
}

struct DirectReadBody {
    first: Option<bytes::Bytes>,
    receiver: tokio::sync::mpsc::Receiver<DirectReadEvent>,
    source_cancellation: s4_wasm_runtime::CancellationToken,
    pipeline_cancellation: s4_wasm_runtime::CancellationToken,
    done: bool,
}

impl http_body::Body for DirectReadBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(bytes) = self.first.take() {
            return std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))));
        }
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(DirectReadEvent::Data(bytes))) => {
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
            }
            std::task::Poll::Ready(Some(DirectReadEvent::Failed(error))) => {
                self.done = true;
                std::task::Poll::Ready(Some(Err(std::io::Error::other(error_to_log(&error)))))
            }
            std::task::Poll::Ready(Some(DirectReadEvent::Done)) | std::task::Poll::Ready(None) => {
                self.done = true;
                std::task::Poll::Ready(None)
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
        }
    }
}

fn error_to_log(error: &TransformedReadError) -> String {
    match error {
        TransformedReadError::InvalidRequest(detail)
        | TransformedReadError::Capacity(detail)
        | TransformedReadError::Source(detail) => detail.clone(),
        TransformedReadError::Pipeline(error) => error.to_string(),
        TransformedReadError::Spool(error) => error.to_string(),
    }
}

async fn transformed_read_response(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    preflight: (Format, String),
    response_metadata: ObjectMetadata,
    object: OpenedObject,
    key: &str,
) -> axum::response::Response {
    let (format, content_type) = preflight;
    let snapshot = match state.gateway.pipeline_snapshot() {
        Some(snapshot) => snapshot,
        None => {
            return transformed_read_error_response(
                key,
                TransformedReadError::Capacity(
                    "transformed reads require a plugin registry".to_string(),
                ),
            );
        }
    };
    let source_cancellation = object.cancellation.clone();
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
        Err(error) => return transformed_read_error_response(key, error.into()),
    };
    let direct = snapshot
        .capabilities()
        .iter()
        .all(|capabilities| capabilities.prefix_safe_for_read);
    if direct {
        let max_source_frame_bytes = state.source_body_limits.max_frame_bytes;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            let result = process_transformed_source(
                object,
                pipeline,
                format,
                max_source_frame_bytes,
                |bytes| {
                    let sender = sender.clone();
                    async move {
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
                Ok(()) => DirectReadEvent::Done,
                Err(error) => DirectReadEvent::Failed(error),
            };
            let _ = sender.send(event).await;
        });
        return match receiver.recv().await {
            Some(DirectReadEvent::Data(first)) => {
                let mut response = axum::response::Response::builder().status(StatusCode::OK);
                response
                    .headers_mut()
                    .unwrap()
                    .extend(transformed_response_headers(&response_metadata, None));
                response
                    .body(axum::body::Body::new(DirectReadBody {
                        first: Some(first),
                        receiver,
                        source_cancellation,
                        pipeline_cancellation,
                        done: false,
                    }))
                    .unwrap()
            }
            Some(DirectReadEvent::Done) | None => {
                let mut response = axum::response::Response::builder().status(StatusCode::OK);
                response
                    .headers_mut()
                    .unwrap()
                    .extend(transformed_response_headers(&response_metadata, Some(0)));
                response.body(axum::body::Body::empty()).unwrap()
            }
            Some(DirectReadEvent::Failed(error)) => transformed_read_error_response(key, error),
        };
    }
    if !state.transformed_read_spool_enabled {
        source_cancellation.cancel();
        return transformed_read_error_response(
            key,
            TransformedReadError::Capacity(
                "unsafe transformed reads require S4_TRANSFORMED_READ_SPOOL=encrypted".to_string(),
            ),
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
        Err(error) => return transformed_read_error_response(key, error.into()),
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
    if let Err(error) = result {
        let _ = spool_writer.await;
        return transformed_read_error_response(key, error);
    }
    let spool = match spool_writer.await {
        Ok(Ok(spool)) => spool,
        Ok(Err(error)) => return transformed_read_error_response(key, error),
        Err(error) => {
            return transformed_read_error_response(
                key,
                TransformedReadError::Capacity(format!(
                    "encrypted transformed-read staging task failed: {error}"
                )),
            );
        }
    };
    let (body, content_length) = match spool.into_body(source_cancellation).await {
        Ok(result) => result,
        Err(error) => return transformed_read_error_response(key, error.into()),
    };
    let mut response = axum::response::Response::builder().status(StatusCode::OK);
    response
        .headers_mut()
        .unwrap()
        .extend(transformed_response_headers(
            &response_metadata,
            Some(content_length),
        ));
    response.body(body).unwrap()
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
    if let Some(reason) = state
        .control
        .authorize(&auth.context, RequestKind::Read)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }

    let transformed_read = wants_transformed_read(&headers);
    if transformed_read && state.streaming_read_mode != StreamingReadMode::Transformed {
        return s3_error::transformed_read_not_supported(&key);
    }
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
    let operation = match request_operation_identity(&headers) {
        Ok(operation) => operation,
        Err(error) => return metering_id_error_response(&key, error),
    };
    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Get).await {
        Ok(backend) => backend,
        Err(_) => return backend_resolution_error_response(&key),
    };
    // A transformed representation must be admitted from authoritative object
    // metadata before a source GET can start delivering bytes. Passthrough keeps
    // its existing one-request behavior below.
    if transformed_read {
        if matches!(&backend, ResolvedBackend::PresignedHttp(_)) {
            return transformed_read_error_response(
                &key,
                TransformedReadError::InvalidRequest(
                    "transformed reads require stored object metadata".to_string(),
                ),
            );
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
            Err(error) => return open_error_response(&key, error),
        };
        let preflight = match transformed_read_preflight(&headers, &params, &metadata) {
            Ok(preflight) => preflight,
            Err(error) => return transformed_read_error_response(&key, error),
        };
        let object =
            match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, false).await
            {
                Ok(object) => object,
                Err(error) => return open_error_response(&key, error),
            };
        let source_preflight = match transformed_read_preflight(&headers, &params, &object.metadata)
        {
            Ok(preflight) => preflight,
            Err(error) => return transformed_read_error_response(&key, error),
        };
        if source_preflight.0 != preflight.0
            || source_preflight.1 != preflight.1
            || !transformed_source_matches_preflight(&metadata, &object.metadata)
        {
            object.cancellation.cancel();
            return transformed_read_error_response(
                &key,
                TransformedReadError::Source(
                    "source metadata changed after transformed-read preflight".to_string(),
                ),
            );
        }
        if let Some(status) = conditional_read_status(&headers, &object.metadata) {
            let response = conditional_read_response(object, status);
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    operation,
                    bucket: &bucket,
                    kind: RequestKind::Read,
                    route: UsageRoute::GetObject,
                    source_bytes: 0,
                    output_bytes: 0,
                },
                &key,
            )
            .await
            {
                return response;
            }
            return response;
        }
        let response_metadata = object.metadata.clone();
        let Some(source_bytes) = content_length(&response_metadata.headers) else {
            object.cancellation.cancel();
            return s3_error::service_unavailable(
                &key,
                "The source size is unavailable for usage metering.",
            );
        };
        let response = transformed_read_response(
            &state,
            &auth,
            &headers,
            preflight,
            response_metadata,
            object,
            &key,
        )
        .await;
        return metered_read_response(
            state.control.clone(),
            &auth,
            operation,
            &bucket,
            &key,
            Some(source_bytes),
            response,
        )
        .await;
    }
    let object =
        match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, false).await {
            Ok(object) => object,
            Err(error) => return open_error_response(&key, error),
        };
    if let Some(status) = conditional_read_status(&headers, &object.metadata) {
        let response = conditional_read_response(object, status);
        if let Err(response) = record_operation(
            state.control.clone(),
            &auth.context,
            OperationUsage {
                operation,
                bucket: &bucket,
                kind: RequestKind::Read,
                route: UsageRoute::GetObject,
                source_bytes: 0,
                output_bytes: 0,
            },
            &key,
        )
        .await
        {
            return response;
        }
        return response;
    }

    if state.streaming_read_mode.streams_passthrough() {
        return metered_read_response(
            state.control.clone(),
            &auth,
            operation,
            &bucket,
            &key,
            None,
            object.into_response(),
        )
        .await;
    }

    // Legacy whole-object GET buffering was removed in Phase 12. With reads
    // administratively disabled, reject without collecting the object body;
    // dropping `object` cancels the source before any byte is buffered.
    s3_error::not_implemented(&key)
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

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct UsageCall {
        context: AuthenticatedRequestContext,
        event: UsageEvent,
    }

    #[derive(Default)]
    struct RecordingControlPlane {
        calls: std::sync::Mutex<Vec<UsageCall>>,
        failure: Option<MeteringError>,
    }

    #[async_trait::async_trait]
    impl ControlPlane for RecordingControlPlane {
        async fn authorize(
            &self,
            _context: &AuthenticatedRequestContext,
            _kind: RequestKind,
        ) -> Option<crate::control::BlockReason> {
            None
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
        let response = metered_read_response(
            control.clone(),
            &auth,
            operation,
            "bucket-a",
            "key-a",
            None,
            axum::response::Response::new(Body::from("range")),
        )
        .await;
        assert_eq!(
            *control.calls.lock().unwrap(),
            vec![UsageCall {
                context: auth.context.clone(),
                event: UsageEvent::new(
                    operation.receipt_id,
                    operation.operation_id,
                    "bucket-a",
                    RequestKind::Read,
                    UsageRoute::GetObject,
                    5,
                    5,
                ),
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
        let response = metered_read_response(
            control,
            &auth,
            OperationIdentity {
                receipt_id: Uuid::now_v7(),
                operation_id: Uuid::now_v7(),
            },
            "bucket-a",
            "key-a",
            None,
            axum::response::Response::new(Body::from("range")),
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
    fn operation_identities_are_validated_and_stable() {
        let supplied = Uuid::parse_str("018f0f6e-7b31-7c1d-8f2f-84f808b9c175").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-s4-metering-id", supplied.to_string().parse().unwrap());
        let first = request_operation_identity(&headers).unwrap();
        assert_eq!(first.receipt_id, supplied);
        assert_eq!(first.operation_id, operation_id_for_receipt(supplied));
        assert_ne!(first.receipt_id, first.operation_id);

        headers.append(
            "x-s4-metering-id",
            Uuid::now_v7().to_string().parse().unwrap(),
        );
        assert_eq!(
            request_operation_identity(&headers),
            Err(MeteringIdError::Duplicate)
        );
        headers = HeaderMap::new();
        headers.insert("x-s4-metering-id", "not-a-uuid".parse().unwrap());
        assert_eq!(
            request_operation_identity(&headers),
            Err(MeteringIdError::Invalid)
        );

        let generated = request_operation_identity(&HeaderMap::new()).unwrap();
        assert_eq!(generated.receipt_id.get_version_num(), 7);
        assert_eq!(generated.operation_id.get_version_num(), 5);
        let multipart = multipart_completion_operation_identity("upload-1");
        assert_eq!(
            multipart,
            multipart_completion_operation_identity("upload-1")
        );
        assert_ne!(
            multipart,
            multipart_completion_operation_identity("upload-2")
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

    #[tokio::test]
    async fn direct_body_truncates_after_a_late_pipeline_failure_and_cancels_on_drop() {
        let source_cancellation = s4_wasm_runtime::CancellationToken::new();
        let pipeline_cancellation = s4_wasm_runtime::CancellationToken::new();
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(DirectReadEvent::Data(Bytes::from_static(b"safe-prefix")))
            .await
            .unwrap();
        sender
            .send(DirectReadEvent::Failed(TransformedReadError::Source(
                "injected late failure".to_string(),
            )))
            .await
            .unwrap();
        let mut body = DirectReadBody {
            first: None,
            receiver,
            source_cancellation: source_cancellation.clone(),
            pipeline_cancellation: pipeline_cancellation.clone(),
            done: false,
        };
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first, Bytes::from_static(b"safe-prefix"));
        assert!(body.frame().await.unwrap().is_err());
        drop(body);
        assert!(!source_cancellation.is_cancelled());
        assert!(!pipeline_cancellation.is_cancelled());

        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(sender);
        let body = DirectReadBody {
            first: None,
            receiver,
            source_cancellation: source_cancellation.clone(),
            pipeline_cancellation: pipeline_cancellation.clone(),
            done: false,
        };
        drop(body);
        assert!(source_cancellation.is_cancelled());
        assert!(pipeline_cancellation.is_cancelled());
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
    let operation = match request_operation_identity(&headers) {
        Ok(operation) => operation,
        Err(error) => return metering_id_error_response(&key, error),
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.context, RequestKind::Read)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }
    if wants_transformed_read(&headers) {
        return s3_error::invalid_request(
            &key,
            "HEAD is not supported for transformed reads until transformed metadata is available",
        );
    }

    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Head).await {
        Ok(backend) => backend,
        Err(_) => return backend_resolution_error_response(&key),
    };
    match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, true).await {
        Ok(object) => {
            let response = if let Some(status) = conditional_read_status(&headers, &object.metadata)
            {
                conditional_read_response(object, status)
            } else {
                object.into_response()
            };
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    operation,
                    bucket: &bucket,
                    kind: RequestKind::Read,
                    route: UsageRoute::HeadObject,
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
        Err(error) => open_error_response(&key, error),
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
    let operation = match request_operation_identity(&headers) {
        Ok(operation) => operation,
        Err(error) => return metering_id_error_response(&key, error),
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.context, RequestKind::Write)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }
    info!("DELETE /{bucket}/{key} user={}", auth.user_id());

    if params.upload_id.is_some() {
        let backend =
            match resolve_backend(&state, &auth, &headers, StorageOperation::Multipart).await {
                Ok(backend) => backend,
                Err(_) => return backend_resolution_error_response(&key),
            };
        let Some(staging) = staged_multipart(&state).cloned() else {
            return s3_error::multipart_not_supported(&key);
        };
        let upload_id = params.upload_id.as_deref().unwrap_or_default();
        let identity = multipart_identity(&auth, &bucket, &key, upload_id);
        let upload = match staging.repository.get_authorized(&identity).await {
            Ok(upload) => upload,
            Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
        };
        if let ResolvedBackend::Managed(storage) = &backend {
            let Some(epoch) = upload.namespace_epoch else {
                return s3_error::service_unavailable(
                    &key,
                    "managed multipart upload has no namespace epoch",
                );
            };
            if let Err(error) = storage
                .assert_managed_multipart(upload_id, auth.workspace_id().as_str(), epoch, true)
                .await
            {
                return s3_error::service_unavailable(&key, &error.to_string());
            }
        }
        return match staging.repository.abort(&identity, now_ms()).await {
            Ok(parts) => {
                cleanup_staged_parts(&staging, upload_id, parts, "abort").await;
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        operation,
                        bucket: &bucket,
                        kind: RequestKind::Write,
                        route: UsageRoute::AbortMultipartUpload,
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
            Err(StagingError::NotFound) => s3_error::no_such_upload(&key),
            Err(StagingError::NotOpen) => {
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        operation,
                        bucket: &bucket,
                        kind: RequestKind::Write,
                        route: UsageRoute::AbortMultipartUpload,
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
            Err(error) => s3_error::internal_error(&key, &error.to_string()),
        };
    }

    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Delete).await {
        Ok(backend) => backend,
        Err(_) => return backend_resolution_error_response(&key),
    };
    match backend {
        ResolvedBackend::PresignedHttp(url) => {
            let client = match state
                .presigned_http_policy
                .client_for_destination(&url, Duration::from_secs(30))
                .await
            {
                Ok(client) => client,
                Err(error) => return open_error_response(&key, OpenObjectError::Rejected(error)),
            };
            match client.delete(url).send().await {
                Ok(response) if response.status().is_success() => {
                    if let Err(response) = record_operation(
                        state.control.clone(),
                        &auth.context,
                        OperationUsage {
                            operation,
                            bucket: &bucket,
                            kind: RequestKind::Write,
                            route: UsageRoute::DeleteObject,
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
                        operation,
                        bucket: &bucket,
                        kind: RequestKind::Write,
                        route: UsageRoute::DeleteObject,
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
            let result = match storage.managed_mode() {
                ManagedStreamingMode::Off => storage
                    .delete(&format!("{}/{bucket}/{key}", auth.workspace_id().as_str()))
                    .await
                    .map_err(|error| error.to_string()),
                ManagedStreamingMode::Observe => {
                    Err("managed mutations are disabled in observe mode".to_string())
                }
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
                    operation,
                    bucket: &bucket,
                    kind: RequestKind::Write,
                    route: UsageRoute::DeleteObject,
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
                    operation,
                    bucket: &bucket,
                    kind: RequestKind::Write,
                    route: UsageRoute::DeleteObject,
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
        if let Err(error) = parse_metering_id(&parts.headers) {
            return metering_id_error_response(&key, error);
        }
        // Completion retries are keyed by the durable upload identity, never a
        // per-attempt client or generated request ID.
        let operation = multipart_completion_operation_identity(upload_id);
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
        if let Some(reason) = state
            .control
            .authorize(&auth.context, RequestKind::Write)
            .await
        {
            return s3_error::payment_required(&key, reason.message);
        }
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
            Err(error) if error.contains("sorted") => return s3_error::invalid_part_order(&key),
            Err(error) => return s3_error::invalid_request(&key, &error),
        };
        let Some(staging) = staged_multipart(&state).cloned() else {
            return s3_error::multipart_not_supported(&key);
        };
        let identity = multipart_identity(&auth, &bucket, &key, upload_id);
        let upload = match staging.repository.get_authorized(&identity).await {
            Ok(upload) => upload,
            Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
        };
        let backend =
            match resolve_backend(&state, &auth, &parts.headers, StorageOperation::Multipart).await
            {
                Ok(backend) => backend,
                Err(_) => return backend_resolution_error_response(&key),
            };
        if let ResolvedBackend::Managed(storage) = &backend {
            let Some(epoch) = upload.namespace_epoch else {
                return s3_error::service_unavailable(
                    &key,
                    "managed multipart upload has no namespace epoch",
                );
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
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
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
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        operation,
                        bucket: &bucket,
                        kind: RequestKind::Write,
                        route: UsageRoute::CompleteMultipartUpload,
                        source_bytes: result.source_bytes,
                        output_bytes: result.size_bytes,
                    },
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
            Ok(CompletionAcquire::Busy) => return s3_error::slow_down(&key),
            Ok(CompletionAcquire::Acquired(lease)) => lease,
            Err(StagingError::InvalidPart) => {
                return s3_error::invalid_part(
                    &key,
                    "submitted part is missing or does not match its staged ETag/checksum",
                );
            }
            Err(StagingError::CompletionConflict) => {
                return s3_error::invalid_request(
                    &key,
                    "conflicting CompleteMultipartUpload request",
                );
            }
            Err(StagingError::NotFound | StagingError::NotOpen) => {
                return s3_error::no_such_upload(&key);
            }
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
        };
        let complete = tokio::time::timeout(
            Duration::from_secs(MAX_MULTIPART_COMPLETION_SECS),
            complete_staged_multipart(&state, &staging, &identity, &upload, &lease, &auth, backend),
        )
        .await;
        let result = match complete {
            Ok(Ok(result)) => result,
            Ok(Err(MultipartCompletionError::Staging(StagingError::Fenced))) => {
                return s3_error::service_unavailable(&key, "multipart completion lease was lost");
            }
            Ok(Err(MultipartCompletionError::Staging(StagingError::InvalidPart))) => {
                return s3_error::invalid_part(&key, "staged part validation failed");
            }
            Ok(Err(MultipartCompletionError::Staging(error))) => {
                return s3_error::internal_error(&key, &error.to_string());
            }
            Ok(Err(MultipartCompletionError::Streaming(error))) => {
                return streaming_put_error_response(&key, error);
            }
            Ok(Err(MultipartCompletionError::Invalid(error))) => {
                return s3_error::invalid_request(&key, &error);
            }
            Err(_) => {
                return s3_error::service_unavailable(
                    &key,
                    "multipart completion exceeded the configured hosted time limit",
                );
            }
        };
        cleanup_staged_parts(&staging, upload_id, lease.cleanup_parts, "complete").await;
        if let Err(response) = record_operation(
            state.control.clone(),
            &auth.context,
            OperationUsage {
                operation,
                bucket: &bucket,
                kind: RequestKind::Write,
                route: UsageRoute::CompleteMultipartUpload,
                source_bytes: result.source_bytes,
                output_bytes: result.size_bytes,
            },
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
    if let Some(reason) = state
        .control
        .authorize(&auth.context, RequestKind::Write)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }
    info!("POST /{bucket}/{key} user={}", auth.user_id());

    if params.uploads.is_some() {
        let backend =
            match resolve_backend(&state, &auth, &parts.headers, StorageOperation::Multipart).await
            {
                Ok(backend) => backend,
                Err(_) => return backend_resolution_error_response(&key),
            };
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
                &state.plugins,
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
    if let Some(reason) = state
        .control
        .authorize(&auth.context, RequestKind::Read)
        .await
    {
        return s3_error::payment_required(&bucket, reason.message);
    }

    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::List).await {
        Ok(backend) => backend,
        Err(_) => return backend_resolution_error_response(&bucket),
    };
    match backend {
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
        ResolvedBackend::Managed(_) => {
            warn!("listing is not supported against managed service storage for {bucket}");
            s3_xml_ok(empty_list(&bucket, &params))
        }
        ResolvedBackend::PresignedHttp(url) => {
            match open_http_object(&state, url, &headers, false).await {
                Ok(object) => object.into_response(),
                Err(error) => open_error_response(&bucket, error),
            }
        }
    }
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

fn empty_list(bucket: &str, params: &S3Query) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>0</KeyCount><MaxKeys>{}</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"#,
        xml_escape(bucket),
        xml_escape(params.prefix.as_deref().unwrap_or("")),
        params.max_keys.unwrap_or(1000).min(1000),
    )
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
        || headers.contains_key("x-s4-access-key")
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
        r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>s4</ID><DisplayName>s4</DisplayName></Owner><Buckets>"#,
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
        WorkspaceStorageError::Repository(_) => (
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

async fn authenticate_public_key_mutation(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<PublicKeyMutationActor, StatusCode> {
    let authorization = unique_header(headers, "authorization")?;
    let access_key = unique_header(headers, "x-s4-access-key")?;
    let secret_key = unique_header(headers, "x-s4-secret-key")?;
    let mcp_token = unique_header(headers, "x-s4-mcp-token")?;
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
    let name = headers
        .get("x-s4-plugin-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("imported")
        .to_string();
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

fn component_path() -> PathBuf {
    std::env::var("S4_FILTER_COMPONENT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("..");
            p.push("..");
            p.push("target");
            p.push("components");
            p.push("pii-default.component.wasm");
            p
        })
}

fn bundled_stable_component() -> Option<Vec<u8>> {
    let directory = match std::env::var("S4_PLUGINS_DIR") {
        Ok(directory) => PathBuf::from(directory),
        Err(_) => {
            warn!("join demo disabled because S4_PLUGINS_DIR is not configured");
            return None;
        }
    };
    let path = directory.join("stable-encrypt.component.wasm");
    match std::fs::read(&path) {
        Ok(component) => Some(component),
        Err(error) => {
            warn!(
                "join demo disabled because {} is unavailable: {error}",
                path.display()
            );
            None
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
    let s3_endpoint = std::env::var("S3_ENDPOINT").ok();
    let auth_disabled = enabled_env_flag("AUTH_DISABLED");
    let explicit_single_tenant =
        explicit_single_tenant_mode(auth_disabled, enabled_env_flag("S4_SINGLE_TENANT"));
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

    let component_bytes = std::fs::read(component_path())?;
    let pipeline_fuel = std::env::var("S4_WASM_FUEL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(crate::plugin_registry::DEFAULT_PIPELINE_FUEL);
    use sha2::Digest as _;

    let engine = s4_wasm_runtime::FilterEngine::with_fuel(&component_bytes, pipeline_fuel)?;
    let plugins = Arc::new(PluginRegistry::with_fuel(pipeline_fuel));
    let prefix_safe_hashes = prefix_safe_component_hashes();

    // Only a startup-controlled component digest can grant direct-read safety.
    let default_hash = hex::encode(sha2::Sha256::digest(&component_bytes));
    plugins.import_with_capabilities(
        "pii-default",
        &component_bytes,
        PluginCapabilities {
            prefix_safe_for_read: prefix_safe_hashes.contains(&default_hash),
        },
    )?;

    // Auto-load plugins from S4_PLUGINS_DIR if set
    if let Ok(plugin_dir) = std::env::var("S4_PLUGINS_DIR") {
        let dir = std::path::Path::new(&plugin_dir);
        if dir.exists() {
            plugins.load_from_dir_with_capabilities(dir, &prefix_safe_hashes)?;
        }
    }

    let stable_demo_component = bundled_stable_component();
    let demo_pipelines = build_demo_pipelines(
        &component_bytes,
        stable_demo_component.as_deref(),
        pipeline_fuel,
    )?;

    let gateway = Gateway::with_registry(engine, plugins.clone());

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
    let source_body_limits = BodyLimits {
        max_frame_bytes: std::env::var("S4_SOURCE_MAX_FRAME_BYTES")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(crate::object::DEFAULT_MAX_SOURCE_FRAME_BYTES),
        max_bytes: std::env::var("S4_MAX_OBJECT_BYTES")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(crate::object::DEFAULT_MAX_SOURCE_BYTES)
            .min(crate::object::DEFAULT_MAX_SOURCE_BYTES),
    };
    let multipart_mode = multipart_mode();
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
    let streaming_write_mode = streaming_write_mode();
    let s3_streaming_capabilities = configured_s3_streaming_capabilities();
    let managed_streaming_capabilities = configured_managed_streaming_capabilities();
    let spool_max_object_bytes = std::env::var("S4_SPOOL_MAX_OBJECT_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(source_body_limits.max_bytes)
        .min(source_body_limits.max_bytes);
    let spool_quota_bytes = std::env::var("S4_SPOOL_QUOTA_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= spool_max_object_bytes)
        .unwrap_or(spool_max_object_bytes.saturating_mul(2));
    let spool_config = CompatibilitySpoolConfig {
        directory: std::env::var("S4_SPOOL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("s4-spool")),
        max_object_bytes: spool_max_object_bytes,
        stale_after: Duration::from_secs(24 * 60 * 60),
    };
    let removed_spools = CompatibilitySpoolTransaction::cleanup_stale(&spool_config).await?;
    if removed_spools > 0 {
        info!(removed_spools, "removed stale spool files");
    }
    schedule_spool_cleanup(spool_config.clone());
    let spool_quota = Arc::new(SpoolQuota::new(spool_quota_bytes));
    let dev_memory_max_object_bytes = std::env::var("S4_DEV_MEMORY_MAX_OBJECT_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(LEGACY_MAX_OBJECT_BYTES)
        .min(64 * 1024 * 1024);
    let dev_memory_streaming_enabled = explicit_single_tenant
        || std::env::var("S4_DEV_MEMORY_STREAMING")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));

    // API key persistence: Postgres (Supabase) when DATABASE_URL is set,
    // a JSON file when S4_KEYS_FILE is set, a default JSON file in local
    // mode (AUTH_DISABLED=true), and otherwise the in-memory KeyStore.
    let mut operation_journal: Option<Arc<dyn OperationJournal>> = None;
    let mut postgres_pool = None;
    let keys: Arc<dyn KeyRepository> = if let Ok(database_url) = std::env::var("DATABASE_URL") {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        let mut migrator = sqlx::migrate!("../../migrations");
        // The SaaS control plane applies its own migrations (workspaces, usage,
        // billing) to the same database and shares the `_sqlx_migrations` table.
        // Ignore migrations we don't know about so both binaries can coexist.
        migrator.set_ignore_missing(true);
        migrator.run(&pool).await.expect("failed to run migrations");
        info!("Key store: Postgres (migrations applied)");
        operation_journal = Some(Arc::new(crate::transaction::PostgresOperationJournal::new(
            pool.clone(),
        )));
        postgres_pool = Some(pool.clone());
        Arc::new(PostgresKeyStore::with_cipher(pool, cipher.clone()))
    } else if let Ok(keys_file) = std::env::var("S4_KEYS_FILE") {
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
        info!("Key store: in-memory (set DATABASE_URL or S4_KEYS_FILE for persistence)");
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
                        "staged multipart requested without a complete S4-controlled staging backend; transformed multipart remains rejected"
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
            println!("S4_ACCESS_KEY={}", created.key_id);
            println!("S4_SECRET_KEY={secret}");
        } else if let Some(k) = existing.into_iter().find(|k| k.label == "local-default")
            && let Some(secret) = keys.decrypt_secret(&k.key_id).await?
        {
            println!("S4_ACCESS_KEY={}", k.key_id);
            println!("S4_SECRET_KEY={secret}");
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
        legacy_max_object_bytes: legacy_max_object_bytes(),
        streaming_read_mode: StreamingReadMode::from_env(),
        streaming_write_mode,
        source_body_limits,
        presigned_http_policy: PresignedHttpPolicy::from_env().map_err(anyhow::Error::msg)?,
        sigv4_cache: Arc::new(SigningKeyCache::standard()),
        sigv4_policy: SigV4Policy::from_env(),
        operation_journal,
        s3_streaming_capabilities,
        managed_streaming_capabilities,
        spool_config,
        spool_quota,
        transformed_read_spool_enabled: transformed_read_spool_enabled(),
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
            let capabilities = configured_s3_streaming_capabilities();
            assert!(
                capabilities.is_some(),
                "provider {provider} must enable direct S3 streaming"
            );
            let capabilities = capabilities.expect("capabilities present");
            assert!(capabilities.supports_conditional_reads());
            assert!(capabilities.supports_response_checksums());
        }
        unsafe { std::env::set_var("S4_STREAMING_S3_PROVIDER", "wasabi") }
        assert!(configured_s3_streaming_capabilities().is_none());
        unsafe { std::env::remove_var("S4_STREAMING_S3_PROVIDER") }
        assert!(configured_s3_streaming_capabilities().is_none());
    }
}
