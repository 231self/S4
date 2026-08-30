//! Phase 10 durable, encrypted staging for client multipart uploads.
//!
//! This module deliberately stops before completion.  It provides the durable
//! upload/part state machine and opaque encrypted artifacts that Phase 11 will
//! consume in part-number order.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(any(test, debug_assertions))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use md5::{Digest as _, Md5};
use rand::{RngCore, rngs::OsRng};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, SqlxPostgresConnector,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::entity::{
    multipart_cleanup_audit, multipart_part_attempt, multipart_staging_quota, multipart_upload,
};
use crate::key_cipher::KeyWrapping;
use crate::s3_safety::{record_s3_body_failure, record_s3_failure};

pub const MAX_ACTIVE_UPLOADS: usize = 16;
pub const MAX_PARTS: u32 = 10_000;
pub const DEFAULT_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);
const MAGIC: &[u8] = b"S4MP10\0";
const NONCE_LEN: usize = 12;
const FILE_PREFIX: &str = "s4-multipart-";
pub const ARTIFACT_PREFIX: &str = "multipart/";
#[cfg(any(test, debug_assertions))]
static FAIL_ABORT_AFTER_UPDATE: AtomicBool = AtomicBool::new(false);
pub const RECONCILIATION_GRACE: Duration = Duration::from_secs(5 * 60);
pub const COMPLETION_LEASE: Duration = Duration::from_secs(30);
const MAX_ARTIFACT_HEADER_BYTES: usize = 64 * 1024;
const MAX_ENCRYPTED_FRAME_BYTES: usize = 8 * 1024 * 1024 + 16;

#[derive(Clone, Copy, Debug)]
pub struct StagingQuotaLimits {
    pub tenant_bytes: u64,
    pub global_bytes: u64,
}

impl StagingQuotaLimits {
    pub fn new(tenant_bytes: u64, global_bytes: u64) -> Result<Self, StagingError> {
        if tenant_bytes == 0 || global_bytes == 0 || tenant_bytes > global_bytes {
            return Err(StagingError::QuotaExceeded);
        }
        Ok(Self {
            tenant_bytes,
            global_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PendingPart {
    pub upload_id: String,
    pub part_number: u32,
    pub attempt: u32,
    pub artifact_key: String,
    pub reserved_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct CleanupCandidate {
    pub upload_id: String,
    pub artifact_key: String,
}

#[derive(Clone, Debug)]
pub struct StagedArtifact {
    pub key: String,
    pub modified_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultipartIdentity {
    pub tenant_id: String,
    pub credential_policy_id: String,
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultipartSnapshot {
    pub metadata: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub checksum_mode: Option<String>,
    pub destination: serde_json::Value,
    pub plugin_snapshot: serde_json::Value,
    pub max_staged_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MultipartLifecycle {
    Open,
    Completing,
    Completed,
    Aborted,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultipartUpload {
    pub identity: MultipartIdentity,
    #[serde(default)]
    pub namespace_epoch: Option<u64>,
    pub snapshot: MultipartSnapshot,
    pub lifecycle: MultipartLifecycle,
    pub staged_bytes: u64,
    pub reserved_bytes: u64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub updated_at_ms: i64,
    pub tombstone_until_ms: Option<i64>,
    pub complete_request_fingerprint: Option<String>,
    pub completion_lease_owner: Option<String>,
    pub completion_lease_expires_at_ms: Option<i64>,
    pub completion_fencing_token: u64,
    pub completion_result: Option<MultipartCompletionResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultipartPart {
    pub upload_id: String,
    pub part_number: u32,
    pub attempt: u32,
    pub artifact_key: String,
    pub etag: String,
    pub checksum_sha256: String,
    pub size_bytes: u64,
    pub created_at_ms: i64,
}

/// A client-selected part from a CompleteMultipartUpload document. Checksum is
/// optional because S3 clients commonly submit only the ETag; when supplied it
/// is matched exactly against the staged part.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletePart {
    pub part_number: u32,
    pub etag: String,
    pub checksum_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultipartCompletionResult {
    pub etag: Option<String>,
    pub checksum_sha256: String,
    pub version_id: Option<String>,
    #[serde(default)]
    pub source_bytes: u64,
    #[serde(default)]
    pub size_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct CompletionLease {
    pub fencing_token: u64,
    pub selected_parts: Vec<MultipartPart>,
    /// Includes selected and unselected current parts. Cleanup is retried by
    /// reconciliation after a process crash, so success never depends on it.
    pub cleanup_parts: Vec<MultipartPart>,
}

#[derive(Clone, Debug)]
pub enum CompletionAcquire {
    Acquired(CompletionLease),
    Replayed(MultipartCompletionResult),
    Busy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupAudit {
    pub id: Uuid,
    pub upload_id: String,
    pub kind: String,
    pub detail: serde_json::Value,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredMultipartUpload {
    pub upload_id: String,
    pub tenant_id: String,
    pub namespace_epoch: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    #[error("multipart staging is unavailable")]
    Unavailable,
    #[error("multipart upload was not found or is not authorized")]
    NotFound,
    #[error("multipart upload is no longer open")]
    NotOpen,
    #[error("multipart staging quota exceeded")]
    QuotaExceeded,
    #[error("invalid multipart part")]
    InvalidPart,
    #[error("multipart completion request conflicts with the existing request")]
    CompletionConflict,
    #[error("multipart completion lease is fenced")]
    Fenced,
    #[error("multipart staging persistence failure: {0}")]
    Persistence(String),
    #[error("multipart staging encryption failure: {0}")]
    Crypto(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AbortMutationError {
    #[error(transparent)]
    PreMutation(StagingError),
    #[error(transparent)]
    MutationUnknown(StagingError),
}

#[async_trait]
pub trait MultipartRepository: Send + Sync {
    fn is_durable(&self) -> bool;
    async fn create(&self, upload: MultipartUpload) -> Result<(), StagingError>;
    async fn get_authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<MultipartUpload, StagingError>;
    async fn replace_part(
        &self,
        identity: &MultipartIdentity,
        part: MultipartPart,
    ) -> Result<Option<MultipartPart>, StagingError>;
    /// Create the durable outbox record and reserve both quota scopes before
    /// the request body is read or a ciphertext file is allocated.
    async fn begin_part(
        &self,
        identity: &MultipartIdentity,
        part_number: u32,
        reserved_bytes: u64,
        now_ms: i64,
    ) -> Result<PendingPart, StagingError>;
    /// Atomically publishes an already-uploaded artifact as the current part.
    /// The returned artifacts remain quota-accounted until cleanup confirms
    /// their delete, so replacement cannot overcommit backing storage.
    async fn commit_part(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
        part: MultipartPart,
    ) -> Result<Vec<MultipartPart>, StagingError>;
    /// Used only before `put_file` has been attempted.
    async fn discard_pending(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
    ) -> Result<(), StagingError>;
    async fn cleanup_candidates(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<CleanupCandidate>, StagingError>;
    /// Idempotently removes accounting only after object deletion succeeds.
    async fn confirm_artifact_deleted(&self, artifact_key: &str) -> Result<(), StagingError>;
    async fn known_artifact_keys(&self) -> Result<HashMap<String, i64>, StagingError>;
    async fn list_parts(
        &self,
        identity: &MultipartIdentity,
        marker: u32,
        limit: usize,
    ) -> Result<(Vec<MultipartPart>, bool), StagingError>;
    /// Validates client-selected parts and acquires (or takes over) the only
    /// completion lease. The request fingerprint is durable before any staged
    /// bytes are read.
    async fn acquire_completion(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        parts: &[CompletePart],
        owner: &str,
        lease_expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<CompletionAcquire, StagingError>;
    async fn renew_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        lease_expires_at_ms: i64,
    ) -> Result<(), StagingError>;
    async fn check_completion_lease(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        now_ms: i64,
    ) -> Result<(), StagingError>;
    async fn complete_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        result: MultipartCompletionResult,
        now_ms: i64,
    ) -> Result<(), StagingError>;
    async fn abort(
        &self,
        identity: &MultipartIdentity,
        now_ms: i64,
    ) -> Result<Vec<MultipartPart>, AbortMutationError>;
    async fn delete_terminal_upload(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<(), StagingError>;
    async fn retire_terminal_uploads(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, StagingError>;
    async fn reap_expired(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<MultipartPart>, StagingError>;
    async fn audit(&self, audit: CleanupAudit) -> Result<(), StagingError>;
}

#[derive(Default)]
struct MemoryState {
    uploads: HashMap<String, MultipartUpload>,
    parts: HashMap<(String, u32), MultipartPart>,
    attempts: HashMap<String, MemoryAttempt>,
    audits: Vec<CleanupAudit>,
    pending: HashMap<String, PendingPart>,
}

#[derive(Clone)]
struct MemoryAttempt {
    part: MultipartPart,
    reserved_bytes: u64,
    lifecycle: &'static str,
}

/// Test/development implementation. Production construction intentionally
/// requires a durable Postgres repository and never falls back to this type.
#[derive(Clone)]
pub struct InMemoryMultipartRepository {
    state: Arc<Mutex<MemoryState>>,
    quotas: StagingQuotaLimits,
}

#[derive(Clone, Debug)]
pub struct PostgresMultipartRepository {
    db: DatabaseConnection,
    quotas: StagingQuotaLimits,
}

impl PostgresMultipartRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self::with_quotas(
            pool,
            StagingQuotaLimits {
                tenant_bytes: i64::MAX as u64,
                global_bytes: i64::MAX as u64,
            },
        )
    }

    #[cfg(any(test, debug_assertions))]
    pub fn fail_next_abort_after_update() {
        FAIL_ABORT_AFTER_UPDATE.store(true, Ordering::Release);
    }

    pub fn with_quotas(pool: sqlx::PgPool, quotas: StagingQuotaLimits) -> Self {
        Self {
            db: SqlxPostgresConnector::from_sqlx_postgres_pool(pool),
            quotas,
        }
    }

    async fn release_artifact(&self, artifact_key: &str) -> Result<(), StagingError> {
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let attempt = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::ArtifactKey.eq(artifact_key.to_string()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let Some(attempt) = attempt else {
            tx.commit()
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            return Ok(());
        };
        let upload = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(attempt.upload_id.clone()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or_else(|| StagingError::Persistence("multipart upload disappeared".to_string()))?;
        let global_scope = global_quota_scope();
        let tenant_scope = tenant_quota_scope(&upload.tenant_id);
        let global = lock_quota(&tx, &global_scope).await?;
        let tenant = lock_quota(&tx, &tenant_scope).await?;
        let pending = attempt.lifecycle == "PENDING";
        let bytes = if pending {
            attempt.reserved_bytes
        } else {
            attempt.size_bytes
        };
        if bytes < 0 {
            return Err(StagingError::Persistence(
                "negative artifact bytes".to_string(),
            ));
        }
        let mut active: multipart_upload::ActiveModel = upload.clone().into();
        if pending {
            if upload.reserved_bytes < bytes
                || global.reserved_bytes < bytes
                || tenant.reserved_bytes < bytes
            {
                return Err(StagingError::Persistence(
                    "multipart reservation underflow".to_string(),
                ));
            }
            active.reserved_bytes = Set(upload.reserved_bytes - bytes);
        } else {
            if upload.staged_bytes < bytes
                || global.staged_bytes < bytes
                || tenant.staged_bytes < bytes
            {
                return Err(StagingError::Persistence(
                    "multipart staged bytes underflow".to_string(),
                ));
            }
            active.staged_bytes = Set(upload.staged_bytes - bytes);
        }
        let now = now_ms();
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        if pending {
            update_quota(
                &tx,
                global.clone(),
                global.staged_bytes,
                global.reserved_bytes - bytes,
                now,
            )
            .await?;
            update_quota(
                &tx,
                tenant.clone(),
                tenant.staged_bytes,
                tenant.reserved_bytes - bytes,
                now,
            )
            .await?;
        } else {
            update_quota(
                &tx,
                global.clone(),
                global.staged_bytes - bytes,
                global.reserved_bytes,
                now,
            )
            .await?;
            update_quota(
                &tx,
                tenant.clone(),
                tenant.staged_bytes - bytes,
                tenant.reserved_bytes,
                now,
            )
            .await?;
        }
        multipart_part_attempt::Entity::delete_by_id(attempt.id)
            .exec(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
}

fn upload_model(upload: &MultipartUpload) -> Result<multipart_upload::ActiveModel, StagingError> {
    Ok(multipart_upload::ActiveModel {
        id: Set(Uuid::now_v7()),
        upload_id: Set(upload.identity.upload_id.clone()),
        lifecycle: Set(lifecycle_name(upload.lifecycle).to_string()),
        tenant_id: Set(upload.identity.tenant_id.clone()),
        namespace_epoch: Set(upload
            .namespace_epoch
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                StagingError::Persistence("namespace epoch exceeds BIGINT".to_string())
            })?),
        credential_policy_id: Set(upload.identity.credential_policy_id.clone()),
        bucket: Set(upload.identity.bucket.clone()),
        object_key: Set(upload.identity.key.clone()),
        metadata: Set(serde_json::to_value(&upload.snapshot.metadata).map_err(json_error)?),
        tags: Set(serde_json::to_value(&upload.snapshot.tags).map_err(json_error)?),
        checksum_mode: Set(upload.snapshot.checksum_mode.clone()),
        destination: Set(upload.snapshot.destination.clone()),
        plugin_snapshot: Set(upload.snapshot.plugin_snapshot.clone()),
        limits: Set(serde_json::json!({"max_staged_bytes": upload.snapshot.max_staged_bytes})),
        staged_bytes: Set(
            i64::try_from(upload.staged_bytes).map_err(|_| StagingError::QuotaExceeded)?
        ),
        reserved_bytes: Set(
            i64::try_from(upload.reserved_bytes).map_err(|_| StagingError::QuotaExceeded)?
        ),
        expires_at_ms: Set(upload.expires_at_ms),
        tombstone_until_ms: Set(upload.tombstone_until_ms),
        complete_request_fingerprint: Set(upload.complete_request_fingerprint.clone()),
        completion_lease_owner: Set(upload.completion_lease_owner.clone()),
        completion_lease_expires_at_ms: Set(upload.completion_lease_expires_at_ms),
        completion_fencing_token: Set(i64::try_from(upload.completion_fencing_token).map_err(
            |_| StagingError::Persistence("invalid completion fencing token".to_string()),
        )?),
        completion_result: Set(upload
            .completion_result
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(json_error)?),
        created_at_ms: Set(upload.created_at_ms),
        updated_at_ms: Set(upload.updated_at_ms),
    })
}

fn lifecycle_name(lifecycle: MultipartLifecycle) -> &'static str {
    match lifecycle {
        MultipartLifecycle::Open => "OPEN",
        MultipartLifecycle::Completing => "COMPLETING",
        MultipartLifecycle::Completed => "COMPLETED",
        MultipartLifecycle::Aborted => "ABORTED",
        MultipartLifecycle::Expired => "EXPIRED",
    }
}
fn lifecycle(value: &str) -> Result<MultipartLifecycle, StagingError> {
    match value {
        "OPEN" => Ok(MultipartLifecycle::Open),
        "COMPLETING" => Ok(MultipartLifecycle::Completing),
        "COMPLETED" => Ok(MultipartLifecycle::Completed),
        "ABORTED" => Ok(MultipartLifecycle::Aborted),
        "EXPIRED" => Ok(MultipartLifecycle::Expired),
        _ => Err(StagingError::Persistence(
            "invalid multipart lifecycle".to_string(),
        )),
    }
}
fn json_error(error: serde_json::Error) -> StagingError {
    StagingError::Persistence(error.to_string())
}
fn upload_from_model(model: multipart_upload::Model) -> Result<MultipartUpload, StagingError> {
    let metadata = serde_json::from_value(model.metadata).map_err(json_error)?;
    let tags = serde_json::from_value(model.tags).map_err(json_error)?;
    let max_staged_bytes = model
        .limits
        .get("max_staged_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| StagingError::Persistence("invalid multipart limits".to_string()))?;
    Ok(MultipartUpload {
        identity: MultipartIdentity {
            tenant_id: model.tenant_id,
            credential_policy_id: model.credential_policy_id,
            bucket: model.bucket,
            key: model.object_key,
            upload_id: model.upload_id,
        },
        namespace_epoch: model
            .namespace_epoch
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StagingError::Persistence("invalid namespace epoch".to_string()))?,
        snapshot: MultipartSnapshot {
            metadata,
            tags,
            checksum_mode: model.checksum_mode,
            destination: model.destination,
            plugin_snapshot: model.plugin_snapshot,
            max_staged_bytes,
        },
        lifecycle: lifecycle(&model.lifecycle)?,
        staged_bytes: u64::try_from(model.staged_bytes)
            .map_err(|_| StagingError::Persistence("negative staged bytes".to_string()))?,
        reserved_bytes: u64::try_from(model.reserved_bytes)
            .map_err(|_| StagingError::Persistence("negative reserved bytes".to_string()))?,
        created_at_ms: model.created_at_ms,
        expires_at_ms: model.expires_at_ms,
        updated_at_ms: model.updated_at_ms,
        tombstone_until_ms: model.tombstone_until_ms,
        complete_request_fingerprint: model.complete_request_fingerprint,
        completion_lease_owner: model.completion_lease_owner,
        completion_lease_expires_at_ms: model.completion_lease_expires_at_ms,
        completion_fencing_token: u64::try_from(model.completion_fencing_token).map_err(|_| {
            StagingError::Persistence("negative completion fencing token".to_string())
        })?,
        completion_result: model
            .completion_result
            .map(serde_json::from_value)
            .transpose()
            .map_err(json_error)?,
    })
}
fn part_from_model(model: multipart_part_attempt::Model) -> Result<MultipartPart, StagingError> {
    Ok(MultipartPart {
        upload_id: model.upload_id,
        part_number: u32::try_from(model.part_number).map_err(|_| StagingError::InvalidPart)?,
        attempt: u32::try_from(model.attempt).map_err(|_| StagingError::InvalidPart)?,
        artifact_key: model.artifact_key,
        etag: model.etag,
        checksum_sha256: model.checksum_sha256,
        size_bytes: u64::try_from(model.size_bytes)
            .map_err(|_| StagingError::Persistence("negative part size".to_string()))?,
        created_at_ms: model.created_at_ms,
    })
}

pub fn completion_fingerprint(
    upload: &MultipartUpload,
    parts: &[CompletePart],
) -> Result<String, StagingError> {
    // Serialize only immutable upload inputs and canonical client selection.
    // BTreeMap-backed metadata/tags keep the fingerprint stable across retries.
    let encoded = serde_json::to_vec(&serde_json::json!({
        "identity": upload.identity,
        "parts": parts,
        "metadata": upload.snapshot.metadata,
        "tags": upload.snapshot.tags,
        "checksum_mode": upload.snapshot.checksum_mode,
        "destination": upload.snapshot.destination,
        "plugin_snapshot": upload.snapshot.plugin_snapshot,
        "limits": upload.snapshot.max_staged_bytes,
    }))
    .map_err(json_error)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn validate_selected_parts(
    current: &[MultipartPart],
    requested: &[CompletePart],
) -> Result<Vec<MultipartPart>, StagingError> {
    if requested.is_empty() {
        return Err(StagingError::InvalidPart);
    }
    let mut previous = 0;
    let mut selected = Vec::with_capacity(requested.len());
    for request in requested {
        if request.part_number == 0 || request.part_number <= previous {
            return Err(StagingError::InvalidPart);
        }
        previous = request.part_number;
        let part = current
            .iter()
            .find(|part| part.part_number == request.part_number)
            .ok_or(StagingError::InvalidPart)?;
        if part.etag != request.etag
            || request
                .checksum_sha256
                .as_deref()
                .is_some_and(|checksum| checksum != part.checksum_sha256)
        {
            return Err(StagingError::InvalidPart);
        }
        selected.push(part.clone());
    }
    Ok(selected)
}

fn global_quota_scope() -> String {
    "global".to_string()
}
fn tenant_quota_scope(tenant_id: &str) -> String {
    format!("tenant:{tenant_id}")
}
fn as_i64(bytes: u64) -> Result<i64, StagingError> {
    i64::try_from(bytes).map_err(|_| StagingError::QuotaExceeded)
}
fn as_u64(bytes: i64) -> Result<u64, StagingError> {
    u64::try_from(bytes)
        .map_err(|_| StagingError::Persistence("negative byte accounting".to_string()))
}

async fn ensure_quota_scope(
    tx: &DatabaseTransaction,
    scope: String,
    limit_bytes: u64,
    now: i64,
) -> Result<(), StagingError> {
    multipart_staging_quota::Entity::insert(multipart_staging_quota::ActiveModel {
        scope: Set(scope),
        limit_bytes: Set(as_i64(limit_bytes)?),
        staged_bytes: Set(0),
        reserved_bytes: Set(0),
        updated_at_ms: Set(now),
    })
    .on_conflict(
        OnConflict::column(multipart_staging_quota::Column::Scope)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(tx)
    .await
    .map_err(|error| StagingError::Persistence(error.to_string()))?;
    Ok(())
}

async fn lock_quota(
    tx: &DatabaseTransaction,
    scope: &str,
) -> Result<multipart_staging_quota::Model, StagingError> {
    multipart_staging_quota::Entity::find_by_id(scope.to_string())
        .lock_exclusive()
        .one(tx)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?
        .ok_or_else(|| StagingError::Persistence("missing multipart quota scope".to_string()))
}

async fn update_quota(
    tx: &DatabaseTransaction,
    model: multipart_staging_quota::Model,
    staged_bytes: i64,
    reserved_bytes: i64,
    now: i64,
) -> Result<(), StagingError> {
    if staged_bytes < 0 || reserved_bytes < 0 {
        return Err(StagingError::Persistence(
            "negative multipart quota".to_string(),
        ));
    }
    let mut active: multipart_staging_quota::ActiveModel = model.into();
    active.staged_bytes = Set(staged_bytes);
    active.reserved_bytes = Set(reserved_bytes);
    active.updated_at_ms = Set(now);
    active
        .update(tx)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?;
    Ok(())
}

#[async_trait]
impl MultipartRepository for PostgresMultipartRepository {
    fn is_durable(&self) -> bool {
        true
    }
    async fn create(&self, upload: MultipartUpload) -> Result<(), StagingError> {
        let active = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::TenantId.eq(upload.identity.tenant_id.clone()))
            .filter(multipart_upload::Column::Lifecycle.eq("OPEN"))
            .count(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        if active >= MAX_ACTIVE_UPLOADS as u64 {
            return Err(StagingError::QuotaExceeded);
        }
        upload_model(&upload)?
            .insert(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
    async fn get_authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<MultipartUpload, StagingError> {
        multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .one(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)
            .and_then(upload_from_model)
    }
    async fn replace_part(
        &self,
        identity: &MultipartIdentity,
        part: MultipartPart,
    ) -> Result<Option<MultipartPart>, StagingError> {
        if part.part_number == 0 || part.part_number > MAX_PARTS {
            return Err(StagingError::InvalidPart);
        }
        let transaction = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let mut upload = upload_from_model(model.clone())?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let previous = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::PartNumber.eq(part.part_number as i32))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .one(&transaction)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .map(part_from_model)
            .transpose()?;
        if let Some(old) = &previous
            && part.attempt <= old.attempt
        {
            return Err(StagingError::Persistence(
                "stale part replacement".to_string(),
            ));
        }
        let next = upload
            .staged_bytes
            .saturating_sub(previous.as_ref().map_or(0, |old| old.size_bytes))
            .saturating_add(part.size_bytes);
        if next > upload.snapshot.max_staged_bytes {
            return Err(StagingError::QuotaExceeded);
        }
        if previous.is_some() {
            multipart_part_attempt::Entity::update_many()
                .col_expr(
                    multipart_part_attempt::Column::IsCurrent,
                    sea_orm::sea_query::Expr::value(false),
                )
                .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
                .filter(multipart_part_attempt::Column::PartNumber.eq(part.part_number as i32))
                .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
                .exec(&transaction)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
        }
        multipart_part_attempt::ActiveModel {
            id: Set(Uuid::now_v7()),
            upload_id: Set(part.upload_id.clone()),
            part_number: Set(part.part_number as i32),
            attempt: Set(part.attempt as i32),
            artifact_key: Set(part.artifact_key.clone()),
            etag: Set(part.etag.clone()),
            checksum_sha256: Set(part.checksum_sha256.clone()),
            size_bytes: Set(
                i64::try_from(part.size_bytes).map_err(|_| StagingError::QuotaExceeded)?
            ),
            reserved_bytes: Set(0),
            lifecycle: Set("CURRENT".to_string()),
            is_current: Set(true),
            created_at_ms: Set(part.created_at_ms),
        }
        .insert(&transaction)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?;
        upload.staged_bytes = next;
        upload.updated_at_ms = now_ms();
        let mut active: multipart_upload::ActiveModel = model.into();
        active.staged_bytes = Set(next as i64);
        active.updated_at_ms = Set(upload.updated_at_ms);
        active
            .update(&transaction)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        transaction
            .commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(previous)
    }
    async fn begin_part(
        &self,
        identity: &MultipartIdentity,
        part_number: u32,
        reserved_bytes: u64,
        now: i64,
    ) -> Result<PendingPart, StagingError> {
        if part_number == 0 || part_number > MAX_PARTS || reserved_bytes == 0 {
            return Err(StagingError::InvalidPart);
        }
        let reserved = as_i64(reserved_bytes)?;
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let upload = upload_from_model(model.clone())?;
        if upload.lifecycle != MultipartLifecycle::Open || upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        let upload_next = upload
            .staged_bytes
            .checked_add(upload.reserved_bytes)
            .and_then(|bytes| bytes.checked_add(reserved_bytes))
            .ok_or(StagingError::QuotaExceeded)?;
        if upload_next > upload.snapshot.max_staged_bytes {
            return Err(StagingError::QuotaExceeded);
        }
        // Always lock account first, then tenant, preventing cross-tenant deadlocks.
        let global_scope = global_quota_scope();
        let tenant_scope = tenant_quota_scope(&identity.tenant_id);
        ensure_quota_scope(&tx, global_scope.clone(), self.quotas.global_bytes, now).await?;
        ensure_quota_scope(&tx, tenant_scope.clone(), self.quotas.tenant_bytes, now).await?;
        let global = lock_quota(&tx, &global_scope).await?;
        let tenant = lock_quota(&tx, &tenant_scope).await?;
        for quota in [&global, &tenant] {
            let used = as_u64(quota.staged_bytes)?
                .checked_add(as_u64(quota.reserved_bytes)?)
                .ok_or(StagingError::QuotaExceeded)?;
            if used
                .checked_add(reserved_bytes)
                .ok_or(StagingError::QuotaExceeded)?
                > as_u64(quota.limit_bytes)?
            {
                return Err(StagingError::QuotaExceeded);
            }
        }
        let attempt = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::PartNumber.eq(part_number as i32))
            .order_by_desc(multipart_part_attempt::Column::Attempt)
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .map(|value| u32::try_from(value.attempt).map_err(|_| StagingError::InvalidPart))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StagingError::InvalidPart)?;
        let pending = PendingPart {
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            artifact_key: format!(
                "{ARTIFACT_PREFIX}{}/{}/{}/{}",
                identity.tenant_id,
                identity.upload_id,
                part_number,
                Uuid::now_v7()
            ),
            reserved_bytes,
        };
        multipart_part_attempt::ActiveModel {
            id: Set(Uuid::now_v7()),
            upload_id: Set(pending.upload_id.clone()),
            part_number: Set(part_number as i32),
            attempt: Set(attempt as i32),
            artifact_key: Set(pending.artifact_key.clone()),
            etag: Set(String::new()),
            checksum_sha256: Set(String::new()),
            size_bytes: Set(0),
            reserved_bytes: Set(reserved),
            lifecycle: Set("PENDING".to_string()),
            is_current: Set(false),
            created_at_ms: Set(now),
        }
        .insert(&tx)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut active: multipart_upload::ActiveModel = model.into();
        active.reserved_bytes = Set(as_i64(
            upload
                .reserved_bytes
                .checked_add(reserved_bytes)
                .ok_or(StagingError::QuotaExceeded)?,
        )?);
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        update_quota(
            &tx,
            global.clone(),
            global.staged_bytes,
            global
                .reserved_bytes
                .checked_add(reserved)
                .ok_or(StagingError::QuotaExceeded)?,
            now,
        )
        .await?;
        update_quota(
            &tx,
            tenant.clone(),
            tenant.staged_bytes,
            tenant
                .reserved_bytes
                .checked_add(reserved)
                .ok_or(StagingError::QuotaExceeded)?,
            now,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(pending)
    }
    async fn commit_part(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
        part: MultipartPart,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        if part.upload_id != pending.upload_id
            || part.part_number != pending.part_number
            || part.attempt != pending.attempt
            || part.artifact_key != pending.artifact_key
            || part.size_bytes > pending.reserved_bytes
        {
            return Err(StagingError::InvalidPart);
        }
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let upload = upload_from_model(model.clone())?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let pending_model = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::ArtifactKey.eq(pending.artifact_key.clone()))
            .filter(multipart_part_attempt::Column::Lifecycle.eq("PENDING"))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        if pending_model.upload_id != identity.upload_id
            || pending_model.reserved_bytes != as_i64(pending.reserved_bytes)?
        {
            return Err(StagingError::NotFound);
        }
        let previous: Vec<_> = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::PartNumber.eq(part.part_number as i32))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .all(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(part_from_model)
            .collect::<Result<_, _>>()?;
        let global_scope = global_quota_scope();
        let tenant_scope = tenant_quota_scope(&identity.tenant_id);
        let global = lock_quota(&tx, &global_scope).await?;
        let tenant = lock_quota(&tx, &tenant_scope).await?;
        let reserved = as_i64(pending.reserved_bytes)?;
        let actual = as_i64(part.size_bytes)?;
        if upload.reserved_bytes < pending.reserved_bytes
            || global.reserved_bytes < reserved
            || tenant.reserved_bytes < reserved
        {
            return Err(StagingError::Persistence(
                "multipart reservation missing".to_string(),
            ));
        }
        multipart_part_attempt::Entity::update_many()
            .col_expr(
                multipart_part_attempt::Column::IsCurrent,
                Expr::value(false),
            )
            .col_expr(
                multipart_part_attempt::Column::Lifecycle,
                Expr::value("RETIRED"),
            )
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::PartNumber.eq(part.part_number as i32))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .exec(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        multipart_part_attempt::Entity::update_many()
            .col_expr(multipart_part_attempt::Column::Etag, Expr::value(part.etag))
            .col_expr(
                multipart_part_attempt::Column::ChecksumSha256,
                Expr::value(part.checksum_sha256),
            )
            .col_expr(
                multipart_part_attempt::Column::SizeBytes,
                Expr::value(actual),
            )
            .col_expr(
                multipart_part_attempt::Column::ReservedBytes,
                Expr::value(0),
            )
            .col_expr(
                multipart_part_attempt::Column::Lifecycle,
                Expr::value("CURRENT"),
            )
            .col_expr(multipart_part_attempt::Column::IsCurrent, Expr::value(true))
            .filter(multipart_part_attempt::Column::ArtifactKey.eq(pending.artifact_key.clone()))
            .filter(multipart_part_attempt::Column::Lifecycle.eq("PENDING"))
            .exec(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let now = now_ms();
        let mut active: multipart_upload::ActiveModel = model.into();
        active.reserved_bytes = Set(as_i64(upload.reserved_bytes - pending.reserved_bytes)?);
        active.staged_bytes = Set(as_i64(
            upload
                .staged_bytes
                .checked_add(part.size_bytes)
                .ok_or(StagingError::QuotaExceeded)?,
        )?);
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        update_quota(
            &tx,
            global.clone(),
            global
                .staged_bytes
                .checked_add(actual)
                .ok_or(StagingError::QuotaExceeded)?,
            global.reserved_bytes - reserved,
            now,
        )
        .await?;
        update_quota(
            &tx,
            tenant.clone(),
            tenant
                .staged_bytes
                .checked_add(actual)
                .ok_or(StagingError::QuotaExceeded)?,
            tenant.reserved_bytes - reserved,
            now,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(previous)
    }
    async fn discard_pending(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
    ) -> Result<(), StagingError> {
        let _ = identity;
        self.release_artifact(&pending.artifact_key).await
    }
    async fn cleanup_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<CleanupCandidate>, StagingError> {
        let attempts = multipart_part_attempt::Entity::find()
            .order_by_asc(multipart_part_attempt::Column::CreatedAtMs)
            .limit((limit.saturating_mul(4)) as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut result = Vec::new();
        for attempt in attempts {
            let upload = multipart_upload::Entity::find()
                .filter(multipart_upload::Column::UploadId.eq(attempt.upload_id.clone()))
                .one(&self.db)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            let Some(upload) = upload else { continue };
            let pending_is_old = attempt.lifecycle == "PENDING"
                && attempt.created_at_ms <= now - RECONCILIATION_GRACE.as_millis() as i64;
            if upload.lifecycle != "OPEN" || attempt.lifecycle == "RETIRED" || pending_is_old {
                result.push(CleanupCandidate {
                    upload_id: attempt.upload_id,
                    artifact_key: attempt.artifact_key,
                });
                if result.len() == limit {
                    break;
                }
            }
        }
        Ok(result)
    }
    async fn confirm_artifact_deleted(&self, artifact_key: &str) -> Result<(), StagingError> {
        let attempt = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::ArtifactKey.eq(artifact_key.to_string()))
            .one(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        if attempt.is_none() {
            return Ok(());
        }
        self.release_artifact(artifact_key).await
    }
    async fn known_artifact_keys(&self) -> Result<HashMap<String, i64>, StagingError> {
        Ok(multipart_part_attempt::Entity::find()
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(|part| (part.artifact_key, part.created_at_ms))
            .collect())
    }
    async fn list_parts(
        &self,
        identity: &MultipartIdentity,
        marker: u32,
        limit: usize,
    ) -> Result<(Vec<MultipartPart>, bool), StagingError> {
        self.get_authorized(identity).await?;
        let mut parts: Vec<_> = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .filter(multipart_part_attempt::Column::PartNumber.gt(marker as i32))
            .order_by_asc(multipart_part_attempt::Column::PartNumber)
            .limit((limit + 1) as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(part_from_model)
            .collect::<Result<_, _>>()?;
        let truncated = parts.len() > limit;
        parts.truncate(limit);
        Ok((parts, truncated))
    }
    async fn acquire_completion(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        parts: &[CompletePart],
        owner: &str,
        lease_expires_at_ms: i64,
        now: i64,
    ) -> Result<CompletionAcquire, StagingError> {
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let upload = upload_from_model(model.clone())?;
        if upload.lifecycle == MultipartLifecycle::Completed {
            let result = upload.completion_result.ok_or_else(|| {
                StagingError::Persistence("completed upload is missing its result".to_string())
            })?;
            tx.commit()
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            return if upload.complete_request_fingerprint.as_deref() == Some(fingerprint) {
                Ok(CompletionAcquire::Replayed(result))
            } else {
                Err(StagingError::CompletionConflict)
            };
        }
        if upload.lifecycle == MultipartLifecycle::Aborted
            || upload.lifecycle == MultipartLifecycle::Expired
        {
            return Err(StagingError::NotOpen);
        }
        if upload.lifecycle == MultipartLifecycle::Completing
            && upload.complete_request_fingerprint.as_deref() != Some(fingerprint)
        {
            return Err(StagingError::CompletionConflict);
        }
        if upload.lifecycle == MultipartLifecycle::Completing
            && upload
                .completion_lease_expires_at_ms
                .is_some_and(|expires| expires > now)
        {
            tx.commit()
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            return Ok(CompletionAcquire::Busy);
        }
        if upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        let cleanup_parts: Vec<_> = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .order_by_asc(multipart_part_attempt::Column::PartNumber)
            .all(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(part_from_model)
            .collect::<Result<_, _>>()?;
        let selected_parts = validate_selected_parts(&cleanup_parts, parts)?;
        let fencing_token = upload
            .completion_fencing_token
            .checked_add(1)
            .ok_or_else(|| {
                StagingError::Persistence("completion fencing token exhausted".to_string())
            })?;
        let mut active: multipart_upload::ActiveModel = model.into();
        active.lifecycle = Set("COMPLETING".to_string());
        active.complete_request_fingerprint = Set(Some(fingerprint.to_string()));
        active.completion_lease_owner = Set(Some(owner.to_string()));
        active.completion_lease_expires_at_ms = Set(Some(lease_expires_at_ms));
        active.completion_fencing_token = Set(i64::try_from(fencing_token).map_err(|_| {
            StagingError::Persistence("invalid completion fencing token".to_string())
        })?);
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(CompletionAcquire::Acquired(CompletionLease {
            fencing_token,
            selected_parts,
            cleanup_parts,
        }))
    }
    async fn renew_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        lease_expires_at_ms: i64,
    ) -> Result<(), StagingError> {
        let result = multipart_upload::Entity::update_many()
            .col_expr(
                multipart_upload::Column::CompletionLeaseExpiresAtMs,
                Expr::value(Some(lease_expires_at_ms)),
            )
            .col_expr(multipart_upload::Column::UpdatedAtMs, Expr::value(now_ms()))
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(multipart_upload::Column::Lifecycle.eq("COMPLETING"))
            .filter(
                multipart_upload::Column::CompletionFencingToken
                    .eq(i64::try_from(fencing_token).map_err(|_| StagingError::Fenced)?),
            )
            .exec(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        (result.rows_affected == 1)
            .then_some(())
            .ok_or(StagingError::Fenced)
    }
    async fn check_completion_lease(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        now: i64,
    ) -> Result<(), StagingError> {
        let upload = self.get_authorized(identity).await?;
        (upload.lifecycle == MultipartLifecycle::Completing
            && upload.completion_fencing_token == fencing_token
            && upload
                .completion_lease_expires_at_ms
                .is_some_and(|expires| expires > now))
        .then_some(())
        .ok_or(StagingError::Fenced)
    }
    async fn complete_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        result: MultipartCompletionResult,
        now: i64,
    ) -> Result<(), StagingError> {
        self.check_completion_lease(identity, fencing_token, now)
            .await?;
        let result_json = serde_json::to_value(&result).map_err(json_error)?;
        let updated = multipart_upload::Entity::update_many()
            .col_expr(
                multipart_upload::Column::Lifecycle,
                Expr::value("COMPLETED"),
            )
            .col_expr(
                multipart_upload::Column::CompletionResult,
                Expr::value(result_json),
            )
            .col_expr(
                multipart_upload::Column::CompletionLeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                multipart_upload::Column::CompletionLeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                multipart_upload::Column::TombstoneUntilMs,
                Expr::value(Some(now + DEFAULT_EXPIRY.as_millis() as i64)),
            )
            .col_expr(multipart_upload::Column::UpdatedAtMs, Expr::value(now))
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::Lifecycle.eq("COMPLETING"))
            .filter(
                multipart_upload::Column::CompletionFencingToken
                    .eq(i64::try_from(fencing_token).map_err(|_| StagingError::Fenced)?),
            )
            .exec(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        (updated.rows_affected == 1)
            .then_some(())
            .ok_or(StagingError::Fenced)
    }
    async fn abort(
        &self,
        identity: &MultipartIdentity,
        now: i64,
    ) -> Result<Vec<MultipartPart>, AbortMutationError> {
        let upload = self
            .get_authorized(identity)
            .await
            .map_err(AbortMutationError::PreMutation)?;
        if upload.lifecycle == MultipartLifecycle::Aborted {
            return Ok(Vec::new());
        }
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(AbortMutationError::PreMutation(StagingError::NotOpen));
        }
        let result = multipart_upload::Entity::update_many()
            .col_expr(
                multipart_upload::Column::Lifecycle,
                sea_orm::sea_query::Expr::value("ABORTED"),
            )
            .col_expr(
                multipart_upload::Column::TombstoneUntilMs,
                sea_orm::sea_query::Expr::value(Some(now + DEFAULT_EXPIRY.as_millis() as i64)),
            )
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::Lifecycle.eq("OPEN"))
            .exec(&self.db)
            .await
            .map_err(|error| {
                AbortMutationError::MutationUnknown(StagingError::Persistence(error.to_string()))
            })?;
        if result.rows_affected != 1 {
            return Err(AbortMutationError::PreMutation(StagingError::NotOpen));
        }
        #[cfg(any(test, debug_assertions))]
        if FAIL_ABORT_AFTER_UPDATE.swap(false, Ordering::AcqRel) {
            return Err(AbortMutationError::MutationUnknown(
                StagingError::Persistence("injected post-abort persistence failure".to_string()),
            ));
        }
        self.list_parts(identity, 0, MAX_PARTS as usize)
            .await
            .map(|value| value.0)
            .map_err(AbortMutationError::MutationUnknown)
    }
    async fn delete_terminal_upload(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<(), StagingError> {
        let upload = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(&identity.upload_id))
            .filter(multipart_upload::Column::TenantId.eq(&identity.tenant_id))
            .filter(multipart_upload::Column::CredentialPolicyId.eq(&identity.credential_policy_id))
            .filter(multipart_upload::Column::Bucket.eq(&identity.bucket))
            .filter(multipart_upload::Column::ObjectKey.eq(&identity.key))
            .one(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        if !matches!(upload.lifecycle.as_str(), "ABORTED" | "EXPIRED") {
            return Err(StagingError::NotOpen);
        }
        let attempts = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(&identity.upload_id))
            .count(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        if attempts > 0 {
            return Err(StagingError::Persistence(
                "multipart artifacts remain after cleanup".to_string(),
            ));
        }
        multipart_upload::Entity::delete_by_id(upload.id)
            .exec(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
    async fn retire_terminal_uploads(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, StagingError> {
        let candidates = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::Lifecycle.is_in(["COMPLETED", "ABORTED", "EXPIRED"]))
            .filter(multipart_upload::Column::TombstoneUntilMs.lte(now_ms))
            .order_by_asc(multipart_upload::Column::UpdatedAtMs)
            .limit(limit as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut retired = Vec::new();
        for upload in candidates {
            let attempts = multipart_part_attempt::Entity::find()
                .filter(multipart_part_attempt::Column::UploadId.eq(&upload.upload_id))
                .count(&self.db)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            if attempts > 0 {
                continue;
            }
            multipart_upload::Entity::delete_by_id(upload.id)
                .exec(&self.db)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            retired.push(RetiredMultipartUpload {
                upload_id: upload.upload_id,
                tenant_id: upload.tenant_id,
                namespace_epoch: upload
                    .namespace_epoch
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| {
                        StagingError::Persistence("invalid namespace epoch".to_string())
                    })?,
            });
        }
        Ok(retired)
    }
    async fn reap_expired(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        let uploads = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::Lifecycle.eq("OPEN"))
            .filter(multipart_upload::Column::ExpiresAtMs.lte(now))
            .limit(limit as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut parts = Vec::new();
        for model in uploads {
            multipart_upload::Entity::update_many()
                .col_expr(
                    multipart_upload::Column::Lifecycle,
                    sea_orm::sea_query::Expr::value("EXPIRED"),
                )
                .col_expr(
                    multipart_upload::Column::TombstoneUntilMs,
                    Expr::value(Some(now + DEFAULT_EXPIRY.as_millis() as i64)),
                )
                .col_expr(multipart_upload::Column::UpdatedAtMs, Expr::value(now))
                .filter(multipart_upload::Column::UploadId.eq(model.upload_id.clone()))
                .filter(multipart_upload::Column::Lifecycle.eq("OPEN"))
                .exec(&self.db)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            parts.extend(
                multipart_part_attempt::Entity::find()
                    .filter(multipart_part_attempt::Column::UploadId.eq(model.upload_id))
                    .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
                    .all(&self.db)
                    .await
                    .map_err(|error| StagingError::Persistence(error.to_string()))?
                    .into_iter()
                    .map(part_from_model)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        Ok(parts)
    }
    async fn audit(&self, audit: CleanupAudit) -> Result<(), StagingError> {
        multipart_cleanup_audit::ActiveModel {
            id: Set(audit.id),
            upload_id: Set(audit.upload_id),
            kind: Set(audit.kind),
            detail: Set(audit.detail),
            created_at_ms: Set(audit.created_at_ms),
        }
        .insert(&self.db)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
}

impl InMemoryMultipartRepository {
    pub fn new() -> Self {
        Self::with_quotas(StagingQuotaLimits {
            tenant_bytes: i64::MAX as u64,
            global_bytes: i64::MAX as u64,
        })
    }

    pub fn with_quotas(quotas: StagingQuotaLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryState::default())),
            quotas,
        }
    }
}

impl Default for InMemoryMultipartRepository {
    fn default() -> Self {
        Self::new()
    }
}

fn same_identity(upload: &MultipartUpload, identity: &MultipartIdentity) -> bool {
    upload.identity.tenant_id == identity.tenant_id
        && upload.identity.credential_policy_id == identity.credential_policy_id
        && upload.identity.bucket == identity.bucket
        && upload.identity.key == identity.key
        && upload.identity.upload_id == identity.upload_id
}

#[async_trait]
impl MultipartRepository for InMemoryMultipartRepository {
    fn is_durable(&self) -> bool {
        false
    }

    async fn create(&self, upload: MultipartUpload) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let active = state
            .uploads
            .values()
            .filter(|candidate| {
                candidate.identity.tenant_id == upload.identity.tenant_id
                    && candidate.lifecycle == MultipartLifecycle::Open
            })
            .count();
        if active >= MAX_ACTIVE_UPLOADS {
            return Err(StagingError::QuotaExceeded);
        }
        if state
            .uploads
            .insert(upload.identity.upload_id.clone(), upload)
            .is_some()
        {
            return Err(StagingError::Persistence("duplicate upload id".to_string()));
        }
        Ok(())
    }

    async fn get_authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<MultipartUpload, StagingError> {
        self.state
            .lock()
            .await
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .cloned()
            .ok_or(StagingError::NotFound)
    }

    async fn replace_part(
        &self,
        identity: &MultipartIdentity,
        part: MultipartPart,
    ) -> Result<Option<MultipartPart>, StagingError> {
        if part.part_number == 0 || part.part_number > MAX_PARTS {
            return Err(StagingError::InvalidPart);
        }
        let mut state = self.state.lock().await;
        let previous = state
            .parts
            .get(&(identity.upload_id.clone(), part.part_number))
            .cloned();
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let next = upload
            .staged_bytes
            .saturating_sub(previous.as_ref().map_or(0, |value| value.size_bytes))
            .saturating_add(part.size_bytes);
        if next > upload.snapshot.max_staged_bytes {
            return Err(StagingError::QuotaExceeded);
        }
        if let Some(previous) = &previous
            && part.attempt <= previous.attempt
        {
            return Err(StagingError::Persistence(
                "stale part replacement".to_string(),
            ));
        }
        upload.staged_bytes = next;
        upload.updated_at_ms = now_ms();
        state
            .parts
            .insert((identity.upload_id.clone(), part.part_number), part);
        Ok(previous)
    }

    async fn begin_part(
        &self,
        identity: &MultipartIdentity,
        part_number: u32,
        reserved_bytes: u64,
        now: i64,
    ) -> Result<PendingPart, StagingError> {
        if part_number == 0 || part_number > MAX_PARTS || reserved_bytes == 0 {
            return Err(StagingError::InvalidPart);
        }
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Open || upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        if upload
            .staged_bytes
            .checked_add(upload.reserved_bytes)
            .and_then(|used| used.checked_add(reserved_bytes))
            .ok_or(StagingError::QuotaExceeded)?
            > upload.snapshot.max_staged_bytes
        {
            return Err(StagingError::QuotaExceeded);
        }
        let (tenant_used, global_used) =
            state
                .uploads
                .values()
                .fold((0u64, 0u64), |(tenant, global), candidate| {
                    let used = candidate
                        .staged_bytes
                        .saturating_add(candidate.reserved_bytes);
                    (
                        tenant
                            + if candidate.identity.tenant_id == identity.tenant_id {
                                used
                            } else {
                                0
                            },
                        global.saturating_add(used),
                    )
                });
        if tenant_used
            .checked_add(reserved_bytes)
            .ok_or(StagingError::QuotaExceeded)?
            > self.quotas.tenant_bytes
            || global_used
                .checked_add(reserved_bytes)
                .ok_or(StagingError::QuotaExceeded)?
                > self.quotas.global_bytes
        {
            return Err(StagingError::QuotaExceeded);
        }
        let attempt = state
            .attempts
            .values()
            .filter(|value| {
                value.part.upload_id == identity.upload_id && value.part.part_number == part_number
            })
            .map(|value| value.part.attempt)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StagingError::InvalidPart)?;
        let pending = PendingPart {
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            artifact_key: format!(
                "{ARTIFACT_PREFIX}{}/{}/{}/{}",
                identity.tenant_id,
                identity.upload_id,
                part_number,
                Uuid::now_v7()
            ),
            reserved_bytes,
        };
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .expect("upload checked above");
        upload.reserved_bytes += reserved_bytes;
        upload.updated_at_ms = now;
        let part = MultipartPart {
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            artifact_key: pending.artifact_key.clone(),
            etag: String::new(),
            checksum_sha256: String::new(),
            size_bytes: 0,
            created_at_ms: now,
        };
        state.attempts.insert(
            pending.artifact_key.clone(),
            MemoryAttempt {
                part,
                reserved_bytes,
                lifecycle: "PENDING",
            },
        );
        state
            .pending
            .insert(pending.artifact_key.clone(), pending.clone());
        Ok(pending)
    }

    async fn commit_part(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
        part: MultipartPart,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        if part.upload_id != pending.upload_id
            || part.part_number != pending.part_number
            || part.attempt != pending.attempt
            || part.artifact_key != pending.artifact_key
            || part.size_bytes > pending.reserved_bytes
        {
            return Err(StagingError::InvalidPart);
        }
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .cloned()
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let previous = state
            .parts
            .get(&(identity.upload_id.clone(), part.part_number))
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        for old in &previous {
            if let Some(old_attempt) = state.attempts.get_mut(&old.artifact_key) {
                old_attempt.lifecycle = "RETIRED";
            }
        }
        {
            let attempt = state
                .attempts
                .get_mut(&pending.artifact_key)
                .ok_or(StagingError::NotFound)?;
            if attempt.lifecycle != "PENDING" || attempt.reserved_bytes != pending.reserved_bytes {
                return Err(StagingError::NotFound);
            }
            attempt.part = part.clone();
            attempt.reserved_bytes = 0;
            attempt.lifecycle = "CURRENT";
        }
        state.pending.remove(&pending.artifact_key);
        state
            .parts
            .insert((identity.upload_id.clone(), part.part_number), part.clone());
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .expect("upload checked above");
        upload.reserved_bytes = upload
            .reserved_bytes
            .checked_sub(pending.reserved_bytes)
            .ok_or_else(|| {
                StagingError::Persistence("multipart reservation missing".to_string())
            })?;
        upload.staged_bytes = upload
            .staged_bytes
            .checked_add(part.size_bytes)
            .ok_or(StagingError::QuotaExceeded)?;
        upload.updated_at_ms = now_ms();
        Ok(previous)
    }

    async fn discard_pending(
        &self,
        _identity: &MultipartIdentity,
        pending: &PendingPart,
    ) -> Result<(), StagingError> {
        self.confirm_artifact_deleted(&pending.artifact_key).await
    }

    async fn cleanup_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<CleanupCandidate>, StagingError> {
        let state = self.state.lock().await;
        Ok(state
            .attempts
            .iter()
            .filter_map(|(key, attempt)| {
                let upload = state.uploads.get(&attempt.part.upload_id)?;
                let old_pending = attempt.lifecycle == "PENDING"
                    && attempt.part.created_at_ms <= now - RECONCILIATION_GRACE.as_millis() as i64;
                (upload.lifecycle != MultipartLifecycle::Open
                    || attempt.lifecycle == "RETIRED"
                    || old_pending)
                    .then(|| CleanupCandidate {
                        upload_id: attempt.part.upload_id.clone(),
                        artifact_key: key.clone(),
                    })
            })
            .take(limit)
            .collect())
    }

    async fn confirm_artifact_deleted(&self, artifact_key: &str) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let Some(attempt) = state.attempts.remove(artifact_key) else {
            return Ok(());
        };
        state.pending.remove(artifact_key);
        state
            .parts
            .retain(|_, part| part.artifact_key != artifact_key);
        let upload = state
            .uploads
            .get_mut(&attempt.part.upload_id)
            .ok_or_else(|| StagingError::Persistence("multipart upload disappeared".to_string()))?;
        if attempt.lifecycle == "PENDING" {
            upload.reserved_bytes = upload
                .reserved_bytes
                .checked_sub(attempt.reserved_bytes)
                .ok_or_else(|| {
                    StagingError::Persistence("multipart reservation underflow".to_string())
                })?;
        } else {
            upload.staged_bytes = upload
                .staged_bytes
                .checked_sub(attempt.part.size_bytes)
                .ok_or_else(|| {
                    StagingError::Persistence("multipart staged bytes underflow".to_string())
                })?;
        }
        upload.updated_at_ms = now_ms();
        Ok(())
    }

    async fn known_artifact_keys(&self) -> Result<HashMap<String, i64>, StagingError> {
        Ok(self
            .state
            .lock()
            .await
            .attempts
            .iter()
            .map(|(key, value)| (key.clone(), value.part.created_at_ms))
            .collect())
    }

    async fn list_parts(
        &self,
        identity: &MultipartIdentity,
        marker: u32,
        limit: usize,
    ) -> Result<(Vec<MultipartPart>, bool), StagingError> {
        self.get_authorized(identity).await?;
        let mut parts: Vec<_> = self
            .state
            .lock()
            .await
            .parts
            .values()
            .filter(|part| part.upload_id == identity.upload_id && part.part_number > marker)
            .cloned()
            .collect();
        parts.sort_by_key(|part| part.part_number);
        let truncated = parts.len() > limit;
        parts.truncate(limit);
        Ok((parts, truncated))
    }

    async fn acquire_completion(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        parts: &[CompletePart],
        owner: &str,
        lease_expires_at_ms: i64,
        now: i64,
    ) -> Result<CompletionAcquire, StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .cloned()
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle == MultipartLifecycle::Completed {
            let result = upload.completion_result.ok_or_else(|| {
                StagingError::Persistence("completed upload is missing its result".to_string())
            })?;
            return if upload.complete_request_fingerprint.as_deref() == Some(fingerprint) {
                Ok(CompletionAcquire::Replayed(result))
            } else {
                Err(StagingError::CompletionConflict)
            };
        }
        if upload.lifecycle == MultipartLifecycle::Aborted
            || upload.lifecycle == MultipartLifecycle::Expired
        {
            return Err(StagingError::NotOpen);
        }
        if upload.lifecycle == MultipartLifecycle::Completing
            && upload.complete_request_fingerprint.as_deref() != Some(fingerprint)
        {
            return Err(StagingError::CompletionConflict);
        }
        if upload.lifecycle == MultipartLifecycle::Completing
            && upload
                .completion_lease_expires_at_ms
                .is_some_and(|expires| expires > now)
        {
            return Ok(CompletionAcquire::Busy);
        }
        if upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        let mut cleanup_parts: Vec<_> = state
            .parts
            .values()
            .filter(|part| part.upload_id == identity.upload_id)
            .cloned()
            .collect();
        cleanup_parts.sort_by_key(|part| part.part_number);
        let selected_parts = validate_selected_parts(&cleanup_parts, parts)?;
        let fencing_token = upload
            .completion_fencing_token
            .checked_add(1)
            .ok_or_else(|| {
                StagingError::Persistence("completion fencing token exhausted".to_string())
            })?;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .expect("upload cloned above");
        upload.lifecycle = MultipartLifecycle::Completing;
        upload.complete_request_fingerprint = Some(fingerprint.to_string());
        upload.completion_lease_owner = Some(owner.to_string());
        upload.completion_lease_expires_at_ms = Some(lease_expires_at_ms);
        upload.completion_fencing_token = fencing_token;
        upload.updated_at_ms = now;
        Ok(CompletionAcquire::Acquired(CompletionLease {
            fencing_token,
            selected_parts,
            cleanup_parts,
        }))
    }

    async fn renew_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        lease_expires_at_ms: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Completing
            || upload.completion_fencing_token != fencing_token
        {
            return Err(StagingError::Fenced);
        }
        upload.completion_lease_expires_at_ms = Some(lease_expires_at_ms);
        upload.updated_at_ms = now_ms();
        Ok(())
    }

    async fn check_completion_lease(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        now: i64,
    ) -> Result<(), StagingError> {
        let upload = self.get_authorized(identity).await?;
        (upload.lifecycle == MultipartLifecycle::Completing
            && upload.completion_fencing_token == fencing_token
            && upload
                .completion_lease_expires_at_ms
                .is_some_and(|expires| expires > now))
        .then_some(())
        .ok_or(StagingError::Fenced)
    }

    async fn complete_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        result: MultipartCompletionResult,
        now: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Completing
            || upload.completion_fencing_token != fencing_token
            || upload
                .completion_lease_expires_at_ms
                .is_none_or(|expires| expires <= now)
        {
            return Err(StagingError::Fenced);
        }
        upload.lifecycle = MultipartLifecycle::Completed;
        upload.completion_result = Some(result);
        upload.completion_lease_owner = None;
        upload.completion_lease_expires_at_ms = None;
        upload.tombstone_until_ms = Some(now + DEFAULT_EXPIRY.as_millis() as i64);
        upload.updated_at_ms = now;
        Ok(())
    }

    async fn abort(
        &self,
        identity: &MultipartIdentity,
        now_ms: i64,
    ) -> Result<Vec<MultipartPart>, AbortMutationError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(AbortMutationError::PreMutation(StagingError::NotFound))?;
        if upload.lifecycle != MultipartLifecycle::Open {
            if upload.lifecycle == MultipartLifecycle::Aborted {
                return Ok(Vec::new());
            }
            return Err(AbortMutationError::PreMutation(StagingError::NotOpen));
        }
        upload.lifecycle = MultipartLifecycle::Aborted;
        upload.tombstone_until_ms = Some(now_ms + DEFAULT_EXPIRY.as_millis() as i64);
        upload.updated_at_ms = now_ms;
        Ok(state
            .parts
            .extract_if(|(upload_id, _), _| upload_id == &identity.upload_id)
            .map(|(_, part)| part)
            .collect())
    }

    async fn delete_terminal_upload(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if !matches!(
            upload.lifecycle,
            MultipartLifecycle::Aborted | MultipartLifecycle::Expired
        ) || state
            .attempts
            .values()
            .any(|attempt| attempt.part.upload_id == identity.upload_id)
            || state
                .pending
                .values()
                .any(|pending| pending.upload_id == identity.upload_id)
        {
            return Err(StagingError::Persistence(
                "multipart artifacts remain after cleanup".to_string(),
            ));
        }
        state.uploads.remove(&identity.upload_id);
        Ok(())
    }
    async fn retire_terminal_uploads(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, StagingError> {
        let mut state = self.state.lock().await;
        let ids: Vec<_> = state
            .uploads
            .values()
            .filter(|upload| {
                matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) && upload
                    .tombstone_until_ms
                    .is_some_and(|until| until <= now_ms)
                    && !state
                        .attempts
                        .values()
                        .any(|attempt| attempt.part.upload_id == upload.identity.upload_id)
                    && !state
                        .pending
                        .values()
                        .any(|pending| pending.upload_id == upload.identity.upload_id)
            })
            .take(limit)
            .map(|upload| upload.identity.upload_id.clone())
            .collect();
        Ok(ids
            .into_iter()
            .filter_map(|upload_id| state.uploads.remove(&upload_id))
            .map(|upload| RetiredMultipartUpload {
                upload_id: upload.identity.upload_id,
                tenant_id: upload.identity.tenant_id,
                namespace_epoch: upload.namespace_epoch,
            })
            .collect())
    }

    async fn reap_expired(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        let mut state = self.state.lock().await;
        let ids: Vec<_> = state
            .uploads
            .values_mut()
            .filter(|upload| {
                upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= now_ms
            })
            .take(limit)
            .map(|upload| {
                upload.lifecycle = MultipartLifecycle::Expired;
                upload.tombstone_until_ms = Some(now_ms + DEFAULT_EXPIRY.as_millis() as i64);
                upload.updated_at_ms = now_ms;
                upload.identity.upload_id.clone()
            })
            .collect();
        Ok(state
            .parts
            .extract_if(|(upload_id, _), _| ids.contains(upload_id))
            .map(|(_, part)| part)
            .collect())
    }

    async fn audit(&self, audit: CleanupAudit) -> Result<(), StagingError> {
        self.state.lock().await.audits.push(audit);
        Ok(())
    }
}

#[async_trait]
pub trait StagingArtifactStore: Send + Sync {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), StagingError>;
    /// Returns an incremental encrypted artifact body. Callers decrypt frame by
    /// frame and must hold a valid completion fence for every read.
    async fn get(&self, key: &str) -> Result<aws_sdk_s3::primitives::ByteStream, StagingError>;
    async fn delete(&self, key: &str) -> Result<(), StagingError>;
    /// Discovery is required for startup reconciliation. Implementations must
    /// return every object below the supplied prefix, not an arbitrary page.
    async fn list(&self, prefix: &str) -> Result<Vec<StagedArtifact>, StagingError>;
}

pub struct S3StagingArtifactStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3StagingArtifactStore {
    pub fn new(client: aws_sdk_s3::Client, bucket: String) -> Self {
        Self { client, bucket }
    }
}

#[async_trait]
impl StagingArtifactStore for S3StagingArtifactStore {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), StagingError> {
        let body = aws_sdk_s3::primitives::ByteStream::from_path(path)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .map_err(|error| {
                StagingError::Persistence(record_s3_failure("staging_put", &error).to_string())
            })?;
        Ok(())
    }
    async fn get(&self, key: &str) -> Result<aws_sdk_s3::primitives::ByteStream, StagingError> {
        self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map(|output| output.body)
            .map_err(|error| {
                StagingError::Persistence(record_s3_failure("staging_get", &error).to_string())
            })
    }
    async fn delete(&self, key: &str) -> Result<(), StagingError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| {
                StagingError::Persistence(record_s3_failure("staging_delete", &error).to_string())
            })?;
        Ok(())
    }
    async fn list(&self, prefix: &str) -> Result<Vec<StagedArtifact>, StagingError> {
        let mut token = None;
        let mut artifacts = Vec::new();
        loop {
            let response = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_continuation_token(token)
                .send()
                .await
                .map_err(|error| {
                    StagingError::Persistence(record_s3_failure("staging_list", &error).to_string())
                })?;
            artifacts.extend(response.contents().iter().filter_map(|object| {
                Some(StagedArtifact {
                    key: object.key()?.to_string(),
                    modified_at_ms: object.last_modified()?.to_millis().ok()?,
                })
            }));
            if !response.is_truncated().unwrap_or(false) {
                break;
            }
            token = response.next_continuation_token().map(ToOwned::to_owned);
            if token.is_none() {
                return Err(StagingError::Persistence(
                    "truncated staging list without continuation token".to_string(),
                ));
            }
        }
        Ok(artifacts)
    }
}

#[derive(Clone, Default)]
pub struct MemoryStagingArtifactStore {
    pub objects: Arc<Mutex<MemoryArtifacts>>,
}

type MemoryArtifacts = HashMap<String, (Vec<u8>, i64)>;

#[async_trait]
impl StagingArtifactStore for MemoryStagingArtifactStore {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), StagingError> {
        self.objects.lock().await.insert(
            key.to_string(),
            (
                tokio::fs::read(path)
                    .await
                    .map_err(|error| StagingError::Persistence(error.to_string()))?,
                now_ms(),
            ),
        );
        Ok(())
    }
    async fn get(&self, key: &str) -> Result<aws_sdk_s3::primitives::ByteStream, StagingError> {
        self.objects
            .lock()
            .await
            .get(key)
            .map(|(bytes, _)| aws_sdk_s3::primitives::ByteStream::from(bytes.clone()))
            .ok_or(StagingError::NotFound)
    }
    async fn delete(&self, key: &str) -> Result<(), StagingError> {
        self.objects.lock().await.remove(key);
        Ok(())
    }
    async fn list(&self, prefix: &str) -> Result<Vec<StagedArtifact>, StagingError> {
        Ok(self
            .objects
            .lock()
            .await
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, (_, modified_at_ms))| StagedArtifact {
                key: key.clone(),
                modified_at_ms: *modified_at_ms,
            })
            .collect())
    }
}

#[derive(Serialize, Deserialize)]
struct ArtifactHeader {
    wrapped_dek: String,
    tenant_id: String,
    upload_id: String,
    part_number: u32,
    attempt: u32,
    metadata_digest: String,
}

/// Streams plaintext input into an encrypted, mode-0600 temporary file.  The
/// file contains only an envelope header and AEAD ciphertext frames.
pub struct EncryptedPartWriter {
    path: PathBuf,
    file: tokio::fs::File,
    dek: [u8; 32],
    header: ArtifactHeader,
    chunk: u64,
    size_bytes: u64,
    max_bytes: u64,
    sha256: Sha256,
    md5: Md5,
}

impl Drop for EncryptedPartWriter {
    fn drop(&mut self) {
        // The only local staging representation is ciphertext.  Best-effort
        // unlink also covers malformed bodies and canceled client requests.
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl EncryptedPartWriter {
    pub async fn begin(
        directory: &Path,
        identity: &MultipartIdentity,
        part_number: u32,
        attempt: u32,
        metadata: &MultipartSnapshot,
        max_bytes: u64,
        wrapping: Arc<dyn KeyWrapping>,
    ) -> Result<Self, StagingError> {
        if !wrapping.is_durable() {
            return Err(StagingError::Unavailable);
        }
        tokio::fs::create_dir_all(directory)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);
        let metadata_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(metadata)
                .map_err(|error| StagingError::Persistence(error.to_string()))?,
        ));
        let header = ArtifactHeader {
            wrapped_dek: B64.encode(
                wrapping
                    .wrap(&dek)
                    .map_err(|error| StagingError::Crypto(error.to_string()))?,
            ),
            tenant_id: identity.tenant_id.clone(),
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            metadata_digest,
        };
        let encoded = serde_json::to_vec(&header)
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let path = directory.join(format!("{FILE_PREFIX}{}.enc", Uuid::now_v7()));
        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        file.write_all(MAGIC).await.map_err(io_error)?;
        file.write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .map_err(io_error)?;
        file.write_all(&encoded).await.map_err(io_error)?;
        Ok(Self {
            path,
            file,
            dek,
            header,
            chunk: 0,
            size_bytes: 0,
            max_bytes,
            sha256: Sha256::new(),
            md5: Md5::new(),
        })
    }

    pub async fn write(&mut self, plaintext: Bytes) -> Result<(), StagingError> {
        if self
            .size_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or(StagingError::QuotaExceeded)?
            > self.max_bytes
        {
            return Err(StagingError::QuotaExceeded);
        }
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = artifact_aad(&self.header, self.chunk);
        let ciphertext = Aes256Gcm::new_from_slice(&self.dek)
            .map_err(|error| StagingError::Crypto(error.to_string()))?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| StagingError::Crypto("part encryption failed".to_string()))?;
        self.file
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .await
            .map_err(io_error)?;
        self.file.write_all(&nonce).await.map_err(io_error)?;
        self.file.write_all(&ciphertext).await.map_err(io_error)?;
        self.size_bytes = self
            .size_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or(StagingError::QuotaExceeded)?;
        self.sha256.update(&plaintext);
        self.md5.update(&plaintext);
        self.chunk += 1;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<FinishedPart, StagingError> {
        self.file.flush().await.map_err(io_error)?;
        self.file.sync_all().await.map_err(io_error)?;
        let path = std::mem::take(&mut self.path);
        Ok(FinishedPart {
            path,
            size_bytes: self.size_bytes,
            checksum_sha256: hex::encode(self.sha256.clone().finalize()),
            etag: format!("\"{}\"", hex::encode(self.md5.clone().finalize())),
        })
    }

    pub async fn cleanup_stale(
        directory: &Path,
        stale_after: Duration,
    ) -> Result<usize, StagingError> {
        let mut entries = match tokio::fs::read_dir(directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(io_error(error)),
        };
        let cutoff = SystemTime::now()
            .checked_sub(stale_after)
            .unwrap_or(UNIX_EPOCH);
        let mut removed = 0;
        while let Some(entry) = entries.next_entry().await.map_err(io_error)? {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with(FILE_PREFIX) {
                continue;
            }
            let metadata = entry.metadata().await.map_err(io_error)?;
            if metadata.is_file() && metadata.modified().map_err(io_error)? <= cutoff {
                tokio::fs::remove_file(entry.path())
                    .await
                    .map_err(io_error)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

pub struct FinishedPart {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub checksum_sha256: String,
    pub etag: String,
}
impl FinishedPart {
    pub async fn remove(&self) {
        let _ = tokio::fs::remove_file(&self.path).await;
    }
}

/// Incrementally authenticates and decrypts one staged artifact. It never
/// exposes a frame until the envelope identity, snapshot digest, and AEAD tag
/// have all been checked.
pub struct EncryptedPartReader<R> {
    reader: R,
    cipher: Aes256Gcm,
    header: ArtifactHeader,
    chunk: u64,
    finished: bool,
}

impl<R: AsyncRead + Unpin> EncryptedPartReader<R> {
    pub async fn open(
        mut reader: R,
        identity: &MultipartIdentity,
        part: &MultipartPart,
        snapshot: &MultipartSnapshot,
        wrapping: Arc<dyn KeyWrapping>,
    ) -> Result<Self, StagingError> {
        let mut magic = [0_u8; MAGIC.len()];
        reader.read_exact(&mut magic).await.map_err(io_error)?;
        if magic != MAGIC {
            return Err(StagingError::Crypto(
                "invalid staging artifact magic".to_string(),
            ));
        }
        let mut header_len = [0_u8; 4];
        reader.read_exact(&mut header_len).await.map_err(io_error)?;
        let header_len = u32::from_be_bytes(header_len) as usize;
        if header_len == 0 || header_len > MAX_ARTIFACT_HEADER_BYTES {
            return Err(StagingError::Crypto(
                "invalid staging artifact header".to_string(),
            ));
        }
        let mut encoded = vec![0_u8; header_len];
        reader.read_exact(&mut encoded).await.map_err(io_error)?;
        let header: ArtifactHeader = serde_json::from_slice(&encoded)
            .map_err(|_| StagingError::Crypto("invalid staging artifact header".to_string()))?;
        let expected_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(snapshot)
                .map_err(|error| StagingError::Persistence(error.to_string()))?,
        ));
        if header.tenant_id != identity.tenant_id
            || header.upload_id != identity.upload_id
            || header.part_number != part.part_number
            || header.attempt != part.attempt
            || header.metadata_digest != expected_digest
        {
            return Err(StagingError::Crypto(
                "staging artifact identity mismatch".to_string(),
            ));
        }
        let dek = wrapping
            .unwrap(
                &B64.decode(&header.wrapped_dek)
                    .map_err(|_| StagingError::Crypto("invalid wrapped staging key".to_string()))?,
            )
            .map_err(|error| StagingError::Crypto(error.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|error| StagingError::Crypto(error.to_string()))?;
        Ok(Self {
            reader,
            cipher,
            header,
            chunk: 0,
            finished: false,
        })
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, StagingError> {
        if self.finished {
            return Ok(None);
        }
        let mut length = [0_u8; 4];
        match self.reader.read_exact(&mut length).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.finished = true;
                return Ok(None);
            }
            Err(error) => return Err(io_error(error)),
        }
        let length = u32::from_be_bytes(length) as usize;
        if !(16..=MAX_ENCRYPTED_FRAME_BYTES).contains(&length) {
            return Err(StagingError::Crypto(
                "invalid staging artifact frame length".to_string(),
            ));
        }
        let mut nonce = [0_u8; NONCE_LEN];
        self.reader.read_exact(&mut nonce).await.map_err(io_error)?;
        let mut ciphertext = vec![0_u8; length];
        self.reader
            .read_exact(&mut ciphertext)
            .await
            .map_err(io_error)?;
        let aad = artifact_aad(&self.header, self.chunk);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                StagingError::Crypto("staging artifact authentication failed".to_string())
            })?;
        self.chunk = self
            .chunk
            .checked_add(1)
            .ok_or_else(|| StagingError::Crypto("staging artifact chunk overflow".to_string()))?;
        Ok(Some(Bytes::from(plaintext)))
    }
}

fn artifact_aad(header: &ArtifactHeader, chunk: u64) -> Vec<u8> {
    format!(
        "s4.multipart.stage.v1\0{}\0{}\0{}\0{}\0{}\0{}",
        header.tenant_id,
        header.upload_id,
        header.part_number,
        header.attempt,
        chunk,
        header.metadata_digest
    )
    .into_bytes()
}
fn io_error(_: std::io::Error) -> StagingError {
    StagingError::Persistence(record_s3_body_failure("staging_get_body").to_string())
}
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_cipher::LocalKeyWrapping;

    fn identity() -> MultipartIdentity {
        MultipartIdentity {
            tenant_id: "tenant-a".to_string(),
            credential_policy_id: "key-a".to_string(),
            bucket: "bucket".to_string(),
            key: "key".to_string(),
            upload_id: "upload".to_string(),
        }
    }
    fn snapshot() -> MultipartSnapshot {
        MultipartSnapshot {
            metadata: BTreeMap::new(),
            tags: BTreeMap::new(),
            checksum_mode: None,
            destination: serde_json::json!({"backend":"test"}),
            plugin_snapshot: serde_json::json!([]),
            max_staged_bytes: 1024,
        }
    }
    fn upload() -> MultipartUpload {
        let now = now_ms();
        MultipartUpload {
            identity: identity(),
            namespace_epoch: None,
            snapshot: snapshot(),
            lifecycle: MultipartLifecycle::Open,
            staged_bytes: 0,
            reserved_bytes: 0,
            created_at_ms: now,
            expires_at_ms: now + 1000,
            updated_at_ms: now,
            tombstone_until_ms: None,
            complete_request_fingerprint: None,
            completion_lease_owner: None,
            completion_lease_expires_at_ms: None,
            completion_fencing_token: 0,
            completion_result: None,
        }
    }

    #[tokio::test]
    async fn ownership_replacement_pagination_and_expiry_are_fenced() {
        let repo = InMemoryMultipartRepository::new();
        repo.create(upload()).await.unwrap();
        let mut thief = identity();
        thief.tenant_id = "tenant-b".to_string();
        assert!(matches!(
            repo.get_authorized(&thief).await,
            Err(StagingError::NotFound)
        ));
        let mut revoked_policy = identity();
        revoked_policy.credential_policy_id = "key-rotated".to_string();
        assert!(matches!(
            repo.get_authorized(&revoked_policy).await,
            Err(StagingError::NotFound)
        ));
        for number in [2, 1] {
            repo.replace_part(
                &identity(),
                MultipartPart {
                    upload_id: "upload".to_string(),
                    part_number: number,
                    attempt: 1,
                    artifact_key: format!("{number}"),
                    etag: "etag".to_string(),
                    checksum_sha256: "digest".to_string(),
                    size_bytes: 10,
                    created_at_ms: now_ms(),
                },
            )
            .await
            .unwrap();
        }
        let (parts, truncated) = repo.list_parts(&identity(), 0, 1).await.unwrap();
        assert_eq!(parts[0].part_number, 1);
        assert!(truncated);
        let previous = repo
            .replace_part(
                &identity(),
                MultipartPart {
                    upload_id: "upload".to_string(),
                    part_number: 1,
                    attempt: 2,
                    artifact_key: "new".to_string(),
                    etag: "new".to_string(),
                    checksum_sha256: "new".to_string(),
                    size_bytes: 11,
                    created_at_ms: now_ms(),
                },
            )
            .await
            .unwrap();
        assert_eq!(previous.unwrap().attempt, 1);
        assert!(repo.reap_expired(now_ms() + 2_000, 10).await.unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn replacement_race_keeps_one_current_attempt_across_restartable_repository_state() {
        let repo = InMemoryMultipartRepository::new();
        repo.create(upload()).await.unwrap();
        let first = MultipartPart {
            upload_id: "upload".to_string(),
            part_number: 1,
            attempt: 1,
            artifact_key: "first".to_string(),
            etag: "first".to_string(),
            checksum_sha256: "first".to_string(),
            size_bytes: 1,
            created_at_ms: now_ms(),
        };
        repo.replace_part(&identity(), first).await.unwrap();
        let candidate = |artifact: &str| MultipartPart {
            upload_id: "upload".to_string(),
            part_number: 1,
            attempt: 2,
            artifact_key: artifact.to_string(),
            etag: artifact.to_string(),
            checksum_sha256: artifact.to_string(),
            size_bytes: 2,
            created_at_ms: now_ms(),
        };
        let identity_left = identity();
        let identity_right = identity();
        let (left, right) = tokio::join!(
            repo.replace_part(&identity_left, candidate("left")),
            repo.replace_part(&identity_right, candidate("right"))
        );
        assert!(left.is_ok() ^ right.is_ok());
        let (parts, _) = repo.list_parts(&identity(), 0, 10).await.unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].attempt, 2);
    }

    #[tokio::test]
    async fn ciphertext_does_not_contain_plaintext_and_aad_is_identity_bound() {
        let directory = std::env::temp_dir().join(format!("s4-stage-test-{}", Uuid::now_v7()));
        let wrapping = Arc::new(LocalKeyWrapping::with_kek([7; 32]));
        let mut writer = EncryptedPartWriter::begin(
            &directory,
            &identity(),
            1,
            1,
            &snapshot(),
            1024,
            wrapping.clone(),
        )
        .await
        .unwrap();
        writer
            .write(Bytes::from_static(b"plain-secret-must-not-persist"))
            .await
            .unwrap();
        let finished = writer.finish().await.unwrap();
        let ciphertext = tokio::fs::read(&finished.path).await.unwrap();
        assert!(
            !ciphertext
                .windows(b"plain-secret-must-not-persist".len())
                .any(|value| value == b"plain-secret-must-not-persist")
        );
        let header_len =
            u32::from_be_bytes(ciphertext[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap())
                as usize;
        let header_end = MAGIC.len() + 4 + header_len;
        let header: ArtifactHeader =
            serde_json::from_slice(&ciphertext[MAGIC.len() + 4..header_end]).unwrap();
        let frame_len =
            u32::from_be_bytes(ciphertext[header_end..header_end + 4].try_into().unwrap()) as usize;
        let nonce = &ciphertext[header_end + 4..header_end + 4 + NONCE_LEN];
        let frame = &ciphertext[header_end + 4 + NONCE_LEN..header_end + 4 + NONCE_LEN + frame_len];
        let dek = wrapping
            .unwrap(&B64.decode(&header.wrapped_dek).unwrap())
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
        assert_eq!(
            cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: frame,
                        aad: &artifact_aad(&header, 0)
                    }
                )
                .unwrap(),
            b"plain-secret-must-not-persist"
        );
        let mut moved = header;
        moved.tenant_id = "tenant-b".to_string();
        assert!(
            cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: frame,
                        aad: &artifact_aad(&moved, 0)
                    }
                )
                .is_err()
        );
        finished.remove().await;
        let _ = tokio::fs::remove_dir(directory).await;
    }

    #[tokio::test]
    async fn encrypted_parts_feed_one_decoder_across_record_and_utf8_boundaries() {
        let directory = std::env::temp_dir().join(format!("s4-stage-test-{}", Uuid::now_v7()));
        let wrapping = Arc::new(LocalKeyWrapping::with_kek([8; 32]));
        let snapshot = snapshot();
        let mut first_writer = EncryptedPartWriter::begin(
            &directory,
            &identity(),
            1,
            1,
            &snapshot,
            1024,
            wrapping.clone(),
        )
        .await
        .unwrap();
        first_writer
            .write(Bytes::from_static(b"first \xc3"))
            .await
            .unwrap();
        let first = first_writer.finish().await.unwrap();
        let mut second_writer = EncryptedPartWriter::begin(
            &directory,
            &identity(),
            2,
            1,
            &snapshot,
            1024,
            wrapping.clone(),
        )
        .await
        .unwrap();
        second_writer
            .write(Bytes::from_static(b"\xa9\nsecond"))
            .await
            .unwrap();
        let second = second_writer.finish().await.unwrap();
        let parts = [(1, first), (2, second)];
        let mut decoder = crate::record::RecordDecoder::new(
            crate::Format::Text,
            crate::record::DecoderLimits::default(),
        )
        .unwrap();
        let mut records = Vec::new();
        for (number, finished) in &parts {
            let part = MultipartPart {
                upload_id: "upload".to_string(),
                part_number: *number,
                attempt: 1,
                artifact_key: format!("artifact-{number}"),
                etag: finished.etag.clone(),
                checksum_sha256: finished.checksum_sha256.clone(),
                size_bytes: finished.size_bytes,
                created_at_ms: now_ms(),
            };
            let ciphertext = tokio::fs::read(&finished.path).await.unwrap();
            let mut reader = EncryptedPartReader::open(
                aws_sdk_s3::primitives::ByteStream::from(ciphertext).into_async_read(),
                &identity(),
                &part,
                &snapshot,
                wrapping.clone(),
            )
            .await
            .unwrap();
            while let Some(chunk) = reader.next_chunk().await.unwrap() {
                decoder.push(&chunk).unwrap();
                while let Some(record) = decoder.next_record().unwrap() {
                    records.push(record);
                }
            }
        }
        decoder.finish().unwrap();
        while let Some(record) = decoder.next_record().unwrap() {
            records.push(record);
        }
        assert_eq!(records[0], crate::record::Record::new("first é", "\n"));
        assert_eq!(records[1], crate::record::Record::new("second", ""));
        for (_, finished) in parts {
            finished.remove().await;
        }
        let _ = tokio::fs::remove_dir(directory).await;
    }

    #[tokio::test]
    async fn ephemeral_wrapping_cannot_start_durable_staging() {
        let directory = std::env::temp_dir().join(format!("s4-stage-test-{}", Uuid::now_v7()));
        let result = EncryptedPartWriter::begin(
            &directory,
            &identity(),
            1,
            1,
            &snapshot(),
            1,
            Arc::new(LocalKeyWrapping::ephemeral()),
        )
        .await;
        assert!(matches!(result, Err(StagingError::Unavailable)));
    }

    #[tokio::test]
    async fn concurrent_reservations_cannot_overcommit_global_quota() {
        let repo = Arc::new(InMemoryMultipartRepository::with_quotas(
            StagingQuotaLimits::new(10, 10).unwrap(),
        ));
        let first = upload();
        let mut second = upload();
        second.identity.upload_id = "upload-2".to_string();
        second.identity.tenant_id = "tenant-b".to_string();
        repo.create(first).await.unwrap();
        repo.create(second).await.unwrap();
        let first_identity = identity();
        let mut second_identity = identity();
        second_identity.upload_id = "upload-2".to_string();
        second_identity.tenant_id = "tenant-b".to_string();
        let (left, right) = tokio::join!(
            repo.begin_part(&first_identity, 1, 6, now_ms()),
            repo.begin_part(&second_identity, 1, 6, now_ms()),
        );
        assert!(left.is_ok() ^ right.is_ok());
        assert!(matches!(
            left.err().or(right.err()),
            Some(StagingError::QuotaExceeded)
        ));
    }

    #[tokio::test]
    async fn crash_after_artifact_put_is_reconciled_from_pending_outbox() {
        let repo =
            InMemoryMultipartRepository::with_quotas(StagingQuotaLimits::new(32, 32).unwrap());
        repo.create(upload()).await.unwrap();
        let pending = repo
            .begin_part(
                &identity(),
                1,
                8,
                now_ms() - RECONCILIATION_GRACE.as_millis() as i64 - 1,
            )
            .await
            .unwrap();
        let artifacts = MemoryStagingArtifactStore::default();
        let path = std::env::temp_dir().join(format!("s4-crash-artifact-{}", Uuid::now_v7()));
        tokio::fs::write(&path, b"ciphertext-only-test-artifact")
            .await
            .unwrap();
        artifacts
            .put_file(&pending.artifact_key, &path)
            .await
            .unwrap();
        tokio::fs::remove_file(&path).await.unwrap();

        // Simulates process death between S3 PUT and the DB CURRENT transition.
        let candidates = repo.cleanup_candidates(now_ms(), 10).await.unwrap();
        assert_eq!(candidates.len(), 1);
        artifacts.delete(&candidates[0].artifact_key).await.unwrap();
        repo.confirm_artifact_deleted(&candidates[0].artifact_key)
            .await
            .unwrap();
        assert!(artifacts.list(ARTIFACT_PREFIX).await.unwrap().is_empty());
        assert_eq!(
            repo.get_authorized(&identity())
                .await
                .unwrap()
                .reserved_bytes,
            0
        );
    }

    fn complete_part(number: u32, etag: &str, checksum: Option<&str>) -> CompletePart {
        CompletePart {
            part_number: number,
            etag: etag.to_string(),
            checksum_sha256: checksum.map(ToOwned::to_owned),
        }
    }

    async fn current_part(
        repo: &InMemoryMultipartRepository,
        number: u32,
        etag: &str,
        checksum: &str,
    ) {
        repo.replace_part(
            &identity(),
            MultipartPart {
                upload_id: "upload".to_string(),
                part_number: number,
                attempt: 1,
                artifact_key: format!("artifact-{number}"),
                etag: etag.to_string(),
                checksum_sha256: checksum.to_string(),
                size_bytes: 3,
                created_at_ms: now_ms(),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn completion_replays_only_the_identical_durable_request() {
        let repo = InMemoryMultipartRepository::new();
        repo.create(upload()).await.unwrap();
        current_part(&repo, 1, "\"one\"", "sha-one").await;
        let request = vec![complete_part(1, "\"one\"", Some("sha-one"))];
        let lease = match repo
            .acquire_completion(&identity(), "fingerprint", &request, "worker-a", 100, 0)
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected completion lease"),
        };
        repo.complete_completion(
            &identity(),
            lease.fencing_token,
            MultipartCompletionResult {
                etag: Some("\"output\"".to_string()),
                checksum_sha256: "output-sha".to_string(),
                version_id: Some("version-a".to_string()),
                source_bytes: 24,
                size_bytes: 42,
            },
            1,
        )
        .await
        .unwrap();
        assert!(matches!(
            repo.acquire_completion(&identity(), "fingerprint", &request, "worker-b", 200, 2)
                .await,
            Ok(CompletionAcquire::Replayed(MultipartCompletionResult { ref etag, ref checksum_sha256, ref version_id, source_bytes: 24, size_bytes: 42 }))
                if etag.as_deref() == Some("\"output\"")
                    && checksum_sha256 == "output-sha"
                    && version_id.as_deref() == Some("version-a")
        ));
        assert!(matches!(
            repo.acquire_completion(&identity(), "different", &request, "worker-b", 200, 2)
                .await,
            Err(StagingError::CompletionConflict)
        ));
    }

    #[tokio::test]
    async fn completion_lease_takeover_fences_the_stale_worker() {
        let repo = InMemoryMultipartRepository::new();
        repo.create(upload()).await.unwrap();
        current_part(&repo, 1, "\"one\"", "sha-one").await;
        let request = vec![complete_part(1, "\"one\"", None)];
        let first = match repo
            .acquire_completion(&identity(), "same", &request, "worker-a", 10, 0)
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected first lease"),
        };
        assert!(matches!(
            repo.acquire_completion(&identity(), "same", &request, "worker-b", 20, 1)
                .await,
            Ok(CompletionAcquire::Busy)
        ));
        let second = match repo
            .acquire_completion(&identity(), "same", &request, "worker-b", 30, 11)
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected takeover lease"),
        };
        assert!(second.fencing_token > first.fencing_token);
        assert!(matches!(
            repo.check_completion_lease(&identity(), first.fencing_token, 12)
                .await,
            Err(StagingError::Fenced)
        ));
        assert!(
            repo.check_completion_lease(&identity(), second.fencing_token, 12)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn completion_rejects_missing_extra_duplicate_and_conflicting_parts() {
        let repo = InMemoryMultipartRepository::new();
        repo.create(upload()).await.unwrap();
        current_part(&repo, 1, "\"one\"", "sha-one").await;
        assert!(matches!(
            repo.acquire_completion(
                &identity(),
                "missing",
                &[complete_part(2, "\"two\"", None)],
                "worker",
                10,
                0,
            )
            .await,
            Err(StagingError::InvalidPart)
        ));
        assert!(matches!(
            repo.acquire_completion(
                &identity(),
                "conflicting",
                &[complete_part(1, "\"wrong\"", Some("sha-one"))],
                "worker",
                10,
                0,
            )
            .await,
            Err(StagingError::InvalidPart)
        ));
        assert!(matches!(
            repo.acquire_completion(
                &identity(),
                "duplicate",
                &[
                    complete_part(1, "\"one\"", None),
                    complete_part(1, "\"one\"", None),
                ],
                "worker",
                10,
                0,
            )
            .await,
            Err(StagingError::InvalidPart)
        ));
    }

    #[tokio::test]
    async fn abort_is_idempotent_and_wins_before_completion_acquisition() {
        let repo = InMemoryMultipartRepository::new();
        repo.create(upload()).await.unwrap();
        current_part(&repo, 1, "\"one\"", "sha-one").await;
        let parts = repo.abort(&identity(), 1).await.unwrap();
        assert_eq!(parts.len(), 1);
        assert!(repo.abort(&identity(), 2).await.unwrap().is_empty());
        repo.confirm_artifact_deleted(&parts[0].artifact_key)
            .await
            .unwrap();
        assert_eq!(
            repo.retire_terminal_uploads(i64::MAX, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            repo.acquire_completion(
                &identity(),
                "after-abort",
                &[complete_part(1, "\"one\"", None)],
                "worker",
                10,
                2,
            )
            .await,
            Err(StagingError::NotFound)
        ));
    }
}
