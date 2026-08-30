//! Durable destination transactions used by future streaming write handlers.
//!
//! This module deliberately has no handler integration. Phase 5 establishes the
//! persistence, backend, and recovery contracts without changing write routing.

mod journal;
mod memory;
mod presign;
mod s3;
mod spool;

#[cfg(any(test, debug_assertions))]
pub use journal::InMemoryOperationJournal;
pub use journal::PostgresOperationJournal;
pub use memory::MemorySinkTransaction;
pub use presign::{MultipartPresignContract, PresignedOperation};
pub use s3::{AwsS3TransactionBackend, DirectS3Sink};
pub(crate) use spool::READ_FILE_PREFIX;
pub use spool::{
    CompatibilitySpoolConfig, CompatibilitySpoolTransaction, CompatibilitySpoolUploader, SpoolQuota,
};

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

pub const DIRECT_PART_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RECONCILIATION_SLA: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationState {
    Intent,
    Open,
    Completing,
    CommitUnknown,
    Committed,
    Aborting,
    ProvenAborted,
}

impl OperationState {
    pub const ALL: [Self; 7] = [
        Self::Intent,
        Self::Open,
        Self::Completing,
        Self::CommitUnknown,
        Self::Committed,
        Self::Aborting,
        Self::ProvenAborted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "INTENT",
            Self::Open => "OPEN",
            Self::Completing => "COMPLETING",
            Self::CommitUnknown => "COMMIT_UNKNOWN",
            Self::Committed => "COMMITTED",
            Self::Aborting => "ABORTING",
            Self::ProvenAborted => "PROVEN_ABORTED",
        }
    }

    pub fn parse(value: &str) -> Result<Self, JournalError> {
        Self::ALL
            .into_iter()
            .find(|state| state.as_str() == value)
            .ok_or_else(|| JournalError::Corrupt(format!("unknown operation state {value:?}")))
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Intent, Self::Open | Self::Aborting)
                | (Self::Open, Self::Completing | Self::Aborting)
                | (Self::Completing, Self::Committed | Self::CommitUnknown)
                | (Self::CommitUnknown, Self::Committed | Self::ProvenAborted)
                | (Self::Aborting, Self::ProvenAborted)
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::ProvenAborted)
    }
}

impl fmt::Display for OperationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectDestination {
    pub backend_id: String,
    pub bucket: String,
    pub logical_key: String,
    pub physical_key: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpectedObject {
    pub digest: Option<String>,
    pub size: Option<u64>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    pub id: Uuid,
    pub state: OperationState,
    pub destination: ObjectDestination,
    pub tenant_id: Option<String>,
    pub namespace_epoch: Option<u64>,
    pub expected: ExpectedObject,
    pub upload_id: Option<String>,
    pub committed: Option<StoredObjectMeta>,
    pub lease_owner: Option<String>,
    pub lease_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedOperationScope {
    pub operation_id: Uuid,
    pub tenant_id: String,
    pub namespace_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectOperationScope {
    pub operation_id: Uuid,
    pub tenant_id: String,
}

impl OperationRecord {
    pub fn intent(destination: ObjectDestination, expected: ExpectedObject) -> Self {
        let now = unix_time_ms();
        Self {
            id: Uuid::now_v7(),
            state: OperationState::Intent,
            destination,
            tenant_id: None,
            namespace_epoch: None,
            expected,
            upload_id: None,
            committed: None,
            lease_owner: None,
            lease_expires_at_ms: None,
            created_at_ms: now,
            updated_at_ms: now,
        }
    }

    pub fn scoped_intent(
        id: Uuid,
        destination: ObjectDestination,
        expected: ExpectedObject,
        tenant_id: String,
        namespace_epoch: u64,
    ) -> Self {
        let mut operation = Self::intent(destination, expected);
        operation.id = id;
        operation.tenant_id = Some(tenant_id);
        operation.namespace_epoch = Some(namespace_epoch);
        operation
    }

    pub fn direct_intent(
        scope: DirectOperationScope,
        destination: ObjectDestination,
        expected: ExpectedObject,
    ) -> Self {
        let mut operation = Self::intent(destination, expected);
        operation.id = scope.operation_id;
        operation.tenant_id = Some(scope.tenant_id);
        operation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartRecord {
    pub operation_id: Uuid,
    pub part_number: i32,
    pub etag: String,
    pub size_bytes: u64,
    pub digest: String,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceRecord {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub kind: String,
    pub detail: serde_json::Value,
    pub created_at_ms: i64,
}

impl EvidenceRecord {
    pub fn new(operation_id: Uuid, kind: impl Into<String>, detail: serde_json::Value) -> Self {
        Self {
            id: Uuid::now_v7(),
            operation_id,
            kind: kind.into(),
            detail,
            created_at_ms: unix_time_ms(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoredObjectMeta {
    pub etag: Option<String>,
    pub version_id: Option<String>,
    pub superseded_version_ids: Vec<String>,
    pub version_history_complete: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("operation {0} was not found")]
    NotFound(Uuid),
    #[error("operation journal conflict: {0}")]
    Conflict(String),
    #[error("operation journal contains corrupt data: {0}")]
    Corrupt(String),
    #[error("operation journal persistence failed: {0}")]
    Persistence(String),
}

#[async_trait]
pub trait OperationJournal: Send + Sync {
    fn is_durable(&self) -> bool;
    async fn insert_intent(&self, operation: OperationRecord) -> Result<(), JournalError>;
    async fn get(&self, operation_id: Uuid) -> Result<Option<OperationRecord>, JournalError>;
    async fn set_open(
        &self,
        operation_id: Uuid,
        upload_id: Option<&str>,
    ) -> Result<(), JournalError>;
    async fn set_expected(
        &self,
        operation_id: Uuid,
        expected: &ExpectedObject,
    ) -> Result<(), JournalError>;
    async fn transition(
        &self,
        operation_id: Uuid,
        expected: OperationState,
        next: OperationState,
        committed: Option<&StoredObjectMeta>,
    ) -> Result<(), JournalError>;
    async fn record_part(&self, part: PartRecord) -> Result<(), JournalError>;
    async fn parts(&self, operation_id: Uuid) -> Result<Vec<PartRecord>, JournalError>;
    async fn append_evidence(&self, evidence: EvidenceRecord) -> Result<(), JournalError>;
    async fn evidence(&self, operation_id: Uuid) -> Result<Vec<EvidenceRecord>, JournalError>;
    async fn claim_reconcilable(
        &self,
        owner: &str,
        stale_before_ms: i64,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<OperationRecord>, JournalError>;
    async fn claim_reconcilable_operation(
        &self,
        operation_id: Uuid,
        owner: &str,
        stale_before_ms: i64,
        lease_until_ms: i64,
    ) -> Result<Option<OperationRecord>, JournalError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompleteUploadDiscovery {
    Unsupported,
    ExactKeyAndStartTime,
    OperationIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionReconciliation {
    Unsupported,
    HeadWithOperationIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersioningCapability {
    Unsupported,
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionalReadCapability {
    Unsupported,
    Etag,
    VersionAndEtag,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseChecksumCapability {
    Unsupported,
    Standard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListCapability {
    Unsupported,
    V1AndV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultipartResponseCapability {
    Unsupported,
    Standard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendCapabilities {
    pub incomplete_upload_discovery: IncompleteUploadDiscovery,
    pub abort_incomplete_upload: bool,
    pub cleanup_sla: Option<Duration>,
    pub lifecycle_rule: bool,
    pub versioning: VersioningCapability,
    pub conditional_reads: ConditionalReadCapability,
    pub response_checksums: ResponseChecksumCapability,
    pub list_operations: ListCapability,
    pub multipart_responses: MultipartResponseCapability,
    pub completion_reconciliation: CompletionReconciliation,
}

impl BackendCapabilities {
    pub fn streaming_eligibility(self) -> Result<(), CapabilityError> {
        if self.incomplete_upload_discovery == IncompleteUploadDiscovery::Unsupported {
            return Err(CapabilityError::MissingIncompleteUploadDiscovery);
        }
        if !self.abort_incomplete_upload {
            return Err(CapabilityError::MissingIncompleteUploadAbort);
        }
        if self.completion_reconciliation == CompletionReconciliation::Unsupported {
            return Err(CapabilityError::MissingCompletionReconciliation);
        }
        match self.cleanup_sla {
            Some(sla) if sla <= MAX_RECONCILIATION_SLA => Ok(()),
            _ => Err(CapabilityError::CleanupSlaExceeded),
        }
    }

    pub fn supports_conditional_reads(self) -> bool {
        self.conditional_reads != ConditionalReadCapability::Unsupported
    }

    pub fn supports_response_checksums(self) -> bool {
        self.response_checksums == ResponseChecksumCapability::Standard
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CapabilityError {
    #[error("backend cannot discover incomplete multipart uploads")]
    MissingIncompleteUploadDiscovery,
    #[error("backend cannot abort discovered multipart uploads")]
    MissingIncompleteUploadAbort,
    #[error("backend cannot reconcile ambiguous completion")]
    MissingCompletionReconciliation,
    #[error("backend cannot guarantee reconciliation within five minutes")]
    CleanupSlaExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendErrorKind {
    Definitive,
    Ambiguous,
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("destination backend {kind:?} failure: {message}")]
pub struct BackendError {
    pub kind: BackendErrorKind,
    pub message: String,
}

impl BackendError {
    pub fn definitive(message: impl Into<String>) -> Self {
        Self {
            kind: BackendErrorKind::Definitive,
            message: message.into(),
        }
    }

    pub fn ambiguous(message: impl Into<String>) -> Self {
        Self {
            kind: BackendErrorKind::Ambiguous,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadedPart {
    pub part_number: i32,
    pub etag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredUpload {
    pub upload_id: String,
    pub key: String,
    pub initiated_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompletionProbe {
    Committed(StoredObjectMeta),
    ProvenAbsent,
    Inconclusive,
}

#[async_trait]
pub trait TransactionBackend: Send + Sync {
    fn capabilities(&self) -> BackendCapabilities;
    async fn put_object(
        &self,
        operation: &OperationRecord,
        body: Bytes,
    ) -> Result<StoredObjectMeta, BackendError>;
    async fn create_multipart(&self, operation: &OperationRecord) -> Result<String, BackendError>;
    async fn upload_part(
        &self,
        operation: &OperationRecord,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<String, BackendError>;
    async fn complete_multipart(
        &self,
        operation: &OperationRecord,
        upload_id: &str,
        parts: &[UploadedPart],
    ) -> Result<StoredObjectMeta, BackendError>;
    async fn abort_multipart(
        &self,
        operation: &OperationRecord,
        upload_id: &str,
    ) -> Result<(), BackendError>;
    async fn discover_incomplete(
        &self,
        operation: &OperationRecord,
    ) -> Result<Vec<DiscoveredUpload>, BackendError>;
    async fn probe_completion(
        &self,
        operation: &OperationRecord,
    ) -> Result<CompletionProbe, BackendError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    #[error("transaction is already finished")]
    Finished,
    #[error("completion outcome is ambiguous and must be reconciled")]
    CompletionAmbiguous,
    #[error("transaction part number limit exceeded")]
    TooManyParts,
    #[error("transaction spool failed: {0}")]
    Spool(String),
    #[error("transaction output does not match the validated digest or size")]
    OutputMismatch,
    #[error("transaction destination capacity or object limit exceeded")]
    CapacityExceeded,
    #[error("managed authority publication failed: {0}")]
    Publication(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkCommitState {
    PreCommit,
    CommitUnknown,
    Committed,
}

impl SinkCommitState {
    pub fn preserves_reservation(self) -> bool {
        self != Self::PreCommit
    }
}

#[async_trait]
pub trait ObjectSinkTransaction: Send {
    fn commit_state(&self) -> SinkCommitState;
    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError>;
    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError>;
    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError>;
    async fn abort(&mut self) -> Result<(), TransactionError>;
}

#[derive(Clone, Debug)]
pub struct AbortSignal {
    sender: mpsc::Sender<Uuid>,
}

impl AbortSignal {
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<Uuid>) {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        (Self { sender }, receiver)
    }

    pub fn signal(&self, operation_id: Uuid) {
        let _ = self.sender.try_send(operation_id);
    }
}

pub struct OperationReconciler {
    journal: Arc<dyn OperationJournal>,
    backend: Arc<dyn TransactionBackend>,
    owner: String,
    lease: Duration,
}

impl OperationReconciler {
    pub fn new(
        journal: Arc<dyn OperationJournal>,
        backend: Arc<dyn TransactionBackend>,
        owner: impl Into<String>,
    ) -> Result<Self, CapabilityError> {
        backend.capabilities().streaming_eligibility()?;
        Ok(Self {
            journal,
            backend,
            owner: owner.into(),
            lease: Duration::from_secs(30),
        })
    }

    pub async fn reconcile_operation(
        &self,
        operation_id: Uuid,
        stale_after: Duration,
    ) -> Result<bool, TransactionError> {
        let now = unix_time_ms();
        let operation = self
            .journal
            .claim_reconcilable_operation(
                operation_id,
                &self.owner,
                now.saturating_sub(duration_ms(stale_after)),
                now.saturating_add(duration_ms(self.lease)),
            )
            .await?;
        if let Some(operation) = operation {
            self.reconcile(operation).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn reconcile(&self, operation: OperationRecord) -> Result<(), TransactionError> {
        self.journal
            .append_evidence(EvidenceRecord::new(
                operation.id,
                "reconcile_started",
                serde_json::json!({"state": operation.state.as_str(), "owner": self.owner}),
            ))
            .await?;
        match operation.state {
            OperationState::Intent => {
                self.journal
                    .transition(
                        operation.id,
                        OperationState::Intent,
                        OperationState::Aborting,
                        None,
                    )
                    .await?;
                self.abort_discovered(&operation).await?;
                self.journal
                    .transition(
                        operation.id,
                        OperationState::Aborting,
                        OperationState::ProvenAborted,
                        None,
                    )
                    .await?;
            }
            OperationState::Open | OperationState::Aborting => {
                if operation.state == OperationState::Open {
                    self.journal
                        .transition(
                            operation.id,
                            OperationState::Open,
                            OperationState::Aborting,
                            None,
                        )
                        .await?;
                }
                if let Some(upload_id) = &operation.upload_id {
                    self.backend.abort_multipart(&operation, upload_id).await?;
                }
                self.abort_discovered(&operation).await?;
                self.journal
                    .transition(
                        operation.id,
                        OperationState::Aborting,
                        OperationState::ProvenAborted,
                        None,
                    )
                    .await?;
            }
            OperationState::Completing => {
                self.journal
                    .transition(
                        operation.id,
                        OperationState::Completing,
                        OperationState::CommitUnknown,
                        None,
                    )
                    .await?;
                self.reconcile_unknown(&operation).await?;
            }
            OperationState::CommitUnknown => self.reconcile_unknown(&operation).await?,
            OperationState::Committed | OperationState::ProvenAborted => {}
        }
        Ok(())
    }

    async fn reconcile_unknown(&self, operation: &OperationRecord) -> Result<(), TransactionError> {
        match self.backend.probe_completion(operation).await? {
            CompletionProbe::Committed(mut meta) => {
                // A completion discovered after an ambiguous response cannot
                // prove that no earlier provider version was also created.
                meta.version_history_complete = false;
                self.journal
                    .transition(
                        operation.id,
                        OperationState::CommitUnknown,
                        OperationState::Committed,
                        Some(&meta),
                    )
                    .await?;
            }
            CompletionProbe::ProvenAbsent => {
                // A point-in-time read cannot prove that a timed-out provider
                // mutation did not commit. Keep the operation fail-closed until
                // an external reconciler has provider-appropriate durable proof.
                self.journal
                    .append_evidence(EvidenceRecord::new(
                        operation.id,
                        "completion_absent_inconclusive",
                        serde_json::json!({}),
                    ))
                    .await?;
            }
            CompletionProbe::Inconclusive => {}
        }
        Ok(())
    }

    async fn abort_discovered(&self, operation: &OperationRecord) -> Result<(), TransactionError> {
        for upload in self.backend.discover_incomplete(operation).await? {
            self.backend
                .abort_multipart(operation, &upload.upload_id)
                .await?;
        }
        Ok(())
    }
}

pub fn validate_production_journal(
    streaming_write_requested: bool,
    journal: Option<&Arc<dyn OperationJournal>>,
) -> anyhow::Result<()> {
    if streaming_write_requested && !journal.is_some_and(|journal| journal.is_durable()) {
        anyhow::bail!(
            "production streaming writes require a durable operation journal; configure DATABASE_URL"
        );
    }
    Ok(())
}

pub(crate) fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

pub(crate) fn duration_ms(duration: Duration) -> i64 {
    duration.as_millis().min(i64::MAX as u128) as i64
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn expected_transition(from: OperationState, to: OperationState) -> bool {
        [
            (OperationState::Intent, OperationState::Open),
            (OperationState::Intent, OperationState::Aborting),
            (OperationState::Open, OperationState::Completing),
            (OperationState::Open, OperationState::Aborting),
            (OperationState::Completing, OperationState::Committed),
            (OperationState::Completing, OperationState::CommitUnknown),
            (OperationState::CommitUnknown, OperationState::Committed),
            (OperationState::CommitUnknown, OperationState::ProvenAborted),
            (OperationState::Aborting, OperationState::ProvenAborted),
        ]
        .contains(&(from, to))
    }

    #[test]
    fn transition_matrix_is_exhaustive_and_canonical() {
        for from in OperationState::ALL {
            for to in OperationState::ALL {
                assert_eq!(
                    from.can_transition_to(to),
                    expected_transition(from, to),
                    "{from} -> {to}"
                );
            }
        }
        assert!(!OperationState::Completing.can_transition_to(OperationState::Aborting));
        assert!(!OperationState::CommitUnknown.can_transition_to(OperationState::Aborting));
    }

    proptest! {
        #[test]
        fn no_transition_leaves_a_terminal_state(from in 0usize..7, to in 0usize..7) {
            let from = OperationState::ALL[from];
            let to = OperationState::ALL[to];
            if from.is_terminal() {
                prop_assert!(!from.can_transition_to(to));
            }
        }
    }

    #[test]
    fn capability_gate_requires_every_recovery_primitive() {
        let eligible = BackendCapabilities {
            incomplete_upload_discovery: IncompleteUploadDiscovery::OperationIdentity,
            abort_incomplete_upload: true,
            cleanup_sla: Some(MAX_RECONCILIATION_SLA),
            lifecycle_rule: true,
            versioning: VersioningCapability::Optional,
            conditional_reads: ConditionalReadCapability::VersionAndEtag,
            response_checksums: ResponseChecksumCapability::Standard,
            list_operations: ListCapability::V1AndV2,
            multipart_responses: MultipartResponseCapability::Standard,
            completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
        };
        assert_eq!(eligible.streaming_eligibility(), Ok(()));

        let mut candidate = eligible;
        candidate.incomplete_upload_discovery = IncompleteUploadDiscovery::Unsupported;
        assert_eq!(
            candidate.streaming_eligibility(),
            Err(CapabilityError::MissingIncompleteUploadDiscovery)
        );
        candidate = eligible;
        candidate.abort_incomplete_upload = false;
        assert_eq!(
            candidate.streaming_eligibility(),
            Err(CapabilityError::MissingIncompleteUploadAbort)
        );
        candidate = eligible;
        candidate.completion_reconciliation = CompletionReconciliation::Unsupported;
        assert_eq!(
            candidate.streaming_eligibility(),
            Err(CapabilityError::MissingCompletionReconciliation)
        );
        candidate = eligible;
        candidate.cleanup_sla = Some(MAX_RECONCILIATION_SLA + Duration::from_millis(1));
        assert_eq!(
            candidate.streaming_eligibility(),
            Err(CapabilityError::CleanupSlaExceeded)
        );
    }

    #[test]
    fn production_rejects_missing_or_development_journal() {
        assert!(validate_production_journal(true, None).is_err());
        let memory: Arc<dyn OperationJournal> = Arc::new(InMemoryOperationJournal::new());
        assert!(validate_production_journal(true, Some(&memory)).is_err());
        assert!(validate_production_journal(false, None).is_ok());
    }
}
