use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::sea_query::{Expr, LockType, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, SqlxPostgresConnector,
    TransactionTrait,
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::entity::{
    managed_multipart_activity, managed_namespace, managed_namespace_purge,
    managed_object_authority, managed_object_repair, managed_physical_object_version,
    managed_physical_write_intent, object_operation,
};

pub const PLACEMENT_VERSION_V1: u32 = 1;
pub const PHYSICAL_WRITE_LEASE_MS: i64 = 2 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum ManagedStreamingMode {
    #[default]
    Off,
    Observe,
    Enforce,
}

impl ManagedStreamingMode {
    pub fn from_value(value: Option<&str>) -> Result<Self, ManagedError> {
        match value {
            None | Some("off") => Ok(Self::Off),
            Some("observe") => Ok(Self::Observe),
            Some("enforce") => Ok(Self::Enforce),
            Some(value) => Err(ManagedError::InvalidMode(value.to_string())),
        }
    }

    pub fn allows_mutations(self) -> bool {
        self == Self::Enforce
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LogicalObjectKey {
    pub tenant_id: String,
    pub bucket: String,
    pub key: String,
}

impl LogicalObjectKey {
    pub fn new(tenant_id: &str, bucket: &str, key: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            bucket: bucket.to_string(),
            key: key.to_string(),
        }
    }

    pub fn object_key(&self) -> String {
        format!("{}/{}", self.bucket, self.key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement {
    pub version: u32,
    pub primary_backend_id: String,
    pub replica_backend_id: Option<String>,
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub fn rendezvous_score(
    placement_version: u32,
    tenant_id: &str,
    object_key: &str,
    backend_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"s4-rendezvous\0");
    hasher.update(placement_version.to_be_bytes());
    hash_field(&mut hasher, tenant_id.as_bytes());
    hash_field(&mut hasher, object_key.as_bytes());
    hash_field(&mut hasher, backend_id.as_bytes());
    hasher.finalize().into()
}

pub fn rendezvous_placement(
    placement_version: u32,
    tenant_id: &str,
    object_key: &str,
    backend_ids: impl IntoIterator<Item = String>,
) -> Option<Placement> {
    let mut scored: Vec<_> = backend_ids
        .into_iter()
        .map(|backend_id| {
            (
                rendezvous_score(placement_version, tenant_id, object_key, &backend_id),
                backend_id,
            )
        })
        .collect();
    scored.sort_by(|(left_score, left_id), (right_score, right_id)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_id.cmp(right_id))
    });
    scored.dedup_by(|(_, left), (_, right)| left == right);
    let primary_backend_id = scored.first()?.1.clone();
    let replica_backend_id = scored.get(1).map(|(_, id)| id.clone());
    Some(Placement {
        version: placement_version,
        primary_backend_id,
        replica_backend_id,
    })
}

pub fn generation_physical_key(logical: &LogicalObjectKey, generation: Uuid) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, logical.tenant_id.as_bytes());
    hash_field(&mut hasher, logical.bucket.as_bytes());
    hash_field(&mut hasher, logical.key.as_bytes());
    format!(
        "__s4/generations/{}/{}",
        hex::encode(hasher.finalize()),
        generation
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyStatus {
    Ready,
    RepairPending,
    Absent,
}

impl CopyStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::RepairPending => "REPAIR_PENDING",
            Self::Absent => "ABSENT",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "READY" => Ok(Self::Ready),
            "REPAIR_PENDING" => Ok(Self::RepairPending),
            "ABSENT" => Ok(Self::Absent),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed copy status {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectAuthority {
    pub logical: LogicalObjectKey,
    pub generation: Uuid,
    pub digest: String,
    pub size: u64,
    pub metadata: BTreeMap<String, String>,
    pub placement_version: u32,
    pub primary_backend_id: String,
    pub replica_backend_id: Option<String>,
    pub primary_status: CopyStatus,
    pub replica_status: CopyStatus,
    pub tombstone: bool,
    pub cas_version: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairKind {
    Replica,
    Placement,
    DeleteGeneration,
}

impl RepairKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Replica => "REPLICA",
            Self::Placement => "PLACEMENT",
            Self::DeleteGeneration => "DELETE_GENERATION",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "REPLICA" => Ok(Self::Replica),
            "PLACEMENT" => Ok(Self::Placement),
            "DELETE_GENERATION" => Ok(Self::DeleteGeneration),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed repair kind {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairTargetRole {
    Primary,
    Replica,
    Cleanup,
}

impl RepairTargetRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "PRIMARY",
            Self::Replica => "REPLICA",
            Self::Cleanup => "CLEANUP",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "PRIMARY" => Ok(Self::Primary),
            "REPLICA" => Ok(Self::Replica),
            "CLEANUP" => Ok(Self::Cleanup),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed repair target role {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairRecord {
    /// An opaque claim capability while leased; otherwise equal to `repair_id`.
    pub id: Uuid,
    pub repair_id: Uuid,
    pub kind: RepairKind,
    pub logical: LogicalObjectKey,
    pub namespace_epoch: u64,
    pub authority_cas_version: u64,
    pub generation: Uuid,
    pub digest: String,
    pub size: u64,
    pub metadata: BTreeMap<String, String>,
    pub physical_key: String,
    pub source_backend_id: Option<String>,
    pub target_backend_id: String,
    pub target_role: RepairTargetRole,
    pub placement_version: u32,
    pub placement_primary_backend_id: Option<String>,
    pub placement_replica_backend_id: Option<String>,
    pub attempts: u32,
    pub lease_owner: Option<String>,
    pub lease_token: Option<Uuid>,
    pub lease_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl RepairRecord {
    pub fn copy(
        kind: RepairKind,
        authority: &ObjectAuthority,
        source_backend_id: Option<String>,
        target_backend_id: String,
        target_role: RepairTargetRole,
        placement_version: u32,
    ) -> Self {
        let now = crate::transaction::unix_time_ms();
        let repair_id = Uuid::now_v7();
        Self {
            id: repair_id,
            repair_id,
            kind,
            logical: authority.logical.clone(),
            namespace_epoch: 0,
            authority_cas_version: authority.cas_version,
            generation: authority.generation,
            digest: authority.digest.clone(),
            size: authority.size,
            metadata: authority.metadata.clone(),
            physical_key: generation_physical_key(&authority.logical, authority.generation),
            source_backend_id,
            target_backend_id,
            target_role,
            placement_version,
            placement_primary_backend_id: None,
            placement_replica_backend_id: None,
            attempts: 0,
            lease_owner: None,
            lease_token: None,
            lease_expires_at_ms: None,
            created_at_ms: now,
            updated_at_ms: now,
        }
    }

    pub fn placement(
        authority: &ObjectAuthority,
        source_backend_id: Option<String>,
        target_backend_id: String,
        target_role: RepairTargetRole,
        placement: &Placement,
    ) -> Self {
        let mut repair = Self::copy(
            RepairKind::Placement,
            authority,
            source_backend_id,
            target_backend_id,
            target_role,
            placement.version,
        );
        repair.placement_primary_backend_id = Some(placement.primary_backend_id.clone());
        repair.placement_replica_backend_id = placement.replica_backend_id.clone();
        repair
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedError {
    #[error("invalid managed streaming mode {0:?}")]
    InvalidMode(String),
    #[error("managed mutations are disabled in {0:?} mode")]
    MutationDisabled(ManagedStreamingMode),
    #[error("managed mode off is invalid after authority exists")]
    OffAfterAuthority,
    #[error("managed authority compare-and-swap conflict")]
    Conflict,
    #[error("managed authority data is corrupt: {0}")]
    Corrupt(String),
    #[error("managed authority persistence failed: {0}")]
    Persistence(String),
    #[error("managed namespace is fenced for purge")]
    NamespaceFenced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacePurgeRequest {
    pub tenant_id: String,
    /// Idempotency key owned by the caller and persisted by implementations
    /// that support complete physical generation deletion.
    pub operation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespacePurgeStatus {
    Pending,
    Running,
    Complete { deleted_versions: u64 },
    Blocked { reason: String },
    Unsupported { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalWriteIntent {
    pub intent_id: Uuid,
    pub tenant_id: String,
    pub backend_id: String,
    pub backend_fingerprint: String,
    pub provider_bucket: String,
    pub physical_key: String,
    pub versioning_mode: BackendVersioningMode,
    pub versioning_capability: BackendVersioningCapability,
    pub lease_owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalWriteLease {
    pub intent_id: Uuid,
    pub namespace_epoch: u64,
    pub owner: String,
    pub token: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePhysicalWriteIntent {
    pub intent: PhysicalWriteIntent,
    pub namespace_epoch: u64,
    pub blocked_reason: Option<String>,
    pub lease_expires_at_ms: i64,
    pub lease: PhysicalWriteLease,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalVersionTarget {
    pub tenant_id: String,
    pub namespace_epoch: u64,
    pub backend_id: String,
    pub backend_fingerprint: String,
    pub provider_bucket: String,
    pub physical_key: String,
    pub version_id: Option<String>,
    pub versioning_mode: BackendVersioningMode,
    pub versioning_capability: BackendVersioningCapability,
    pub write_operation_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendVersioningMode {
    Unversioned,
    Enabled,
    Suspended,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendVersioningCapability {
    Unsupported,
    Optional,
    Required,
}

impl BackendVersioningCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "UNSUPPORTED",
            Self::Optional => "OPTIONAL",
            Self::Required => "REQUIRED",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "UNSUPPORTED" => Ok(Self::Unsupported),
            "OPTIONAL" => Ok(Self::Optional),
            "REQUIRED" => Ok(Self::Required),
            value => Err(ManagedError::Corrupt(format!(
                "unknown backend versioning capability {value:?}"
            ))),
        }
    }
}

impl BackendVersioningMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unversioned => "UNVERSIONED",
            Self::Enabled => "ENABLED",
            Self::Suspended => "SUSPENDED",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "UNVERSIONED" => Ok(Self::Unversioned),
            "ENABLED" => Ok(Self::Enabled),
            "SUSPENDED" => Ok(Self::Suspended),
            "UNKNOWN" => Ok(Self::Unknown),
            value => Err(ManagedError::Corrupt(format!(
                "unknown backend versioning mode {value:?}"
            ))),
        }
    }
}

#[async_trait]
pub trait ManagedRepository: Send + Sync {
    fn is_durable(&self) -> bool;
    async fn assert_namespace_active(&self, _tenant_id: &str) -> Result<(), ManagedError> {
        Ok(())
    }
    async fn begin_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn assert_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
        _allow_purging: bool,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn confirm_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn reconcile_multipart_activities(&self, _limit: u64) -> Result<u64, ManagedError> {
        Ok(0)
    }
    async fn finish_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn any_authority(&self) -> Result<bool, ManagedError>;
    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError>;
    async fn publish(
        &self,
        authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError>;
    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError>;
    async fn enqueue(&self, repair: RepairRecord) -> Result<(), ManagedError>;
    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError>;
    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError>;
    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError>;
    async fn fail_repair(&self, lease_token: Uuid, error: &str) -> Result<(), ManagedError>;

    /// Persist a write intent before any provider operation can create a
    /// physical version. Implementations must reject a fenced namespace.
    async fn begin_physical_write(
        &self,
        _intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn pending_physical_write_intents(
        &self,
        _limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        Ok(Vec::new())
    }
    async fn renew_physical_write_intent(
        &self,
        _lease: &PhysicalWriteLease,
        _lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical write lease is unsupported".to_string(),
        ))
    }
    async fn claim_expired_physical_write_intent(
        &self,
        _intent_id: Uuid,
        _owner: &str,
        _lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        Ok(None)
    }

    /// Atomically replace a durable write intent with its exact provider
    /// version. `None` denotes an unversioned object.
    async fn commit_physical_write(
        &self,
        _lease: &PhysicalWriteLease,
        _superseded_version_ids: &[String],
        _version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn abort_physical_write(&self, _lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn block_physical_write(
        &self,
        _lease: &PhysicalWriteLease,
        _reason: &str,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn physical_versions(
        &self,
        _tenant_id: &str,
        _backend_id: &str,
        _provider_bucket: &str,
        _physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn forget_physical_version(
        &self,
        _target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn purge_targets(
        &self,
        _request: &NamespacePurgeRequest,
        _limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Ok(Vec::new())
    }

    async fn mark_purge_target_deleted(
        &self,
        _request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed namespace purge target tracking is unsupported".to_string(),
        ))
    }

    async fn mark_purge_target_blocked(
        &self,
        _request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
        _reason: &str,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed namespace purge target tracking is unsupported".to_string(),
        ))
    }

    /// Purge every physical generation owned by a managed tenant namespace.
    /// The default is deliberately unsupported: authority rows are not a full
    /// version ledger, so ListObjects-based deletion cannot prove completeness.
    async fn purge_namespace(
        &self,
        _request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        Ok(NamespacePurgeStatus::Unsupported {
            reason: "managed storage has no complete physical version ledger".to_string(),
        })
    }

    /// Query an idempotent purge operation without starting or advancing it.
    async fn namespace_purge_status(
        &self,
        _request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        Ok(NamespacePurgeStatus::Unsupported {
            reason: "managed storage has no complete physical version ledger".to_string(),
        })
    }
}

fn cleanup_repairs(authority: &ObjectAuthority) -> Vec<RepairRecord> {
    let mut repairs = vec![RepairRecord::copy(
        RepairKind::DeleteGeneration,
        authority,
        None,
        authority.primary_backend_id.clone(),
        RepairTargetRole::Cleanup,
        authority.placement_version,
    )];
    if let Some(replica) = &authority.replica_backend_id {
        repairs.push(RepairRecord::copy(
            RepairKind::DeleteGeneration,
            authority,
            None,
            replica.clone(),
            RepairTargetRole::Cleanup,
            authority.placement_version,
        ));
    }
    repairs
}

fn publication_repairs(authority: &ObjectAuthority) -> Vec<RepairRecord> {
    match (&authority.replica_backend_id, authority.replica_status) {
        (Some(replica), CopyStatus::RepairPending) => vec![RepairRecord::copy(
            RepairKind::Replica,
            authority,
            Some(authority.primary_backend_id.clone()),
            replica.clone(),
            RepairTargetRole::Replica,
            authority.placement_version,
        )],
        _ => Vec::new(),
    }
}

fn apply_repair_to_authority(
    authority: &mut ObjectAuthority,
    repair: &RepairRecord,
) -> Result<bool, ManagedError> {
    if repair.kind == RepairKind::Placement {
        let Some(primary) = repair.placement_primary_backend_id.as_deref() else {
            return Err(ManagedError::Corrupt(
                "placement repair has no requested primary backend".to_string(),
            ));
        };
        if repair.placement_version < authority.placement_version {
            return Ok(false);
        }
        match repair.target_role {
            RepairTargetRole::Primary if repair.target_backend_id == primary => {
                authority.primary_backend_id = primary.to_string();
                authority.primary_status = CopyStatus::Ready;
                if repair.placement_replica_backend_id.is_none() {
                    authority.replica_backend_id = None;
                    authority.replica_status = CopyStatus::Absent;
                }
            }
            RepairTargetRole::Replica
                if repair.placement_replica_backend_id.as_deref()
                    == Some(repair.target_backend_id.as_str()) =>
            {
                authority.replica_backend_id = Some(repair.target_backend_id.clone());
                authority.replica_status = CopyStatus::Ready;
            }
            _ => {
                return Err(ManagedError::Corrupt(
                    "placement repair target does not match requested placement".to_string(),
                ));
            }
        }
        if authority.primary_backend_id == primary
            && authority.primary_status == CopyStatus::Ready
            && match repair.placement_replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            }
        {
            authority.placement_version = repair.placement_version;
        }
        return Ok(true);
    }

    match repair.target_role {
        RepairTargetRole::Primary => {
            authority.primary_backend_id = repair.target_backend_id.clone();
            authority.primary_status = CopyStatus::Ready;
        }
        RepairTargetRole::Replica => {
            authority.replica_backend_id = Some(repair.target_backend_id.clone());
            authority.replica_status = CopyStatus::Ready;
        }
        RepairTargetRole::Cleanup => return Ok(false),
    }
    Ok(true)
}

fn authority_from_model(
    model: managed_object_authority::Model,
) -> Result<ObjectAuthority, ManagedError> {
    Ok(ObjectAuthority {
        logical: LogicalObjectKey {
            tenant_id: model.tenant_id,
            bucket: model.bucket,
            key: model.logical_key,
        },
        generation: model.generation,
        digest: model.digest,
        size: u64::try_from(model.size_bytes)
            .map_err(|_| ManagedError::Corrupt("negative authority size".to_string()))?,
        metadata: serde_json::from_value(model.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
        placement_version: u32::try_from(model.placement_version)
            .map_err(|_| ManagedError::Corrupt("invalid placement version".to_string()))?,
        primary_backend_id: model.primary_backend_id,
        replica_backend_id: model.replica_backend_id,
        primary_status: CopyStatus::parse(&model.primary_status)?,
        replica_status: CopyStatus::parse(&model.replica_status)?,
        tombstone: model.tombstone,
        cas_version: u64::try_from(model.cas_version)
            .map_err(|_| ManagedError::Corrupt("invalid authority CAS version".to_string()))?,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

fn repair_from_model(model: managed_object_repair::Model) -> Result<RepairRecord, ManagedError> {
    Ok(RepairRecord {
        id: model.lease_token.unwrap_or(model.id),
        repair_id: model.id,
        kind: RepairKind::parse(&model.kind)?,
        logical: LogicalObjectKey {
            tenant_id: model.tenant_id,
            bucket: model.bucket,
            key: model.logical_key,
        },
        namespace_epoch: u64::try_from(model.namespace_epoch)
            .map_err(|_| ManagedError::Corrupt("invalid repair namespace epoch".to_string()))?,
        authority_cas_version: u64::try_from(model.authority_cas_version)
            .map_err(|_| ManagedError::Corrupt("invalid repair authority CAS".to_string()))?,
        generation: model.generation,
        digest: model.digest,
        size: u64::try_from(model.size_bytes)
            .map_err(|_| ManagedError::Corrupt("negative repair size".to_string()))?,
        metadata: serde_json::from_value(model.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
        physical_key: model.physical_key,
        source_backend_id: model.source_backend_id,
        target_backend_id: model.target_backend_id,
        target_role: RepairTargetRole::parse(&model.target_role)?,
        placement_version: u32::try_from(model.placement_version)
            .map_err(|_| ManagedError::Corrupt("invalid repair placement version".to_string()))?,
        placement_primary_backend_id: model.placement_primary_backend_id,
        placement_replica_backend_id: model.placement_replica_backend_id,
        attempts: u32::try_from(model.attempts)
            .map_err(|_| ManagedError::Corrupt("negative repair attempts".to_string()))?,
        lease_owner: model.lease_owner,
        lease_token: model.lease_token,
        lease_expires_at_ms: model.lease_expires_at_ms,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

fn repair_active(repair: RepairRecord) -> Result<managed_object_repair::ActiveModel, ManagedError> {
    Ok(managed_object_repair::ActiveModel {
        id: Set(repair.repair_id),
        kind: Set(repair.kind.as_str().to_string()),
        state: Set("PENDING".to_string()),
        tenant_id: Set(repair.logical.tenant_id),
        namespace_epoch: Set(i64::try_from(repair.namespace_epoch).map_err(|_| {
            ManagedError::Corrupt("repair namespace epoch exceeds BIGINT".to_string())
        })?),
        authority_cas_version: Set(i64::try_from(repair.authority_cas_version).map_err(|_| {
            ManagedError::Corrupt("repair authority CAS exceeds BIGINT".to_string())
        })?),
        bucket: Set(repair.logical.bucket),
        logical_key: Set(repair.logical.key),
        generation: Set(repair.generation),
        digest: Set(repair.digest),
        size_bytes: Set(i64::try_from(repair.size)
            .map_err(|_| ManagedError::Corrupt("repair size exceeds BIGINT".to_string()))?),
        metadata: Set(serde_json::to_value(repair.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?),
        physical_key: Set(repair.physical_key),
        source_backend_id: Set(repair.source_backend_id),
        target_backend_id: Set(repair.target_backend_id),
        target_role: Set(repair.target_role.as_str().to_string()),
        placement_version: Set(i64::from(repair.placement_version)),
        placement_primary_backend_id: Set(repair.placement_primary_backend_id),
        placement_replica_backend_id: Set(repair.placement_replica_backend_id),
        attempts: Set(i32::try_from(repair.attempts)
            .map_err(|_| ManagedError::Corrupt("repair attempts exceed INTEGER".to_string()))?),
        lease_owner: Set(repair.lease_owner),
        lease_token: Set(None),
        lease_expires_at_ms: Set(repair.lease_expires_at_ms),
        last_error: Set(None),
        created_at_ms: Set(repair.created_at_ms),
        updated_at_ms: Set(repair.updated_at_ms),
    })
}

fn persistence(error: impl std::fmt::Display) -> ManagedError {
    ManagedError::Persistence(error.to_string())
}

async fn locked_namespace<C>(
    db: &C,
    tenant_id: &str,
) -> Result<managed_namespace::Model, ManagedError>
where
    C: ConnectionTrait,
{
    let now = crate::transaction::unix_time_ms();
    managed_namespace::Entity::insert(managed_namespace::ActiveModel {
        tenant_id: Set(tenant_id.to_string()),
        epoch: Set(1),
        state: Set("ACTIVE".to_string()),
        purge_operation_id: Set(None),
        created_at_ms: Set(now),
        updated_at_ms: Set(now),
    })
    .on_conflict(
        OnConflict::column(managed_namespace::Column::TenantId)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(db)
    .await
    .map_err(persistence)?;
    managed_namespace::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
        .ok_or_else(|| ManagedError::Persistence("managed namespace disappeared".to_string()))
}

async fn require_active_namespace<C>(db: &C, tenant_id: &str) -> Result<i64, ManagedError>
where
    C: ConnectionTrait,
{
    let namespace = locked_namespace(db, tenant_id).await?;
    if namespace.state != "ACTIVE" {
        return Err(ManagedError::NamespaceFenced);
    }
    Ok(namespace.epoch)
}

fn purge_status_from_model(
    purge: managed_namespace_purge::Model,
) -> Result<NamespacePurgeStatus, ManagedError> {
    match purge.state.as_str() {
        "RUNNING" => Ok(NamespacePurgeStatus::Running),
        "BLOCKED" => Ok(NamespacePurgeStatus::Blocked {
            reason: purge
                .blocked_reason
                .unwrap_or_else(|| "managed namespace purge is blocked".to_string()),
        }),
        "COMPLETE" => Ok(NamespacePurgeStatus::Complete {
            deleted_versions: u64::try_from(purge.deleted_versions).map_err(|_| {
                ManagedError::Corrupt("purge deleted-version count is invalid".to_string())
            })?,
        }),
        state => Err(ManagedError::Corrupt(format!(
            "unknown managed namespace purge state {state:?}"
        ))),
    }
}

fn physical_target_from_model(
    model: managed_physical_object_version::Model,
) -> Result<PhysicalVersionTarget, ManagedError> {
    Ok(PhysicalVersionTarget {
        tenant_id: model.tenant_id,
        namespace_epoch: u64::try_from(model.epoch)
            .map_err(|_| ManagedError::Corrupt("physical version epoch is invalid".to_string()))?,
        backend_id: model.backend_id,
        backend_fingerprint: model.backend_fingerprint,
        provider_bucket: model.provider_bucket,
        physical_key: model.physical_key,
        version_id: (!model.version_id.is_empty()).then_some(model.version_id),
        versioning_mode: BackendVersioningMode::parse(&model.versioning_mode)?,
        versioning_capability: BackendVersioningCapability::parse(&model.versioning_capability)?,
        write_operation_id: model.write_operation_id,
    })
}

#[derive(Clone, Debug)]
pub struct PostgresManagedRepository {
    db: DatabaseConnection,
}

impl PostgresManagedRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            db: SqlxPostgresConnector::from_sqlx_postgres_pool(pool),
        }
    }

    async fn finalize_purge_if_ready(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let purge = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .filter(|purge| purge.tenant_id == request.tenant_id);
        let Some(purge) = purge else {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "managed namespace purge operation was not found".to_string(),
            });
        };
        if purge.state == "COMPLETE" {
            return purge_status_from_model(purge);
        }

        let now = crate::transaction::unix_time_ms();
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_PENDING"),
            )
            .col_expr(
                managed_physical_object_version::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_object_version::Column::Epoch.lte(purge.epoch))
            .filter(managed_physical_object_version::Column::State.eq("LIVE"))
            .exec(&txn)
            .await
            .map_err(persistence)?;

        let intents = managed_physical_write_intent::Entity::find()
            .filter(managed_physical_write_intent::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_write_intent::Column::Epoch.lte(purge.epoch))
            .all(&txn)
            .await
            .map_err(persistence)?;
        let targets = managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .all(&txn)
            .await
            .map_err(persistence)?;
        if let Some(intent) = intents.iter().find(|intent| intent.state == "BLOCKED") {
            let reason = intent
                .last_error
                .clone()
                .unwrap_or_else(|| "physical provider version history is ambiguous".to_string());
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }
        if !intents.is_empty() || targets.iter().any(|target| target.state == "PURGE_PENDING") {
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Running);
        }
        if let Some(target) = targets
            .iter()
            .find(|target| target.state == "PURGE_BLOCKED")
        {
            let reason = target
                .last_error
                .clone()
                .unwrap_or_else(|| "physical version deletion is blocked".to_string());
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        let unresolved_journal_rows = object_operation::Entity::find()
            .filter(object_operation::Column::TenantId.eq(&request.tenant_id))
            .filter(object_operation::Column::NamespaceEpoch.lte(purge.epoch))
            .filter(object_operation::Column::State.is_not_in([
                crate::transaction::OperationState::Committed.as_str(),
                crate::transaction::OperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if unresolved_journal_rows > 0 {
            let reason = "managed namespace has unresolved operation journal rows".to_string();
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        // Multipart staging owns encrypted artifacts and quota accounting in a
        // separate repository. Completing purge while rows remain would leak
        // those artifacts, so fail closed instead of deleting metadata alone.
        let multipart_uploads = crate::entity::multipart_upload::Entity::find()
            .filter(crate::entity::multipart_upload::Column::TenantId.eq(&request.tenant_id))
            .filter(
                Condition::any()
                    .add(crate::entity::multipart_upload::Column::NamespaceEpoch.is_null())
                    .add(crate::entity::multipart_upload::Column::NamespaceEpoch.lte(purge.epoch)),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        let multipart_activities = managed_multipart_activity::Entity::find()
            .filter(managed_multipart_activity::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.lte(purge.epoch))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if multipart_uploads > 0 || multipart_activities > 0 {
            let reason =
                "managed namespace has multipart staging artifacts that must be aborted first"
                    .to_string();
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_object_repair::Column::NamespaceEpoch.lte(purge.epoch))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        object_operation::Entity::delete_many()
            .filter(object_operation::Column::TenantId.eq(&request.tenant_id))
            .filter(object_operation::Column::NamespaceEpoch.lte(purge.epoch))
            .filter(object_operation::Column::State.is_in([
                crate::transaction::OperationState::Committed.as_str(),
                crate::transaction::OperationState::ProvenAborted.as_str(),
            ]))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace::Entity::update_many()
            .col_expr(
                managed_namespace::Column::Epoch,
                Expr::value(purge.epoch.saturating_add(1)),
            )
            .col_expr(managed_namespace::Column::State, Expr::value("ACTIVE"))
            .col_expr(
                managed_namespace::Column::PurgeOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(managed_namespace::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_namespace::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_namespace::Column::PurgeOperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace_purge::Entity::update_many()
            .col_expr(
                managed_namespace_purge::Column::State,
                Expr::value("COMPLETE"),
            )
            .col_expr(
                managed_namespace_purge::Column::BlockedReason,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_namespace_purge::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_namespace_purge::Column::CompletedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        let mut complete = purge;
        complete.state = "COMPLETE".to_string();
        complete.completed_at_ms = Some(now);
        purge_status_from_model(complete)
    }
}

async fn insert_repair<C>(db: &C, repair: RepairRecord) -> Result<(), ManagedError>
where
    C: sea_orm::ConnectionTrait,
{
    let revival = repair.clone();
    let kind = repair.kind.as_str().to_string();
    let generation = repair.generation;
    let target = repair.target_backend_id.clone();
    let inserted = managed_object_repair::Entity::insert(repair_active(repair)?)
        .on_conflict(
            OnConflict::columns([
                managed_object_repair::Column::Kind,
                managed_object_repair::Column::Generation,
                managed_object_repair::Column::TargetBackendId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(db)
        .await
        .map_err(persistence)?;
    if inserted == 1 {
        return Ok(());
    }
    let existing = managed_object_repair::Entity::find()
        .filter(managed_object_repair::Column::Kind.eq(kind))
        .filter(managed_object_repair::Column::Generation.eq(generation))
        .filter(managed_object_repair::Column::TargetBackendId.eq(target))
        .one(db)
        .await
        .map_err(persistence)?;
    let Some(existing) = existing else {
        return Err(ManagedError::Persistence(
            "managed repair conflict row disappeared".to_string(),
        ));
    };
    if existing.state == "DONE" {
        managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value("PENDING"))
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .col_expr(
                managed_object_repair::Column::NamespaceEpoch,
                Expr::value(i64::try_from(revival.namespace_epoch).map_err(|_| {
                    ManagedError::Corrupt("repair namespace epoch exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::AuthorityCasVersion,
                Expr::value(i64::try_from(revival.authority_cas_version).map_err(|_| {
                    ManagedError::Corrupt("repair authority CAS exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::SourceBackendId,
                Expr::value(revival.source_backend_id),
            )
            .col_expr(
                managed_object_repair::Column::PhysicalKey,
                Expr::value(revival.physical_key),
            )
            .col_expr(
                managed_object_repair::Column::Digest,
                Expr::value(revival.digest),
            )
            .col_expr(
                managed_object_repair::Column::SizeBytes,
                Expr::value(i64::try_from(revival.size).map_err(|_| {
                    ManagedError::Corrupt("repair size exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::Metadata,
                Expr::value(
                    serde_json::to_value(revival.metadata)
                        .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
                ),
            )
            .col_expr(
                managed_object_repair::Column::TargetRole,
                Expr::value(revival.target_role.as_str()),
            )
            .col_expr(
                managed_object_repair::Column::PlacementVersion,
                Expr::value(i64::from(revival.placement_version)),
            )
            .col_expr(
                managed_object_repair::Column::PlacementPrimaryBackendId,
                Expr::value(revival.placement_primary_backend_id),
            )
            .col_expr(
                managed_object_repair::Column::PlacementReplicaBackendId,
                Expr::value(revival.placement_replica_backend_id),
            )
            .filter(managed_object_repair::Column::Id.eq(existing.id))
            .exec(db)
            .await
            .map_err(persistence)?;
    }
    Ok(())
}

fn authority_active(
    authority: &ObjectAuthority,
) -> Result<managed_object_authority::ActiveModel, ManagedError> {
    Ok(managed_object_authority::ActiveModel {
        tenant_id: Set(authority.logical.tenant_id.clone()),
        bucket: Set(authority.logical.bucket.clone()),
        logical_key: Set(authority.logical.key.clone()),
        generation: Set(authority.generation),
        digest: Set(authority.digest.clone()),
        size_bytes: Set(i64::try_from(authority.size)
            .map_err(|_| ManagedError::Corrupt("authority size exceeds BIGINT".to_string()))?),
        metadata: Set(serde_json::to_value(&authority.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?),
        placement_version: Set(i64::from(authority.placement_version)),
        primary_backend_id: Set(authority.primary_backend_id.clone()),
        replica_backend_id: Set(authority.replica_backend_id.clone()),
        primary_status: Set(authority.primary_status.as_str().to_string()),
        replica_status: Set(authority.replica_status.as_str().to_string()),
        tombstone: Set(authority.tombstone),
        cas_version: Set(i64::try_from(authority.cas_version)
            .map_err(|_| ManagedError::Corrupt("authority CAS exceeds BIGINT".to_string()))?),
        created_at_ms: Set(authority.created_at_ms),
        updated_at_ms: Set(authority.updated_at_ms),
    })
}

#[async_trait]
impl ManagedRepository for PostgresManagedRepository {
    fn is_durable(&self) -> bool {
        true
    }

    async fn assert_namespace_active(&self, tenant_id: &str) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        require_active_namespace(&txn, tenant_id).await?;
        txn.commit().await.map_err(persistence)
    }

    async fn begin_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let epoch = require_active_namespace(&txn, tenant_id).await?;
        let now = crate::transaction::unix_time_ms();
        managed_multipart_activity::ActiveModel {
            upload_id: Set(upload_id.to_string()),
            tenant_id: Set(tenant_id.to_string()),
            namespace_epoch: Set(epoch),
            state: Set("REGISTERING".to_string()),
            registration_expires_at_ms: Set(Some(now.saturating_add(10 * 60 * 1000))),
            created_at_ms: Set(now),
            updated_at_ms: Set(now),
        }
        .insert(&txn)
        .await
        .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        u64::try_from(epoch)
            .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))
    }

    async fn assert_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
        allow_purging: bool,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, tenant_id).await?;
        if namespace.epoch != epoch
            || (namespace.state != "ACTIVE" && !(allow_purging && namespace.state == "PURGING"))
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let activity = managed_multipart_activity::Entity::find_by_id(upload_id.to_string())
            .one(&txn)
            .await
            .map_err(persistence)?;
        if activity.is_none_or(|activity| {
            activity.tenant_id != tenant_id
                || activity.namespace_epoch != epoch
                || activity.state != "ACTIVE"
        }) {
            return Err(ManagedError::NamespaceFenced);
        }
        txn.commit().await.map_err(persistence)
    }

    async fn confirm_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, tenant_id).await?;
        if namespace.state != "ACTIVE" || namespace.epoch != epoch {
            return Err(ManagedError::NamespaceFenced);
        }
        if let Some(existing) =
            managed_multipart_activity::Entity::find_by_id(upload_id.to_string())
                .one(&txn)
                .await
                .map_err(persistence)?
            && existing.tenant_id == tenant_id
            && existing.namespace_epoch == epoch
            && existing.state == "ACTIVE"
        {
            txn.commit().await.map_err(persistence)?;
            return Ok(());
        }
        let result = managed_multipart_activity::Entity::update_many()
            .col_expr(
                managed_multipart_activity::Column::State,
                Expr::value("ACTIVE"),
            )
            .col_expr(
                managed_multipart_activity::Column::RegistrationExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_multipart_activity::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_multipart_activity::Column::UploadId.eq(upload_id))
            .filter(managed_multipart_activity::Column::TenantId.eq(tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.eq(epoch))
            .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::NamespaceFenced);
        }
        txn.commit().await.map_err(persistence)
    }

    async fn reconcile_multipart_activities(&self, limit: u64) -> Result<u64, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let candidates = managed_multipart_activity::Entity::find()
            .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
            .filter(managed_multipart_activity::Column::RegistrationExpiresAtMs.lte(now))
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let count = candidates.len() as u64;
        for activity in candidates {
            let upload = crate::entity::multipart_upload::Entity::find()
                .filter(crate::entity::multipart_upload::Column::UploadId.eq(&activity.upload_id))
                .filter(crate::entity::multipart_upload::Column::TenantId.eq(&activity.tenant_id))
                .filter(
                    crate::entity::multipart_upload::Column::NamespaceEpoch
                        .eq(activity.namespace_epoch),
                )
                .one(&self.db)
                .await
                .map_err(persistence)?;
            if upload.is_some() {
                managed_multipart_activity::Entity::update_many()
                    .col_expr(
                        managed_multipart_activity::Column::State,
                        Expr::value("ACTIVE"),
                    )
                    .col_expr(
                        managed_multipart_activity::Column::RegistrationExpiresAtMs,
                        Expr::value(Option::<i64>::None),
                    )
                    .filter(managed_multipart_activity::Column::UploadId.eq(&activity.upload_id))
                    .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
                    .exec(&self.db)
                    .await
                    .map_err(persistence)?;
            } else {
                managed_multipart_activity::Entity::delete_many()
                    .filter(managed_multipart_activity::Column::UploadId.eq(&activity.upload_id))
                    .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
                    .filter(managed_multipart_activity::Column::RegistrationExpiresAtMs.lte(now))
                    .exec(&self.db)
                    .await
                    .map_err(persistence)?;
            }
        }
        Ok(count)
    }

    async fn finish_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        managed_multipart_activity::Entity::delete_many()
            .filter(managed_multipart_activity::Column::UploadId.eq(upload_id))
            .filter(managed_multipart_activity::Column::TenantId.eq(tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.eq(epoch))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    async fn any_authority(&self) -> Result<bool, ManagedError> {
        Ok(managed_object_authority::Entity::find()
            .limit(1)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .is_some())
    }

    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        require_active_namespace(&txn, &logical.tenant_id).await?;
        let authority = managed_object_authority::Entity::find_by_id((
            logical.tenant_id.clone(),
            logical.bucket.clone(),
            logical.key.clone(),
        ))
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        txn.commit().await.map_err(persistence)?;
        Ok(authority)
    }

    async fn publish(
        &self,
        mut authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &authority.logical.tenant_id).await?;
        if !authority.tombstone {
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let primary_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId
                        .eq(&authority.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&authority.primary_backend_id),
                )
                .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                .count(&txn)
                .await
                .map_err(persistence)?;
            if primary_versions == 0 {
                return Err(ManagedError::Persistence(
                    "managed primary cannot publish before its physical versions are ledgered"
                        .to_string(),
                ));
            }
            if authority.replica_status == CopyStatus::Ready
                && let Some(replica) = &authority.replica_backend_id
            {
                let replica_versions = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&authority.logical.tenant_id),
                    )
                    .filter(managed_physical_object_version::Column::BackendId.eq(replica))
                    .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if replica_versions == 0 {
                    return Err(ManagedError::Persistence(
                        "managed replica cannot publish before its physical versions are ledgered"
                            .to_string(),
                    ));
                }
            }
        }
        let existing = managed_object_authority::Entity::find_by_id((
            authority.logical.tenant_id.clone(),
            authority.logical.bucket.clone(),
            authority.logical.key.clone(),
        ))
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        authority.cas_version = expected_cas.unwrap_or(0).saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        match expected_cas {
            None => {
                authority_active(&authority)?
                    .insert(&txn)
                    .await
                    .map_err(|_| ManagedError::Conflict)?;
            }
            Some(expected) => {
                let active = authority_active(&authority)?;
                let result = managed_object_authority::Entity::update_many()
                    .set(active)
                    .filter(
                        managed_object_authority::Column::TenantId.eq(&authority.logical.tenant_id),
                    )
                    .filter(managed_object_authority::Column::Bucket.eq(&authority.logical.bucket))
                    .filter(managed_object_authority::Column::LogicalKey.eq(&authority.logical.key))
                    .filter(
                        managed_object_authority::Column::CasVersion
                            .eq(i64::try_from(expected).map_err(|_| ManagedError::Conflict)?),
                    )
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                if result.rows_affected != 1 {
                    return Err(ManagedError::Conflict);
                }
            }
        }
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = u64::try_from(namespace_epoch)
                .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
            insert_repair(&txn, repair).await?;
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets == 0 {
                    continue;
                }
                repair.namespace_epoch = u64::try_from(namespace_epoch)
                    .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
                insert_repair(&txn, repair).await?;
            }
        }
        txn.commit().await.map_err(persistence)?;
        Ok(authority)
    }

    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let existing = self.get(logical).await?;
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let generation = Uuid::now_v7();
        let now = crate::transaction::unix_time_ms();
        let tombstone = ObjectAuthority {
            logical: logical.clone(),
            generation,
            digest: String::new(),
            size: 0,
            metadata: BTreeMap::new(),
            placement_version: placement.version,
            primary_backend_id: placement.primary_backend_id.clone(),
            replica_backend_id: placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
            tombstone: true,
            cas_version: 0,
            created_at_ms: now,
            updated_at_ms: now,
        };
        self.publish(tombstone, expected_cas).await
    }

    async fn enqueue(&self, mut repair: RepairRecord) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &repair.logical.tenant_id).await?;
        let current = managed_object_authority::Entity::find_by_id((
            repair.logical.tenant_id.clone(),
            repair.logical.bucket.clone(),
            repair.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        if repair.kind == RepairKind::DeleteGeneration {
            let targets = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId.eq(&repair.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&repair.target_backend_id),
                )
                .filter(
                    managed_physical_object_version::Column::PhysicalKey.eq(&repair.physical_key),
                )
                .all(&txn)
                .await
                .map_err(persistence)?;
            if targets.is_empty() {
                txn.commit().await.map_err(persistence)?;
                return Ok(());
            }
            if targets.iter().any(|target| target.epoch != namespace_epoch) {
                return Err(ManagedError::Conflict);
            }
        } else if current.as_ref().is_none_or(|authority| {
            authority.generation != repair.generation
                || authority.cas_version != repair.authority_cas_version
        }) {
            return Err(ManagedError::Conflict);
        }
        repair.namespace_epoch = u64::try_from(namespace_epoch)
            .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
        insert_repair(&txn, repair).await?;
        txn.commit().await.map_err(persistence)
    }

    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let candidates = managed_object_repair::Entity::find()
            .filter(
                Condition::any()
                    .add(managed_object_repair::Column::State.eq("PENDING"))
                    .add(
                        Condition::all()
                            .add(managed_object_repair::Column::State.eq("LEASED"))
                            .add(managed_object_repair::Column::LeaseExpiresAtMs.lte(now)),
                    ),
            )
            .order_by_asc(managed_object_repair::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let mut claimed = Vec::new();
        for candidate in candidates {
            let txn = self.db.begin().await.map_err(persistence)?;
            match require_active_namespace(&txn, &candidate.tenant_id).await {
                Ok(epoch) if epoch == candidate.namespace_epoch => {}
                Ok(_) => continue,
                Err(ManagedError::NamespaceFenced) => continue,
                Err(error) => return Err(error),
            }
            let lease_token = Uuid::now_v7();
            let result = managed_object_repair::Entity::update_many()
                .col_expr(managed_object_repair::Column::State, Expr::value("LEASED"))
                .col_expr(
                    managed_object_repair::Column::LeaseOwner,
                    Expr::value(Some(owner.to_string())),
                )
                .col_expr(
                    managed_object_repair::Column::LeaseExpiresAtMs,
                    Expr::value(Some(lease_until_ms)),
                )
                .col_expr(
                    managed_object_repair::Column::LeaseToken,
                    Expr::value(Some(lease_token)),
                )
                .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
                .filter(managed_object_repair::Column::Id.eq(candidate.id))
                .filter(
                    Condition::any()
                        .add(managed_object_repair::Column::State.eq("PENDING"))
                        .add(
                            Condition::all()
                                .add(managed_object_repair::Column::State.eq("LEASED"))
                                .add(managed_object_repair::Column::LeaseExpiresAtMs.lte(now)),
                        ),
                )
                .exec(&txn)
                .await
                .map_err(persistence)?;
            if result.rows_affected == 1 {
                let mut record = repair_from_model(candidate)?;
                record.id = lease_token;
                record.lease_owner = Some(owner.to_string());
                record.lease_token = Some(lease_token);
                record.lease_expires_at_ms = Some(lease_until_ms);
                claimed.push(record);
            }
            txn.commit().await.map_err(persistence)?;
        }
        Ok(claimed)
    }

    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let result = managed_object_repair::Entity::update_many()
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Some(lease_until_ms)),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(lease_token))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        Ok(())
    }

    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &repair.logical.tenant_id).await?;
        if u64::try_from(namespace_epoch).ok() != Some(repair.namespace_epoch) {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        if repair.lease_token != Some(repair.id) {
            return Err(ManagedError::Conflict);
        }
        let result = managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value("DONE"))
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::Id.eq(repair.repair_id))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(repair.id))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        let mut authority_updated = false;
        if repair.kind != RepairKind::DeleteGeneration {
            let target_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId.eq(&repair.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&repair.target_backend_id),
                )
                .filter(
                    managed_physical_object_version::Column::PhysicalKey.eq(&repair.physical_key),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if target_versions == 0 {
                return Err(ManagedError::Persistence(
                    "managed repair cannot publish before target physical versions are ledgered"
                        .to_string(),
                ));
            }
            let current = managed_object_authority::Entity::find_by_id((
                repair.logical.tenant_id.clone(),
                repair.logical.bucket.clone(),
                repair.logical.key.clone(),
            ))
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?;
            if let Some(current) = current {
                let mut authority = authority_from_model(current.clone())?;
                if authority.generation == repair.generation
                    && (repair.kind == RepairKind::Placement
                        || authority.cas_version == repair.authority_cas_version)
                    && !authority.tombstone
                    && apply_repair_to_authority(&mut authority, repair)?
                {
                    authority.cas_version = authority.cas_version.saturating_add(1);
                    authority.updated_at_ms = crate::transaction::unix_time_ms();
                    let result = managed_object_authority::Entity::update_many()
                        .set(authority_active(&authority)?)
                        .filter(
                            managed_object_authority::Column::TenantId
                                .eq(&repair.logical.tenant_id),
                        )
                        .filter(managed_object_authority::Column::Bucket.eq(&repair.logical.bucket))
                        .filter(
                            managed_object_authority::Column::LogicalKey.eq(&repair.logical.key),
                        )
                        .filter(managed_object_authority::Column::Generation.eq(repair.generation))
                        .filter(
                            managed_object_authority::Column::CasVersion.eq(current.cas_version),
                        )
                        .exec(&txn)
                        .await
                        .map_err(persistence)?;
                    if result.rows_affected != 1 {
                        return Err(ManagedError::Conflict);
                    }
                    authority_updated = true;
                }
            }
        }
        txn.commit().await.map_err(persistence)?;
        Ok(authority_updated)
    }

    async fn fail_repair(&self, lease_token: Uuid, error: &str) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let result = managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value("PENDING"))
            .col_expr(
                managed_object_repair::Column::Attempts,
                Expr::col(managed_object_repair::Column::Attempts).add(1),
            )
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_object_repair::Column::LastError,
                Expr::value(Some(error.chars().take(1024).collect::<String>())),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(lease_token))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        Ok(())
    }

    async fn begin_physical_write(
        &self,
        intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let epoch = require_active_namespace(&txn, &intent.tenant_id).await?;
        let now = crate::transaction::unix_time_ms();
        let lease_token = Uuid::now_v7();
        let expected = intent.clone();
        let inserted = managed_physical_write_intent::Entity::insert(
            managed_physical_write_intent::ActiveModel {
                intent_id: Set(intent.intent_id),
                tenant_id: Set(intent.tenant_id),
                epoch: Set(epoch),
                backend_id: Set(intent.backend_id),
                backend_fingerprint: Set(intent.backend_fingerprint),
                provider_bucket: Set(intent.provider_bucket),
                physical_key: Set(intent.physical_key),
                versioning_mode: Set(intent.versioning_mode.as_str().to_string()),
                versioning_capability: Set(intent.versioning_capability.as_str().to_string()),
                state: Set("PENDING".to_string()),
                last_error: Set(None),
                lease_owner: Set(intent.lease_owner.clone()),
                lease_token: Set(lease_token),
                lease_expires_at_ms: Set(now.saturating_add(PHYSICAL_WRITE_LEASE_MS)),
                created_at_ms: Set(now),
                updated_at_ms: Set(now),
            },
        )
        .on_conflict(
            OnConflict::column(managed_physical_write_intent::Column::IntentId)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&txn)
        .await
        .map_err(persistence)?;
        if inserted == 0 {
            let existing = managed_physical_write_intent::Entity::find_by_id(expected.intent_id)
                .one(&txn)
                .await
                .map_err(persistence)?
                .ok_or(ManagedError::Conflict)?;
            if existing.tenant_id != expected.tenant_id
                || existing.epoch != epoch
                || existing.backend_id != expected.backend_id
                || existing.backend_fingerprint != expected.backend_fingerprint
                || existing.provider_bucket != expected.provider_bucket
                || existing.physical_key != expected.physical_key
                || existing.versioning_mode != expected.versioning_mode.as_str()
                || existing.versioning_capability != expected.versioning_capability.as_str()
                || existing.lease_owner != expected.lease_owner
            {
                return Err(ManagedError::Conflict);
            }
            txn.commit().await.map_err(persistence)?;
            return Ok(PhysicalWriteLease {
                intent_id: existing.intent_id,
                namespace_epoch: u64::try_from(existing.epoch)
                    .map_err(|_| ManagedError::Conflict)?,
                owner: existing.lease_owner,
                token: existing.lease_token,
            });
        }
        txn.commit().await.map_err(persistence)?;
        Ok(PhysicalWriteLease {
            intent_id: intent.intent_id,
            namespace_epoch: u64::try_from(epoch)
                .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?,
            owner: intent.lease_owner,
            token: lease_token,
        })
    }

    async fn pending_physical_write_intents(
        &self,
        limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        managed_physical_write_intent::Entity::find()
            .order_by_asc(managed_physical_write_intent::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(|intent| {
                Ok(DurablePhysicalWriteIntent {
                    namespace_epoch: u64::try_from(intent.epoch).map_err(|_| {
                        ManagedError::Corrupt("physical write intent epoch is invalid".to_string())
                    })?,
                    blocked_reason: intent.last_error,
                    lease_expires_at_ms: intent.lease_expires_at_ms,
                    lease: PhysicalWriteLease {
                        intent_id: intent.intent_id,
                        namespace_epoch: u64::try_from(intent.epoch).map_err(|_| {
                            ManagedError::Corrupt(
                                "physical write intent epoch is invalid".to_string(),
                            )
                        })?,
                        owner: intent.lease_owner.clone(),
                        token: intent.lease_token,
                    },
                    intent: PhysicalWriteIntent {
                        intent_id: intent.intent_id,
                        tenant_id: intent.tenant_id,
                        backend_id: intent.backend_id,
                        backend_fingerprint: intent.backend_fingerprint,
                        provider_bucket: intent.provider_bucket,
                        physical_key: intent.physical_key,
                        versioning_mode: BackendVersioningMode::parse(&intent.versioning_mode)?,
                        versioning_capability: BackendVersioningCapability::parse(
                            &intent.versioning_capability,
                        )?,
                        lease_owner: intent.lease_owner,
                    },
                })
            })
            .collect()
    }

    async fn renew_physical_write_intent(
        &self,
        lease: &PhysicalWriteLease,
        lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::LeaseExpiresAtMs,
                Expr::value(lease_expires_at_ms),
            )
            .col_expr(
                managed_physical_write_intent::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        Ok(())
    }

    async fn claim_expired_physical_write_intent(
        &self,
        intent_id: Uuid,
        owner: &str,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let token = Uuid::now_v7();
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::LeaseOwner,
                Expr::value(owner.to_string()),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseToken,
                Expr::value(token),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseExpiresAtMs,
                Expr::value(lease_expires_at_ms),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(intent_id))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .lte(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Ok(None);
        }
        let intent = managed_physical_write_intent::Entity::find_by_id(intent_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        Ok(Some(PhysicalWriteLease {
            intent_id,
            namespace_epoch: u64::try_from(intent.epoch).map_err(|_| ManagedError::Conflict)?,
            owner: owner.to_string(),
            token,
        }))
    }

    async fn commit_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        superseded_version_ids: &[String],
        version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let Some(intent) = managed_physical_write_intent::Entity::find_by_id(lease.intent_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
        else {
            // A committed retry and a confirmed abort are both terminal and
            // safe; neither can create a new provider version here.
            txn.commit().await.map_err(persistence)?;
            return Ok(());
        };
        if intent.lease_owner != lease.owner
            || intent.lease_token != lease.token
            || intent.lease_expires_at_ms <= crate::transaction::unix_time_ms()
        {
            return Err(ManagedError::Conflict);
        }
        let namespace = locked_namespace(&txn, &intent.tenant_id).await?;
        let now = crate::transaction::unix_time_ms();
        let purging = namespace.state == "PURGING";
        for recorded_version_id in superseded_version_ids
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(version_id.unwrap_or_default()))
        {
            managed_physical_object_version::Entity::insert(
                managed_physical_object_version::ActiveModel {
                    tenant_id: Set(intent.tenant_id.clone()),
                    backend_id: Set(intent.backend_id.clone()),
                    backend_fingerprint: Set(intent.backend_fingerprint.clone()),
                    provider_bucket: Set(intent.provider_bucket.clone()),
                    physical_key: Set(intent.physical_key.clone()),
                    versioning_mode: Set(intent.versioning_mode.clone()),
                    versioning_capability: Set(intent.versioning_capability.clone()),
                    write_operation_id: Set(lease.intent_id),
                    version_id: Set(recorded_version_id.to_string()),
                    epoch: Set(intent.epoch),
                    state: Set(if purging {
                        "PURGE_PENDING".to_string()
                    } else {
                        "LIVE".to_string()
                    }),
                    purge_operation_id: Set(if purging {
                        namespace.purge_operation_id
                    } else {
                        None
                    }),
                    last_error: Set(None),
                    created_at_ms: Set(now),
                    updated_at_ms: Set(now),
                },
            )
            .on_conflict(
                OnConflict::columns([
                    managed_physical_object_version::Column::TenantId,
                    managed_physical_object_version::Column::BackendId,
                    managed_physical_object_version::Column::ProviderBucket,
                    managed_physical_object_version::Column::PhysicalKey,
                    managed_physical_object_version::Column::VersionId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(&txn)
            .await
            .map_err(persistence)?;
        }
        managed_physical_write_intent::Entity::delete_by_id(lease.intent_id)
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)
    }

    async fn abort_physical_write(&self, lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        let result = managed_physical_write_intent::Entity::delete_many()
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        (result.rows_affected == 1)
            .then_some(())
            .ok_or(ManagedError::Conflict)
    }

    async fn block_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::State,
                Expr::value("BLOCKED"),
            )
            .col_expr(
                managed_physical_write_intent::Column::LastError,
                Expr::value(Some(reason.chars().take(1024).collect::<String>())),
            )
            .col_expr(
                managed_physical_write_intent::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        (result.rows_affected == 1)
            .then_some(())
            .ok_or(ManagedError::Conflict)
    }

    async fn physical_versions(
        &self,
        tenant_id: &str,
        backend_id: &str,
        provider_bucket: &str,
        physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(backend_id))
            .filter(managed_physical_object_version::Column::ProviderBucket.eq(provider_bucket))
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(physical_key))
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(physical_target_from_model)
            .collect()
    }

    async fn forget_physical_version(
        &self,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let remaining = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(target.write_operation_id),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        if remaining == 0 {
            object_operation::Entity::delete_many()
                .filter(object_operation::Column::Id.eq(target.write_operation_id))
                .filter(object_operation::Column::State.is_in([
                    crate::transaction::OperationState::Committed.as_str(),
                    crate::transaction::OperationState::ProvenAborted.as_str(),
                ]))
                .exec(&txn)
                .await
                .map_err(persistence)?;
        }
        txn.commit().await.map_err(persistence)
    }

    async fn purge_namespace(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        if let Some(existing) = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
        {
            if existing.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return self.finalize_purge_if_ready(request).await;
        }

        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &request.tenant_id).await?;
        if let Some(existing) = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
        {
            txn.commit().await.map_err(persistence)?;
            if existing.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return self.finalize_purge_if_ready(request).await;
        }
        if namespace.state == "PURGING" {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "another managed namespace purge is already running".to_string(),
            });
        }
        let authorities = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::TenantId.eq(&request.tenant_id))
            .all(&txn)
            .await
            .map_err(persistence)?;
        for authority_model in authorities {
            let authority = authority_from_model(authority_model)?;
            if authority.tombstone {
                continue;
            }
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let required_backends = std::iter::once(authority.primary_backend_id.as_str()).chain(
                authority
                    .replica_backend_id
                    .as_deref()
                    .filter(|_| authority.replica_status == CopyStatus::Ready),
            );
            for backend_id in required_backends {
                let versions = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId.eq(&request.tenant_id),
                    )
                    .filter(managed_physical_object_version::Column::BackendId.eq(backend_id))
                    .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if versions == 0 {
                    return Ok(NamespacePurgeStatus::Blocked {
                        reason: format!(
                            "managed authority references unledgered physical versions on backend {backend_id}"
                        ),
                    });
                }
            }
        }
        let now = crate::transaction::unix_time_ms();
        managed_namespace_purge::Entity::insert(managed_namespace_purge::ActiveModel {
            operation_id: Set(request.operation_id),
            tenant_id: Set(request.tenant_id.clone()),
            epoch: Set(namespace.epoch),
            state: Set("RUNNING".to_string()),
            blocked_reason: Set(None),
            deleted_versions: Set(0),
            created_at_ms: Set(now),
            updated_at_ms: Set(now),
            completed_at_ms: Set(None),
        })
        .exec(&txn)
        .await
        .map_err(persistence)?;
        managed_namespace::Entity::update_many()
            .col_expr(managed_namespace::Column::State, Expr::value("PURGING"))
            .col_expr(
                managed_namespace::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(managed_namespace::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_namespace::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_namespace::Column::State.eq("ACTIVE"))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_PENDING"),
            )
            .col_expr(
                managed_physical_object_version::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_object_version::Column::Epoch.lte(namespace.epoch))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        self.finalize_purge_if_ready(request).await
    }

    async fn namespace_purge_status(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        self.finalize_purge_if_ready(request).await
    }

    async fn purge_targets(
        &self,
        request: &NamespacePurgeRequest,
        limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        let purge = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?;
        if purge.as_ref().map(|value| value.tenant_id.as_str()) != Some(&request.tenant_id) {
            return Err(ManagedError::Conflict);
        }
        managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .filter(
                Condition::any()
                    .add(managed_physical_object_version::Column::State.eq("PURGE_PENDING"))
                    .add(managed_physical_object_version::Column::State.eq("PURGE_BLOCKED")),
            )
            .order_by_asc(managed_physical_object_version::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(physical_target_from_model)
            .collect()
    }

    async fn mark_purge_target_deleted(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let result = managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected == 1 {
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::DeletedVersions,
                    Expr::col(managed_namespace_purge::Column::DeletedVersions).add(1),
                )
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("RUNNING"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Option::<String>::None),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            let remaining = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::WriteOperationId
                        .eq(target.write_operation_id),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if remaining == 0 {
                object_operation::Entity::delete_many()
                    .filter(object_operation::Column::Id.eq(target.write_operation_id))
                    .filter(object_operation::Column::State.is_in([
                        crate::transaction::OperationState::Committed.as_str(),
                        crate::transaction::OperationState::ProvenAborted.as_str(),
                    ]))
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
            }
        }
        txn.commit().await.map_err(persistence)
    }

    async fn mark_purge_target_blocked(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let reason = reason.chars().take(1024).collect::<String>();
        let now = crate::transaction::unix_time_ms();
        let txn = self.db.begin().await.map_err(persistence)?;
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_BLOCKED"),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Some(reason.clone())),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace_purge::Entity::update_many()
            .col_expr(
                managed_namespace_purge::Column::State,
                Expr::value("BLOCKED"),
            )
            .col_expr(
                managed_namespace_purge::Column::BlockedReason,
                Expr::value(Some(reason)),
            )
            .col_expr(
                managed_namespace_purge::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)
    }
}

#[derive(Default)]
struct MemoryState {
    authorities: HashMap<LogicalObjectKey, ObjectAuthority>,
    repairs: HashMap<Uuid, (RepairRecord, String)>,
    physical_write_intents: HashMap<Uuid, PhysicalWriteIntent>,
    blocked_write_intents: HashMap<Uuid, String>,
    physical_write_leases: HashMap<Uuid, i64>,
    physical_write_tokens: HashMap<Uuid, Uuid>,
    physical_versions: Vec<PhysicalVersionTarget>,
    fenced_namespaces: HashMap<String, Uuid>,
    purges: HashMap<Uuid, MemoryPurge>,
    namespace_epochs: HashMap<String, u64>,
    multipart_activities: HashMap<String, (String, u64)>,
    confirmed_multipart_activities: HashSet<String>,
    multipart_registration_expiry: HashMap<String, i64>,
}

#[derive(Clone)]
struct MemoryPurge {
    tenant_id: String,
    status: NamespacePurgeStatus,
    deleted_versions: u64,
}

#[derive(Clone, Default)]
pub struct InMemoryManagedRepository {
    state: Arc<Mutex<MemoryState>>,
}

impl InMemoryManagedRepository {
    pub fn new() -> Self {
        Self::default()
    }

    fn finish_purge(state: &mut MemoryState, operation_id: Uuid) -> NamespacePurgeStatus {
        let Some(purge) = state.purges.get(&operation_id).cloned() else {
            return NamespacePurgeStatus::Blocked {
                reason: "managed namespace purge operation was not found".to_string(),
            };
        };
        if matches!(purge.status, NamespacePurgeStatus::Complete { .. }) {
            return purge.status;
        }
        if let Some(reason) = state
            .blocked_write_intents
            .iter()
            .find_map(|(intent_id, reason)| {
                state
                    .physical_write_intents
                    .get(intent_id)
                    .filter(|intent| intent.tenant_id == purge.tenant_id)
                    .map(|_| reason.clone())
            })
        {
            let blocked = NamespacePurgeStatus::Blocked { reason };
            if let Some(purge) = state.purges.get_mut(&operation_id) {
                purge.status = blocked.clone();
            }
            return blocked;
        }
        if state
            .physical_write_intents
            .values()
            .any(|intent| intent.tenant_id == purge.tenant_id)
            || state
                .physical_versions
                .iter()
                .any(|target| target.tenant_id == purge.tenant_id)
            || state
                .multipart_activities
                .values()
                .any(|(tenant_id, _)| tenant_id == &purge.tenant_id)
        {
            return purge.status;
        }
        state
            .authorities
            .retain(|logical, _| logical.tenant_id != purge.tenant_id);
        state
            .repairs
            .retain(|_, (repair, _)| repair.logical.tenant_id != purge.tenant_id);
        state.fenced_namespaces.remove(&purge.tenant_id);
        *state
            .namespace_epochs
            .entry(purge.tenant_id.clone())
            .or_insert(1) += 1;
        let complete = NamespacePurgeStatus::Complete {
            deleted_versions: purge.deleted_versions,
        };
        if let Some(purge) = state.purges.get_mut(&operation_id) {
            purge.status = complete.clone();
        }
        complete
    }
}

fn insert_memory_repair(state: &mut MemoryState, repair: RepairRecord) {
    let duplicate = state.repairs.iter_mut().find(|(_, (existing, _))| {
        existing.kind == repair.kind
            && existing.generation == repair.generation
            && existing.target_backend_id == repair.target_backend_id
    });
    if let Some((_, (existing, status))) = duplicate {
        if status == "DONE" {
            let repair_id = existing.repair_id;
            *existing = repair;
            existing.id = repair_id;
            existing.repair_id = repair_id;
            existing.updated_at_ms = crate::transaction::unix_time_ms();
            existing.lease_owner = None;
            existing.lease_token = None;
            existing.lease_expires_at_ms = None;
            *status = "PENDING".to_string();
        }
    } else {
        state
            .repairs
            .insert(repair.repair_id, (repair, "PENDING".to_string()));
    }
}

#[async_trait]
impl ManagedRepository for InMemoryManagedRepository {
    fn is_durable(&self) -> bool {
        false
    }

    async fn assert_namespace_active(&self, tenant_id: &str) -> Result<(), ManagedError> {
        if self
            .state
            .lock()
            .await
            .fenced_namespaces
            .contains_key(tenant_id)
        {
            Err(ManagedError::NamespaceFenced)
        } else {
            Ok(())
        }
    }

    async fn begin_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let epoch = *state
            .namespace_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        state
            .multipart_activities
            .insert(upload_id.to_string(), (tenant_id.to_string(), epoch));
        state.multipart_registration_expiry.insert(
            upload_id.to_string(),
            crate::transaction::unix_time_ms().saturating_add(10 * 60 * 1000),
        );
        Ok(epoch)
    }

    async fn assert_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
        allow_purging: bool,
    ) -> Result<(), ManagedError> {
        let state = self.state.lock().await;
        if state.namespace_epochs.get(tenant_id).copied().unwrap_or(1) != namespace_epoch
            || (state.fenced_namespaces.contains_key(tenant_id) && !allow_purging)
            || state.multipart_activities.get(upload_id)
                != Some(&(tenant_id.to_string(), namespace_epoch))
            || !state.confirmed_multipart_activities.contains(upload_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        Ok(())
    }

    async fn confirm_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id)
            || state.multipart_activities.get(upload_id)
                != Some(&(tenant_id.to_string(), namespace_epoch))
        {
            return Err(ManagedError::NamespaceFenced);
        }
        state
            .confirmed_multipart_activities
            .insert(upload_id.to_string());
        state.multipart_registration_expiry.remove(upload_id);
        Ok(())
    }

    async fn reconcile_multipart_activities(&self, limit: u64) -> Result<u64, ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        let expired: Vec<_> = state
            .multipart_registration_expiry
            .iter()
            .filter(|(_, expires)| **expires <= now)
            .take(limit as usize)
            .map(|(upload_id, _)| upload_id.clone())
            .collect();
        for upload_id in &expired {
            state.multipart_registration_expiry.remove(upload_id);
            state.multipart_activities.remove(upload_id);
        }
        Ok(expired.len() as u64)
    }

    async fn finish_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.multipart_activities.get(upload_id)
            == Some(&(tenant_id.to_string(), namespace_epoch))
        {
            state.multipart_activities.remove(upload_id);
            state.confirmed_multipart_activities.remove(upload_id);
            state.multipart_registration_expiry.remove(upload_id);
        }
        Ok(())
    }

    async fn any_authority(&self) -> Result<bool, ManagedError> {
        Ok(!self.state.lock().await.authorities.is_empty())
    }

    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError> {
        let state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&logical.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        Ok(state.authorities.get(logical).cloned())
    }

    async fn publish(
        &self,
        mut authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&authority.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let existing = state.authorities.get(&authority.logical).cloned();
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        authority.cas_version = expected_cas.unwrap_or(0).saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        let namespace_epoch = *state
            .namespace_epochs
            .entry(authority.logical.tenant_id.clone())
            .or_insert(1);
        state
            .authorities
            .insert(authority.logical.clone(), authority.clone());
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = namespace_epoch;
            insert_memory_repair(&mut state, repair);
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                if !state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                }) {
                    continue;
                }
                repair.namespace_epoch = namespace_epoch;
                insert_memory_repair(&mut state, repair);
            }
        }
        Ok(authority)
    }

    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        self.publish(
            ObjectAuthority {
                logical: logical.clone(),
                generation: Uuid::now_v7(),
                digest: String::new(),
                size: 0,
                metadata: BTreeMap::new(),
                placement_version: placement.version,
                primary_backend_id: placement.primary_backend_id.clone(),
                replica_backend_id: placement.replica_backend_id.clone(),
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
                tombstone: true,
                cas_version: 0,
                created_at_ms: now,
                updated_at_ms: now,
            },
            expected_cas,
        )
        .await
    }

    async fn enqueue(&self, mut repair: RepairRecord) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&repair.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let current_epoch = *state
            .namespace_epochs
            .entry(repair.logical.tenant_id.clone())
            .or_insert(1);
        if repair.kind == RepairKind::DeleteGeneration {
            let targets: Vec<_> = state
                .physical_versions
                .iter()
                .filter(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                })
                .collect();
            if targets.is_empty() {
                return Ok(());
            }
            if targets
                .iter()
                .any(|target| target.namespace_epoch != current_epoch)
            {
                return Err(ManagedError::Conflict);
            }
        } else if state
            .authorities
            .get(&repair.logical)
            .is_none_or(|authority| {
                authority.generation != repair.generation
                    || authority.cas_version != repair.authority_cas_version
            })
        {
            return Err(ManagedError::Conflict);
        }
        repair.namespace_epoch = current_epoch;
        insert_memory_repair(&mut state, repair);
        Ok(())
    }

    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let mut state = self.state.lock().await;
        let fenced_namespaces = state.fenced_namespaces.clone();
        let namespace_epochs = state.namespace_epochs.clone();
        let mut candidates: Vec<_> = state
            .repairs
            .values_mut()
            .filter(|(repair, status)| {
                !fenced_namespaces.contains_key(&repair.logical.tenant_id)
                    && namespace_epochs
                        .get(&repair.logical.tenant_id)
                        .copied()
                        .unwrap_or(1)
                        == repair.namespace_epoch
                    && (status.as_str() == "PENDING"
                        || (status.as_str() == "LEASED"
                            && repair
                                .lease_expires_at_ms
                                .is_some_and(|expiry| expiry <= now)))
            })
            .collect();
        candidates.sort_by_key(|(repair, _)| repair.updated_at_ms);
        let mut claimed = Vec::new();
        for (repair, status) in candidates.into_iter().take(limit as usize) {
            let lease_token = Uuid::now_v7();
            *status = "LEASED".to_string();
            repair.id = lease_token;
            repair.lease_owner = Some(owner.to_string());
            repair.lease_token = Some(lease_token);
            repair.lease_expires_at_ms = Some(lease_until_ms);
            repair.updated_at_ms = now;
            claimed.push(repair.clone());
        }
        Ok(claimed)
    }

    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let mut state = self.state.lock().await;
        let Some((repair, status)) = state
            .repairs
            .values_mut()
            .find(|(repair, _)| repair.lease_token == Some(lease_token))
        else {
            return Err(ManagedError::Conflict);
        };
        if status != "LEASED"
            || repair
                .lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(ManagedError::Conflict);
        }
        repair.lease_expires_at_ms = Some(lease_until_ms);
        repair.updated_at_ms = now;
        Ok(())
    }

    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        if repair.lease_token != Some(repair.id) {
            return Err(ManagedError::Conflict);
        }
        if state
            .namespace_epochs
            .get(&repair.logical.tenant_id)
            .copied()
            .unwrap_or(1)
            != repair.namespace_epoch
        {
            return Err(ManagedError::Conflict);
        }
        {
            let Some((stored, status)) = state.repairs.get_mut(&repair.repair_id) else {
                return Err(ManagedError::Conflict);
            };
            if status != "LEASED"
                || stored.lease_token != Some(repair.id)
                || stored
                    .lease_expires_at_ms
                    .is_none_or(|expiry| expiry <= now)
            {
                return Err(ManagedError::Conflict);
            }
            *status = "DONE".to_string();
            stored.lease_owner = None;
            stored.lease_token = None;
            stored.lease_expires_at_ms = None;
            stored.updated_at_ms = now;
        }
        let mut updated = false;
        if repair.kind != RepairKind::DeleteGeneration
            && let Some(authority) = state.authorities.get_mut(&repair.logical)
            && authority.generation == repair.generation
            && (repair.kind == RepairKind::Placement
                || authority.cas_version == repair.authority_cas_version)
            && !authority.tombstone
            && apply_repair_to_authority(authority, repair)?
        {
            authority.cas_version = authority.cas_version.saturating_add(1);
            authority.updated_at_ms = crate::transaction::unix_time_ms();
            updated = true;
        }
        Ok(updated)
    }

    async fn fail_repair(&self, lease_token: Uuid, _error: &str) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        let Some((repair, status)) = state
            .repairs
            .values_mut()
            .find(|(repair, _)| repair.lease_token == Some(lease_token))
        else {
            return Err(ManagedError::Conflict);
        };
        if status != "LEASED"
            || repair
                .lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(ManagedError::Conflict);
        }
        repair.attempts = repair.attempts.saturating_add(1);
        repair.lease_owner = None;
        repair.lease_token = None;
        repair.lease_expires_at_ms = None;
        repair.updated_at_ms = now;
        *status = "PENDING".to_string();
        Ok(())
    }

    async fn begin_physical_write(
        &self,
        intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&intent.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let intent_id = intent.intent_id;
        let owner = intent.lease_owner.clone();
        let token = Uuid::now_v7();
        state.physical_write_intents.insert(intent_id, intent);
        state.physical_write_leases.insert(
            intent_id,
            crate::transaction::unix_time_ms().saturating_add(PHYSICAL_WRITE_LEASE_MS),
        );
        state.physical_write_tokens.insert(intent_id, token);
        Ok(PhysicalWriteLease {
            intent_id,
            namespace_epoch: 1,
            owner,
            token,
        })
    }

    async fn pending_physical_write_intents(
        &self,
        limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        let state = self.state.lock().await;
        Ok(state
            .physical_write_intents
            .values()
            .take(limit as usize)
            .map(|intent| DurablePhysicalWriteIntent {
                intent: intent.clone(),
                namespace_epoch: 1,
                blocked_reason: state.blocked_write_intents.get(&intent.intent_id).cloned(),
                lease_expires_at_ms: state
                    .physical_write_leases
                    .get(&intent.intent_id)
                    .copied()
                    .unwrap_or(0),
                lease: PhysicalWriteLease {
                    intent_id: intent.intent_id,
                    namespace_epoch: 1,
                    owner: intent.lease_owner.clone(),
                    token: state
                        .physical_write_tokens
                        .get(&intent.intent_id)
                        .copied()
                        .unwrap_or(Uuid::nil()),
                },
            })
            .collect())
    }

    async fn renew_physical_write_intent(
        &self,
        lease: &PhysicalWriteLease,
        lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .physical_write_intents
            .get(&lease.intent_id)
            .is_none_or(|intent| intent.lease_owner != lease.owner)
            || state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state
            .physical_write_leases
            .insert(lease.intent_id, lease_expires_at_ms);
        Ok(())
    }

    async fn claim_expired_physical_write_intent(
        &self,
        intent_id: Uuid,
        owner: &str,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .physical_write_leases
            .get(&intent_id)
            .is_none_or(|expires| *expires > crate::transaction::unix_time_ms())
        {
            return Ok(None);
        }
        let token = Uuid::now_v7();
        let intent = state
            .physical_write_intents
            .get_mut(&intent_id)
            .ok_or(ManagedError::Conflict)?;
        intent.lease_owner = owner.to_string();
        state.physical_write_tokens.insert(intent_id, token);
        state
            .physical_write_leases
            .insert(intent_id, lease_expires_at_ms);
        Ok(Some(PhysicalWriteLease {
            intent_id,
            namespace_epoch: 1,
            owner: owner.to_string(),
            token,
        }))
    }

    async fn commit_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        superseded_version_ids: &[String],
        version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .physical_write_intents
            .get(&lease.intent_id)
            .is_none_or(|intent| intent.lease_owner != lease.owner)
            || state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        let intent = state
            .physical_write_intents
            .remove(&lease.intent_id)
            .unwrap();
        state.blocked_write_intents.remove(&lease.intent_id);
        state.physical_write_leases.remove(&lease.intent_id);
        state.physical_write_tokens.remove(&lease.intent_id);
        for version_id in superseded_version_ids
            .iter()
            .map(|value| Some(value.clone()))
            .chain(std::iter::once(version_id.map(ToOwned::to_owned)))
        {
            state.physical_versions.push(PhysicalVersionTarget {
                tenant_id: intent.tenant_id.clone(),
                namespace_epoch: 1,
                backend_id: intent.backend_id.clone(),
                backend_fingerprint: intent.backend_fingerprint.clone(),
                provider_bucket: intent.provider_bucket.clone(),
                physical_key: intent.physical_key.clone(),
                version_id,
                versioning_mode: intent.versioning_mode,
                versioning_capability: intent.versioning_capability,
                write_operation_id: lease.intent_id,
            });
        }
        Ok(())
    }

    async fn abort_physical_write(&self, lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state.physical_write_intents.remove(&lease.intent_id);
        state.blocked_write_intents.remove(&lease.intent_id);
        state.physical_write_leases.remove(&lease.intent_id);
        state.physical_write_tokens.remove(&lease.intent_id);
        Ok(())
    }

    async fn block_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state
            .blocked_write_intents
            .insert(lease.intent_id, reason.to_string());
        Ok(())
    }

    async fn physical_versions(
        &self,
        tenant_id: &str,
        backend_id: &str,
        provider_bucket: &str,
        physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Ok(self
            .state
            .lock()
            .await
            .physical_versions
            .iter()
            .filter(|target| {
                target.tenant_id == tenant_id
                    && target.backend_id == backend_id
                    && target.provider_bucket == provider_bucket
                    && target.physical_key == physical_key
            })
            .cloned()
            .collect())
    }

    async fn forget_physical_version(
        &self,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        self.state
            .lock()
            .await
            .physical_versions
            .retain(|candidate| candidate != target);
        Ok(())
    }

    async fn purge_namespace(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let mut state = self.state.lock().await;
        if let Some(purge) = state.purges.get(&request.operation_id) {
            if purge.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return Ok(Self::finish_purge(&mut state, request.operation_id));
        }
        if state.fenced_namespaces.contains_key(&request.tenant_id) {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "another managed namespace purge is already running".to_string(),
            });
        }
        for authority in state
            .authorities
            .values()
            .filter(|authority| authority.logical.tenant_id == request.tenant_id)
            .filter(|authority| !authority.tombstone)
        {
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let required_backends = std::iter::once(authority.primary_backend_id.as_str()).chain(
                authority
                    .replica_backend_id
                    .as_deref()
                    .filter(|_| authority.replica_status == CopyStatus::Ready),
            );
            for backend_id in required_backends {
                if !state.physical_versions.iter().any(|target| {
                    target.tenant_id == request.tenant_id
                        && target.backend_id == backend_id
                        && target.physical_key == physical_key
                }) {
                    return Ok(NamespacePurgeStatus::Blocked {
                        reason: format!(
                            "managed authority references unledgered physical versions on backend {backend_id}"
                        ),
                    });
                }
            }
        }
        state
            .fenced_namespaces
            .insert(request.tenant_id.clone(), request.operation_id);
        state.purges.insert(
            request.operation_id,
            MemoryPurge {
                tenant_id: request.tenant_id.clone(),
                status: NamespacePurgeStatus::Running,
                deleted_versions: 0,
            },
        );
        Ok(Self::finish_purge(&mut state, request.operation_id))
    }

    async fn namespace_purge_status(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let mut state = self.state.lock().await;
        Ok(Self::finish_purge(&mut state, request.operation_id))
    }

    async fn purge_targets(
        &self,
        request: &NamespacePurgeRequest,
        limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        let state = self.state.lock().await;
        if state
            .purges
            .get(&request.operation_id)
            .is_none_or(|purge| purge.tenant_id != request.tenant_id)
        {
            return Err(ManagedError::Conflict);
        }
        Ok(state
            .physical_versions
            .iter()
            .filter(|target| target.tenant_id == request.tenant_id)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn mark_purge_target_deleted(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let before = state.physical_versions.len();
        state
            .physical_versions
            .retain(|candidate| candidate != target);
        if state.physical_versions.len() != before
            && let Some(purge) = state.purges.get_mut(&request.operation_id)
        {
            purge.deleted_versions = purge.deleted_versions.saturating_add(1);
            purge.status = NamespacePurgeStatus::Running;
        }
        Ok(())
    }

    async fn mark_purge_target_blocked(
        &self,
        request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
        reason: &str,
    ) -> Result<(), ManagedError> {
        if let Some(purge) = self
            .state
            .lock()
            .await
            .purges
            .get_mut(&request.operation_id)
        {
            purge.status = NamespacePurgeStatus::Blocked {
                reason: reason.to_string(),
            };
        }
        Ok(())
    }
}

pub async fn validate_mode(
    mode: ManagedStreamingMode,
    repository: &dyn ManagedRepository,
    development: bool,
) -> Result<(), ManagedError> {
    if mode == ManagedStreamingMode::Off && repository.any_authority().await? {
        return Err(ManagedError::OffAfterAuthority);
    }
    if mode != ManagedStreamingMode::Off && !repository.is_durable() && !development {
        return Err(ManagedError::Persistence(
            "managed observe/enforce mode requires DATABASE_URL".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(logical: LogicalObjectKey, generation: Uuid) -> ObjectAuthority {
        ObjectAuthority {
            logical,
            generation,
            digest: "abc".to_string(),
            size: 3,
            metadata: BTreeMap::new(),
            placement_version: 1,
            primary_backend_id: "a".to_string(),
            replica_backend_id: Some("b".to_string()),
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::RepairPending,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }

    #[tokio::test]
    async fn empty_in_memory_namespace_purge_completes_idempotently() {
        let repository = InMemoryManagedRepository::new();
        let request = NamespacePurgeRequest {
            tenant_id: "tenant-a".to_string(),
            operation_id: Uuid::now_v7(),
        };
        let complete = NamespacePurgeStatus::Complete {
            deleted_versions: 0,
        };
        assert_eq!(
            repository.purge_namespace(&request).await.unwrap(),
            complete
        );
        assert_eq!(
            repository.namespace_purge_status(&request).await.unwrap(),
            complete
        );
    }

    #[tokio::test]
    async fn in_memory_purge_fences_concurrent_writes_and_blocks_ambiguous_history() {
        let repository = InMemoryManagedRepository::new();
        let intent_id = Uuid::now_v7();
        let lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id,
                tenant_id: "tenant-a".to_string(),
                backend_id: "provider:bucket".to_string(),
                backend_fingerprint: "fingerprint".to_string(),
                provider_bucket: "bucket".to_string(),
                physical_key: "managed/key".to_string(),
                versioning_mode: BackendVersioningMode::Unversioned,
                versioning_capability: BackendVersioningCapability::Unsupported,
                lease_owner: "writer-a".to_string(),
            })
            .await
            .unwrap();
        let request = NamespacePurgeRequest {
            tenant_id: "tenant-a".to_string(),
            operation_id: Uuid::now_v7(),
        };
        assert_eq!(
            repository.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Running
        );
        assert!(matches!(
            repository
                .begin_physical_write(PhysicalWriteIntent {
                    intent_id: Uuid::now_v7(),
                    tenant_id: "tenant-a".to_string(),
                    backend_id: "provider:bucket".to_string(),
                    backend_fingerprint: "fingerprint".to_string(),
                    provider_bucket: "bucket".to_string(),
                    physical_key: "managed/new-key".to_string(),
                    versioning_mode: BackendVersioningMode::Unversioned,
                    versioning_capability: BackendVersioningCapability::Unsupported,
                    lease_owner: "writer-b".to_string(),
                })
                .await,
            Err(ManagedError::NamespaceFenced)
        ));
        repository
            .block_physical_write(&lease, "provider response was ambiguous")
            .await
            .unwrap();
        assert_eq!(
            repository.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Blocked {
                reason: "provider response was ambiguous".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn stale_authority_snapshot_cannot_enqueue_repair_after_cas_changes() {
        let repository = InMemoryManagedRepository::new();
        let first = repository
            .publish(
                authority(
                    LogicalObjectKey::new("tenant-stale", "bucket", "key"),
                    Uuid::now_v7(),
                ),
                None,
            )
            .await
            .unwrap();
        let stale_repair = RepairRecord::copy(
            RepairKind::Replica,
            &first,
            Some(first.primary_backend_id.clone()),
            first.replica_backend_id.clone().unwrap(),
            RepairTargetRole::Replica,
            first.placement_version,
        );
        let mut replacement = first.clone();
        replacement.generation = Uuid::now_v7();
        repository
            .publish(replacement, Some(first.cas_version))
            .await
            .unwrap();
        assert!(matches!(
            repository.enqueue(stale_repair).await,
            Err(ManagedError::Conflict)
        ));
    }

    #[tokio::test]
    async fn cleanup_without_matching_physical_ledger_is_already_complete() {
        let repository = InMemoryManagedRepository::new();
        let mut source = authority(
            LogicalObjectKey::new("tenant-cleanup", "bucket", "key"),
            Uuid::now_v7(),
        );
        source.replica_backend_id = None;
        source.replica_status = CopyStatus::Absent;
        let published = repository.publish(source, None).await.unwrap();
        let cleanup = cleanup_repairs(&published).pop().unwrap();
        repository.enqueue(cleanup).await.unwrap();
        assert!(
            repository
                .claim_repairs("worker", crate::transaction::unix_time_ms() + 60_000, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn multipart_activity_fences_parts_and_blocks_purge_until_abort_cleanup() {
        let repository = InMemoryManagedRepository::new();
        let epoch = repository
            .begin_multipart_activity("upload", "tenant-a")
            .await
            .unwrap();
        repository
            .confirm_multipart_activity("upload", "tenant-a", epoch)
            .await
            .unwrap();
        let request = NamespacePurgeRequest {
            tenant_id: "tenant-a".to_string(),
            operation_id: Uuid::now_v7(),
        };
        assert_eq!(
            repository.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Running
        );
        assert!(matches!(
            repository
                .assert_multipart_activity("upload", "tenant-a", epoch, false)
                .await,
            Err(ManagedError::NamespaceFenced)
        ));
        repository
            .assert_multipart_activity("upload", "tenant-a", epoch, true)
            .await
            .unwrap();
        repository
            .finish_multipart_activity("upload", "tenant-a", epoch)
            .await
            .unwrap();
        assert_eq!(
            repository.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Complete {
                deleted_versions: 0,
            }
        );
        assert!(matches!(
            repository
                .assert_multipart_activity("upload", "tenant-a", epoch, false)
                .await,
            Err(ManagedError::NamespaceFenced)
        ));
    }

    #[tokio::test]
    async fn crashed_multipart_registration_expires_without_racing_confirmed_upload() {
        let repository = InMemoryManagedRepository::new();
        let orphan_epoch = repository
            .begin_multipart_activity("orphan", "tenant-a")
            .await
            .unwrap();
        repository
            .state
            .lock()
            .await
            .multipart_registration_expiry
            .insert("orphan".to_string(), crate::transaction::unix_time_ms() - 1);
        let valid_epoch = repository
            .begin_multipart_activity("valid", "tenant-a")
            .await
            .unwrap();
        repository
            .confirm_multipart_activity("valid", "tenant-a", valid_epoch)
            .await
            .unwrap();
        assert_eq!(
            repository.reconcile_multipart_activities(10).await.unwrap(),
            1
        );
        assert!(matches!(
            repository
                .assert_multipart_activity("orphan", "tenant-a", orphan_epoch, false)
                .await,
            Err(ManagedError::NamespaceFenced)
        ));
        repository
            .assert_multipart_activity("valid", "tenant-a", valid_epoch, false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reclaimed_physical_write_lease_fences_stale_writer() {
        let repository = InMemoryManagedRepository::new();
        let intent_id = Uuid::now_v7();
        let stale = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id,
                tenant_id: "tenant-lease".to_string(),
                backend_id: "provider:bucket".to_string(),
                backend_fingerprint: "fingerprint".to_string(),
                provider_bucket: "bucket".to_string(),
                physical_key: "managed/key".to_string(),
                versioning_mode: BackendVersioningMode::Enabled,
                versioning_capability: BackendVersioningCapability::Optional,
                lease_owner: "writer-a".to_string(),
            })
            .await
            .unwrap();
        repository
            .renew_physical_write_intent(
                &stale,
                crate::transaction::unix_time_ms().saturating_sub(1),
            )
            .await
            .unwrap();
        let current = repository
            .claim_expired_physical_write_intent(
                intent_id,
                "writer-b",
                crate::transaction::unix_time_ms().saturating_add(60_000),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            repository
                .commit_physical_write(&stale, &[], Some("stale-version"))
                .await,
            Err(ManagedError::Conflict)
        ));
        assert!(matches!(
            repository.abort_physical_write(&stale).await,
            Err(ManagedError::Conflict)
        ));
        repository
            .commit_physical_write(&current, &[], Some("current-version"))
            .await
            .unwrap();
    }

    #[test]
    fn rendezvous_has_stable_golden_vectors() {
        let score = rendezvous_score(1, "tenant-a", "bucket/path/to/object", "b2:bucket-a");
        assert_eq!(
            hex::encode(score),
            "bdaa1cebd6b1ff544ff1a5821c103391418bdecf94e17d934f8e56b0915c1657"
        );
        let placement = rendezvous_placement(
            1,
            "tenant-a",
            "bucket/path/to/object",
            ["r2:bucket-c", "b2:bucket-a", "s3:bucket-b"]
                .into_iter()
                .map(str::to_string),
        )
        .unwrap();
        assert_eq!(placement.primary_backend_id, "s3:bucket-b");
        assert_eq!(placement.replica_backend_id.as_deref(), Some("b2:bucket-a"));
    }

    #[test]
    fn placement_is_independent_of_backend_input_order() {
        let first = rendezvous_placement(
            1,
            "tenant",
            "bucket/key",
            ["a", "b", "c"].into_iter().map(str::to_string),
        );
        let second = rendezvous_placement(
            1,
            "tenant",
            "bucket/key",
            ["c", "a", "b"].into_iter().map(str::to_string),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn placement_process_helper() {
        if std::env::var_os("S4_PLACEMENT_PROCESS_HELPER").is_some() {
            let placement = rendezvous_placement(
                1,
                "tenant-a",
                "bucket/path/to/object",
                ["r2:bucket-c", "b2:bucket-a", "s3:bucket-b"]
                    .into_iter()
                    .map(str::to_string),
            )
            .unwrap();
            println!(
                "S4_PLACEMENT={}:{}",
                placement.primary_backend_id,
                placement.replica_backend_id.unwrap()
            );
        }
    }

    #[test]
    fn placement_is_stable_in_a_separate_process() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "managed::tests::placement_process_helper",
                "--nocapture",
            ])
            .env("S4_PLACEMENT_PROCESS_HELPER", "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("S4_PLACEMENT=s3:bucket-b:b2:bucket-a")
        );
    }

    #[tokio::test]
    async fn authority_cas_tombstone_and_repair_restart_are_safe() {
        let repository = InMemoryManagedRepository::new();
        let logical = LogicalObjectKey::new("tenant", "bucket", "key");
        let first = repository
            .publish(authority(logical.clone(), Uuid::now_v7()), None)
            .await
            .unwrap();
        assert!(
            repository
                .publish(authority(logical.clone(), Uuid::now_v7()), None)
                .await
                .is_err()
        );
        let claimed = repository
            .claim_repairs("process-a", crate::transaction::unix_time_ms() - 1, 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let reclaimed = repository
            .claim_repairs("process-b", crate::transaction::unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert!(repository.complete_repair(&claimed[0]).await.is_err());
        assert!(
            repository
                .fail_repair(claimed[0].id, "stale worker")
                .await
                .is_err()
        );
        repository.complete_repair(&reclaimed[0]).await.unwrap();
        let repaired = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(repaired.replica_status, CopyStatus::Ready);
        let placement = Placement {
            version: 1,
            primary_backend_id: "a".to_string(),
            replica_backend_id: Some("b".to_string()),
        };
        let tombstone = repository
            .tombstone(&logical, Some(repaired.cas_version), &placement)
            .await
            .unwrap();
        assert!(tombstone.tombstone);
        assert!(
            repository
                .publish(authority(logical, Uuid::now_v7()), Some(first.cas_version))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn mode_transition_floor_is_enforced() {
        let repository = InMemoryManagedRepository::new();
        validate_mode(ManagedStreamingMode::Off, &repository, true)
            .await
            .unwrap();
        validate_mode(ManagedStreamingMode::Observe, &repository, true)
            .await
            .unwrap();
        validate_mode(ManagedStreamingMode::Enforce, &repository, true)
            .await
            .unwrap();
        let logical = LogicalObjectKey::new("tenant", "bucket", "key");
        repository
            .publish(authority(logical, Uuid::now_v7()), None)
            .await
            .unwrap();
        assert!(
            validate_mode(ManagedStreamingMode::Off, &repository, true)
                .await
                .is_err()
        );
        validate_mode(ManagedStreamingMode::Observe, &repository, true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn replica_outcome_and_old_generation_cleanup_are_durable() {
        let repository = InMemoryManagedRepository::new();
        let logical = LogicalObjectKey::new("tenant", "bucket", "key");
        let pending = repository
            .publish(authority(logical.clone(), Uuid::now_v7()), None)
            .await
            .unwrap();
        let repairs = repository
            .claim_repairs("repair", crate::transaction::unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(repairs.len(), 1);
        assert_eq!(repairs[0].kind, RepairKind::Replica);
        repository.complete_repair(&repairs[0]).await.unwrap();

        let mut replacement = authority(logical, Uuid::now_v7());
        replacement.replica_status = CopyStatus::Ready;
        repository
            .publish(replacement, Some(pending.cas_version + 1))
            .await
            .unwrap();
        let cleanup = repository
            .claim_repairs("gc", crate::transaction::unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert!(cleanup.is_empty());
        assert!(
            cleanup
                .iter()
                .all(|repair| repair.kind == RepairKind::DeleteGeneration)
        );
    }

    #[tokio::test]
    async fn replica_only_placement_repair_advances_authority_placement_version() {
        let repository = InMemoryManagedRepository::new();
        let logical = LogicalObjectKey::new("tenant", "bucket", "key");
        let mut initial = authority(logical.clone(), Uuid::now_v7());
        initial.replica_status = CopyStatus::Ready;
        let published = repository.publish(initial, None).await.unwrap();
        let placement = Placement {
            version: published.placement_version + 1,
            primary_backend_id: "a".to_string(),
            replica_backend_id: Some("c".to_string()),
        };
        repository
            .enqueue(RepairRecord::placement(
                &published,
                Some("a".to_string()),
                "c".to_string(),
                RepairTargetRole::Replica,
                &placement,
            ))
            .await
            .unwrap();

        let repair = repository
            .claim_repairs("repair", crate::transaction::unix_time_ms() + 30_000, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert!(repository.complete_repair(&repair).await.unwrap());

        let repaired = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(repaired.primary_backend_id, "a");
        assert_eq!(repaired.replica_backend_id.as_deref(), Some("c"));
        assert_eq!(repaired.replica_status, CopyStatus::Ready);
        assert_eq!(
            repaired.placement_version,
            published.placement_version + 1,
            "a replica-only placement repair must advance the authority version"
        );
    }

    #[tokio::test]
    async fn concurrent_authority_publish_has_one_cas_winner() {
        let repository = InMemoryManagedRepository::new();
        let logical = LogicalObjectKey::new("tenant", "bucket", "race");
        let initial = repository
            .publish(authority(logical.clone(), Uuid::now_v7()), None)
            .await
            .unwrap();
        let left = authority(logical.clone(), Uuid::now_v7());
        let right = authority(logical, Uuid::now_v7());
        let (left, right) = tokio::join!(
            repository.publish(left, Some(initial.cas_version)),
            repository.publish(right, Some(initial.cas_version)),
        );
        assert_ne!(left.is_ok(), right.is_ok());
    }

    #[tokio::test]
    async fn placement_migration_never_advances_before_both_targets_are_ready() {
        let repository = InMemoryManagedRepository::new();
        let logical = LogicalObjectKey::new("tenant", "bucket", "placement-legs");
        let mut initial = authority(logical.clone(), Uuid::now_v7());
        initial.replica_status = CopyStatus::Ready;
        let initial = repository.publish(initial, None).await.unwrap();
        let placement = Placement {
            version: initial.placement_version + 1,
            primary_backend_id: "c".to_string(),
            replica_backend_id: Some("d".to_string()),
        };
        repository
            .enqueue(RepairRecord::placement(
                &initial,
                Some("a".to_string()),
                "c".to_string(),
                RepairTargetRole::Primary,
                &placement,
            ))
            .await
            .unwrap();
        repository
            .enqueue(RepairRecord::placement(
                &initial,
                Some("a".to_string()),
                "d".to_string(),
                RepairTargetRole::Replica,
                &placement,
            ))
            .await
            .unwrap();
        let mut repairs = repository
            .claim_repairs(
                "placement-worker",
                crate::transaction::unix_time_ms() + 30_000,
                2,
            )
            .await
            .unwrap();
        let primary = repairs
            .iter()
            .position(|repair| repair.target_role == RepairTargetRole::Primary)
            .map(|index| repairs.swap_remove(index))
            .unwrap();
        let replica = repairs.pop().unwrap();

        repository.complete_repair(&primary).await.unwrap();
        let partial = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(partial.primary_backend_id, "c");
        assert_eq!(partial.replica_backend_id.as_deref(), Some("b"));
        assert_eq!(partial.placement_version, initial.placement_version);

        repository.complete_repair(&replica).await.unwrap();
        let converged = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(converged.primary_backend_id, "c");
        assert_eq!(converged.replica_backend_id.as_deref(), Some("d"));
        assert_eq!(converged.placement_version, placement.version);
    }

    #[tokio::test]
    async fn concurrent_placement_repair_completions_converge() {
        let repository = InMemoryManagedRepository::new();
        let logical = LogicalObjectKey::new("tenant", "bucket", "placement-race");
        let mut initial = authority(logical.clone(), Uuid::now_v7());
        initial.replica_status = CopyStatus::Ready;
        let initial = repository.publish(initial, None).await.unwrap();
        let placement = Placement {
            version: initial.placement_version + 1,
            primary_backend_id: "c".to_string(),
            replica_backend_id: Some("d".to_string()),
        };
        for (target_backend_id, target_role) in [
            ("c".to_string(), RepairTargetRole::Primary),
            ("d".to_string(), RepairTargetRole::Replica),
        ] {
            repository
                .enqueue(RepairRecord::placement(
                    &initial,
                    Some("a".to_string()),
                    target_backend_id,
                    target_role,
                    &placement,
                ))
                .await
                .unwrap();
        }
        let repairs = repository
            .claim_repairs(
                "placement-workers",
                crate::transaction::unix_time_ms() + 30_000,
                2,
            )
            .await
            .unwrap();
        let (left, right) = tokio::join!(
            repository.complete_repair(&repairs[0]),
            repository.complete_repair(&repairs[1]),
        );
        left.unwrap();
        right.unwrap();
        let converged = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(converged.primary_backend_id, "c");
        assert_eq!(converged.replica_backend_id.as_deref(), Some("d"));
        assert_eq!(converged.placement_version, placement.version);
    }

    #[tokio::test]
    async fn repair_lease_renewal_extends_only_the_current_fence() {
        let repository = InMemoryManagedRepository::new();
        let logical = LogicalObjectKey::new("tenant", "bucket", "lease-renewal");
        let pending = repository
            .publish(authority(logical, Uuid::now_v7()), None)
            .await
            .unwrap();
        let claim = repository
            .claim_repairs("worker-a", crate::transaction::unix_time_ms() + 1_000, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert!(
            repository
                .renew_repair(Uuid::now_v7(), crate::transaction::unix_time_ms() + 60_000)
                .await
                .is_err()
        );
        repository
            .renew_repair(claim.id, crate::transaction::unix_time_ms() + 60_000)
            .await
            .unwrap();
        assert!(
            repository
                .claim_repairs("worker-b", crate::transaction::unix_time_ms() + 60_000, 1)
                .await
                .unwrap()
                .is_empty()
        );
        repository.complete_repair(&claim).await.unwrap();

        let current = repository.get(&pending.logical).await.unwrap().unwrap();
        repository
            .enqueue(RepairRecord::copy(
                RepairKind::Replica,
                &current,
                Some("a".to_string()),
                "b".to_string(),
                RepairTargetRole::Replica,
                current.placement_version,
            ))
            .await
            .unwrap();
        let expired = repository
            .claim_repairs("worker-c", crate::transaction::unix_time_ms() - 1, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert!(
            repository
                .renew_repair(expired.id, crate::transaction::unix_time_ms() + 60_000)
                .await
                .is_err()
        );
        assert_eq!(
            repository
                .claim_repairs("worker-d", crate::transaction::unix_time_ms() + 60_000, 1)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
