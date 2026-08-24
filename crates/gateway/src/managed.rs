use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::sea_query::{Expr, LockType, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, SqlxPostgresConnector, TransactionTrait,
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::entity::{managed_object_authority, managed_object_repair};

pub const PLACEMENT_VERSION_V1: u32 = 1;

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
    Complete { deleted_generations: u64 },
    Blocked { reason: String },
    Unsupported { reason: String },
}

#[async_trait]
pub trait ManagedRepository: Send + Sync {
    fn is_durable(&self) -> bool;
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
        managed_object_authority::Entity::find_by_id((
            logical.tenant_id.clone(),
            logical.bucket.clone(),
            logical.key.clone(),
        ))
        .one(&self.db)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()
    }

    async fn publish(
        &self,
        mut authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
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
        for repair in publication_repairs(&authority) {
            insert_repair(&txn, repair).await?;
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for repair in cleanup_repairs(&existing) {
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

    async fn enqueue(&self, repair: RepairRecord) -> Result<(), ManagedError> {
        insert_repair(&self.db, repair).await
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
                .exec(&self.db)
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
}

#[derive(Default)]
struct MemoryState {
    authorities: HashMap<LogicalObjectKey, ObjectAuthority>,
    repairs: HashMap<Uuid, (RepairRecord, String)>,
}

#[derive(Clone, Default)]
pub struct InMemoryManagedRepository {
    state: Arc<Mutex<MemoryState>>,
}

impl InMemoryManagedRepository {
    pub fn new() -> Self {
        Self::default()
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

    async fn any_authority(&self) -> Result<bool, ManagedError> {
        Ok(!self.state.lock().await.authorities.is_empty())
    }

    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError> {
        Ok(self.state.lock().await.authorities.get(logical).cloned())
    }

    async fn publish(
        &self,
        mut authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError> {
        let mut state = self.state.lock().await;
        let existing = state.authorities.get(&authority.logical).cloned();
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        authority.cas_version = expected_cas.unwrap_or(0).saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        state
            .authorities
            .insert(authority.logical.clone(), authority.clone());
        for repair in publication_repairs(&authority) {
            insert_memory_repair(&mut state, repair);
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for repair in cleanup_repairs(&existing) {
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

    async fn enqueue(&self, repair: RepairRecord) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
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
        let mut candidates: Vec<_> = state
            .repairs
            .values_mut()
            .filter(|(repair, status)| {
                status.as_str() == "PENDING"
                    || (status.as_str() == "LEASED"
                        && repair
                            .lease_expires_at_ms
                            .is_some_and(|expiry| expiry <= now))
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
    async fn namespace_purge_is_explicitly_unsupported_without_a_version_ledger() {
        let repository = InMemoryManagedRepository::new();
        let request = NamespacePurgeRequest {
            tenant_id: "tenant-a".to_string(),
            operation_id: Uuid::now_v7(),
        };
        assert!(matches!(
            repository.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Unsupported { .. }
        ));
        assert!(matches!(
            repository.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Unsupported { .. }
        ));
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
        assert_eq!(cleanup.len(), 2);
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

        repository
            .enqueue(RepairRecord::copy(
                RepairKind::Replica,
                &pending,
                Some("a".to_string()),
                "b".to_string(),
                RepairTargetRole::Replica,
                pending.placement_version,
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
