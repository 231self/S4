#[cfg(any(test, debug_assertions))]
use std::collections::HashMap;
#[cfg(any(test, debug_assertions))]
use std::sync::Arc;
#[cfg(any(test, debug_assertions))]
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, SqlxPostgresConnector,
};
#[cfg(any(test, debug_assertions))]
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::entity::{object_operation, object_operation_evidence, object_operation_part};

use super::{
    EvidenceRecord, ExpectedObject, JournalError, ObjectDestination, OperationJournal,
    OperationRecord, OperationState, PartRecord, StoredObjectMeta, WorkspaceDestinationBinding,
    unix_time_ms,
};

#[derive(Clone, Debug)]
pub struct PostgresOperationJournal {
    db: DatabaseConnection,
}

impl PostgresOperationJournal {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            db: SqlxPostgresConnector::from_sqlx_postgres_pool(pool),
        }
    }
}

fn persistence(error: impl std::fmt::Display) -> JournalError {
    JournalError::Persistence(error.to_string())
}

fn operation_from_model(model: object_operation::Model) -> Result<OperationRecord, JournalError> {
    let expected_size = model
        .expected_size
        .map(|size| {
            u64::try_from(size)
                .map_err(|_| JournalError::Corrupt("negative expected object size".to_string()))
        })
        .transpose()?;
    let metadata = serde_json::from_value(model.expected_metadata)
        .map_err(|error| JournalError::Corrupt(format!("invalid expected metadata: {error}")))?;
    let committed = if model.committed_etag.is_some() || model.committed_version_id.is_some() {
        Some(StoredObjectMeta {
            etag: model.committed_etag,
            version_id: model.committed_version_id,
            superseded_version_ids: serde_json::from_value(model.committed_superseded_version_ids)
                .map_err(|error| {
                    JournalError::Corrupt(format!("invalid committed version history: {error}"))
                })?,
            version_history_complete: model.committed_version_history_complete,
        })
    } else {
        None
    };
    Ok(OperationRecord {
        id: model.id,
        state: OperationState::parse(&model.state)?,
        tenant_id: model.tenant_id,
        namespace_epoch: model
            .namespace_epoch
            .map(|epoch| {
                u64::try_from(epoch)
                    .map_err(|_| JournalError::Corrupt("negative namespace epoch".to_string()))
            })
            .transpose()?,
        destination: ObjectDestination {
            backend_id: model.backend_id,
            bucket: model.bucket,
            logical_key: model.logical_key,
            physical_key: model.physical_key,
            workspace_binding: match (
                model.backend_config_version,
                model.capability_attestation_id,
                model.routing_epoch,
                model.routing_lease_id,
                model.routing_fencing_token,
            ) {
                (None, None, None, None, None) => None,
                (Some(config), Some(attestation), Some(epoch), Some(lease_id), Some(token)) => {
                    Some(WorkspaceDestinationBinding {
                        backend_config_version: config,
                        capability_attestation_id: attestation,
                        routing_epoch: u64::try_from(epoch).map_err(|_| {
                            JournalError::Corrupt("negative routing epoch".to_string())
                        })?,
                        routing_lease_id: lease_id,
                        routing_fencing_token: u64::try_from(token).map_err(|_| {
                            JournalError::Corrupt("negative routing fencing token".to_string())
                        })?,
                    })
                }
                _ => {
                    return Err(JournalError::Corrupt(
                        "partial workspace destination binding".to_string(),
                    ));
                }
            },
        },
        expected: ExpectedObject {
            digest: model.expected_digest,
            size: expected_size,
            metadata,
        },
        upload_id: model.upload_id,
        committed,
        lease_owner: model.lease_owner,
        lease_expires_at_ms: model.lease_expires_at_ms,
        mutation_not_before_ms: model.mutation_not_before_ms,
        exact_absence_observed_at_ms: model.exact_absence_observed_at_ms,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

fn part_from_model(model: object_operation_part::Model) -> Result<PartRecord, JournalError> {
    Ok(PartRecord {
        operation_id: model.operation_id,
        part_number: model.part_number,
        etag: model.etag,
        size_bytes: u64::try_from(model.size_bytes)
            .map_err(|_| JournalError::Corrupt("negative uploaded part size".to_string()))?,
        digest: model.digest,
        created_at_ms: model.created_at_ms,
    })
}

fn evidence_from_model(model: object_operation_evidence::Model) -> EvidenceRecord {
    EvidenceRecord {
        id: model.id,
        operation_id: model.operation_id,
        kind: model.kind,
        detail: model.detail,
        created_at_ms: model.created_at_ms,
    }
}

#[async_trait]
impl OperationJournal for PostgresOperationJournal {
    fn is_durable(&self) -> bool {
        true
    }

    async fn insert_intent(&self, operation: OperationRecord) -> Result<(), JournalError> {
        if operation.state != OperationState::Intent {
            return Err(JournalError::Conflict(
                "new operation must start in INTENT".to_string(),
            ));
        }
        let expected_size = operation
            .expected
            .size
            .map(|size| {
                i64::try_from(size).map_err(|_| {
                    JournalError::Conflict("expected object size exceeds BIGINT".to_string())
                })
            })
            .transpose()?;
        let expected_metadata = serde_json::to_value(&operation.expected.metadata)
            .map_err(|error| JournalError::Corrupt(error.to_string()))?;
        let workspace_binding = operation.destination.workspace_binding;
        object_operation::ActiveModel {
            id: Set(operation.id),
            state: Set(OperationState::Intent.as_str().to_string()),
            backend_id: Set(operation.destination.backend_id),
            bucket: Set(operation.destination.bucket),
            logical_key: Set(operation.destination.logical_key),
            physical_key: Set(operation.destination.physical_key),
            tenant_id: Set(operation.tenant_id),
            namespace_epoch: Set(operation
                .namespace_epoch
                .map(i64::try_from)
                .transpose()
                .map_err(|_| {
                    JournalError::Conflict("namespace epoch exceeds BIGINT".to_string())
                })?),
            backend_config_version: Set(workspace_binding
                .as_ref()
                .map(|binding| binding.backend_config_version.clone())),
            capability_attestation_id: Set(workspace_binding
                .as_ref()
                .map(|binding| binding.capability_attestation_id.clone())),
            routing_epoch: Set(workspace_binding
                .as_ref()
                .map(|binding| i64::try_from(binding.routing_epoch))
                .transpose()
                .map_err(|_| JournalError::Corrupt("routing epoch exceeds BIGINT".to_string()))?),
            routing_lease_id: Set(workspace_binding
                .as_ref()
                .map(|binding| binding.routing_lease_id)),
            routing_fencing_token: Set(workspace_binding
                .as_ref()
                .map(|binding| i64::try_from(binding.routing_fencing_token))
                .transpose()
                .map_err(|_| {
                    JournalError::Corrupt("routing fencing token exceeds BIGINT".to_string())
                })?),
            mutation_not_before_ms: Set(operation.mutation_not_before_ms),
            exact_absence_observed_at_ms: Set(operation.exact_absence_observed_at_ms),
            expected_digest: Set(operation.expected.digest),
            expected_size: Set(expected_size),
            expected_metadata: Set(expected_metadata),
            upload_id: Set(None),
            committed_etag: Set(None),
            committed_version_id: Set(None),
            committed_superseded_version_ids: Set(serde_json::json!([])),
            committed_version_history_complete: Set(true),
            lease_owner: Set(None),
            lease_expires_at_ms: Set(None),
            created_at_ms: Set(operation.created_at_ms),
            updated_at_ms: Set(operation.updated_at_ms),
        }
        .insert(&self.db)
        .await
        .map_err(persistence)?;
        Ok(())
    }

    async fn get(&self, operation_id: Uuid) -> Result<Option<OperationRecord>, JournalError> {
        object_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(operation_from_model)
            .transpose()
    }

    async fn set_open(
        &self,
        operation_id: Uuid,
        upload_id: Option<&str>,
    ) -> Result<(), JournalError> {
        let result = object_operation::Entity::update_many()
            .col_expr(
                object_operation::Column::State,
                Expr::value(OperationState::Open.as_str()),
            )
            .col_expr(
                object_operation::Column::UploadId,
                Expr::value(upload_id.map(ToOwned::to_owned)),
            )
            .col_expr(
                object_operation::Column::UpdatedAtMs,
                Expr::value(unix_time_ms()),
            )
            .filter(object_operation::Column::Id.eq(operation_id))
            .filter(object_operation::Column::State.eq(OperationState::Intent.as_str()))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(JournalError::Conflict(format!(
                "operation {operation_id} did not transition INTENT -> OPEN"
            )));
        }
        Ok(())
    }

    async fn set_expected(
        &self,
        operation_id: Uuid,
        expected: &ExpectedObject,
    ) -> Result<(), JournalError> {
        let expected_size = expected
            .size
            .map(|size| {
                i64::try_from(size).map_err(|_| {
                    JournalError::Conflict("expected object size exceeds BIGINT".to_string())
                })
            })
            .transpose()?;
        let metadata = serde_json::to_value(&expected.metadata)
            .map_err(|error| JournalError::Corrupt(error.to_string()))?;
        let result = object_operation::Entity::update_many()
            .col_expr(
                object_operation::Column::ExpectedDigest,
                Expr::value(expected.digest.clone()),
            )
            .col_expr(
                object_operation::Column::ExpectedSize,
                Expr::value(expected_size),
            )
            .col_expr(
                object_operation::Column::ExpectedMetadata,
                Expr::value(metadata),
            )
            .col_expr(
                object_operation::Column::UpdatedAtMs,
                Expr::value(unix_time_ms()),
            )
            .filter(object_operation::Column::Id.eq(operation_id))
            .filter(object_operation::Column::State.is_in([
                OperationState::Intent.as_str(),
                OperationState::Open.as_str(),
            ]))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(JournalError::Conflict(format!(
                "operation {operation_id} cannot update expected output"
            )));
        }
        Ok(())
    }

    async fn transition(
        &self,
        operation_id: Uuid,
        expected: OperationState,
        next: OperationState,
        committed: Option<&StoredObjectMeta>,
    ) -> Result<(), JournalError> {
        if !expected.can_transition_to(next) {
            return Err(JournalError::Conflict(format!(
                "illegal transition {expected} -> {next}"
            )));
        }
        if (next == OperationState::Committed) != committed.is_some() {
            return Err(JournalError::Conflict(
                "COMMITTED transitions require object metadata only".to_string(),
            ));
        }
        let mut update = object_operation::Entity::update_many()
            .col_expr(object_operation::Column::State, Expr::value(next.as_str()))
            .col_expr(
                object_operation::Column::UpdatedAtMs,
                Expr::value(unix_time_ms()),
            )
            .col_expr(
                object_operation::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                object_operation::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            );
        if let Some(committed) = committed {
            update = update
                .col_expr(
                    object_operation::Column::CommittedEtag,
                    Expr::value(committed.etag.clone()),
                )
                .col_expr(
                    object_operation::Column::CommittedVersionId,
                    Expr::value(committed.version_id.clone()),
                )
                .col_expr(
                    object_operation::Column::CommittedSupersededVersionIds,
                    Expr::value(serde_json::json!(committed.superseded_version_ids)),
                )
                .col_expr(
                    object_operation::Column::CommittedVersionHistoryComplete,
                    Expr::value(committed.version_history_complete),
                );
        }
        let result = update
            .filter(object_operation::Column::Id.eq(operation_id))
            .filter(object_operation::Column::State.eq(expected.as_str()))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(JournalError::Conflict(format!(
                "operation {operation_id} did not transition {expected} -> {next}"
            )));
        }
        Ok(())
    }

    async fn record_part(&self, part: PartRecord) -> Result<(), JournalError> {
        let size_bytes = i64::try_from(part.size_bytes)
            .map_err(|_| JournalError::Conflict("part size exceeds BIGINT".to_string()))?;
        let model = object_operation_part::ActiveModel {
            operation_id: Set(part.operation_id),
            part_number: Set(part.part_number),
            etag: Set(part.etag.clone()),
            size_bytes: Set(size_bytes),
            digest: Set(part.digest.clone()),
            created_at_ms: Set(part.created_at_ms),
        };
        if let Err(insert_error) = model.insert(&self.db).await {
            let existing =
                object_operation_part::Entity::find_by_id((part.operation_id, part.part_number))
                    .one(&self.db)
                    .await
                    .map_err(persistence)?
                    .ok_or_else(|| persistence(insert_error))?;
            let existing = part_from_model(existing)?;
            if existing.etag != part.etag
                || existing.digest != part.digest
                || existing.size_bytes != part.size_bytes
            {
                return Err(JournalError::Conflict(format!(
                    "part {} retry body or result changed",
                    part.part_number
                )));
            }
        }
        Ok(())
    }

    async fn parts(&self, operation_id: Uuid) -> Result<Vec<PartRecord>, JournalError> {
        object_operation_part::Entity::find()
            .filter(object_operation_part::Column::OperationId.eq(operation_id))
            .order_by_asc(object_operation_part::Column::PartNumber)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(part_from_model)
            .collect()
    }

    async fn append_evidence(&self, evidence: EvidenceRecord) -> Result<(), JournalError> {
        let expected = evidence.clone();
        object_operation_evidence::Entity::insert(object_operation_evidence::ActiveModel {
            id: Set(evidence.id),
            operation_id: Set(evidence.operation_id),
            kind: Set(evidence.kind),
            detail: Set(evidence.detail),
            created_at_ms: Set(evidence.created_at_ms),
        })
        .on_conflict(
            OnConflict::column(object_operation_evidence::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&self.db)
        .await
        .map_err(persistence)?;
        let stored = object_operation_evidence::Entity::find_by_id(expected.id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or_else(|| JournalError::Persistence("evidence insert disappeared".to_string()))?;
        if stored.operation_id != expected.operation_id
            || stored.kind != expected.kind
            || stored.detail != expected.detail
        {
            return Err(JournalError::Conflict(
                "evidence id conflicts with an existing record".to_string(),
            ));
        }
        Ok(())
    }

    async fn evidence(&self, operation_id: Uuid) -> Result<Vec<EvidenceRecord>, JournalError> {
        Ok(object_operation_evidence::Entity::find()
            .filter(object_operation_evidence::Column::OperationId.eq(operation_id))
            .order_by_asc(object_operation_evidence::Column::CreatedAtMs)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(evidence_from_model)
            .collect())
    }

    async fn record_mutation_launch(
        &self,
        operation_id: Uuid,
        not_before_ms: i64,
    ) -> Result<(), JournalError> {
        let model = object_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(JournalError::NotFound(operation_id))?;
        if OperationState::parse(&model.state)?.is_terminal() {
            return Err(JournalError::Conflict(
                "terminal operation cannot launch a provider mutation".to_string(),
            ));
        }
        let next_not_before = model
            .mutation_not_before_ms
            .unwrap_or(i64::MIN)
            .max(not_before_ms);
        let mut active: object_operation::ActiveModel = model.into();
        active.mutation_not_before_ms = Set(Some(next_not_before));
        active.exact_absence_observed_at_ms = Set(None);
        active.updated_at_ms = Set(unix_time_ms());
        active.update(&self.db).await.map_err(persistence)?;
        Ok(())
    }

    async fn confirm_exact_absence(
        &self,
        operation_id: Uuid,
        observed_at_ms: i64,
        minimum_separation_ms: i64,
    ) -> Result<bool, JournalError> {
        let model = object_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(JournalError::NotFound(operation_id))?;
        if model
            .mutation_not_before_ms
            .is_some_and(|not_before| observed_at_ms < not_before)
        {
            return Ok(false);
        }
        if let Some(first) = model.exact_absence_observed_at_ms {
            return Ok(observed_at_ms.saturating_sub(first) >= minimum_separation_ms);
        }
        let mut active: object_operation::ActiveModel = model.into();
        active.exact_absence_observed_at_ms = Set(Some(observed_at_ms));
        active.updated_at_ms = Set(unix_time_ms());
        active.update(&self.db).await.map_err(persistence)?;
        Ok(false)
    }

    async fn claim_reconcilable(
        &self,
        owner: &str,
        stale_before_ms: i64,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<OperationRecord>, JournalError> {
        let candidates = object_operation::Entity::find()
            .filter(object_operation::Column::State.is_not_in([
                OperationState::Committed.as_str(),
                OperationState::ProvenAborted.as_str(),
            ]))
            .filter(object_operation::Column::UpdatedAtMs.lte(stale_before_ms))
            .filter(
                Condition::any()
                    .add(object_operation::Column::LeaseExpiresAtMs.is_null())
                    .add(object_operation::Column::LeaseExpiresAtMs.lt(unix_time_ms())),
            )
            .order_by_asc(object_operation::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let mut claimed = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let result = object_operation::Entity::update_many()
                .col_expr(
                    object_operation::Column::LeaseOwner,
                    Expr::value(Some(owner.to_string())),
                )
                .col_expr(
                    object_operation::Column::LeaseExpiresAtMs,
                    Expr::value(Some(lease_until_ms)),
                )
                .filter(object_operation::Column::Id.eq(candidate.id))
                .filter(
                    Condition::any()
                        .add(object_operation::Column::LeaseExpiresAtMs.is_null())
                        .add(object_operation::Column::LeaseExpiresAtMs.lt(unix_time_ms())),
                )
                .exec(&self.db)
                .await
                .map_err(persistence)?;
            if result.rows_affected == 1 {
                let mut operation = operation_from_model(candidate)?;
                operation.lease_owner = Some(owner.to_string());
                operation.lease_expires_at_ms = Some(lease_until_ms);
                claimed.push(operation);
            }
        }
        Ok(claimed)
    }

    async fn claim_reconcilable_operation(
        &self,
        operation_id: Uuid,
        owner: &str,
        stale_before_ms: i64,
        lease_until_ms: i64,
    ) -> Result<Option<OperationRecord>, JournalError> {
        let candidate = object_operation::Entity::find_by_id(operation_id)
            .filter(object_operation::Column::State.is_not_in([
                OperationState::Committed.as_str(),
                OperationState::ProvenAborted.as_str(),
            ]))
            .filter(object_operation::Column::UpdatedAtMs.lte(stale_before_ms))
            .filter(
                Condition::any()
                    .add(object_operation::Column::LeaseExpiresAtMs.is_null())
                    .add(object_operation::Column::LeaseExpiresAtMs.lt(unix_time_ms())),
            )
            .one(&self.db)
            .await
            .map_err(persistence)?;
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let result = object_operation::Entity::update_many()
            .col_expr(
                object_operation::Column::LeaseOwner,
                Expr::value(Some(owner.to_string())),
            )
            .col_expr(
                object_operation::Column::LeaseExpiresAtMs,
                Expr::value(Some(lease_until_ms)),
            )
            .filter(object_operation::Column::Id.eq(operation_id))
            .filter(
                Condition::any()
                    .add(object_operation::Column::LeaseExpiresAtMs.is_null())
                    .add(object_operation::Column::LeaseExpiresAtMs.lt(unix_time_ms())),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Ok(None);
        }
        let mut operation = operation_from_model(candidate)?;
        operation.lease_owner = Some(owner.to_string());
        operation.lease_expires_at_ms = Some(lease_until_ms);
        Ok(Some(operation))
    }
}

#[cfg(any(test, debug_assertions))]
#[derive(Default)]
struct MemoryState {
    operations: HashMap<Uuid, OperationRecord>,
    parts: HashMap<(Uuid, i32), PartRecord>,
    evidence: Vec<EvidenceRecord>,
}

/// Development-only journal. Release builds cannot construct this type.
#[cfg(any(test, debug_assertions))]
#[derive(Clone, Default)]
pub struct InMemoryOperationJournal {
    state: Arc<Mutex<MemoryState>>,
    fail_committed_transitions: Arc<AtomicUsize>,
    fail_evidence_appends: Arc<AtomicUsize>,
    durable_for_test: bool,
}

#[cfg(any(test, debug_assertions))]
impl InMemoryOperationJournal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn durable_for_test() -> Self {
        Self {
            durable_for_test: true,
            ..Self::default()
        }
    }

    pub fn fail_next_committed_transitions(&self, count: usize) {
        self.fail_committed_transitions
            .store(count, Ordering::Release);
    }

    pub fn fail_next_evidence_appends(&self, count: usize) {
        self.fail_evidence_appends.store(count, Ordering::Release);
    }
}

#[cfg(any(test, debug_assertions))]
#[async_trait]
impl OperationJournal for InMemoryOperationJournal {
    fn is_durable(&self) -> bool {
        self.durable_for_test
    }

    async fn insert_intent(&self, operation: OperationRecord) -> Result<(), JournalError> {
        if operation.state != OperationState::Intent {
            return Err(JournalError::Conflict(
                "new operation must start in INTENT".to_string(),
            ));
        }
        let mut state = self.state.lock().await;
        if state.operations.insert(operation.id, operation).is_some() {
            return Err(JournalError::Conflict("duplicate operation id".to_string()));
        }
        Ok(())
    }

    async fn get(&self, operation_id: Uuid) -> Result<Option<OperationRecord>, JournalError> {
        Ok(self
            .state
            .lock()
            .await
            .operations
            .get(&operation_id)
            .cloned())
    }

    async fn set_open(
        &self,
        operation_id: Uuid,
        upload_id: Option<&str>,
    ) -> Result<(), JournalError> {
        let mut state = self.state.lock().await;
        let operation = state
            .operations
            .get_mut(&operation_id)
            .ok_or(JournalError::NotFound(operation_id))?;
        if operation.state != OperationState::Intent {
            return Err(JournalError::Conflict(format!(
                "expected INTENT, found {}",
                operation.state
            )));
        }
        operation.state = OperationState::Open;
        operation.upload_id = upload_id.map(ToOwned::to_owned);
        operation.updated_at_ms = unix_time_ms();
        Ok(())
    }

    async fn set_expected(
        &self,
        operation_id: Uuid,
        expected: &ExpectedObject,
    ) -> Result<(), JournalError> {
        let mut state = self.state.lock().await;
        let operation = state
            .operations
            .get_mut(&operation_id)
            .ok_or(JournalError::NotFound(operation_id))?;
        if !matches!(
            operation.state,
            OperationState::Intent | OperationState::Open
        ) {
            return Err(JournalError::Conflict(format!(
                "operation {operation_id} cannot update expected output in {}",
                operation.state
            )));
        }
        operation.expected = expected.clone();
        operation.updated_at_ms = unix_time_ms();
        Ok(())
    }

    async fn transition(
        &self,
        operation_id: Uuid,
        expected: OperationState,
        next: OperationState,
        committed: Option<&StoredObjectMeta>,
    ) -> Result<(), JournalError> {
        if !expected.can_transition_to(next) {
            return Err(JournalError::Conflict(format!(
                "illegal transition {expected} -> {next}"
            )));
        }
        if (next == OperationState::Committed) != committed.is_some() {
            return Err(JournalError::Conflict(
                "COMMITTED transitions require object metadata only".to_string(),
            ));
        }
        if next == OperationState::Committed
            && self
                .fail_committed_transitions
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            return Err(JournalError::Persistence(
                "injected COMMITTED transition failure".to_string(),
            ));
        }
        let mut state = self.state.lock().await;
        let operation = state
            .operations
            .get_mut(&operation_id)
            .ok_or(JournalError::NotFound(operation_id))?;
        if operation.state != expected {
            return Err(JournalError::Conflict(format!(
                "expected {expected}, found {}",
                operation.state
            )));
        }
        operation.state = next;
        operation.committed = committed.cloned();
        operation.updated_at_ms = unix_time_ms();
        operation.lease_owner = None;
        operation.lease_expires_at_ms = None;
        Ok(())
    }

    async fn record_part(&self, part: PartRecord) -> Result<(), JournalError> {
        let mut state = self.state.lock().await;
        let key = (part.operation_id, part.part_number);
        if let Some(existing) = state.parts.get(&key) {
            if existing.etag == part.etag
                && existing.size_bytes == part.size_bytes
                && existing.digest == part.digest
            {
                return Ok(());
            }
            return Err(JournalError::Conflict(format!(
                "part {} retry body or result changed",
                part.part_number
            )));
        }
        state.parts.insert(key, part);
        Ok(())
    }

    async fn parts(&self, operation_id: Uuid) -> Result<Vec<PartRecord>, JournalError> {
        let mut parts: Vec<_> = self
            .state
            .lock()
            .await
            .parts
            .values()
            .filter(|part| part.operation_id == operation_id)
            .cloned()
            .collect();
        parts.sort_by_key(|part| part.part_number);
        Ok(parts)
    }

    async fn append_evidence(&self, evidence: EvidenceRecord) -> Result<(), JournalError> {
        if self
            .fail_evidence_appends
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(JournalError::Persistence(
                "injected evidence append failure".to_string(),
            ));
        }
        let mut state = self.state.lock().await;
        if let Some(existing) = state
            .evidence
            .iter()
            .find(|record| record.id == evidence.id)
        {
            return if existing.operation_id == evidence.operation_id
                && existing.kind == evidence.kind
                && existing.detail == evidence.detail
            {
                Ok(())
            } else {
                Err(JournalError::Conflict(
                    "evidence id conflicts with an existing record".to_string(),
                ))
            };
        }
        state.evidence.push(evidence);
        Ok(())
    }

    async fn evidence(&self, operation_id: Uuid) -> Result<Vec<EvidenceRecord>, JournalError> {
        Ok(self
            .state
            .lock()
            .await
            .evidence
            .iter()
            .filter(|evidence| evidence.operation_id == operation_id)
            .cloned()
            .collect())
    }

    async fn record_mutation_launch(
        &self,
        operation_id: Uuid,
        not_before_ms: i64,
    ) -> Result<(), JournalError> {
        let mut state = self.state.lock().await;
        let operation = state
            .operations
            .get_mut(&operation_id)
            .ok_or(JournalError::NotFound(operation_id))?;
        if operation.state.is_terminal() {
            return Err(JournalError::Conflict(
                "terminal operation cannot launch a provider mutation".to_string(),
            ));
        }
        operation.mutation_not_before_ms = Some(
            operation
                .mutation_not_before_ms
                .unwrap_or(i64::MIN)
                .max(not_before_ms),
        );
        operation.exact_absence_observed_at_ms = None;
        operation.updated_at_ms = unix_time_ms();
        Ok(())
    }

    async fn confirm_exact_absence(
        &self,
        operation_id: Uuid,
        observed_at_ms: i64,
        minimum_separation_ms: i64,
    ) -> Result<bool, JournalError> {
        let mut state = self.state.lock().await;
        let operation = state
            .operations
            .get_mut(&operation_id)
            .ok_or(JournalError::NotFound(operation_id))?;
        if operation
            .mutation_not_before_ms
            .is_some_and(|not_before| observed_at_ms < not_before)
        {
            return Ok(false);
        }
        if let Some(first) = operation.exact_absence_observed_at_ms {
            return Ok(observed_at_ms.saturating_sub(first) >= minimum_separation_ms);
        }
        operation.exact_absence_observed_at_ms = Some(observed_at_ms);
        operation.updated_at_ms = unix_time_ms();
        Ok(false)
    }

    async fn claim_reconcilable(
        &self,
        owner: &str,
        stale_before_ms: i64,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<OperationRecord>, JournalError> {
        let now = unix_time_ms();
        let mut state = self.state.lock().await;
        let mut ids: Vec<_> = state
            .operations
            .values()
            .filter(|operation| {
                !operation.state.is_terminal()
                    && operation.updated_at_ms <= stale_before_ms
                    && operation
                        .lease_expires_at_ms
                        .is_none_or(|expiry| expiry < now)
            })
            .map(|operation| (operation.updated_at_ms, operation.id))
            .collect();
        ids.sort_unstable();
        ids.truncate(limit as usize);
        let mut claimed = Vec::with_capacity(ids.len());
        for (_, id) in ids {
            if let Some(operation) = state.operations.get_mut(&id) {
                operation.lease_owner = Some(owner.to_string());
                operation.lease_expires_at_ms = Some(lease_until_ms);
                claimed.push(operation.clone());
            }
        }
        Ok(claimed)
    }

    async fn claim_reconcilable_operation(
        &self,
        operation_id: Uuid,
        owner: &str,
        stale_before_ms: i64,
        lease_until_ms: i64,
    ) -> Result<Option<OperationRecord>, JournalError> {
        let now = unix_time_ms();
        let mut state = self.state.lock().await;
        let Some(operation) = state.operations.get_mut(&operation_id) else {
            return Ok(None);
        };
        if operation.state.is_terminal()
            || operation.updated_at_ms > stale_before_ms
            || operation
                .lease_expires_at_ms
                .is_some_and(|expiry| expiry >= now)
        {
            return Ok(None);
        }
        operation.lease_owner = Some(owner.to_string());
        operation.lease_expires_at_ms = Some(lease_until_ms);
        Ok(Some(operation.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> OperationRecord {
        OperationRecord::intent(
            ObjectDestination {
                backend_id: "test".to_string(),
                bucket: "bucket".to_string(),
                logical_key: "logical".to_string(),
                physical_key: "physical".to_string(),
                workspace_binding: None,
            },
            ExpectedObject::default(),
        )
    }

    #[tokio::test]
    async fn memory_journal_enforces_cas_and_immutable_parts() {
        let journal = InMemoryOperationJournal::new();
        let operation = operation();
        journal.insert_intent(operation.clone()).await.unwrap();
        journal
            .set_open(operation.id, Some("upload"))
            .await
            .unwrap();
        assert!(journal.set_open(operation.id, Some("other")).await.is_err());

        let part = PartRecord {
            operation_id: operation.id,
            part_number: 1,
            etag: "etag".to_string(),
            size_bytes: 3,
            digest: "digest".to_string(),
            created_at_ms: unix_time_ms(),
        };
        journal.record_part(part.clone()).await.unwrap();
        journal.record_part(part.clone()).await.unwrap();
        let mut changed = part;
        changed.digest = "changed".to_string();
        assert!(journal.record_part(changed).await.is_err());
    }

    #[tokio::test]
    async fn restart_simulation_claims_only_stale_nonterminal_operations() {
        let journal = InMemoryOperationJournal::new();
        let mut stale = operation();
        stale.updated_at_ms = 1;
        journal.insert_intent(stale.clone()).await.unwrap();
        let lease_until = unix_time_ms() + 10_000;
        let claimed = journal
            .claim_reconcilable("restarted-process", 2, lease_until, 10)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, stale.id);
        assert!(
            journal
                .claim_reconcilable("other-process", 2, lease_until, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
