use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_logical_operations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub operation_id: Uuid,
    pub receipt_id: Uuid,
    pub tenant_id: String,
    pub bucket: String,
    pub logical_key: String,
    pub operation_kind: String,
    pub generation: Uuid,
    pub namespace_epoch: i64,
    pub routing_epoch: i64,
    pub expected_authority_cas: Option<i64>,
    pub prior_logical_size: i64,
    pub primary_child_operation_id: Uuid,
    pub backend_id: String,
    pub provider_bucket: String,
    pub physical_key: String,
    pub expected_output_digest: Option<String>,
    pub expected_output_size: Option<i64>,
    pub source_bytes: Option<i64>,
    pub processed_bytes: Option<i64>,
    pub reserved_physical_bytes: i64,
    pub committed_physical_bytes: i64,
    pub released_physical_bytes: i64,
    pub state: String,
    pub committed_authority_version: Option<i64>,
    pub occurred_at_ms: i64,
    pub rate_version: i32,
    pub usage_route: String,
    pub request_kind: String,
    pub max_processed_bytes: i64,
    pub usage_evidence: Json,
    pub settlement_state: String,
    pub last_error_class: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub committed_at_ms: Option<i64>,
    pub aborted_at_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
