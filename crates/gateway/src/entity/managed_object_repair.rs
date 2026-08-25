use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_object_repairs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub kind: String,
    pub state: String,
    pub tenant_id: String,
    pub namespace_epoch: i64,
    pub authority_cas_version: i64,
    pub bucket: String,
    pub logical_key: String,
    pub generation: Uuid,
    pub digest: String,
    pub size_bytes: i64,
    pub metadata: Json,
    pub physical_key: String,
    pub source_backend_id: Option<String>,
    pub target_backend_id: String,
    pub target_role: String,
    pub placement_version: i64,
    pub placement_primary_backend_id: Option<String>,
    pub placement_replica_backend_id: Option<String>,
    pub attempts: i32,
    pub lease_owner: Option<String>,
    pub lease_token: Option<Uuid>,
    pub lease_expires_at_ms: Option<i64>,
    pub last_error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
