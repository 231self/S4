use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_physical_object_versions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tenant_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub backend_id: String,
    pub provider_kind: String,
    pub provider_instance_id: String,
    pub provider_account_id: String,
    pub canonical_endpoint: String,
    pub provider_region: String,
    pub credential_epoch: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub provider_bucket: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub physical_key: String,
    pub versioning_mode: String,
    pub versioning_capability: String,
    pub write_operation_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub version_id: String,
    pub epoch: i64,
    pub state: String,
    pub purge_operation_id: Option<Uuid>,
    pub last_error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
