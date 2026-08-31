use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_physical_write_intents")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub intent_id: Uuid,
    pub tenant_id: String,
    pub epoch: i64,
    pub backend_id: String,
    pub provider_kind: String,
    pub provider_instance_id: String,
    pub provider_account_id: String,
    pub canonical_endpoint: String,
    pub provider_region: String,
    pub credential_epoch: i64,
    pub provider_bucket: String,
    pub physical_key: String,
    pub versioning_mode: String,
    pub versioning_capability: String,
    pub state: String,
    pub last_error: Option<String>,
    pub lease_owner: String,
    pub lease_token: Uuid,
    pub lease_expires_at_ms: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
