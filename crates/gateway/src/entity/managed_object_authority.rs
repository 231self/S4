use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_object_authorities")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tenant_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub bucket: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub logical_key: String,
    pub generation: Uuid,
    pub digest: String,
    pub size_bytes: i64,
    pub metadata: Json,
    pub placement_version: i64,
    pub primary_backend_id: String,
    pub replica_backend_id: Option<String>,
    pub primary_status: String,
    pub replica_status: String,
    pub tombstone: bool,
    pub cas_version: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
