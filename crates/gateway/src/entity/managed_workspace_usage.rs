use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_workspace_usage")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tenant_id: String,
    pub visible_logical_bytes: i64,
    pub physical_allocated_bytes: i64,
    pub reserved_bytes: i64,
    pub visible_limit_bytes: i64,
    pub replacement_headroom_bytes: i64,
    pub active_operation_id: Option<Uuid>,
    pub version: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
