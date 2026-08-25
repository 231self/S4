use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_namespace_purges")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub operation_id: Uuid,
    pub tenant_id: String,
    pub epoch: i64,
    pub state: String,
    pub blocked_reason: Option<String>,
    pub deleted_versions: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub completed_at_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
