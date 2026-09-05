use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_placement_policy_versions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub version: i32,
    pub fingerprint: String,
    pub backend_facts: String,
    pub activated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
