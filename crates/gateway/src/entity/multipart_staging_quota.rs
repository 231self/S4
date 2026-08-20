use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "multipart_staging_quotas")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub scope: String,
    pub limit_bytes: i64,
    pub staged_bytes: i64,
    pub reserved_bytes: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
