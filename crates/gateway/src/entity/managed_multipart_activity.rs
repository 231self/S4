use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_multipart_activities")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub upload_id: String,
    pub tenant_id: String,
    pub namespace_epoch: i64,
    pub state: String,
    pub registration_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
