use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: String,
    pub key_id: String,
    pub secret_hash: String,
    pub secret_encrypted: Option<String>,
    pub label: String,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: Option<i64>,
    pub public_key_pem: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
