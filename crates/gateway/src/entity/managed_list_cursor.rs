use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "managed_list_cursors")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub cursor_id: Uuid,
    pub predecessor_cursor_id: Option<Uuid>,
    pub tenant_id: String,
    pub namespace_epoch: i64,
    pub routing_epoch: i64,
    pub bucket: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub list_version: String,
    pub last_key: Option<String>,
    pub last_common_prefix: Option<String>,
    pub response_state: Vec<u8>,
    pub response_state_bytes: i64,
    pub final_page: bool,
    pub state: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub first_used_at_ms: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
