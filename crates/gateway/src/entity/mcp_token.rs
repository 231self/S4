use sea_orm::entity::prelude::*;

/// MCP bearer tokens: `s4m_...`. The full token is the credential; only its
/// SHA-256 hash is stored.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "mcp_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: String,
    pub token_hash: String,
    pub label: String,
    pub created_at: DateTimeWithTimeZone,
    pub expires_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
