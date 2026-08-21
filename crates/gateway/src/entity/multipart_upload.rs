use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "multipart_uploads")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub upload_id: String,
    pub lifecycle: String,
    pub tenant_id: String,
    pub credential_policy_id: String,
    pub bucket: String,
    pub object_key: String,
    pub metadata: Json,
    pub tags: Json,
    pub checksum_mode: Option<String>,
    pub destination: Json,
    pub plugin_snapshot: Json,
    pub limits: Json,
    pub staged_bytes: i64,
    pub reserved_bytes: i64,
    pub expires_at_ms: i64,
    pub tombstone_until_ms: Option<i64>,
    pub complete_request_fingerprint: Option<String>,
    pub completion_lease_owner: Option<String>,
    pub completion_lease_expires_at_ms: Option<i64>,
    pub completion_fencing_token: i64,
    pub completion_result: Option<Json>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::multipart_part_attempt::Entity")]
    Parts,
    #[sea_orm(has_many = "super::multipart_cleanup_audit::Entity")]
    CleanupAudit,
}

impl Related<super::multipart_part_attempt::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Parts.def()
    }
}

impl Related<super::multipart_cleanup_audit::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CleanupAudit.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
