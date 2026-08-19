use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "object_operations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub state: String,
    pub backend_id: String,
    pub bucket: String,
    pub logical_key: String,
    pub physical_key: String,
    pub expected_digest: Option<String>,
    pub expected_size: Option<i64>,
    pub expected_metadata: Json,
    pub upload_id: Option<String>,
    pub committed_etag: Option<String>,
    pub committed_version_id: Option<String>,
    pub lease_owner: Option<String>,
    pub lease_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::object_operation_part::Entity")]
    Parts,
    #[sea_orm(has_many = "super::object_operation_evidence::Entity")]
    Evidence,
}

impl Related<super::object_operation_part::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Parts.def()
    }
}

impl Related<super::object_operation_evidence::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Evidence.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
