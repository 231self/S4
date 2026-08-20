use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "multipart_part_attempts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub upload_id: String,
    pub part_number: i32,
    pub attempt: i32,
    pub artifact_key: String,
    pub etag: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
    pub reserved_bytes: i64,
    pub lifecycle: String,
    pub is_current: bool,
    pub created_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::multipart_upload::Entity",
        from = "Column::UploadId",
        to = "super::multipart_upload::Column::UploadId"
    )]
    Upload,
}

impl Related<super::multipart_upload::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Upload.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
