use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "object_operation_parts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub operation_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub part_number: i32,
    pub etag: String,
    pub size_bytes: i64,
    pub digest: String,
    pub created_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::object_operation::Entity",
        from = "Column::OperationId",
        to = "super::object_operation::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Operation,
}

impl Related<super::object_operation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Operation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
