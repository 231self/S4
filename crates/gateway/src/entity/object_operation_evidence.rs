use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "object_operation_evidence")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub operation_id: Uuid,
    pub kind: String,
    pub detail: Json,
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
