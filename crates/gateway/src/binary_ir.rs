//! Versioned, format-neutral schema and value representations for binary codecs.
//!
//! The IR deliberately has no named schema references. Container children are
//! owned, so recursive schemas cannot be represented, and validation additionally
//! bounds structural nesting.
//!
//! Maskura Canonical JSON v1 is UTF-8 without a BOM, contains no insignificant
//! whitespace, and sorts every JSON object key lexicographically. Arrays retain
//! their declared order, including schema and value record fields. Encoding goes
//! through [`serde_json::Value`], whose object map is sorted when serde_json's
//! `preserve_order` feature is disabled. Signed 64-bit integers and IEEE floats
//! use canonical strings so the WIT byte contract does not depend on a guest
//! language's JSON number implementation. Finite floats use Ryu shortest-roundtrip
//! decimal form, both signed zeros encode as `"0"`, and non-finite values use the
//! exact tokens `"NaN"`, `"Infinity"`, and `"-Infinity"`. Dates and timestamps
//! use ISO calendar years in the inclusive range 0001 through 9999.

use std::collections::HashSet;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use s4_error::{S4Error, codes};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;

pub const SCHEMA_IR_VERSION: u32 = 1;
pub const VALUE_IR_VERSION: u32 = 1;

pub const DEFAULT_MAX_ENCODED_SCHEMA_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_FIELDS: usize = 4096;
pub const DEFAULT_MAX_NESTING_DEPTH: usize = 8;
pub const DEFAULT_MAX_ENCODED_VALUE_BYTES: usize = 8 * 1024 * 1024;

pub const ERROR_SCHEMA_INVALID: &str = "binary_ir.schema_invalid";
pub const ERROR_VALUE_INVALID: &str = "binary_ir.value_invalid";
pub const ERROR_VERSION_UNSUPPORTED: &str = "binary_ir.version_unsupported";
pub const ERROR_NON_CANONICAL: &str = "binary_ir.non_canonical";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryIrLimits {
    pub max_encoded_schema_bytes: usize,
    pub max_fields: usize,
    pub max_nesting_depth: usize,
    pub max_encoded_value_bytes: usize,
}

impl Default for BinaryIrLimits {
    fn default() -> Self {
        Self {
            max_encoded_schema_bytes: DEFAULT_MAX_ENCODED_SCHEMA_BYTES,
            max_fields: DEFAULT_MAX_FIELDS,
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
            max_encoded_value_bytes: DEFAULT_MAX_ENCODED_VALUE_BYTES,
        }
    }
}

impl BinaryIrLimits {
    fn validate(self) -> Result<(), S4Error> {
        if self.max_encoded_schema_bytes == 0
            || self.max_fields == 0
            || self.max_nesting_depth == 0
            || self.max_encoded_value_bytes == 0
        {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "binary IR limits must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaIr {
    pub version: u32,
    pub root: SchemaNode,
}

impl SchemaIr {
    pub fn new(root: SchemaNode) -> Self {
        Self {
            version: SCHEMA_IR_VERSION,
            root,
        }
    }

    pub fn validate(&self, limits: BinaryIrLimits) -> Result<(), S4Error> {
        limits.validate()?;
        validate_version("schema", self.version, SCHEMA_IR_VERSION)?;
        let mut field_count = 0;
        let mut path = SchemaPath::root();
        self.root
            .validate_inner(limits, 0, &mut field_count, &mut path)
    }

    pub fn to_canonical_json(&self, limits: BinaryIrLimits) -> Result<Vec<u8>, S4Error> {
        encode_schema_canonical_json(self, limits)
    }

    pub fn from_canonical_json(encoded: &[u8], limits: BinaryIrLimits) -> Result<Self, S4Error> {
        decode_schema_canonical_json(encoded, limits)
    }

    pub fn visit_paths<F>(&self, visitor: F)
    where
        F: FnMut(&SchemaPath, &SchemaNode),
    {
        self.root.visit_paths(visitor);
    }

    /// Returns paths a reductor may claim directly: records and custom logical nodes.
    pub fn reductor_claim_paths(&self) -> Vec<SchemaPath> {
        let mut paths = Vec::new();
        self.visit_paths(|path, node| {
            if matches!(
                node.kind,
                SchemaKind::Record { .. } | SchemaKind::Custom { .. }
            ) {
                paths.push(path.clone());
            }
        });
        paths
    }

    pub fn node_at_path(&self, path: &SchemaPath) -> Option<&SchemaNode> {
        self.root.node_at_path(path)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaNode {
    pub nullable: bool,
    pub kind: SchemaKind,
}

impl SchemaNode {
    pub fn required(kind: SchemaKind) -> Self {
        Self {
            nullable: false,
            kind,
        }
    }

    pub fn nullable(kind: SchemaKind) -> Self {
        Self {
            nullable: true,
            kind,
        }
    }

    pub fn visit_paths<F>(&self, mut visitor: F)
    where
        F: FnMut(&SchemaPath, &SchemaNode),
    {
        let mut path = SchemaPath::root();
        self.visit_paths_inner(&mut path, &mut visitor);
    }

    pub fn node_at_path(&self, path: &SchemaPath) -> Option<&SchemaNode> {
        let mut node = self;
        for segment in &path.0 {
            node = match (&node.kind, segment) {
                (SchemaKind::Array { items }, SchemaPathSegment::ArrayElement) => items,
                (SchemaKind::Map { values }, SchemaPathSegment::MapValue) => values,
                (SchemaKind::Record { fields }, SchemaPathSegment::Field(name)) => fields
                    .iter()
                    .find(|field| field.name == *name)
                    .map(|field| &field.schema)?,
                (SchemaKind::Custom { value, .. }, SchemaPathSegment::LogicalValue) => value,
                _ => return None,
            };
        }
        Some(node)
    }

    fn validate_inner(
        &self,
        limits: BinaryIrLimits,
        depth: usize,
        field_count: &mut usize,
        path: &mut SchemaPath,
    ) -> Result<(), S4Error> {
        if depth > limits.max_nesting_depth {
            return Err(schema_error(
                path,
                format!(
                    "nesting depth {depth} exceeds limit {}",
                    limits.max_nesting_depth
                ),
            ));
        }
        if self.nullable && matches!(self.kind, SchemaKind::Null) {
            return Err(schema_error(path, "null cannot also be nullable"));
        }

        match &self.kind {
            SchemaKind::Array { items } => {
                path.0.push(SchemaPathSegment::ArrayElement);
                let result = items.validate_inner(limits, depth + 1, field_count, path);
                path.0.pop();
                result?;
            }
            SchemaKind::Map { values } => {
                path.0.push(SchemaPathSegment::MapValue);
                let result = values.validate_inner(limits, depth + 1, field_count, path);
                path.0.pop();
                result?;
            }
            SchemaKind::Record { fields } => {
                *field_count = field_count.checked_add(fields.len()).ok_or_else(|| {
                    schema_error(path, "field count overflow while validating schema")
                })?;
                if *field_count > limits.max_fields {
                    return Err(schema_error(
                        path,
                        format!(
                            "field count {} exceeds limit {}",
                            *field_count, limits.max_fields
                        ),
                    ));
                }

                let mut names = HashSet::with_capacity(fields.len());
                for field in fields {
                    if field.name.is_empty() {
                        return Err(schema_error(path, "field names must not be empty"));
                    }
                    if !names.insert(field.name.as_str()) {
                        return Err(schema_error(
                            path,
                            format!("duplicate field name {:?}", field.name),
                        ));
                    }
                    path.0.push(SchemaPathSegment::Field(field.name.clone()));
                    let result = field
                        .schema
                        .validate_inner(limits, depth + 1, field_count, path);
                    path.0.pop();
                    result?;
                }
            }
            SchemaKind::Decimal { precision, scale } => {
                if *precision == 0 {
                    return Err(schema_error(path, "decimal precision must be positive"));
                }
                if scale > precision {
                    return Err(schema_error(
                        path,
                        format!("decimal scale {scale} exceeds precision {precision}"),
                    ));
                }
            }
            SchemaKind::Custom { type_id, value } => {
                if type_id.is_empty() {
                    return Err(schema_error(
                        path,
                        "custom logical type ID must not be empty",
                    ));
                }
                path.0.push(SchemaPathSegment::LogicalValue);
                let result = value.validate_inner(limits, depth + 1, field_count, path);
                path.0.pop();
                result?;
            }
            SchemaKind::Null
            | SchemaKind::Boolean
            | SchemaKind::I32
            | SchemaKind::I64
            | SchemaKind::F32
            | SchemaKind::F64
            | SchemaKind::String
            | SchemaKind::Bytes
            | SchemaKind::Date
            | SchemaKind::Time
            | SchemaKind::Timestamp
            | SchemaKind::Uuid => {}
        }
        Ok(())
    }

    fn visit_paths_inner<F>(&self, path: &mut SchemaPath, visitor: &mut F)
    where
        F: FnMut(&SchemaPath, &SchemaNode),
    {
        visitor(path, self);
        match &self.kind {
            SchemaKind::Array { items } => {
                path.0.push(SchemaPathSegment::ArrayElement);
                items.visit_paths_inner(path, visitor);
                path.0.pop();
            }
            SchemaKind::Map { values } => {
                path.0.push(SchemaPathSegment::MapValue);
                values.visit_paths_inner(path, visitor);
                path.0.pop();
            }
            SchemaKind::Record { fields } => {
                for field in fields {
                    path.0.push(SchemaPathSegment::Field(field.name.clone()));
                    field.schema.visit_paths_inner(path, visitor);
                    path.0.pop();
                }
            }
            SchemaKind::Custom { value, .. } => {
                path.0.push(SchemaPathSegment::LogicalValue);
                value.visit_paths_inner(path, visitor);
                path.0.pop();
            }
            SchemaKind::Null
            | SchemaKind::Boolean
            | SchemaKind::I32
            | SchemaKind::I64
            | SchemaKind::F32
            | SchemaKind::F64
            | SchemaKind::String
            | SchemaKind::Bytes
            | SchemaKind::Date
            | SchemaKind::Time
            | SchemaKind::Timestamp
            | SchemaKind::Uuid
            | SchemaKind::Decimal { .. } => {}
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SchemaKind {
    Null,
    Boolean,
    I32,
    I64,
    F32,
    F64,
    String,
    Bytes,
    Array {
        items: Box<SchemaNode>,
    },
    Map {
        values: Box<SchemaNode>,
    },
    Record {
        fields: Vec<SchemaField>,
    },
    Date,
    Time,
    Timestamp,
    Uuid,
    Decimal {
        precision: u32,
        scale: u32,
    },
    Custom {
        type_id: String,
        value: Box<SchemaNode>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaField {
    pub name: String,
    pub schema: SchemaNode,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SchemaPath(pub Vec<SchemaPathSegment>);

impl SchemaPath {
    pub fn root() -> Self {
        Self::default()
    }

    pub fn segments(&self) -> &[SchemaPathSegment] {
        &self.0
    }
}

impl fmt::Display for SchemaPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("$")?;
        for segment in &self.0 {
            match segment {
                SchemaPathSegment::Field(name) => write!(formatter, ".{name}")?,
                SchemaPathSegment::ArrayElement => formatter.write_str("[*]")?,
                SchemaPathSegment::MapValue => formatter.write_str("{*}")?,
                SchemaPathSegment::LogicalValue => formatter.write_str("<logical>")?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SchemaPathSegment {
    Field(String),
    ArrayElement,
    MapValue,
    LogicalValue,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueIr {
    pub version: u32,
    pub root: Value,
}

impl ValueIr {
    pub fn new(root: Value) -> Self {
        Self {
            version: VALUE_IR_VERSION,
            root,
        }
    }

    pub fn validate(&self, schema: &SchemaIr, limits: BinaryIrLimits) -> Result<(), S4Error> {
        limits.validate()?;
        validate_version("value", self.version, VALUE_IR_VERSION)?;
        schema.validate(limits)?;

        let mut path = ValuePath::root();
        self.root.validate_inner(limits, 0, &mut path)?;
        validate_value_against_schema(&self.root, &schema.root, &mut path)
    }

    pub fn to_canonical_json(
        &self,
        schema: &SchemaIr,
        limits: BinaryIrLimits,
    ) -> Result<Vec<u8>, S4Error> {
        encode_value_canonical_json(self, schema, limits)
    }

    pub fn from_canonical_json(
        encoded: &[u8],
        schema: &SchemaIr,
        limits: BinaryIrLimits,
    ) -> Result<Self, S4Error> {
        decode_value_canonical_json(encoded, schema, limits)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    Null,
    Boolean {
        value: bool,
    },
    I32 {
        value: i32,
    },
    I64 {
        #[serde(with = "canonical_i64")]
        value: i64,
    },
    F32 {
        #[serde(with = "canonical_f32")]
        value: f32,
    },
    F64 {
        #[serde(with = "canonical_f64")]
        value: f64,
    },
    String {
        value: String,
    },
    Bytes {
        #[serde(with = "base64_value")]
        value: Vec<u8>,
    },
    Array {
        items: Vec<Value>,
    },
    Map {
        entries: Vec<MapEntry>,
    },
    Record {
        fields: Vec<ValueField>,
    },
    Date {
        value: String,
    },
    Time {
        value: String,
    },
    Timestamp {
        value: String,
    },
    Uuid {
        value: String,
    },
    Decimal {
        value: String,
    },
    Custom {
        type_id: String,
        value: Box<Value>,
    },
}

impl Value {
    pub fn value_at_path(&self, path: &ValuePath) -> Option<&Value> {
        let mut value = self;
        for segment in &path.0 {
            value = match (value, segment) {
                (Self::Array { items }, ValuePathSegment::ArrayIndex(index)) => {
                    items.get(*index)?
                }
                (Self::Map { entries }, ValuePathSegment::MapKey(key)) => entries
                    .iter()
                    .find(|entry| entry.key == *key)
                    .map(|entry| &entry.value)?,
                (Self::Record { fields }, ValuePathSegment::Field(name)) => fields
                    .iter()
                    .find(|field| field.name == *name)
                    .map(|field| &field.value)?,
                (Self::Custom { value, .. }, ValuePathSegment::LogicalValue) => value,
                _ => return None,
            };
        }
        Some(value)
    }

    pub fn value_at_path_mut(&mut self, path: &ValuePath) -> Option<&mut Value> {
        let mut value = self;
        for segment in &path.0 {
            value = match (value, segment) {
                (Self::Array { items }, ValuePathSegment::ArrayIndex(index)) => {
                    items.get_mut(*index)?
                }
                (Self::Map { entries }, ValuePathSegment::MapKey(key)) => entries
                    .iter_mut()
                    .find(|entry| entry.key == *key)
                    .map(|entry| &mut entry.value)?,
                (Self::Record { fields }, ValuePathSegment::Field(name)) => fields
                    .iter_mut()
                    .find(|field| field.name == *name)
                    .map(|field| &mut field.value)?,
                (Self::Custom { value, .. }, ValuePathSegment::LogicalValue) => value,
                _ => return None,
            };
        }
        Some(value)
    }

    /// Visits every concrete value selected by a schema path. Array and map
    /// segments fan out to all elements, which is the operation reductors need
    /// when applying one schema claim to a row.
    pub fn visit_claim_matches<F>(&self, claim: &SchemaPath, mut visitor: F)
    where
        F: FnMut(&ValuePath, &Value),
    {
        let mut path = ValuePath::root();
        visit_claim_matches_inner(self, claim.segments(), &mut path, &mut visitor);
    }

    pub fn visit_claim_matches_mut<F>(&mut self, claim: &SchemaPath, mut visitor: F)
    where
        F: FnMut(&ValuePath, &mut Value),
    {
        let mut path = ValuePath::root();
        visit_claim_matches_mut_inner(self, claim.segments(), &mut path, &mut visitor);
    }

    fn validate_inner(
        &self,
        limits: BinaryIrLimits,
        depth: usize,
        path: &mut ValuePath,
    ) -> Result<(), S4Error> {
        if depth > limits.max_nesting_depth {
            return Err(value_error(
                path,
                format!(
                    "nesting depth {depth} exceeds limit {}",
                    limits.max_nesting_depth
                ),
            ));
        }

        match self {
            Self::Array { items } => {
                for (index, item) in items.iter().enumerate() {
                    path.0.push(ValuePathSegment::ArrayIndex(index));
                    let result = item.validate_inner(limits, depth + 1, path);
                    path.0.pop();
                    result?;
                }
            }
            Self::Map { entries } => {
                let mut previous_key: Option<&str> = None;
                for entry in entries {
                    if previous_key.is_some_and(|previous| previous >= entry.key.as_str()) {
                        return Err(value_error(
                            path,
                            "map entries must have unique keys in ascending order",
                        ));
                    }
                    previous_key = Some(entry.key.as_str());
                    path.0.push(ValuePathSegment::MapKey(entry.key.clone()));
                    let result = entry.value.validate_inner(limits, depth + 1, path);
                    path.0.pop();
                    result?;
                }
            }
            Self::Record { fields } => {
                let mut names = HashSet::with_capacity(fields.len());
                for field in fields {
                    if field.name.is_empty() {
                        return Err(value_error(path, "record field names must not be empty"));
                    }
                    if !names.insert(field.name.as_str()) {
                        return Err(value_error(
                            path,
                            format!("duplicate record field name {:?}", field.name),
                        ));
                    }
                    path.0.push(ValuePathSegment::Field(field.name.clone()));
                    let result = field.value.validate_inner(limits, depth + 1, path);
                    path.0.pop();
                    result?;
                }
            }
            Self::Date { value } => validate_date(value)
                .map_err(|message| value_error(path, format!("invalid date: {message}")))?,
            Self::Time { value } => validate_time(value)
                .map_err(|message| value_error(path, format!("invalid time: {message}")))?,
            Self::Timestamp { value } => validate_timestamp(value)
                .map_err(|message| value_error(path, format!("invalid timestamp: {message}")))?,
            Self::Uuid { value } => validate_uuid(value)
                .map_err(|message| value_error(path, format!("invalid UUID: {message}")))?,
            Self::Decimal { value } => {
                parse_decimal(value)
                    .map_err(|message| value_error(path, format!("invalid decimal: {message}")))?;
            }
            Self::Custom { type_id, value } => {
                if type_id.is_empty() {
                    return Err(value_error(
                        path,
                        "custom logical type ID must not be empty",
                    ));
                }
                path.0.push(ValuePathSegment::LogicalValue);
                let result = value.validate_inner(limits, depth + 1, path);
                path.0.pop();
                result?;
            }
            Self::Null
            | Self::Boolean { .. }
            | Self::I32 { .. }
            | Self::I64 { .. }
            | Self::F32 { .. }
            | Self::F64 { .. }
            | Self::String { .. }
            | Self::Bytes { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MapEntry {
    pub key: String,
    pub value: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueField {
    pub name: String,
    pub value: Value,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ValuePath(pub Vec<ValuePathSegment>);

impl ValuePath {
    pub fn root() -> Self {
        Self::default()
    }

    pub fn segments(&self) -> &[ValuePathSegment] {
        &self.0
    }
}

impl fmt::Display for ValuePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("$")?;
        for segment in &self.0 {
            match segment {
                ValuePathSegment::Field(name) => write!(formatter, ".{name}")?,
                ValuePathSegment::ArrayIndex(index) => write!(formatter, "[{index}]")?,
                ValuePathSegment::MapKey(key) => write!(formatter, "[{key:?}]")?,
                ValuePathSegment::LogicalValue => formatter.write_str("<logical>")?,
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ValuePathSegment {
    Field(String),
    ArrayIndex(usize),
    MapKey(String),
    LogicalValue,
}

pub fn encode_schema_canonical_json(
    schema: &SchemaIr,
    limits: BinaryIrLimits,
) -> Result<Vec<u8>, S4Error> {
    schema.validate(limits)?;
    let encoded = serialize_json(schema)?;
    ensure_size(
        "encoded schema",
        encoded.len(),
        limits.max_encoded_schema_bytes,
        codes::LIMIT_INPUT_BYTES,
    )?;
    Ok(encoded)
}

pub fn decode_schema_canonical_json(
    encoded: &[u8],
    limits: BinaryIrLimits,
) -> Result<SchemaIr, S4Error> {
    limits.validate()?;
    ensure_size(
        "encoded schema",
        encoded.len(),
        limits.max_encoded_schema_bytes,
        codes::LIMIT_INPUT_BYTES,
    )?;
    let json = parse_canonical_json(encoded, "schema")?;
    reject_unit_variant_extras(
        &json,
        &[
            "null",
            "boolean",
            "i32",
            "i64",
            "f32",
            "f64",
            "string",
            "bytes",
            "date",
            "time",
            "timestamp",
            "uuid",
        ],
        "schema",
    )?;
    let schema: SchemaIr = deserialize_json(json)?;
    schema.validate(limits)?;
    Ok(schema)
}

pub fn encode_value_canonical_json(
    value: &ValueIr,
    schema: &SchemaIr,
    limits: BinaryIrLimits,
) -> Result<Vec<u8>, S4Error> {
    value.validate(schema, limits)?;
    let encoded = serialize_json(value)?;
    ensure_size(
        "encoded value",
        encoded.len(),
        limits.max_encoded_value_bytes,
        codes::RECORD_TOO_LARGE,
    )?;
    Ok(encoded)
}

pub fn decode_value_canonical_json(
    encoded: &[u8],
    schema: &SchemaIr,
    limits: BinaryIrLimits,
) -> Result<ValueIr, S4Error> {
    limits.validate()?;
    ensure_size(
        "encoded value",
        encoded.len(),
        limits.max_encoded_value_bytes,
        codes::RECORD_TOO_LARGE,
    )?;
    let json = parse_canonical_json(encoded, "value")?;
    reject_unit_variant_extras(&json, &["null"], "value")?;
    let value: ValueIr = deserialize_json(json)?;
    value.validate(schema, limits)?;
    Ok(value)
}

fn validate_value_against_schema(
    value: &Value,
    schema: &SchemaNode,
    path: &mut ValuePath,
) -> Result<(), S4Error> {
    if matches!(value, Value::Null) {
        return if schema.nullable || matches!(schema.kind, SchemaKind::Null) {
            Ok(())
        } else {
            Err(value_error(path, "null supplied for a required schema"))
        };
    }

    let mismatch = || {
        value_error(
            path,
            format!(
                "value type {} does not match schema type {}",
                value.kind_name(),
                schema.kind.kind_name()
            ),
        )
    };

    match (value, &schema.kind) {
        (Value::Boolean { .. }, SchemaKind::Boolean)
        | (Value::I32 { .. }, SchemaKind::I32)
        | (Value::I64 { .. }, SchemaKind::I64)
        | (Value::F32 { .. }, SchemaKind::F32)
        | (Value::F64 { .. }, SchemaKind::F64)
        | (Value::String { .. }, SchemaKind::String)
        | (Value::Bytes { .. }, SchemaKind::Bytes)
        | (Value::Date { .. }, SchemaKind::Date)
        | (Value::Time { .. }, SchemaKind::Time)
        | (Value::Timestamp { .. }, SchemaKind::Timestamp)
        | (Value::Uuid { .. }, SchemaKind::Uuid) => Ok(()),
        (Value::Array { items }, SchemaKind::Array { items: item_schema }) => {
            for (index, item) in items.iter().enumerate() {
                path.0.push(ValuePathSegment::ArrayIndex(index));
                let result = validate_value_against_schema(item, item_schema, path);
                path.0.pop();
                result?;
            }
            Ok(())
        }
        (Value::Map { entries }, SchemaKind::Map { values }) => {
            for entry in entries {
                path.0.push(ValuePathSegment::MapKey(entry.key.clone()));
                let result = validate_value_against_schema(&entry.value, values, path);
                path.0.pop();
                result?;
            }
            Ok(())
        }
        (
            Value::Record { fields },
            SchemaKind::Record {
                fields: schema_fields,
            },
        ) => {
            if fields.len() != schema_fields.len() {
                return Err(value_error(
                    path,
                    format!(
                        "record has {} fields but schema requires {}",
                        fields.len(),
                        schema_fields.len()
                    ),
                ));
            }
            for (field, schema_field) in fields.iter().zip(schema_fields) {
                if field.name != schema_field.name {
                    return Err(value_error(
                        path,
                        format!(
                            "record field {:?} is out of order or does not match schema field {:?}",
                            field.name, schema_field.name
                        ),
                    ));
                }
                path.0.push(ValuePathSegment::Field(field.name.clone()));
                let result =
                    validate_value_against_schema(&field.value, &schema_field.schema, path);
                path.0.pop();
                result?;
            }
            Ok(())
        }
        (Value::Decimal { value }, SchemaKind::Decimal { precision, scale }) => {
            let decimal = parse_decimal(value)
                .map_err(|message| value_error(path, format!("invalid decimal: {message}")))?;
            if decimal.scale != *scale {
                return Err(value_error(
                    path,
                    format!(
                        "decimal scale {} does not match schema scale {scale}",
                        decimal.scale
                    ),
                ));
            }
            if decimal.precision > *precision {
                return Err(value_error(
                    path,
                    format!(
                        "decimal precision {} exceeds schema precision {precision}",
                        decimal.precision
                    ),
                ));
            }
            Ok(())
        }
        (
            Value::Custom {
                type_id,
                value: inner,
            },
            SchemaKind::Custom {
                type_id: schema_type_id,
                value: inner_schema,
            },
        ) => {
            if type_id != schema_type_id {
                return Err(value_error(
                    path,
                    format!(
                        "custom logical type ID {type_id:?} does not match schema ID {schema_type_id:?}"
                    ),
                ));
            }
            path.0.push(ValuePathSegment::LogicalValue);
            let result = validate_value_against_schema(inner, inner_schema, path);
            path.0.pop();
            result
        }
        _ => Err(mismatch()),
    }
}

impl SchemaKind {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean => "boolean",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::String => "string",
            Self::Bytes => "bytes",
            Self::Array { .. } => "array",
            Self::Map { .. } => "map",
            Self::Record { .. } => "record",
            Self::Date => "date",
            Self::Time => "time",
            Self::Timestamp => "timestamp",
            Self::Uuid => "uuid",
            Self::Decimal { .. } => "decimal",
            Self::Custom { .. } => "custom",
        }
    }
}

impl Value {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Boolean { .. } => "boolean",
            Self::I32 { .. } => "i32",
            Self::I64 { .. } => "i64",
            Self::F32 { .. } => "f32",
            Self::F64 { .. } => "f64",
            Self::String { .. } => "string",
            Self::Bytes { .. } => "bytes",
            Self::Array { .. } => "array",
            Self::Map { .. } => "map",
            Self::Record { .. } => "record",
            Self::Date { .. } => "date",
            Self::Time { .. } => "time",
            Self::Timestamp { .. } => "timestamp",
            Self::Uuid { .. } => "uuid",
            Self::Decimal { .. } => "decimal",
            Self::Custom { .. } => "custom",
        }
    }
}

fn visit_claim_matches_inner<F>(
    value: &Value,
    segments: &[SchemaPathSegment],
    path: &mut ValuePath,
    visitor: &mut F,
) where
    F: FnMut(&ValuePath, &Value),
{
    let Some((segment, rest)) = segments.split_first() else {
        visitor(path, value);
        return;
    };
    match (value, segment) {
        (Value::Record { fields }, SchemaPathSegment::Field(name)) => {
            if let Some(field) = fields.iter().find(|field| field.name == *name) {
                path.0.push(ValuePathSegment::Field(name.clone()));
                visit_claim_matches_inner(&field.value, rest, path, visitor);
                path.0.pop();
            }
        }
        (Value::Array { items }, SchemaPathSegment::ArrayElement) => {
            for (index, item) in items.iter().enumerate() {
                path.0.push(ValuePathSegment::ArrayIndex(index));
                visit_claim_matches_inner(item, rest, path, visitor);
                path.0.pop();
            }
        }
        (Value::Map { entries }, SchemaPathSegment::MapValue) => {
            for entry in entries {
                path.0.push(ValuePathSegment::MapKey(entry.key.clone()));
                visit_claim_matches_inner(&entry.value, rest, path, visitor);
                path.0.pop();
            }
        }
        (Value::Custom { value, .. }, SchemaPathSegment::LogicalValue) => {
            path.0.push(ValuePathSegment::LogicalValue);
            visit_claim_matches_inner(value, rest, path, visitor);
            path.0.pop();
        }
        _ => {}
    }
}

fn visit_claim_matches_mut_inner<F>(
    value: &mut Value,
    segments: &[SchemaPathSegment],
    path: &mut ValuePath,
    visitor: &mut F,
) where
    F: FnMut(&ValuePath, &mut Value),
{
    let Some((segment, rest)) = segments.split_first() else {
        visitor(path, value);
        return;
    };
    match (value, segment) {
        (Value::Record { fields }, SchemaPathSegment::Field(name)) => {
            if let Some(field) = fields.iter_mut().find(|field| field.name == *name) {
                path.0.push(ValuePathSegment::Field(name.clone()));
                visit_claim_matches_mut_inner(&mut field.value, rest, path, visitor);
                path.0.pop();
            }
        }
        (Value::Array { items }, SchemaPathSegment::ArrayElement) => {
            for (index, item) in items.iter_mut().enumerate() {
                path.0.push(ValuePathSegment::ArrayIndex(index));
                visit_claim_matches_mut_inner(item, rest, path, visitor);
                path.0.pop();
            }
        }
        (Value::Map { entries }, SchemaPathSegment::MapValue) => {
            for entry in entries {
                path.0.push(ValuePathSegment::MapKey(entry.key.clone()));
                visit_claim_matches_mut_inner(&mut entry.value, rest, path, visitor);
                path.0.pop();
            }
        }
        (Value::Custom { value, .. }, SchemaPathSegment::LogicalValue) => {
            path.0.push(ValuePathSegment::LogicalValue);
            visit_claim_matches_mut_inner(value, rest, path, visitor);
            path.0.pop();
        }
        _ => {}
    }
}

fn validate_version(kind: &str, actual: u32, expected: u32) -> Result<(), S4Error> {
    if actual != expected {
        return Err(S4Error::new(
            ERROR_VERSION_UNSUPPORTED,
            format!("unsupported {kind} IR version {actual}; expected {expected}"),
        ));
    }
    Ok(())
}

fn serialize_json<T: Serialize>(value: &T) -> Result<Vec<u8>, S4Error> {
    let value = serde_json::to_value(value)
        .map_err(|error| S4Error::new(codes::INTERNAL, format!("JSON encoding failed: {error}")))?;
    serde_json::to_vec(&value)
        .map_err(|error| S4Error::new(codes::INTERNAL, format!("JSON encoding failed: {error}")))
}

fn deserialize_json<T: DeserializeOwned>(value: JsonValue) -> Result<T, S4Error> {
    serde_json::from_value(value)
        .map_err(|error| S4Error::new(codes::DECODE_JSON, error.to_string()))
}

fn parse_canonical_json(encoded: &[u8], kind: &str) -> Result<JsonValue, S4Error> {
    let value: JsonValue = serde_json::from_slice(encoded)
        .map_err(|error| S4Error::new(codes::DECODE_JSON, error.to_string()))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| S4Error::new(codes::INTERNAL, format!("JSON encoding failed: {error}")))?;
    if encoded != canonical {
        return Err(S4Error::new(
            ERROR_NON_CANONICAL,
            format!("{kind} IR JSON is not in canonical form"),
        ));
    }
    Ok(value)
}

fn reject_unit_variant_extras(
    value: &JsonValue,
    unit_variants: &[&str],
    kind: &str,
) -> Result<(), S4Error> {
    match value {
        JsonValue::Array(values) => {
            for value in values {
                reject_unit_variant_extras(value, unit_variants, kind)?;
            }
        }
        JsonValue::Object(object) => {
            if object
                .get("type")
                .and_then(JsonValue::as_str)
                .is_some_and(|tag| unit_variants.contains(&tag))
                && object.len() != 1
            {
                return Err(S4Error::new(
                    codes::DECODE_JSON,
                    format!("{kind} unit variant contains unknown fields"),
                ));
            }
            for value in object.values() {
                reject_unit_variant_extras(value, unit_variants, kind)?;
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
    }
    Ok(())
}

fn ensure_size(kind: &str, actual: usize, limit: usize, code: &'static str) -> Result<(), S4Error> {
    if actual > limit {
        return Err(S4Error::new(
            code,
            format!("{kind} size {actual} exceeds limit {limit}"),
        ));
    }
    Ok(())
}

fn schema_error(path: &SchemaPath, message: impl fmt::Display) -> S4Error {
    S4Error::new(ERROR_SCHEMA_INVALID, format!("schema at {path}: {message}"))
}

fn value_error(path: &ValuePath, message: impl fmt::Display) -> S4Error {
    S4Error::new(ERROR_VALUE_INVALID, format!("value at {path}: {message}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecimalParts {
    precision: u32,
    scale: u32,
}

fn parse_decimal(value: &str) -> Result<DecimalParts, &'static str> {
    let (negative, unsigned) = match value.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, value),
    };
    if unsigned.is_empty() || unsigned.starts_with('+') {
        return Err("expected digits with an optional leading minus sign");
    }

    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() {
        return Err("more than one decimal point");
    }
    if integer.is_empty() || !integer.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("integer part must contain ASCII digits");
    }
    if integer.len() > 1 && integer.starts_with('0') {
        return Err("integer part has a leading zero");
    }

    let fraction = fraction.unwrap_or_default();
    if unsigned.contains('.')
        && (fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("fractional part must contain ASCII digits");
    }
    let scale = u32::try_from(fraction.len()).map_err(|_| "scale is too large")?;

    let all_digits = integer.bytes().chain(fraction.bytes());
    let first_significant = all_digits
        .clone()
        .position(|byte| byte != b'0')
        .unwrap_or_else(|| integer.len() + fraction.len() - 1);
    let precision = u32::try_from(integer.len() + fraction.len() - first_significant)
        .map_err(|_| "precision is too large")?;

    if negative
        && integer
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte == b'0')
    {
        return Err("negative zero is not canonical");
    }
    Ok(DecimalParts { precision, scale })
}

fn validate_date(value: &str) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err("expected YYYY-MM-DD");
    }
    let year = parse_digits(&bytes[0..4]).ok_or("year must contain digits")?;
    let month = parse_digits(&bytes[5..7]).ok_or("month must contain digits")?;
    let day = parse_digits(&bytes[8..10]).ok_or("day must contain digits")?;
    if year == 0 {
        return Err("year zero is not supported");
    }
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return Err("month is out of range"),
    };
    if day == 0 || day > days {
        return Err("day is out of range");
    }
    Ok(())
}

fn validate_time(value: &str) -> Result<(), &'static str> {
    let bytes = value.as_bytes();
    if bytes.len() < 8 || bytes[2] != b':' || bytes[5] != b':' {
        return Err("expected HH:MM:SS with an optional fractional part");
    }
    let hour = parse_digits(&bytes[0..2]).ok_or("hour must contain digits")?;
    let minute = parse_digits(&bytes[3..5]).ok_or("minute must contain digits")?;
    let second = parse_digits(&bytes[6..8]).ok_or("second must contain digits")?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err("time component is out of range");
    }
    if bytes.len() == 8 {
        return Ok(());
    }
    if bytes[8] != b'.' {
        return Err("fractional seconds must start with a decimal point");
    }
    let fraction = &bytes[9..];
    if fraction.is_empty() || fraction.len() > 9 || !fraction.iter().all(u8::is_ascii_digit) {
        return Err("fractional seconds must contain one to nine digits");
    }
    if fraction.last() == Some(&b'0') {
        return Err("fractional seconds must not have trailing zeros");
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), &'static str> {
    let Some(without_zone) = value.strip_suffix('Z') else {
        return Err("expected a UTC timestamp ending in Z");
    };
    let Some((date, time)) = without_zone.split_once('T') else {
        return Err("expected date and time separated by T");
    };
    if time.contains('T') {
        return Err("timestamp contains more than one T separator");
    }
    validate_date(date)?;
    validate_time(time)
}

fn validate_uuid(value: &str) -> Result<(), &'static str> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| "expected a UUID")?;
    if parsed.hyphenated().to_string() != value {
        return Err("expected lowercase hyphenated canonical form");
    }
    Ok(())
}

fn parse_digits(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

mod base64_value {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        BASE64_STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

mod canonical_i64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let value = encoded.parse::<i64>().map_err(serde::de::Error::custom)?;
        if value.to_string() != encoded {
            return Err(serde::de::Error::custom(
                "expected a canonical i64 decimal string",
            ));
        }
        Ok(value)
    }
}

mod canonical_f32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &f32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&canonical(*value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let value = match encoded.as_str() {
            "NaN" => f32::NAN,
            "Infinity" => f32::INFINITY,
            "-Infinity" => f32::NEG_INFINITY,
            _ => encoded.parse::<f32>().map_err(serde::de::Error::custom)?,
        };
        if canonical(value) != encoded {
            return Err(serde::de::Error::custom(
                "expected a canonical IEEE f32 string",
            ));
        }
        Ok(value)
    }

    fn canonical(value: f32) -> String {
        if value.is_nan() {
            "NaN".to_string()
        } else if value == f32::INFINITY {
            "Infinity".to_string()
        } else if value == f32::NEG_INFINITY {
            "-Infinity".to_string()
        } else if value == 0.0 {
            "0".to_string()
        } else {
            value.to_string()
        }
    }
}

mod canonical_f64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &f64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&canonical(*value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let value = match encoded.as_str() {
            "NaN" => f64::NAN,
            "Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            _ => encoded.parse::<f64>().map_err(serde::de::Error::custom)?,
        };
        if canonical(value) != encoded {
            return Err(serde::de::Error::custom(
                "expected a canonical IEEE f64 string",
            ));
        }
        Ok(value)
    }

    fn canonical(value: f64) -> String {
        if value.is_nan() {
            "NaN".to_string()
        } else if value == f64::INFINITY {
            "Infinity".to_string()
        } else if value == f64::NEG_INFINITY {
            "-Infinity".to_string()
        } else if value == 0.0 {
            "0".to_string()
        } else {
            value.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SCHEMA_V1_GOLDEN: &[u8] = br#"{"root":{"kind":{"fields":[{"name":"id","schema":{"kind":{"type":"i64"},"nullable":false}},{"name":"payload","schema":{"kind":{"type":"bytes"},"nullable":false}},{"name":"tags","schema":{"kind":{"items":{"kind":{"type":"string"},"nullable":false},"type":"array"},"nullable":true}}],"type":"record"},"nullable":false},"version":1}"#;
    const VALUE_V1_GOLDEN: &[u8] = br#"{"root":{"fields":[{"name":"id","value":{"type":"i64","value":"42"}},{"name":"payload","value":{"type":"bytes","value":"AAEC/w=="}},{"name":"tags","value":{"items":[{"type":"string","value":"canonical"}],"type":"array"}}],"type":"record"},"version":1}"#;

    fn required(kind: SchemaKind) -> SchemaNode {
        SchemaNode::required(kind)
    }

    fn field(name: &str, kind: SchemaKind) -> SchemaField {
        SchemaField {
            name: name.to_string(),
            schema: required(kind),
        }
    }

    fn value_field(name: &str, value: Value) -> ValueField {
        ValueField {
            name: name.to_string(),
            value,
        }
    }

    fn record_schema() -> SchemaIr {
        SchemaIr::new(required(SchemaKind::Record {
            fields: vec![
                field("id", SchemaKind::I64),
                field("payload", SchemaKind::Bytes),
                SchemaField {
                    name: "tags".to_string(),
                    schema: SchemaNode::nullable(SchemaKind::Array {
                        items: Box::new(required(SchemaKind::String)),
                    }),
                },
            ],
        }))
    }

    fn record_value() -> ValueIr {
        ValueIr::new(Value::Record {
            fields: vec![
                value_field("id", Value::I64 { value: 42 }),
                value_field(
                    "payload",
                    Value::Bytes {
                        value: vec![0, 1, 2, 255],
                    },
                ),
                value_field(
                    "tags",
                    Value::Array {
                        items: vec![Value::String {
                            value: "canonical".to_string(),
                        }],
                    },
                ),
            ],
        })
    }

    #[test]
    fn canonical_schema_and_value_roundtrip() {
        let limits = BinaryIrLimits::default();
        let schema = record_schema();
        let encoded_schema = schema.to_canonical_json(limits).unwrap();
        assert_eq!(encoded_schema, SCHEMA_V1_GOLDEN);
        assert_eq!(
            SchemaIr::from_canonical_json(SCHEMA_V1_GOLDEN, limits).unwrap(),
            schema
        );

        let value = record_value();
        let encoded_value = value.to_canonical_json(&schema, limits).unwrap();
        assert_eq!(encoded_value, VALUE_V1_GOLDEN);
        assert_eq!(
            ValueIr::from_canonical_json(VALUE_V1_GOLDEN, &schema, limits).unwrap(),
            value
        );
        assert_eq!(
            value.to_canonical_json(&schema, limits).unwrap(),
            encoded_value
        );
    }

    #[test]
    fn decoding_rejects_noncanonical_and_unknown_json() {
        let limits = BinaryIrLimits::default();
        let schema = SchemaIr::new(required(SchemaKind::Boolean));
        let pretty = serde_json::to_string_pretty(&schema).unwrap();
        let error = SchemaIr::from_canonical_json(pretty.as_bytes(), limits).unwrap_err();
        assert_eq!(error.code(), ERROR_NON_CANONICAL);

        let unknown =
            br#"{"extra":true,"root":{"kind":{"type":"boolean"},"nullable":false},"version":1}"#;
        let error = SchemaIr::from_canonical_json(unknown, limits).unwrap_err();
        assert_eq!(error.code(), codes::DECODE_JSON);

        let unsorted = br#"{"version":1,"root":{"kind":{"type":"boolean"},"nullable":false}}"#;
        let error = SchemaIr::from_canonical_json(unsorted, limits).unwrap_err();
        assert_eq!(error.code(), ERROR_NON_CANONICAL);

        let with_bom = b"\xef\xbb\xbf{\"root\":{\"kind\":{\"type\":\"boolean\"},\"nullable\":false},\"version\":1}";
        let error = SchemaIr::from_canonical_json(with_bom, limits).unwrap_err();
        assert_eq!(error.code(), codes::DECODE_JSON);
    }

    #[test]
    fn internally_tagged_unit_variants_reject_unknown_fields() {
        let schema_unit_extra =
            br#"{"root":{"kind":{"extra":true,"type":"boolean"},"nullable":false},"version":1}"#;
        let error = SchemaIr::from_canonical_json(schema_unit_extra, BinaryIrLimits::default())
            .unwrap_err();
        assert_eq!(error.code(), codes::DECODE_JSON);

        let null_schema = SchemaIr::new(SchemaNode::nullable(SchemaKind::String));
        let value_unit_extra = br#"{"root":{"extra":true,"type":"null"},"version":1}"#;
        let error =
            ValueIr::from_canonical_json(value_unit_extra, &null_schema, BinaryIrLimits::default())
                .unwrap_err();
        assert_eq!(error.code(), codes::DECODE_JSON);
    }

    #[test]
    fn schema_limits_cover_encoded_size_fields_and_depth() {
        let schema = record_schema();
        let encoded = schema.to_canonical_json(BinaryIrLimits::default()).unwrap();
        let size_limited = BinaryIrLimits {
            max_encoded_schema_bytes: encoded.len() - 1,
            ..BinaryIrLimits::default()
        };
        assert_eq!(
            schema.to_canonical_json(size_limited).unwrap_err().code(),
            codes::LIMIT_INPUT_BYTES
        );
        assert_eq!(
            SchemaIr::from_canonical_json(&encoded, size_limited)
                .unwrap_err()
                .code(),
            codes::LIMIT_INPUT_BYTES
        );

        let fields = SchemaIr::new(required(SchemaKind::Record {
            fields: vec![field("a", SchemaKind::I32), field("b", SchemaKind::I32)],
        }));
        let one_field = BinaryIrLimits {
            max_fields: 1,
            ..BinaryIrLimits::default()
        };
        assert_eq!(
            fields.validate(one_field).unwrap_err().code(),
            ERROR_SCHEMA_INVALID
        );

        let mut nested = required(SchemaKind::String);
        for _ in 0..=DEFAULT_MAX_NESTING_DEPTH {
            nested = required(SchemaKind::Array {
                items: Box::new(nested),
            });
        }
        assert_eq!(
            SchemaIr::new(nested)
                .validate(BinaryIrLimits::default())
                .unwrap_err()
                .code(),
            ERROR_SCHEMA_INVALID
        );
    }

    #[test]
    fn value_encoded_size_is_bounded_before_and_after_decode() {
        let schema = SchemaIr::new(required(SchemaKind::String));
        let value = ValueIr::new(Value::String {
            value: "longer than the configured limit".to_string(),
        });
        let encoded = value
            .to_canonical_json(&schema, BinaryIrLimits::default())
            .unwrap();
        let limits = BinaryIrLimits {
            max_encoded_value_bytes: encoded.len() - 1,
            ..BinaryIrLimits::default()
        };
        assert_eq!(
            value.to_canonical_json(&schema, limits).unwrap_err().code(),
            codes::RECORD_TOO_LARGE
        );
        assert_eq!(
            ValueIr::from_canonical_json(&encoded, &schema, limits)
                .unwrap_err()
                .code(),
            codes::RECORD_TOO_LARGE
        );
    }

    #[test]
    fn duplicate_schema_and_value_fields_are_rejected() {
        let schema = SchemaIr::new(required(SchemaKind::Record {
            fields: vec![
                field("same", SchemaKind::I32),
                field("same", SchemaKind::I32),
            ],
        }));
        let error = schema.validate(BinaryIrLimits::default()).unwrap_err();
        assert_eq!(error.code(), ERROR_SCHEMA_INVALID);
        assert!(error.message().contains("duplicate field"));

        let valid_schema = SchemaIr::new(required(SchemaKind::Record {
            fields: vec![field("same", SchemaKind::I32)],
        }));
        let value = ValueIr::new(Value::Record {
            fields: vec![
                value_field("same", Value::I32 { value: 1 }),
                value_field("same", Value::I32 { value: 2 }),
            ],
        });
        let error = value
            .validate(&valid_schema, BinaryIrLimits::default())
            .unwrap_err();
        assert_eq!(error.code(), ERROR_VALUE_INVALID);
        assert!(error.message().contains("duplicate record field"));
    }

    #[test]
    fn nested_custom_type_paths_select_and_mutate_all_claimed_values() {
        let custom = required(SchemaKind::Custom {
            type_id: "vendor.money".to_string(),
            value: Box::new(required(SchemaKind::String)),
        });
        let schema = SchemaIr::new(required(SchemaKind::Record {
            fields: vec![SchemaField {
                name: "items".to_string(),
                schema: required(SchemaKind::Array {
                    items: Box::new(custom),
                }),
            }],
        }));
        schema.validate(BinaryIrLimits::default()).unwrap();

        let claim = SchemaPath(vec![
            SchemaPathSegment::Field("items".to_string()),
            SchemaPathSegment::ArrayElement,
        ]);
        assert!(matches!(
            schema.node_at_path(&claim).map(|node| &node.kind),
            Some(SchemaKind::Custom { type_id, .. }) if type_id == "vendor.money"
        ));
        assert!(schema.reductor_claim_paths().contains(&claim));

        let mut value = ValueIr::new(Value::Record {
            fields: vec![value_field(
                "items",
                Value::Array {
                    items: vec![
                        Value::Custom {
                            type_id: "vendor.money".to_string(),
                            value: Box::new(Value::String {
                                value: "one".to_string(),
                            }),
                        },
                        Value::Custom {
                            type_id: "vendor.money".to_string(),
                            value: Box::new(Value::String {
                                value: "two".to_string(),
                            }),
                        },
                    ],
                },
            )],
        });
        value.validate(&schema, BinaryIrLimits::default()).unwrap();

        let mut paths = Vec::new();
        value.root.visit_claim_matches_mut(&claim, |path, claimed| {
            paths.push(path.clone());
            let Value::Custom { value, .. } = claimed else {
                panic!("claim should select custom values");
            };
            let Value::String { value } = value.as_mut() else {
                panic!("custom value should contain a string");
            };
            value.make_ascii_uppercase();
        });
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].to_string(), "$.items[0]");
        value.validate(&schema, BinaryIrLimits::default()).unwrap();
    }

    #[test]
    fn decimal_schema_and_values_are_validated() {
        let schema = SchemaIr::new(required(SchemaKind::Decimal {
            precision: 5,
            scale: 2,
        }));
        ValueIr::new(Value::Decimal {
            value: "123.45".to_string(),
        })
        .validate(&schema, BinaryIrLimits::default())
        .unwrap();

        for invalid in ["1234.56", "123.4", "01.20", "-0.00", "1e2"] {
            assert!(
                ValueIr::new(Value::Decimal {
                    value: invalid.to_string()
                })
                .validate(&schema, BinaryIrLimits::default())
                .is_err(),
                "{invalid} should be rejected"
            );
        }

        let invalid_schema = SchemaIr::new(required(SchemaKind::Decimal {
            precision: 2,
            scale: 3,
        }));
        assert!(invalid_schema.validate(BinaryIrLimits::default()).is_err());

        let integer_boundary = SchemaIr::new(required(SchemaKind::Decimal {
            precision: 1,
            scale: 0,
        }));
        for valid in ["0", "9", "-9"] {
            ValueIr::new(Value::Decimal {
                value: valid.to_string(),
            })
            .validate(&integer_boundary, BinaryIrLimits::default())
            .unwrap();
        }
        for invalid in ["10", "-10"] {
            assert!(
                ValueIr::new(Value::Decimal {
                    value: invalid.to_string(),
                })
                .validate(&integer_boundary, BinaryIrLimits::default())
                .is_err()
            );
        }

        let scale_boundary = SchemaIr::new(required(SchemaKind::Decimal {
            precision: 5,
            scale: 5,
        }));
        for valid in ["0.00000", "0.00001", "0.99999", "-0.00001"] {
            ValueIr::new(Value::Decimal {
                value: valid.to_string(),
            })
            .validate(&scale_boundary, BinaryIrLimits::default())
            .unwrap();
        }
        for invalid in ["1.00000", "0.000001", "-0.00000"] {
            assert!(
                ValueIr::new(Value::Decimal {
                    value: invalid.to_string(),
                })
                .validate(&scale_boundary, BinaryIrLimits::default())
                .is_err()
            );
        }

        let maximum_schema_numbers = SchemaIr::new(required(SchemaKind::Decimal {
            precision: u32::MAX,
            scale: u32::MAX,
        }));
        maximum_schema_numbers
            .validate(BinaryIrLimits::default())
            .unwrap();
        let zero_precision = SchemaIr::new(required(SchemaKind::Decimal {
            precision: 0,
            scale: 0,
        }));
        assert!(zero_precision.validate(BinaryIrLimits::default()).is_err());
    }

    #[test]
    fn bytes_use_canonical_base64_and_invalid_base64_is_rejected() {
        let schema = SchemaIr::new(required(SchemaKind::Bytes));
        let value = ValueIr::new(Value::Bytes {
            value: vec![0xfb, 0xff],
        });
        let encoded = value
            .to_canonical_json(&schema, BinaryIrLimits::default())
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            r#"{"root":{"type":"bytes","value":"+/8="},"version":1}"#
        );

        let invalid = br#"{"root":{"type":"bytes","value":"-_8"},"version":1}"#;
        let error =
            ValueIr::from_canonical_json(invalid, &schema, BinaryIrLimits::default()).unwrap_err();
        assert_eq!(error.code(), codes::DECODE_JSON);
    }

    #[test]
    fn i64_uses_canonical_decimal_strings_on_wire() {
        let schema = SchemaIr::new(required(SchemaKind::I64));
        for value in [i64::MIN, -1, 0, 1, i64::MAX] {
            let ir = ValueIr::new(Value::I64 { value });
            let encoded = ir
                .to_canonical_json(&schema, BinaryIrLimits::default())
                .unwrap();
            assert_eq!(
                encoded,
                format!(r#"{{"root":{{"type":"i64","value":"{value}"}},"version":1}}"#).as_bytes()
            );
            assert_eq!(
                ValueIr::from_canonical_json(&encoded, &schema, BinaryIrLimits::default(),)
                    .unwrap(),
                ir
            );
        }

        for invalid in [
            br#"{"root":{"type":"i64","value":1},"version":1}"#.as_slice(),
            br#"{"root":{"type":"i64","value":"01"},"version":1}"#.as_slice(),
            br#"{"root":{"type":"i64","value":"-0"},"version":1}"#.as_slice(),
        ] {
            assert_eq!(
                ValueIr::from_canonical_json(invalid, &schema, BinaryIrLimits::default(),)
                    .unwrap_err()
                    .code(),
                codes::DECODE_JSON
            );
        }
    }

    #[test]
    fn ieee_float_strings_cover_special_values_and_signed_zero() {
        let f64_schema = SchemaIr::new(required(SchemaKind::F64));
        for (value, token) in [
            (f64::NAN, "NaN"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
            (-0.0, "0"),
            (0.0, "0"),
            (1.5, "1.5"),
        ] {
            let encoded = ValueIr::new(Value::F64 { value })
                .to_canonical_json(&f64_schema, BinaryIrLimits::default())
                .unwrap();
            assert_eq!(
                encoded,
                format!(r#"{{"root":{{"type":"f64","value":"{token}"}},"version":1}}"#).as_bytes()
            );
            let decoded =
                ValueIr::from_canonical_json(&encoded, &f64_schema, BinaryIrLimits::default())
                    .unwrap();
            let Value::F64 { value: decoded } = decoded.root else {
                panic!("expected f64");
            };
            if value.is_nan() {
                assert!(decoded.is_nan());
            } else if value == 0.0 {
                assert_eq!(decoded.to_bits(), 0.0_f64.to_bits());
            } else {
                assert_eq!(decoded.to_bits(), value.to_bits());
            }
        }

        let f32_schema = SchemaIr::new(required(SchemaKind::F32));
        for (value, token) in [
            (f32::NAN, "NaN"),
            (f32::INFINITY, "Infinity"),
            (f32::NEG_INFINITY, "-Infinity"),
            (-0.0, "0"),
            (1.25, "1.25"),
        ] {
            let encoded = ValueIr::new(Value::F32 { value })
                .to_canonical_json(&f32_schema, BinaryIrLimits::default())
                .unwrap();
            assert!(
                std::str::from_utf8(&encoded)
                    .unwrap()
                    .contains(&format!(r#""value":"{token}""#))
            );
            let decoded =
                ValueIr::from_canonical_json(&encoded, &f32_schema, BinaryIrLimits::default())
                    .unwrap();
            let Value::F32 { value: decoded } = decoded.root else {
                panic!("expected f32");
            };
            if value.is_nan() {
                assert!(decoded.is_nan());
            } else if value == 0.0 {
                assert_eq!(decoded.to_bits(), 0.0_f32.to_bits());
            } else {
                assert_eq!(decoded.to_bits(), value.to_bits());
            }
        }

        for invalid in ["nan", "+Infinity", "-0", "1.0"] {
            let encoded = format!(r#"{{"root":{{"type":"f64","value":"{invalid}"}},"version":1}}"#);
            assert_eq!(
                ValueIr::from_canonical_json(
                    encoded.as_bytes(),
                    &f64_schema,
                    BinaryIrLimits::default(),
                )
                .unwrap_err()
                .code(),
                codes::DECODE_JSON
            );
        }
    }

    #[test]
    fn date_and_timestamp_year_range_is_0001_through_9999() {
        let date_schema = SchemaIr::new(required(SchemaKind::Date));
        for value in ["0001-01-01", "9999-12-31"] {
            ValueIr::new(Value::Date {
                value: value.to_string(),
            })
            .validate(&date_schema, BinaryIrLimits::default())
            .unwrap();
        }
        for value in ["0000-01-01", "10000-01-01"] {
            assert!(
                ValueIr::new(Value::Date {
                    value: value.to_string(),
                })
                .validate(&date_schema, BinaryIrLimits::default())
                .is_err()
            );
        }

        let timestamp_schema = SchemaIr::new(required(SchemaKind::Timestamp));
        for value in ["0001-01-01T00:00:00Z", "9999-12-31T23:59:59.1Z"] {
            ValueIr::new(Value::Timestamp {
                value: value.to_string(),
            })
            .validate(&timestamp_schema, BinaryIrLimits::default())
            .unwrap();
        }
        for value in ["0000-01-01T00:00:00Z", "10000-01-01T00:00:00Z"] {
            assert!(
                ValueIr::new(Value::Timestamp {
                    value: value.to_string(),
                })
                .validate(&timestamp_schema, BinaryIrLimits::default())
                .is_err()
            );
        }
    }

    #[test]
    fn value_validation_covers_nullability_order_maps_logicals_and_floats() {
        let required_string = SchemaIr::new(required(SchemaKind::String));
        assert!(
            ValueIr::new(Value::Null)
                .validate(&required_string, BinaryIrLimits::default())
                .is_err()
        );
        let nullable_string = SchemaIr::new(SchemaNode::nullable(SchemaKind::String));
        ValueIr::new(Value::Null)
            .validate(&nullable_string, BinaryIrLimits::default())
            .unwrap();

        let record = SchemaIr::new(required(SchemaKind::Record {
            fields: vec![field("a", SchemaKind::I32), field("b", SchemaKind::I32)],
        }));
        let out_of_order = ValueIr::new(Value::Record {
            fields: vec![
                value_field("b", Value::I32 { value: 1 }),
                value_field("a", Value::I32 { value: 2 }),
            ],
        });
        assert!(
            out_of_order
                .validate(&record, BinaryIrLimits::default())
                .is_err()
        );

        let map_schema = SchemaIr::new(required(SchemaKind::Map {
            values: Box::new(required(SchemaKind::Boolean)),
        }));
        let unsorted = ValueIr::new(Value::Map {
            entries: vec![
                MapEntry {
                    key: "z".to_string(),
                    value: Value::Boolean { value: true },
                },
                MapEntry {
                    key: "a".to_string(),
                    value: Value::Boolean { value: false },
                },
            ],
        });
        assert!(
            unsorted
                .validate(&map_schema, BinaryIrLimits::default())
                .is_err()
        );
        let empty_map_key = ValueIr::new(Value::Map {
            entries: vec![
                MapEntry {
                    key: String::new(),
                    value: Value::Boolean { value: true },
                },
                MapEntry {
                    key: "a".to_string(),
                    value: Value::Boolean { value: false },
                },
            ],
        });
        let encoded = empty_map_key
            .to_canonical_json(&map_schema, BinaryIrLimits::default())
            .unwrap();
        assert_eq!(
            ValueIr::from_canonical_json(&encoded, &map_schema, BinaryIrLimits::default(),)
                .unwrap(),
            empty_map_key
        );

        let timestamp = SchemaIr::new(required(SchemaKind::Timestamp));
        ValueIr::new(Value::Timestamp {
            value: "2024-02-29T23:59:59.123Z".to_string(),
        })
        .validate(&timestamp, BinaryIrLimits::default())
        .unwrap();
        assert!(
            ValueIr::new(Value::Timestamp {
                value: "2023-02-29T00:00:00Z".to_string()
            })
            .validate(&timestamp, BinaryIrLimits::default())
            .is_err()
        );
    }

    #[test]
    fn unsupported_versions_and_recursive_reference_forms_are_rejected() {
        let schema = SchemaIr {
            version: SCHEMA_IR_VERSION + 1,
            root: required(SchemaKind::Boolean),
        };
        assert_eq!(
            schema
                .validate(BinaryIrLimits::default())
                .unwrap_err()
                .code(),
            ERROR_VERSION_UNSUPPORTED
        );

        let reference =
            br#"{"root":{"kind":{"name":"Node","type":"reference"},"nullable":false},"version":1}"#;
        let error =
            SchemaIr::from_canonical_json(reference, BinaryIrLimits::default()).unwrap_err();
        assert_eq!(error.code(), codes::DECODE_JSON);
    }

    proptest! {
        #[test]
        fn canonical_record_roundtrip_is_stable(
            integer in any::<i64>(),
            text in any::<String>(),
            bytes in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let schema = record_schema();
            let value = ValueIr::new(Value::Record {
                fields: vec![
                    value_field("id", Value::I64 { value: integer }),
                    value_field("payload", Value::Bytes { value: bytes }),
                    value_field("tags", Value::Array {
                        items: vec![Value::String { value: text }],
                    }),
                ],
            });
            let limits = BinaryIrLimits::default();
            let encoded = value.to_canonical_json(&schema, limits).unwrap();
            let decoded = ValueIr::from_canonical_json(&encoded, &schema, limits).unwrap();
            prop_assert_eq!(&decoded, &value);
            prop_assert_eq!(decoded.to_canonical_json(&schema, limits).unwrap(), encoded);
        }

        #[test]
        fn finite_float_roundtrip_is_stable(bits in any::<u64>()) {
            let float = f64::from_bits(bits);
            prop_assume!(float.is_finite());
            let schema = SchemaIr::new(required(SchemaKind::F64));
            let value = ValueIr::new(Value::F64 { value: float });
            let limits = BinaryIrLimits::default();
            let encoded = value.to_canonical_json(&schema, limits).unwrap();
            let decoded = ValueIr::from_canonical_json(&encoded, &schema, limits).unwrap();
            prop_assert_eq!(decoded, value);
        }
    }
}
