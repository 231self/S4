//! Avro Object Container File conversion at the binary-codec boundary.
//!
//! This module intentionally has no HTTP or storage dependency. Callers stream
//! decoded values through the typed binary pump and only commit encoded output
//! after the pump succeeds.

use std::collections::BTreeMap;
use std::io::{self, Read};

use apache_avro::{Codec, Reader, Schema, Writer, types::Value as AvroValue};
use chrono::{DateTime, Duration, NaiveDate, NaiveTime, SecondsFormat, Timelike, Utc};
use num_bigint::{BigInt, Sign};
use s4_error::{S4Error, codes};
use serde_json::{Value as JsonValue, json};

use crate::binary_ir::{
    BinaryIrLimits, MapEntry, SchemaField, SchemaIr, SchemaKind, SchemaNode, Value, ValueField,
    ValueIr,
};
use crate::binary_pump::{BinaryPump, BinaryTransform};
use crate::binary_reductor::BinaryReductor;

pub const DEFAULT_MAX_AVRO_SOURCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct AvroLimits {
    pub max_source_bytes: usize,
    pub ir: BinaryIrLimits,
}

impl Default for AvroLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_AVRO_SOURCE_BYTES,
            ir: BinaryIrLimits::default(),
        }
    }
}

/// Decodes one OCF source and invokes `emit` once per logical record.
///
/// The source reader is capped before the Avro library sees bytes; each emitted
/// value is separately validated against the bounded Maskura IR schema.
pub fn decode_ocf<R, F>(source: R, limits: AvroLimits, mut emit: F) -> Result<SchemaIr, S4Error>
where
    R: Read,
    F: FnMut(ValueIr) -> Result<(), S4Error>,
{
    validate_limits(limits)?;
    let mut reader =
        Reader::new(LimitedReader::new(source, limits.max_source_bytes)).map_err(avro_error)?;
    let schema = schema_from_avro(reader.writer_schema(), limits.ir)?;
    for value in &mut reader {
        let value = avro_value_to_ir(value.map_err(avro_error)?, &schema.root)?;
        let value = ValueIr::new(value);
        value.validate(&schema, limits.ir)?;
        emit(value)?;
    }
    Ok(schema)
}

/// Encodes validated IR records to an Avro OCF using Zstandard output blocks.
pub fn encode_ocf(
    schema: &SchemaIr,
    values: &[ValueIr],
    limits: AvroLimits,
) -> Result<Vec<u8>, S4Error> {
    validate_limits(limits)?;
    schema.validate(limits.ir)?;
    let avro_schema = Schema::parse(&schema_to_avro_json(&schema.root)?).map_err(avro_error)?;
    let mut writer = Writer::with_codec(
        &avro_schema,
        Vec::new(),
        Codec::Zstandard(Default::default()),
    )
    .map_err(avro_error)?;
    for value in values {
        value.validate(schema, limits.ir)?;
        writer
            .append_value(ir_value_to_avro(&value.root, &schema.root)?)
            .map_err(avro_error)?;
    }
    writer.into_inner().map_err(avro_error)
}

/// Runs an OCF source through a planned typed binary transform and emits a new
/// OCF only after every accepted value has passed schema validation.
pub fn process_ocf<R, Reductor, Transform>(
    source: R,
    limits: AvroLimits,
    pump: &mut BinaryPump<Reductor, Transform>,
) -> Result<Vec<u8>, S4Error>
where
    R: Read,
    Reductor: BinaryReductor,
    Transform: BinaryTransform,
{
    validate_limits(limits)?;
    let mut reader =
        Reader::new(LimitedReader::new(source, limits.max_source_bytes)).map_err(avro_error)?;
    let input_schema = schema_from_avro(reader.writer_schema(), limits.ir)?;
    let output_schema = pump.plan(&input_schema)?.clone();
    let output_avro_schema =
        Schema::parse(&schema_to_avro_json(&output_schema.root)?).map_err(avro_error)?;
    let mut writer = Writer::with_codec(
        &output_avro_schema,
        Vec::new(),
        Codec::Zstandard(Default::default()),
    )
    .map_err(avro_error)?;

    for value in &mut reader {
        let value = ValueIr::new(avro_value_to_ir(
            value.map_err(avro_error)?,
            &input_schema.root,
        )?);
        value.validate(&input_schema, limits.ir)?;
        let Some(value) = pump.process(value)? else {
            continue;
        };
        value.validate(&output_schema, limits.ir)?;
        writer
            .append_value(ir_value_to_avro(&value.root, &output_schema.root)?)
            .map_err(avro_error)?;
    }
    writer.into_inner().map_err(avro_error)
}

pub fn schema_from_avro(schema: &Schema, limits: BinaryIrLimits) -> Result<SchemaIr, S4Error> {
    let raw = serde_json::to_value(schema).map_err(avro_error)?;
    let schema = SchemaIr::new(schema_node_from_json(&raw)?);
    schema.validate(limits)?;
    Ok(schema)
}

fn schema_node_from_json(raw: &JsonValue) -> Result<SchemaNode, S4Error> {
    if let Some(kind) = raw.as_str() {
        return primitive_schema(kind);
    }
    if let Some(variants) = raw.as_array() {
        if variants.len() != 2 {
            return Err(unsupported(
                "Avro unions must contain exactly null and one type",
            ));
        }
        let non_null = variants
            .iter()
            .find(|variant| !variant.is_string() || variant.as_str() != Some("null"))
            .ok_or_else(|| unsupported("Avro nullable union is missing its value type"))?;
        if !variants
            .iter()
            .any(|variant| variant.as_str() == Some("null"))
        {
            return Err(unsupported("Avro unions must contain null"));
        }
        let mut node = schema_node_from_json(non_null)?;
        if matches!(node.kind, SchemaKind::Null) {
            return Err(unsupported("Avro union cannot contain null twice"));
        }
        node.nullable = true;
        return Ok(node);
    }

    let object = raw
        .as_object()
        .ok_or_else(|| unsupported("Avro schema must be a string, object, or nullable union"))?;
    let kind = object
        .get("type")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| unsupported("Avro schema type is missing"))?;
    if let Some(logical_type) = object.get("logicalType").and_then(JsonValue::as_str) {
        return match (kind, logical_type) {
            ("int", "date") => Ok(SchemaNode::required(SchemaKind::Date)),
            ("int", "time-millis") | ("long", "time-micros") => {
                Ok(SchemaNode::required(SchemaKind::Time))
            }
            ("long", "timestamp-millis")
            | ("long", "timestamp-micros")
            | ("long", "timestamp-nanos") => Ok(SchemaNode::required(SchemaKind::Timestamp)),
            ("string", "uuid") => Ok(SchemaNode::required(SchemaKind::Uuid)),
            ("bytes", "decimal") => {
                let precision = object
                    .get("precision")
                    .and_then(JsonValue::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| unsupported("Avro decimal precision is missing"))?;
                let scale = object
                    .get("scale")
                    .and_then(JsonValue::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or(0);
                Ok(SchemaNode::required(SchemaKind::Decimal {
                    precision,
                    scale,
                }))
            }
            _ => Err(unsupported(format!(
                "unsupported Avro logical type {logical_type:?} for {kind:?}"
            ))),
        };
    }
    match kind {
        "record" => {
            let fields = object
                .get("fields")
                .and_then(JsonValue::as_array)
                .ok_or_else(|| unsupported("Avro record fields are missing"))?
                .iter()
                .map(|field| {
                    let field = field
                        .as_object()
                        .ok_or_else(|| unsupported("Avro record field must be an object"))?;
                    let name = field
                        .get("name")
                        .and_then(JsonValue::as_str)
                        .filter(|name| !name.is_empty())
                        .ok_or_else(|| unsupported("Avro record field name is missing"))?;
                    let kind = field
                        .get("type")
                        .ok_or_else(|| unsupported("Avro record field type is missing"))?;
                    Ok(SchemaField {
                        name: name.to_string(),
                        schema: schema_node_from_json(kind)?,
                    })
                })
                .collect::<Result<Vec<_>, S4Error>>()?;
            Ok(SchemaNode::required(SchemaKind::Record { fields }))
        }
        "array" => Ok(SchemaNode::required(SchemaKind::Array {
            items: Box::new(schema_node_from_json(
                object
                    .get("items")
                    .ok_or_else(|| unsupported("Avro array items are missing"))?,
            )?),
        })),
        "map" => Ok(SchemaNode::required(SchemaKind::Map {
            values: Box::new(schema_node_from_json(
                object
                    .get("values")
                    .ok_or_else(|| unsupported("Avro map values are missing"))?,
            )?),
        })),
        "enum" | "fixed" | "duration" => Err(unsupported(format!(
            "Avro {kind} schemas are not supported"
        ))),
        primitive => primitive_schema(primitive),
    }
}

fn primitive_schema(kind: &str) -> Result<SchemaNode, S4Error> {
    let kind = match kind {
        "null" => SchemaKind::Null,
        "boolean" => SchemaKind::Boolean,
        "int" => SchemaKind::I32,
        "long" => SchemaKind::I64,
        "float" => SchemaKind::F32,
        "double" => SchemaKind::F64,
        "bytes" => SchemaKind::Bytes,
        "string" => SchemaKind::String,
        other => {
            return Err(unsupported(format!(
                "unsupported Avro schema type {other:?}"
            )));
        }
    };
    Ok(SchemaNode::required(kind))
}

fn schema_to_avro_json(root: &SchemaNode) -> Result<JsonValue, S4Error> {
    let mut records = 0_u32;
    schema_node_to_json(root, &mut records)
}

fn schema_node_to_json(node: &SchemaNode, records: &mut u32) -> Result<JsonValue, S4Error> {
    let raw = match &node.kind {
        SchemaKind::Null => json!("null"),
        SchemaKind::Boolean => json!("boolean"),
        SchemaKind::I32 => json!("int"),
        SchemaKind::I64 => json!("long"),
        SchemaKind::F32 => json!("float"),
        SchemaKind::F64 => json!("double"),
        SchemaKind::String => json!("string"),
        SchemaKind::Bytes => json!("bytes"),
        SchemaKind::Array { items } => {
            json!({"type":"array","items":schema_node_to_json(items, records)?})
        }
        SchemaKind::Map { values } => {
            json!({"type":"map","values":schema_node_to_json(values, records)?})
        }
        SchemaKind::Record { fields } => {
            let name = format!("maskura_record_{records}");
            *records = records.saturating_add(1);
            let fields = fields
                .iter()
                .map(|field| Ok(json!({"name":field.name,"type":schema_node_to_json(&field.schema, records)?})))
                .collect::<Result<Vec<_>, S4Error>>()?;
            json!({"type":"record","name":name,"fields":fields})
        }
        SchemaKind::Date => json!({"type":"int","logicalType":"date"}),
        SchemaKind::Time => json!({"type":"long","logicalType":"time-micros"}),
        SchemaKind::Timestamp => json!({"type":"long","logicalType":"timestamp-micros"}),
        SchemaKind::Uuid => json!({"type":"string","logicalType":"uuid"}),
        SchemaKind::Decimal { precision, scale } => json!({
            "type":"bytes",
            "logicalType":"decimal",
            "precision":precision,
            "scale":scale,
        }),
        SchemaKind::Custom { .. } => {
            return Err(unsupported(
                "custom IR types need a binary reductor before Avro encoding",
            ));
        }
    };
    Ok(if node.nullable {
        json!(["null", raw])
    } else {
        raw
    })
}

fn avro_value_to_ir(value: AvroValue, schema: &SchemaNode) -> Result<Value, S4Error> {
    let value = match value {
        AvroValue::Union(_, value) => *value,
        value => value,
    };
    if schema.nullable && matches!(value, AvroValue::Null) {
        return Ok(Value::Null);
    }
    match (&schema.kind, value) {
        (SchemaKind::Null, AvroValue::Null) => Ok(Value::Null),
        (SchemaKind::Boolean, AvroValue::Boolean(value)) => Ok(Value::Boolean { value }),
        (SchemaKind::I32, AvroValue::Int(value)) => Ok(Value::I32 { value }),
        (SchemaKind::I64, AvroValue::Long(value)) => Ok(Value::I64 { value }),
        (SchemaKind::F32, AvroValue::Float(value)) => Ok(Value::F32 { value }),
        (SchemaKind::F64, AvroValue::Double(value)) => Ok(Value::F64 { value }),
        (SchemaKind::String, AvroValue::String(value)) => Ok(Value::String { value }),
        (SchemaKind::Bytes, AvroValue::Bytes(value)) => Ok(Value::Bytes { value }),
        (SchemaKind::Date, AvroValue::Date(value)) => Ok(Value::Date {
            value: date_from_epoch_days(value)?,
        }),
        (SchemaKind::Time, AvroValue::TimeMillis(value)) => Ok(Value::Time {
            value: time_from_micros(i64::from(value) * 1_000)?,
        }),
        (SchemaKind::Time, AvroValue::TimeMicros(value)) => Ok(Value::Time {
            value: time_from_micros(value)?,
        }),
        (SchemaKind::Timestamp, AvroValue::TimestampMillis(value)) => Ok(Value::Timestamp {
            value: timestamp_from_micros(value * 1_000)?,
        }),
        (SchemaKind::Timestamp, AvroValue::TimestampMicros(value)) => Ok(Value::Timestamp {
            value: timestamp_from_micros(value)?,
        }),
        (SchemaKind::Timestamp, AvroValue::TimestampNanos(value)) => Ok(Value::Timestamp {
            value: timestamp_from_nanos(value)?,
        }),
        (SchemaKind::Uuid, AvroValue::Uuid(value)) => Ok(Value::Uuid {
            value: value.to_string(),
        }),
        (SchemaKind::Decimal { scale, .. }, AvroValue::Decimal(value)) => Ok(Value::Decimal {
            value: unscaled_to_decimal_string(&BigInt::from(value), *scale),
        }),
        (SchemaKind::Decimal { scale, .. }, AvroValue::Bytes(value)) => Ok(Value::Decimal {
            value: unscaled_to_decimal_string(&BigInt::from_signed_bytes_be(&value), *scale),
        }),
        (SchemaKind::Array { items }, AvroValue::Array(values)) => Ok(Value::Array {
            items: values
                .into_iter()
                .map(|value| avro_value_to_ir(value, items))
                .collect::<Result<Vec<_>, _>>()?,
        }),
        (SchemaKind::Map { values }, AvroValue::Map(entries)) => Ok(Value::Map {
            entries: entries
                .into_iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(key, value)| {
                    Ok(MapEntry {
                        key,
                        value: avro_value_to_ir(value, values)?,
                    })
                })
                .collect::<Result<Vec<_>, S4Error>>()?,
        }),
        (SchemaKind::Record { fields }, AvroValue::Record(values)) => Ok(Value::Record {
            fields: fields
                .iter()
                .map(|field| {
                    let value = values
                        .iter()
                        .find(|(name, _)| name == &field.name)
                        .map(|(_, value)| value.clone())
                        .ok_or_else(|| {
                            unsupported(format!("Avro record is missing field {:?}", field.name))
                        })?;
                    Ok(ValueField {
                        name: field.name.clone(),
                        value: avro_value_to_ir(value, &field.schema)?,
                    })
                })
                .collect::<Result<Vec<_>, S4Error>>()?,
        }),
        _ => Err(unsupported(
            "Avro value does not match its supported schema",
        )),
    }
}

fn ir_value_to_avro(value: &Value, schema: &SchemaNode) -> Result<AvroValue, S4Error> {
    if schema.nullable {
        if matches!(value, Value::Null) {
            return Ok(AvroValue::Union(0, Box::new(AvroValue::Null)));
        }
        return Ok(AvroValue::Union(
            1,
            Box::new(ir_value_to_avro_required(value, schema)?),
        ));
    }
    ir_value_to_avro_required(value, schema)
}

fn ir_value_to_avro_required(value: &Value, schema: &SchemaNode) -> Result<AvroValue, S4Error> {
    match (&schema.kind, value) {
        (SchemaKind::Null, Value::Null) => Ok(AvroValue::Null),
        (SchemaKind::Boolean, Value::Boolean { value }) => Ok(AvroValue::Boolean(*value)),
        (SchemaKind::I32, Value::I32 { value }) => Ok(AvroValue::Int(*value)),
        (SchemaKind::I64, Value::I64 { value }) => Ok(AvroValue::Long(*value)),
        (SchemaKind::F32, Value::F32 { value }) => Ok(AvroValue::Float(*value)),
        (SchemaKind::F64, Value::F64 { value }) => Ok(AvroValue::Double(*value)),
        (SchemaKind::String, Value::String { value }) => Ok(AvroValue::String(value.clone())),
        (SchemaKind::Bytes, Value::Bytes { value }) => Ok(AvroValue::Bytes(value.clone())),
        (SchemaKind::Date, Value::Date { value }) => {
            Ok(AvroValue::Date(date_to_epoch_days(value)?))
        }
        (SchemaKind::Time, Value::Time { value }) => {
            Ok(AvroValue::TimeMicros(time_to_micros(value)?))
        }
        (SchemaKind::Timestamp, Value::Timestamp { value }) => {
            Ok(AvroValue::TimestampMicros(timestamp_to_micros(value)?))
        }
        (SchemaKind::Uuid, Value::Uuid { value }) => Ok(AvroValue::Uuid(
            uuid::Uuid::parse_str(value).map_err(|_| unsupported("invalid UUID IR value"))?,
        )),
        (SchemaKind::Decimal { precision, scale }, Value::Decimal { value }) => {
            let unscaled = decimal_to_unscaled(value, *scale)?;
            Ok(AvroValue::Decimal(apache_avro::Decimal::from(
                decimal_to_bytes(&unscaled, *precision),
            )))
        }
        (SchemaKind::Array { items }, Value::Array { items: values }) => Ok(AvroValue::Array(
            values
                .iter()
                .map(|value| ir_value_to_avro(value, items))
                .collect::<Result<_, _>>()?,
        )),
        (SchemaKind::Map { values }, Value::Map { entries }) => Ok(AvroValue::Map(
            entries
                .iter()
                .map(|entry| Ok((entry.key.clone(), ir_value_to_avro(&entry.value, values)?)))
                .collect::<Result<_, S4Error>>()?,
        )),
        (SchemaKind::Record { fields }, Value::Record { fields: values }) => Ok(AvroValue::Record(
            fields
                .iter()
                .map(|field| {
                    let value = values
                        .iter()
                        .find(|candidate| candidate.name == field.name)
                        .ok_or_else(|| {
                            unsupported(format!("IR record is missing field {:?}", field.name))
                        })?;
                    Ok((
                        field.name.clone(),
                        ir_value_to_avro(&value.value, &field.schema)?,
                    ))
                })
                .collect::<Result<_, S4Error>>()?,
        )),
        _ => Err(unsupported(
            "IR value does not match its supported Avro schema",
        )),
    }
}

fn decimal_to_unscaled(value: &str, scale: u32) -> Result<BigInt, S4Error> {
    let (negative, unsigned) = match value.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, value),
    };
    let (integer, fraction) = match unsigned.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (unsigned, ""),
    };
    if fraction.len() as u32 > scale {
        return Err(unsupported(
            "decimal fractional digits exceed the schema scale",
        ));
    }
    let mut digits = String::with_capacity(integer.len() + scale as usize + 1);
    digits.push_str(integer);
    digits.push_str(fraction);
    for _ in (fraction.len() as u32)..scale {
        digits.push('0');
    }
    let mut unscaled = BigInt::parse_bytes(digits.as_bytes(), 10)
        .ok_or_else(|| unsupported("invalid decimal IR value"))?;
    if negative {
        unscaled = -unscaled;
    }
    Ok(unscaled)
}

fn unscaled_to_decimal_string(unscaled: &BigInt, scale: u32) -> String {
    let negative = unscaled.sign() == Sign::Minus;
    let digits = unscaled.magnitude().to_str_radix(10);
    let scale = scale as usize;
    let sign = if negative { "-" } else { "" };
    if scale == 0 {
        return format!("{sign}{digits}");
    }
    if digits.len() > scale {
        let split = digits.len() - scale;
        format!("{sign}{}.{}", &digits[..split], &digits[split..])
    } else {
        let fraction = format!("{:0>width$}", digits, width = scale);
        format!("{sign}0.{fraction}")
    }
}

fn decimal_to_bytes(unscaled: &BigInt, precision: u32) -> Vec<u8> {
    let minimal = unscaled.to_signed_bytes_be();
    let required = min_decimal_len(precision);
    if minimal.len() >= required {
        return minimal;
    }
    let pad = if unscaled.sign() == Sign::Minus {
        0xFF
    } else {
        0x00
    };
    let mut bytes = vec![pad; required];
    bytes[required - minimal.len()..].copy_from_slice(&minimal);
    bytes
}

fn min_decimal_len(precision: u32) -> usize {
    let mut len = 1_usize;
    while (((2.0_f64).powi(8 * len as i32 - 1) - 1.0).log10().floor() as u32) < precision {
        len += 1;
    }
    len
}

fn date_from_epoch_days(days: i32) -> Result<String, S4Error> {
    NaiveDate::from_ymd_opt(1970, 1, 1)
        .and_then(|epoch| epoch.checked_add_signed(Duration::days(i64::from(days))))
        .map(|date| date.format("%F").to_string())
        .ok_or_else(|| unsupported("Avro date is outside the supported calendar range"))
}

fn date_to_epoch_days(value: &str) -> Result<i32, S4Error> {
    let date =
        NaiveDate::parse_from_str(value, "%F").map_err(|_| unsupported("invalid date IR value"))?;
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).expect("1970-01-01 is valid");
    i32::try_from(date.signed_duration_since(epoch).num_days())
        .map_err(|_| unsupported("date is outside the Avro i32 day range"))
}

fn time_from_micros(micros: i64) -> Result<String, S4Error> {
    let micros_per_day = 86_400_000_000_i64;
    if !(0..micros_per_day).contains(&micros) {
        return Err(unsupported("Avro time is outside one UTC day"));
    }
    let seconds = u32::try_from(micros / 1_000_000).expect("bounded to one day");
    let nanoseconds = u32::try_from((micros % 1_000_000) * 1_000).expect("subsecond is bounded");
    NaiveTime::from_num_seconds_from_midnight_opt(seconds, nanoseconds)
        .map(|time| time.format("%H:%M:%S%.f").to_string())
        .ok_or_else(|| unsupported("invalid Avro time"))
}

fn time_to_micros(value: &str) -> Result<i64, S4Error> {
    let time = NaiveTime::parse_from_str(value, "%H:%M:%S%.f")
        .map_err(|_| unsupported("invalid time IR value"))?;
    Ok(i64::from(time.num_seconds_from_midnight()) * 1_000_000
        + i64::from(time.nanosecond() / 1_000))
}

fn timestamp_from_micros(micros: i64) -> Result<String, S4Error> {
    DateTime::from_timestamp_micros(micros)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .ok_or_else(|| unsupported("Avro timestamp is outside the supported range"))
}

fn timestamp_from_nanos(nanos: i64) -> Result<String, S4Error> {
    let seconds = nanos.div_euclid(1_000_000_000);
    let nanoseconds = u32::try_from(nanos.rem_euclid(1_000_000_000)).expect("remainder is bounded");
    DateTime::from_timestamp(seconds, nanoseconds)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .ok_or_else(|| unsupported("Avro timestamp is outside the supported range"))
}

fn timestamp_to_micros(value: &str) -> Result<i64, S4Error> {
    Ok(DateTime::parse_from_rfc3339(value)
        .map_err(|_| unsupported("invalid timestamp IR value"))?
        .with_timezone(&Utc)
        .timestamp_micros())
}

fn validate_limits(limits: AvroLimits) -> Result<(), S4Error> {
    if limits.max_source_bytes == 0 {
        return Err(S4Error::new(
            codes::CONFIG_INVALID,
            "Avro source byte limit must be greater than zero",
        ));
    }
    Ok(())
}

fn avro_error(error: impl std::fmt::Display) -> S4Error {
    S4Error::new(
        codes::UNSUPPORTED_FORMAT,
        format!("invalid Avro OCF: {error}"),
    )
}

fn unsupported(message: impl Into<String>) -> S4Error {
    S4Error::new(codes::UNSUPPORTED_FORMAT, message)
}

struct LimitedReader<R> {
    inner: R,
    remaining: usize,
}

impl<R> LimitedReader<R> {
    fn new(inner: R, maximum: usize) -> Self {
        Self {
            inner,
            remaining: maximum,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return match self.inner.read(&mut buffer[..1])? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Avro source exceeds configured byte limit",
                )),
            };
        }
        let maximum = buffer.len().min(self.remaining);
        let read = self.inner.read(&mut buffer[..maximum])?;
        self.remaining -= read;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_pump::{BinaryTransform, EnvelopeBinaryTransform};
    use crate::binary_reductor::CommonTypeBinaryReductor;
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    const SCHEMA: &str = r#"{
        "type":"record","name":"customer","fields":[
          {"name":"id","type":"long"},
          {"name":"email","type":["null","string"]},
          {"name":"labels","type":{"type":"map","values":"string"}},
          {"name":"events","type":{"type":"array","items":{"type":"record","name":"event","fields":[{"name":"name","type":"string"}]}}}
        ]
    }"#;

    fn input() -> Vec<u8> {
        let schema = Schema::parse_str(SCHEMA).unwrap();
        let values = [
            AvroValue::Record(vec![
                ("id".to_string(), AvroValue::Long(7)),
                (
                    "email".to_string(),
                    AvroValue::Union(
                        1,
                        Box::new(AvroValue::String("ada@example.com".to_string())),
                    ),
                ),
                (
                    "labels".to_string(),
                    AvroValue::Map(
                        BTreeMap::from([(
                            "role".to_string(),
                            AvroValue::String("admin".to_string()),
                        )])
                        .into_iter()
                        .collect(),
                    ),
                ),
                (
                    "events".to_string(),
                    AvroValue::Array(vec![AvroValue::Record(vec![(
                        "name".to_string(),
                        AvroValue::String("login".to_string()),
                    )])]),
                ),
            ]),
            AvroValue::Record(vec![
                ("id".to_string(), AvroValue::Long(8)),
                (
                    "email".to_string(),
                    AvroValue::Union(0, Box::new(AvroValue::Null)),
                ),
                ("labels".to_string(), AvroValue::Map(Default::default())),
                ("events".to_string(), AvroValue::Array(Vec::new())),
            ]),
        ];
        let mut writer = Writer::with_codec(&schema, Vec::new(), Codec::Null).unwrap();
        for value in values {
            writer.append_value(value).unwrap();
        }
        writer.into_inner().unwrap()
    }

    struct ChunkedReader {
        bytes: Vec<u8>,
        offset: usize,
        chunk_size: usize,
    }

    impl ChunkedReader {
        fn new(bytes: Vec<u8>, chunk_size: usize) -> Self {
            Self {
                bytes,
                offset: 0,
                chunk_size,
            }
        }
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let length = (self.bytes.len() - self.offset)
                .min(self.chunk_size)
                .min(buffer.len());
            buffer[..length].copy_from_slice(&self.bytes[self.offset..self.offset + length]);
            self.offset += length;
            Ok(length)
        }
    }

    #[test]
    fn ocf_round_trip_preserves_supported_schema_and_values() {
        let mut values = Vec::new();
        let schema = decode_ocf(input().as_slice(), AvroLimits::default(), |value| {
            values.push(value);
            Ok(())
        })
        .unwrap();
        assert_eq!(values.len(), 2);
        assert!(matches!(schema.root.kind, SchemaKind::Record { .. }));

        let output = encode_ocf(&schema, &values, AvroLimits::default()).unwrap();
        assert!(output.starts_with(b"Obj\x01"));
        let mut decoded = Vec::new();
        let output_schema = decode_ocf(output.as_slice(), AvroLimits::default(), |value| {
            decoded.push(value);
            Ok(())
        })
        .unwrap();
        assert_eq!(output_schema, schema);
        assert_eq!(decoded, values);
    }

    #[test]
    fn source_limit_fails_before_ocf_bytes_are_unbounded() {
        let error = decode_ocf(
            input().as_slice(),
            AvroLimits {
                max_source_bytes: 4,
                ..AvroLimits::default()
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
    }

    #[test]
    fn source_limit_allows_an_ocf_with_exactly_the_configured_size() {
        let input = input();
        let mut records = 0;
        decode_ocf(
            input.as_slice(),
            AvroLimits {
                max_source_bytes: input.len(),
                ..AvroLimits::default()
            },
            |_| {
                records += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(records, 2);
    }

    #[test]
    fn ocf_decoding_is_invariant_across_transport_chunk_sizes() {
        let input = input();
        for chunk_size in 1..=32 {
            let mut values = Vec::new();
            decode_ocf(
                ChunkedReader::new(input.clone(), chunk_size),
                AvroLimits::default(),
                |value| {
                    values.push(value);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(values.len(), 2, "chunk size {chunk_size}");
        }
    }

    #[test]
    fn unsupported_union_is_rejected() {
        let schema = Schema::parse_str(r#"["null","string","long"]"#).unwrap();
        let error = schema_from_avro(&schema, BinaryIrLimits::default()).unwrap_err();
        assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
    }

    #[test]
    fn logical_date_is_mapped_to_typed_ir() {
        let schema = Schema::parse_str(r#"{"type":"int","logicalType":"date"}"#).unwrap();
        let schema = schema_from_avro(&schema, BinaryIrLimits::default()).unwrap();
        assert_eq!(schema.root.kind, SchemaKind::Date);
    }

    #[test]
    fn supported_logical_values_round_trip_through_ocf() {
        let cases = vec![
            (
                SchemaIr::new(SchemaNode::required(SchemaKind::Date)),
                ValueIr::new(Value::Date {
                    value: "2026-08-30".to_string(),
                }),
            ),
            (
                SchemaIr::new(SchemaNode::required(SchemaKind::Time)),
                ValueIr::new(Value::Time {
                    value: "12:34:56.789".to_string(),
                }),
            ),
            (
                SchemaIr::new(SchemaNode::required(SchemaKind::Timestamp)),
                ValueIr::new(Value::Timestamp {
                    value: "2026-08-30T12:34:56.789Z".to_string(),
                }),
            ),
            (
                SchemaIr::new(SchemaNode::required(SchemaKind::Uuid)),
                ValueIr::new(Value::Uuid {
                    value: "d5ed6eb6-89be-4aab-84a0-f1e4a12d50f8".to_string(),
                }),
            ),
            (
                SchemaIr::new(SchemaNode::required(SchemaKind::Decimal {
                    precision: 20,
                    scale: 4,
                })),
                ValueIr::new(Value::Decimal {
                    value: "123.4500".to_string(),
                }),
            ),
            (
                SchemaIr::new(SchemaNode::required(SchemaKind::Decimal {
                    precision: 20,
                    scale: 4,
                })),
                ValueIr::new(Value::Decimal {
                    value: "-0.0500".to_string(),
                }),
            ),
        ];
        for (schema, value) in cases {
            let output =
                encode_ocf(&schema, std::slice::from_ref(&value), AvroLimits::default()).unwrap();
            let mut decoded = Vec::new();
            let decoded_schema = decode_ocf(output.as_slice(), AvroLimits::default(), |value| {
                decoded.push(value);
                Ok(())
            })
            .unwrap();
            assert_eq!(decoded_schema, schema);
            assert_eq!(decoded, vec![value]);
        }
    }

    struct Uppercase;

    impl BinaryTransform for Uppercase {
        fn output_schema(&mut self, input_schema: &SchemaIr) -> Result<SchemaIr, S4Error> {
            Ok(input_schema.clone())
        }

        fn transform(
            &mut self,
            value: ValueIr,
            _input_schema: &SchemaIr,
            _output_schema: &SchemaIr,
        ) -> Result<Option<ValueIr>, S4Error> {
            let Value::Record { mut fields } = value.root else {
                return Err(S4Error::new(codes::INTERNAL, "test expects a record"));
            };
            match &mut fields[1].value {
                Value::String { value } => *value = value.to_uppercase(),
                Value::Null => {}
                _ => {
                    return Err(S4Error::new(
                        codes::INTERNAL,
                        "test expects an optional email string",
                    ));
                }
            }
            Ok(Some(ValueIr::new(Value::Record { fields })))
        }
    }

    #[test]
    fn process_ocf_routes_each_record_through_the_typed_pump() {
        let mut pump = BinaryPump::new(
            CommonTypeBinaryReductor::default(),
            Uppercase,
            BinaryIrLimits::default(),
        );
        let output = process_ocf(input().as_slice(), AvroLimits::default(), &mut pump).unwrap();
        let mut values = Vec::new();
        decode_ocf(output.as_slice(), AvroLimits::default(), |value| {
            values.push(value);
            Ok(())
        })
        .unwrap();
        let Value::Record { fields } = &values[0].root else {
            panic!("expected record");
        };
        assert_eq!(
            fields[1].value,
            Value::String {
                value: "ADA@EXAMPLE.COM".to_string(),
            }
        );
    }

    #[test]
    fn process_ocf_emits_the_typed_envelope_schema() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let target =
            crate::binary_ir::SchemaPath(vec![crate::binary_ir::SchemaPathSegment::Field(
                "email".to_string(),
            )]);
        let mut pump = BinaryPump::new(
            CommonTypeBinaryReductor::default(),
            EnvelopeBinaryTransform::new(vec![target], Some(&public_pem)).unwrap(),
            BinaryIrLimits::default(),
        );
        let output = process_ocf(input().as_slice(), AvroLimits::default(), &mut pump).unwrap();
        assert!(
            !output
                .windows(b"ada@example.com".len())
                .any(|bytes| bytes == b"ada@example.com")
        );

        let mut values = Vec::new();
        let schema = decode_ocf(output.as_slice(), AvroLimits::default(), |value| {
            values.push(value);
            Ok(())
        })
        .unwrap();
        let SchemaKind::Record { fields } = &schema.root.kind else {
            panic!("expected record schema");
        };
        assert!(matches!(fields[1].schema.kind, SchemaKind::Record { .. }));
        let Value::Record { fields } = &values[0].root else {
            panic!("expected record value");
        };
        assert!(matches!(fields[1].value, Value::Record { .. }));
    }
}
