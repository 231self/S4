//! Schema-aware reduction, transformation, restoration, and validation.

use std::cmp::Ordering;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::Oaep;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use s4_error::{S4Error, codes};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::binary_ir::{
    BinaryIrLimits, SchemaField, SchemaIr, SchemaKind, SchemaNode, SchemaPath, SchemaPathSegment,
    Value, ValueField, ValueIr,
};
use crate::binary_reductor::{BinaryReductionPlan, BinaryReductor, BinaryRestorePlan};

/// A typed binary transform declares its output schema before processing data.
///
/// This intentionally differs from the byte-oriented text filter contract: an
/// encoder must know the resulting binary schema before it can accept records.
pub trait BinaryTransform {
    fn output_schema(&mut self, input_schema: &SchemaIr) -> Result<SchemaIr, S4Error>;

    /// Returns `None` when the record is deliberately dropped.
    fn transform(
        &mut self,
        value: ValueIr,
        input_schema: &SchemaIr,
        output_schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, S4Error>;
}

#[derive(Default)]
pub struct IdentityBinaryTransform;

impl BinaryTransform for IdentityBinaryTransform {
    fn output_schema(&mut self, input_schema: &SchemaIr) -> Result<SchemaIr, S4Error> {
        Ok(input_schema.clone())
    }

    fn transform(
        &mut self,
        value: ValueIr,
        _input_schema: &SchemaIr,
        _output_schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, S4Error> {
        Ok(Some(value))
    }
}

/// Replaces explicitly selected string values with S4 envelope records.
///
/// A missing public key deliberately redacts instead of producing a malformed
/// envelope. No private key is accepted or retained by this transform.
#[derive(Debug)]
pub struct EnvelopeBinaryTransform {
    targets: Vec<SchemaPath>,
    public_key: Option<RsaPublicKey>,
}

impl EnvelopeBinaryTransform {
    pub fn new(targets: Vec<SchemaPath>, public_key_pem: Option<&str>) -> Result<Self, S4Error> {
        let targets = canonicalize_targets(targets)?;
        let public_key = public_key_pem.map(parse_public_key).transpose()?;
        Ok(Self {
            targets,
            public_key,
        })
    }

    pub fn targets(&self) -> &[SchemaPath] {
        &self.targets
    }
}

/// Parses `x-s4-encrypt-fields`: comma-separated paths such as
/// `email,contacts[*].email` or `$.email`.
pub fn parse_envelope_targets(value: &str) -> Result<Vec<SchemaPath>, S4Error> {
    let mut paths = Vec::new();
    for raw_path in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let raw_path = raw_path.strip_prefix("$.").unwrap_or(raw_path);
        if raw_path.is_empty() {
            return Err(transform_error("envelope target must not be the root path"));
        }
        let mut segments = Vec::new();
        for segment in raw_path.split('.') {
            let (field, array) = segment
                .strip_suffix("[*]")
                .map_or((segment, false), |field| (field, true));
            if field.is_empty()
                || !field
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            {
                return Err(transform_error(
                    "envelope target contains an invalid field name",
                ));
            }
            segments.push(SchemaPathSegment::Field(field.to_string()));
            if array {
                segments.push(SchemaPathSegment::ArrayElement);
            }
        }
        paths.push(SchemaPath(segments));
    }
    canonicalize_targets(paths)
}

impl BinaryTransform for EnvelopeBinaryTransform {
    fn output_schema(&mut self, input_schema: &SchemaIr) -> Result<SchemaIr, S4Error> {
        let mut output = input_schema.clone();
        if self.public_key.is_none() {
            return Ok(output);
        }
        for target in &self.targets {
            replace_schema_at_path(&mut output.root, target.segments(), target)?;
        }
        Ok(output)
    }

    fn transform(
        &mut self,
        mut value: ValueIr,
        input_schema: &SchemaIr,
        _output_schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, S4Error> {
        for target in &self.targets {
            let node = input_schema.node_at_path(target).ok_or_else(|| {
                transform_error(format!("envelope target {target} does not exist"))
            })?;
            if !matches!(&node.kind, SchemaKind::String) {
                return Err(transform_error(format!(
                    "envelope target {target} must be a string schema"
                )));
            }
            transform_values_at_path(&mut value.root, target.segments(), target, &self.public_key)?;
        }
        Ok(Some(value))
    }
}

fn envelope_schema(nullable: bool) -> SchemaNode {
    SchemaNode {
        nullable,
        kind: SchemaKind::Record {
            fields: ["alg", "iv", "enc_dek", "ct", "tag"]
                .into_iter()
                .map(|name| SchemaField {
                    name: name.to_string(),
                    schema: SchemaNode::required(SchemaKind::String),
                })
                .collect(),
        },
    }
}

fn replace_schema_at_path(
    node: &mut SchemaNode,
    segments: &[SchemaPathSegment],
    target: &SchemaPath,
) -> Result<(), S4Error> {
    let Some((segment, remaining)) = segments.split_first() else {
        if !matches!(&node.kind, SchemaKind::String) {
            return Err(transform_error(format!(
                "envelope target {target} must be a string schema"
            )));
        }
        *node = envelope_schema(node.nullable);
        return Ok(());
    };
    match (&mut node.kind, segment) {
        (SchemaKind::Array { items }, SchemaPathSegment::ArrayElement) => {
            replace_schema_at_path(items, remaining, target)
        }
        (SchemaKind::Map { values }, SchemaPathSegment::MapValue) => {
            replace_schema_at_path(values, remaining, target)
        }
        (SchemaKind::Record { fields }, SchemaPathSegment::Field(name)) => {
            let field = fields
                .iter_mut()
                .find(|field| field.name == *name)
                .ok_or_else(|| {
                    transform_error(format!("envelope target {target} does not exist"))
                })?;
            replace_schema_at_path(&mut field.schema, remaining, target)
        }
        (SchemaKind::Custom { value, .. }, SchemaPathSegment::LogicalValue) => {
            replace_schema_at_path(value, remaining, target)
        }
        _ => Err(transform_error(format!(
            "envelope target {target} does not match the input schema"
        ))),
    }
}

fn transform_values_at_path(
    value: &mut Value,
    segments: &[SchemaPathSegment],
    target: &SchemaPath,
    public_key: &Option<RsaPublicKey>,
) -> Result<(), S4Error> {
    let Some((segment, remaining)) = segments.split_first() else {
        let Value::String { value: plaintext } = value else {
            if matches!(value, Value::Null) {
                return Ok(());
            }
            return Err(transform_error(format!(
                "envelope target {target} does not contain a string value"
            )));
        };
        *value = match public_key {
            Some(public_key) => encrypt_string(plaintext, public_key)?,
            None => Value::String {
                value: "[REDACTED]".to_string(),
            },
        };
        return Ok(());
    };
    match (value, segment) {
        (Value::Array { items }, SchemaPathSegment::ArrayElement) => {
            for item in items {
                transform_values_at_path(item, remaining, target, public_key)?;
            }
            Ok(())
        }
        (Value::Map { entries }, SchemaPathSegment::MapValue) => {
            for entry in entries {
                transform_values_at_path(&mut entry.value, remaining, target, public_key)?;
            }
            Ok(())
        }
        (Value::Record { fields }, SchemaPathSegment::Field(name)) => {
            let field = fields
                .iter_mut()
                .find(|field| field.name == *name)
                .ok_or_else(|| {
                    transform_error(format!(
                        "envelope target {target} does not exist in a value"
                    ))
                })?;
            transform_values_at_path(&mut field.value, remaining, target, public_key)
        }
        (Value::Custom { value, .. }, SchemaPathSegment::LogicalValue) => {
            transform_values_at_path(value, remaining, target, public_key)
        }
        _ => Err(transform_error(format!(
            "envelope target {target} does not match an input value"
        ))),
    }
}

fn encrypt_string(plaintext: &str, public_key: &RsaPublicKey) -> Result<Value, S4Error> {
    let mut dek = [0_u8; 32];
    let mut iv = [0_u8; 12];
    OsRng.fill_bytes(&mut dek);
    OsRng.fill_bytes(&mut iv);
    let result = (|| {
        let encrypted_dek = public_key
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &dek)
            .map_err(|_| transform_error("envelope DEK wrapping failed"))?;
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|_| transform_error("envelope cipher initialization failed"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
            .map_err(|_| transform_error("envelope encryption failed"))?;
        let tag_start = ciphertext.len().checked_sub(16).ok_or_else(|| {
            transform_error("envelope ciphertext is missing an authentication tag")
        })?;
        Ok(Value::Record {
            fields: vec![
                string_field("alg", "RSA-OAEP/AES-256-GCM".to_string()),
                string_field("iv", BASE64.encode(iv)),
                string_field("enc_dek", BASE64.encode(encrypted_dek)),
                string_field("ct", BASE64.encode(&ciphertext[..tag_start])),
                string_field("tag", BASE64.encode(&ciphertext[tag_start..])),
            ],
        })
    })();
    dek.zeroize();
    result
}

fn string_field(name: &str, value: String) -> ValueField {
    ValueField {
        name: name.to_string(),
        value: Value::String { value },
    }
}

fn parse_public_key(pem: &str) -> Result<RsaPublicKey, S4Error> {
    let pem = pem.trim();
    if pem.is_empty() {
        return Err(transform_error("envelope public key must not be empty"));
    }
    if let Ok(key) = RsaPublicKey::from_public_key_pem(pem) {
        return Ok(key);
    }
    let (_, certificate) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|_| transform_error("envelope public key must be RSA SPKI or X.509 PEM"))?;
    let certificate = certificate
        .parse_x509()
        .map_err(|_| transform_error("envelope public key must be RSA SPKI or X.509 PEM"))?;
    RsaPublicKey::from_public_key_der(certificate.public_key().raw)
        .map_err(|_| transform_error("envelope public key must be RSA SPKI or X.509 PEM"))
}

fn canonicalize_targets(mut targets: Vec<SchemaPath>) -> Result<Vec<SchemaPath>, S4Error> {
    targets.sort_by(compare_paths);
    for pair in targets.windows(2) {
        if path_is_prefix(&pair[0], &pair[1]) {
            return Err(transform_error(format!(
                "envelope targets {} and {} overlap",
                pair[0], pair[1]
            )));
        }
    }
    Ok(targets)
}

fn compare_paths(left: &SchemaPath, right: &SchemaPath) -> Ordering {
    left.segments()
        .iter()
        .map(segment_sort_key)
        .cmp(right.segments().iter().map(segment_sort_key))
}

fn segment_sort_key(segment: &SchemaPathSegment) -> (u8, &str) {
    match segment {
        SchemaPathSegment::Field(name) => (0, name),
        SchemaPathSegment::ArrayElement => (1, ""),
        SchemaPathSegment::MapValue => (2, ""),
        SchemaPathSegment::LogicalValue => (3, ""),
    }
}

fn path_is_prefix(prefix: &SchemaPath, path: &SchemaPath) -> bool {
    prefix.segments().len() <= path.segments().len()
        && prefix
            .segments()
            .iter()
            .zip(path.segments())
            .all(|(left, right)| left == right)
}

fn transform_error(message: impl Into<String>) -> S4Error {
    S4Error::new(codes::CONFIG_INVALID, message)
}

pub struct BinaryPump<R, T> {
    reductor: R,
    transform: T,
    limits: BinaryIrLimits,
    plans: Option<(BinaryReductionPlan, BinaryRestorePlan)>,
}

impl<R, T> BinaryPump<R, T>
where
    R: BinaryReductor,
    T: BinaryTransform,
{
    pub fn new(reductor: R, transform: T, limits: BinaryIrLimits) -> Self {
        Self {
            reductor,
            transform,
            limits,
            plans: None,
        }
    }

    /// Freezes all schemas before the first value is accepted.
    pub fn plan(&mut self, source_schema: &SchemaIr) -> Result<&SchemaIr, S4Error> {
        source_schema.validate(self.limits)?;
        let reduction = self.reductor.plan(source_schema)?;
        let transformed = self.transform.output_schema(reduction.reduced_schema())?;
        transformed.validate(self.limits)?;
        let restoration = self.reductor.plan_restore(&reduction, &transformed)?;
        self.plans = Some((reduction, restoration));
        Ok(self
            .plans
            .as_ref()
            .expect("binary pump plans were just installed")
            .1
            .output_schema())
    }

    pub fn process(&mut self, source_value: ValueIr) -> Result<Option<ValueIr>, S4Error> {
        let (reduction, restoration) = self.plans.clone().ok_or_else(|| {
            S4Error::new(
                codes::CONFIG_INVALID,
                "binary pump must be planned before processing values",
            )
        })?;
        source_value.validate(reduction.source_schema(), self.limits)?;
        let reduced = self.reductor.reduce(&reduction, &source_value)?;
        let transformed = self.transform.transform(
            reduced,
            reduction.reduced_schema(),
            restoration.transformed_reduced_schema(),
        )?;
        let Some(transformed) = transformed else {
            return Ok(None);
        };
        transformed.validate(restoration.transformed_reduced_schema(), self.limits)?;
        let restored = self.reductor.restore(&restoration, &transformed)?;
        restored.validate(restoration.output_schema(), self.limits)?;
        Ok(Some(restored))
    }

    pub fn output_schema(&self) -> Option<&SchemaIr> {
        self.plans
            .as_ref()
            .map(|(_, restore)| restore.output_schema())
    }

    pub fn into_parts(self) -> (R, T) {
        (self.reductor, self.transform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_ir::{SchemaKind, SchemaNode, Value};
    use crate::binary_reductor::CommonTypeBinaryReductor;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use rand::rngs::OsRng;
    use rsa::Oaep;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use sha2::Sha256;

    fn string_schema() -> SchemaIr {
        SchemaIr::new(SchemaNode::required(SchemaKind::String))
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
            let Value::String { value } = value.root else {
                return Err(S4Error::new(codes::INTERNAL, "test expects a string"));
            };
            Ok(Some(ValueIr::new(Value::String {
                value: value.to_uppercase(),
            })))
        }
    }

    struct InvalidTransform;

    impl BinaryTransform for InvalidTransform {
        fn output_schema(&mut self, input_schema: &SchemaIr) -> Result<SchemaIr, S4Error> {
            Ok(input_schema.clone())
        }

        fn transform(
            &mut self,
            _value: ValueIr,
            _input_schema: &SchemaIr,
            _output_schema: &SchemaIr,
        ) -> Result<Option<ValueIr>, S4Error> {
            Ok(Some(ValueIr::new(Value::I64 { value: 1 })))
        }
    }

    #[test]
    fn plans_before_processing_and_validates_typed_output() {
        let schema = string_schema();
        let mut pump = BinaryPump::new(
            CommonTypeBinaryReductor::default(),
            Uppercase,
            BinaryIrLimits::default(),
        );
        let value = ValueIr::new(Value::String {
            value: "Ada".to_string(),
        });
        assert_eq!(
            pump.process(value.clone()).unwrap_err().code(),
            codes::CONFIG_INVALID
        );
        assert_eq!(pump.plan(&schema).unwrap(), &schema);
        assert_eq!(
            pump.process(value).unwrap(),
            Some(ValueIr::new(Value::String {
                value: "ADA".to_string(),
            }))
        );
    }

    #[test]
    fn rejects_a_transform_that_violates_its_declared_schema() {
        let mut pump = BinaryPump::new(
            CommonTypeBinaryReductor::default(),
            InvalidTransform,
            BinaryIrLimits::default(),
        );
        let schema = string_schema();
        pump.plan(&schema).unwrap();
        assert!(
            pump.process(ValueIr::new(Value::String {
                value: "Ada".to_string(),
            }))
            .is_err()
        );
    }

    fn email_schema() -> SchemaIr {
        SchemaIr::new(SchemaNode::required(SchemaKind::Record {
            fields: vec![
                SchemaField {
                    name: "email".to_string(),
                    schema: SchemaNode::required(SchemaKind::String),
                },
                SchemaField {
                    name: "note".to_string(),
                    schema: SchemaNode::required(SchemaKind::String),
                },
            ],
        }))
    }

    fn email_value() -> ValueIr {
        ValueIr::new(Value::Record {
            fields: vec![
                ValueField {
                    name: "email".to_string(),
                    value: Value::String {
                        value: "ada@example.com".to_string(),
                    },
                },
                ValueField {
                    name: "note".to_string(),
                    value: Value::String {
                        value: "keep".to_string(),
                    },
                },
            ],
        })
    }

    fn email_target() -> SchemaPath {
        SchemaPath(vec![SchemaPathSegment::Field("email".to_string())])
    }

    #[test]
    fn envelope_without_a_public_key_redacts_and_preserves_schema() {
        let schema = email_schema();
        let mut pump = BinaryPump::new(
            CommonTypeBinaryReductor::default(),
            EnvelopeBinaryTransform::new(vec![email_target()], None).unwrap(),
            BinaryIrLimits::default(),
        );
        assert_eq!(pump.plan(&schema).unwrap(), &schema);
        let output = pump.process(email_value()).unwrap().unwrap();
        let Value::Record { fields } = output.root else {
            panic!("expected record");
        };
        assert_eq!(
            fields[0].value,
            Value::String {
                value: "[REDACTED]".to_string(),
            }
        );
        assert_eq!(
            fields[1].value,
            Value::String {
                value: "keep".to_string(),
            }
        );
    }

    #[test]
    fn envelope_with_a_public_key_changes_schema_and_round_trips_cryptographically() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let schema = email_schema();
        let mut pump = BinaryPump::new(
            CommonTypeBinaryReductor::default(),
            EnvelopeBinaryTransform::new(vec![email_target()], Some(&public_pem)).unwrap(),
            BinaryIrLimits::default(),
        );
        let output_schema = pump.plan(&schema).unwrap();
        let SchemaKind::Record { fields } = &output_schema.root.kind else {
            panic!("expected record schema");
        };
        assert!(matches!(fields[0].schema.kind, SchemaKind::Record { .. }));

        let output = pump.process(email_value()).unwrap().unwrap();
        let Value::Record { fields } = output.root else {
            panic!("expected output record");
        };
        let Value::Record { fields: envelope } = &fields[0].value else {
            panic!("expected envelope record");
        };
        let contents = envelope
            .iter()
            .map(|field| {
                let Value::String { value } = &field.value else {
                    panic!("envelope values must be strings");
                };
                (field.name.as_str(), value.as_str())
            })
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(contents["alg"], "RSA-OAEP/AES-256-GCM");
        assert!(!contents["ct"].contains("ada@example.com"));

        let dek = private_key
            .decrypt(
                Oaep::new::<Sha256>(),
                &BASE64.decode(contents["enc_dek"]).unwrap(),
            )
            .unwrap();
        let mut ciphertext = BASE64.decode(contents["ct"]).unwrap();
        ciphertext.extend(BASE64.decode(contents["tag"]).unwrap());
        let plaintext = Aes256Gcm::new_from_slice(&dek)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&BASE64.decode(contents["iv"]).unwrap()),
                ciphertext.as_ref(),
            )
            .unwrap();
        assert_eq!(plaintext, b"ada@example.com");
    }

    #[test]
    fn envelope_target_paths_must_not_overlap() {
        let error = EnvelopeBinaryTransform::new(
            vec![
                SchemaPath(vec![SchemaPathSegment::Field("contacts".to_string())]),
                SchemaPath(vec![
                    SchemaPathSegment::Field("contacts".to_string()),
                    SchemaPathSegment::ArrayElement,
                ]),
            ],
            None,
        )
        .unwrap_err();
        assert_eq!(error.code(), codes::CONFIG_INVALID);
    }

    #[test]
    fn parses_header_targets_into_schema_paths() {
        assert_eq!(
            parse_envelope_targets("$.email,contacts[*].email").unwrap(),
            vec![
                SchemaPath(vec![
                    SchemaPathSegment::Field("contacts".to_string()),
                    SchemaPathSegment::ArrayElement,
                    SchemaPathSegment::Field("email".to_string()),
                ]),
                SchemaPath(vec![SchemaPathSegment::Field("email".to_string())]),
            ]
        );
        assert!(parse_envelope_targets("contacts..email").is_err());
    }
}
