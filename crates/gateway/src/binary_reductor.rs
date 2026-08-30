//! Typed reduction and restoration contracts for binary object codecs.
//!
//! Format codecs use this boundary to expose normalized values to the existing
//! filter pipeline without allowing unclaimed custom logical types through.

use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Instant;

use s4_error::{S4Error, codes};
use s4_wasm_runtime::{
    BinaryReductorEngine as WasmBinaryReductorEngine,
    BinaryReductorPathSegment as WasmBinaryReductorPathSegment,
    BinaryReductorSession as WasmBinaryReductorSession, CancellationToken,
};
use sha2::{Digest, Sha256};

use crate::binary_ir::{
    BinaryIrLimits, SchemaIr, SchemaKind, SchemaPath, SchemaPathSegment, ValueIr,
};

const COMMON_IDENTITY_ID: &str = "s4:common-type-identity@1";
const PLAN_HASH_DOMAIN: &[u8] = b"s4.binary-reductor.plan.v1";
const RESTORE_PLAN_HASH_DOMAIN: &[u8] = b"s4.binary-reductor.restore-plan.v1";

/// One logical schema subtree owned by a custom reductor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryReductorClaim {
    path: SchemaPath,
    type_id: String,
}

impl BinaryReductorClaim {
    pub fn new(path: SchemaPath, type_id: impl Into<String>) -> Self {
        Self {
            path,
            type_id: type_id.into(),
        }
    }

    pub fn path(&self) -> &SchemaPath {
        &self.path
    }

    pub fn type_id(&self) -> &str {
        &self.type_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReductorOwner(Arc<str>);

impl ReductorOwner {
    fn common_identity() -> Self {
        Self(Arc::from(COMMON_IDENTITY_ID))
    }

    fn component_digest(&self) -> Option<&str> {
        if self.0.as_ref() == COMMON_IDENTITY_ID {
            None
        } else {
            Some(self.0.as_ref())
        }
    }

    fn stable_id(&self) -> &str {
        &self.0
    }
}

/// Immutable, typed output of [`BinaryReductor::plan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryReductionPlan {
    owner: ReductorOwner,
    source_schema: SchemaIr,
    reduced_schema: SchemaIr,
    claims: Arc<[BinaryReductorClaim]>,
    custom_coverage: Arc<[BinaryReductorClaim]>,
    opaque_plan: Arc<[u8]>,
    plan_hash: [u8; 32],
}

impl BinaryReductionPlan {
    fn new(
        owner: ReductorOwner,
        source_schema: SchemaIr,
        reduced_schema: SchemaIr,
        claims: Vec<BinaryReductorClaim>,
        custom_coverage: Vec<BinaryReductorClaim>,
        opaque_plan: Vec<u8>,
        limits: BinaryIrLimits,
    ) -> Result<Self, S4Error> {
        let claims = canonicalize_claims(claims)?;
        let custom_coverage = canonicalize_claims(custom_coverage)?;
        let source_encoded = source_schema.to_canonical_json(limits)?;
        let reduced_encoded = reduced_schema.to_canonical_json(limits)?;
        let plan_hash = hash_reduction_plan(
            &owner,
            &source_encoded,
            &reduced_encoded,
            &claims,
            &custom_coverage,
            &opaque_plan,
        );
        Ok(Self {
            owner,
            source_schema,
            reduced_schema,
            claims: claims.into(),
            custom_coverage: custom_coverage.into(),
            opaque_plan: opaque_plan.into(),
            plan_hash,
        })
    }

    pub fn source_schema(&self) -> &SchemaIr {
        &self.source_schema
    }

    pub fn reduced_schema(&self) -> &SchemaIr {
        &self.reduced_schema
    }

    pub fn claims(&self) -> &[BinaryReductorClaim] {
        &self.claims
    }

    pub fn opaque_plan(&self) -> &[u8] {
        &self.opaque_plan
    }

    pub fn component_digest(&self) -> Option<&str> {
        self.owner.component_digest()
    }

    pub fn plan_hash(&self) -> &[u8; 32] {
        &self.plan_hash
    }

    pub fn plan_hash_hex(&self) -> String {
        hex::encode(self.plan_hash)
    }
}

/// Immutable, typed output of [`BinaryReductor::plan_restore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryRestorePlan {
    reduction: BinaryReductionPlan,
    transformed_reduced_schema: SchemaIr,
    output_schema: SchemaIr,
    opaque_restore_plan: Arc<[u8]>,
    plan_hash: [u8; 32],
}

impl BinaryRestorePlan {
    fn new(
        reduction: &BinaryReductionPlan,
        transformed_reduced_schema: SchemaIr,
        output_schema: SchemaIr,
        opaque_restore_plan: Vec<u8>,
        limits: BinaryIrLimits,
    ) -> Result<Self, S4Error> {
        let transformed_encoded = transformed_reduced_schema.to_canonical_json(limits)?;
        let output_encoded = output_schema.to_canonical_json(limits)?;
        let plan_hash = hash_parts(
            RESTORE_PLAN_HASH_DOMAIN,
            [
                reduction.plan_hash.as_slice(),
                transformed_encoded.as_slice(),
                output_encoded.as_slice(),
                opaque_restore_plan.as_slice(),
            ],
        );
        Ok(Self {
            reduction: reduction.clone(),
            transformed_reduced_schema,
            output_schema,
            opaque_restore_plan: opaque_restore_plan.into(),
            plan_hash,
        })
    }

    pub fn reduction_plan(&self) -> &BinaryReductionPlan {
        &self.reduction
    }

    pub fn transformed_reduced_schema(&self) -> &SchemaIr {
        &self.transformed_reduced_schema
    }

    pub fn output_schema(&self) -> &SchemaIr {
        &self.output_schema
    }

    pub fn opaque_restore_plan(&self) -> &[u8] {
        &self.opaque_restore_plan
    }

    pub fn component_digest(&self) -> Option<&str> {
        self.reduction.component_digest()
    }

    pub fn plan_hash(&self) -> &[u8; 32] {
        &self.plan_hash
    }

    pub fn plan_hash_hex(&self) -> String {
        hex::encode(self.plan_hash)
    }
}

/// Typed host contract shared by native and future Wasm reductors.
///
/// Plans own all schema and opaque state needed by later calls, so callers only
/// pass immutable plan references after planning succeeds.
pub trait BinaryReductor {
    fn plan(&mut self, source_schema: &SchemaIr) -> Result<BinaryReductionPlan, S4Error>;

    fn plan_restore(
        &mut self,
        plan: &BinaryReductionPlan,
        transformed_reduced_schema: &SchemaIr,
    ) -> Result<BinaryRestorePlan, S4Error>;

    fn reduce(
        &mut self,
        plan: &BinaryReductionPlan,
        source_value: &ValueIr,
    ) -> Result<ValueIr, S4Error>;

    fn restore(
        &mut self,
        plan: &BinaryRestorePlan,
        transformed_value: &ValueIr,
    ) -> Result<ValueIr, S4Error>;
}

/// Built-in identity reductor for the approved common Schema IR type set.
pub struct CommonTypeBinaryReductor {
    limits: BinaryIrLimits,
}

impl CommonTypeBinaryReductor {
    pub fn new(limits: BinaryIrLimits) -> Self {
        Self { limits }
    }

    fn plan_with_coverage(
        &mut self,
        source_schema: &SchemaIr,
        owned_claims: &[BinaryReductorClaim],
    ) -> Result<BinaryReductionPlan, S4Error> {
        source_schema.validate(self.limits)?;
        reject_unclaimed_custom_nodes(source_schema, owned_claims)?;
        BinaryReductionPlan::new(
            ReductorOwner::common_identity(),
            source_schema.clone(),
            source_schema.clone(),
            Vec::new(),
            owned_claims.to_vec(),
            Vec::new(),
            self.limits,
        )
    }
}

impl Default for CommonTypeBinaryReductor {
    fn default() -> Self {
        Self::new(BinaryIrLimits::default())
    }
}

impl BinaryReductor for CommonTypeBinaryReductor {
    fn plan(&mut self, source_schema: &SchemaIr) -> Result<BinaryReductionPlan, S4Error> {
        self.plan_with_coverage(source_schema, &[])
    }

    fn plan_restore(
        &mut self,
        plan: &BinaryReductionPlan,
        transformed_reduced_schema: &SchemaIr,
    ) -> Result<BinaryRestorePlan, S4Error> {
        ensure_owner(plan, &ReductorOwner::common_identity())?;
        transformed_reduced_schema.validate(self.limits)?;
        reject_unclaimed_custom_nodes(transformed_reduced_schema, plan.custom_coverage.as_ref())?;
        BinaryRestorePlan::new(
            plan,
            transformed_reduced_schema.clone(),
            transformed_reduced_schema.clone(),
            Vec::new(),
            self.limits,
        )
    }

    fn reduce(
        &mut self,
        plan: &BinaryReductionPlan,
        source_value: &ValueIr,
    ) -> Result<ValueIr, S4Error> {
        ensure_owner(plan, &ReductorOwner::common_identity())?;
        source_value.validate(plan.source_schema(), self.limits)?;
        let reduced = source_value.clone();
        reduced.validate(plan.reduced_schema(), self.limits)?;
        Ok(reduced)
    }

    fn restore(
        &mut self,
        plan: &BinaryRestorePlan,
        transformed_value: &ValueIr,
    ) -> Result<ValueIr, S4Error> {
        ensure_owner(&plan.reduction, &ReductorOwner::common_identity())?;
        transformed_value.validate(&plan.transformed_reduced_schema, self.limits)?;
        let restored = transformed_value.clone();
        restored.validate(&plan.output_schema, self.limits)?;
        Ok(restored)
    }
}

/// Adapter from the bounded `s4:binary-reductor` runtime world to the typed
/// gateway contract used by binary codecs.
///
/// The runtime bounds byte-oriented guest calls. This adapter is responsible
/// for parsing canonical IR, binding plans to the component digest, and making
/// sure a guest changes schema only at paths it explicitly owns.
pub struct WasmBinaryReductor {
    session: WasmBinaryReductorSession,
    owner: ReductorOwner,
    limits: BinaryIrLimits,
}

impl WasmBinaryReductor {
    pub fn start(
        engine: &WasmBinaryReductorEngine,
        limits: BinaryIrLimits,
    ) -> Result<Self, S4Error> {
        Self::start_with_cancellation(engine, limits, CancellationToken::new())
    }

    pub fn start_with_cancellation(
        engine: &WasmBinaryReductorEngine,
        limits: BinaryIrLimits,
        cancellation: CancellationToken,
    ) -> Result<Self, S4Error> {
        let session = engine.start_session_with_cancellation(cancellation)?;
        Ok(Self {
            session,
            owner: ReductorOwner(Arc::from(engine.component_digest())),
            limits,
        })
    }

    pub fn start_with_control(
        engine: &WasmBinaryReductorEngine,
        limits: BinaryIrLimits,
        cancellation: CancellationToken,
        object_deadline: Instant,
    ) -> Result<Self, S4Error> {
        let session = engine.start_session_with_control(cancellation, object_deadline)?;
        Ok(Self {
            session,
            owner: ReductorOwner(Arc::from(engine.component_digest())),
            limits,
        })
    }

    pub fn component_digest(&self) -> &str {
        self.owner
            .component_digest()
            .expect("Wasm reductors always have a component digest")
    }

    pub fn fuel_consumed(&self) -> u64 {
        self.session.fuel_consumed()
    }
}

impl BinaryReductor for WasmBinaryReductor {
    fn plan(&mut self, source_schema: &SchemaIr) -> Result<BinaryReductionPlan, S4Error> {
        source_schema.validate(self.limits)?;
        let source_encoded = source_schema.to_canonical_json(self.limits)?;
        let planned = self.session.plan(&source_encoded)?;
        let claims = canonicalize_claims(convert_wasm_claims(planned.claims))?;
        validate_claims_against_schema(source_schema, &claims)?;
        let reduced_schema =
            SchemaIr::from_canonical_json(&planned.reduced_schema_ir, self.limits)?;
        ensure_schema_changes_are_claimed(source_schema, &reduced_schema, &claims)?;

        BinaryReductionPlan::new(
            self.owner.clone(),
            source_schema.clone(),
            reduced_schema,
            claims.clone(),
            claims,
            planned.plan,
            self.limits,
        )
    }

    fn plan_restore(
        &mut self,
        plan: &BinaryReductionPlan,
        transformed_reduced_schema: &SchemaIr,
    ) -> Result<BinaryRestorePlan, S4Error> {
        ensure_owner(plan, &self.owner)?;
        transformed_reduced_schema.validate(self.limits)?;
        let source_encoded = plan.source_schema().to_canonical_json(self.limits)?;
        let transformed_encoded = transformed_reduced_schema.to_canonical_json(self.limits)?;
        let planned =
            self.session
                .plan_restore(&source_encoded, &transformed_encoded, plan.opaque_plan())?;
        let output_schema = SchemaIr::from_canonical_json(&planned.output_schema_ir, self.limits)?;
        ensure_schema_changes_are_claimed(
            transformed_reduced_schema,
            &output_schema,
            plan.claims(),
        )?;

        BinaryRestorePlan::new(
            plan,
            transformed_reduced_schema.clone(),
            output_schema,
            planned.restore_plan,
            self.limits,
        )
    }

    fn reduce(
        &mut self,
        plan: &BinaryReductionPlan,
        source_value: &ValueIr,
    ) -> Result<ValueIr, S4Error> {
        ensure_owner(plan, &self.owner)?;
        source_value.validate(plan.source_schema(), self.limits)?;
        let source_encoded = source_value.to_canonical_json(plan.source_schema(), self.limits)?;
        let reduced_encoded = self.session.reduce(plan.opaque_plan(), &source_encoded)?;
        ValueIr::from_canonical_json(&reduced_encoded, plan.reduced_schema(), self.limits)
    }

    fn restore(
        &mut self,
        plan: &BinaryRestorePlan,
        transformed_value: &ValueIr,
    ) -> Result<ValueIr, S4Error> {
        ensure_owner(&plan.reduction, &self.owner)?;
        transformed_value.validate(plan.transformed_reduced_schema(), self.limits)?;
        let transformed_encoded =
            transformed_value.to_canonical_json(plan.transformed_reduced_schema(), self.limits)?;
        let restored_encoded = self
            .session
            .restore(plan.opaque_restore_plan(), &transformed_encoded)?;
        ValueIr::from_canonical_json(&restored_encoded, plan.output_schema(), self.limits)
    }
}

fn convert_wasm_claims(
    claims: Vec<s4_wasm_runtime::BinaryReductorClaim>,
) -> Vec<BinaryReductorClaim> {
    claims
        .into_iter()
        .map(|claim| {
            BinaryReductorClaim::new(
                SchemaPath(
                    claim
                        .path
                        .into_iter()
                        .map(|segment| match segment {
                            WasmBinaryReductorPathSegment::Field(name) => {
                                SchemaPathSegment::Field(name)
                            }
                            WasmBinaryReductorPathSegment::ArrayElement => {
                                SchemaPathSegment::ArrayElement
                            }
                            WasmBinaryReductorPathSegment::MapValue => SchemaPathSegment::MapValue,
                            WasmBinaryReductorPathSegment::LogicalValue => {
                                SchemaPathSegment::LogicalValue
                            }
                        })
                        .collect(),
                ),
                claim.type_id,
            )
        })
        .collect()
}

fn validate_claims_against_schema(
    schema: &SchemaIr,
    claims: &[BinaryReductorClaim],
) -> Result<(), S4Error> {
    for claim in claims {
        let node = schema.node_at_path(claim.path()).ok_or_else(|| {
            claim_error(format!(
                "reductor claimed nonexistent schema path {}",
                claim.path()
            ))
        })?;
        match &node.kind {
            SchemaKind::Custom { type_id, .. } if type_id == claim.type_id() => {}
            SchemaKind::Custom { type_id, .. } => {
                return Err(claim_error(format!(
                    "reductor claimed type {:?} at {}, but the schema declares {:?}",
                    claim.type_id(),
                    claim.path(),
                    type_id
                )));
            }
            SchemaKind::Record { .. } => {}
            _ => {
                return Err(claim_error(format!(
                    "reductor claim at {} must target a custom logical value or record",
                    claim.path()
                )));
            }
        }
    }
    Ok(())
}

fn ensure_schema_changes_are_claimed(
    source: &SchemaIr,
    transformed: &SchemaIr,
    claims: &[BinaryReductorClaim],
) -> Result<(), S4Error> {
    let mut path = SchemaPath::root();
    ensure_node_changes_are_claimed(&source.root, &transformed.root, claims, &mut path)
}

fn ensure_node_changes_are_claimed(
    source: &crate::binary_ir::SchemaNode,
    transformed: &crate::binary_ir::SchemaNode,
    claims: &[BinaryReductorClaim],
    path: &mut SchemaPath,
) -> Result<(), S4Error> {
    if claims
        .iter()
        .any(|claim| path_is_prefix(claim.path(), path))
    {
        return Ok(());
    }
    if source.nullable != transformed.nullable {
        return Err(unclaimed_schema_change(path));
    }
    match (&source.kind, &transformed.kind) {
        (SchemaKind::Array { items: source }, SchemaKind::Array { items: transformed }) => {
            path.0.push(SchemaPathSegment::ArrayElement);
            let result = ensure_node_changes_are_claimed(source, transformed, claims, path);
            path.0.pop();
            result
        }
        (
            SchemaKind::Map { values: source },
            SchemaKind::Map {
                values: transformed,
            },
        ) => {
            path.0.push(SchemaPathSegment::MapValue);
            let result = ensure_node_changes_are_claimed(source, transformed, claims, path);
            path.0.pop();
            result
        }
        (
            SchemaKind::Record {
                fields: source_fields,
            },
            SchemaKind::Record {
                fields: transformed_fields,
            },
        ) => {
            if source_fields.len() != transformed_fields.len() {
                return Err(unclaimed_schema_change(path));
            }
            for (source_field, transformed_field) in source_fields.iter().zip(transformed_fields) {
                if source_field.name != transformed_field.name {
                    return Err(unclaimed_schema_change(path));
                }
                path.0
                    .push(SchemaPathSegment::Field(source_field.name.clone()));
                let result = ensure_node_changes_are_claimed(
                    &source_field.schema,
                    &transformed_field.schema,
                    claims,
                    path,
                );
                path.0.pop();
                result?;
            }
            Ok(())
        }
        (
            SchemaKind::Custom {
                type_id: source_type,
                value: source_value,
            },
            SchemaKind::Custom {
                type_id: transformed_type,
                value: transformed_value,
            },
        ) if source_type == transformed_type => {
            path.0.push(SchemaPathSegment::LogicalValue);
            let result =
                ensure_node_changes_are_claimed(source_value, transformed_value, claims, path);
            path.0.pop();
            result
        }
        _ if source == transformed => Ok(()),
        _ => Err(unclaimed_schema_change(path)),
    }
}

fn unclaimed_schema_change(path: &SchemaPath) -> S4Error {
    plan_error(format!(
        "reductor changed schema outside its declared claims at {path}"
    ))
}

fn reject_unclaimed_custom_nodes(
    schema: &SchemaIr,
    claims: &[BinaryReductorClaim],
) -> Result<(), S4Error> {
    let mut unclaimed = None;
    schema.visit_paths(|path, node| {
        if unclaimed.is_none()
            && matches!(node.kind, SchemaKind::Custom { .. })
            && !claims.iter().any(|claim| path_is_prefix(&claim.path, path))
        {
            unclaimed = Some(path.clone());
        }
    });
    if let Some(path) = unclaimed {
        return Err(claim_error(format!(
            "custom schema node at {path} is not claimed by a reductor"
        )));
    }
    Ok(())
}

fn canonicalize_claims(
    mut claims: Vec<BinaryReductorClaim>,
) -> Result<Vec<BinaryReductorClaim>, S4Error> {
    claims.sort_by(compare_claims);
    for pair in claims.windows(2) {
        if pair[0].path == pair[1].path {
            return Err(claim_error(
                "binary reductor returned duplicate claim paths",
            ));
        }
        if path_is_prefix(&pair[0].path, &pair[1].path) {
            return Err(claim_error(
                "binary reductor returned prefix-overlapping claim paths",
            ));
        }
    }
    Ok(claims)
}

fn compare_claims(left: &BinaryReductorClaim, right: &BinaryReductorClaim) -> Ordering {
    compare_paths(&left.path, &right.path).then_with(|| left.type_id.cmp(&right.type_id))
}

fn compare_paths(left: &SchemaPath, right: &SchemaPath) -> Ordering {
    for (left, right) in left.segments().iter().zip(right.segments()) {
        let ordering = compare_path_segments(left, right);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.segments().len().cmp(&right.segments().len())
}

fn compare_path_segments(left: &SchemaPathSegment, right: &SchemaPathSegment) -> Ordering {
    fn rank(segment: &SchemaPathSegment) -> u8 {
        match segment {
            SchemaPathSegment::Field(_) => 0,
            SchemaPathSegment::ArrayElement => 1,
            SchemaPathSegment::MapValue => 2,
            SchemaPathSegment::LogicalValue => 3,
        }
    }

    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (SchemaPathSegment::Field(left), SchemaPathSegment::Field(right)) => left.cmp(right),
            _ => Ordering::Equal,
        })
}

fn path_is_prefix(prefix: &SchemaPath, path: &SchemaPath) -> bool {
    path.segments().starts_with(prefix.segments())
}

fn ensure_owner(plan: &BinaryReductionPlan, expected: &ReductorOwner) -> Result<(), S4Error> {
    if &plan.owner != expected {
        return Err(plan_error(format!(
            "plan belongs to {} instead of {}",
            plan.owner.stable_id(),
            expected.stable_id()
        )));
    }
    Ok(())
}

fn claim_error(message: impl Into<String>) -> S4Error {
    S4Error::new(codes::WASM_REDUCTOR_CLAIM, message)
}

fn plan_error(message: impl Into<String>) -> S4Error {
    S4Error::new(codes::WASM_REDUCTOR_PLAN, message)
}

fn hash_reduction_plan(
    owner: &ReductorOwner,
    source_schema: &[u8],
    reduced_schema: &[u8],
    claims: &[BinaryReductorClaim],
    custom_coverage: &[BinaryReductorClaim],
    opaque_plan: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, PLAN_HASH_DOMAIN);
    hash_part(&mut hasher, owner.stable_id().as_bytes());
    hash_part(&mut hasher, source_schema);
    hash_part(&mut hasher, reduced_schema);
    hash_claims(&mut hasher, claims);
    hash_claims(&mut hasher, custom_coverage);
    hash_part(&mut hasher, opaque_plan);
    hasher.finalize().into()
}

fn hash_claims(hasher: &mut Sha256, claims: &[BinaryReductorClaim]) {
    hash_part(hasher, &usize_bytes(claims.len()));
    for claim in claims {
        hash_part(hasher, claim.type_id.as_bytes());
        hash_part(hasher, &usize_bytes(claim.path.segments().len()));
        for segment in claim.path.segments() {
            match segment {
                SchemaPathSegment::Field(name) => {
                    hash_part(hasher, b"field");
                    hash_part(hasher, name.as_bytes());
                }
                SchemaPathSegment::ArrayElement => hash_part(hasher, b"array-element"),
                SchemaPathSegment::MapValue => hash_part(hasher, b"map-value"),
                SchemaPathSegment::LogicalValue => hash_part(hasher, b"logical-value"),
            }
        }
    }
}

fn hash_parts<'a>(domain: &[u8], parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, domain);
    for part in parts {
        hash_part(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

fn usize_bytes(value: usize) -> [u8; 8] {
    u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;
    use crate::binary_ir::{MapEntry, SchemaField, SchemaNode, Value, ValueField};

    fn required(kind: SchemaKind) -> SchemaNode {
        SchemaNode::required(kind)
    }

    fn field(name: &str, kind: SchemaKind) -> SchemaField {
        SchemaField {
            name: name.to_string(),
            schema: required(kind),
        }
    }

    fn common_schema() -> SchemaIr {
        SchemaIr::new(required(SchemaKind::Record {
            fields: vec![
                field("id", SchemaKind::I64),
                field("name", SchemaKind::String),
                field("day", SchemaKind::Date),
                field(
                    "amount",
                    SchemaKind::Decimal {
                        precision: 8,
                        scale: 2,
                    },
                ),
                SchemaField {
                    name: "flags".to_string(),
                    schema: required(SchemaKind::Map {
                        values: Box::new(required(SchemaKind::Boolean)),
                    }),
                },
            ],
        }))
    }

    fn common_value() -> ValueIr {
        ValueIr::new(Value::Record {
            fields: vec![
                ValueField {
                    name: "id".to_string(),
                    value: Value::I64 { value: 42 },
                },
                ValueField {
                    name: "name".to_string(),
                    value: Value::String {
                        value: "Ada".to_string(),
                    },
                },
                ValueField {
                    name: "day".to_string(),
                    value: Value::Date {
                        value: "2026-08-30".to_string(),
                    },
                },
                ValueField {
                    name: "amount".to_string(),
                    value: Value::Decimal {
                        value: "1234.50".to_string(),
                    },
                },
                ValueField {
                    name: "flags".to_string(),
                    value: Value::Map {
                        entries: vec![MapEntry {
                            key: "active".to_string(),
                            value: Value::Boolean { value: true },
                        }],
                    },
                },
            ],
        })
    }

    fn custom_schema() -> SchemaIr {
        SchemaIr::new(required(SchemaKind::Record {
            fields: vec![SchemaField {
                name: "money".to_string(),
                schema: required(SchemaKind::Custom {
                    type_id: "vendor.money".to_string(),
                    value: Box::new(required(SchemaKind::String)),
                }),
            }],
        }))
    }

    fn guest_custom_schema() -> SchemaIr {
        SchemaIr::new(required(SchemaKind::Custom {
            type_id: "vendor.money".to_string(),
            value: Box::new(required(SchemaKind::String)),
        }))
    }

    fn guest_custom_value() -> ValueIr {
        ValueIr::new(Value::Custom {
            type_id: "vendor.money".to_string(),
            value: Box::new(Value::String {
                value: "12.34".to_string(),
            }),
        })
    }

    fn test_reductor_component() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-components")
            .join("test-binary-reductor.component.wasm");
        std::fs::read(path).expect("test component missing; run just build-filters")
    }

    #[test]
    fn trait_is_object_safe() {
        fn accept(_: &mut dyn BinaryReductor) {}
        accept(&mut CommonTypeBinaryReductor::default());
    }

    #[test]
    fn common_identity_round_trips_common_schema_values() {
        let schema = common_schema();
        let value = common_value();
        let mut reductor = CommonTypeBinaryReductor::default();

        let plan = reductor.plan(&schema).unwrap();
        assert_eq!(plan.source_schema(), &schema);
        assert_eq!(plan.reduced_schema(), &schema);
        assert!(plan.claims().is_empty());
        assert!(plan.opaque_plan().is_empty());
        assert!(plan.component_digest().is_none());

        let reduced = reductor.reduce(&plan, &value).unwrap();
        assert_eq!(reduced, value);
        let restore_plan = reductor.plan_restore(&plan, &schema).unwrap();
        let restored = reductor.restore(&restore_plan, &reduced).unwrap();
        assert_eq!(restored, value);
        assert_eq!(restore_plan.output_schema(), &schema);
        assert_ne!(plan.plan_hash(), restore_plan.plan_hash());
    }

    #[test]
    fn common_identity_rejects_unclaimed_custom_types() {
        let error = CommonTypeBinaryReductor::default()
            .plan(&custom_schema())
            .unwrap_err();
        assert_eq!(error.code(), codes::WASM_REDUCTOR_CLAIM);
        assert!(error.message().contains("$.money"));
    }

    #[test]
    fn common_identity_rejects_values_that_do_not_match_the_plan_schema() {
        let schema = SchemaIr::new(required(SchemaKind::String));
        let invalid = ValueIr::new(Value::I32 { value: 7 });
        let mut reductor = CommonTypeBinaryReductor::default();
        let plan = reductor.plan(&schema).unwrap();
        assert!(reductor.reduce(&plan, &invalid).is_err());

        let restore_plan = reductor.plan_restore(&plan, &schema).unwrap();
        assert!(reductor.restore(&restore_plan, &invalid).is_err());
    }

    #[test]
    fn plans_are_bound_to_the_reductor_owner() {
        let schema = common_schema();
        let plan = BinaryReductionPlan::new(
            ReductorOwner(Arc::from("test-component")),
            schema.clone(),
            schema.clone(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            BinaryIrLimits::default(),
        )
        .unwrap();
        let mut common = CommonTypeBinaryReductor::default();
        let error = common.plan_restore(&plan, &schema).unwrap_err();
        assert_eq!(error.code(), codes::WASM_REDUCTOR_PLAN);
    }

    #[test]
    fn plan_hashes_are_stable_and_input_sensitive() {
        let schema = common_schema();
        let mut reductor = CommonTypeBinaryReductor::default();
        let first = reductor.plan(&schema).unwrap();
        let second = reductor.plan(&schema).unwrap();
        assert_eq!(first.plan_hash(), second.plan_hash());
        assert_eq!(first.plan_hash_hex().len(), 64);

        let other = reductor
            .plan(&SchemaIr::new(required(SchemaKind::String)))
            .unwrap();
        assert_ne!(first.plan_hash(), other.plan_hash());
    }

    #[test]
    fn wasm_adapter_validates_and_round_trips_custom_values() {
        let engine = WasmBinaryReductorEngine::new(&test_reductor_component()).unwrap();
        let mut reductor = WasmBinaryReductor::start(&engine, BinaryIrLimits::default()).unwrap();
        let source_schema = guest_custom_schema();
        let source_value = guest_custom_value();

        let plan = reductor.plan(&source_schema).unwrap();
        assert_eq!(plan.claims().len(), 1);
        assert_eq!(plan.claims()[0].path(), &SchemaPath::root());
        assert_eq!(plan.claims()[0].type_id(), "vendor.money");
        assert_eq!(plan.component_digest(), Some(engine.component_digest()));
        assert_eq!(plan.reduced_schema().root.kind, SchemaKind::String);

        let reduced = reductor.reduce(&plan, &source_value).unwrap();
        assert_eq!(
            reduced,
            ValueIr::new(Value::String {
                value: "12.34".to_string(),
            })
        );

        let restore_plan = reductor.plan_restore(&plan, plan.reduced_schema()).unwrap();
        let restored = reductor.restore(&restore_plan, &reduced).unwrap();
        assert_eq!(restored, source_value);
        assert_eq!(restore_plan.output_schema(), &source_schema);
        assert!(reductor.fuel_consumed() > 0);
    }

    #[test]
    fn wasm_adapter_rejects_claims_that_do_not_match_the_source_schema() {
        let engine = WasmBinaryReductorEngine::new(&test_reductor_component()).unwrap();
        let mut reductor = WasmBinaryReductor::start(&engine, BinaryIrLimits::default()).unwrap();

        let error = reductor.plan(&custom_schema()).unwrap_err();
        assert_eq!(error.code(), codes::WASM_REDUCTOR_CLAIM);
        assert!(error.message().contains("$.custom"));
    }

    #[test]
    fn schema_changes_outside_wasm_claims_are_rejected() {
        let source = SchemaIr::new(required(SchemaKind::String));
        let transformed = SchemaIr::new(required(SchemaKind::I64));

        let error = ensure_schema_changes_are_claimed(&source, &transformed, &[]).unwrap_err();
        assert_eq!(error.code(), codes::WASM_REDUCTOR_PLAN);
        assert!(error.message().contains('$'));
    }

    #[test]
    fn schema_changes_inside_a_wasm_claim_are_allowed() {
        let source = guest_custom_schema();
        let transformed = SchemaIr::new(required(SchemaKind::String));
        let claims = vec![BinaryReductorClaim::new(SchemaPath::root(), "vendor.money")];

        ensure_schema_changes_are_claimed(&source, &transformed, &claims).unwrap();
    }
}
