use std::time::Instant;

use s4_error::{S4Error, codes};
use sha2::{Digest, Sha256};

use super::binary_reductor_bindings::{
    BinaryReductor, Claim, PathSegment, PlannedReduction, PlannedRestoration, ReductorError,
};
use super::{
    CancellationToken, DEFAULT_FUEL, RuntimeCapabilityProfile, RuntimeComponent, RuntimeLimits,
    RuntimeSession, validate_runtime_limits,
};

pub const DEFAULT_MAX_BINARY_REDUCTOR_PLAN_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_BINARY_REDUCTOR_COMPONENT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_BINARY_REDUCTOR_SCHEMA_IR_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_BINARY_REDUCTOR_VALUE_IR_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_BINARY_REDUCTOR_CLAIMS: usize = 4096;
pub const DEFAULT_MAX_BINARY_REDUCTOR_CLAIM_PATH_DEPTH: usize = 8;
pub const DEFAULT_MAX_BINARY_REDUCTOR_IDENTIFIER_BYTES: usize = 256;
pub const DEFAULT_MAX_BINARY_REDUCTOR_GUEST_DIAGNOSTIC_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug)]
pub struct BinaryReductorConfig {
    pub runtime_limits: RuntimeLimits,
    pub max_component_bytes: usize,
    pub max_plan_bytes: usize,
    pub max_schema_ir_bytes: usize,
    pub max_value_ir_bytes: usize,
    pub max_claims: usize,
    pub max_claim_path_depth: usize,
    pub max_identifier_bytes: usize,
    pub max_guest_diagnostic_bytes: usize,
}

impl Default for BinaryReductorConfig {
    fn default() -> Self {
        Self {
            runtime_limits: RuntimeLimits::default(),
            max_component_bytes: DEFAULT_MAX_BINARY_REDUCTOR_COMPONENT_BYTES,
            max_plan_bytes: DEFAULT_MAX_BINARY_REDUCTOR_PLAN_BYTES,
            max_schema_ir_bytes: DEFAULT_MAX_BINARY_REDUCTOR_SCHEMA_IR_BYTES,
            max_value_ir_bytes: DEFAULT_MAX_BINARY_REDUCTOR_VALUE_IR_BYTES,
            max_claims: DEFAULT_MAX_BINARY_REDUCTOR_CLAIMS,
            max_claim_path_depth: DEFAULT_MAX_BINARY_REDUCTOR_CLAIM_PATH_DEPTH,
            max_identifier_bytes: DEFAULT_MAX_BINARY_REDUCTOR_IDENTIFIER_BYTES,
            max_guest_diagnostic_bytes: DEFAULT_MAX_BINARY_REDUCTOR_GUEST_DIAGNOSTIC_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BinaryReductorBoundaryLimits {
    max_plan_bytes: usize,
    max_schema_ir_bytes: usize,
    max_value_ir_bytes: usize,
    max_claims: usize,
    max_claim_path_depth: usize,
    max_identifier_bytes: usize,
    max_guest_diagnostic_bytes: usize,
}

impl From<&BinaryReductorConfig> for BinaryReductorBoundaryLimits {
    fn from(config: &BinaryReductorConfig) -> Self {
        Self {
            max_plan_bytes: config.max_plan_bytes,
            max_schema_ir_bytes: config.max_schema_ir_bytes,
            max_value_ir_bytes: config.max_value_ir_bytes,
            max_claims: config.max_claims,
            max_claim_path_depth: config.max_claim_path_depth,
            max_identifier_bytes: config.max_identifier_bytes,
            max_guest_diagnostic_bytes: config.max_guest_diagnostic_bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryReductorClaim {
    pub path: Vec<BinaryReductorPathSegment>,
    pub type_id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BinaryReductorPathSegment {
    Field(String),
    ArrayElement,
    MapValue,
    LogicalValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryReductorPlan {
    pub claims: Vec<BinaryReductorClaim>,
    pub reduced_schema_ir: Vec<u8>,
    pub plan: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryReductorRestorationPlan {
    pub output_schema_ir: Vec<u8>,
    pub restore_plan: Vec<u8>,
}

pub struct BinaryReductorEngine {
    runtime: RuntimeComponent,
    boundary_limits: BinaryReductorBoundaryLimits,
    component_digest: String,
}

pub struct BinaryReductorSession {
    runtime: RuntimeSession,
    funcs: BinaryReductor,
    boundary_limits: BinaryReductorBoundaryLimits,
}

impl BinaryReductorEngine {
    pub fn new(component_bytes: &[u8]) -> Result<Self, S4Error> {
        Self::with_fuel(component_bytes, DEFAULT_FUEL)
    }

    pub fn with_fuel(component_bytes: &[u8], fuel: u64) -> Result<Self, S4Error> {
        Self::with_config(
            component_bytes,
            BinaryReductorConfig {
                runtime_limits: RuntimeLimits {
                    cumulative_fuel: fuel,
                    per_call_fuel: fuel,
                    ..RuntimeLimits::default()
                },
                ..BinaryReductorConfig::default()
            },
        )
    }

    pub fn with_limits(
        component_bytes: &[u8],
        runtime_limits: RuntimeLimits,
    ) -> Result<Self, S4Error> {
        Self::with_config(
            component_bytes,
            BinaryReductorConfig {
                runtime_limits,
                ..BinaryReductorConfig::default()
            },
        )
    }

    pub fn with_config(
        component_bytes: &[u8],
        config: BinaryReductorConfig,
    ) -> Result<Self, S4Error> {
        validate_config(&config)?;
        validate_component_bytes(component_bytes, config.max_component_bytes)?;
        let boundary_limits = BinaryReductorBoundaryLimits::from(&config);
        let runtime = RuntimeComponent::compile(
            component_bytes,
            config.runtime_limits,
            RuntimeCapabilityProfile::NoHostImports,
        )
        .map_err(|error| S4Error::new(codes::COMPONENT_LOAD, error.to_string()))?;
        Ok(Self {
            runtime,
            boundary_limits,
            component_digest: sha256_hex(component_bytes),
        })
    }

    pub fn component_digest(&self) -> &str {
        &self.component_digest
    }

    pub fn guest_memory_limit(&self) -> usize {
        self.runtime.limits.guest_memory_bytes
    }

    pub fn cumulative_fuel_limit(&self) -> u64 {
        self.runtime.limits.cumulative_fuel
    }

    pub fn start_session(&self) -> Result<BinaryReductorSession, S4Error> {
        self.start_session_with_cancellation(CancellationToken::new())
    }

    pub fn start_session_with_cancellation(
        &self,
        cancellation: CancellationToken,
    ) -> Result<BinaryReductorSession, S4Error> {
        self.start_session_with_control(
            cancellation,
            Instant::now() + self.runtime.limits.object_timeout,
        )
    }

    pub fn start_session_with_control(
        &self,
        cancellation: CancellationToken,
        object_deadline: Instant,
    ) -> Result<BinaryReductorSession, S4Error> {
        let initial_fuel = self.runtime.limits.cumulative_fuel;
        let (mut runtime, instance) = self.runtime.instantiate(
            cancellation,
            object_deadline,
            initial_fuel,
            // NoHostImports: no WASI linker is registered, so the WasiCtx is
            // never used. Build the hardened empty context for symmetry.
            wasmtime_wasi::WasiCtxBuilder::new().build(),
        )?;
        let funcs = BinaryReductor::new(&mut runtime.store, &instance).map_err(|error| {
            super::startup_error(
                codes::WIT_INVALID,
                error,
                &runtime.cancellation,
                runtime.object_deadline,
            )
        })?;
        Ok(BinaryReductorSession {
            runtime,
            funcs,
            boundary_limits: self.boundary_limits,
        })
    }
}

impl BinaryReductorSession {
    pub fn plan(&mut self, source_schema_ir: &[u8]) -> Result<BinaryReductorPlan, S4Error> {
        self.plan_with_fuel_limit(source_schema_ir, u64::MAX)
    }

    pub fn plan_with_fuel_limit(
        &mut self,
        source_schema_ir: &[u8],
        fuel_limit: u64,
    ) -> Result<BinaryReductorPlan, S4Error> {
        validate_ir_bytes(
            "source Schema IR",
            source_schema_ir,
            self.boundary_limits.max_schema_ir_bytes,
        )?;
        let window = self.runtime.prepare_call(fuel_limit)?;
        let result = self
            .funcs
            .call_plan(&mut self.runtime.store, source_schema_ir);
        let planned = self
            .runtime
            .complete_call(window, result, "reductor plan", codes::WASM_TRAP)?
            .map_err(|error| {
                guest_error(
                    "plan",
                    error,
                    self.boundary_limits.max_guest_diagnostic_bytes,
                )
            })?;
        validate_plan_blob(&planned.plan, self.boundary_limits.max_plan_bytes)?;
        validate_ir_bytes(
            "reduced Schema IR",
            &planned.reduced_schema_ir,
            self.boundary_limits.max_schema_ir_bytes,
        )?;
        if planned.claims.len() > self.boundary_limits.max_claims {
            return Err(claim_limit_error(
                planned.claims.len(),
                self.boundary_limits.max_claims,
            ));
        }
        let planned = convert_plan(planned);
        validate_claims(&planned.claims, self.boundary_limits)?;
        Ok(planned)
    }

    pub fn plan_restore(
        &mut self,
        source_schema_ir: &[u8],
        transformed_reduced_schema_ir: &[u8],
        plan: &[u8],
    ) -> Result<BinaryReductorRestorationPlan, S4Error> {
        self.plan_restore_with_fuel_limit(
            source_schema_ir,
            transformed_reduced_schema_ir,
            plan,
            u64::MAX,
        )
    }

    pub fn plan_restore_with_fuel_limit(
        &mut self,
        source_schema_ir: &[u8],
        transformed_reduced_schema_ir: &[u8],
        plan: &[u8],
        fuel_limit: u64,
    ) -> Result<BinaryReductorRestorationPlan, S4Error> {
        validate_ir_bytes(
            "source Schema IR",
            source_schema_ir,
            self.boundary_limits.max_schema_ir_bytes,
        )?;
        validate_ir_bytes(
            "transformed reduced Schema IR",
            transformed_reduced_schema_ir,
            self.boundary_limits.max_schema_ir_bytes,
        )?;
        validate_plan_blob(plan, self.boundary_limits.max_plan_bytes)?;
        let window = self.runtime.prepare_call(fuel_limit)?;
        let result = self.funcs.call_plan_restore(
            &mut self.runtime.store,
            source_schema_ir,
            transformed_reduced_schema_ir,
            plan,
        );
        let planned = self
            .runtime
            .complete_call(window, result, "reductor plan-restore", codes::WASM_TRAP)?
            .map_err(|error| {
                guest_error(
                    "plan-restore",
                    error,
                    self.boundary_limits.max_guest_diagnostic_bytes,
                )
            })?;
        validate_ir_bytes(
            "restored Schema IR",
            &planned.output_schema_ir,
            self.boundary_limits.max_schema_ir_bytes,
        )?;
        validate_plan_blob(&planned.restore_plan, self.boundary_limits.max_plan_bytes)?;
        Ok(convert_restoration_plan(planned))
    }

    pub fn reduce(&mut self, plan: &[u8], source_value_ir: &[u8]) -> Result<Vec<u8>, S4Error> {
        self.reduce_with_fuel_limit(plan, source_value_ir, u64::MAX)
    }

    pub fn reduce_with_fuel_limit(
        &mut self,
        plan: &[u8],
        source_value_ir: &[u8],
        fuel_limit: u64,
    ) -> Result<Vec<u8>, S4Error> {
        validate_plan_blob(plan, self.boundary_limits.max_plan_bytes)?;
        validate_ir_bytes(
            "source Value IR",
            source_value_ir,
            self.boundary_limits.max_value_ir_bytes,
        )?;
        let window = self.runtime.prepare_call(fuel_limit)?;
        let result = self
            .funcs
            .call_reduce(&mut self.runtime.store, plan, source_value_ir);
        let value_ir = self
            .runtime
            .complete_call(window, result, "reductor reduce", codes::WASM_TRAP)?
            .map_err(|error| {
                guest_error(
                    "reduce",
                    error,
                    self.boundary_limits.max_guest_diagnostic_bytes,
                )
            })?;
        validate_ir_bytes(
            "reduced Value IR",
            &value_ir,
            self.boundary_limits.max_value_ir_bytes,
        )?;
        Ok(value_ir)
    }

    pub fn restore(
        &mut self,
        restore_plan: &[u8],
        transformed_value_ir: &[u8],
    ) -> Result<Vec<u8>, S4Error> {
        self.restore_with_fuel_limit(restore_plan, transformed_value_ir, u64::MAX)
    }

    pub fn restore_with_fuel_limit(
        &mut self,
        restore_plan: &[u8],
        transformed_value_ir: &[u8],
        fuel_limit: u64,
    ) -> Result<Vec<u8>, S4Error> {
        validate_plan_blob(restore_plan, self.boundary_limits.max_plan_bytes)?;
        validate_ir_bytes(
            "transformed Value IR",
            transformed_value_ir,
            self.boundary_limits.max_value_ir_bytes,
        )?;
        let window = self.runtime.prepare_call(fuel_limit)?;
        let result =
            self.funcs
                .call_restore(&mut self.runtime.store, restore_plan, transformed_value_ir);
        let value_ir = self
            .runtime
            .complete_call(window, result, "reductor restore", codes::WASM_TRAP)?
            .map_err(|error| {
                guest_error(
                    "restore",
                    error,
                    self.boundary_limits.max_guest_diagnostic_bytes,
                )
            })?;
        validate_ir_bytes(
            "restored Value IR",
            &value_ir,
            self.boundary_limits.max_value_ir_bytes,
        )?;
        Ok(value_ir)
    }

    pub fn fuel_consumed(&self) -> u64 {
        self.runtime.fuel_consumed
    }
}

fn validate_config(config: &BinaryReductorConfig) -> Result<(), S4Error> {
    validate_runtime_limits(&config.runtime_limits)
        .map_err(|error| S4Error::new(codes::CONFIG_INVALID, error.to_string()))?;
    let limits = [
        ("component bytes", config.max_component_bytes),
        ("plan bytes", config.max_plan_bytes),
        ("Schema IR bytes", config.max_schema_ir_bytes),
        ("Value IR bytes", config.max_value_ir_bytes),
        ("claims", config.max_claims),
        ("claim path depth", config.max_claim_path_depth),
        ("identifier bytes", config.max_identifier_bytes),
        ("guest diagnostic bytes", config.max_guest_diagnostic_bytes),
    ];
    if let Some((name, _)) = limits.into_iter().find(|(_, value)| *value == 0) {
        return Err(S4Error::new(
            codes::CONFIG_INVALID,
            format!("Wasm binary reductor {name} limit must be greater than zero"),
        ));
    }
    Ok(())
}

fn validate_component_bytes(component: &[u8], max_component_bytes: usize) -> Result<(), S4Error> {
    if component.len() > max_component_bytes {
        return Err(S4Error::new(
            codes::WASM_REDUCTOR_LIMIT,
            format!(
                "Wasm binary reductor component is {} bytes; limit is {max_component_bytes}",
                component.len()
            ),
        ));
    }
    Ok(())
}

fn validate_plan_blob(plan: &[u8], max_plan_bytes: usize) -> Result<(), S4Error> {
    if plan.len() > max_plan_bytes {
        return Err(S4Error::new(
            codes::WASM_REDUCTOR_PLAN,
            format!(
                "Wasm binary reductor plan is {} bytes; limit is {max_plan_bytes}",
                plan.len()
            ),
        ));
    }
    Ok(())
}

fn validate_ir_bytes(kind: &str, bytes: &[u8], max_bytes: usize) -> Result<(), S4Error> {
    if bytes.len() > max_bytes {
        return Err(S4Error::new(
            codes::WASM_REDUCTOR_LIMIT,
            format!(
                "Wasm binary reductor {kind} is {} bytes; limit is {max_bytes}",
                bytes.len()
            ),
        ));
    }
    Ok(())
}

fn validate_claims(
    claims: &[BinaryReductorClaim],
    limits: BinaryReductorBoundaryLimits,
) -> Result<(), S4Error> {
    if claims.len() > limits.max_claims {
        return Err(claim_limit_error(claims.len(), limits.max_claims));
    }

    for (index, claim) in claims.iter().enumerate() {
        validate_identifier(
            "type ID",
            &claim.type_id,
            limits.max_identifier_bytes,
            index,
        )?;
        if claim.path.len() > limits.max_claim_path_depth {
            return Err(S4Error::new(
                codes::WASM_REDUCTOR_CLAIM,
                format!(
                    "Wasm binary reductor claim {index} path depth is {}; limit is {}",
                    claim.path.len(),
                    limits.max_claim_path_depth
                ),
            ));
        }
        for segment in &claim.path {
            if let BinaryReductorPathSegment::Field(name) = segment {
                validate_identifier("field", name, limits.max_identifier_bytes, index)?;
            }
        }
    }

    let mut paths: Vec<&[BinaryReductorPathSegment]> =
        claims.iter().map(|claim| claim.path.as_slice()).collect();
    paths.sort_unstable();
    for pair in paths.windows(2) {
        if pair[0] == pair[1] {
            return Err(S4Error::new(
                codes::WASM_REDUCTOR_CLAIM,
                "Wasm binary reductor returned duplicate claim paths",
            ));
        }
        if pair[1].starts_with(pair[0]) {
            return Err(S4Error::new(
                codes::WASM_REDUCTOR_CLAIM,
                "Wasm binary reductor returned prefix-overlapping claim paths",
            ));
        }
    }
    Ok(())
}

fn claim_limit_error(actual: usize, limit: usize) -> S4Error {
    S4Error::new(
        codes::WASM_REDUCTOR_CLAIM,
        format!("Wasm binary reductor returned {actual} claims; limit is {limit}"),
    )
}

fn validate_identifier(
    kind: &str,
    identifier: &str,
    max_bytes: usize,
    claim_index: usize,
) -> Result<(), S4Error> {
    if identifier.is_empty() {
        return Err(S4Error::new(
            codes::WASM_REDUCTOR_CLAIM,
            format!("Wasm binary reductor claim {claim_index} has an empty {kind}"),
        ));
    }
    if identifier.len() > max_bytes {
        return Err(S4Error::new(
            codes::WASM_REDUCTOR_CLAIM,
            format!(
                "Wasm binary reductor claim {claim_index} {kind} is {} bytes; limit is {max_bytes}",
                identifier.len()
            ),
        ));
    }
    Ok(())
}

fn guest_error(stage: &str, error: ReductorError, max_diagnostic_bytes: usize) -> S4Error {
    if error.code.is_empty() {
        return S4Error::new(
            codes::WIT_INVALID,
            format!("{stage}: binary reductor returned an empty guest error code"),
        );
    }
    if error.code.len() > max_diagnostic_bytes || error.message.len() > max_diagnostic_bytes {
        return S4Error::new(
            codes::WIT_INVALID,
            format!(
                "{stage}: binary reductor guest diagnostic exceeds {max_diagnostic_bytes} bytes"
            ),
        );
    }
    S4Error::new(
        codes::WASM_REDUCTOR,
        format!("{stage}: {}: {}", error.code, error.message),
    )
}

fn convert_plan(planned: PlannedReduction) -> BinaryReductorPlan {
    BinaryReductorPlan {
        claims: planned.claims.into_iter().map(convert_claim).collect(),
        reduced_schema_ir: planned.reduced_schema_ir,
        plan: planned.plan,
    }
}

fn convert_restoration_plan(planned: PlannedRestoration) -> BinaryReductorRestorationPlan {
    BinaryReductorRestorationPlan {
        output_schema_ir: planned.output_schema_ir,
        restore_plan: planned.restore_plan,
    }
}

fn convert_claim(claim: Claim) -> BinaryReductorClaim {
    BinaryReductorClaim {
        path: claim.path.into_iter().map(convert_path_segment).collect(),
        type_id: claim.type_id,
    }
}

fn convert_path_segment(segment: PathSegment) -> BinaryReductorPathSegment {
    match segment {
        PathSegment::Field(name) => BinaryReductorPathSegment::Field(name),
        PathSegment::ArrayElement => BinaryReductorPathSegment::ArrayElement,
        PathSegment::MapValue => BinaryReductorPathSegment::MapValue,
        PathSegment::LogicalValue => BinaryReductorPathSegment::LogicalValue,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    const CUSTOM_SCHEMA_IR: &[u8] = br#"{"root":{"kind":{"type":"custom","type_id":"vendor.money","value":{"kind":{"type":"string"},"nullable":false}},"nullable":false},"version":1}"#;
    const STRING_SCHEMA_IR: &[u8] =
        br#"{"root":{"kind":{"type":"string"},"nullable":false},"version":1}"#;
    const CUSTOM_VALUE_IR: &[u8] = br#"{"root":{"type":"custom","type_id":"vendor.money","value":{"type":"string","value":"12.34"}},"version":1}"#;
    const STRING_VALUE_IR: &[u8] = br#"{"root":{"type":"string","value":"12.34"},"version":1}"#;
    const REDUCTION_PLAN: &[u8] = b"vendor.money->string@1";
    const RESTORATION_PLAN_PREFIX: &[u8] = b"vendor.money<-";

    fn expected_restoration_plan(schema_ir: &[u8]) -> Vec<u8> {
        let mut plan = RESTORATION_PLAN_PREFIX.to_vec();
        plan.extend_from_slice(schema_ir);
        plan
    }

    fn component(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-components")
            .join(name);
        std::fs::read(path).expect("test component missing; run just build-filters")
    }

    fn reductor_component() -> Vec<u8> {
        component("test-binary-reductor.component.wasm")
    }

    fn noop_filter_component() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("components")
            .join("noop.component.wasm");
        std::fs::read(path).expect("noop component missing; run just build-filters")
    }

    fn boundary_limits() -> BinaryReductorBoundaryLimits {
        BinaryReductorBoundaryLimits::from(&BinaryReductorConfig::default())
    }

    fn claim(path: Vec<BinaryReductorPathSegment>) -> BinaryReductorClaim {
        BinaryReductorClaim {
            path,
            type_id: "test.type".to_string(),
        }
    }

    #[test]
    fn boundary_defaults_match_the_binary_contract() {
        let config = BinaryReductorConfig::default();
        assert_eq!(config.max_component_bytes, 16 * 1024 * 1024);
        assert_eq!(config.max_plan_bytes, 1024 * 1024);
        assert_eq!(config.max_schema_ir_bytes, 1024 * 1024);
        assert_eq!(config.max_value_ir_bytes, 8 * 1024 * 1024);
        assert_eq!(config.max_claims, 4096);
        assert_eq!(config.max_claim_path_depth, 8);
        assert_eq!(config.max_identifier_bytes, 256);
        assert_eq!(config.max_guest_diagnostic_bytes, 4 * 1024);
    }

    #[test]
    fn zero_boundary_limits_are_rejected_before_component_loading() {
        let zero_limit: [fn(&mut BinaryReductorConfig); 8] = [
            |config| config.max_component_bytes = 0,
            |config| config.max_plan_bytes = 0,
            |config| config.max_schema_ir_bytes = 0,
            |config| config.max_value_ir_bytes = 0,
            |config| config.max_claims = 0,
            |config| config.max_claim_path_depth = 0,
            |config| config.max_identifier_bytes = 0,
            |config| config.max_guest_diagnostic_bytes = 0,
        ];
        for set_zero in zero_limit {
            let mut config = BinaryReductorConfig::default();
            set_zero(&mut config);
            let error = BinaryReductorEngine::with_config(b"not a component", config)
                .err()
                .unwrap();
            assert_eq!(error.code(), codes::CONFIG_INVALID);
        }
    }

    #[test]
    fn invalid_runtime_limits_are_configuration_errors() {
        let error = BinaryReductorEngine::with_limits(
            b"not a component",
            RuntimeLimits {
                cumulative_fuel: 0,
                ..RuntimeLimits::default()
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.code(), codes::CONFIG_INVALID);
    }

    #[test]
    fn invalid_component_has_a_stable_load_error() {
        let error = BinaryReductorEngine::new(b"not a component").err().unwrap();
        assert_eq!(error.code(), codes::COMPONENT_LOAD);
    }

    #[test]
    fn oversized_component_is_rejected_before_wasmtime_compilation() {
        let error = BinaryReductorEngine::with_config(
            b"not a component",
            BinaryReductorConfig {
                max_component_bytes: 1,
                ..BinaryReductorConfig::default()
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.code(), codes::WASM_REDUCTOR_LIMIT);
    }

    #[test]
    fn stateless_plans_may_be_empty_but_remain_bounded() {
        validate_plan_blob(&[], 1).unwrap();
        assert_eq!(
            validate_plan_blob(&[1, 2], 1).unwrap_err().code(),
            codes::WASM_REDUCTOR_PLAN
        );
        validate_plan_blob(&[1], 1).unwrap();
    }

    #[test]
    fn guest_errors_have_a_stable_host_code_and_preserve_diagnostics() {
        let error = guest_error(
            "reduce",
            ReductorError {
                code: "example.invalid-value".to_string(),
                message: "bad value".to_string(),
            },
            64,
        );
        assert_eq!(error.code(), codes::WASM_REDUCTOR);
        assert!(error.message().contains("example.invalid-value"));
        assert!(error.message().contains("bad value"));
    }

    #[test]
    fn guest_diagnostics_are_nonempty_and_bounded_before_formatting() {
        let empty_code = guest_error(
            "reduce",
            ReductorError {
                code: String::new(),
                message: "bad value".to_string(),
            },
            4,
        );
        assert_eq!(empty_code.code(), codes::WIT_INVALID);

        for error in [
            ReductorError {
                code: "12345".to_string(),
                message: String::new(),
            },
            ReductorError {
                code: "code".to_string(),
                message: "12345".to_string(),
            },
        ] {
            assert_eq!(guest_error("reduce", error, 4).code(), codes::WIT_INVALID);
        }
    }

    #[test]
    fn schema_and_value_ir_bytes_are_bounded_without_parsing() {
        validate_ir_bytes("Schema IR", &[1], 1).unwrap();
        assert_eq!(
            validate_ir_bytes("Schema IR", &[1, 2], 1)
                .unwrap_err()
                .code(),
            codes::WASM_REDUCTOR_LIMIT
        );
        assert_eq!(
            validate_ir_bytes("Value IR", &[1, 2], 1)
                .unwrap_err()
                .code(),
            codes::WASM_REDUCTOR_LIMIT
        );
    }

    #[test]
    fn claims_enforce_count_depth_and_identifier_byte_limits() {
        let mut limits = boundary_limits();
        limits.max_claims = 1;
        assert_eq!(
            validate_claims(&[claim(Vec::new()), claim(Vec::new())], limits)
                .unwrap_err()
                .code(),
            codes::WASM_REDUCTOR_CLAIM
        );

        let mut limits = boundary_limits();
        limits.max_claim_path_depth = 1;
        let deep = claim(vec![
            BinaryReductorPathSegment::ArrayElement,
            BinaryReductorPathSegment::LogicalValue,
        ]);
        assert_eq!(
            validate_claims(&[deep], limits).unwrap_err().code(),
            codes::WASM_REDUCTOR_CLAIM
        );

        let mut limits = boundary_limits();
        limits.max_identifier_bytes = 1;
        let long_field = BinaryReductorClaim {
            path: vec![BinaryReductorPathSegment::Field("é".to_string())],
            type_id: "t".to_string(),
        };
        assert_eq!(
            validate_claims(&[long_field], limits).unwrap_err().code(),
            codes::WASM_REDUCTOR_CLAIM
        );
        let empty_type = BinaryReductorClaim {
            path: Vec::new(),
            type_id: String::new(),
        };
        assert_eq!(
            validate_claims(&[empty_type], boundary_limits())
                .unwrap_err()
                .code(),
            codes::WASM_REDUCTOR_CLAIM
        );
    }

    #[test]
    fn duplicate_and_prefix_overlapping_claims_are_rejected() {
        let field = BinaryReductorPathSegment::Field("field".to_string());
        let duplicate = [claim(vec![field.clone()]), claim(vec![field.clone()])];
        assert_eq!(
            validate_claims(&duplicate, boundary_limits())
                .unwrap_err()
                .code(),
            codes::WASM_REDUCTOR_CLAIM
        );

        let overlap = [
            claim(vec![field.clone()]),
            claim(vec![field, BinaryReductorPathSegment::LogicalValue]),
        ];
        assert_eq!(
            validate_claims(&overlap, boundary_limits())
                .unwrap_err()
                .code(),
            codes::WASM_REDUCTOR_CLAIM
        );

        let siblings = [
            claim(vec![BinaryReductorPathSegment::Field("a".to_string())]),
            claim(vec![BinaryReductorPathSegment::Field("b".to_string())]),
        ];
        validate_claims(&siblings, boundary_limits()).unwrap();
    }

    #[test]
    fn conforming_no_import_component_supports_stateless_pass_through() {
        let engine = BinaryReductorEngine::new(&reductor_component()).unwrap();
        assert_eq!(engine.component_digest().len(), 64);
        let mut session = engine.start_session().unwrap();

        let planned = session.plan(b"schema").unwrap();
        assert_eq!(planned.reduced_schema_ir, b"schema");
        assert!(planned.plan.is_empty());
        assert_eq!(planned.claims.len(), 1);
        let restoration = session
            .plan_restore(b"schema", b"transformed", &[])
            .unwrap();
        assert_eq!(restoration.output_schema_ir, b"transformed");
        assert!(restoration.restore_plan.is_empty());
        assert_eq!(session.reduce(&[], b"value").unwrap(), b"value");
        assert_eq!(
            session
                .restore(&restoration.restore_plan, b"filtered")
                .unwrap(),
            b"filtered"
        );
        assert!(session.fuel_consumed() > 0);
    }

    #[test]
    fn exact_custom_string_vector_reduces_and_restores_with_a_restore_plan() {
        let limits = RuntimeLimits {
            guest_memory_bytes: 32 * 1024 * 1024,
            cumulative_fuel: 2_000_000,
            per_call_fuel: 2_000_000,
            ..RuntimeLimits::default()
        };
        let engine = BinaryReductorEngine::with_limits(&reductor_component(), limits).unwrap();
        assert_eq!(engine.guest_memory_limit(), 32 * 1024 * 1024);
        assert_eq!(engine.cumulative_fuel_limit(), 2_000_000);
        let mut session = engine.start_session().unwrap();

        let reduction = session.plan(CUSTOM_SCHEMA_IR).unwrap();
        assert_eq!(reduction.reduced_schema_ir, STRING_SCHEMA_IR);
        assert_eq!(reduction.plan, REDUCTION_PLAN);
        assert_eq!(
            reduction.claims,
            vec![BinaryReductorClaim {
                path: Vec::new(),
                type_id: "vendor.money".to_string(),
            }]
        );

        let reduced_value = session.reduce(&reduction.plan, CUSTOM_VALUE_IR).unwrap();
        assert_eq!(reduced_value, STRING_VALUE_IR);

        let restoration = session
            .plan_restore(CUSTOM_SCHEMA_IR, STRING_SCHEMA_IR, &reduction.plan)
            .unwrap();
        assert_eq!(restoration.output_schema_ir, CUSTOM_SCHEMA_IR);
        assert_eq!(
            restoration.restore_plan,
            expected_restoration_plan(STRING_SCHEMA_IR)
        );
        assert!(!restoration.restore_plan.is_empty());
        assert_ne!(restoration.restore_plan, reduction.plan);

        assert_eq!(
            session.restore(&reduction.plan, &reduced_value).unwrap(),
            STRING_VALUE_IR
        );
        assert_eq!(
            session
                .restore(&restoration.restore_plan, &reduced_value)
                .unwrap(),
            CUSTOM_VALUE_IR
        );
    }

    #[test]
    fn binary_reductor_does_not_link_filter_wasi_imports() {
        let engine = BinaryReductorEngine::new(&noop_filter_component()).unwrap();
        assert_eq!(
            engine.start_session().err().unwrap().code(),
            codes::WIT_INVALID
        );
    }

    #[test]
    fn no_import_component_with_the_wrong_world_is_wit_invalid() {
        let engine = BinaryReductorEngine::new(b"(component)").unwrap();
        assert_eq!(
            engine.start_session().err().unwrap().code(),
            codes::WIT_INVALID
        );
    }

    #[test]
    fn abi_errors_and_all_returned_bytes_are_bounded() {
        let engine = BinaryReductorEngine::with_config(
            &reductor_component(),
            BinaryReductorConfig {
                max_plan_bytes: 8,
                max_schema_ir_bytes: 8,
                max_value_ir_bytes: 8,
                ..BinaryReductorConfig::default()
            },
        )
        .unwrap();

        let mut session = engine.start_session().unwrap();
        assert_eq!(session.plan(b"e").unwrap_err().code(), codes::WASM_REDUCTOR);
        assert_eq!(
            session.plan(b"p").unwrap_err().code(),
            codes::WASM_REDUCTOR_PLAN
        );
        assert_eq!(
            session.plan(b"s").unwrap_err().code(),
            codes::WASM_REDUCTOR_LIMIT
        );
        assert_eq!(
            session.plan_restore(b"a", b"x", &[]).unwrap_err().code(),
            codes::WASM_REDUCTOR_LIMIT
        );
        assert_eq!(
            session.plan_restore(b"a", b"r", &[]).unwrap_err().code(),
            codes::WASM_REDUCTOR_PLAN
        );
        assert_eq!(
            session.reduce(&[], b"x").unwrap_err().code(),
            codes::WASM_REDUCTOR_LIMIT
        );
        assert_eq!(
            session.restore(&[], b"x").unwrap_err().code(),
            codes::WASM_REDUCTOR_LIMIT
        );
    }

    #[test]
    fn reductor_deadline_interrupts_a_guest_without_host_imports() {
        let engine = BinaryReductorEngine::with_limits(
            &reductor_component(),
            RuntimeLimits {
                cumulative_fuel: u64::MAX,
                per_call_fuel: u64::MAX,
                per_call_timeout: Duration::from_millis(25),
                object_timeout: Duration::from_secs(1),
                ..RuntimeLimits::default()
            },
        )
        .unwrap();
        let mut session = engine.start_session().unwrap();
        assert_eq!(
            session.reduce(&[], b"loop").unwrap_err().code(),
            codes::WASM_DEADLINE
        );
    }

    #[test]
    fn reductor_fuel_interrupts_a_guest_without_host_imports() {
        let engine = BinaryReductorEngine::with_fuel(&reductor_component(), 1_000_000).unwrap();
        let mut session = engine.start_session().unwrap();
        assert_eq!(
            session.reduce(&[], b"loop").unwrap_err().code(),
            codes::WASM_FUEL
        );
    }

    #[test]
    fn reductor_cancellation_interrupts_a_guest_without_host_imports() {
        let engine = BinaryReductorEngine::with_limits(
            &reductor_component(),
            RuntimeLimits {
                cumulative_fuel: u64::MAX,
                per_call_fuel: u64::MAX,
                per_call_timeout: Duration::from_secs(5),
                object_timeout: Duration::from_secs(5),
                ..RuntimeLimits::default()
            },
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let mut session = engine
            .start_session_with_cancellation(cancellation.clone())
            .unwrap();
        let call = std::thread::spawn(move || session.reduce(&[], b"loop"));
        std::thread::sleep(Duration::from_millis(25));
        cancellation.cancel();
        assert_eq!(
            call.join().unwrap().unwrap_err().code(),
            codes::WASM_CANCELLED
        );
    }

    #[test]
    fn component_digest_is_lowercase_sha256() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn binary_reductor_session_can_move_to_a_dedicated_executor() {
        fn assert_send<T: Send>() {}
        assert_send::<BinaryReductorSession>();
    }
}
