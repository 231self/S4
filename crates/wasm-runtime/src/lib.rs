wasmtime::component::bindgen!({
    world: "filter",
    path: "../../wit/s4-filter/world.wit",
});

use s4_error::{S4Error, codes};
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, ResourceLimiter, Store};

#[derive(Debug, Default)]
struct S4ResourceLimiter {
    memory_limit: usize,
}

impl ResourceLimiter for S4ResourceLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        let _ = current;
        if desired > self.memory_limit {
            return Err(wasmtime::Error::msg(format!(
                "memory limit exceeded: {} > {}",
                desired, self.memory_limit
            )));
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        let _ = current;
        if desired > 10_000 {
            return Err(wasmtime::Error::msg(format!(
                "table limit exceeded: {desired}"
            )));
        }
        Ok(true)
    }
}

#[derive(Debug, Default)]
struct S4HostState {
    resource_limiter: S4ResourceLimiter,
}

#[derive(Debug, Clone, Default)]
pub struct Session {
    pub format: String,
    pub content_type: String,
    pub policy_version: u64,
    pub public_key_pem: Option<String>,
    pub stable_key: Option<Vec<u8>>,
    pub stable_fields: Option<String>,
}

pub struct FilterEngine {
    engine: Engine,
    component: Component,
    fuel: u64,
}

const DEFAULT_FUEL: u64 = 10_000_000;

impl FilterEngine {
    pub fn new(component_bytes: &[u8]) -> anyhow::Result<Self> {
        Self::with_fuel(component_bytes, DEFAULT_FUEL)
    }

    pub fn with_fuel(component_bytes: &[u8], fuel: u64) -> anyhow::Result<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config)?;
        let component = Component::new(&engine, component_bytes)?;
        Ok(Self {
            engine,
            component,
            fuel,
        })
    }

    fn create_store(&self) -> Result<Store<S4HostState>, S4Error> {
        let state = S4HostState {
            resource_limiter: S4ResourceLimiter {
                memory_limit: 67_108_864,
            },
        };
        let mut store = Store::new(&self.engine, state);
        store
            .set_fuel(self.fuel)
            .map_err(|e| S4Error::new(codes::WASM_INIT, e.to_string()))?;
        store.limiter(|s| &mut s.resource_limiter);
        Ok(store)
    }

    pub fn run_session(
        &self,
        session: &Session,
        records: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, S4Error> {
        let mut store = self
            .create_store()
            .map_err(|e| S4Error::new(codes::WASM_INIT, e.to_string()))?;
        let linker = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &self.component)
            .map_err(|e| S4Error::new(codes::WASM_INIT, e.to_string()))?;

        let funcs = Filter::new(&mut store, &instance)
            .map_err(|e| S4Error::new(codes::WASM_INIT, e.to_string()))?;

        let entropy_seed: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let ctx = Context {
            format: session.format.clone(),
            content_type: session.content_type.clone(),
            policy_version: session.policy_version,
            public_key_pem: session.public_key_pem.clone(),
            entropy_seed: Some(entropy_seed),
            stable_key: session.stable_key.clone(),
            stable_fields: session.stable_fields.clone(),
        };

        funcs
            .call_begin(&mut store, &ctx)
            .map_err(|e| S4Error::new(codes::WASM_INIT, format!("begin: {e}")))
            .and_then(|r| r.map_err(|e| S4Error::new(codes::WASM_INIT, e)))?;

        let mut output = Vec::with_capacity(records.len());
        for payload in records {
            let decision_result = funcs
                .call_transform(&mut store, payload)
                .map_err(|e| S4Error::new(codes::WASM_TRAP, format!("transform: {e}")))?;

            match decision_result {
                Ok(Decision::Emit(data)) => output.push(data),
                Ok(Decision::Drop) => {}
                Ok(Decision::Reject(reason)) => {
                    return Err(S4Error::new(codes::WASM_REJECT, reason));
                }
                Err(e) => {
                    return Err(S4Error::new(codes::WASM_TRAP, e));
                }
            }
        }

        let trailing = funcs
            .call_finish(&mut store)
            .map_err(|e| S4Error::new(codes::WASM_TRAP, format!("finish: {e}")))
            .and_then(|r| r.map_err(|e| S4Error::new(codes::WASM_TRAP, e)))?;

        if !trailing.is_empty() {
            output.push(trailing);
        }

        Ok(output)
    }

    pub fn run(&self, session: &Session, records: &[Vec<u8>]) -> Result<Vec<u8>, S4Error> {
        let results = self.run_session(session, records)?;
        let mut out = Vec::new();
        for r in &results {
            out.extend_from_slice(r);
        }
        Ok(out)
    }
}
