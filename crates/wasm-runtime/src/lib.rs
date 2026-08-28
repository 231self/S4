wasmtime::component::bindgen!({
    world: "filter",
    path: "../../wit/s4-filter/world.wit",
});

mod executor;

pub use executor::{
    CancellationToken, ExecutorConfig, MemoryAdmission, MemoryPermit, WasmExecutor,
};

use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use s4_error::{S4Error, codes};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Engine, ResourceLimiter, Store, Trap, UpdateDeadline};
use wasmtime_wasi::p2::add_to_linker_sync as add_wasi_to_linker;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};
use zeroize::Zeroize;

const DEFAULT_GUEST_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_MEMORIES: usize = 4;
const DEFAULT_TABLE_ELEMENTS: usize = 10_000;
const EPOCH_TICK: Duration = Duration::from_millis(10);

#[derive(Debug)]
struct S4ResourceLimiter {
    memory_limit: usize,
    memory_used: usize,
    max_memories: usize,
    table_elements: usize,
}

impl ResourceLimiter for S4ResourceLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        let growth = desired.saturating_sub(current);
        let aggregate = self.memory_used.saturating_add(growth);
        if aggregate > self.memory_limit {
            return Err(wasmtime::Error::msg(format!(
                "aggregate memory limit exceeded: {} > {}",
                aggregate, self.memory_limit
            )));
        }
        self.memory_used = aggregate;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        let _ = current;
        if desired > self.table_elements {
            return Err(wasmtime::Error::msg(format!(
                "table limit exceeded: {desired}"
            )));
        }
        Ok(true)
    }

    fn memories(&self) -> usize {
        self.max_memories
    }
}

struct S4HostState {
    resource_limiter: S4ResourceLimiter,
    wasi: WasiCtx,
    table: ResourceTable,
}

impl WasiView for S4HostState {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
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

impl Drop for Session {
    fn drop(&mut self) {
        zeroize_stable_key(&mut self.stable_key);
    }
}

fn zeroize_stable_key(stable_key: &mut Option<Vec<u8>>) {
    if let Some(mut key) = stable_key.take() {
        key.zeroize();
    }
}

pub struct FilterEngine {
    epoch_engine: Arc<EpochEngine>,
    component: Component,
    limits: RuntimeLimits,
}

struct EpochEngine {
    engine: Engine,
}

static EPOCH_ENGINES: OnceLock<Mutex<Vec<Weak<EpochEngine>>>> = OnceLock::new();
static EPOCH_THREAD: OnceLock<()> = OnceLock::new();

#[derive(Clone, Debug)]
pub struct RuntimeLimits {
    pub guest_memory_bytes: usize,
    pub max_memories: usize,
    pub table_elements: usize,
    pub cumulative_fuel: u64,
    pub per_call_fuel: u64,
    pub per_call_timeout: Duration,
    pub object_timeout: Duration,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            guest_memory_bytes: DEFAULT_GUEST_MEMORY_BYTES,
            max_memories: DEFAULT_MAX_MEMORIES,
            table_elements: DEFAULT_TABLE_ELEMENTS,
            cumulative_fuel: DEFAULT_FUEL,
            per_call_fuel: DEFAULT_FUEL,
            per_call_timeout: Duration::from_secs(30),
            object_timeout: Duration::from_secs(5 * 60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformOutcome {
    Emit(Vec<u8>),
    Drop,
}

pub struct FilterSession {
    store: Store<S4HostState>,
    funcs: Filter,
    cancellation: CancellationToken,
    control: Arc<CallControl>,
    limits: RuntimeLimits,
    object_deadline: Instant,
    fuel_consumed: u64,
}

#[derive(Debug)]
struct CallControl {
    deadline: Mutex<Instant>,
    cancellation: CancellationToken,
}

#[derive(Clone, Copy, Debug)]
struct FuelWindow {
    total_before: u64,
    call_budget: u64,
}

impl FilterSession {
    pub fn transform(&mut self, payload: &[u8]) -> Result<TransformOutcome, S4Error> {
        self.transform_with_fuel_limit(payload, u64::MAX)
    }

    pub fn transform_with_fuel_limit(
        &mut self,
        payload: &[u8],
        fuel_limit: u64,
    ) -> Result<TransformOutcome, S4Error> {
        let window = self.prepare_call(fuel_limit)?;
        let result = self.funcs.call_transform(&mut self.store, payload);
        let decision = self.complete_call(window, result, "transform", codes::WASM_TRAP)?;
        let decision = decision.map_err(|error| S4Error::new(codes::WASM_TRAP, error))?;
        match decision {
            Decision::Emit(data) => Ok(TransformOutcome::Emit(data)),
            Decision::Drop => Ok(TransformOutcome::Drop),
            Decision::Reject(reason) => Err(S4Error::new(codes::WASM_REJECT, reason)),
        }
    }

    pub fn finish(self) -> Result<Vec<u8>, S4Error> {
        self.finish_with_fuel_limit(u64::MAX)
            .map(|(output, _)| output)
    }

    pub fn finish_with_fuel_limit(mut self, fuel_limit: u64) -> Result<(Vec<u8>, u64), S4Error> {
        let window = self.prepare_call(fuel_limit)?;
        let result = self.funcs.call_finish(&mut self.store);
        let output = self
            .complete_call(window, result, "finish", codes::WASM_TRAP)?
            .map_err(|error| S4Error::new(codes::WASM_TRAP, error))?;
        Ok((output, self.fuel_consumed))
    }

    pub fn fuel_consumed(&self) -> u64 {
        self.fuel_consumed
    }

    fn call_begin(&mut self, context: &Context, fuel_limit: u64) -> Result<(), S4Error> {
        let window = self.prepare_call(fuel_limit)?;
        let result = self.funcs.call_begin(&mut self.store, context);
        self.complete_call(window, result, "begin", codes::WASM_INIT)?
            .map_err(|error| S4Error::new(codes::WASM_INIT, error))
    }

    fn prepare_call(&mut self, fuel_limit: u64) -> Result<FuelWindow, S4Error> {
        if self.cancellation.is_cancelled() {
            return Err(S4Error::new(
                codes::WASM_CANCELLED,
                "Wasm execution was cancelled",
            ));
        }
        let object_remaining = self
            .object_deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| S4Error::new(codes::WASM_DEADLINE, "Wasm object deadline exceeded"))?;
        let call_timeout = self.limits.per_call_timeout.min(object_remaining);
        *self.control.deadline.lock().unwrap() = Instant::now() + call_timeout;
        self.store.set_epoch_deadline(1);

        let total_before = self
            .store
            .get_fuel()
            .map_err(|error| S4Error::new(codes::WASM_FUEL, error.to_string()))?;
        let call_budget = total_before.min(self.limits.per_call_fuel).min(fuel_limit);
        if call_budget == 0 {
            return Err(S4Error::new(
                codes::WASM_FUEL,
                "Wasm cumulative fuel budget exhausted",
            ));
        }
        self.store
            .set_fuel(call_budget)
            .map_err(|error| S4Error::new(codes::WASM_FUEL, error.to_string()))?;
        Ok(FuelWindow {
            total_before,
            call_budget,
        })
    }

    fn complete_call<T>(
        &mut self,
        window: FuelWindow,
        result: wasmtime::Result<T>,
        stage: &str,
        default_code: &'static str,
    ) -> Result<T, S4Error> {
        let call_remaining = self.store.get_fuel().unwrap_or(0);
        let consumed = window.call_budget.saturating_sub(call_remaining);
        self.fuel_consumed = self.fuel_consumed.saturating_add(consumed);
        let total_remaining = window.total_before.saturating_sub(consumed);
        self.store
            .set_fuel(total_remaining)
            .map_err(|error| S4Error::new(codes::WASM_FUEL, error.to_string()))?;

        result.map_err(|error| {
            let code = if self.cancellation.is_cancelled() {
                codes::WASM_CANCELLED
            } else if Instant::now() >= *self.control.deadline.lock().unwrap() {
                codes::WASM_DEADLINE
            } else if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
                codes::WASM_FUEL
            } else {
                default_code
            };
            S4Error::new(code, format!("{stage}: {error}"))
        })
    }
}

const DEFAULT_FUEL: u64 = 10_000_000;

impl FilterEngine {
    pub fn new(component_bytes: &[u8]) -> anyhow::Result<Self> {
        Self::with_fuel(component_bytes, DEFAULT_FUEL)
    }

    pub fn with_fuel(component_bytes: &[u8], fuel: u64) -> anyhow::Result<Self> {
        Self::with_limits(
            component_bytes,
            RuntimeLimits {
                cumulative_fuel: fuel,
                per_call_fuel: fuel,
                ..RuntimeLimits::default()
            },
        )
    }

    pub fn with_limits(component_bytes: &[u8], limits: RuntimeLimits) -> anyhow::Result<Self> {
        if limits.guest_memory_bytes == 0
            || limits.max_memories == 0
            || limits.table_elements == 0
            || limits.cumulative_fuel == 0
            || limits.per_call_fuel == 0
            || limits.per_call_timeout.is_zero()
            || limits.object_timeout.is_zero()
        {
            anyhow::bail!("Wasm runtime limits must be greater than zero");
        }
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config)?;
        let component = Component::new(&engine, component_bytes)?;
        let epoch_engine = Arc::new(EpochEngine { engine });
        register_epoch_engine(&epoch_engine);
        Ok(Self {
            epoch_engine,
            component,
            limits,
        })
    }

    pub fn guest_memory_limit(&self) -> usize {
        self.limits.guest_memory_bytes
    }

    fn create_store(
        &self,
        cancellation: &CancellationToken,
        object_deadline: Instant,
        initial_fuel: u64,
    ) -> Result<(Store<S4HostState>, Arc<CallControl>), S4Error> {
        let wasi = WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            .build();
        let state = S4HostState {
            resource_limiter: S4ResourceLimiter {
                memory_limit: self.limits.guest_memory_bytes,
                memory_used: 0,
                max_memories: self.limits.max_memories,
                table_elements: self.limits.table_elements,
            },
            wasi,
            table: ResourceTable::new(),
        };
        let mut store = Store::new(&self.epoch_engine.engine, state);
        store
            .set_fuel(initial_fuel)
            .map_err(|e| S4Error::new(codes::WASM_INIT, e.to_string()))?;
        store.limiter(|s| &mut s.resource_limiter);
        let control = Arc::new(CallControl {
            deadline: Mutex::new(object_deadline),
            cancellation: cancellation.clone(),
        });
        let callback_control = Arc::clone(&control);
        store.epoch_deadline_callback(move |_| {
            if callback_control.cancellation.is_cancelled() {
                return Err(wasmtime::Error::msg("Wasm execution cancelled"));
            }
            if Instant::now() >= *callback_control.deadline.lock().unwrap() {
                return Err(wasmtime::Error::msg("Wasm execution deadline exceeded"));
            }
            Ok(UpdateDeadline::Continue(1))
        });
        store.set_epoch_deadline(1);
        cancellation.register_engine(&self.epoch_engine.engine);
        Ok((store, control))
    }

    pub fn run_session(
        &self,
        session: &Session,
        records: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, S4Error> {
        let mut filter_session = self.start_session(session)?;
        let mut output = Vec::with_capacity(records.len());
        for payload in records {
            match filter_session.transform(payload)? {
                TransformOutcome::Emit(data) => output.push(data),
                TransformOutcome::Drop => {}
            }
        }

        let trailing = filter_session.finish()?;
        if !trailing.is_empty() {
            output.push(trailing);
        }
        Ok(output)
    }

    pub fn start_session(&self, session: &Session) -> Result<FilterSession, S4Error> {
        self.start_session_with_cancellation(session, CancellationToken::new())
    }

    pub fn start_session_with_cancellation(
        &self,
        session: &Session,
        cancellation: CancellationToken,
    ) -> Result<FilterSession, S4Error> {
        self.start_session_with_cancellation_and_fuel(session, cancellation, u64::MAX)
    }

    pub fn start_session_with_cancellation_and_fuel(
        &self,
        session: &Session,
        cancellation: CancellationToken,
        begin_fuel_limit: u64,
    ) -> Result<FilterSession, S4Error> {
        self.start_session_with_control(
            session,
            cancellation,
            begin_fuel_limit,
            Instant::now() + self.limits.object_timeout,
        )
    }

    pub fn start_session_with_control(
        &self,
        session: &Session,
        cancellation: CancellationToken,
        begin_fuel_limit: u64,
        object_deadline: Instant,
    ) -> Result<FilterSession, S4Error> {
        let object_deadline = object_deadline.min(Instant::now() + self.limits.object_timeout);
        check_start_control(&cancellation, object_deadline)?;
        let initial_fuel = self.limits.cumulative_fuel.min(begin_fuel_limit);
        if initial_fuel == 0 {
            return Err(S4Error::new(
                codes::WASM_FUEL,
                "Wasm startup fuel budget exhausted",
            ));
        }
        let (mut store, control) = self
            .create_store(&cancellation, object_deadline, initial_fuel)
            .map_err(|e| S4Error::new(codes::WASM_INIT, e.to_string()))?;
        let mut linker = Linker::new(&self.epoch_engine.engine);
        add_wasi_to_linker(&mut linker)
            .map_err(|e| S4Error::new(codes::WASM_INIT, e.to_string()))?;
        check_start_control(&cancellation, object_deadline)?;
        let instance = linker
            .instantiate(&mut store, &self.component)
            .map_err(|error| startup_error("instantiate", error, &cancellation, object_deadline))?;

        let remaining_after_start = store
            .get_fuel()
            .map_err(|error| S4Error::new(codes::WASM_FUEL, error.to_string()))?;
        let startup_fuel = initial_fuel.saturating_sub(remaining_after_start);
        check_start_control(&cancellation, object_deadline)?;

        let funcs = Filter::new(&mut store, &instance).map_err(|error| {
            startup_error("bind exports", error, &cancellation, object_deadline)
        })?;
        check_start_control(&cancellation, object_deadline)?;

        let entropy_seed: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        let mut ctx = Context {
            format: session.format.clone(),
            content_type: session.content_type.clone(),
            policy_version: session.policy_version,
            public_key_pem: session.public_key_pem.clone(),
            entropy_seed: Some(entropy_seed),
            stable_key: session.stable_key.clone(),
            stable_fields: session.stable_fields.clone(),
        };

        let mut filter_session = FilterSession {
            store,
            funcs,
            cancellation,
            control,
            limits: self.limits.clone(),
            object_deadline,
            fuel_consumed: startup_fuel,
        };
        let begin = filter_session.call_begin(&ctx, begin_fuel_limit);
        zeroize_stable_key(&mut ctx.stable_key);
        // The trusted guest receives its own linear-memory copy. That memory is
        // destroyed with this per-request store, but Wasmtime does not
        // synchronously scrub every guest byte before releasing the pages.
        begin?;
        Ok(filter_session)
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

fn check_start_control(
    cancellation: &CancellationToken,
    object_deadline: Instant,
) -> Result<(), S4Error> {
    if cancellation.is_cancelled() {
        return Err(S4Error::new(
            codes::WASM_CANCELLED,
            "Wasm startup was cancelled",
        ));
    }
    if Instant::now() >= object_deadline {
        return Err(S4Error::new(
            codes::WASM_DEADLINE,
            "Wasm startup deadline exceeded",
        ));
    }
    Ok(())
}

fn startup_error(
    stage: &str,
    error: wasmtime::Error,
    cancellation: &CancellationToken,
    object_deadline: Instant,
) -> S4Error {
    let code = if cancellation.is_cancelled() {
        codes::WASM_CANCELLED
    } else if Instant::now() >= object_deadline {
        codes::WASM_DEADLINE
    } else if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
        codes::WASM_FUEL
    } else {
        codes::WASM_INIT
    };
    S4Error::new(code, format!("{stage}: {error}"))
}

fn register_epoch_engine(engine: &Arc<EpochEngine>) {
    EPOCH_ENGINES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .push(Arc::downgrade(engine));
    EPOCH_THREAD.get_or_init(|| {
        std::thread::Builder::new()
            .name("s4-wasm-epoch".to_string())
            .spawn(|| {
                loop {
                    std::thread::sleep(EPOCH_TICK);
                    let Some(engines) = EPOCH_ENGINES.get() else {
                        continue;
                    };
                    engines.lock().unwrap().retain(|engine| {
                        if let Some(engine) = engine.upgrade() {
                            engine.engine.increment_epoch();
                            true
                        } else {
                            false
                        }
                    });
                }
            })
            .expect("failed to start Wasmtime epoch ticker");
    });
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn noop_component() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("components")
            .join("noop.component.wasm");
        std::fs::read(path).expect("noop.component.wasm; run just build-filters")
    }

    fn test_component() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-components")
            .join("test-filter.component.wasm");
        std::fs::read(path).expect("test-filter.component.wasm; run just build-filters")
    }

    fn session() -> Session {
        Session {
            format: "text".to_string(),
            content_type: "text/plain".to_string(),
            policy_version: 1,
            public_key_pem: None,
            stable_key: None,
            stable_fields: None,
        }
    }

    fn hostile_start_component() -> &'static [u8] {
        br#"(component
            (core module $hostile
                (func $start
                    (loop $forever
                        br $forever
                    )
                )
                (start $start)
            )
            (core instance $instance (instantiate $hostile))
        )"#
    }

    #[test]
    fn stable_key_zeroization_hook_removes_host_copy() {
        let mut stable_key = Some(vec![0x5a; 64]);
        zeroize_stable_key(&mut stable_key);
        assert!(stable_key.is_none());
    }

    #[test]
    fn persistent_session_processes_records_and_finishes_once() {
        let engine = FilterEngine::new(&noop_component()).unwrap();
        let mut filter = engine.start_session(&session()).unwrap();
        assert_eq!(
            filter.transform(b"first").unwrap(),
            TransformOutcome::Emit(b"first".to_vec())
        );
        assert_eq!(
            filter.transform(b"second").unwrap(),
            TransformOutcome::Emit(b"second".to_vec())
        );
        assert!(filter.finish().unwrap().is_empty());
    }

    #[test]
    fn batch_wrapper_matches_incremental_session() {
        let engine = FilterEngine::new(&noop_component()).unwrap();
        let records = vec![b"first".to_vec(), b"second".to_vec()];
        let batch = engine.run_session(&session(), &records).unwrap();

        let mut filter = engine.start_session(&session()).unwrap();
        let mut incremental = Vec::new();
        for record in &records {
            if let TransformOutcome::Emit(bytes) = filter.transform(record).unwrap() {
                incremental.push(bytes);
            }
        }
        let tail = filter.finish().unwrap();
        if !tail.is_empty() {
            incremental.push(tail);
        }
        assert_eq!(incremental, batch);
    }

    #[test]
    fn each_object_gets_an_independent_store() {
        let engine = FilterEngine::new(&noop_component()).unwrap();
        let mut first = engine.start_session(&session()).unwrap();
        let mut second = engine.start_session(&session()).unwrap();
        assert_eq!(
            first.transform(b"first").unwrap(),
            TransformOutcome::Emit(b"first".to_vec())
        );
        assert_eq!(
            second.transform(b"second").unwrap(),
            TransformOutcome::Emit(b"second".to_vec())
        );
    }

    #[test]
    fn filter_session_can_move_to_a_dedicated_executor() {
        fn assert_send<T: Send>() {}
        assert_send::<FilterSession>();
    }

    #[test]
    fn guest_state_continues_within_object_and_resets_between_stores() {
        let engine = FilterEngine::new(&test_component()).unwrap();
        let mut first = engine.start_session(&session()).unwrap();
        assert_eq!(
            first.transform(b"state").unwrap(),
            TransformOutcome::Emit(b"1".to_vec())
        );
        assert_eq!(
            first.transform(b"state").unwrap(),
            TransformOutcome::Emit(b"2".to_vec())
        );
        let mut second = engine.start_session(&session()).unwrap();
        assert_eq!(
            second.transform(b"state").unwrap(),
            TransformOutcome::Emit(b"1".to_vec())
        );
    }

    #[test]
    fn guest_drop_reject_and_lifecycle_traps_have_stable_codes() {
        let engine = FilterEngine::new(&test_component()).unwrap();
        let mut filter = engine.start_session(&session()).unwrap();
        assert_eq!(filter.transform(b"drop").unwrap(), TransformOutcome::Drop);
        assert_eq!(
            filter.transform(b"reject").unwrap_err().code(),
            codes::WASM_REJECT
        );

        let mut filter = engine.start_session(&session()).unwrap();
        assert_eq!(
            filter.transform(b"trap").unwrap_err().code(),
            codes::WASM_TRAP
        );

        let mut begin_trap = session();
        begin_trap.content_type = "test/begin-trap".to_string();
        assert_eq!(
            engine.start_session(&begin_trap).err().unwrap().code(),
            codes::WASM_INIT
        );

        let mut finish_trap = session();
        finish_trap.content_type = "test/finish=trap".to_string();
        assert_eq!(
            engine
                .start_session(&finish_trap)
                .unwrap()
                .finish()
                .unwrap_err()
                .code(),
            codes::WASM_TRAP
        );
    }

    #[test]
    fn non_empty_finish_output_is_returned_once() {
        let engine = FilterEngine::new(&test_component()).unwrap();
        let mut configured = session();
        configured.content_type = "test/finish=tail".to_string();
        assert_eq!(
            engine.start_session(&configured).unwrap().finish().unwrap(),
            b"tail"
        );
    }

    #[test]
    fn cancellation_interrupts_an_active_guest_call() {
        let engine = FilterEngine::with_limits(
            &test_component(),
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
        let mut filter = engine
            .start_session_with_cancellation(&session(), cancellation.clone())
            .unwrap();
        let call = std::thread::spawn(move || filter.transform(b"loop"));
        std::thread::sleep(Duration::from_millis(25));
        cancellation.cancel();
        assert_eq!(
            call.join().unwrap().unwrap_err().code(),
            codes::WASM_CANCELLED
        );
    }

    #[test]
    fn per_call_wall_deadline_interrupts_an_infinite_loop() {
        let engine = FilterEngine::with_limits(
            &test_component(),
            RuntimeLimits {
                cumulative_fuel: u64::MAX,
                per_call_fuel: u64::MAX,
                per_call_timeout: Duration::from_millis(25),
                object_timeout: Duration::from_secs(1),
                ..RuntimeLimits::default()
            },
        )
        .unwrap();
        let mut filter = engine.start_session(&session()).unwrap();
        assert_eq!(
            filter.transform(b"loop").unwrap_err().code(),
            codes::WASM_DEADLINE
        );
    }

    #[test]
    fn constrained_fuel_interrupts_a_hostile_core_start_function() {
        let engine = FilterEngine::with_limits(
            hostile_start_component(),
            RuntimeLimits {
                cumulative_fuel: u64::MAX,
                per_call_fuel: u64::MAX,
                ..RuntimeLimits::default()
            },
        )
        .unwrap();
        let error = engine
            .start_session_with_control(
                &session(),
                CancellationToken::new(),
                1_000,
                Instant::now() + Duration::from_secs(1),
            )
            .err()
            .expect("hostile start must exhaust constrained fuel");
        assert_eq!(error.code(), codes::WASM_FUEL);
    }

    #[test]
    fn object_deadline_interrupts_a_hostile_core_start_function() {
        let engine = FilterEngine::with_limits(
            hostile_start_component(),
            RuntimeLimits {
                cumulative_fuel: u64::MAX,
                per_call_fuel: u64::MAX,
                per_call_timeout: Duration::from_secs(1),
                object_timeout: Duration::from_secs(1),
                ..RuntimeLimits::default()
            },
        )
        .unwrap();
        let error = engine
            .start_session_with_control(
                &session(),
                CancellationToken::new(),
                u64::MAX,
                Instant::now() + Duration::from_millis(25),
            )
            .err()
            .expect("hostile start must hit the object deadline");
        assert_eq!(error.code(), codes::WASM_DEADLINE);
    }

    #[test]
    fn aggregate_guest_memory_growth_is_limited() {
        let engine = FilterEngine::new(&test_component()).unwrap();
        let mut filter = engine.start_session(&session()).unwrap();
        assert_eq!(
            filter.transform(b"memory").unwrap_err().code(),
            codes::WASM_TRAP
        );
    }
}
