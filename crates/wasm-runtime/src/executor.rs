use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use s4_error::{S4Error, codes};
use wasmtime::Engine;

type Job = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone, Debug)]
pub struct CancellationToken {
    inner: Arc<CancellationState>,
}

#[derive(Debug, Default)]
struct CancellationState {
    cancelled: AtomicBool,
    engines: Mutex<Vec<Engine>>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CancellationState::default()),
        }
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        let engines = self.inner.engines.lock().unwrap();
        for engine in engines.iter() {
            engine.increment_epoch();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn register_engine(&self, engine: &Engine) {
        let mut engines = self.inner.engines.lock().unwrap();
        engines.push(engine.clone());
        if self.is_cancelled() {
            engine.increment_epoch();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorConfig {
    pub workers: usize,
    pub queue_capacity: usize,
    pub guest_memory_budget_bytes: usize,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            workers: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
                .min(4),
            queue_capacity: 16,
            guest_memory_budget_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
struct AdmissionState {
    used: usize,
}

#[derive(Debug)]
struct AdmissionInner {
    capacity: usize,
    state: Mutex<AdmissionState>,
    available: Condvar,
}

#[derive(Clone, Debug)]
pub struct MemoryAdmission {
    inner: Arc<AdmissionInner>,
}

impl MemoryAdmission {
    pub fn new(capacity: usize) -> Result<Self, S4Error> {
        if capacity == 0 {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "Wasm guest-memory admission capacity must be greater than zero",
            ));
        }
        Ok(Self {
            inner: Arc::new(AdmissionInner {
                capacity,
                state: Mutex::new(AdmissionState { used: 0 }),
                available: Condvar::new(),
            }),
        })
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    pub fn used(&self) -> usize {
        self.inner.state.lock().unwrap().used
    }

    pub fn try_reserve(&self, bytes: usize) -> Result<MemoryPermit, S4Error> {
        self.validate_request(bytes)?;
        let mut state = self.inner.state.lock().unwrap();
        if state.used.saturating_add(bytes) > self.inner.capacity {
            return Err(admission_error(bytes, self.inner.capacity));
        }
        state.used += bytes;
        Ok(MemoryPermit {
            admission: self.clone(),
            bytes,
        })
    }

    pub fn reserve(
        &self,
        bytes: usize,
        cancellation: &CancellationToken,
    ) -> Result<MemoryPermit, S4Error> {
        self.validate_request(bytes)?;
        let mut state = self.inner.state.lock().unwrap();
        while state.used.saturating_add(bytes) > self.inner.capacity {
            if cancellation.is_cancelled() {
                return Err(S4Error::new(
                    codes::WASM_CANCELLED,
                    "Wasm execution cancelled while waiting for memory admission",
                ));
            }
            state = self
                .inner
                .available
                .wait_timeout(state, Duration::from_millis(10))
                .unwrap()
                .0;
        }
        state.used += bytes;
        Ok(MemoryPermit {
            admission: self.clone(),
            bytes,
        })
    }

    pub fn reserve_until(
        &self,
        bytes: usize,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> Result<MemoryPermit, S4Error> {
        self.validate_request(bytes)?;
        let mut state = self.inner.state.lock().unwrap();
        while state.used.saturating_add(bytes) > self.inner.capacity {
            if let Some(error) = execution_control_error(cancellation, deadline) {
                return Err(error);
            }
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10));
            state = self.inner.available.wait_timeout(state, wait).unwrap().0;
        }
        if let Some(error) = execution_control_error(cancellation, deadline) {
            return Err(error);
        }
        state.used += bytes;
        Ok(MemoryPermit {
            admission: self.clone(),
            bytes,
        })
    }

    fn validate_request(&self, bytes: usize) -> Result<(), S4Error> {
        if bytes > self.inner.capacity {
            return Err(admission_error(bytes, self.inner.capacity));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct MemoryPermit {
    admission: MemoryAdmission,
    bytes: usize,
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        let mut state = self.admission.inner.state.lock().unwrap();
        state.used -= self.bytes;
        self.admission.inner.available.notify_all();
    }
}

fn admission_error(requested: usize, capacity: usize) -> S4Error {
    S4Error::new(
        codes::WASM_ADMISSION,
        format!("Wasm guest-memory reservation {requested} exceeds available budget {capacity}"),
    )
}

#[derive(Clone)]
pub struct WasmExecutor {
    sender: SyncSender<Job>,
    admission: MemoryAdmission,
}

impl WasmExecutor {
    pub fn new(config: ExecutorConfig) -> Result<Self, S4Error> {
        if config.workers == 0 || config.queue_capacity == 0 {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "Wasm executor workers and queue capacity must be greater than zero",
            ));
        }
        let admission = MemoryAdmission::new(config.guest_memory_budget_bytes)?;
        let (sender, receiver) = sync_channel::<Job>(config.queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..config.workers {
            spawn_worker(index, Arc::clone(&receiver))?;
        }
        Ok(Self { sender, admission })
    }

    pub fn admission(&self) -> &MemoryAdmission {
        &self.admission
    }

    pub fn execute<R, F>(
        &self,
        guest_memory_bytes: usize,
        cancellation: &CancellationToken,
        task: F,
    ) -> Result<R, S4Error>
    where
        R: Send + 'static,
        F: FnOnce() -> R + Send + 'static,
    {
        let permit = self.admission.reserve(guest_memory_bytes, cancellation)?;
        let (result_sender, result_receiver) = sync_channel(1);
        let job = make_job(task, permit, result_sender);
        self.sender
            .send(job)
            .map_err(|_| S4Error::new(codes::WASM_ADMISSION, "Wasm executor is not available"))?;
        receive_result(result_receiver)
    }

    pub fn try_execute<R, F>(&self, guest_memory_bytes: usize, task: F) -> Result<R, S4Error>
    where
        R: Send + 'static,
        F: FnOnce() -> R + Send + 'static,
    {
        let permit = self.admission.try_reserve(guest_memory_bytes)?;
        let (result_sender, result_receiver) = sync_channel(1);
        let job = make_job(task, permit, result_sender);
        self.sender.try_send(job).map_err(|error| match error {
            TrySendError::Full(_) => {
                S4Error::new(codes::WASM_ADMISSION, "Wasm executor queue is full")
            }
            TrySendError::Disconnected(_) => {
                S4Error::new(codes::WASM_ADMISSION, "Wasm executor is not available")
            }
        })?;
        receive_result(result_receiver)
    }

    pub fn execute_until<R, F>(
        &self,
        guest_memory_bytes: usize,
        cancellation: &CancellationToken,
        deadline: Instant,
        task: F,
    ) -> Result<R, S4Error>
    where
        R: Send + 'static,
        F: FnOnce() -> R + Send + 'static,
    {
        let permit = self
            .admission
            .reserve_until(guest_memory_bytes, cancellation, deadline)?;
        let pending = Arc::new(Mutex::new(Some((task, permit))));
        let (result_sender, result_receiver) = sync_channel(1);
        let mut job = make_cancellable_job(Arc::clone(&pending), result_sender);
        loop {
            match self.sender.try_send(job) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) => {
                    job = returned;
                    if let Some(error) = execution_control_error(cancellation, deadline) {
                        cancellation.cancel();
                        pending.lock().unwrap().take();
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TrySendError::Disconnected(_)) => {
                    pending.lock().unwrap().take();
                    return Err(S4Error::new(
                        codes::WASM_ADMISSION,
                        "Wasm executor is not available",
                    ));
                }
            }
        }
        receive_result_until(result_receiver, pending, cancellation, deadline)
    }
}

fn make_job<R, F>(
    task: F,
    permit: MemoryPermit,
    result_sender: SyncSender<Result<R, S4Error>>,
) -> Job
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    Box::new(move || {
        let result = catch_unwind(AssertUnwindSafe(task)).map_err(panic_error);
        // Release aggregate guest-memory admission before publishing task
        // completion so callers never observe a completed job still consuming
        // capacity.
        drop(permit);
        let _ = result_sender.send(result);
    })
}

fn make_cancellable_job<R, F>(
    pending: Arc<Mutex<Option<(F, MemoryPermit)>>>,
    result_sender: SyncSender<Result<R, S4Error>>,
) -> Job
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    Box::new(move || {
        let Some((task, permit)) = pending.lock().unwrap().take() else {
            return;
        };
        let result = catch_unwind(AssertUnwindSafe(task)).map_err(panic_error);
        drop(permit);
        let _ = result_sender.send(result);
    })
}

fn receive_result<R>(receiver: Receiver<Result<R, S4Error>>) -> Result<R, S4Error> {
    receiver.recv().map_err(|_| {
        S4Error::new(
            codes::INTERNAL,
            "Wasm executor worker stopped before returning a result",
        )
    })?
}

fn receive_result_until<R, F>(
    receiver: Receiver<Result<R, S4Error>>,
    pending: Arc<Mutex<Option<(F, MemoryPermit)>>>,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<R, S4Error> {
    loop {
        if let Some(error) = execution_control_error(cancellation, deadline) {
            cancellation.cancel();
            if pending.lock().unwrap().take().is_none() {
                let _ = receiver.recv();
            }
            return Err(error);
        }
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));
        match receiver.recv_timeout(wait) {
            Ok(result) => {
                if let Some(error) = execution_control_error(cancellation, deadline) {
                    cancellation.cancel();
                    return Err(error);
                }
                return result;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(S4Error::new(
                    codes::INTERNAL,
                    "Wasm executor worker stopped before returning a result",
                ));
            }
        }
    }
}

fn execution_control_error(cancellation: &CancellationToken, deadline: Instant) -> Option<S4Error> {
    if Instant::now() >= deadline {
        Some(S4Error::new(
            codes::WASM_DEADLINE,
            "Wasm execution deadline exceeded",
        ))
    } else if cancellation.is_cancelled() {
        Some(S4Error::new(
            codes::WASM_CANCELLED,
            "Wasm execution was cancelled",
        ))
    } else {
        None
    }
}

fn panic_error(payload: Box<dyn Any + Send>) -> S4Error {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic");
    S4Error::new(
        codes::WASM_TRAP,
        format!("Wasm executor task panicked: {message}"),
    )
}

fn spawn_worker(index: usize, receiver: Arc<Mutex<Receiver<Job>>>) -> Result<(), S4Error> {
    std::thread::Builder::new()
        .name(format!("s4-wasm-{index}"))
        .spawn(move || {
            loop {
                let job = receiver.lock().unwrap().recv();
                match job {
                    Ok(job) => job(),
                    Err(_) => break,
                }
            }
        })
        .map(|_| ())
        .map_err(|error| S4Error::new(codes::CONFIG_INVALID, error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn admission_is_aggregate_and_released_by_drop() {
        let admission = MemoryAdmission::new(10).unwrap();
        let first = admission.try_reserve(6).unwrap();
        assert_eq!(admission.used(), 6);
        assert_eq!(
            admission.try_reserve(5).unwrap_err().code(),
            codes::WASM_ADMISSION
        );
        drop(first);
        assert_eq!(admission.used(), 0);
        admission.try_reserve(10).unwrap();
    }

    #[test]
    fn executor_runs_on_a_named_dedicated_worker() {
        let executor = WasmExecutor::new(ExecutorConfig {
            workers: 1,
            queue_capacity: 1,
            guest_memory_budget_bytes: 10,
        })
        .unwrap();
        let name = executor
            .execute(10, &CancellationToken::new(), || {
                std::thread::current().name().unwrap().to_string()
            })
            .unwrap();
        assert_eq!(name, "s4-wasm-0");
        assert_eq!(executor.admission().used(), 0);
    }

    #[test]
    fn cancellation_stops_an_admission_waiter() {
        let admission = MemoryAdmission::new(1).unwrap();
        let permit = admission.try_reserve(1).unwrap();
        let cancellation = CancellationToken::new();
        let waiting_admission = admission.clone();
        let waiting_cancellation = cancellation.clone();
        let waiter =
            std::thread::spawn(move || waiting_admission.reserve(1, &waiting_cancellation));
        std::thread::sleep(Duration::from_millis(20));
        cancellation.cancel();
        assert_eq!(
            waiter.join().unwrap().unwrap_err().code(),
            codes::WASM_CANCELLED
        );
        drop(permit);
    }

    #[test]
    fn queued_deadline_drops_the_task_and_releases_admission() {
        let executor = Arc::new(
            WasmExecutor::new(ExecutorConfig {
                workers: 1,
                queue_capacity: 1,
                guest_memory_budget_bytes: 2,
            })
            .unwrap(),
        );
        let release = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let blocker_executor = Arc::clone(&executor);
        let blocker_release = Arc::clone(&release);
        let blocker_started = Arc::clone(&started);
        let blocker = std::thread::spawn(move || {
            blocker_executor
                .execute(1, &CancellationToken::new(), move || {
                    blocker_started.store(true, Ordering::Release);
                    while !blocker_release.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                })
                .unwrap();
        });
        while !started.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        let ran = Arc::new(AtomicBool::new(false));
        let queued_ran = Arc::clone(&ran);
        let cancellation = CancellationToken::new();
        let error = executor
            .execute_until(
                1,
                &cancellation,
                Instant::now() + Duration::from_millis(25),
                move || queued_ran.store(true, Ordering::Release),
            )
            .unwrap_err();
        assert_eq!(error.code(), codes::WASM_DEADLINE);
        assert!(!ran.load(Ordering::Acquire));
        assert_eq!(executor.admission().used(), 1);

        release.store(true, Ordering::Release);
        blocker.join().unwrap();
        executor
            .execute(1, &CancellationToken::new(), || ())
            .unwrap();
        assert!(!ran.load(Ordering::Acquire));
        assert_eq!(executor.admission().used(), 0);
    }
}
