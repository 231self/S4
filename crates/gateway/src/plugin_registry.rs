use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use s4_error::{S4Error, codes};
use s4_wasm_runtime::{
    CancellationToken, ExecutorConfig, FilterEngine, FilterSession, TransformOutcome, WasmExecutor,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use tokio::sync::{mpsc, oneshot};

use crate::record::Record;

/// Default per-session fuel budget for the plugin pipeline. Set high enough
/// for crypto filters (one RSA-2048 OAEP wrap costs ~25M wasm instructions).
pub const DEFAULT_PIPELINE_FUEL: u64 = 1_000_000_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PluginCapabilities {
    pub prefix_safe_for_read: bool,
}

struct Plugin {
    info: PluginInfo,
    component_hash: String,
    capabilities: PluginCapabilities,
    engine: Arc<FilterEngine>,
}

#[derive(Default)]
struct RegistryState {
    plugins: HashMap<String, Plugin>,
    order: Vec<String>,
    engines: HashMap<String, Arc<FilterEngine>>,
    capabilities: HashMap<String, PluginCapabilities>,
}

pub struct PluginRegistry {
    state: RwLock<RegistryState>,
    fuel: u64,
    pipeline_limits: PipelineLimits,
    executor: Arc<WasmExecutor>,
}

#[derive(Clone)]
struct SnapshotPlugin {
    info: PluginInfo,
    component_hash: String,
    capabilities: PluginCapabilities,
    engine: Arc<FilterEngine>,
}

#[derive(Clone)]
pub struct PipelineSnapshot {
    plugins: Vec<SnapshotPlugin>,
    limits: PipelineLimits,
    executor: Arc<WasmExecutor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipelineLimits {
    pub max_intermediate_record_bytes: usize,
    pub max_plugin_finish_bytes: usize,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_expansion_factor: u64,
    pub max_expansion_slack_bytes: u64,
    pub max_plugins: usize,
    pub max_cumulative_fuel: u64,
    pub max_wall_time: Duration,
}

impl Default for PipelineLimits {
    fn default() -> Self {
        Self {
            max_intermediate_record_bytes: 16 * 1024 * 1024,
            max_plugin_finish_bytes: 8 * 1024 * 1024,
            max_input_bytes: 5 * 1024 * 1024 * 1024,
            max_output_bytes: 5 * 1024 * 1024 * 1024,
            max_expansion_factor: 32,
            max_expansion_slack_bytes: 1024 * 1024,
            max_plugins: 16,
            max_cumulative_fuel: DEFAULT_PIPELINE_FUEL,
            max_wall_time: Duration::from_secs(5 * 60),
        }
    }
}

impl PipelineLimits {
    fn validate(self) -> Result<Self, S4Error> {
        if self.max_intermediate_record_bytes == 0
            || self.max_plugin_finish_bytes == 0
            || self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_expansion_factor == 0
            || self.max_plugins == 0
            || self.max_cumulative_fuel == 0
            || self.max_wall_time.is_zero()
        {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "pipeline limits except expansion slack must be greater than zero",
            ));
        }
        Ok(self)
    }
}

trait PipelineFilter: Send {
    fn transform(&mut self, payload: &[u8], fuel_limit: u64) -> Result<TransformOutcome, S4Error>;
    fn finish(self: Box<Self>, fuel_limit: u64) -> Result<(Vec<u8>, u64), S4Error>;
    fn fuel_consumed(&self) -> u64;
}

impl PipelineFilter for FilterSession {
    fn transform(&mut self, payload: &[u8], fuel_limit: u64) -> Result<TransformOutcome, S4Error> {
        self.transform_with_fuel_limit(payload, fuel_limit)
    }

    fn finish(self: Box<Self>, fuel_limit: u64) -> Result<(Vec<u8>, u64), S4Error> {
        self.finish_with_fuel_limit(fuel_limit)
    }

    fn fuel_consumed(&self) -> u64 {
        FilterSession::fuel_consumed(self)
    }
}

struct PluginSession {
    name: String,
    filter: Box<dyn PipelineFilter>,
    accounted_fuel: u64,
}

pub struct PipelineSession {
    plugins: Vec<Option<PluginSession>>,
    limits: PipelineLimits,
    input_bytes: u64,
    output_bytes: u64,
    stage_output_bytes: Vec<u64>,
    fuel_consumed: u64,
    object_deadline: Instant,
}

enum PipelineCommand {
    Process(Record, oneshot::Sender<Result<Option<Record>, S4Error>>),
    Finish(oneshot::Sender<Result<Vec<Record>, S4Error>>),
}

/// Async, backpressured handle to one object-scoped pipeline running on the
/// dedicated Wasm executor. At most one command can be queued in addition to
/// the command currently executing.
pub struct StreamingPipelineSession {
    sender: Option<mpsc::Sender<PipelineCommand>>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<(), S4Error>>>,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::with_fuel(DEFAULT_PIPELINE_FUEL)
    }

    pub fn with_fuel(fuel: u64) -> Self {
        let limits = PipelineLimits {
            max_cumulative_fuel: fuel,
            ..PipelineLimits::default()
        };
        Self::with_options(fuel, limits, ExecutorConfig::default())
            .expect("default plugin registry configuration must be valid")
    }

    pub fn with_options(
        fuel: u64,
        pipeline_limits: PipelineLimits,
        executor_config: ExecutorConfig,
    ) -> Result<Self, S4Error> {
        if fuel == 0 {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "pipeline fuel must be greater than zero",
            ));
        }
        Ok(Self {
            state: RwLock::new(RegistryState::default()),
            fuel,
            pipeline_limits: pipeline_limits.validate()?,
            executor: Arc::new(WasmExecutor::new(executor_config)?),
        })
    }

    pub fn import(&self, name: &str, component_bytes: &[u8]) -> anyhow::Result<PluginInfo> {
        self.import_with_capabilities(name, component_bytes, PluginCapabilities::default())
    }

    pub fn import_with_capabilities(
        &self,
        name: &str,
        component_bytes: &[u8],
        capabilities: PluginCapabilities,
    ) -> anyhow::Result<PluginInfo> {
        let component_hash = hex::encode(Sha256::digest(component_bytes));
        let mut state = self.state.write().unwrap();
        let engine = if let Some(engine) = state.engines.get(&component_hash) {
            let registered = state
                .capabilities
                .get(&component_hash)
                .expect("cached component capabilities must exist");
            if registered != &capabilities {
                anyhow::bail!(
                    "component {component_hash} is already registered with different capabilities"
                );
            }
            Arc::clone(engine)
        } else {
            let engine = Arc::new(FilterEngine::with_fuel(component_bytes, self.fuel)?);
            state
                .engines
                .insert(component_hash.clone(), Arc::clone(&engine));
            state
                .capabilities
                .insert(component_hash.clone(), capabilities);
            engine
        };
        let id = Uuid::new_v4().to_string();
        let info = PluginInfo {
            id: id.clone(),
            name: name.to_string(),
            version: "0.1.0".to_string(),
            enabled: true,
            description: String::new(),
        };
        state.plugins.insert(
            id.clone(),
            Plugin {
                info: info.clone(),
                component_hash,
                capabilities,
                engine,
            },
        );
        state.order.push(id);
        Ok(info)
    }

    pub fn list(&self) -> Vec<PluginInfo> {
        let state = self.state.read().unwrap();
        state
            .order
            .iter()
            .filter_map(|id| state.plugins.get(id).map(|plugin| plugin.info.clone()))
            .collect()
    }

    pub fn get_info(&self, id: &str) -> Option<PluginInfo> {
        self.state
            .read()
            .unwrap()
            .plugins
            .get(id)
            .map(|plugin| plugin.info.clone())
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Option<PluginInfo> {
        let mut state = self.state.write().unwrap();
        state.plugins.get_mut(id).map(|plugin| {
            plugin.info.enabled = enabled;
            plugin.info.clone()
        })
    }

    pub fn set_name(&self, id: &str, name: &str) -> Option<PluginInfo> {
        let mut state = self.state.write().unwrap();
        state.plugins.get_mut(id).map(|plugin| {
            plugin.info.name = name.to_string();
            plugin.info.clone()
        })
    }

    pub fn remove(&self, id: &str) -> bool {
        let mut state = self.state.write().unwrap();
        state.order.retain(|ordered_id| ordered_id != id);
        state.plugins.remove(id).is_some()
    }

    /// Plugins omitted from `ids` retain their relative order at the end.
    pub fn reorder(&self, ids: Vec<String>) {
        let mut state = self.state.write().unwrap();
        let old_order = state.order.clone();
        let mut new_order = Vec::with_capacity(old_order.len());
        for id in ids {
            if state.plugins.contains_key(&id) && !new_order.contains(&id) {
                new_order.push(id);
            }
        }
        for id in old_order {
            if !new_order.contains(&id) {
                new_order.push(id);
            }
        }
        state.order = new_order;
    }

    pub fn get_engine(&self, id: &str) -> Option<Arc<FilterEngine>> {
        self.state
            .read()
            .unwrap()
            .plugins
            .get(id)
            .map(|plugin| Arc::clone(&plugin.engine))
    }

    pub fn snapshot(&self) -> PipelineSnapshot {
        self.snapshot_with_skip(&[])
    }

    fn snapshot_with_skip(&self, skip: &[&str]) -> PipelineSnapshot {
        let state = self.state.read().unwrap();
        let plugins = state
            .order
            .iter()
            .filter_map(|id| state.plugins.get(id))
            .filter(|plugin| plugin.info.enabled)
            .filter(|plugin| !plugin_is_skipped(&plugin.info.name, skip))
            .map(|plugin| SnapshotPlugin {
                info: plugin.info.clone(),
                component_hash: plugin.component_hash.clone(),
                capabilities: plugin.capabilities,
                engine: Arc::clone(&plugin.engine),
            })
            .collect();
        PipelineSnapshot {
            plugins,
            limits: self.pipeline_limits,
            executor: Arc::clone(&self.executor),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_all(
        &self,
        format: super::Format,
        content_type: &str,
        public_key_pem: Option<&str>,
        stable_key: Option<&[u8]>,
        stable_fields: Option<&str>,
        records: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, S4Error> {
        self.process_all_with(
            format,
            content_type,
            public_key_pem,
            stable_key,
            stable_fields,
            records,
            &[],
        )
    }

    /// Like `process_all`, but excludes matching plugin names from the snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn process_all_with(
        &self,
        format: super::Format,
        content_type: &str,
        public_key_pem: Option<&str>,
        stable_key: Option<&[u8]>,
        stable_fields: Option<&str>,
        records: &[Vec<u8>],
        skip: &[&str],
    ) -> Result<Vec<Vec<u8>>, S4Error> {
        let snapshot = self.snapshot_with_skip(skip);
        let session = s4_wasm_runtime::Session {
            format: format.as_str().to_string(),
            content_type: content_type.to_string(),
            policy_version: 0,
            public_key_pem: public_key_pem.map(str::to_string),
            stable_key: stable_key.map(<[u8]>::to_vec),
            stable_fields: stable_fields.map(str::to_string),
        };
        let records: Vec<Record> = records
            .iter()
            .map(|payload| Record::new(Bytes::copy_from_slice(payload), Bytes::new()))
            .collect();
        snapshot
            .process_records(session, records, CancellationToken::new())
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| record.payload.to_vec())
                    .collect()
            })
    }

    pub fn load_from_dir(&self, dir: &Path) -> anyhow::Result<Vec<PluginInfo>> {
        let mut added = Vec::new();
        if !dir.exists() || !dir.is_dir() {
            return Ok(added);
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "wasm"))
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let bytes = std::fs::read(&path)?;
            let name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
            match self.import(name, &bytes) {
                Ok(info) => {
                    tracing::info!("loaded plugin: {} ({})", name, path.display());
                    added.push(info);
                }
                Err(error) => tracing::warn!("failed to load plugin {}: {}", name, error),
            }
        }
        Ok(added)
    }
}

impl PipelineSnapshot {
    pub fn plugin_infos(&self) -> Vec<PluginInfo> {
        self.plugins
            .iter()
            .map(|plugin| plugin.info.clone())
            .collect()
    }

    pub fn component_hashes(&self) -> Vec<&str> {
        self.plugins
            .iter()
            .map(|plugin| plugin.component_hash.as_str())
            .collect()
    }

    pub fn capabilities(&self) -> Vec<PluginCapabilities> {
        self.plugins
            .iter()
            .map(|plugin| plugin.capabilities)
            .collect()
    }

    pub fn guest_memory_reservation(&self) -> Result<usize, S4Error> {
        self.plugins.iter().try_fold(0usize, |total, plugin| {
            total
                .checked_add(plugin.engine.guest_memory_limit())
                .ok_or_else(|| {
                    S4Error::new(
                        codes::WASM_ADMISSION,
                        "Wasm guest-memory reservation overflow",
                    )
                })
        })
    }

    pub fn start_session(
        &self,
        session: &s4_wasm_runtime::Session,
        cancellation: CancellationToken,
    ) -> Result<PipelineSession, S4Error> {
        if self.plugins.len() > self.limits.max_plugins {
            return Err(limit_error(
                codes::LIMIT_PLUGIN_COUNT,
                "plugin count",
                self.plugins.len() as u64,
                self.limits.max_plugins as u64,
            ));
        }
        let mut plugins = Vec::with_capacity(self.plugins.len());
        let mut fuel_consumed = 0u64;
        let object_deadline = Instant::now() + self.limits.max_wall_time;
        for plugin in &self.plugins {
            let remaining_fuel = self.limits.max_cumulative_fuel - fuel_consumed;
            let filter = plugin
                .engine
                .start_session_with_control(
                    session,
                    cancellation.clone(),
                    remaining_fuel,
                    object_deadline,
                )
                .map_err(|error| plugin_error(&plugin.info.name, error))?;
            fuel_consumed = fuel_consumed
                .checked_add(filter.fuel_consumed())
                .ok_or_else(fuel_limit_error)?;
            if fuel_consumed > self.limits.max_cumulative_fuel {
                return Err(fuel_limit_error());
            }
            plugins.push(Some(PluginSession {
                name: plugin.info.name.clone(),
                accounted_fuel: filter.fuel_consumed(),
                filter: Box::new(filter),
            }));
        }
        Ok(PipelineSession {
            stage_output_bytes: vec![0; plugins.len()],
            plugins,
            limits: self.limits,
            input_bytes: 0,
            output_bytes: 0,
            fuel_consumed,
            object_deadline,
        })
    }

    pub fn process_records(
        self,
        session: s4_wasm_runtime::Session,
        records: Vec<Record>,
        cancellation: CancellationToken,
    ) -> Result<Vec<Record>, S4Error> {
        let reservation = self.guest_memory_reservation()?;
        let executor = Arc::clone(&self.executor);
        let task_cancellation = cancellation.clone();
        executor.execute(reservation, &cancellation, move || {
            let mut pipeline = self.start_session(&session, task_cancellation)?;
            let mut output = Vec::new();
            for record in records {
                if let Some(record) = pipeline.process(record)? {
                    output.push(record);
                }
            }
            output.extend(pipeline.finish()?);
            Ok::<_, S4Error>(output)
        })?
    }

    pub async fn start_streaming_session(
        self,
        session: s4_wasm_runtime::Session,
        cancellation: CancellationToken,
    ) -> Result<StreamingPipelineSession, S4Error> {
        let reservation = self.guest_memory_reservation()?;
        let executor = Arc::clone(&self.executor);
        let task_cancellation = cancellation.clone();
        let (sender, mut receiver) = mpsc::channel(1);
        let (started_sender, started_receiver) = oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            executor.execute(reservation, &task_cancellation.clone(), move || {
                let mut pipeline = match self.start_session(&session, task_cancellation) {
                    Ok(pipeline) => {
                        let _ = started_sender.send(Ok(()));
                        pipeline
                    }
                    Err(error) => {
                        let _ = started_sender.send(Err(error));
                        return Ok(());
                    }
                };
                while let Some(command) = receiver.blocking_recv() {
                    match command {
                        PipelineCommand::Process(record, response) => {
                            match pipeline.process(record) {
                                Ok(record) => {
                                    let _ = response.send(Ok(record));
                                }
                                Err(error) => {
                                    let _ = response.send(Err(error));
                                    break;
                                }
                            }
                        }
                        PipelineCommand::Finish(response) => {
                            let _ = response.send(pipeline.finish());
                            break;
                        }
                    }
                }
                Ok(())
            })?
        });
        match started_receiver.await {
            Ok(Ok(())) => Ok(StreamingPipelineSession {
                sender: Some(sender),
                cancellation,
                task: Some(task),
            }),
            Ok(Err(error)) => {
                let _ = task.await;
                Err(error)
            }
            Err(_) => match task.await {
                Ok(Err(error)) => Err(error),
                Ok(Ok(())) => Err(S4Error::new(
                    codes::INTERNAL,
                    "Wasm pipeline stopped before session startup",
                )),
                Err(error) => Err(S4Error::new(codes::INTERNAL, error.to_string())),
            },
        }
    }
}

impl StreamingPipelineSession {
    pub async fn process(&mut self, record: Record) -> Result<Option<Record>, S4Error> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.sender
            .as_ref()
            .ok_or_else(pipeline_stopped)?
            .send(PipelineCommand::Process(record, response_sender))
            .await
            .map_err(|_| pipeline_stopped())?;
        response_receiver.await.map_err(|_| pipeline_stopped())?
    }

    pub async fn finish(mut self) -> Result<Vec<Record>, S4Error> {
        let (response_sender, response_receiver) = oneshot::channel();
        let sender = self.sender.take().ok_or_else(pipeline_stopped)?;
        sender
            .send(PipelineCommand::Finish(response_sender))
            .await
            .map_err(|_| pipeline_stopped())?;
        drop(sender);
        let result = response_receiver.await.map_err(|_| pipeline_stopped())?;
        self.wait().await?;
        result
    }

    pub async fn cancel_and_wait(mut self) -> Result<(), S4Error> {
        self.cancellation.cancel();
        self.sender.take();
        self.wait().await
    }

    async fn wait(&mut self) -> Result<(), S4Error> {
        match self.task.take() {
            Some(task) => task
                .await
                .map_err(|error| S4Error::new(codes::INTERNAL, error.to_string()))?,
            None => Ok(()),
        }
    }
}

impl Drop for StreamingPipelineSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.sender.take();
    }
}

fn pipeline_stopped() -> S4Error {
    S4Error::new(codes::WASM_CANCELLED, "Wasm pipeline session stopped")
}

impl PipelineSession {
    pub(crate) fn from_filter(name: impl Into<String>, filter: FilterSession) -> Self {
        let fuel_consumed = filter.fuel_consumed();
        let limits = PipelineLimits::default();
        Self {
            plugins: vec![Some(PluginSession {
                name: name.into(),
                filter: Box::new(filter),
                accounted_fuel: fuel_consumed,
            })],
            limits,
            input_bytes: 0,
            output_bytes: 0,
            stage_output_bytes: vec![0],
            fuel_consumed,
            object_deadline: Instant::now() + limits.max_wall_time,
        }
    }

    pub fn process(&mut self, record: Record) -> Result<Option<Record>, S4Error> {
        self.check_deadline()?;
        self.input_bytes = checked_total(
            codes::LIMIT_INPUT_BYTES,
            "input bytes",
            self.input_bytes,
            record_len(&record),
            self.limits.max_input_bytes,
        )?;
        self.route_from(0, record)
    }

    pub fn finish(mut self) -> Result<Vec<Record>, S4Error> {
        let mut output = Vec::new();
        for index in 0..self.plugins.len() {
            self.check_deadline()?;
            let plugin = self.plugins[index]
                .take()
                .expect("pipeline plugin can only be finished once");
            let name = plugin.name;
            let remaining_fuel = self.remaining_fuel()?;
            let (trailing, plugin_fuel) = plugin
                .filter
                .finish(remaining_fuel)
                .map_err(|error| plugin_error(&name, error))?;
            self.account_fuel(plugin_fuel.saturating_sub(plugin.accounted_fuel))?;
            if trailing.len() > self.limits.max_plugin_finish_bytes {
                return Err(limit_error(
                    codes::LIMIT_FINISH_BYTES,
                    "plugin finish output",
                    trailing.len() as u64,
                    self.limits.max_plugin_finish_bytes as u64,
                ));
            }
            if trailing.is_empty() {
                continue;
            }
            self.check_intermediate(trailing.len())?;
            let record = Record::new(Bytes::from(trailing), Bytes::new());
            self.account_stage(index, record_len(&record))?;
            if let Some(record) = self.route_from(index + 1, record)? {
                output.push(record);
            }
        }
        Ok(output)
    }

    pub fn input_bytes(&self) -> u64 {
        self.input_bytes
    }

    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    fn route_from(&mut self, start: usize, mut record: Record) -> Result<Option<Record>, S4Error> {
        for index in start..self.plugins.len() {
            let remaining_fuel = self.remaining_fuel()?;
            let (name, outcome, fuel_delta) = {
                let plugin = self.plugins[index]
                    .as_mut()
                    .expect("downstream plugin must not be finished yet");
                let outcome = plugin.filter.transform(&record.payload, remaining_fuel);
                let current_fuel = plugin.filter.fuel_consumed();
                let fuel_delta = current_fuel.saturating_sub(plugin.accounted_fuel);
                plugin.accounted_fuel = current_fuel;
                (plugin.name.clone(), outcome, fuel_delta)
            };
            self.account_fuel(fuel_delta)?;
            match outcome.map_err(|error| plugin_error(&name, error))? {
                TransformOutcome::Emit(payload) => {
                    self.check_intermediate(payload.len())?;
                    record.payload = Bytes::from(payload);
                    self.account_stage(index, record_len(&record))?;
                }
                TransformOutcome::Drop => return Ok(None),
            }
        }
        self.account_output(record_len(&record))?;
        Ok(Some(record))
    }

    fn check_intermediate(&self, bytes: usize) -> Result<(), S4Error> {
        if bytes > self.limits.max_intermediate_record_bytes {
            return Err(limit_error(
                codes::LIMIT_INTERMEDIATE_BYTES,
                "intermediate record",
                bytes as u64,
                self.limits.max_intermediate_record_bytes as u64,
            ));
        }
        Ok(())
    }

    fn account_stage(&mut self, index: usize, bytes: u64) -> Result<(), S4Error> {
        let total = self.stage_output_bytes[index]
            .checked_add(bytes)
            .ok_or_else(|| S4Error::new(codes::LIMIT_OUTPUT_BYTES, "stage byte count overflow"))?;
        self.check_cumulative_output(total)?;
        self.stage_output_bytes[index] = total;
        Ok(())
    }

    fn account_output(&mut self, bytes: u64) -> Result<(), S4Error> {
        let total = self
            .output_bytes
            .checked_add(bytes)
            .ok_or_else(|| S4Error::new(codes::LIMIT_OUTPUT_BYTES, "output byte count overflow"))?;
        self.check_cumulative_output(total)?;
        self.output_bytes = total;
        Ok(())
    }

    fn check_cumulative_output(&self, total: u64) -> Result<(), S4Error> {
        if total > self.limits.max_output_bytes {
            return Err(limit_error(
                codes::LIMIT_OUTPUT_BYTES,
                "output bytes",
                total,
                self.limits.max_output_bytes,
            ));
        }
        let expansion_limit = self
            .input_bytes
            .saturating_mul(self.limits.max_expansion_factor)
            .saturating_add(self.limits.max_expansion_slack_bytes)
            .min(self.limits.max_output_bytes);
        if total > expansion_limit {
            return Err(limit_error(
                codes::LIMIT_EXPANSION,
                "cumulative expansion",
                total,
                expansion_limit,
            ));
        }
        Ok(())
    }

    fn remaining_fuel(&self) -> Result<u64, S4Error> {
        self.limits
            .max_cumulative_fuel
            .checked_sub(self.fuel_consumed)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(fuel_limit_error)
    }

    fn check_deadline(&self) -> Result<(), S4Error> {
        if Instant::now() >= self.object_deadline {
            return Err(S4Error::new(
                codes::WASM_DEADLINE,
                "Wasm pipeline wall-time deadline exceeded",
            ));
        }
        Ok(())
    }

    fn account_fuel(&mut self, consumed: u64) -> Result<(), S4Error> {
        self.fuel_consumed = self
            .fuel_consumed
            .checked_add(consumed)
            .ok_or_else(fuel_limit_error)?;
        if self.fuel_consumed > self.limits.max_cumulative_fuel {
            return Err(fuel_limit_error());
        }
        Ok(())
    }
}

fn plugin_is_skipped(name: &str, skip: &[&str]) -> bool {
    skip.contains(&name) || skip.contains(&name.split('.').next().unwrap_or(""))
}

fn plugin_error(name: &str, error: S4Error) -> S4Error {
    S4Error::new(error.code(), format!("plugin {name}: {}", error.message()))
}

fn record_len(record: &Record) -> u64 {
    record.payload.len().saturating_add(record.separator.len()) as u64
}

fn checked_total(
    code: &'static str,
    kind: &str,
    current: u64,
    added: u64,
    limit: u64,
) -> Result<u64, S4Error> {
    let total = current
        .checked_add(added)
        .ok_or_else(|| S4Error::new(code, format!("{kind} count overflow")))?;
    if total > limit {
        return Err(limit_error(code, kind, total, limit));
    }
    Ok(total)
}

fn limit_error(code: &'static str, kind: &str, actual: u64, limit: u64) -> S4Error {
    S4Error::new(code, format!("{kind} {actual} exceeds limit {limit}"))
}

fn fuel_limit_error() -> S4Error {
    S4Error::new(codes::WASM_FUEL, "Wasm pipeline cumulative fuel exhausted")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::Format;

    fn component_named(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("components")
            .join(name);
        std::fs::read(path).unwrap_or_else(|_| panic!("{name}; run just build-filters"))
    }

    fn component() -> Vec<u8> {
        component_named("noop.component.wasm")
    }

    fn session() -> s4_wasm_runtime::Session {
        s4_wasm_runtime::Session {
            format: "text".to_string(),
            content_type: "text/plain".to_string(),
            policy_version: 1,
            ..Default::default()
        }
    }

    struct FakeFilter {
        name: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        count: usize,
        finish: Vec<u8>,
        drop: bool,
        reject: Option<&'static str>,
    }

    impl PipelineFilter for FakeFilter {
        fn transform(
            &mut self,
            payload: &[u8],
            _fuel_limit: u64,
        ) -> Result<TransformOutcome, S4Error> {
            self.count += 1;
            self.calls.lock().unwrap().push(format!(
                "{}:{}",
                self.name,
                String::from_utf8_lossy(payload)
            ));
            if let Some(message) = self.reject {
                return Err(S4Error::new(codes::WASM_REJECT, message));
            }
            if self.drop {
                return Ok(TransformOutcome::Drop);
            }
            let mut output = payload.to_vec();
            output.extend_from_slice(format!("{}{}", self.name, self.count).as_bytes());
            Ok(TransformOutcome::Emit(output))
        }

        fn finish(self: Box<Self>, _fuel_limit: u64) -> Result<(Vec<u8>, u64), S4Error> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:finish", self.name));
            Ok((self.finish, 0))
        }

        fn fuel_consumed(&self) -> u64 {
            0
        }
    }

    fn fake_pipeline(filters: Vec<FakeFilter>, limits: PipelineLimits) -> PipelineSession {
        let plugins: Vec<_> = filters
            .into_iter()
            .map(|filter| {
                Some(PluginSession {
                    name: filter.name.to_string(),
                    filter: Box::new(filter),
                    accounted_fuel: 0,
                })
            })
            .collect();
        PipelineSession {
            stage_output_bytes: vec![0; plugins.len()],
            plugins,
            limits,
            input_bytes: 0,
            output_bytes: 0,
            fuel_consumed: 0,
            object_deadline: Instant::now() + limits.max_wall_time,
        }
    }

    fn fake(name: &'static str, calls: Arc<Mutex<Vec<String>>>) -> FakeFilter {
        FakeFilter {
            name,
            calls,
            count: 0,
            finish: Vec::new(),
            drop: false,
            reject: None,
        }
    }

    #[test]
    fn identical_components_share_one_compiled_engine() {
        let registry = PluginRegistry::new();
        let first = registry.import("a", &component()).unwrap();
        let second = registry.import("b", &component()).unwrap();
        assert!(Arc::ptr_eq(
            &registry.get_engine(&first.id).unwrap(),
            &registry.get_engine(&second.id).unwrap()
        ));
        assert_eq!(registry.state.read().unwrap().engines.len(), 1);
    }

    #[test]
    fn capabilities_are_immutable_per_component_hash() {
        let registry = PluginRegistry::new();
        registry.import("unsafe", &component()).unwrap();
        let error = registry
            .import_with_capabilities(
                "safe",
                &component(),
                PluginCapabilities {
                    prefix_safe_for_read: true,
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("different capabilities"));
    }

    #[test]
    fn snapshot_is_immutable_across_registry_mutation() {
        let registry = PluginRegistry::new();
        let first = registry.import("a", &component()).unwrap();
        let second = registry.import("b", &component()).unwrap();
        let snapshot = registry.snapshot();
        registry.set_enabled(&first.id, false);
        registry.remove(&second.id);
        assert_eq!(
            snapshot
                .plugin_infos()
                .into_iter()
                .map(|plugin| plugin.name)
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(registry.snapshot().plugin_infos().is_empty());
    }

    #[test]
    fn registry_mutation_changes_only_later_object_execution() {
        let registry = PluginRegistry::new();
        let plugin = registry
            .import("email", &component_named("email-detect.component.wasm"))
            .unwrap();
        let first_object = registry.snapshot();
        registry.set_enabled(&plugin.id, false);
        let later_object = registry.snapshot();
        let input = Record::new("alice@example.com", "\n");

        let first_output = first_object
            .process_records(session(), vec![input.clone()], CancellationToken::new())
            .unwrap();
        let later_output = later_object
            .process_records(session(), vec![input], CancellationToken::new())
            .unwrap();

        assert_eq!(first_output[0], Record::new("[REDACTED_EMAIL]", "\n"));
        assert_eq!(later_output[0], Record::new("alice@example.com", "\n"));
    }

    #[test]
    fn record_major_order_and_state_are_preserved() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = fake_pipeline(
            vec![fake("a", calls.clone()), fake("b", calls.clone())],
            PipelineLimits::default(),
        );
        let first = pipeline.process(Record::new("x", "\r\n")).unwrap().unwrap();
        let second = pipeline.process(Record::new("y", "\n")).unwrap().unwrap();
        assert_eq!(first.payload, "xa1b1");
        assert_eq!(first.separator, "\r\n");
        assert_eq!(second.payload, "ya2b2");
        assert_eq!(second.separator, "\n");
        assert_eq!(*calls.lock().unwrap(), ["a:x", "b:xa1", "a:y", "b:ya2"]);
    }

    #[test]
    fn drop_and_reject_stop_downstream_execution() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut dropping = fake("a", calls.clone());
        dropping.drop = true;
        let mut pipeline = fake_pipeline(
            vec![dropping, fake("b", calls.clone())],
            PipelineLimits::default(),
        );
        assert!(pipeline.process(Record::new("x", "\n")).unwrap().is_none());
        assert_eq!(*calls.lock().unwrap(), ["a:x"]);

        let mut rejecting = fake("reject", calls.clone());
        rejecting.reject = Some("no");
        let mut pipeline = fake_pipeline(vec![rejecting], PipelineLimits::default());
        assert_eq!(
            pipeline.process(Record::new("x", "")).unwrap_err().code(),
            codes::WASM_REJECT
        );
    }

    #[test]
    fn finish_output_cascades_only_through_downstream_sessions() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut first = fake("a", calls.clone());
        first.finish = b"tail".to_vec();
        let mut second = fake("b", calls.clone());
        second.finish = b"last".to_vec();
        let output = fake_pipeline(vec![first, second], PipelineLimits::default())
            .finish()
            .unwrap();
        assert_eq!(output[0], Record::new("tailb1", ""));
        assert_eq!(output[1], Record::new("last", ""));
        assert_eq!(*calls.lock().unwrap(), ["a:finish", "b:tail", "b:finish"]);
    }

    #[test]
    fn limits_have_stable_codes() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let limits = PipelineLimits {
            max_wall_time: Duration::from_nanos(1),
            ..PipelineLimits::default()
        };
        let mut pipeline = fake_pipeline(Vec::new(), limits);
        assert_eq!(
            pipeline.process(Record::new("x", "")).unwrap_err().code(),
            codes::WASM_DEADLINE
        );

        let limits = PipelineLimits {
            max_input_bytes: 1,
            ..PipelineLimits::default()
        };
        let mut pipeline = fake_pipeline(Vec::new(), limits);
        assert_eq!(
            pipeline.process(Record::new("xx", "")).unwrap_err().code(),
            codes::LIMIT_INPUT_BYTES
        );

        let limits = PipelineLimits {
            max_output_bytes: 2,
            ..PipelineLimits::default()
        };
        let mut pipeline = fake_pipeline(vec![fake("a", calls.clone())], limits);
        assert_eq!(
            pipeline.process(Record::new("x", "")).unwrap_err().code(),
            codes::LIMIT_OUTPUT_BYTES
        );

        let limits = PipelineLimits {
            max_expansion_factor: 1,
            max_expansion_slack_bytes: 0,
            ..PipelineLimits::default()
        };
        let mut pipeline = fake_pipeline(vec![fake("a", calls.clone())], limits);
        assert_eq!(
            pipeline.process(Record::new("x", "")).unwrap_err().code(),
            codes::LIMIT_EXPANSION
        );

        let limits = PipelineLimits {
            max_intermediate_record_bytes: 2,
            ..PipelineLimits::default()
        };
        let mut pipeline = fake_pipeline(vec![fake("a", calls.clone())], limits);
        assert_eq!(
            pipeline.process(Record::new("xx", "")).unwrap_err().code(),
            codes::LIMIT_INTERMEDIATE_BYTES
        );

        let mut finishing = fake("a", calls);
        finishing.finish = b"long".to_vec();
        let limits = PipelineLimits {
            max_plugin_finish_bytes: 2,
            ..PipelineLimits::default()
        };
        assert_eq!(
            fake_pipeline(vec![finishing], limits)
                .finish()
                .unwrap_err()
                .code(),
            codes::LIMIT_FINISH_BYTES
        );
    }

    #[test]
    fn plugin_count_fuel_and_admission_have_stable_codes() {
        let plugin_limits = PipelineLimits {
            max_plugins: 1,
            ..PipelineLimits::default()
        };
        let registry = PluginRegistry::with_options(
            DEFAULT_PIPELINE_FUEL,
            plugin_limits,
            ExecutorConfig::default(),
        )
        .unwrap();
        registry.import("a", &component()).unwrap();
        registry.import("b", &component()).unwrap();
        assert_eq!(
            registry
                .snapshot()
                .start_session(&session(), CancellationToken::new())
                .err()
                .unwrap()
                .code(),
            codes::LIMIT_PLUGIN_COUNT
        );

        let fuel_limits = PipelineLimits {
            max_cumulative_fuel: 1,
            ..PipelineLimits::default()
        };
        let registry = PluginRegistry::with_options(
            DEFAULT_PIPELINE_FUEL,
            fuel_limits,
            ExecutorConfig::default(),
        )
        .unwrap();
        registry.import("a", &component()).unwrap();
        assert_eq!(
            registry
                .snapshot()
                .start_session(&session(), CancellationToken::new())
                .err()
                .unwrap()
                .code(),
            codes::WASM_FUEL
        );

        let registry = PluginRegistry::with_options(
            DEFAULT_PIPELINE_FUEL,
            PipelineLimits::default(),
            ExecutorConfig {
                workers: 1,
                queue_capacity: 1,
                guest_memory_budget_bytes: 1,
            },
        )
        .unwrap();
        registry.import("a", &component()).unwrap();
        assert_eq!(
            registry
                .process_all(
                    Format::Text,
                    "text/plain",
                    None,
                    None,
                    None,
                    &[b"x".to_vec()],
                )
                .unwrap_err()
                .code(),
            codes::WASM_ADMISSION
        );
    }

    #[test]
    fn reorder_preserves_unlisted_plugins() {
        let registry = PluginRegistry::new();
        let a = registry.import("a", &component()).unwrap();
        let b = registry.import("b", &component()).unwrap();
        let c = registry.import("c", &component()).unwrap();
        registry.reorder(vec![c.id.clone()]);
        assert_eq!(
            registry
                .list()
                .into_iter()
                .map(|plugin| plugin.id)
                .collect::<Vec<_>>(),
            [c.id, a.id, b.id]
        );
    }

    #[test]
    fn compatibility_wrapper_uses_snapshot_pipeline() {
        let registry = PluginRegistry::new();
        registry.import("noop", &component()).unwrap();
        let records = vec![b"one".to_vec(), b"two".to_vec()];
        assert_eq!(
            registry
                .process_all(Format::Text, "text/plain", None, None, None, &records)
                .unwrap(),
            records
        );
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.component_hashes().len(), 1);
        assert_eq!(snapshot.capabilities(), [PluginCapabilities::default()]);
        snapshot
            .start_session(&session(), CancellationToken::new())
            .unwrap();
    }
}
