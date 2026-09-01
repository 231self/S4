use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use s4_error::{S4Error, codes};
use s4_wasm_runtime::{
    CancellationToken, ExecutorConfig, FilterEngine, FilterSession, SensitiveGrant,
    TransformOutcome, WasmExecutor,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use tokio::sync::{mpsc, oneshot};

use crate::pipeline::{
    ComponentSource, PipelineResolution, PipelineStep, pipeline_requires_passthrough,
    plugin_step_info,
};
use crate::record::{OutputValidator, Record};

/// Default per-session fuel budget for the plugin pipeline. Set high enough
/// for crypto filters (one RSA-2048 OAEP wrap costs ~25M wasm instructions).
pub const DEFAULT_PIPELINE_FUEL: u64 = 1_000_000_000;

/// Default bound for the digest-keyed compiled-component cache. Weight is the
/// guest-memory reservation of each compiled engine, so this admits roughly
/// sixteen 64 MiB components before evicting least-recently-used entries.
pub const DEFAULT_COMPILE_CACHE_MAX_WEIGHT: usize = 1024 * 1024 * 1024;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PluginCapabilities {
    pub prefix_safe_for_read: bool,
}

#[derive(Clone)]
struct Plugin {
    info: PluginInfo,
    component_hash: String,
    capabilities: PluginCapabilities,
    engine: Arc<FilterEngine>,
}

/// One entry in the bounded digest-keyed compile cache. Weight is the guest
/// memory reservation of the compiled engine; eviction is weighted LRU.
#[derive(Clone)]
struct CacheEntry {
    engine: Arc<FilterEngine>,
    capabilities: PluginCapabilities,
    bytes: Arc<[u8]>,
    weight: usize,
}

#[derive(Clone, Default)]
struct RegistryState {
    plugins: HashMap<String, Plugin>,
    order: Vec<String>,
    engines: HashMap<String, CacheEntry>,
    cache_order: VecDeque<String>,
    cache_weight: usize,
    cache_max_weight: usize,
}

fn touch_cache_entry(state: &mut RegistryState, component_hash: &str) {
    if let Some(pos) = state
        .cache_order
        .iter()
        .position(|hash| hash == component_hash)
    {
        state.cache_order.remove(pos);
    }
    state.cache_order.push_back(component_hash.to_string());
}

fn evict_unreferenced_engines(state: &mut RegistryState) {
    // Catalog engines are pinned. Hosted request-only entries remain bounded
    // by weighted LRU eviction.
    while state.cache_weight > state.cache_max_weight {
        let referenced: HashSet<&str> = state
            .plugins
            .values()
            .map(|plugin| plugin.component_hash.as_str())
            .collect();
        let victim = state
            .cache_order
            .iter()
            .find(|hash| !referenced.contains(hash.as_str()) && state.engines.contains_key(*hash));
        let Some(victim) = victim.cloned() else {
            break;
        };
        if let Some(pos) = state.cache_order.iter().position(|hash| hash == &victim) {
            state.cache_order.remove(pos);
        }
        if let Some(entry) = state.engines.remove(&victim) {
            state.cache_weight = state.cache_weight.saturating_sub(entry.weight);
        }
    }
}

pub struct PluginRegistry {
    state: RwLock<RegistryState>,
    fuel: u64,
    pipeline_limits: PipelineLimits,
    executor: Arc<WasmExecutor>,
    executor_config: ExecutorConfig,
}

#[derive(Clone)]
struct SnapshotPlugin {
    info: PluginInfo,
    component_hash: String,
    enabled: bool,
    config_json: Option<String>,
    capabilities: PluginCapabilities,
    sensitive_grant: SensitiveGrant,
    engine: Option<Arc<FilterEngine>>,
}

#[derive(Clone)]
pub struct PipelineSnapshot {
    plugins: Vec<SnapshotPlugin>,
    limits: PipelineLimits,
    executor: Arc<WasmExecutor>,
    /// Canonical fingerprint of the resolved chain, when produced by a
    /// resolution-aware builder. `None` for the legacy global snapshot.
    fingerprint: Option<String>,
    /// Immutable revision identifier of the resolved chain.
    revision: Option<String>,
}

impl PipelineSnapshot {
    /// COGS evidence for the executed pipeline, if a revision was resolved.
    pub fn pipeline_evidence(
        &self,
        fuel_consumed: u64,
        duration_ms: u64,
        spool_mode: &str,
    ) -> Option<crate::control::PipelineEvidence> {
        let fingerprint = self.fingerprint.as_ref()?;
        let revision = self.revision.as_deref()?;
        let mut hashes: Vec<&str> = self.component_hashes().into_iter().collect();
        hashes.sort_unstable();
        Some(crate::control::PipelineEvidence {
            revision: revision.to_string(),
            fingerprint: fingerprint.clone(),
            components: hashes.join(","),
            fuel_consumed,
            duration_ms,
            spool_mode: spool_mode.to_string(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    output_validator: OutputValidator,
    input_bytes: u64,
    output_bytes: u64,
    stage_output_bytes: Vec<u64>,
    fuel_consumed: u64,
    object_deadline: Instant,
}

enum PipelineCommand {
    Process(Record, oneshot::Sender<Result<Option<Record>, S4Error>>),
    Finish(oneshot::Sender<Result<(Vec<Record>, u64), S4Error>>),
    Cancel,
}

/// Async, backpressured handle to one object-scoped pipeline running on the
/// dedicated Wasm executor. At most one command can be queued in addition to
/// the command currently executing.
pub struct StreamingPipelineSession {
    sender: Option<mpsc::Sender<PipelineCommand>>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<(), S4Error>>>,
    watchdog: Option<tokio::task::JoinHandle<()>>,
    object_deadline: Instant,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Self-hosted component source: serves the content-addressed bytes retained
/// in the bounded compile cache. The static resolver only references digests
/// that startup administration imported, so fetches always hit the cache.
#[async_trait]
impl ComponentSource for PluginRegistry {
    async fn load(&self, component_hash: &str) -> Result<Bytes, S4Error> {
        self.component_bytes(component_hash)
            .map(|bytes| Bytes::from(bytes.to_vec()))
            .ok_or_else(|| crate::pipeline::missing_component_error(component_hash))
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
        Self::with_options_and_cache(fuel, pipeline_limits, executor_config, None)
    }

    pub fn with_options_and_cache(
        fuel: u64,
        pipeline_limits: PipelineLimits,
        executor_config: ExecutorConfig,
        cache_max_weight: Option<usize>,
    ) -> Result<Self, S4Error> {
        if fuel == 0 {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "pipeline fuel must be greater than zero",
            ));
        }
        let cache_max_weight = cache_max_weight.unwrap_or(DEFAULT_COMPILE_CACHE_MAX_WEIGHT);
        if cache_max_weight == 0 {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "component compile cache weight must be greater than zero",
            ));
        }
        Ok(Self {
            state: RwLock::new(RegistryState {
                cache_max_weight,
                ..RegistryState::default()
            }),
            fuel,
            pipeline_limits: pipeline_limits.validate()?,
            executor: Arc::new(WasmExecutor::new(executor_config)?),
            executor_config,
        })
    }

    /// Create an isolated registry that reuses only immutable compiled Wasm
    /// engines and component bytes. Catalog mutations and executor admission
    /// state remain local to the returned registry.
    pub fn isolated_clone(&self) -> Result<Self, S4Error> {
        Ok(Self {
            state: RwLock::new(self.state.read().unwrap().clone()),
            fuel: self.fuel,
            pipeline_limits: self.pipeline_limits,
            executor: Arc::new(WasmExecutor::new(self.executor_config)?),
            executor_config: self.executor_config,
        })
    }

    pub fn import(&self, name: &str, component_bytes: &[u8]) -> anyhow::Result<PluginInfo> {
        self.import_with_capabilities(name, component_bytes, PluginCapabilities::default())
    }

    pub(crate) fn import_with_capabilities(
        &self,
        name: &str,
        component_bytes: &[u8],
        capabilities: PluginCapabilities,
    ) -> anyhow::Result<PluginInfo> {
        let component_hash = hex::encode(Sha256::digest(component_bytes));
        let candidate = match self.cached_engine(&component_hash) {
            Some((engine, registered)) => {
                if registered != capabilities {
                    anyhow::bail!(
                        "component {component_hash} is already registered with different capabilities"
                    );
                }
                engine
            }
            None => {
                // Compile outside the registry lock so a slow first compile
                // never stalls catalog reads or other request paths.
                Arc::new(FilterEngine::with_fuel(component_bytes, self.fuel)?)
            }
        };
        let id = Uuid::new_v4().to_string();
        let info = PluginInfo {
            id: id.clone(),
            name: name.to_string(),
            version: "0.1.0".to_string(),
            enabled: true,
            description: String::new(),
        };
        let mut state = self.state.write().unwrap();
        // Cache insertion and catalog pinning are one transaction. No
        // concurrent insertion can evict this component in between them.
        let engine = if let Some(existing) = state.engines.get(&component_hash) {
            if existing.capabilities != capabilities {
                anyhow::bail!(
                    "component {component_hash} is already registered with different capabilities"
                );
            }
            Arc::clone(&existing.engine)
        } else {
            let weight = candidate.guest_memory_limit();
            state.cache_weight = state.cache_weight.saturating_add(weight);
            state.engines.insert(
                component_hash.clone(),
                CacheEntry {
                    engine: Arc::clone(&candidate),
                    capabilities,
                    bytes: Arc::from(component_bytes),
                    weight,
                },
            );
            candidate
        };
        touch_cache_entry(&mut state, &component_hash);
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
        evict_unreferenced_engines(&mut state);
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
        let removed = state.plugins.remove(id).is_some();
        if removed {
            evict_unreferenced_engines(&mut state);
        }
        removed
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

    /// Look up a compiled engine by component digest, refreshing LRU recency.
    /// Returns the engine and the capabilities recorded at first registration.
    pub(crate) fn cached_engine(
        &self,
        component_hash: &str,
    ) -> Option<(Arc<FilterEngine>, PluginCapabilities)> {
        let mut state = self.state.write().unwrap();
        let entry = state.engines.get(component_hash)?;
        let result = (Arc::clone(&entry.engine), entry.capabilities);
        if let Some(pos) = state
            .cache_order
            .iter()
            .position(|hash| hash == component_hash)
        {
            state.cache_order.remove(pos);
            state.cache_order.push_back(component_hash.to_string());
        }
        Some(result)
    }

    /// Content-addressed bytes retained in the compile cache.
    pub(crate) fn component_bytes(&self, component_hash: &str) -> Option<Arc<[u8]>> {
        self.state
            .read()
            .unwrap()
            .engines
            .get(component_hash)
            .map(|entry| Arc::clone(&entry.bytes))
    }

    /// Insert or refresh a compiled engine in the bounded digest-keyed cache.
    /// Evicts least-recently-used entries until the weighted budget is met.
    fn insert_engine(
        &self,
        component_hash: String,
        engine: Arc<FilterEngine>,
        capabilities: PluginCapabilities,
        bytes: Arc<[u8]>,
        weight: usize,
    ) -> Result<Arc<FilterEngine>, S4Error> {
        let mut state = self.state.write().unwrap();
        if let Some(existing) = state.engines.get(&component_hash) {
            if existing.capabilities != capabilities {
                return Err(S4Error::new(
                    codes::CONFIG_INVALID,
                    format!(
                        "component {component_hash} is already registered with different capabilities"
                    ),
                ));
            }
            let authoritative = Arc::clone(&existing.engine);
            touch_cache_entry(&mut state, &component_hash);
            return Ok(authoritative);
        }
        state.cache_weight = state.cache_weight.saturating_add(weight);
        state.engines.insert(
            component_hash.clone(),
            CacheEntry {
                engine: Arc::clone(&engine),
                capabilities,
                bytes,
                weight,
            },
        );
        touch_cache_entry(&mut state, &component_hash);
        evict_unreferenced_engines(&mut state);
        Ok(engine)
    }

    /// Snapshot builder over an immutable [`PipelineResolution`]. Missing
    /// component bytes are fetched through `source`, hash-verified, compiled
    /// outside the registry lock, and cached for the process lifetime budget.
    pub async fn snapshot_for(
        &self,
        resolution: &PipelineResolution,
        source: &dyn ComponentSource,
    ) -> Result<PipelineSnapshot, S4Error> {
        if pipeline_requires_passthrough(resolution) {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "empty pipeline requires explicit pass-through",
            ));
        }
        let limits = resolution.limits.validate()?;
        let mut plugins = Vec::with_capacity(resolution.steps.len());
        for step in &resolution.steps {
            let engine = if step.enabled {
                Some(self.engine_for(step, source).await?)
            } else {
                None
            };
            plugins.push(SnapshotPlugin {
                info: plugin_step_info(step),
                component_hash: step.component_hash.clone(),
                enabled: step.enabled,
                config_json: step.config_json.clone(),
                capabilities: step.capabilities,
                sensitive_grant: step.sensitive_grant,
                engine,
            });
        }
        PipelineSnapshot {
            plugins,
            limits,
            executor: Arc::clone(&self.executor),
            fingerprint: Some(resolution.locator.fingerprint.clone()),
            revision: Some(resolution.locator.revision.clone()),
        }
        .constrained(self.pipeline_limits)
    }

    async fn engine_for(
        &self,
        step: &PipelineStep,
        source: &dyn ComponentSource,
    ) -> Result<Arc<FilterEngine>, S4Error> {
        if let Some((engine, registered)) = self.cached_engine(&step.component_hash) {
            if registered != step.capabilities {
                return Err(S4Error::new(
                    codes::CONFIG_INVALID,
                    format!(
                        "component {} is already registered with different capabilities",
                        step.component_hash
                    ),
                ));
            }
            return Ok(engine);
        }
        let bytes = source.load(&step.component_hash).await?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != step.component_hash {
            return Err(S4Error::new(
                codes::WASM_INIT,
                format!(
                    "component {} digest mismatch after fetch",
                    step.component_hash
                ),
            ));
        }
        // Compile outside the registry lock (we already hold no lock here).
        let engine = Arc::new(FilterEngine::with_fuel(&bytes, self.fuel).map_err(|error| {
            S4Error::new(
                codes::WASM_INIT,
                format!(
                    "component {} failed to compile: {error}",
                    step.component_hash
                ),
            )
        })?);
        self.insert_engine(
            step.component_hash.clone(),
            Arc::clone(&engine),
            step.capabilities,
            Arc::from(bytes.as_ref()),
            engine.guest_memory_limit(),
        )
    }

    /// Ordered enabled catalog entries for the static/self-hosted resolver.
    pub(crate) fn enabled_catalog(&self) -> Vec<(PluginInfo, String, PluginCapabilities)> {
        let state = self.state.read().unwrap();
        state
            .order
            .iter()
            .filter_map(|id| state.plugins.get(id))
            .filter(|plugin| plugin.info.enabled)
            .map(|plugin| {
                (
                    plugin.info.clone(),
                    plugin.component_hash.clone(),
                    plugin.capabilities,
                )
            })
            .collect()
    }

    pub(crate) fn pipeline_limits(&self) -> PipelineLimits {
        self.pipeline_limits
    }

    pub fn snapshot(&self) -> PipelineSnapshot {
        let state = self.state.read().unwrap();
        let plugins = state
            .order
            .iter()
            .filter_map(|id| state.plugins.get(id))
            .filter(|plugin| plugin.info.enabled)
            .map(|plugin| SnapshotPlugin {
                info: plugin.info.clone(),
                component_hash: plugin.component_hash.clone(),
                enabled: true,
                config_json: None,
                capabilities: plugin.capabilities,
                sensitive_grant: SensitiveGrant::ALL,
                engine: Some(Arc::clone(&plugin.engine)),
            })
            .collect();
        PipelineSnapshot {
            plugins,
            limits: self.pipeline_limits,
            executor: Arc::clone(&self.executor),
            fingerprint: None,
            revision: None,
        }
    }

    pub fn load_from_dir(&self, dir: &Path) -> anyhow::Result<Vec<PluginInfo>> {
        self.load_from_dir_with_capabilities_excluding(dir, &HashSet::new(), None)
    }

    /// Capability declarations and exclusions are supplied by startup
    /// administration, never by component bytes or dashboard requests.
    pub(crate) fn load_from_dir_with_capabilities_excluding(
        &self,
        dir: &Path,
        prefix_safe_hashes: &HashSet<String>,
        excluded_component: Option<&Path>,
    ) -> anyhow::Result<Vec<PluginInfo>> {
        let mut added = Vec::new();
        if !dir.exists() || !dir.is_dir() {
            return Ok(added);
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "wasm"))
            .collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let excluded_component = excluded_component
            .map(std::fs::canonicalize)
            .transpose()?
            .or_else(|| excluded_component.map(Path::to_path_buf));
        for entry in entries {
            let path = entry.path();
            let canonical_path = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            if excluded_component.as_ref() == Some(&canonical_path) {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            let name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
            let hash = hex::encode(Sha256::digest(&bytes));
            let capabilities = PluginCapabilities {
                prefix_safe_for_read: prefix_safe_hashes.contains(&hash),
            };
            match self.import_with_capabilities(name, &bytes, capabilities) {
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
    /// Return a snapshot with endpoint-specific limits. Every field is merged
    /// with `min`, so a caller can only tighten the registry configuration.
    pub fn constrained(&self, constraints: PipelineLimits) -> Result<Self, S4Error> {
        let constraints = constraints.validate()?;
        let mut snapshot = self.clone();
        snapshot.limits.max_intermediate_record_bytes = snapshot
            .limits
            .max_intermediate_record_bytes
            .min(constraints.max_intermediate_record_bytes);
        snapshot.limits.max_plugin_finish_bytes = snapshot
            .limits
            .max_plugin_finish_bytes
            .min(constraints.max_plugin_finish_bytes);
        snapshot.limits.max_input_bytes = snapshot
            .limits
            .max_input_bytes
            .min(constraints.max_input_bytes);
        snapshot.limits.max_output_bytes = snapshot
            .limits
            .max_output_bytes
            .min(constraints.max_output_bytes);
        snapshot.limits.max_expansion_factor = snapshot
            .limits
            .max_expansion_factor
            .min(constraints.max_expansion_factor);
        snapshot.limits.max_expansion_slack_bytes = snapshot
            .limits
            .max_expansion_slack_bytes
            .min(constraints.max_expansion_slack_bytes);
        snapshot.limits.max_plugins = snapshot.limits.max_plugins.min(constraints.max_plugins);
        snapshot.limits.max_cumulative_fuel = snapshot
            .limits
            .max_cumulative_fuel
            .min(constraints.max_cumulative_fuel);
        snapshot.limits.max_wall_time =
            snapshot.limits.max_wall_time.min(constraints.max_wall_time);
        Ok(snapshot)
    }

    pub fn plugin_infos(&self) -> Vec<PluginInfo> {
        self.plugins
            .iter()
            .filter(|plugin| plugin.enabled)
            .map(|plugin| plugin.info.clone())
            .collect()
    }

    pub fn component_hashes(&self) -> Vec<&str> {
        self.plugins
            .iter()
            .filter(|plugin| plugin.enabled)
            .map(|plugin| plugin.component_hash.as_str())
            .collect()
    }

    pub fn capabilities(&self) -> Vec<PluginCapabilities> {
        self.plugins
            .iter()
            .filter(|plugin| plugin.enabled)
            .map(|plugin| plugin.capabilities)
            .collect()
    }

    pub fn guest_memory_reservation(&self) -> Result<usize, S4Error> {
        self.plugins
            .iter()
            .filter(|plugin| plugin.enabled)
            .try_fold(0usize, |total, plugin| {
                total
                    .checked_add(
                        plugin
                            .engine
                            .as_ref()
                            .expect("enabled snapshot plugins have compiled engines")
                            .guest_memory_limit(),
                    )
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
        self.start_session_with_deadline(
            session,
            cancellation,
            Instant::now() + self.limits.max_wall_time,
        )
    }

    pub fn start_session_with_deadline(
        &self,
        session: &s4_wasm_runtime::Session,
        cancellation: CancellationToken,
        requested_deadline: Instant,
    ) -> Result<PipelineSession, S4Error> {
        let enabled_plugins = self.plugins.iter().filter(|plugin| plugin.enabled).count();
        if enabled_plugins > self.limits.max_plugins {
            return Err(limit_error(
                codes::LIMIT_PLUGIN_COUNT,
                "plugin count",
                enabled_plugins as u64,
                self.limits.max_plugins as u64,
            ));
        }
        let mut plugins = Vec::with_capacity(enabled_plugins);
        let mut fuel_consumed = 0u64;
        let object_deadline = requested_deadline.min(Instant::now() + self.limits.max_wall_time);
        for plugin in self.plugins.iter().filter(|plugin| plugin.enabled) {
            let remaining_fuel = self.limits.max_cumulative_fuel - fuel_consumed;
            let mut plugin_session = session.clone();
            plugin_session.config_json = plugin.config_json.clone();
            let filter = plugin
                .engine
                .as_ref()
                .expect("enabled snapshot plugins have compiled engines")
                .start_session_with_control_and_grant(
                    &plugin_session,
                    cancellation.clone(),
                    remaining_fuel,
                    object_deadline,
                    plugin.sensitive_grant,
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
        let output_format = crate::Format::parse(&session.format).unwrap_or(crate::Format::Text);
        Ok(PipelineSession {
            stage_output_bytes: vec![0; plugins.len()],
            plugins,
            limits: self.limits,
            output_validator: OutputValidator::new(
                output_format,
                crate::record::DecoderLimits::default(),
            )?,
            input_bytes: 0,
            output_bytes: 0,
            fuel_consumed,
            object_deadline,
        })
    }

    pub async fn start_streaming_session(
        self,
        session: s4_wasm_runtime::Session,
        cancellation: CancellationToken,
    ) -> Result<StreamingPipelineSession, S4Error> {
        let deadline = Instant::now() + self.limits.max_wall_time;
        self.start_streaming_session_with_deadline(session, cancellation, deadline)
            .await
    }

    pub async fn start_streaming_session_with_deadline(
        self,
        session: s4_wasm_runtime::Session,
        cancellation: CancellationToken,
        requested_deadline: Instant,
    ) -> Result<StreamingPipelineSession, S4Error> {
        let object_deadline = requested_deadline.min(Instant::now() + self.limits.max_wall_time);
        let reservation = self.guest_memory_reservation()?;
        let executor = Arc::clone(&self.executor);
        let task_cancellation = cancellation.clone();
        let executor_cancellation = cancellation.clone();
        let (sender, mut receiver) = mpsc::channel(1);
        let (started_sender, started_receiver) = oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            executor.execute_until(
                reservation,
                &executor_cancellation,
                object_deadline,
                move || {
                    let startup = self.start_session_with_deadline(
                        &session,
                        task_cancellation,
                        object_deadline,
                    );
                    drop(session);
                    let mut pipeline = match startup {
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
                                let _ = response.send(pipeline.finish_with_fuel());
                                break;
                            }
                            PipelineCommand::Cancel => break,
                        }
                    }
                    Ok(())
                },
            )?
        });
        let started = tokio::time::timeout_at(
            tokio::time::Instant::from_std(object_deadline),
            started_receiver,
        )
        .await;
        match started {
            Ok(Ok(Ok(()))) => {
                let watchdog =
                    spawn_deadline_watchdog(&sender, cancellation.clone(), object_deadline);
                Ok(StreamingPipelineSession {
                    sender: Some(sender),
                    cancellation,
                    task: Some(task),
                    watchdog: Some(watchdog),
                    object_deadline,
                })
            }
            Ok(Ok(Err(error))) => {
                cancellation.cancel();
                drop(sender);
                let _ = task.await;
                Err(error)
            }
            Err(_) => {
                cancellation.cancel();
                drop(sender);
                let _ = task.await;
                Err(deadline_error())
            }
            Ok(Err(_)) => {
                cancellation.cancel();
                drop(sender);
                match task.await {
                    Ok(Err(error)) => Err(error),
                    Ok(Ok(())) => Err(S4Error::new(
                        codes::INTERNAL,
                        "Wasm pipeline stopped before session startup",
                    )),
                    Err(error) => Err(S4Error::new(codes::INTERNAL, error.to_string())),
                }
            }
        }
    }
}

impl StreamingPipelineSession {
    pub async fn process(&mut self, record: Record) -> Result<Option<Record>, S4Error> {
        let (response_sender, response_receiver) = oneshot::channel();
        let sender = self.sender.as_ref().ok_or_else(pipeline_stopped)?;
        let deadline = tokio::time::Instant::from_std(self.object_deadline);
        let send = tokio::time::timeout_at(
            deadline,
            sender.send(PipelineCommand::Process(record, response_sender)),
        )
        .await;
        let send_error = match send {
            Ok(Ok(())) => None,
            Ok(Err(_)) => Some(pipeline_stopped()),
            Err(_) => Some(deadline_error()),
        };
        if let Some(error) = send_error {
            let _ = self.abort_and_wait().await;
            return Err(error);
        }
        let result = match tokio::time::timeout_at(deadline, response_receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(pipeline_stopped()),
            Err(_) => Err(deadline_error()),
        };
        if result.is_err() {
            let _ = self.abort_and_wait().await;
        }
        result
    }

    pub async fn finish(mut self) -> Result<(Vec<Record>, u64), S4Error> {
        let (response_sender, response_receiver) = oneshot::channel();
        let Some(sender) = self.sender.take() else {
            let _ = self.abort_and_wait().await;
            return Err(pipeline_stopped());
        };
        let deadline = tokio::time::Instant::from_std(self.object_deadline);
        let send = tokio::time::timeout_at(
            deadline,
            sender.send(PipelineCommand::Finish(response_sender)),
        )
        .await;
        let send_error = match send {
            Ok(Ok(())) => None,
            Ok(Err(_)) => Some(pipeline_stopped()),
            Err(_) => Some(deadline_error()),
        };
        if let Some(error) = send_error {
            drop(sender);
            let _ = self.abort_and_wait().await;
            return Err(error);
        }
        drop(sender);
        let result = match tokio::time::timeout_at(deadline, response_receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(pipeline_stopped()),
            Err(_) => Err(deadline_error()),
        };
        if result.is_err() {
            self.cancellation.cancel();
        }
        let wait = self.wait().await;
        if result.is_ok() {
            wait?;
        }
        result
    }

    pub async fn cancel_and_wait(mut self) -> Result<(), S4Error> {
        self.abort_and_wait().await
    }

    async fn abort_and_wait(&mut self) -> Result<(), S4Error> {
        self.cancellation.cancel();
        self.sender.take();
        self.stop_watchdog().await;
        match self.wait_task().await {
            Err(error) if error.code() == codes::WASM_CANCELLED => Ok(()),
            result => result,
        }
    }

    async fn wait(&mut self) -> Result<(), S4Error> {
        let result = self.wait_task().await;
        self.stop_watchdog().await;
        result
    }

    async fn wait_task(&mut self) -> Result<(), S4Error> {
        match self.task.take() {
            Some(task) => task
                .await
                .map_err(|error| S4Error::new(codes::INTERNAL, error.to_string()))?,
            None => Ok(()),
        }
    }

    async fn stop_watchdog(&mut self) {
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abort();
            let _ = watchdog.await;
        }
    }
}

impl Drop for StreamingPipelineSession {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.sender.take();
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abort();
        }
    }
}

fn spawn_deadline_watchdog(
    sender: &mpsc::Sender<PipelineCommand>,
    cancellation: CancellationToken,
    object_deadline: Instant,
) -> tokio::task::JoinHandle<()> {
    let sender = sender.downgrade();
    tokio::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(object_deadline)).await;
        cancellation.cancel();
        if let Some(sender) = sender.upgrade() {
            let _ = sender.send(PipelineCommand::Cancel).await;
        }
    })
}

fn pipeline_stopped() -> S4Error {
    S4Error::new(codes::WASM_CANCELLED, "Wasm pipeline session stopped")
}

fn deadline_error() -> S4Error {
    S4Error::new(codes::WASM_DEADLINE, "Wasm pipeline deadline exceeded")
}

impl PipelineSession {
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

    pub fn finish(self) -> Result<Vec<Record>, S4Error> {
        self.finish_with_fuel().map(|(records, _)| records)
    }

    fn finish_with_fuel(mut self) -> Result<(Vec<Record>, u64), S4Error> {
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
        self.output_validator
            .finish()
            .map_err(output_validation_error)?;
        Ok((output, self.fuel_consumed))
    }

    pub fn input_bytes(&self) -> u64 {
        self.input_bytes
    }

    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    /// Total guest fuel accounted across the session (COGS evidence).
    pub fn fuel_consumed(&self) -> u64 {
        self.fuel_consumed
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
        self.output_validator
            .push_record(&record)
            .map_err(output_validation_error)?;
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

fn output_validation_error(error: S4Error) -> S4Error {
    S4Error::new(codes::DECODE_INVALID_OUTPUT, error.message().to_string())
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
    use crate::pipeline::PipelineResolver;

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

    fn component_v02() -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/test-components/test-filter-v02.component.wasm"),
        )
        .expect("test-filter-v02.component.wasm; run just build-filters")
    }

    fn session() -> s4_wasm_runtime::Session {
        s4_wasm_runtime::Session {
            format: "text".to_string(),
            content_type: "text/plain".to_string(),
            policy_version: 1,
            operation: s4_wasm_runtime::Operation::Write,
            config_json: None,
            public_key_pem: None,
            stable_key: None,
            stable_fields: None,
        }
    }

    struct FakeFilter {
        name: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
        count: usize,
        finish: Vec<u8>,
        finish_fuel: u64,
        emit: Option<Vec<u8>>,
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
            if let Some(output) = &self.emit {
                return Ok(TransformOutcome::Emit(output.clone()));
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
            Ok((self.finish, self.finish_fuel))
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
            output_validator: OutputValidator::new(
                crate::Format::Text,
                crate::record::DecoderLimits::default(),
            )
            .unwrap(),
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
            finish_fuel: 0,
            emit: None,
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
    fn cache_insertion_returns_the_authoritative_engine_and_rejects_conflicts() {
        let registry = PluginRegistry::new();
        let bytes = component();
        let digest = hex::encode(Sha256::digest(&bytes));
        let first = Arc::new(FilterEngine::with_fuel(&bytes, DEFAULT_PIPELINE_FUEL).unwrap());
        let authoritative = registry
            .insert_engine(
                digest.clone(),
                first.clone(),
                PluginCapabilities::default(),
                Arc::from(bytes.as_slice()),
                first.guest_memory_limit(),
            )
            .unwrap();
        assert!(Arc::ptr_eq(&authoritative, &first));

        let duplicate = Arc::new(FilterEngine::with_fuel(&bytes, DEFAULT_PIPELINE_FUEL).unwrap());
        let authoritative = registry
            .insert_engine(
                digest.clone(),
                duplicate,
                PluginCapabilities::default(),
                Arc::from(bytes.as_slice()),
                first.guest_memory_limit(),
            )
            .unwrap();
        assert!(Arc::ptr_eq(&authoritative, &first));

        let conflicting = Arc::new(FilterEngine::with_fuel(&bytes, DEFAULT_PIPELINE_FUEL).unwrap());
        assert!(
            registry
                .insert_engine(
                    digest,
                    conflicting,
                    PluginCapabilities {
                        prefix_safe_for_read: true,
                    },
                    Arc::from(bytes.as_slice()),
                    first.guest_memory_limit(),
                )
                .is_err()
        );
    }

    #[test]
    fn directory_catalog_preserves_digest_identical_steps() {
        let directory = std::env::temp_dir().join(format!("s4-plugin-dir-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&directory).unwrap();
        let bytes = component();
        std::fs::write(directory.join("a.wasm"), &bytes).unwrap();
        std::fs::write(directory.join("b.wasm"), &bytes).unwrap();
        let registry = PluginRegistry::new();
        let loaded = registry.load_from_dir(&directory).unwrap();
        std::fs::remove_dir_all(directory).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(registry.list().len(), 2);
        assert_eq!(registry.state.read().unwrap().engines.len(), 1);
    }

    #[test]
    fn isolated_clone_shares_compiled_engines_but_not_mutable_state() {
        let registry = PluginRegistry::new();
        let bytes = component();
        let digest = hex::encode(Sha256::digest(&bytes));
        let plugin = registry.import("shared", &bytes).unwrap();
        let isolated = registry.isolated_clone().unwrap();

        let original_engine = registry
            .state
            .read()
            .unwrap()
            .engines
            .get(&digest)
            .unwrap()
            .engine
            .clone();
        let isolated_engine = isolated
            .state
            .read()
            .unwrap()
            .engines
            .get(&digest)
            .unwrap()
            .engine
            .clone();
        assert!(Arc::ptr_eq(&original_engine, &isolated_engine));
        assert!(!Arc::ptr_eq(&registry.executor, &isolated.executor));

        isolated.set_enabled(&plugin.id, false).unwrap();
        assert!(registry.get_info(&plugin.id).unwrap().enabled);
        assert!(!isolated.get_info(&plugin.id).unwrap().enabled);
    }

    #[test]
    fn standard_image_excludes_only_the_explicit_component_path() {
        let directory = std::env::temp_dir().join(format!("s4-image-dir-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&directory).unwrap();
        let bytes = component();
        let explicit = directory.join("pii-default.component.wasm");
        let intentional_duplicate = directory.join("intentional-copy.component.wasm");
        std::fs::write(&explicit, &bytes).unwrap();
        std::fs::write(&intentional_duplicate, &bytes).unwrap();
        let registry = PluginRegistry::new();
        registry.import("pii-default", &bytes).unwrap();
        let loaded = registry
            .load_from_dir_with_capabilities_excluding(&directory, &HashSet::new(), Some(&explicit))
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "intentional-copy.component");
        assert_eq!(registry.list().len(), 2);
        assert_eq!(registry.state.read().unwrap().engines.len(), 1);
    }

    #[test]
    fn catalog_import_is_pinned_before_capacity_eviction() {
        let registry = PluginRegistry::with_options_and_cache(
            DEFAULT_PIPELINE_FUEL,
            PipelineLimits::default(),
            ExecutorConfig::default(),
            Some(1),
        )
        .unwrap();
        let bytes = component();
        let digest = hex::encode(Sha256::digest(&bytes));
        registry.import("pinned", &bytes).unwrap();

        assert!(registry.cached_engine(&digest).is_some());
        assert_eq!(registry.list().len(), 1);
        assert!(registry.state.read().unwrap().cache_weight > 1);
    }

    #[test]
    fn catalog_remove_evicts_engine_after_its_last_pin_disappears() {
        let registry = PluginRegistry::with_options_and_cache(
            DEFAULT_PIPELINE_FUEL,
            PipelineLimits::default(),
            ExecutorConfig::default(),
            Some(1),
        )
        .unwrap();
        let bytes = component();
        let digest = hex::encode(Sha256::digest(&bytes));
        let plugin = registry.import("temporary", &bytes).unwrap();
        assert!(registry.cached_engine(&digest).is_some());

        assert!(registry.remove(&plugin.id));
        assert!(registry.cached_engine(&digest).is_none());
        let state = registry.state.read().unwrap();
        assert_eq!(state.cache_weight, 0);
        assert!(state.cache_order.is_empty());
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
    fn constrained_snapshot_only_lowers_limits() {
        let limits = PipelineLimits {
            max_cumulative_fuel: 25,
            max_wall_time: Duration::from_millis(25),
            ..PipelineLimits::default()
        };
        let registry =
            PluginRegistry::with_options(DEFAULT_PIPELINE_FUEL, limits, ExecutorConfig::default())
                .unwrap();
        let snapshot = registry.snapshot();

        let unchanged = snapshot
            .constrained(PipelineLimits {
                max_cumulative_fuel: 50,
                max_wall_time: Duration::from_millis(50),
                ..PipelineLimits::default()
            })
            .unwrap();
        assert_eq!(unchanged.limits.max_cumulative_fuel, 25);
        assert_eq!(unchanged.limits.max_wall_time, Duration::from_millis(25));

        let lowered = snapshot
            .constrained(PipelineLimits {
                max_intermediate_record_bytes: 64,
                max_plugin_finish_bytes: 63,
                max_input_bytes: 62,
                max_output_bytes: 61,
                max_expansion_factor: 8,
                max_expansion_slack_bytes: 60,
                max_plugins: 2,
                max_cumulative_fuel: 10,
                max_wall_time: Duration::from_millis(10),
            })
            .unwrap();
        assert_eq!(lowered.limits.max_intermediate_record_bytes, 64);
        assert_eq!(lowered.limits.max_plugin_finish_bytes, 63);
        assert_eq!(lowered.limits.max_input_bytes, 62);
        assert_eq!(lowered.limits.max_output_bytes, 61);
        assert_eq!(lowered.limits.max_expansion_factor, 8);
        assert_eq!(lowered.limits.max_expansion_slack_bytes, 60);
        assert_eq!(lowered.limits.max_plugins, 2);
        assert_eq!(lowered.limits.max_cumulative_fuel, 10);
        assert_eq!(lowered.limits.max_wall_time, Duration::from_millis(10));
        assert_eq!(
            snapshot
                .constrained(PipelineLimits {
                    max_cumulative_fuel: 0,
                    ..PipelineLimits::default()
                })
                .err()
                .expect("zero fuel is invalid")
                .code(),
            codes::CONFIG_INVALID
        );
    }

    #[test]
    fn constrained_snapshot_enforces_fuel_and_wall_time() {
        let registry = PluginRegistry::new();
        registry.import("noop", &component()).unwrap();
        let fuel_error = registry
            .snapshot()
            .constrained(PipelineLimits {
                max_cumulative_fuel: 1,
                max_wall_time: Duration::from_secs(1),
                ..PipelineLimits::default()
            })
            .unwrap()
            .start_session(&session(), CancellationToken::new())
            .err()
            .expect("one fuel unit cannot initialize the component");
        assert_eq!(fuel_error.code(), codes::WASM_FUEL);

        let registry = PluginRegistry::new();
        let snapshot = registry
            .snapshot()
            .constrained(PipelineLimits {
                max_cumulative_fuel: DEFAULT_PIPELINE_FUEL,
                max_wall_time: Duration::from_millis(1),
                ..PipelineLimits::default()
            })
            .unwrap();
        let mut pipeline = snapshot
            .start_session(&session(), CancellationToken::new())
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            pipeline.process(Record::new("x", "")).unwrap_err().code(),
            codes::WASM_DEADLINE
        );
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
            .start_session(&session(), CancellationToken::new())
            .unwrap()
            .process(input.clone())
            .unwrap()
            .unwrap();
        let later_output = later_object
            .start_session(&session(), CancellationToken::new())
            .unwrap()
            .process(input)
            .unwrap()
            .unwrap();

        assert_eq!(first_output, Record::new("[REDACTED_EMAIL]", "\n"));
        assert_eq!(later_output, Record::new("alice@example.com", "\n"));
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
    fn finish_fuel_is_included_in_the_reported_total() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut filter = fake("fuel", calls);
        filter.finish_fuel = 17;
        let (_, fuel) = fake_pipeline(vec![filter], PipelineLimits::default())
            .finish_with_fuel()
            .unwrap();
        assert_eq!(fuel, 17);
    }

    #[test]
    fn malformed_transform_output_is_rejected_before_it_reaches_a_sink() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut filter = fake("malformed", calls);
        filter.emit = Some(br#"{"unterminated":"#.to_vec());
        let mut pipeline = fake_pipeline(vec![filter], PipelineLimits::default());
        pipeline.output_validator = OutputValidator::new(
            crate::Format::Jsonl,
            crate::record::DecoderLimits::default(),
        )
        .unwrap();

        let error = pipeline
            .process(Record::new(br#"{"source":true}"#.to_vec(), "\n"))
            .unwrap_err();
        assert_eq!(error.code(), codes::DECODE_INVALID_OUTPUT);
    }

    #[test]
    fn aggregate_transform_and_finish_json_is_rejected_before_commit() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut filter = fake("aggregate", calls);
        filter.emit = Some(br#"{"transform":true}"#.to_vec());
        filter.finish = br#"{"finish":true}"#.to_vec();
        let mut pipeline = fake_pipeline(vec![filter], PipelineLimits::default());
        pipeline.output_validator =
            OutputValidator::new(crate::Format::Json, crate::record::DecoderLimits::default())
                .unwrap();

        assert!(pipeline.process(Record::new("source", "")).is_ok());
        assert_eq!(
            pipeline.finish().unwrap_err().code(),
            codes::DECODE_INVALID_OUTPUT
        );
    }

    #[test]
    fn complete_eight_mibibyte_record_bypasses_only_transport_frame_limit() {
        let mut pipeline = fake_pipeline(Vec::new(), PipelineLimits::default());
        let payload = vec![b'x'; crate::record::DEFAULT_MAX_RECORD_BYTES];
        let output = pipeline
            .process(Record::new(payload.clone(), "\n"))
            .unwrap()
            .unwrap();
        assert_eq!(output.payload.len(), payload.len());
        assert!(pipeline.finish().unwrap().is_empty());
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

    #[tokio::test]
    async fn plugin_count_fuel_and_admission_have_stable_codes() {
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
        match registry
            .snapshot()
            .start_streaming_session(session(), CancellationToken::new())
            .await
        {
            Ok(_) => panic!("admission must reject an over-budget pipeline"),
            Err(error) => assert_eq!(error.code(), codes::WASM_ADMISSION),
        }
    }

    #[tokio::test]
    async fn queued_startup_deadline_cancels_without_leaking_executor_work() {
        let registry = PluginRegistry::with_options(
            DEFAULT_PIPELINE_FUEL,
            PipelineLimits::default(),
            ExecutorConfig {
                workers: 1,
                queue_capacity: 1,
                guest_memory_budget_bytes: 2 * 64 * 1024 * 1024,
            },
        )
        .unwrap();
        let test_component = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/test-components/test-filter.component.wasm"),
        )
        .expect("test-filter.component.wasm; run just build-filters");
        registry.import("test-filter", &test_component).unwrap();
        let snapshot = registry.snapshot();

        let first_cancellation = CancellationToken::new();
        let mut first = snapshot
            .clone()
            .start_streaming_session_with_deadline(
                session(),
                first_cancellation.clone(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        let running = tokio::spawn(async move { first.process(Record::new("loop", "")).await });
        tokio::time::sleep(Duration::from_millis(25)).await;

        let queued_cancellation = CancellationToken::new();
        let error = snapshot
            .clone()
            .start_streaming_session_with_deadline(
                session(),
                queued_cancellation,
                Instant::now() + Duration::from_millis(25),
            )
            .await
            .err()
            .expect("queued startup must time out");
        assert_eq!(error.code(), codes::WASM_DEADLINE);
        assert_eq!(registry.executor.admission().used(), 64 * 1024 * 1024);

        first_cancellation.cancel();
        let first_error = running
            .await
            .unwrap()
            .expect_err("running guest must be cancelled");
        assert_eq!(first_error.code(), codes::WASM_CANCELLED);
        assert_eq!(registry.executor.admission().used(), 0);

        let third = snapshot
            .start_streaming_session_with_deadline(
                session(),
                CancellationToken::new(),
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .expect("executor worker remains available");
        third.cancel_and_wait().await.unwrap();
        assert_eq!(registry.executor.admission().used(), 0);
    }

    #[tokio::test]
    async fn constrained_finish_cap_rejects_large_guest_output() {
        let registry = PluginRegistry::new();
        let test_component = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("target/test-components/test-filter.component.wasm"),
        )
        .expect("test-filter.component.wasm; run just build-filters");
        registry.import("test-filter", &test_component).unwrap();
        let snapshot = registry
            .snapshot()
            .constrained(PipelineLimits {
                max_intermediate_record_bytes: 64 * 1024,
                max_plugin_finish_bytes: 64 * 1024,
                max_input_bytes: 64 * 1024,
                max_output_bytes: 64 * 1024,
                max_expansion_factor: 8,
                max_expansion_slack_bytes: 1024,
                max_plugins: 1,
                max_cumulative_fuel: DEFAULT_PIPELINE_FUEL,
                max_wall_time: Duration::from_secs(1),
            })
            .unwrap();
        let mut configured = session();
        configured.stable_fields = Some("finish-large".to_string());
        let pipeline = snapshot
            .start_streaming_session(configured, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            pipeline.finish().await.unwrap_err().code(),
            codes::LIMIT_FINISH_BYTES
        );
    }

    #[tokio::test]
    async fn finish_timeout_before_enqueue_drops_sender_and_joins_worker() {
        let cancellation = CancellationToken::new();
        let (sender, mut receiver) = mpsc::channel(1);
        let (queued_response, _queued_receiver) = oneshot::channel();
        assert!(
            sender
                .try_send(PipelineCommand::Process(
                    Record::new("queued", ""),
                    queued_response,
                ))
                .is_ok()
        );
        let task = tokio::task::spawn_blocking(move || -> Result<(), S4Error> {
            std::thread::sleep(Duration::from_millis(25));
            while receiver.blocking_recv().is_some() {}
            Ok(())
        });
        let pipeline = StreamingPipelineSession {
            sender: Some(sender),
            cancellation,
            task: Some(task),
            watchdog: None,
            object_deadline: Instant::now() + Duration::from_millis(5),
        };

        let error = tokio::time::timeout(Duration::from_secs(1), pipeline.finish())
            .await
            .expect("finish cleanup must not retain the local sender")
            .expect_err("full command queue must hit the finish deadline");
        assert_eq!(error.code(), codes::WASM_DEADLINE);
    }

    #[tokio::test]
    async fn idle_deadline_watchdog_releases_worker_and_admission() {
        let registry = PluginRegistry::with_options(
            DEFAULT_PIPELINE_FUEL,
            PipelineLimits::default(),
            ExecutorConfig {
                workers: 1,
                queue_capacity: 1,
                guest_memory_budget_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        registry.import("noop", &component()).unwrap();
        let pipeline = registry
            .snapshot()
            .start_streaming_session_with_deadline(
                session(),
                CancellationToken::new(),
                Instant::now() + Duration::from_millis(250),
            )
            .await
            .unwrap();
        assert_eq!(registry.executor.admission().used(), 64 * 1024 * 1024);

        tokio::time::timeout(Duration::from_secs(1), async {
            while registry.executor.admission().used() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("idle deadline must release the executor reservation");
        let error = pipeline
            .cancel_and_wait()
            .await
            .expect_err("watchdog expiry must preserve the deadline result");
        assert_eq!(error.code(), codes::WASM_DEADLINE);
    }

    #[tokio::test]
    async fn watchdog_weak_sender_does_not_keep_dropped_session_alive() {
        let registry = PluginRegistry::with_options(
            DEFAULT_PIPELINE_FUEL,
            PipelineLimits::default(),
            ExecutorConfig {
                workers: 1,
                queue_capacity: 1,
                guest_memory_budget_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        registry.import("noop", &component()).unwrap();
        let pipeline = registry
            .snapshot()
            .start_streaming_session_with_deadline(
                session(),
                CancellationToken::new(),
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(registry.executor.admission().used(), 64 * 1024 * 1024);
        drop(pipeline);

        tokio::time::timeout(Duration::from_secs(1), async {
            while registry.executor.admission().used() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("dropping the last strong sender must stop the idle worker");
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
    fn snapshot_pipeline_processes_records_and_finishes() {
        let registry = PluginRegistry::new();
        registry.import("noop", &component()).unwrap();
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.component_hashes().len(), 1);
        assert_eq!(snapshot.capabilities(), [PluginCapabilities::default()]);
        let mut pipeline = snapshot
            .start_session(&session(), CancellationToken::new())
            .unwrap();
        assert_eq!(
            pipeline.process(Record::new("one", "\n")).unwrap().unwrap(),
            Record::new("one", "\n")
        );
        assert_eq!(
            pipeline.process(Record::new("two", "\n")).unwrap().unwrap(),
            Record::new("two", "\n")
        );
        assert!(pipeline.finish().unwrap().is_empty());
    }

    #[tokio::test]
    async fn snapshot_for_rejects_empty_chain_without_explicit_passthrough() {
        let registry = PluginRegistry::new();
        let resolution = PipelineResolution {
            locator: crate::pipeline::PipelineLocator {
                revision: "test".to_string(),
                fingerprint: "deadbeef".to_string(),
            },
            steps: Vec::new(),
            explicit_passthrough: false,
            limits: PipelineLimits::default(),
        };
        let error = registry
            .snapshot_for(&resolution, &registry)
            .await
            .err()
            .expect("empty pipeline without explicit passthrough must fail");
        assert_eq!(error.code(), codes::CONFIG_INVALID);
    }

    #[tokio::test]
    async fn snapshot_for_rejects_all_disabled_chain_without_explicit_passthrough() {
        let registry = PluginRegistry::new();
        let resolution = PipelineResolution {
            locator: crate::pipeline::PipelineLocator {
                revision: "test".to_string(),
                fingerprint: "deadbeef".to_string(),
            },
            steps: vec![PipelineStep {
                component_hash: "unavailable-disabled-component".to_string(),
                enabled: false,
                version: None,
                config_json: None,
                capabilities: PluginCapabilities::default(),
                sensitive_grant: SensitiveGrant::NONE,
            }],
            explicit_passthrough: false,
            limits: PipelineLimits::default(),
        };
        let error = registry
            .snapshot_for(&resolution, &registry)
            .await
            .err()
            .expect("all-disabled pipeline without pass-through must fail");
        assert_eq!(error.code(), codes::CONFIG_INVALID);
    }

    #[tokio::test]
    async fn snapshot_for_accepts_explicit_passthrough() {
        let registry = PluginRegistry::new();
        let resolution = PipelineResolution {
            locator: crate::pipeline::PipelineLocator {
                revision: "test".to_string(),
                fingerprint: "deadbeef".to_string(),
            },
            steps: Vec::new(),
            explicit_passthrough: true,
            limits: PipelineLimits::default(),
        };
        let snapshot = registry
            .snapshot_for(&resolution, &registry)
            .await
            .expect("explicit pass-through is legal");
        assert!(snapshot.component_hashes().is_empty());
    }

    #[tokio::test]
    async fn resolved_limits_cannot_raise_registry_deployment_limits() {
        let deployment_limits = PipelineLimits {
            max_output_bytes: 128,
            max_cumulative_fuel: 256,
            ..PipelineLimits::default()
        };
        let registry = PluginRegistry::with_options(
            DEFAULT_PIPELINE_FUEL,
            deployment_limits,
            ExecutorConfig::default(),
        )
        .unwrap();
        let resolution = PipelineResolution {
            locator: crate::pipeline::PipelineLocator {
                revision: "test".to_string(),
                fingerprint: "deadbeef".to_string(),
            },
            steps: Vec::new(),
            explicit_passthrough: true,
            limits: PipelineLimits::default(),
        };

        let snapshot = registry.snapshot_for(&resolution, &registry).await.unwrap();
        assert_eq!(snapshot.limits.max_output_bytes, 128);
        assert_eq!(snapshot.limits.max_cumulative_fuel, 256);
    }

    #[tokio::test]
    async fn snapshot_for_verifies_digest_after_component_source_fetch() {
        let registry = PluginRegistry::new();
        let step = PipelineStep {
            component_hash: "bogus-not-a-real-sha256".to_string(),
            enabled: true,
            version: None,
            config_json: None,
            capabilities: PluginCapabilities::default(),
            sensitive_grant: SensitiveGrant::NONE,
        };
        let resolution = PipelineResolution {
            locator: crate::pipeline::PipelineLocator {
                revision: "test".to_string(),
                fingerprint: "deadbeef".to_string(),
            },
            steps: vec![step],
            explicit_passthrough: false,
            limits: PipelineLimits::default(),
        };
        let error = registry
            .snapshot_for(&resolution, &registry)
            .await
            .err()
            .expect("digest mismatch must fail");
        assert_eq!(error.code(), codes::WASM_INIT);
    }

    #[tokio::test]
    async fn static_resolver_freezes_the_enabled_catalog_in_order() {
        let registry = Arc::new(PluginRegistry::new());
        registry.import("b", &component()).unwrap();
        registry.import("a", &component()).unwrap();
        let resolver = crate::pipeline::StaticPipelineResolver::new(registry.clone());
        let resolved = resolver
            .resolve("ws", "bucket", crate::pipeline::PipelineDirection::Write)
            .await
            .unwrap();
        assert_eq!(resolved.locator.revision, "static");
        assert_eq!(resolved.steps.len(), 2);
        assert_eq!(
            resolved.steps[0].version.as_deref(),
            Some(registry.list()[0].version.as_str())
        );
        let snapshot = registry
            .snapshot_for(&resolved, registry.as_ref())
            .await
            .unwrap();
        assert_eq!(snapshot.component_hashes().len(), 2);

        let read_resolved = resolver
            .resolve("ws", "bucket", crate::pipeline::PipelineDirection::Read)
            .await
            .unwrap();
        assert_ne!(
            resolved.locator.fingerprint, read_resolved.locator.fingerprint,
            "write and read pipelines must fingerprint distinctly"
        );
    }

    #[tokio::test]
    async fn component_source_compiles_and_caches_missing_digests() {
        let registry = PluginRegistry::new();
        let bytes = component();
        let digest = hex::encode(Sha256::digest(&bytes));
        let step = PipelineStep {
            component_hash: digest,
            enabled: true,
            version: Some("1.0.0".to_string()),
            config_json: None,
            capabilities: PluginCapabilities::default(),
            sensitive_grant: SensitiveGrant::NONE,
        };
        let resolution = PipelineResolution {
            locator: crate::pipeline::PipelineLocator {
                revision: "test".to_string(),
                fingerprint: "deadbeef".to_string(),
            },
            steps: vec![step],
            explicit_passthrough: false,
            limits: PipelineLimits::default(),
        };
        let source = Arc::new(StaticComponentSource {
            bytes: Arc::new(bytes),
        });
        let snapshot = registry
            .snapshot_for(&resolution, source.as_ref())
            .await
            .expect("digest-verified fetch must compile");
        assert_eq!(
            snapshot.component_hashes(),
            [resolution.steps[0].component_hash.clone()]
        );
        let cached = registry.cached_engine(&resolution.steps[0].component_hash);
        assert!(cached.is_some(), "compiled engine must be cached");
    }

    #[tokio::test]
    async fn resolved_step_applies_its_config_and_explicit_sensitive_grant() {
        let registry = PluginRegistry::new();
        let bytes = component_v02();
        let digest = hex::encode(Sha256::digest(&bytes));
        let resolution = PipelineResolution {
            locator: crate::pipeline::PipelineLocator {
                revision: "configured".to_string(),
                fingerprint: "configured-fingerprint".to_string(),
            },
            steps: vec![PipelineStep {
                component_hash: digest,
                enabled: true,
                version: Some("0.2.0".to_string()),
                config_json: Some(r#"{"region":"eu"}"#.to_string()),
                capabilities: PluginCapabilities::default(),
                sensitive_grant: SensitiveGrant::NONE,
            }],
            explicit_passthrough: false,
            limits: PipelineLimits::default(),
        };
        let source = StaticComponentSource {
            bytes: Arc::new(bytes),
        };
        let snapshot = registry.snapshot_for(&resolution, &source).await.unwrap();
        let mut request = session();
        request.operation = s4_wasm_runtime::Operation::Read;
        request.content_type = "test/require-step-context".to_string();
        request.public_key_pem = Some("must-not-be-shared".to_string());
        request.stable_key = Some(vec![7; 32]);
        request.stable_fields = Some("email".to_string());

        let mut pipeline = snapshot
            .start_session(&request, CancellationToken::new())
            .unwrap();
        assert_eq!(
            pipeline.process(Record::new("payload", "")).unwrap(),
            Some(Record::new("payload", ""))
        );
    }

    struct StaticComponentSource {
        bytes: Arc<Vec<u8>>,
    }

    #[async_trait]
    impl ComponentSource for StaticComponentSource {
        async fn load(&self, _component_hash: &str) -> Result<Bytes, S4Error> {
            Ok(Bytes::from(self.bytes.as_ref().clone()))
        }
    }
}
