use s4_wasm_runtime::FilterEngine;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

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

struct Plugin {
    info: PluginInfo,
    component_bytes: Vec<u8>,
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: RwLock<HashMap<String, Plugin>>,
    order: RwLock<Vec<String>>,
    fuel: u64,
}

/// Default per-session fuel budget for the plugin pipeline. Set high enough
/// for crypto filters (one RSA-2048 OAEP wrap costs ~25M wasm instructions);
/// override per-deployment with `S4_WASM_FUEL`.
pub const DEFAULT_PIPELINE_FUEL: u64 = 1_000_000_000;

impl PluginRegistry {
    pub fn new() -> Self {
        Self::with_fuel(DEFAULT_PIPELINE_FUEL)
    }

    pub fn with_fuel(fuel: u64) -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            order: RwLock::new(Vec::new()),
            fuel,
        }
    }

    pub fn import(&self, name: &str, component_bytes: &[u8]) -> anyhow::Result<PluginInfo> {
        // Validate by attempting to compile
        FilterEngine::new(component_bytes)?;
        let id = Uuid::new_v4().to_string();
        let info = PluginInfo {
            id: id.clone(),
            name: name.to_string(),
            version: "0.1.0".to_string(),
            enabled: true,
            description: String::new(),
        };
        let plugin = Plugin {
            info: info.clone(),
            component_bytes: component_bytes.to_vec(),
        };
        self.plugins.write().unwrap().insert(id.clone(), plugin);
        self.order.write().unwrap().push(id.clone());
        Ok(info)
    }

    pub fn list(&self) -> Vec<PluginInfo> {
        let order = self.order.read().unwrap();
        let plugins = self.plugins.read().unwrap();
        order
            .iter()
            .filter_map(|id| plugins.get(id).map(|p| p.info.clone()))
            .collect()
    }

    pub fn get_info(&self, id: &str) -> Option<PluginInfo> {
        self.plugins.read().unwrap().get(id).map(|p| p.info.clone())
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Option<PluginInfo> {
        let mut plugins = self.plugins.write().unwrap();
        plugins.get_mut(id).map(|p| {
            p.info.enabled = enabled;
            p.info.clone()
        })
    }

    pub fn set_name(&self, id: &str, name: &str) -> Option<PluginInfo> {
        let mut plugins = self.plugins.write().unwrap();
        plugins.get_mut(id).map(|p| {
            p.info.name = name.to_string();
            p.info.clone()
        })
    }

    pub fn remove(&self, id: &str) -> bool {
        let mut plugins = self.plugins.write().unwrap();
        let mut order = self.order.write().unwrap();
        order.retain(|oid| oid != id);
        plugins.remove(id).is_some()
    }

    /// Reorder the pipeline. Plugins not named in `ids` keep their relative
    /// position appended after the named ones, so a partial reorder never
    /// silently drops plugins from the pipeline.
    pub fn reorder(&self, ids: Vec<String>) {
        let plugins = self.plugins.read().unwrap();
        let old_order = self.order.read().unwrap().clone();
        let mut new_order: Vec<String> = Vec::new();
        for id in &ids {
            if plugins.contains_key(id) && !new_order.contains(id) {
                new_order.push(id.clone());
            }
        }
        for id in old_order {
            if !new_order.contains(&id) {
                new_order.push(id);
            }
        }
        let mut order = self.order.write().unwrap();
        *order = new_order;
    }

    pub fn get_engine(&self, id: &str) -> Option<FilterEngineHandle> {
        // Return a handle that can be used to run sessions.
        // We can't return a reference to the FilterEngine because of Wasmtime's
        // single-threaded Store requirement. Instead, we clone the component bytes
        // and the caller creates a temporary engine.
        self.plugins
            .read()
            .unwrap()
            .get(id)
            .map(|p| FilterEngineHandle {
                component_bytes: p.component_bytes.clone(),
            })
    }

    pub fn process_all(
        &self,
        format: super::Format,
        content_type: &str,
        public_key_pem: Option<&str>,
        stable_key: Option<&[u8]>,
        stable_fields: Option<&str>,
        records: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, anyhow::Error> {
        let mut current = records.to_vec();
        let order = self.order.read().unwrap();
        let plugins = self.plugins.read().unwrap();

        for id in order.iter() {
            if let Some(plugin) = plugins.get(id) {
                if !plugin.info.enabled {
                    continue;
                }
                let engine = FilterEngine::with_fuel(&plugin.component_bytes, self.fuel)?;
                let session = s4_wasm_runtime::Session {
                    format: format.as_str().to_string(),
                    content_type: content_type.to_string(),
                    policy_version: 0,
                    public_key_pem: public_key_pem.map(|s| s.to_string()),
                    stable_key: stable_key.map(|k| k.to_vec()),
                    stable_fields: stable_fields.map(|s| s.to_string()),
                };
                let output = engine
                    .run_session(&session, &current)
                    .map_err(|e| anyhow::anyhow!("Plugin {}: {}", plugin.info.name, e))?;
                current = output;
            }
        }
        Ok(current)
    }

    pub fn load_from_dir(&self, dir: &std::path::Path) -> anyhow::Result<Vec<PluginInfo>> {
        let mut added = Vec::new();
        if !dir.exists() || !dir.is_dir() {
            return Ok(added);
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "wasm")
                    .unwrap_or(false)
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let bytes = std::fs::read(&path)?;
            let name = path
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            match self.import(name, &bytes) {
                Ok(info) => {
                    tracing::info!("loaded plugin: {} ({})", name, path.display());
                    added.push(info);
                }
                Err(e) => {
                    tracing::warn!("failed to load plugin {}: {}", name, e);
                }
            }
        }
        Ok(added)
    }
}

pub struct FilterEngineHandle {
    pub component_bytes: Vec<u8>,
}

impl FilterEngineHandle {
    pub fn new_engine(&self) -> anyhow::Result<FilterEngine> {
        FilterEngine::new(&self.component_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes() -> Vec<u8> {
        // Minimal placeholder — import() validates by compiling; use a real
        // noop component if available, otherwise skip compile-heavy paths.
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let path = std::path::Path::new(&dir)
            .join("..")
            .join("..")
            .join("target")
            .join("components")
            .join("noop.component.wasm");
        std::fs::read(path).expect("noop.component.wasm; run just build-filters")
    }

    #[test]
    fn reorder_preserves_unlisted_plugins() {
        let registry = PluginRegistry::new();
        let a = registry.import("a", &bytes()).unwrap();
        let b = registry.import("b", &bytes()).unwrap();
        let c = registry.import("c", &bytes()).unwrap();

        registry.reorder(vec![c.id.clone()]);
        let order: Vec<String> = registry.list().into_iter().map(|p| p.id).collect();
        assert_eq!(order, vec![c.id.clone(), a.id.clone(), b.id.clone()]);
    }

    #[test]
    fn reorder_ignores_unknown_ids() {
        let registry = PluginRegistry::new();
        let a = registry.import("a", &bytes()).unwrap();
        registry.reorder(vec!["does-not-exist".to_string(), a.id.clone()]);
        let names: Vec<String> = registry.list().into_iter().map(|p| p.name).collect();
        assert_eq!(names, vec!["a"]);
    }
}
