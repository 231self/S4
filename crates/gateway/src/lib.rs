pub mod backend;
pub mod control;
pub mod entity;
pub mod format;
pub mod integrity;
pub mod key_cipher;
pub mod managed;
pub mod multipart_staging;
pub mod object;
pub mod plugin_registry;
pub mod read_spool;
pub mod record;
pub mod s3_error;
mod s3_safety;
pub mod server;
pub mod service_storage;
pub mod sigv4;
pub mod store;
pub mod transaction;
pub mod workspace_storage;

use plugin_registry::PluginRegistry;
use s4_wasm_runtime::FilterEngine;
use std::sync::Arc;

pub use format::Format;

pub struct Gateway {
    pub engine: Arc<FilterEngine>,
    pub plugins: Option<Arc<PluginRegistry>>,
}

impl Gateway {
    pub fn new(component_bytes: &[u8]) -> anyhow::Result<Self> {
        let engine = FilterEngine::new(component_bytes)?;
        Ok(Self {
            engine: Arc::new(engine),
            plugins: None,
        })
    }

    pub fn with_registry(engine: FilterEngine, plugins: Arc<PluginRegistry>) -> Self {
        Self {
            engine: Arc::new(engine),
            plugins: Some(plugins),
        }
    }

    pub fn pipeline_snapshot(&self) -> Option<plugin_registry::PipelineSnapshot> {
        self.plugins.as_ref().map(|plugins| plugins.snapshot())
    }
}
