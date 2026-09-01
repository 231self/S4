pub mod avro;
pub mod backend;
pub mod binary_ir;
pub mod binary_pump;
pub mod binary_reductor;
pub mod control;
pub mod entity;
pub mod format;
pub mod integrity;
pub mod key_cipher;
pub mod managed;
pub mod multipart_staging;
pub mod object;
pub mod pipeline;
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
use pipeline::{ComponentSource, PipelineDirection, PipelineResolver, StaticPipelineResolver};

/// Apply the public engine schema while tolerating private migrations sharing
/// the same `_sqlx_migrations` table.
pub async fn run_engine_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut migrator = sqlx::migrate!("../../migrations");
    migrator.set_ignore_missing(true);
    migrator.run(pool).await
}

#[derive(Clone)]
pub struct Gateway {
    pub engine: Arc<FilterEngine>,
    pub plugins: Option<Arc<PluginRegistry>>,
    /// Per-request pipeline policy seam. `None` disables pipeline resolution
    /// (e.g. `Gateway::new` with no registry).
    pub resolver: Option<Arc<dyn PipelineResolver>>,
    /// Content-addressed component fetches used by the snapshot builder.
    pub component_source: Option<Arc<dyn ComponentSource>>,
}

impl Gateway {
    pub fn new(component_bytes: &[u8]) -> anyhow::Result<Self> {
        let engine = FilterEngine::new(component_bytes)?;
        Ok(Self {
            engine: Arc::new(engine),
            plugins: None,
            resolver: None,
            component_source: None,
        })
    }

    pub fn with_registry(engine: FilterEngine, plugins: Arc<PluginRegistry>) -> Self {
        Self::with_shared_registry(Arc::new(engine), plugins)
    }

    /// Build a gateway around an already compiled immutable engine.
    pub fn with_shared_registry(engine: Arc<FilterEngine>, plugins: Arc<PluginRegistry>) -> Self {
        Self {
            engine,
            plugins: Some(plugins.clone()),
            resolver: Some(Arc::new(StaticPipelineResolver::new(plugins.clone()))),
            component_source: Some(plugins),
        }
    }

    /// Rebuild this gateway with a new resolver/source pair, preserving the
    /// engine and registry compile cache.
    pub fn with_resolver(
        mut self,
        resolver: Arc<dyn PipelineResolver>,
        component_source: Arc<dyn ComponentSource>,
    ) -> Self {
        self.resolver = Some(resolver);
        self.component_source = Some(component_source);
        self
    }

    pub fn pipeline_snapshot(&self) -> Option<plugin_registry::PipelineSnapshot> {
        self.plugins.as_ref().map(|plugins| plugins.snapshot())
    }

    /// Resolve the effective pipeline policy after authentication, before
    /// authorization. This freezes the immutable revision without touching
    /// the component source, so multipart initiation can persist the locator.
    pub async fn resolve(
        &self,
        workspace_id: &str,
        bucket: &str,
        direction: PipelineDirection,
    ) -> Result<pipeline::PipelineResolution, s4_error::S4Error> {
        let resolver = self.resolver.as_ref().ok_or_else(|| {
            s4_error::S4Error::new(
                s4_error::codes::CONFIG_INVALID,
                "no pipeline resolver is configured",
            )
        })?;
        resolver.resolve(workspace_id, bucket, direction).await
    }

    /// Resolve the effective pipeline after authentication, before
    /// authorization. The immutable revision is frozen before any body or
    /// source disclosure so in-flight work cannot be repointed mid-stream.
    pub async fn resolve_pipeline(
        &self,
        workspace_id: &str,
        bucket: &str,
        direction: PipelineDirection,
    ) -> Result<plugin_registry::PipelineSnapshot, s4_error::S4Error> {
        let resolution = self.resolve(workspace_id, bucket, direction).await?;
        self.snapshot_for(&resolution).await
    }

    /// Build an execution snapshot from a previously-frozen resolution (used
    /// for multipart completion, which must resolve the exact revision the
    /// upload started with rather than the current assignment).
    pub async fn snapshot_for(
        &self,
        resolution: &pipeline::PipelineResolution,
    ) -> Result<plugin_registry::PipelineSnapshot, s4_error::S4Error> {
        let source = self.component_source.as_ref().ok_or_else(|| {
            s4_error::S4Error::new(
                s4_error::codes::CONFIG_INVALID,
                "no component source is configured",
            )
        })?;
        let registry = self.plugins.as_ref().ok_or_else(|| {
            s4_error::S4Error::new(
                s4_error::codes::CONFIG_INVALID,
                "no plugin registry is configured",
            )
        })?;
        registry.snapshot_for(resolution, source.as_ref()).await
    }
}
