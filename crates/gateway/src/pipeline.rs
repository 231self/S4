//! Pipeline resolution seam separating catalog/cache from per-request policy.
//!
//! Self-hosted OSS keeps the historical global behavior behind
//! [`StaticPipelineResolver`]; the hosted control plane injects a relational
//! resolver through the same [`PipelineResolver`] trait. Request paths resolve
//! once after authentication and freeze an immutable
//! [`PipelineResolution`] (revision locator + fingerprint + ordered steps)
//! before touching the body or disclosing the source.

use std::sync::Arc;

use async_trait::async_trait;
use s4_error::{S4Error, codes};
use sha2::{Digest, Sha256};

use crate::plugin_registry::{PipelineLimits, PluginCapabilities, PluginInfo, PluginRegistry};

/// Write vs opt-in processed-read pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PipelineDirection {
    Write,
    Read,
}

/// Immutable identity of one resolved pipeline revision.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PipelineLocator {
    /// Opaque immutable revision identifier (hosted: relational revision UUID;
    /// static self-hosted: `static`).
    pub revision: String,
    /// Canonical fingerprint covering the ordered steps, limits, and
    /// pass-through flag for this direction.
    pub fingerprint: String,
}

/// One ordered, content-addressed step in a resolved pipeline.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PipelineStep {
    pub component_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Bounded canonical JSON configuration (v0.2 steps only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_json: Option<String>,
    pub capabilities: PluginCapabilities,
}

/// Fully-resolved, immutable pipeline for one workspace/bucket/direction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PipelineResolution {
    pub locator: PipelineLocator,
    pub steps: Vec<PipelineStep>,
    /// An empty chain is legal only when this is true.
    #[serde(default)]
    pub explicit_passthrough: bool,
    pub limits: PipelineLimits,
}

/// Resolves the effective pipeline for a workspace + exact bucket + direction.
#[async_trait]
pub trait PipelineResolver: Send + Sync {
    async fn resolve(
        &self,
        workspace_id: &str,
        bucket: &str,
        direction: PipelineDirection,
    ) -> Result<PipelineResolution, S4Error>;
}

/// Loads immutable component bytes by content address.
#[async_trait]
pub trait ComponentSource: Send + Sync {
    async fn load(&self, component_hash: &str) -> Result<bytes::Bytes, S4Error>;
}

/// OSS/self-hosted resolver: the catalog's enabled plugins in order.
///
/// `S4_PLUGINS_DIR` and the bundled default component remain a *catalog* of
/// available artifacts; this resolver decides the pipeline from that catalog
/// exactly as the historical global chain did. An empty enabled set is the
/// operator's explicit pass-through choice.
pub struct StaticPipelineResolver {
    registry: Arc<PluginRegistry>,
}

impl StaticPipelineResolver {
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self { registry }
    }

    fn resolution(&self, direction: PipelineDirection) -> PipelineResolution {
        let catalog = self.registry.enabled_catalog();
        let steps: Vec<PipelineStep> = catalog
            .into_iter()
            .map(|(info, component_hash, capabilities)| PipelineStep {
                component_hash,
                version: Some(info.version),
                config_json: None,
                capabilities,
            })
            .collect();
        let explicit_passthrough = steps.is_empty();
        let limits = self.registry.pipeline_limits();
        let fingerprint = resolution_fingerprint(direction, &steps, explicit_passthrough, limits);
        PipelineResolution {
            locator: PipelineLocator {
                revision: "static".to_string(),
                fingerprint,
            },
            steps,
            explicit_passthrough,
            limits,
        }
    }
}

#[async_trait]
impl PipelineResolver for StaticPipelineResolver {
    async fn resolve(
        &self,
        _workspace_id: &str,
        _bucket: &str,
        direction: PipelineDirection,
    ) -> Result<PipelineResolution, S4Error> {
        Ok(self.resolution(direction))
    }
}

/// Canonical fingerprint over the ordered steps, pass-through flag, limits,
/// and direction. `serde_json` map keys sort canonically (BTreeMap default),
/// so the digest is stable across processes.
pub fn resolution_fingerprint(
    direction: PipelineDirection,
    steps: &[PipelineStep],
    explicit_passthrough: bool,
    limits: PipelineLimits,
) -> String {
    let canonical = serde_json::json!({
        "direction": format!("{direction:?}").to_ascii_lowercase(),
        "steps": steps,
        "explicit_passthrough": explicit_passthrough,
        "limits": limits,
    });
    let encoded = serde_json::to_vec(&canonical)
        .expect("canonical fingerprint encoding is always serializable");
    hex::encode(Sha256::digest(&encoded))
}

pub(crate) fn plugin_step_info(step: &PipelineStep) -> PluginInfo {
    PluginInfo {
        id: step.component_hash.clone(),
        name: step
            .version
            .clone()
            .unwrap_or_else(|| step.component_hash.chars().take(8).collect()),
        version: step.version.clone().unwrap_or_else(|| "0.1.0".to_string()),
        enabled: true,
        description: String::new(),
    }
}

pub(crate) fn pipeline_requires_passthrough(resolution: &PipelineResolution) -> bool {
    resolution.steps.is_empty() && !resolution.explicit_passthrough
}

pub(crate) fn missing_component_error(component_hash: &str) -> S4Error {
    S4Error::new(
        codes::WASM_INIT,
        format!("component {component_hash} is not available from its component source"),
    )
}
