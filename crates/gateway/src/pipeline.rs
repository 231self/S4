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
    /// Exact immutable hosted plugin-version identity. Static catalogs omit
    /// this so their serialized snapshots and fingerprints stay compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_version_id: Option<String>,
    /// Disabled steps remain part of the immutable revision fingerprint but
    /// are not loaded or executed. Older persisted resolutions predate this
    /// field and contained only enabled steps.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Bounded canonical JSON configuration (v0.2 steps only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_json: Option<String>,
    pub capabilities: PluginCapabilities,
    /// Sensitive request context is denied unless the resolver explicitly
    /// grants individual fields to this exact step.
    #[serde(default)]
    pub sensitive_grant: s4_wasm_runtime::SensitiveGrant,
}

const fn enabled_by_default() -> bool {
    true
}

/// Fully-resolved, immutable pipeline for one workspace/bucket/direction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PipelineResolution {
    pub locator: PipelineLocator,
    pub steps: Vec<PipelineStep>,
    /// Monotonic hosted publication generation. Static and legacy resolutions
    /// omit it; a republish can therefore freeze a distinct policy identity
    /// even when every step is otherwise byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_generation: Option<u64>,
    /// An empty chain is legal only when this is true.
    #[serde(default)]
    pub explicit_passthrough: bool,
    pub limits: PipelineLimits,
}

#[derive(serde::Deserialize)]
struct PersistedPipelineResolution {
    locator: PipelineLocator,
    steps: Vec<PersistedPipelineStep>,
    #[serde(default)]
    policy_generation: Option<u64>,
    #[serde(default)]
    explicit_passthrough: bool,
    limits: PipelineLimits,
}

#[derive(serde::Deserialize)]
struct PersistedPipelineStep {
    component_hash: String,
    #[serde(default)]
    plugin_version_id: Option<String>,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    config_json: Option<String>,
    capabilities: PluginCapabilities,
    #[serde(default)]
    sensitive_grant: Option<s4_wasm_runtime::SensitiveGrant>,
}

impl<'de> serde::Deserialize<'de> for PipelineResolution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let persisted = PersistedPipelineResolution::deserialize(deserializer)?;
        let static_revision = persisted.locator.revision == "static";
        Ok(Self {
            locator: persisted.locator,
            steps: persisted
                .steps
                .into_iter()
                .map(|step| PipelineStep {
                    component_hash: step.component_hash,
                    plugin_version_id: step.plugin_version_id,
                    enabled: step.enabled,
                    version: step.version,
                    config_json: step.config_json,
                    capabilities: step.capabilities,
                    sensitive_grant: step.sensitive_grant.unwrap_or(if static_revision {
                        s4_wasm_runtime::SensitiveGrant::ALL
                    } else {
                        s4_wasm_runtime::SensitiveGrant::NONE
                    }),
                })
                .collect(),
            policy_generation: persisted.policy_generation,
            explicit_passthrough: persisted.explicit_passthrough,
            limits: persisted.limits,
        })
    }
}

impl PipelineResolution {
    /// Verify persisted or externally resolved policy against the canonical
    /// public fingerprint for this request direction.
    pub fn verify_fingerprint(&self, direction: PipelineDirection) -> Result<(), S4Error> {
        let recomputed = resolution_fingerprint_with_generation(
            direction,
            &self.steps,
            self.explicit_passthrough,
            self.limits,
            self.policy_generation,
        );
        if recomputed != self.locator.fingerprint {
            return Err(S4Error::new(
                codes::CONFIG_INVALID,
                "pipeline fingerprint does not match its immutable resolution",
            ));
        }
        Ok(())
    }
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
                plugin_version_id: None,
                enabled: true,
                version: Some(info.version),
                config_json: None,
                capabilities,
                // Preserve the historical self-hosted contract explicitly;
                // hosted resolutions default to no sensitive grants.
                sensitive_grant: s4_wasm_runtime::SensitiveGrant::ALL,
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
            policy_generation: None,
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

/// Canonical hosted fingerprint extension. Omitting the generation delegates
/// to the original byte contract exactly, preserving every static fingerprint.
pub fn resolution_fingerprint_with_generation(
    direction: PipelineDirection,
    steps: &[PipelineStep],
    explicit_passthrough: bool,
    limits: PipelineLimits,
    policy_generation: Option<u64>,
) -> String {
    let Some(policy_generation) = policy_generation else {
        return resolution_fingerprint(direction, steps, explicit_passthrough, limits);
    };
    let canonical = serde_json::json!({
        "direction": format!("{direction:?}").to_ascii_lowercase(),
        "steps": steps,
        "explicit_passthrough": explicit_passthrough,
        "limits": limits,
        "policy_generation": policy_generation,
    });
    let encoded = serde_json::to_vec(&canonical)
        .expect("canonical fingerprint encoding is always serializable");
    hex::encode(Sha256::digest(&encoded))
}

/// Stable count plus digest fingerprint for the enabled component set. Digest
/// order is canonicalized because compilation COGS is content-addressed, not
/// execution-position-addressed.
pub fn component_digest_evidence(steps: &[PipelineStep]) -> String {
    let mut hashes: Vec<&str> = steps
        .iter()
        .filter(|step| step.enabled)
        .map(|step| step.component_hash.as_str())
        .collect();
    hashes.sort_unstable();
    let canonical =
        serde_json::to_vec(&hashes).expect("component digest evidence is always serializable");
    format!(
        "v1:{}:{}",
        hashes.len(),
        hex::encode(Sha256::digest(canonical))
    )
}

pub(crate) fn plugin_step_info(step: &PipelineStep) -> PluginInfo {
    PluginInfo {
        id: step.component_hash.clone(),
        name: step
            .version
            .clone()
            .unwrap_or_else(|| step.component_hash.chars().take(8).collect()),
        version: step.version.clone().unwrap_or_else(|| "0.1.0".to_string()),
        enabled: step.enabled,
        description: String::new(),
    }
}

pub(crate) fn pipeline_requires_passthrough(resolution: &PipelineResolution) -> bool {
    !resolution.steps.iter().any(|step| step.enabled) && !resolution.explicit_passthrough
}

pub(crate) fn missing_component_error(component_hash: &str) -> S4Error {
    S4Error::new(
        codes::WASM_INIT,
        format!("component {component_hash} is not available from its component source"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_pre_grant_steps_default_enabled_and_deny_sensitive_context() {
        let step: PipelineStep = serde_json::from_value(serde_json::json!({
            "component_hash": "a".repeat(64),
            "version": "0.2.0",
            "config_json": "{\"mode\":\"redact\"}",
            "capabilities": { "prefix_safe_for_read": false }
        }))
        .unwrap();

        assert!(step.enabled);
        assert_eq!(step.sensitive_grant, s4_wasm_runtime::SensitiveGrant::NONE);
        assert_eq!(step.config_json.as_deref(), Some("{\"mode\":\"redact\"}"));
    }

    fn persisted_resolution_without_grant(revision: &str) -> serde_json::Value {
        serde_json::json!({
            "locator": {
                "revision": revision,
                "fingerprint": "legacy-fingerprint"
            },
            "steps": [{
                "component_hash": "b".repeat(64),
                "version": "0.1.0",
                "config_json": null,
                "capabilities": { "prefix_safe_for_read": false }
            }],
            "explicit_passthrough": false,
            "limits": serde_json::to_value(PipelineLimits::default()).unwrap()
        })
    }

    #[test]
    fn old_static_multipart_resolution_restores_legacy_grants_only_for_static_revision() {
        let static_resolution: PipelineResolution =
            serde_json::from_value(persisted_resolution_without_grant("static")).unwrap();
        assert_eq!(
            static_resolution.steps[0].sensitive_grant,
            s4_wasm_runtime::SensitiveGrant::ALL
        );

        let hosted_resolution: PipelineResolution =
            serde_json::from_value(persisted_resolution_without_grant("relational-revision-id"))
                .unwrap();
        assert_eq!(
            hosted_resolution.steps[0].sensitive_grant,
            s4_wasm_runtime::SensitiveGrant::NONE
        );
    }

    #[test]
    fn canonical_fingerprint_round_trips_and_rejects_persisted_tampering() {
        let resolver = StaticPipelineResolver::new(Arc::new(PluginRegistry::new()));
        let resolution = resolver.resolution(PipelineDirection::Write);
        resolution
            .verify_fingerprint(PipelineDirection::Write)
            .unwrap();
        assert_eq!(
            resolution
                .verify_fingerprint(PipelineDirection::Read)
                .unwrap_err()
                .code(),
            codes::CONFIG_INVALID
        );

        let mut persisted: serde_json::Value = serde_json::to_value(&resolution).unwrap();
        persisted["explicit_passthrough"] = serde_json::Value::Bool(false);
        let tampered: PipelineResolution = serde_json::from_value(persisted).unwrap();
        assert_eq!(
            tampered
                .verify_fingerprint(PipelineDirection::Write)
                .unwrap_err()
                .code(),
            codes::CONFIG_INVALID
        );
    }

    #[test]
    fn component_evidence_has_explicit_count_and_order_independent_digest() {
        let step = |hash: &str| PipelineStep {
            component_hash: hash.to_string(),
            plugin_version_id: None,
            enabled: true,
            version: None,
            config_json: None,
            capabilities: PluginCapabilities::default(),
            sensitive_grant: s4_wasm_runtime::SensitiveGrant::NONE,
        };
        let first = component_digest_evidence(&[step("b"), step("a")]);
        let second = component_digest_evidence(&[step("a"), step("b")]);
        assert_eq!(first, second);
        assert!(first.starts_with("v1:2:"));
        assert_eq!(first.len(), 69);
    }

    #[test]
    fn exact_plugin_version_identity_and_policy_generation_are_fingerprint_inputs() {
        let step = |plugin_version_id: &str| PipelineStep {
            component_hash: "a".repeat(64),
            plugin_version_id: Some(plugin_version_id.to_string()),
            enabled: true,
            version: Some("same-label".to_string()),
            config_json: None,
            capabilities: PluginCapabilities::default(),
            sensitive_grant: s4_wasm_runtime::SensitiveGrant::NONE,
        };
        let limits = PipelineLimits::default();
        let first = resolution_fingerprint(
            PipelineDirection::Write,
            &[step("version-a")],
            false,
            limits,
        );
        let second = resolution_fingerprint(
            PipelineDirection::Write,
            &[step("version-b")],
            false,
            limits,
        );
        assert_ne!(
            first, second,
            "exact version identity must distinguish identical bytes and labels"
        );

        let steps = [step("version-a")];
        let generation_one = resolution_fingerprint_with_generation(
            PipelineDirection::Write,
            &steps,
            false,
            limits,
            Some(1),
        );
        let generation_two = resolution_fingerprint_with_generation(
            PipelineDirection::Write,
            &steps,
            false,
            limits,
            Some(2),
        );
        assert_ne!(
            generation_one, generation_two,
            "republishing must advance policy identity"
        );
    }

    #[test]
    fn absent_hosted_identity_fields_preserve_static_serialization_and_fingerprint() {
        let resolver = StaticPipelineResolver::new(Arc::new(PluginRegistry::new()));
        let resolution = resolver.resolution(PipelineDirection::Write);
        let serialized = serde_json::to_value(&resolution).unwrap();
        assert!(serialized.get("policy_generation").is_none());
        assert!(
            serialized["steps"]
                .as_array()
                .unwrap()
                .iter()
                .all(|step| step.get("plugin_version_id").is_none())
        );

        let legacy_canonical = serde_json::json!({
            "direction": "write",
            "steps": resolution.steps,
            "explicit_passthrough": resolution.explicit_passthrough,
            "limits": resolution.limits,
        });
        let legacy = hex::encode(Sha256::digest(
            serde_json::to_vec(&legacy_canonical).unwrap(),
        ));
        assert_eq!(resolution.locator.fingerprint, legacy);
        assert_eq!(
            resolution_fingerprint_with_generation(
                PipelineDirection::Write,
                &resolution.steps,
                resolution.explicit_passthrough,
                resolution.limits,
                None,
            ),
            legacy
        );
    }
}
