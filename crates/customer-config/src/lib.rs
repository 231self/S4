use std::ffi::OsString;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvAlias {
    pub canonical: &'static str,
    pub legacy: &'static str,
}

impl EnvAlias {
    pub const fn new(canonical: &'static str, legacy: &'static str) -> Self {
        Self { canonical, legacy }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum EnvError {
    #[error("{name} contains non-Unicode data")]
    NotUnicode { name: &'static str },
    #[error("conflicting environment aliases: {canonical} and {legacy}")]
    Conflict {
        canonical: &'static str,
        legacy: &'static str,
    },
}

pub mod aliases {
    use super::EnvAlias;

    pub const GATEWAY_URL: EnvAlias = EnvAlias::new("MASKURA_GATEWAY_URL", "S4_GATEWAY_URL");
    pub const ACCESS_KEY: EnvAlias = EnvAlias::new("MASKURA_ACCESS_KEY", "S4_ACCESS_KEY");
    pub const SECRET_KEY: EnvAlias = EnvAlias::new("MASKURA_SECRET_KEY", "S4_SECRET_KEY");
    pub const MCP_TOKEN: EnvAlias = EnvAlias::new("MASKURA_MCP_TOKEN", "S4_MCP_TOKEN");
    pub const PORT: EnvAlias = EnvAlias::new("MASKURA_PORT", "S4_PORT");

    pub const FILTER_COMPONENT: EnvAlias =
        EnvAlias::new("MASKURA_FILTER_COMPONENT", "S4_FILTER_COMPONENT");
    pub const PLUGINS_DIR: EnvAlias = EnvAlias::new("MASKURA_PLUGINS_DIR", "S4_PLUGINS_DIR");
    pub const WASM_FUEL: EnvAlias = EnvAlias::new("MASKURA_WASM_FUEL", "S4_WASM_FUEL");
    pub const SOURCE_MAX_FRAME_BYTES: EnvAlias = EnvAlias::new(
        "MASKURA_SOURCE_MAX_FRAME_BYTES",
        "S4_SOURCE_MAX_FRAME_BYTES",
    );
    pub const MAX_OBJECT_BYTES: EnvAlias =
        EnvAlias::new("MASKURA_MAX_OBJECT_BYTES", "S4_MAX_OBJECT_BYTES");
    pub const MAX_PIPELINE_OUTPUT_BYTES: EnvAlias = EnvAlias::new(
        "MASKURA_MAX_PIPELINE_OUTPUT_BYTES",
        "S4_MAX_PIPELINE_OUTPUT_BYTES",
    );
    pub const STREAMING_READ_MODE: EnvAlias =
        EnvAlias::new("MASKURA_STREAMING_READ_MODE", "S4_STREAMING_READ_MODE");
    pub const TRANSFORMED_READ_SPOOL: EnvAlias = EnvAlias::new(
        "MASKURA_TRANSFORMED_READ_SPOOL",
        "S4_TRANSFORMED_READ_SPOOL",
    );
    pub const PREFIX_SAFE_COMPONENT_HASHES: EnvAlias = EnvAlias::new(
        "MASKURA_PREFIX_SAFE_COMPONENT_HASHES",
        "S4_PREFIX_SAFE_COMPONENT_HASHES",
    );
    pub const STREAMING_WRITE_MODE: EnvAlias =
        EnvAlias::new("MASKURA_STREAMING_WRITE_MODE", "S4_STREAMING_WRITE_MODE");
    pub const STREAMING_S3_PROVIDER: EnvAlias =
        EnvAlias::new("MASKURA_STREAMING_S3_PROVIDER", "S4_STREAMING_S3_PROVIDER");
    pub const ENABLE_AVRO: EnvAlias = EnvAlias::new("MASKURA_ENABLE_AVRO", "S4_ENABLE_AVRO");
    pub const LEGACY_MAX_OBJECT_BYTES: EnvAlias = EnvAlias::new(
        "MASKURA_LEGACY_MAX_OBJECT_BYTES",
        "S4_LEGACY_MAX_OBJECT_BYTES",
    );
    pub const SINGLE_TENANT: EnvAlias = EnvAlias::new("MASKURA_SINGLE_TENANT", "S4_SINGLE_TENANT");
    pub const MULTIPART_MODE: EnvAlias =
        EnvAlias::new("MASKURA_MULTIPART_MODE", "S4_MULTIPART_MODE");
    pub const SPOOL_DIR: EnvAlias = EnvAlias::new("MASKURA_SPOOL_DIR", "S4_SPOOL_DIR");
    pub const SPOOL_MAX_OBJECT_BYTES: EnvAlias = EnvAlias::new(
        "MASKURA_SPOOL_MAX_OBJECT_BYTES",
        "S4_SPOOL_MAX_OBJECT_BYTES",
    );
    pub const SPOOL_QUOTA_BYTES: EnvAlias =
        EnvAlias::new("MASKURA_SPOOL_QUOTA_BYTES", "S4_SPOOL_QUOTA_BYTES");
    pub const DEV_MEMORY_MAX_OBJECT_BYTES: EnvAlias = EnvAlias::new(
        "MASKURA_DEV_MEMORY_MAX_OBJECT_BYTES",
        "S4_DEV_MEMORY_MAX_OBJECT_BYTES",
    );
    pub const DEV_MEMORY_STREAMING: EnvAlias =
        EnvAlias::new("MASKURA_DEV_MEMORY_STREAMING", "S4_DEV_MEMORY_STREAMING");
    pub const KEYS_FILE: EnvAlias = EnvAlias::new("MASKURA_KEYS_FILE", "S4_KEYS_FILE");

    pub const GATEWAY_CUSTOMER_SETTINGS: &[EnvAlias] = &[
        FILTER_COMPONENT,
        PLUGINS_DIR,
        WASM_FUEL,
        SOURCE_MAX_FRAME_BYTES,
        MAX_OBJECT_BYTES,
        MAX_PIPELINE_OUTPUT_BYTES,
        STREAMING_READ_MODE,
        TRANSFORMED_READ_SPOOL,
        PREFIX_SAFE_COMPONENT_HASHES,
        STREAMING_WRITE_MODE,
        STREAMING_S3_PROVIDER,
        ENABLE_AVRO,
        LEGACY_MAX_OBJECT_BYTES,
        SINGLE_TENANT,
        MULTIPART_MODE,
        SPOOL_DIR,
        SPOOL_MAX_OBJECT_BYTES,
        SPOOL_QUOTA_BYTES,
        DEV_MEMORY_MAX_OBJECT_BYTES,
        DEV_MEMORY_STREAMING,
        KEYS_FILE,
        PORT,
    ];

    pub const CLIENT_CUSTOMER_SETTINGS: &[EnvAlias] =
        &[GATEWAY_URL, ACCESS_KEY, SECRET_KEY, MCP_TOKEN];
}

pub fn resolve(alias: EnvAlias) -> Result<Option<String>, EnvError> {
    resolve_with(alias, |name| std::env::var_os(name))
}

pub fn validate(aliases: &[EnvAlias]) -> Result<(), EnvError> {
    for alias in aliases {
        resolve(*alias)?;
    }
    Ok(())
}

pub fn resolve_with(
    alias: EnvAlias,
    mut read: impl FnMut(&str) -> Option<OsString>,
) -> Result<Option<String>, EnvError> {
    let canonical = read(alias.canonical)
        .map(|value| {
            value.into_string().map_err(|_| EnvError::NotUnicode {
                name: alias.canonical,
            })
        })
        .transpose()?;
    let legacy = read(alias.legacy)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| EnvError::NotUnicode { name: alias.legacy })
        })
        .transpose()?;

    match (canonical, legacy) {
        (Some(canonical), Some(legacy)) if canonical != legacy => Err(EnvError::Conflict {
            canonical: alias.canonical,
            legacy: alias.legacy,
        }),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const TEST_ALIAS: EnvAlias = EnvAlias::new("MASKURA_VALUE", "S4_VALUE");

    fn resolve_values(values: &[(&str, &str)]) -> Result<Option<String>, EnvError> {
        let values: HashMap<_, _> = values
            .iter()
            .map(|(name, value)| ((*name).to_string(), OsString::from(value)))
            .collect();
        resolve_with(TEST_ALIAS, |name| values.get(name).cloned())
    }

    #[test]
    fn resolves_canonical_only() {
        assert_eq!(
            resolve_values(&[("MASKURA_VALUE", "canonical")]),
            Ok(Some("canonical".to_string()))
        );
    }

    #[test]
    fn resolves_legacy_only() {
        assert_eq!(
            resolve_values(&[("S4_VALUE", "legacy")]),
            Ok(Some("legacy".to_string()))
        );
    }

    #[test]
    fn accepts_equal_dual_values() {
        assert_eq!(
            resolve_values(&[("MASKURA_VALUE", "same"), ("S4_VALUE", "same")]),
            Ok(Some("same".to_string()))
        );
    }

    #[test]
    fn rejects_differing_dual_values_without_exposing_them() {
        let error = resolve_values(&[("MASKURA_VALUE", "new-secret"), ("S4_VALUE", "old-secret")])
            .unwrap_err();
        let message = error.to_string();
        assert_eq!(
            error,
            EnvError::Conflict {
                canonical: "MASKURA_VALUE",
                legacy: "S4_VALUE"
            }
        );
        assert!(!message.contains("new-secret"));
        assert!(!message.contains("old-secret"));
    }

    #[test]
    fn preserves_empty_values_and_treats_empty_vs_nonempty_as_conflict() {
        assert_eq!(
            resolve_values(&[("MASKURA_VALUE", "")]),
            Ok(Some(String::new()))
        );
        assert_eq!(
            resolve_values(&[("MASKURA_VALUE", ""), ("S4_VALUE", "")]),
            Ok(Some(String::new()))
        );
        assert!(matches!(
            resolve_values(&[("MASKURA_VALUE", ""), ("S4_VALUE", "set")]),
            Err(EnvError::Conflict { .. })
        ));
    }

    #[test]
    fn returns_none_when_both_names_are_absent() {
        assert_eq!(resolve_values(&[]), Ok(None));
    }

    #[test]
    fn shipped_alias_tables_are_canonical_unique_and_customer_only() {
        let aliases = aliases::GATEWAY_CUSTOMER_SETTINGS
            .iter()
            .chain(aliases::CLIENT_CUSTOMER_SETTINGS);
        let mut canonical = std::collections::HashSet::new();
        let mut legacy = std::collections::HashSet::new();
        for alias in aliases {
            assert!(alias.canonical.starts_with("MASKURA_"));
            assert!(alias.legacy.starts_with("S4_"));
            assert!(canonical.insert(alias.canonical));
            assert!(legacy.insert(alias.legacy));
        }
        for operator_only in [
            "S4_SECRET_KEK",
            "S4_SERVICE_BUCKETS",
            "S4_SIGV4_REGION",
            "S4_WORKSPACE_ENDPOINT_ALLOWLIST",
            "S4_PRESIGNED_HTTP_ALLOWLIST",
            "S4_MANAGED_STREAMING_MODE",
            "S4_MULTIPART_STAGING_BUCKET",
        ] {
            assert!(!legacy.contains(operator_only));
        }
    }
}
