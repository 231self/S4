use axum::http::{HeaderMap, HeaderValue};

#[derive(Clone, Copy, Debug)]
pub struct HeaderAlias {
    pub canonical: &'static str,
    pub legacy: &'static str,
}

impl HeaderAlias {
    const fn new(canonical: &'static str, legacy: &'static str) -> Self {
        Self { canonical, legacy }
    }
}

pub const ACCESS_KEY: HeaderAlias = HeaderAlias::new("x-maskura-access-key", "x-s4-access-key");
pub const SECRET_KEY: HeaderAlias = HeaderAlias::new("x-maskura-secret-key", "x-s4-secret-key");
pub const MCP_TOKEN: HeaderAlias = HeaderAlias::new("x-maskura-mcp-token", "x-s4-mcp-token");
pub const STORAGE_MODE: HeaderAlias =
    HeaderAlias::new("x-maskura-storage-mode", "x-s4-storage-mode");
pub const BACKEND_URL: HeaderAlias = HeaderAlias::new("x-maskura-backend-url", "x-s4-backend-url");
pub const PROCESS: HeaderAlias = HeaderAlias::new("x-maskura-process", "x-s4-process");
pub const STABLE_FIELDS: HeaderAlias =
    HeaderAlias::new("x-maskura-stable-fields", "x-s4-stable-fields");
pub const ENCRYPT_FIELDS: HeaderAlias =
    HeaderAlias::new("x-maskura-encrypt-fields", "x-s4-encrypt-fields");
pub const PLUGIN_NAME: HeaderAlias = HeaderAlias::new("x-maskura-plugin-name", "x-s4-plugin-name");

pub const ALL: &[HeaderAlias] = &[
    ACCESS_KEY,
    SECRET_KEY,
    MCP_TOKEN,
    STORAGE_MODE,
    BACKEND_URL,
    PROCESS,
    STABLE_FIELDS,
    ENCRYPT_FIELDS,
    PLUGIN_NAME,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderAliasError {
    Duplicate(&'static str),
    Conflict {
        canonical: &'static str,
        legacy: &'static str,
    },
}

fn unique<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a HeaderValue>, HeaderAliasError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(HeaderAliasError::Duplicate(name));
    }
    Ok(value)
}

pub fn aliased(
    headers: &HeaderMap,
    alias: HeaderAlias,
) -> Result<Option<&HeaderValue>, HeaderAliasError> {
    aliased_unique(headers, alias)
}

pub fn aliased_unique(
    headers: &HeaderMap,
    alias: HeaderAlias,
) -> Result<Option<&HeaderValue>, HeaderAliasError> {
    resolve_pair(
        unique(headers, alias.canonical)?,
        unique(headers, alias.legacy)?,
        alias,
    )
}

fn resolve_pair<'a>(
    canonical: Option<&'a HeaderValue>,
    legacy: Option<&'a HeaderValue>,
    alias: HeaderAlias,
) -> Result<Option<&'a HeaderValue>, HeaderAliasError> {
    match (canonical, legacy) {
        (Some(canonical), Some(legacy)) if canonical.as_bytes() != legacy.as_bytes() => {
            Err(HeaderAliasError::Conflict {
                canonical: alias.canonical,
                legacy: alias.legacy,
            })
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

pub fn validated(headers: &HeaderMap, alias: HeaderAlias) -> Option<&HeaderValue> {
    aliased(headers, alias).expect("customer header aliases were validated before use")
}

pub fn validate_all(headers: &HeaderMap) -> Result<(), HeaderAliasError> {
    for alias in ALL {
        aliased(headers, *alias)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_legacy_and_equal_dual_headers() {
        for names in [
            vec![(ACCESS_KEY.canonical, "value")],
            vec![(ACCESS_KEY.legacy, "value")],
            vec![
                (ACCESS_KEY.canonical, "value"),
                (ACCESS_KEY.legacy, "value"),
            ],
        ] {
            let mut headers = HeaderMap::new();
            for (name, value) in names {
                headers.insert(name, value.parse().unwrap());
            }
            assert_eq!(
                aliased(&headers, ACCESS_KEY)
                    .unwrap()
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "value"
            );
        }
    }

    #[test]
    fn rejects_conflicting_aliases_and_duplicate_names() {
        let mut conflicting = HeaderMap::new();
        conflicting.insert(ACCESS_KEY.canonical, "new".parse().unwrap());
        conflicting.insert(ACCESS_KEY.legacy, "old".parse().unwrap());
        assert_eq!(
            aliased(&conflicting, ACCESS_KEY),
            Err(HeaderAliasError::Conflict {
                canonical: ACCESS_KEY.canonical,
                legacy: ACCESS_KEY.legacy,
            })
        );

        let mut duplicate = HeaderMap::new();
        duplicate.append(PROCESS.canonical, "read".parse().unwrap());
        duplicate.append(PROCESS.canonical, "read".parse().unwrap());
        assert_eq!(
            aliased_unique(&duplicate, PROCESS),
            Err(HeaderAliasError::Duplicate(PROCESS.canonical))
        );
        assert_eq!(
            validate_all(&duplicate),
            Err(HeaderAliasError::Duplicate(PROCESS.canonical))
        );
    }
}
