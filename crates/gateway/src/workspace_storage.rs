use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use utoipa::ToSchema;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WorkspaceId(String);

impl WorkspaceId {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkspaceStorageError> {
        let value = value.into();
        if value.is_empty() {
            return Err(WorkspaceStorageError::InvalidConfig(
                "workspace id must not be empty".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    S3Compatible,
    AwsRole,
    Managed,
}

/// Dashboard request DTO. Secrets are accepted only on writes and are never
/// reused as a response type. JSON uses `backend_type`: `managed` needs no
/// other fields; `s3_compatible` needs `endpoint`, `access_key`, `secret_key`,
/// and `region`.
#[derive(Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BackendConfigRequest {
    pub backend_type: BackendType,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub role_arn: String,
}

/// Redacted dashboard representation. Credential material is intentionally
/// absent from this type, so a GET cannot serialize it by mistake. Its exact
/// JSON keys are `configured`, `backend_type`, `endpoint`, `region`,
/// `role_arn`, `access_key_configured`, and `secret_key_configured`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct BackendConfigResponse {
    pub configured: bool,
    pub backend_type: Option<BackendType>,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub role_arn: Option<String>,
    pub access_key_configured: bool,
    pub secret_key_configured: bool,
}

impl BackendConfigResponse {
    pub fn unconfigured() -> Self {
        Self {
            configured: false,
            backend_type: None,
            endpoint: None,
            region: None,
            role_arn: None,
            access_key_configured: false,
            secret_key_configured: false,
        }
    }
}

/// Decrypted runtime configuration. This type deliberately implements neither
/// `Serialize` nor `ToSchema`.
#[derive(Clone)]
pub enum RuntimeBackendConfig {
    S3Compatible {
        endpoint: String,
        access_key: String,
        secret_key: String,
        region: String,
    },
    Managed,
}

impl RuntimeBackendConfig {
    pub fn redacted(&self) -> BackendConfigResponse {
        match self {
            Self::S3Compatible {
                endpoint,
                access_key,
                secret_key,
                region,
            } => BackendConfigResponse {
                configured: true,
                backend_type: Some(BackendType::S3Compatible),
                endpoint: Some(endpoint.clone()),
                region: Some(region.clone()),
                role_arn: None,
                access_key_configured: !access_key.is_empty(),
                secret_key_configured: !secret_key.is_empty(),
            },
            Self::Managed => BackendConfigResponse {
                configured: true,
                backend_type: Some(BackendType::Managed),
                endpoint: None,
                region: None,
                role_arn: None,
                access_key_configured: false,
                secret_key_configured: false,
            },
        }
    }
}

impl TryFrom<BackendConfigRequest> for RuntimeBackendConfig {
    type Error = WorkspaceStorageError;

    fn try_from(request: BackendConfigRequest) -> Result<Self, Self::Error> {
        match request.backend_type {
            BackendType::AwsRole => Err(WorkspaceStorageError::UnsupportedConfig(
                "aws_role backend authentication is not implemented".to_string(),
            )),
            BackendType::Managed => {
                if [
                    request.endpoint,
                    request.access_key,
                    request.secret_key,
                    request.region,
                    request.role_arn,
                ]
                .iter()
                .any(|value| !value.trim().is_empty())
                {
                    return Err(WorkspaceStorageError::InvalidConfig(
                        "managed backend configuration must not include endpoint, region, role, or credentials"
                            .to_string(),
                    ));
                }
                Ok(Self::Managed)
            }
            BackendType::S3Compatible => {
                for (name, value) in [
                    ("endpoint", request.endpoint.as_str()),
                    ("access_key", request.access_key.as_str()),
                    ("secret_key", request.secret_key.as_str()),
                    ("region", request.region.as_str()),
                ] {
                    if value.trim().is_empty() {
                        return Err(WorkspaceStorageError::InvalidConfig(format!(
                            "{name} is required for s3_compatible backends"
                        )));
                    }
                }
                let endpoint = reqwest::Url::parse(&request.endpoint).map_err(|_| {
                    WorkspaceStorageError::InvalidConfig(
                        "endpoint must be an absolute HTTP(S) URL".to_string(),
                    )
                })?;
                if !matches!(endpoint.scheme(), "http" | "https")
                    || endpoint.host_str().is_none()
                    || !endpoint.username().is_empty()
                    || endpoint.password().is_some()
                    || endpoint.query().is_some()
                    || endpoint.fragment().is_some()
                {
                    return Err(WorkspaceStorageError::InvalidConfig(
                        "endpoint must be an absolute HTTP(S) origin without credentials, query, or fragment"
                            .to_string(),
                    ));
                }
                Ok(Self::S3Compatible {
                    endpoint: request.endpoint,
                    access_key: request.access_key,
                    secret_key: request.secret_key,
                    region: request.region,
                })
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceStorageError {
    #[error("invalid workspace storage configuration: {0}")]
    InvalidConfig(String),
    #[error("unsupported workspace storage configuration: {0}")]
    UnsupportedConfig(String),
    #[error("workspace storage repository failed: {0}")]
    Repository(String),
}

/// Public injection seam for private workspace mapping and encrypted backend
/// persistence. Implementations may map many users to one opaque workspace.
#[async_trait]
pub trait WorkspaceStorageRepository: Send + Sync + 'static {
    async fn resolve_workspace(&self, user_id: &str) -> Result<WorkspaceId, WorkspaceStorageError>;

    async fn get_runtime_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<RuntimeBackendConfig>, WorkspaceStorageError>;

    async fn get_public_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError>;

    async fn put_config(
        &self,
        workspace_id: &WorkspaceId,
        request: BackendConfigRequest,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError>;
}

#[derive(Default)]
pub struct InMemoryWorkspaceStorageRepository {
    configs: RwLock<HashMap<WorkspaceId, RuntimeBackendConfig>>,
}

impl InMemoryWorkspaceStorageRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WorkspaceStorageRepository for InMemoryWorkspaceStorageRepository {
    async fn resolve_workspace(&self, user_id: &str) -> Result<WorkspaceId, WorkspaceStorageError> {
        WorkspaceId::new(user_id)
    }

    async fn get_runtime_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<RuntimeBackendConfig>, WorkspaceStorageError> {
        Ok(self.configs.read().await.get(workspace_id).cloned())
    }

    async fn get_public_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
        Ok(self
            .configs
            .read()
            .await
            .get(workspace_id)
            .map(RuntimeBackendConfig::redacted)
            .unwrap_or_else(BackendConfigResponse::unconfigured))
    }

    async fn put_config(
        &self,
        workspace_id: &WorkspaceId,
        request: BackendConfigRequest,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
        let config = RuntimeBackendConfig::try_from(request)?;
        let response = config.redacted();
        self.configs
            .write()
            .await
            .insert(workspace_id.clone(), config);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> BackendConfigRequest {
        BackendConfigRequest {
            backend_type: BackendType::S3Compatible,
            endpoint: "https://objects.example".to_string(),
            access_key: "access".to_string(),
            secret_key: "secret".to_string(),
            region: "us-east-1".to_string(),
            role_arn: String::new(),
        }
    }

    #[tokio::test]
    async fn in_memory_repository_is_async_redacted_and_defaults_to_no_config() {
        let repository = InMemoryWorkspaceStorageRepository::new();
        let workspace = repository.resolve_workspace("user-1").await.unwrap();
        assert_eq!(workspace.as_str(), "user-1");
        assert_eq!(
            repository.get_public_config(&workspace).await.unwrap(),
            BackendConfigResponse::unconfigured()
        );

        let response = repository
            .put_config(&workspace, valid_request())
            .await
            .unwrap();
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["configured"], true);
        assert!(json.get("access_key").is_none());
        assert!(json.get("secret_key").is_none());
        assert!(
            repository
                .get_runtime_config(&workspace)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn incomplete_and_unsupported_configs_are_rejected() {
        let repository = InMemoryWorkspaceStorageRepository::new();
        let workspace = repository.resolve_workspace("user-1").await.unwrap();
        let mut incomplete = valid_request();
        incomplete.secret_key.clear();
        assert!(matches!(
            repository.put_config(&workspace, incomplete).await,
            Err(WorkspaceStorageError::InvalidConfig(_))
        ));

        let mut unsupported = valid_request();
        unsupported.backend_type = BackendType::AwsRole;
        unsupported.role_arn = "arn:aws:iam::123456789012:role/s4".to_string();
        assert!(matches!(
            repository.put_config(&workspace, unsupported).await,
            Err(WorkspaceStorageError::UnsupportedConfig(_))
        ));
    }

    #[tokio::test]
    async fn managed_config_has_no_credentials_and_an_exact_redacted_shape() {
        let repository = InMemoryWorkspaceStorageRepository::new();
        let workspace = repository.resolve_workspace("user-1").await.unwrap();
        let response = repository
            .put_config(
                &workspace,
                BackendConfigRequest {
                    backend_type: BackendType::Managed,
                    endpoint: String::new(),
                    access_key: String::new(),
                    secret_key: String::new(),
                    region: String::new(),
                    role_arn: String::new(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "configured": true,
                "backend_type": "managed",
                "endpoint": null,
                "region": null,
                "role_arn": null,
                "access_key_configured": false,
                "secret_key_configured": false,
            })
        );
        assert!(matches!(
            repository.get_runtime_config(&workspace).await.unwrap(),
            Some(RuntimeBackendConfig::Managed)
        ));

        assert!(matches!(
            repository
                .put_config(
                    &workspace,
                    BackendConfigRequest {
                        backend_type: BackendType::Managed,
                        endpoint: "https://must-not-be-used.example".to_string(),
                        access_key: String::new(),
                        secret_key: String::new(),
                        region: String::new(),
                        role_arn: String::new(),
                    },
                )
                .await,
            Err(WorkspaceStorageError::InvalidConfig(_))
        ));
    }
}
