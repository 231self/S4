// Local stdio MCP server for Maskura. Each tool call uses the gateway's
// S3-compatible HTTP surface, preserving the same authentication, processing,
// storage, and metering path as native S3 traffic.

use std::fmt;

use futures_util::StreamExt;
use maskura_customer_config::{aliases as customer_env, resolve as resolve_customer_env};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::tool;
use rmcp::transport::stdio;
use rmcp::{ErrorData as McpError, ServiceExt, tool_router};
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_GATEWAY_URL: &str = "http://localhost:8080";
const MAX_TEXT_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ERROR_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
enum GatewayAuth {
    McpToken(HeaderValue),
    ApiKey {
        access_key: HeaderValue,
        secret_key: HeaderValue,
    },
}

impl fmt::Debug for GatewayAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::McpToken(_) => formatter.write_str("McpToken([REDACTED])"),
            Self::ApiKey { .. } => formatter.write_str("ApiKey([REDACTED])"),
        }
    }
}

#[derive(Clone, Debug)]
struct Config {
    gateway_url: Url,
    auth: GatewayAuth,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let gateway_url = resolve_customer_env(customer_env::GATEWAY_URL)?
            .unwrap_or_else(|| DEFAULT_GATEWAY_URL.to_string());
        let mcp_token =
            resolve_customer_env(customer_env::MCP_TOKEN)?.filter(|value| !value.is_empty());
        let access_key =
            resolve_customer_env(customer_env::ACCESS_KEY)?.filter(|value| !value.is_empty());
        let secret_key =
            resolve_customer_env(customer_env::SECRET_KEY)?.filter(|value| !value.is_empty());
        Self::new(&gateway_url, mcp_token, access_key, secret_key)
    }

    fn new(
        gateway_url: &str,
        mcp_token: Option<String>,
        access_key: Option<String>,
        secret_key: Option<String>,
    ) -> anyhow::Result<Self> {
        let gateway_url = Url::parse(gateway_url)
            .map_err(|error| anyhow::anyhow!("invalid MASKURA_GATEWAY_URL: {error}"))?;
        if !matches!(gateway_url.scheme(), "http" | "https") || gateway_url.host().is_none() {
            anyhow::bail!("MASKURA_GATEWAY_URL must be an absolute HTTP(S) URL");
        }

        let auth = if let Some(token) = mcp_token {
            GatewayAuth::McpToken(parse_secret_header("MASKURA_MCP_TOKEN", &token)?)
        } else {
            let access_key = access_key.ok_or_else(|| {
                anyhow::anyhow!(
                    "missing credentials: set MASKURA_MCP_TOKEN, or both MASKURA_ACCESS_KEY and MASKURA_SECRET_KEY"
                )
            })?;
            let secret_key = secret_key.ok_or_else(|| {
                anyhow::anyhow!(
                    "missing credentials: set MASKURA_MCP_TOKEN, or both MASKURA_ACCESS_KEY and MASKURA_SECRET_KEY"
                )
            })?;
            GatewayAuth::ApiKey {
                access_key: parse_secret_header("MASKURA_ACCESS_KEY", &access_key)?,
                secret_key: parse_secret_header("MASKURA_SECRET_KEY", &secret_key)?,
            }
        };

        Ok(Self { gateway_url, auth })
    }

    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        match &self.auth {
            GatewayAuth::McpToken(token) => {
                headers.insert("x-maskura-mcp-token", token.clone());
            }
            GatewayAuth::ApiKey {
                access_key,
                secret_key,
            } => {
                headers.insert("x-maskura-access-key", access_key.clone());
                headers.insert("x-maskura-secret-key", secret_key.clone());
            }
        }
        headers
    }
}

fn parse_secret_header(name: &str, value: &str) -> anyhow::Result<HeaderValue> {
    HeaderValue::from_str(value)
        .map_err(|_| anyhow::anyhow!("{name} is not a valid HTTP header value"))
}

#[derive(Clone)]
struct MaskuraServer {
    config: Config,
    client: reqwest::Client,
}

impl MaskuraServer {
    fn new(config: Config) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("maskura-mcp/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { config, client })
    }

    fn object_url(&self, bucket: &str, key: &str) -> anyhow::Result<Url> {
        if bucket.is_empty() {
            anyhow::bail!("bucket must not be empty");
        }
        let mut url = self.config.gateway_url.clone();
        url.set_query(None);
        url.set_fragment(None);
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("gateway URL cannot be used as a path base"))?;
        segments.pop_if_empty();
        segments.push(bucket);
        for segment in key.split('/').filter(|segment| !segment.is_empty()) {
            segments.push(segment);
        }
        drop(segments);
        Ok(url)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PutObjectParams {
    /// Bucket to write into.
    bucket: String,
    /// Object key within the bucket.
    key: String,
    /// UTF-8 object body.
    body: String,
    /// Content-Type used by Maskura to select the processing format.
    #[serde(default = "default_content_type")]
    content_type: String,
}

fn default_content_type() -> String {
    "text/plain; charset=utf-8".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GetObjectParams {
    bucket: String,
    key: String,
    /// Run the configured processing pipeline before returning the object.
    #[serde(default)]
    process: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListObjectsParams {
    bucket: String,
    #[serde(default)]
    prefix: String,
    /// Opaque token returned by the previous truncated page.
    continuation_token: Option<String>,
    /// Maximum number of keys and common prefixes to return (S3 caps this at 1000).
    max_keys: Option<u32>,
    /// Group keys that share the substring between the prefix and this delimiter.
    delimiter: Option<String>,
    /// On the first page, begin listing lexicographically after this key.
    start_after: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteObjectParams {
    bucket: String,
    key: String,
}

#[tool_router(server_handler)]
impl MaskuraServer {
    #[tool(description = "Store a UTF-8 object through the configured Maskura pipeline")]
    async fn maskura_put_object(
        &self,
        Parameters(params): Parameters<PutObjectParams>,
    ) -> Result<CallToolResult, McpError> {
        let url = match object_url_for_tool(self, &params.bucket, &params.key, true) {
            Ok(url) => url,
            Err(result) => return Ok(result),
        };
        let content_type = match HeaderValue::from_str(&params.content_type) {
            Ok(value) => value,
            Err(_) => return Ok(tool_error("content_type is not a valid HTTP header value")),
        };
        let response = self
            .client
            .put(url)
            .headers(self.config.auth_headers())
            .header(CONTENT_TYPE, content_type)
            .body(params.body)
            .send()
            .await;
        Ok(status_only_result(response, "stored", &params.bucket, &params.key).await)
    }

    #[tool(description = "Read an object through the Maskura Gateway")]
    async fn maskura_get_object(
        &self,
        Parameters(params): Parameters<GetObjectParams>,
    ) -> Result<CallToolResult, McpError> {
        let url = match object_url_for_tool(self, &params.bucket, &params.key, true) {
            Ok(url) => url,
            Err(result) => return Ok(result),
        };
        let mut request = self.client.get(url).headers(self.config.auth_headers());
        if params.process {
            request = request.header("x-maskura-process", "read");
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => return Ok(tool_error(format!("gateway request failed: {error}"))),
        };
        if !response.status().is_success() {
            return Ok(gateway_error(response).await);
        }
        match read_text_bounded(response, MAX_TEXT_RESPONSE_BYTES).await {
            Ok(body) => Ok(CallToolResult::success(vec![ContentBlock::text(body)])),
            Err(error) => Ok(tool_error(error)),
        }
    }

    #[tool(description = "List object keys in a bucket using ListObjectsV2")]
    async fn maskura_list_objects(
        &self,
        Parameters(params): Parameters<ListObjectsParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut url = match self.object_url(&params.bucket, "") {
            Ok(url) => url,
            Err(error) => return Ok(tool_error(error.to_string())),
        };
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("list-type", "2")
                .append_pair("prefix", &params.prefix);
            if let Some(token) = params.continuation_token.as_deref() {
                query.append_pair("continuation-token", token);
            }
            if let Some(max_keys) = params.max_keys {
                query.append_pair("max-keys", &max_keys.to_string());
            }
            if let Some(delimiter) = params.delimiter.as_deref() {
                query.append_pair("delimiter", delimiter);
            }
            if let Some(start_after) = params.start_after.as_deref() {
                query.append_pair("start-after", start_after);
            }
        }
        let response = match self
            .client
            .get(url)
            .headers(self.config.auth_headers())
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => return Ok(tool_error(format!("gateway request failed: {error}"))),
        };
        if !response.status().is_success() {
            return Ok(gateway_error(response).await);
        }
        let body = match read_text_bounded(response, MAX_TEXT_RESPONSE_BYTES).await {
            Ok(body) => body,
            Err(error) => return Ok(tool_error(error)),
        };
        let page = match parse_s3_list_page(&body) {
            Ok(page) => page,
            Err(error) => {
                return Ok(tool_error(format!(
                    "invalid ListObjectsV2 response: {error}"
                )));
            }
        };
        Ok(list_page_result(page, &params.prefix))
    }

    #[tool(description = "Delete an object through the Maskura Gateway")]
    async fn maskura_delete_object(
        &self,
        Parameters(params): Parameters<DeleteObjectParams>,
    ) -> Result<CallToolResult, McpError> {
        let url = match object_url_for_tool(self, &params.bucket, &params.key, true) {
            Ok(url) => url,
            Err(result) => return Ok(result),
        };
        let response = self
            .client
            .delete(url)
            .headers(self.config.auth_headers())
            .send()
            .await;
        Ok(status_only_result(response, "deleted", &params.bucket, &params.key).await)
    }

    #[tool(description = "Legacy alias for maskura_put_object")]
    async fn s4_put_object(
        &self,
        params: Parameters<PutObjectParams>,
    ) -> Result<CallToolResult, McpError> {
        self.maskura_put_object(params).await
    }

    #[tool(description = "Legacy alias for maskura_get_object")]
    async fn s4_get_object(
        &self,
        params: Parameters<GetObjectParams>,
    ) -> Result<CallToolResult, McpError> {
        self.maskura_get_object(params).await
    }

    #[tool(description = "Legacy alias for maskura_list_objects")]
    async fn s4_list_objects(
        &self,
        params: Parameters<ListObjectsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.maskura_list_objects(params).await
    }

    #[tool(description = "Legacy alias for maskura_delete_object")]
    async fn s4_delete_object(
        &self,
        params: Parameters<DeleteObjectParams>,
    ) -> Result<CallToolResult, McpError> {
        self.maskura_delete_object(params).await
    }
}

fn object_url_for_tool(
    server: &MaskuraServer,
    bucket: &str,
    key: &str,
    require_key: bool,
) -> Result<Url, CallToolResult> {
    if require_key && key.is_empty() {
        return Err(tool_error("key must not be empty"));
    }
    server
        .object_url(bucket, key)
        .map_err(|error| tool_error(error.to_string()))
}

async fn status_only_result(
    response: Result<reqwest::Response, reqwest::Error>,
    action: &str,
    bucket: &str,
    key: &str,
) -> CallToolResult {
    match response {
        Ok(response) if response.status().is_success() => {
            CallToolResult::success(vec![ContentBlock::text(format!(
                "{action} {bucket}/{key} (status {})",
                response.status().as_u16()
            ))])
        }
        Ok(response) => gateway_error(response).await,
        Err(error) => tool_error(format!("gateway request failed: {error}")),
    }
}

async fn gateway_error(response: reqwest::Response) -> CallToolResult {
    let status = response.status().as_u16();
    let body = read_text_bounded(response, MAX_ERROR_RESPONSE_BYTES)
        .await
        .unwrap_or_else(|error| error);
    tool_error(format!("gateway returned {status}: {body}"))
}

async fn read_text_bounded(response: reqwest::Response, limit: usize) -> Result<String, String> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(format!("gateway response exceeds {limit} bytes"));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("failed to read gateway response: {error}"))?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(format!("gateway response exceeds {limit} bytes"));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| "gateway response is not valid UTF-8".to_string())
}

fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

#[derive(Debug, Deserialize)]
#[serde(rename = "ListBucketResult")]
struct ListBucketResult {
    #[serde(rename = "Contents", default)]
    contents: Vec<ListObject>,
    #[serde(rename = "CommonPrefixes", default)]
    common_prefixes: Vec<CommonPrefix>,
    #[serde(rename = "IsTruncated", default)]
    is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    next_continuation_token: Option<String>,
    #[serde(rename = "KeyCount")]
    key_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ListObject {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Debug, Deserialize)]
struct CommonPrefix {
    #[serde(rename = "Prefix")]
    prefix: String,
}

#[derive(Debug, Serialize, PartialEq)]
struct ListObjectsPage {
    keys: Vec<String>,
    common_prefixes: Vec<String>,
    is_truncated: bool,
    next_continuation_token: Option<String>,
    key_count: usize,
}

fn parse_s3_list_page(xml: &str) -> anyhow::Result<ListObjectsPage> {
    let result: ListBucketResult = quick_xml::de::from_str(xml)?;
    if result.is_truncated
        && result
            .next_continuation_token
            .as_deref()
            .is_none_or(str::is_empty)
    {
        anyhow::bail!("truncated response has no next continuation token");
    }
    let keys = result
        .contents
        .into_iter()
        .map(|object| object.key)
        .collect::<Vec<_>>();
    let common_prefixes = result
        .common_prefixes
        .into_iter()
        .map(|prefix| prefix.prefix)
        .collect::<Vec<_>>();
    let key_count = result
        .key_count
        .unwrap_or(keys.len() + common_prefixes.len());
    Ok(ListObjectsPage {
        keys,
        common_prefixes,
        is_truncated: result.is_truncated,
        next_continuation_token: result.next_continuation_token,
        key_count,
    })
}

fn list_page_result(page: ListObjectsPage, prefix: &str) -> CallToolResult {
    let message = if page.is_truncated || !page.common_prefixes.is_empty() {
        serde_json::to_string(&page).expect("list page is serializable")
    } else if page.keys.is_empty() {
        format!("no objects matching prefix '{prefix}'")
    } else {
        page.keys.join("\n")
    };
    let structured_content = serde_json::to_value(&page).expect("list page is serializable");
    let mut result = CallToolResult::success(vec![ContentBlock::text(message)]);
    result.structured_content = Some(structured_content);
    result
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
    let server = MaskuraServer::new(Config::from_env()?)?;
    tracing::info!("maskura-mcp stdio server ready");
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Router,
        body::Body,
        extract::{Request, State},
        http::{HeaderMap as AxumHeaderMap, Method, Response, StatusCode},
        routing::any,
    };
    use http_body_util::BodyExt;
    use s4_gateway::managed::{
        AuthorityListPage, AuthorityListQuery, CopyStatus, InMemoryManagedRepository,
        LogicalObjectKey, ManagedListCursorBinding, ManagedListCursorPosition,
        ManagedListCursorRequest, ManagedListVersion, ManagedRepository, ObjectAuthority,
    };

    use super::*;

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        method: Method,
        path: String,
        query: Option<String>,
        headers: AxumHeaderMap,
        body: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct MockState {
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    }

    #[derive(Clone)]
    struct ManagedAuthorityState {
        repository: Arc<InMemoryManagedRepository>,
    }

    fn authority_list_xml(page: &AuthorityListPage, continuation: Option<&str>) -> String {
        let contents = page
            .objects
            .iter()
            .map(|authority| format!("<Contents><Key>{}</Key></Contents>", authority.logical.key))
            .collect::<String>();
        let truncated = continuation.is_some();
        let continuation_xml = continuation
            .map(|token| format!("<NextContinuationToken>{token}</NextContinuationToken>"))
            .unwrap_or_default();
        format!(
            "<ListBucketResult><KeyCount>{}</KeyCount><IsTruncated>{truncated}</IsTruncated>{continuation_xml}{contents}</ListBucketResult>",
            page.objects.len(),
        )
    }

    async fn managed_authority_gateway(
        State(state): State<ManagedAuthorityState>,
        request: Request,
    ) -> Response<Body> {
        let query =
            url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>();
        let binding = ManagedListCursorBinding {
            tenant_id: "mcp-managed-tenant".to_string(),
            bucket: request.uri().path().trim_start_matches('/').to_string(),
            prefix: query.get("prefix").cloned().unwrap_or_default(),
            delimiter: query.get("delimiter").cloned(),
            version: ManagedListVersion::V2,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        if let Some(token) = query.get("continuation-token") {
            let cursor = state
                .repository
                .use_list_cursor(token.parse().unwrap(), &binding, now)
                .await
                .unwrap();
            return Response::new(Body::from(
                cursor.response_state["xml"].as_str().unwrap().to_string(),
            ));
        }

        let max_keys = query
            .get("max-keys")
            .and_then(|value| value.parse().ok())
            .unwrap_or(1000);
        let first = state
            .repository
            .list_authority(AuthorityListQuery {
                tenant_id: binding.tenant_id.clone(),
                bucket: binding.bucket.clone(),
                prefix: binding.prefix.clone(),
                after: query.get("start-after").cloned(),
                max_keys,
            })
            .await
            .unwrap();
        let continuation = if let Some(after) = first.next_after.clone() {
            let second = state
                .repository
                .list_authority(AuthorityListQuery {
                    tenant_id: binding.tenant_id.clone(),
                    bucket: binding.bucket.clone(),
                    prefix: binding.prefix.clone(),
                    after: Some(after.clone()),
                    max_keys,
                })
                .await
                .unwrap();
            let second_xml = authority_list_xml(&second, None);
            Some(
                state
                    .repository
                    .create_list_cursor(
                        ManagedListCursorRequest {
                            binding,
                            position: ManagedListCursorPosition {
                                last_key: Some(after),
                                last_common_prefix: None,
                            },
                            response_state: serde_json::json!({"xml": second_xml}),
                            final_page: second.next_after.is_none(),
                        },
                        now,
                    )
                    .await
                    .unwrap()
                    .id
                    .to_string(),
            )
        } else {
            None
        };
        Response::new(Body::from(authority_list_xml(
            &first,
            continuation.as_deref(),
        )))
    }

    fn test_server() -> MaskuraServer {
        MaskuraServer::new(
            Config::new(
                "http://localhost:8080",
                Some("s4m_test".to_string()),
                None,
                None,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn object_url_encodes_bucket_and_key_segments() {
        let url = test_server()
            .object_url("sandbox", "logs/agent run/1.json")
            .unwrap();
        assert_eq!(
            url.as_str(),
            "http://localhost:8080/sandbox/logs/agent%20run/1.json"
        );
    }

    #[test]
    fn config_rejects_invalid_secret_headers_without_exposing_values() {
        let error = Config::new(
            "http://localhost:8080",
            Some("secret\nvalue".to_string()),
            None,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("MASKURA_MCP_TOKEN"));
        assert!(!error.contains("secret"));
    }

    #[test]
    fn config_debug_redacts_credentials() {
        let config = Config::new(
            "http://localhost:8080",
            None,
            Some("access-test".to_string()),
            Some("secret-test".to_string()),
        )
        .unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("access-test"));
        assert!(!debug.contains("secret-test"));
    }

    #[test]
    fn parses_s3_list_page_metadata_and_decodes_values() {
        let xml = r#"<?xml version="1.0"?>
<ListBucketResult>
  <KeyCount>3</KeyCount>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>next&amp;page</NextContinuationToken>
  <Contents><Key>a.txt</Key></Contents>
  <Contents><Key>dir/a&amp;b.txt</Key></Contents>
  <CommonPrefixes><Prefix>dir/nested&amp;/</Prefix></CommonPrefixes>
</ListBucketResult>"#;
        assert_eq!(
            parse_s3_list_page(xml).unwrap(),
            ListObjectsPage {
                keys: vec!["a.txt".to_string(), "dir/a&b.txt".to_string()],
                common_prefixes: vec!["dir/nested&/".to_string()],
                is_truncated: true,
                next_continuation_token: Some("next&page".to_string()),
                key_count: 3,
            }
        );
    }

    #[test]
    fn empty_s3_list_has_no_keys() {
        let page = parse_s3_list_page("<ListBucketResult/>").unwrap();
        assert!(page.keys.is_empty());
        assert!(page.common_prefixes.is_empty());
        assert!(!page.is_truncated);
        assert_eq!(page.next_continuation_token, None);
        assert_eq!(page.key_count, 0);
    }

    #[test]
    fn publishes_canonical_and_legacy_tool_names() {
        let mut names: Vec<_> = MaskuraServer::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "maskura_delete_object",
                "maskura_get_object",
                "maskura_list_objects",
                "maskura_put_object",
                "s4_delete_object",
                "s4_get_object",
                "s4_list_objects",
                "s4_put_object",
            ]
        );
    }

    async fn mock_gateway(State(state): State<MockState>, request: Request) -> Response<Body> {
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        let query = request.uri().query().map(str::to_string);
        let headers = request.headers().clone();
        let body = request
            .into_body()
            .collect()
            .await
            .expect("mock request body")
            .to_bytes()
            .to_vec();
        state.requests.lock().unwrap().push(RecordedRequest {
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            headers,
            body,
        });

        if path.ends_with("/too-large") {
            return Response::new(Body::from(vec![b'x'; MAX_TEXT_RESPONSE_BYTES + 1]));
        }
        if method == Method::GET
            && query
                .as_deref()
                .is_some_and(|value| value.contains("list-type=2"))
        {
            if path == "/malformed" {
                return Response::new(Body::from(
                    "<ListBucketResult><Contents><Key>broken</Contents></ListBucketResult>",
                ));
            }
            if path == "/truncated-no-token" {
                return Response::new(Body::from(
                    "<ListBucketResult><KeyCount>1</KeyCount><IsTruncated>true</IsTruncated><Contents><Key>orphaned-page</Key></Contents></ListBucketResult>",
                ));
            }
            if path == "/gateway-failure" {
                return Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("<Error><Code>SlowDown</Code></Error>"))
                    .unwrap();
            }
            if path == "/managed" {
                let query_params =
                    url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes())
                        .into_owned()
                        .collect::<std::collections::HashMap<_, _>>();
                if query_params
                    .get("delimiter")
                    .is_some_and(|value| value == "/")
                {
                    return Response::new(Body::from(
                        "<ListBucketResult><KeyCount>3</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>tenant/root.txt</Key></Contents><CommonPrefixes><Prefix>tenant/logs/</Prefix></CommonPrefixes><CommonPrefixes><Prefix>tenant/reports/</Prefix></CommonPrefixes></ListBucketResult>",
                    ));
                }
                if query_params
                    .get("continuation-token")
                    .is_some_and(|token| token == "managed/page+2==")
                {
                    return Response::new(Body::from(
                        "<ListBucketResult><KeyCount>2</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>managed/object-1000</Key></Contents><Contents><Key>managed/object-1001</Key></Contents></ListBucketResult>",
                    ));
                }
                let contents = (0..1000)
                    .map(|index| {
                        format!("<Contents><Key>managed/object-{index:04}</Key></Contents>")
                    })
                    .collect::<String>();
                return Response::new(Body::from(format!(
                    "<ListBucketResult><KeyCount>1000</KeyCount><IsTruncated>true</IsTruncated><NextContinuationToken>managed/page+2==</NextContinuationToken>{contents}</ListBucketResult>"
                )));
            }
            return Response::new(Body::from(
                "<ListBucketResult><Contents><Key>logs/a&amp;b.txt</Key></Contents></ListBucketResult>",
            ));
        }
        if method == Method::GET {
            return Response::new(Body::from("processed object"));
        }
        Response::new(Body::empty())
    }

    async fn mock_server() -> (String, MockState) {
        let state = MockState::default();
        let app = Router::new()
            .route("/{*path}", any(mock_gateway))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), state)
    }

    async fn managed_authority_server(repository: Arc<InMemoryManagedRepository>) -> String {
        let app = Router::new()
            .route("/{*path}", any(managed_authority_gateway))
            .with_state(ManagedAuthorityState { repository });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}")
    }

    fn result_text(result: &CallToolResult) -> String {
        serde_json::to_value(&result.content[0])
            .unwrap()
            .get("text")
            .and_then(serde_json::Value::as_str)
            .expect("text tool result")
            .to_string()
    }

    #[tokio::test]
    async fn tools_preserve_mcp_auth_and_processing_semantics() {
        let (gateway_url, state) = mock_server().await;
        let server = MaskuraServer::new(
            Config::new(&gateway_url, Some("s4m_test-token".to_string()), None, None).unwrap(),
        )
        .unwrap();

        let put = server
            .maskura_put_object(Parameters(PutObjectParams {
                bucket: "records".to_string(),
                key: "daily report.json".to_string(),
                body: r#"{"email":"alice@example.com"}"#.to_string(),
                content_type: "application/json".to_string(),
            }))
            .await
            .unwrap();
        assert_eq!(put.is_error, Some(false));

        let get = server
            .maskura_get_object(Parameters(GetObjectParams {
                bucket: "records".to_string(),
                key: "daily report.json".to_string(),
                process: true,
            }))
            .await
            .unwrap();
        assert_eq!(get.is_error, Some(false));
        assert_eq!(result_text(&get), "processed object");

        let list = server
            .maskura_list_objects(Parameters(ListObjectsParams {
                bucket: "records".to_string(),
                prefix: "logs/".to_string(),
                continuation_token: None,
                max_keys: None,
                delimiter: None,
                start_after: None,
            }))
            .await
            .unwrap();
        assert_eq!(list.is_error, Some(false));
        assert_eq!(result_text(&list), "logs/a&b.txt");

        let delete = server
            .maskura_delete_object(Parameters(DeleteObjectParams {
                bucket: "records".to_string(),
                key: "daily report.json".to_string(),
            }))
            .await
            .unwrap();
        assert_eq!(delete.is_error, Some(false));

        let requests = state.requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].method, Method::PUT);
        assert_eq!(requests[0].path, "/records/daily%20report.json");
        assert_eq!(requests[0].headers["x-maskura-mcp-token"], "s4m_test-token");
        assert_eq!(requests[0].headers[CONTENT_TYPE], "application/json");
        assert_eq!(requests[0].body, br#"{"email":"alice@example.com"}"#);
        assert_eq!(requests[1].headers["x-maskura-process"], "read");
        assert_eq!(requests[2].method, Method::GET);
        assert_eq!(
            requests[2].query.as_deref(),
            Some("list-type=2&prefix=logs%2F")
        );
        assert_eq!(requests[3].method, Method::DELETE);
    }

    #[tokio::test]
    async fn api_key_auth_uses_both_gateway_headers() {
        let (gateway_url, state) = mock_server().await;
        let server = MaskuraServer::new(
            Config::new(
                &gateway_url,
                None,
                Some("s4_access".to_string()),
                Some("s4s_secret".to_string()),
            )
            .unwrap(),
        )
        .unwrap();
        server
            .s4_delete_object(Parameters(DeleteObjectParams {
                bucket: "records".to_string(),
                key: "old.txt".to_string(),
            }))
            .await
            .unwrap();

        let requests = state.requests.lock().unwrap();
        assert_eq!(requests[0].headers["x-maskura-access-key"], "s4_access");
        assert_eq!(requests[0].headers["x-maskura-secret-key"], "s4s_secret");
        assert!(!requests[0].headers.contains_key("x-maskura-mcp-token"));
    }

    #[tokio::test]
    async fn get_rejects_responses_above_the_text_limit() {
        let (gateway_url, _) = mock_server().await;
        let server = MaskuraServer::new(
            Config::new(&gateway_url, Some("s4m_test-token".to_string()), None, None).unwrap(),
        )
        .unwrap();
        let result = server
            .maskura_get_object(Parameters(GetObjectParams {
                bucket: "records".to_string(),
                key: "too-large".to_string(),
                process: false,
            }))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        assert!(result_text(&result).contains("exceeds"));
    }

    #[tokio::test]
    async fn list_pages_through_managed_namespace_over_1000_objects() {
        let (gateway_url, state) = mock_server().await;
        let server = MaskuraServer::new(
            Config::new(&gateway_url, Some("s4m_test-token".to_string()), None, None).unwrap(),
        )
        .unwrap();

        let first = server
            .s4_list_objects(Parameters(ListObjectsParams {
                bucket: "managed".to_string(),
                prefix: "managed/".to_string(),
                continuation_token: None,
                max_keys: None,
                delimiter: None,
                start_after: None,
            }))
            .await
            .unwrap();
        assert_eq!(first.is_error, Some(false));
        let first_page = first.structured_content.as_ref().unwrap();
        assert_eq!(first_page["keys"].as_array().unwrap().len(), 1000);
        assert_eq!(first_page["key_count"], 1000);
        assert_eq!(first_page["is_truncated"], true);
        assert_eq!(first_page["next_continuation_token"], "managed/page+2==");
        assert!(result_text(&first).contains("managed/page+2=="));

        let token = first_page["next_continuation_token"]
            .as_str()
            .unwrap()
            .to_string();
        let second = server
            .s4_list_objects(Parameters(ListObjectsParams {
                bucket: "managed".to_string(),
                prefix: "managed/".to_string(),
                continuation_token: Some(token),
                max_keys: Some(1000),
                delimiter: None,
                start_after: None,
            }))
            .await
            .unwrap();
        assert_eq!(second.is_error, Some(false));
        let second_page = second.structured_content.as_ref().unwrap();
        assert_eq!(second_page["keys"].as_array().unwrap().len(), 2);
        assert_eq!(second_page["key_count"], 2);
        assert_eq!(second_page["is_truncated"], false);
        assert!(second_page["next_continuation_token"].is_null());
        assert_eq!(
            result_text(&second),
            "managed/object-1000\nmanaged/object-1001"
        );

        let total = first_page["keys"].as_array().unwrap().len()
            + second_page["keys"].as_array().unwrap().len();
        assert_eq!(total, 1002);
        let requests = state.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].query.as_deref(),
            Some(
                "list-type=2&prefix=managed%2F&continuation-token=managed%2Fpage%2B2%3D%3D&max-keys=1000"
            )
        );
    }

    #[tokio::test]
    async fn list_pages_through_real_managed_authority_and_cursor_repository() {
        let repository = Arc::new(InMemoryManagedRepository::new());
        for index in 0..1002 {
            repository
                .publish(
                    ObjectAuthority {
                        logical: LogicalObjectKey::new(
                            "mcp-managed-tenant",
                            "managed-live",
                            &format!("managed/object-{index:04}"),
                        ),
                        generation: uuid::Uuid::now_v7(),
                        digest: format!("digest-{index}"),
                        size: index,
                        metadata: std::collections::BTreeMap::new(),
                        placement_version: 1,
                        primary_backend_id: "primary".to_string(),
                        primary_version_id: None,
                        replica_backend_id: None,
                        primary_status: CopyStatus::Ready,
                        replica_status: CopyStatus::Absent,
                        tombstone: false,
                        cas_version: 0,
                        created_at_ms: 0,
                        updated_at_ms: 0,
                    },
                    None,
                )
                .await
                .unwrap();
        }
        let gateway_url = managed_authority_server(repository).await;
        let server = MaskuraServer::new(
            Config::new(&gateway_url, Some("s4m_test-token".to_string()), None, None).unwrap(),
        )
        .unwrap();

        let first = server
            .s4_list_objects(Parameters(ListObjectsParams {
                bucket: "managed-live".to_string(),
                prefix: "managed/".to_string(),
                continuation_token: None,
                max_keys: Some(1000),
                delimiter: None,
                start_after: None,
            }))
            .await
            .unwrap();
        let first_page = first.structured_content.as_ref().unwrap();
        assert_eq!(first_page["keys"].as_array().unwrap().len(), 1000);
        assert_eq!(first_page["is_truncated"], true);
        let token = first_page["next_continuation_token"]
            .as_str()
            .unwrap()
            .to_string();

        let second = server
            .s4_list_objects(Parameters(ListObjectsParams {
                bucket: "managed-live".to_string(),
                prefix: "managed/".to_string(),
                continuation_token: Some(token),
                max_keys: Some(1000),
                delimiter: None,
                start_after: None,
            }))
            .await
            .unwrap();
        let second_page = second.structured_content.as_ref().unwrap();
        assert_eq!(
            second_page["keys"],
            serde_json::json!(["managed/object-1000", "managed/object-1001"])
        );
        assert_eq!(second_page["is_truncated"], false);
    }

    #[tokio::test]
    async fn list_forwards_delimiter_and_start_after_and_returns_common_prefixes() {
        let (gateway_url, state) = mock_server().await;
        let server = MaskuraServer::new(
            Config::new(&gateway_url, Some("s4m_test-token".to_string()), None, None).unwrap(),
        )
        .unwrap();
        let result = server
            .s4_list_objects(Parameters(ListObjectsParams {
                bucket: "managed".to_string(),
                prefix: "tenant/".to_string(),
                continuation_token: None,
                max_keys: Some(3),
                delimiter: Some("/".to_string()),
                start_after: Some("tenant/a b".to_string()),
            }))
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(false));
        let page = result.structured_content.as_ref().unwrap();
        assert_eq!(page["keys"], serde_json::json!(["tenant/root.txt"]));
        assert_eq!(
            page["common_prefixes"],
            serde_json::json!(["tenant/logs/", "tenant/reports/"])
        );
        assert_eq!(page["key_count"], 3);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&result_text(&result)).unwrap(),
            *page
        );

        let requests = state.requests.lock().unwrap();
        assert_eq!(
            requests[0].query.as_deref(),
            Some("list-type=2&prefix=tenant%2F&max-keys=3&delimiter=%2F&start-after=tenant%2Fa+b")
        );
    }

    #[tokio::test]
    async fn list_reports_malformed_truncated_and_gateway_failures() {
        let (gateway_url, _) = mock_server().await;
        let server = MaskuraServer::new(
            Config::new(&gateway_url, Some("s4m_test-token".to_string()), None, None).unwrap(),
        )
        .unwrap();

        for (bucket, expected) in [
            ("malformed", "invalid ListObjectsV2 response"),
            ("truncated-no-token", "no next continuation token"),
            ("gateway-failure", "gateway returned 503"),
        ] {
            let result = server
                .s4_list_objects(Parameters(ListObjectsParams {
                    bucket: bucket.to_string(),
                    prefix: String::new(),
                    continuation_token: None,
                    max_keys: None,
                    delimiter: None,
                    start_after: None,
                }))
                .await
                .unwrap();
            assert_eq!(result.is_error, Some(true), "bucket {bucket}");
            assert!(
                result_text(&result).contains(expected),
                "unexpected error for {bucket}: {}",
                result_text(&result)
            );
        }
    }
}
