//! Local stdio MCP server for S4.
//!
//! Each tool call uses the gateway's S3-compatible HTTP surface, preserving the
//! same authentication, processing, storage, and metering path as native S3
//! traffic.

use std::{env, fmt};

use futures_util::StreamExt;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::tool;
use rmcp::transport::stdio;
use rmcp::{ErrorData as McpError, ServiceExt, tool_router};
use serde::Deserialize;
use url::Url;

const DEFAULT_GATEWAY_URL: &str = "http://localhost:8080";
const ENV_GATEWAY_URL: &str = "S4_GATEWAY_URL";
const ENV_MCP_TOKEN: &str = "S4_MCP_TOKEN";
const ENV_ACCESS_KEY: &str = "S4_ACCESS_KEY";
const ENV_SECRET_KEY: &str = "S4_SECRET_KEY";
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
        let gateway_url =
            env::var(ENV_GATEWAY_URL).unwrap_or_else(|_| DEFAULT_GATEWAY_URL.to_string());
        let mcp_token = env::var(ENV_MCP_TOKEN)
            .ok()
            .filter(|value| !value.is_empty());
        let access_key = env::var(ENV_ACCESS_KEY)
            .ok()
            .filter(|value| !value.is_empty());
        let secret_key = env::var(ENV_SECRET_KEY)
            .ok()
            .filter(|value| !value.is_empty());
        Self::new(&gateway_url, mcp_token, access_key, secret_key)
    }

    fn new(
        gateway_url: &str,
        mcp_token: Option<String>,
        access_key: Option<String>,
        secret_key: Option<String>,
    ) -> anyhow::Result<Self> {
        let gateway_url = Url::parse(gateway_url)
            .map_err(|error| anyhow::anyhow!("invalid {ENV_GATEWAY_URL}: {error}"))?;
        if !matches!(gateway_url.scheme(), "http" | "https") || gateway_url.host().is_none() {
            anyhow::bail!("{ENV_GATEWAY_URL} must be an absolute HTTP(S) URL");
        }

        let auth = if let Some(token) = mcp_token {
            GatewayAuth::McpToken(parse_secret_header(ENV_MCP_TOKEN, &token)?)
        } else {
            let access_key = access_key.ok_or_else(|| {
                anyhow::anyhow!(
                    "missing credentials: set {ENV_MCP_TOKEN}, or both {ENV_ACCESS_KEY} and {ENV_SECRET_KEY}"
                )
            })?;
            let secret_key = secret_key.ok_or_else(|| {
                anyhow::anyhow!(
                    "missing credentials: set {ENV_MCP_TOKEN}, or both {ENV_ACCESS_KEY} and {ENV_SECRET_KEY}"
                )
            })?;
            GatewayAuth::ApiKey {
                access_key: parse_secret_header(ENV_ACCESS_KEY, &access_key)?,
                secret_key: parse_secret_header(ENV_SECRET_KEY, &secret_key)?,
            }
        };

        Ok(Self { gateway_url, auth })
    }

    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        match &self.auth {
            GatewayAuth::McpToken(token) => {
                headers.insert("x-s4-mcp-token", token.clone());
            }
            GatewayAuth::ApiKey {
                access_key,
                secret_key,
            } => {
                headers.insert("x-s4-access-key", access_key.clone());
                headers.insert("x-s4-secret-key", secret_key.clone());
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
struct S4Server {
    config: Config,
    client: reqwest::Client,
}

impl S4Server {
    fn new(config: Config) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("s4-mcp/", env!("CARGO_PKG_VERSION")))
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
    /// Content-Type used by S4 to select the processing format.
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
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteObjectParams {
    bucket: String,
    key: String,
}

#[tool_router(server_handler)]
impl S4Server {
    #[tool(description = "Store a UTF-8 object through the configured S4 pipeline")]
    async fn s4_put_object(
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

    #[tool(description = "Read an object through the S4 gateway")]
    async fn s4_get_object(
        &self,
        Parameters(params): Parameters<GetObjectParams>,
    ) -> Result<CallToolResult, McpError> {
        let url = match object_url_for_tool(self, &params.bucket, &params.key, true) {
            Ok(url) => url,
            Err(result) => return Ok(result),
        };
        let mut request = self.client.get(url).headers(self.config.auth_headers());
        if params.process {
            request = request.header("x-s4-process", "read");
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
    async fn s4_list_objects(
        &self,
        Parameters(params): Parameters<ListObjectsParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut url = match self.object_url(&params.bucket, "") {
            Ok(url) => url,
            Err(error) => return Ok(tool_error(error.to_string())),
        };
        url.query_pairs_mut()
            .append_pair("list-type", "2")
            .append_pair("prefix", &params.prefix);
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
        let keys = match parse_s3_list_keys(&body) {
            Ok(keys) => keys,
            Err(error) => {
                return Ok(tool_error(format!(
                    "invalid ListObjectsV2 response: {error}"
                )));
            }
        };
        let message = if keys.is_empty() {
            format!("no objects matching prefix '{}'", params.prefix)
        } else {
            keys.join("\n")
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(message)]))
    }

    #[tool(description = "Delete an object through the S4 gateway")]
    async fn s4_delete_object(
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
}

fn object_url_for_tool(
    server: &S4Server,
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
}

#[derive(Debug, Deserialize)]
struct ListObject {
    #[serde(rename = "Key")]
    key: String,
}

fn parse_s3_list_keys(xml: &str) -> Result<Vec<String>, quick_xml::DeError> {
    let result: ListBucketResult = quick_xml::de::from_str(xml)?;
    Ok(result
        .contents
        .into_iter()
        .map(|object| object.key)
        .collect())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();
    let server = S4Server::new(Config::from_env()?)?;
    tracing::info!("s4-mcp stdio server ready");
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
        http::{HeaderMap as AxumHeaderMap, Method, Response},
        routing::any,
    };
    use http_body_util::BodyExt;

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

    fn test_server() -> S4Server {
        S4Server::new(
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
        assert!(error.contains(ENV_MCP_TOKEN));
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
    fn parses_and_decodes_s3_list_keys() {
        let xml = r#"<?xml version="1.0"?>
<ListBucketResult>
  <Contents><Key>a.txt</Key></Contents>
  <Contents><Key>dir/a&amp;b.txt</Key></Contents>
</ListBucketResult>"#;
        assert_eq!(
            parse_s3_list_keys(xml).unwrap(),
            vec!["a.txt", "dir/a&b.txt"]
        );
    }

    #[test]
    fn empty_s3_list_has_no_keys() {
        assert!(
            parse_s3_list_keys("<ListBucketResult/>")
                .unwrap()
                .is_empty()
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
        let server = S4Server::new(
            Config::new(&gateway_url, Some("s4m_test-token".to_string()), None, None).unwrap(),
        )
        .unwrap();

        let put = server
            .s4_put_object(Parameters(PutObjectParams {
                bucket: "records".to_string(),
                key: "daily report.json".to_string(),
                body: r#"{"email":"alice@example.com"}"#.to_string(),
                content_type: "application/json".to_string(),
            }))
            .await
            .unwrap();
        assert_eq!(put.is_error, Some(false));

        let get = server
            .s4_get_object(Parameters(GetObjectParams {
                bucket: "records".to_string(),
                key: "daily report.json".to_string(),
                process: true,
            }))
            .await
            .unwrap();
        assert_eq!(get.is_error, Some(false));
        assert_eq!(result_text(&get), "processed object");

        let list = server
            .s4_list_objects(Parameters(ListObjectsParams {
                bucket: "records".to_string(),
                prefix: "logs/".to_string(),
            }))
            .await
            .unwrap();
        assert_eq!(list.is_error, Some(false));
        assert_eq!(result_text(&list), "logs/a&b.txt");

        let delete = server
            .s4_delete_object(Parameters(DeleteObjectParams {
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
        assert_eq!(requests[0].headers["x-s4-mcp-token"], "s4m_test-token");
        assert_eq!(requests[0].headers[CONTENT_TYPE], "application/json");
        assert_eq!(requests[0].body, br#"{"email":"alice@example.com"}"#);
        assert_eq!(requests[1].headers["x-s4-process"], "read");
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
        let server = S4Server::new(
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
        assert_eq!(requests[0].headers["x-s4-access-key"], "s4_access");
        assert_eq!(requests[0].headers["x-s4-secret-key"], "s4s_secret");
        assert!(!requests[0].headers.contains_key("x-s4-mcp-token"));
    }

    #[tokio::test]
    async fn get_rejects_responses_above_the_text_limit() {
        let (gateway_url, _) = mock_server().await;
        let server = S4Server::new(
            Config::new(&gateway_url, Some("s4m_test-token".to_string()), None, None).unwrap(),
        )
        .unwrap();
        let result = server
            .s4_get_object(Parameters(GetObjectParams {
                bucket: "records".to_string(),
                key: "too-large".to_string(),
                process: false,
            }))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        assert!(result_text(&result).contains("exceeds"));
    }
}
