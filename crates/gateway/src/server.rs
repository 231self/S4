//! Composable engine server: axum handlers + router + state construction.
//!
//! The engine is policy-free. Authorization (rate limits, quotas, billing)
//! and metering are injected through [`crate::control::ControlPlane`], held
//! in [`AppState`]. The OSS self-host binary builds this with
//! [`crate::control::NoopControlPlane`]; the private SaaS crate builds it with
//! its own control-plane implementation.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials as SigV4Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningParams,
    SigningSettings, UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{Html, IntoResponse},
    routing::{delete, get, head, post, put},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use crate::control::{ControlPlane, RequestKind};
use crate::key_cipher::{KeyWrapping, SecretCipher};
use crate::plugin_registry::PluginRegistry;
use crate::s3_error;
use crate::service_storage::{ServiceStorage, parse_service_backends};
use crate::store::{
    BackendConfig, BackendRegistry, FileKeyStore, KeyRepository, KeyStore, MemoryStore,
    PostgresKeyStore, sha256_hash,
};
use crate::{Format, Gateway};

#[derive(Clone)]
pub struct AppState {
    pub gateway: Arc<Gateway>,
    pub store: Arc<MemoryStore>,
    pub keys: Arc<dyn KeyRepository>,
    pub backends: Arc<BackendRegistry>,
    pub plugins: Arc<PluginRegistry>,
    pub service_storage: Arc<ServiceStorage>,
    pub s3_client: Option<Client>,
    pub supabase_url: String,
    pub jwt_decoder: Option<Arc<jsonwebtoken::DecodingKey>>,
    pub auth_disabled: bool,
    pub control: Arc<dyn ControlPlane>,
    pub legacy_max_object_bytes: usize,
}

pub struct Auth {
    user_id: String,
    public_key_pem: Option<String>,
    stable_key: Option<Vec<u8>>,
}

const LEGACY_MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;

fn legacy_max_object_bytes() -> usize {
    let configured = match std::env::var("S4_LEGACY_MAX_OBJECT_BYTES") {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(value) if value > 0 => value,
            _ => {
                warn!(
                    "invalid S4_LEGACY_MAX_OBJECT_BYTES={raw:?}; using {LEGACY_MAX_OBJECT_BYTES}"
                );
                LEGACY_MAX_OBJECT_BYTES
            }
        },
        Err(_) => LEGACY_MAX_OBJECT_BYTES,
    };
    let bounded = configured.min(LEGACY_MAX_OBJECT_BYTES);
    if bounded != configured {
        warn!(
            "S4_LEGACY_MAX_OBJECT_BYTES={configured} exceeds the immutable 16 MiB limit; using {bounded}"
        );
    }
    bounded
}

fn effective_legacy_max_object_bytes(state: &AppState) -> usize {
    state
        .legacy_max_object_bytes
        .min(LEGACY_MAX_OBJECT_BYTES)
}

#[derive(Debug)]
enum BoundedReadError {
    EntityTooLarge,
    Backend(String),
}

fn append_bounded(
    data: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
) -> Result<(), BoundedReadError> {
    if chunk.len() > max_bytes.saturating_sub(data.len()) {
        return Err(BoundedReadError::EntityTooLarge);
    }
    data.extend_from_slice(chunk);
    Ok(())
}

async fn collect_http_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    if response.content_length().is_some_and(|size| size > max_bytes as u64) {
        return Err(BoundedReadError::EntityTooLarge);
    }
    let mut data = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(max_bytes as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| BoundedReadError::Backend(error.to_string()))?
    {
        append_bounded(&mut data, &chunk, max_bytes)?;
    }
    Ok(data)
}

async fn collect_s3_body(
    mut body: ByteStream,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    let (_, upper) = body.size_hint();
    if upper.is_some_and(|size| size > max_bytes as u64) {
        return Err(BoundedReadError::EntityTooLarge);
    }
    let mut data = Vec::with_capacity(upper.unwrap_or(0).min(max_bytes as u64) as usize);
    while let Some(chunk) = body
        .try_next()
        .await
        .map_err(|error| BoundedReadError::Backend(error.to_string()))?
    {
        append_bounded(&mut data, &chunk, max_bytes)?;
    }
    Ok(data)
}

/// Derive the deterministic-encryption key for an API key secret:
/// two 32-byte HMAC-SHA256 outputs (`"s4-stable-encrypt"` + counter) giving
/// the 64-byte key AES-256-SIV requires. The plugin receives only this
/// derived key, never the raw secret.
fn derive_stable_key(secret: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut out = Vec::with_capacity(64);
    for i in 1..=2u8 {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(b"s4-stable-encrypt");
        mac.update(&[i]);
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out
}

#[derive(Serialize, ToSchema)]
struct ApiKeyResponse {
    key_id: String,
    secret: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct InternalErrorResponse {
    error: String,
}

#[derive(Serialize, ToSchema)]
struct ListKeyResponse {
    key_id: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ObjectResponse {
    key: String,
    size: usize,
}

#[derive(Deserialize, ToSchema)]
struct CreateKeyRequest {
    label: String,
    #[serde(default)]
    expires_in: u64,
    #[serde(default)]
    public_key_pem: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct DeleteKeyRequest {
    key_id: String,
}

#[derive(Serialize, ToSchema)]
struct McpTokenResponse {
    token_hash: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct McpTokenCreatedResponse {
    token: String,
    label: String,
    created_at: String,
    expires_at: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct CreateMcpTokenRequest {
    label: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize, ToSchema)]
struct DeleteMcpTokenRequest {
    token_hash: String,
}

#[derive(serde::Deserialize, Default)]
struct S3Query {
    #[serde(rename = "uploads")]
    uploads: Option<String>,
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
    #[serde(rename = "list-type")]
    list_type: Option<String>,
    prefix: Option<String>,
    delimiter: Option<String>,
    #[serde(rename = "continuation-token")]
    continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    start_after: Option<String>,
    #[serde(rename = "max-keys")]
    max_keys: Option<u32>,
    #[serde(rename = "encoding-type")]
    encoding_type: Option<String>,
    #[allow(dead_code)]
    marker: Option<String>,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "S4 Gateway API",
        version = "0.3.5",
        description = "Pluggable processing gateway for S3-compatible storage. Manage plugins and API keys, proxy S3 requests through a Wasm plugin pipeline."
    ),
    paths(get_keys, create_key, delete_key, list_objects),
    components(schemas(ApiKeyResponse, InternalErrorResponse, ListKeyResponse, CreateKeyRequest, DeleteKeyRequest, ObjectResponse)),
    tags(
        (name = "keys", description = "API key management"),
        (name = "objects", description = "Object store listing")
    )
)]
struct ApiDoc;

fn detect_format(headers: &HeaderMap) -> Format {
    let ct = headers
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/plain");
    match ct {
        "application/x-ndjson" | "application/jsonlines" => Format::Jsonl,
        "application/json" => Format::Json,
        "text/csv" => Format::Csv,
        "text/tab-separated-values" => Format::Tsv,
        _ => Format::Text,
    }
}

/// Escape a value for inclusion in an S3 XML document.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// URL-encode a key for `encoding-type=url` list responses (S3 url-encoding:
/// everything except unreserved `A-Za-z0-9-_.~`).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

struct SigV4Auth {
    access_key: String,
    region: String,
    service: String,
    signed_headers: Vec<String>,
    signature: String,
}

/// Parse the components of an `Authorization: AWS4-HMAC-SHA256 ...` header.
fn parse_sigv4(auth: &str) -> Option<SigV4Auth> {
    let rest = auth.strip_prefix("AWS4-HMAC-SHA256 ")?;
    let mut credential: Option<(String, String, String)> = None;
    let mut signed_headers: Option<Vec<String>> = None;
    let mut signature: Option<String> = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("Credential=") {
            let mut it = v.splitn(5, '/');
            let access_key = it.next()?.to_string();
            it.next()?; // scope date
            let region = it.next()?.to_string();
            let service = it.next()?.to_string();
            it.next()?; // "aws4_request"
            credential = Some((access_key, region, service));
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(v.split(';').map(|s| s.to_string()).collect());
        } else if let Some(v) = part.strip_prefix("Signature=") {
            signature = Some(v.to_string());
        }
    }
    Some(SigV4Auth {
        access_key: credential.as_ref()?.0.clone(),
        region: credential.as_ref()?.1.clone(),
        service: credential.as_ref()?.2.clone(),
        signed_headers: signed_headers?,
        signature: signature?,
    })
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYYMMDD'T'HHMMSS'Z'` (the SigV4 `x-amz-date` format).
fn parse_sigv4_timestamp(s: &str) -> Option<SystemTime> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let two = |i: usize| -> Option<u64> {
        let hi = b[i].checked_sub(b'0')? as u64;
        let lo = b[i + 1].checked_sub(b'0')? as u64;
        Some(hi * 10 + lo)
    };
    let year = two(0)? * 100 + two(2)?;
    let month = two(4)?;
    let day = two(6)?;
    let hour = two(9)?;
    let minute = two(11)?;
    let second = two(13)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let total = days_from_civil(year as i64, month as i64, day as i64) * 86_400
        + hour as i64 * 3_600
        + minute as i64 * 60
        + second as i64;
    if total < 0 {
        return None;
    }
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(total as u64))
}

/// Lowercase hex SHA-256 of `bytes` (for `x-amz-content-sha256` comparison).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    use std::fmt::Write;
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Recompute the SigV4 signature for the incoming request using the same
/// signing settings the AWS SDK applies for S3 (single percent-encoding, no
/// URI path normalization, `x-amz-content-sha256` payload hash) and compare
/// against the client-provided signature.
fn verify_sigv4(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    secret: &str,
    sigv4: &SigV4Auth,
) -> bool {
    let Some(x_amz_date) = headers.get("x-amz-date").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(time) = parse_sigv4_timestamp(x_amz_date) else {
        return false;
    };

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    let identity: aws_smithy_runtime_api::client::identity::Identity = SigV4Credentials::new(
        sigv4.access_key.clone(),
        secret.to_string(),
        None,
        None,
        "s4-front-door",
    )
    .into();
    let params: SigningParams = match v4::SigningParams::builder()
        .identity(&identity)
        .region(&sigv4.region)
        .name(&sigv4.service)
        .time(time)
        .settings(settings)
        .build()
    {
        Ok(p) => p.into(),
        Err(_) => return false,
    };

    // Feed exactly the headers the client signed — any extra header changes
    // the canonical request and the signature would not match.
    let mut signed_headers = Vec::with_capacity(sigv4.signed_headers.len());
    for name in &sigv4.signed_headers {
        let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        signed_headers.push((name.as_str(), value));
    }

    let target = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());
    let payload = match headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
    {
        Some("UNSIGNED-PAYLOAD") => SignableBody::UnsignedPayload,
        Some(hash) if !hash.is_empty() => {
            // Never trust the claimed hash for a non-empty body: recompute
            // against the actual bytes so body tampering is detected even when
            // the attacker keeps the original x-amz-content-sha256 header.
            if !body.is_empty() {
                let actual = sha256_hex(body);
                if !actual.eq_ignore_ascii_case(hash) {
                    return false;
                }
            }
            SignableBody::Precomputed(hash.to_string())
        }
        _ => SignableBody::Bytes(body),
    };

    let request = match SignableRequest::new(
        method,
        target.to_string(),
        signed_headers.into_iter(),
        payload,
    ) {
        Ok(r) => r,
        Err(_) => return false,
    };

    match sign(request, &params) {
        Ok(output) => output.signature().eq_ignore_ascii_case(&sigv4.signature),
        Err(_) => false,
    }
}

async fn get_user_s3_client(state: &AppState, uid: &str) -> Option<Client> {
    if let Some(ref s3) = state.s3_client {
        return Some(s3.clone());
    }
    let cfg = state.backends.get(uid)?;
    if !cfg.is_configured() || cfg.endpoint.is_empty() {
        return None;
    }
    let creds = Credentials::new(&cfg.access_key, &cfg.secret_key, None, None, "s4-backend");
    let region = if cfg.region.is_empty() {
        "us-east-1".to_string()
    } else {
        cfg.region.clone()
    };
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(region))
        .endpoint_url(&cfg.endpoint)
        .credentials_provider(creds)
        .load()
        .await;
    Some(Client::new(&config))
}

async fn authenticate(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    keys: &Arc<dyn KeyRepository>,
    state: &AppState,
) -> Option<Auth> {
    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
    match auth {
        Some(a) if a.starts_with("AWS4-") => {
            // Local/demo mode skips signature verification entirely.
            if state.auth_disabled {
                return Some(Auth {
                    user_id: "demo-user".to_string(),
                    public_key_pem: None,
                    stable_key: None,
                });
            }
            let sigv4 = parse_sigv4(a)?;
            let key = keys.get_key(&sigv4.access_key).await?;
            if key_expired(key.expires_at.as_deref()) {
                return None;
            }
            let secret = keys.decrypt_secret(&sigv4.access_key).await?;
            if !verify_sigv4(method, uri, headers, body, &secret, &sigv4) {
                return None;
            }
            return Some(Auth {
                user_id: key.user_id.clone(),
                public_key_pem: key.public_key_pem.clone(),
                stable_key: Some(derive_stable_key(&secret)),
            });
        }
        Some(a) if a.starts_with("Bearer ") => {
            let token = &a[7..];
            // MCP bearer token (s4m_...): a self-contained credential.
            if token.starts_with("s4m_") {
                if let Some(user_id) = keys.resolve_mcp_token(token).await {
                    return Some(Auth {
                        user_id,
                        public_key_pem: None,
                        stable_key: None,
                    });
                }
                return None;
            }
            // Try API key format: Bearer s4_xxx:s4s_xxx
            if let Some((ak, sk)) = token.split_once(':') {
                let (user_id, public_key_pem) = keys.resolve_credentials(ak, sk).await?;
                return Some(Auth {
                    user_id,
                    public_key_pem,
                    stable_key: Some(derive_stable_key(sk)),
                });
            }
            // Try JWT
            if state.jwt_decoder.is_some() {
                let uid = get_user_id(headers, state);
                if uid != "demo-user" {
                    return Some(Auth {
                        user_id: uid,
                        public_key_pem: None,
                        stable_key: None,
                    });
                }
            }
            return None;
        }
        _ => None::<Auth>,
    };
    // x-s4-mcp-token header: MCP bearer token.
    if let Some(tok) = headers.get("x-s4-mcp-token").and_then(|v| v.to_str().ok()) {
        if tok.starts_with("s4m_")
            && let Some(user_id) = keys.resolve_mcp_token(tok).await
        {
            return Some(Auth {
                user_id,
                public_key_pem: None,
                stable_key: None,
            });
        }
        return None;
    }
    let ak = headers
        .get("x-s4-access-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sk = headers
        .get("x-s4-secret-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some((user_id, public_key_pem)) = keys.resolve_credentials(ak, sk).await {
        return Some(Auth {
            user_id,
            public_key_pem,
            stable_key: Some(derive_stable_key(sk)),
        });
    }
    // Allow access in demo mode only when auth is explicitly disabled or
    // when using an in-memory keystore with no keys (dev/first-run mode).
    // Never allow unauthenticated access when keys are persisted — this
    // prevents an empty database from becoming an open door in production.
    if state.auth_disabled {
        return Some(Auth {
            user_id: "demo-user".to_string(),
            public_key_pem: None,
            stable_key: None,
        });
    }
    None
}

fn key_expired(expires_at: Option<&str>) -> bool {
    if let Some(exp) = expires_at {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if exp.parse::<u64>().is_ok_and(|ts| now >= ts) {
            return true;
        }
    }
    false
}

fn get_user_id(headers: &HeaderMap, state: &AppState) -> String {
    match get_user_claims(headers, state) {
        Some(claims) => claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("demo-user")
            .to_string(),
        None => "demo-user".to_string(),
    }
}

fn supabase_jwt_validation(
    algorithm: jsonwebtoken::Algorithm,
    issuer: &str,
) -> jsonwebtoken::Validation {
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&["authenticated"]);
    validation.validate_exp = true;
    validation
}

/// Resolve and validate the authenticated user's Supabase claims.
pub async fn require_user_claims(
    headers: &HeaderMap,
    state: &AppState,
) -> Option<serde_json::Value> {
    if state.auth_disabled {
        return Some(serde_json::json!({
            "sub": "demo-user",
            "email": "",
            "app_metadata": { "provider": "demo" },
        }));
    }
    if let Some(claims) = verify_jwks_claims(headers, state).await {
        return Some(claims);
    }
    get_user_claims(headers, state)
}

/// Resolve the authenticated user id, or `None` when the request is not
/// authenticated. When auth is disabled (local/demo mode) this is permissive
/// and returns the demo user. When auth is enabled (production SaaS) an
/// unauthenticated request returns `None` so callers can reject with 401.
/// Accepts both ES256 (Supabase OAuth access tokens, via JWKS) and HS256
/// (email/password sessions, via the JWT secret).
pub async fn require_user_id(headers: &HeaderMap, state: &AppState) -> Option<String> {
    let claims = require_user_claims(headers, state).await?;
    let sub = claims.get("sub")?.as_str()?;
    if sub.is_empty() {
        return None;
    }
    Some(sub.to_string())
}

/// Verify a Supabase ES256 access token against the project JWKS and return
/// its `sub`. Uses the async client (safe in tokio handlers).
#[allow(clippy::type_complexity)]
async fn verify_jwks_claims(headers: &HeaderMap, state: &AppState) -> Option<serde_json::Value> {
    use std::sync::OnceLock;
    use std::time::Instant;

    static CACHE: OnceLock<std::sync::Mutex<Option<(String, Vec<serde_json::Value>, Instant)>>> =
        OnceLock::new();

    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok())?;
    let token = auth.strip_prefix("Bearer ")?;
    let header = jsonwebtoken::decode_header(token).ok()?;
    let kid = header.kid.as_deref()?;
    let issuer = format!("{}/auth/v1", state.supabase_url.trim_end_matches('/'));
    let jwks_url = format!("{}/.well-known/jwks.json", issuer);

    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(None));
    {
        let stale = {
            let guard = cache.lock().ok()?;
            match &*guard {
                Some((url, _, at)) => {
                    url != &jwks_url || at.elapsed() > Duration::from_secs(6 * 60 * 60)
                }
                None => true,
            }
        };
        if stale {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .ok()?;
            let resp = client.get(&jwks_url).send().await.ok()?;
            let body: serde_json::Value = resp.json().await.ok()?;
            let keys = body.get("keys")?.as_array()?.clone();
            let mut guard = cache.lock().ok()?;
            *guard = Some((jwks_url, keys, Instant::now()));
        }
    }
    let guard = cache.lock().ok()?;
    let (_, keys, _) = guard.as_ref()?;
    let key = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))?;
    let x = key.get("x")?.as_str()?;
    let y = key.get("y")?.as_str()?;
    let pem = engine_ec_pem(x, y)?;

    let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes()).ok()?;
    let validation = supabase_jwt_validation(jsonwebtoken::Algorithm::ES256, &issuer);
    let data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation).ok()?;
    Some(data.claims)
}

/// Build an EC public-key PEM (SPKI) from base64url JWK x/y coordinates.
fn engine_ec_pem(x: &str, y: &str) -> Option<String> {
    use base64::Engine;
    let xb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .ok()?;
    let yb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y)
        .ok()?;
    if xb.len() != 32 || yb.len() != 32 {
        return None;
    }
    let alg_id = [
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let mut bit_string = vec![0x00];
    bit_string.push(0x04);
    bit_string.extend_from_slice(&xb);
    bit_string.extend_from_slice(&yb);
    let bit_len = bit_string.len();
    let mut bit_tlv = vec![0x03];
    bit_tlv.push(if bit_len < 128 {
        bit_len as u8
    } else {
        return None;
    });
    bit_tlv.extend_from_slice(&bit_string);
    let body_len = alg_id.len() + bit_tlv.len();
    let mut spki = vec![0x30];
    spki.push(if body_len < 128 {
        body_len as u8
    } else {
        return None;
    });
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&bit_tlv);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
    Some(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        b64.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// Decode and validate the Supabase JWT, returning its claims.
fn get_user_claims(headers: &HeaderMap, state: &AppState) -> Option<serde_json::Value> {
    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let token = match auth {
        Some(a) if a.starts_with("Bearer ") => &a[7..],
        _ => return None,
    };

    let key = state.jwt_decoder.as_ref()?;
    let issuer = format!("{}/auth/v1", state.supabase_url.trim_end_matches('/'));
    let validation = supabase_jwt_validation(jsonwebtoken::Algorithm::HS256, &issuer);
    match jsonwebtoken::decode::<serde_json::Value>(token, key, &validation) {
        Ok(data) => Some(data.claims),
        Err(e) => {
            warn!("JWT validation failed: {e}");
            None
        }
    }
}

async fn get_me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let Some(claims) = require_user_claims(&headers, &state).await else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    let Some(user_id) = claims.get("sub").and_then(|v| v.as_str()) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    let email = claims
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = claims
        .get("app_metadata")
        .and_then(|m| m.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("email")
        .to_string();
    let keys = state.keys.list_for_user(user_id).await;
    Json(serde_json::json!({
        "user_id": user_id,
        "email": email,
        "provider": provider,
        "keys": keys.len(),
    }))
    .into_response()
}

/// Interactive demo: run the WASM PII pipeline over the submitted text and
/// return the redacted output. Uses the demo-user identity (no storage write);
/// rate limited in the client (5 trials).
#[derive(Deserialize, ToSchema)]
struct DemoRedactRequest {
    text: String,
}

async fn demo_redact(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DemoRedactRequest>,
) -> impl IntoResponse {
    if body.text.len() > 64 * 1024 {
        return (StatusCode::BAD_REQUEST, "demo input must be <= 64KB").into_response();
    }
    // Run the engine's default pipeline (PII redaction). No public key, no
    // stable key: this is the pure "detect + redact" path.
    match state.gateway.process(
        body.text.as_bytes(),
        Format::Text,
        "text/plain",
        None,
        None,
        None,
    ) {
        Ok(out) => Json(serde_json::json!({
            "redacted": String::from_utf8_lossy(&out.bytes),
            "records_processed": out.records_processed,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("pipeline error: {e}"),
        )
            .into_response(),
    }
}

/// Demo store: persist a batch of demo records (shared join keys allowed) in
/// the in-memory store under a fixed demo namespace. No auth — this is the
/// landing-page "store raw data" step. The store is in-memory, so it resets on
/// gateway restart.
#[derive(Deserialize, ToSchema)]
struct DemoStoreRequest {
    records: Vec<serde_json::Value>,
}

async fn demo_store(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DemoStoreRequest>,
) -> impl IntoResponse {
    if body.records.is_empty() || body.records.len() > 10 {
        return (StatusCode::BAD_REQUEST, "store 1-10 records").into_response();
    }
    for (i, record) in body.records.iter().enumerate() {
        let data = serde_json::to_vec(record).unwrap_or_default();
        state.store.put(
            "__demo",
            &format!("record-{}.json", i + 1),
            data,
            "application/json",
        );
    }
    Json(serde_json::json!({ "stored": body.records.len(), "namespace": "__demo" })).into_response()
}

/// Demo read: fetch a stored demo record in raw mode. Transformed modes remain
/// unavailable until the streaming disclosure model is implemented.
/// `mode`:
/// - `raw`  -> the bytes at rest (as your app sees them)
/// - `safe` / `join` -> rejected
#[derive(Deserialize, ToSchema)]
struct DemoReadQuery {
    id: Option<u32>,      // 1-based record number; default 1
    mode: Option<String>, // raw | safe | join
}

async fn demo_read(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DemoReadQuery>,
) -> impl IntoResponse {
    let id = q.id.unwrap_or(1);
    let mode = q.mode.as_deref().unwrap_or("raw");
    if mode != "raw" {
        return s3_error::transformed_read_not_supported(&format!("record-{id}.json"));
    }
    let Some(obj) = state.store.get("__demo", &format!("record-{id}.json")) else {
        return (StatusCode::NOT_FOUND, "no demo record stored yet").into_response();
    };
    Json(serde_json::json!({
        "mode": mode,
        "record": id,
        "body": String::from_utf8_lossy(&obj.data),
    }))
    .into_response()
}

fn s3_xml_ok(xml: String) -> axum::response::Response {
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(axum::body::Body::from(xml))
        .unwrap()
}

fn wants_transformed_read(headers: &HeaderMap) -> bool {
    headers
        .get("x-s4-process")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("read") || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn bounded_read_error(key: &str, error: BoundedReadError) -> axum::response::Response {
    match error {
        BoundedReadError::EntityTooLarge => s3_error::entity_too_large(key),
        BoundedReadError::Backend(detail) => {
            warn!("backend read failed for {key}: {detail}");
            s3_error::internal_error(key, &detail)
        }
    }
}

/// Run the filter pipeline over `body`.
fn process_input(
    state: &AppState,
    headers: &HeaderMap,
    auth: &Auth,
    body: &[u8],
) -> Result<crate::TransformOutput, s4_error::S4Error> {
    let format = detect_format(headers);
    let stable_fields = headers
        .get("x-s4-stable-fields")
        .and_then(|v| v.to_str().ok());
    state.gateway.process(
        body,
        format,
        "text/plain",
        auth.public_key_pem.as_deref(),
        auth.stable_key.as_deref(),
        stable_fields,
    )
}

/// Store already-filtered bytes via the configured backend, following the same
/// priority as a plain PUT (presigned URL header → S3 backend → service
/// storage → in-memory).
async fn store_processed(
    state: &AppState,
    auth: &Auth,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    output: crate::TransformOutput,
    input_len: usize,
) -> axum::response::Response {
    if let Some(backend_url) = headers
        .get("x-s4-backend-url")
        .and_then(|v| v.to_str().ok())
    {
        match reqwest::Client::new()
            .put(backend_url)
            .body(output.bytes.clone())
            .send()
            .await
        {
            Ok(_) => {
                state
                    .control
                    .record(&auth.user_id, RequestKind::Write, input_len as u64)
                    .await;
                info!(
                    "PUT /{bucket}/{key} -> presigned URL ({} records, user={})",
                    output.records_processed, auth.user_id
                );
                StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!("backend put failed: {e}");
                s3_error::internal_error(key, &e.to_string())
            }
        }
    } else if let Some(s3) = get_user_s3_client(state, &auth.user_id).await {
        match s3
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(output.bytes))
            .send()
            .await
        {
            Ok(_) => {
                state
                    .control
                    .record(&auth.user_id, RequestKind::Write, input_len as u64)
                    .await;
                info!(
                    "PUT /{bucket}/{key} -> S3 ({} records, user={})",
                    output.records_processed, auth.user_id
                );
                StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!("upstream put failed: {e}");
                s3_error::internal_error(key, &e.to_string())
            }
        }
    } else if !state.service_storage.is_empty() {
        match state
            .service_storage
            .put(
                &format!("{}/{bucket}/{key}", auth.user_id),
                output.bytes.to_vec(),
                "text/plain",
            )
            .await
        {
            Ok(()) => {
                state
                    .control
                    .record(&auth.user_id, RequestKind::Write, input_len as u64)
                    .await;
                info!(
                    "PUT /{bucket}/{key} -> service storage ({} records, user={})",
                    output.records_processed, auth.user_id
                );
                StatusCode::OK.into_response()
            }
            Err(e) => {
                warn!("service storage put failed: {e}");
                s3_error::internal_error(key, &e.to_string())
            }
        }
    } else {
        state
            .control
            .record(&auth.user_id, RequestKind::Write, input_len as u64)
            .await;
        let obj = state.store.put(bucket, key, output.bytes, "text/plain");
        info!(
            "PUT /{bucket}/{key} -> memory ({} records, {} bytes, user={})",
            output.records_processed,
            obj.data.len(),
            auth.user_id
        );
        let mut resp = axum::response::Response::builder().status(StatusCode::OK);
        resp = resp.header("ETag", &obj.etag);
        resp.body(axum::body::Body::empty()).unwrap()
    }
}

async fn s3_put(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    request: Request,
) -> impl IntoResponse {
    let (parts, request_body) = request.into_parts();
    if params.part_number.is_some() || params.upload_id.is_some() {
        let Some(auth) = authenticate(
            parts.method.as_str(),
            &parts.uri,
            &parts.headers,
            &[],
            &state.keys,
            &state,
        )
        .await
        else {
            return s3_error::access_denied(&key);
        };
        if let Some(reason) = state
            .control
            .authorize(&auth.user_id, RequestKind::Write)
            .await
        {
            return s3_error::payment_required(&key, reason.message);
        }
        return s3_error::multipart_not_supported(&key);
    }
    let max_bytes = effective_legacy_max_object_bytes(&state);
    let body = match axum::body::to_bytes(request_body, max_bytes).await {
        Ok(body) => body,
        Err(_) => return s3_error::entity_too_large(&key),
    };
    let Some(auth) = authenticate(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &body,
        &state.keys,
        &state,
    )
    .await
    else {
        return s3_error::access_denied(&key);
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.user_id, RequestKind::Write)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }

    let output = match process_input(&state, &parts.headers, &auth, &body) {
        Ok(o) => o,
        Err(e) => {
            warn!("filter failed for /{bucket}/{key}: {e}");
            return s3_error::internal_error(&key, &e.to_string());
        }
    };
    if output.bytes.len() > max_bytes {
        warn!(
            input_bytes = body.len(),
            output_bytes = output.bytes.len(),
            max_bytes,
            "filtered output exceeds the legacy object limit"
        );
        return s3_error::entity_too_large(&key);
    }
    store_processed(
        &state,
        &auth,
        &bucket,
        &key,
        &parts.headers,
        output,
        body.len(),
    )
    .await
}

async fn s3_get(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(auth) = authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await
    else {
        return s3_error::access_denied(&key);
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.user_id, RequestKind::Read)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }

    if wants_transformed_read(&headers) {
        return s3_error::transformed_read_not_supported(&key);
    }
    if params.upload_id.is_some() {
        return s3_error::multipart_not_supported(&key);
    }
    let max_bytes = effective_legacy_max_object_bytes(&state);

    if let Some(backend_url) = headers
        .get("x-s4-backend-url")
        .and_then(|v| v.to_str().ok())
    {
        match reqwest::get(backend_url).await {
            Ok(resp) => {
                state
                    .control
                    .record(&auth.user_id, RequestKind::Read, 0)
                    .await;
                let status = resp.status();
                let ct = resp
                    .headers()
                    .get("content-type")
                    .map(|v| v.to_str().unwrap_or("application/octet-stream").to_string())
                    .unwrap_or_else(|| "text/plain".to_string());
                let body_bytes = match collect_http_body(resp, max_bytes).await {
                    Ok(bytes) => bytes,
                    Err(error) => return bounded_read_error(&key, error),
                };
                let mut builder = axum::response::Response::builder()
                    .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
                builder = builder.header("Content-Type", &ct);
                builder = builder.header("Content-Length", body_bytes.len().to_string());
                builder.body(axum::body::Body::from(body_bytes)).unwrap()
            }
            Err(e) => {
                warn!("backend get failed: {e}");
                s3_error::internal_error(&key, &e.to_string())
            }
        }
    } else if let Some(ref s3) = state.s3_client {
        let mut req = s3.get_object().bucket(&bucket).key(&key);
        if let Some(range) = headers.get("Range").and_then(|v| v.to_str().ok()) {
            req = req.range(range);
        }
        match req.send().await {
            Ok(output) => {
                let ct = output
                    .content_type
                    .clone()
                    .unwrap_or_else(|| "text/plain".to_string());
                let etag = output.e_tag.clone();
                match collect_s3_body(output.body, max_bytes).await {
                    Ok(bytes) => {
                        state
                            .control
                            .record(&auth.user_id, RequestKind::Read, 0)
                            .await;
                        let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                        if let Some(etag) = etag.as_deref() {
                            resp = resp.header("ETag", etag);
                        }
                        resp = resp.header("Content-Type", &ct);
                        resp = resp.header("Content-Length", bytes.len().to_string());
                        resp.body(axum::body::Body::from(bytes)).unwrap()
                    }
                    Err(error) => bounded_read_error(&key, error),
                }
            }
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    s3_error::no_such_key(&key)
                } else {
                    s3_error::internal_error(&key, &e.to_string())
                }
            }
        }
    } else if !state.service_storage.is_empty() {
        match state
            .service_storage
            .get(
                &format!("{}/{bucket}/{key}", auth.user_id),
                max_bytes,
            )
            .await
        {
            Ok(Some((data, content_type))) => {
                state
                    .control
                    .record(&auth.user_id, RequestKind::Read, 0)
                    .await;
                let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                resp = resp.header("Content-Type", content_type);
                resp = resp.header("Content-Length", data.len().to_string());
                resp.body(axum::body::Body::from(data)).unwrap()
            }
            Ok(None) => s3_error::no_such_key(&key),
            Err(crate::service_storage::ServiceStorageReadError::EntityTooLarge) => {
                s3_error::entity_too_large(&key)
            }
        }
    } else {
        match state.store.get(&bucket, &key) {
            Some(obj) => {
                if obj.data.len() > max_bytes {
                    return s3_error::entity_too_large(&key);
                }
                state
                    .control
                    .record(&auth.user_id, RequestKind::Read, 0)
                    .await;
                let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                resp = resp.header("ETag", &obj.etag);
                resp = resp.header("Content-Type", &obj.content_type);
                resp = resp.header("Content-Length", obj.data.len().to_string());
                resp.body(axum::body::Body::from(obj.data)).unwrap()
            }
            None => s3_error::no_such_key(&key),
        }
    }
}

async fn s3_head(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(auth) = authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await
    else {
        return s3_error::access_denied(&key);
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.user_id, RequestKind::Read)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }

    if let Some(ref s3) = state.s3_client {
        match s3.head_object().bucket(&bucket).key(&key).send().await {
            Ok(output) => {
                state
                    .control
                    .record(&auth.user_id, RequestKind::Read, 0)
                    .await;
                let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                if let Some(etag) = output.e_tag.as_deref() {
                    resp = resp.header("ETag", etag);
                }
                if let Some(ct) = output.content_type.as_deref() {
                    resp = resp.header("Content-Type", ct);
                }
                if let Some(cl) = output.content_length {
                    resp = resp.header("Content-Length", cl.to_string());
                }
                resp.body(axum::body::Body::empty()).unwrap()
            }
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    s3_error::no_such_key(&key)
                } else {
                    s3_error::internal_error(&key, &e.to_string())
                }
            }
        }
    } else {
        match state.store.head(&bucket, &key) {
            Some(obj) => {
                state
                    .control
                    .record(&auth.user_id, RequestKind::Read, 0)
                    .await;
                let mut resp = axum::response::Response::builder().status(StatusCode::OK);
                resp = resp.header("ETag", &obj.etag);
                resp = resp.header("Content-Type", &obj.content_type);
                resp = resp.header("Content-Length", obj.data.len().to_string());
                resp.body(axum::body::Body::empty()).unwrap()
            }
            None => s3_error::no_such_key(&key),
        }
    }
}

async fn s3_delete(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(auth) = authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await
    else {
        return s3_error::access_denied(&key);
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.user_id, RequestKind::Write)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }
    info!("DELETE /{bucket}/{key} user={}", auth.user_id);

    if params.upload_id.is_some() {
        return s3_error::multipart_not_supported(&key);
    }

    if let Some(ref s3) = state.s3_client {
        match s3.delete_object().bucket(&bucket).key(&key).send().await {
            Ok(_) => {
                state
                    .control
                    .record(&auth.user_id, RequestKind::Write, 0)
                    .await;
                StatusCode::NO_CONTENT.into_response()
            }
            Err(e) => s3_error::internal_error(&key, &e.to_string()),
        }
    } else {
        state.store.delete(&bucket, &key);
        state
            .control
            .record(&auth.user_id, RequestKind::Write, 0)
            .await;
        StatusCode::NO_CONTENT.into_response()
    }
}

async fn s3_post(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    request: Request,
) -> impl IntoResponse {
    let (parts, _body) = request.into_parts();
    let Some(auth) = authenticate(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &[],
        &state.keys,
        &state,
    )
    .await
    else {
        return s3_error::access_denied(&key);
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.user_id, RequestKind::Write)
        .await
    {
        return s3_error::payment_required(&key, reason.message);
    }
    info!("POST /{bucket}/{key} user={}", auth.user_id);

    if params.uploads.is_some() || params.upload_id.is_some() {
        return s3_error::multipart_not_supported(&key);
    }
    s3_error::not_implemented(&key)
}

/// ListObjectsV2/ListObjectsV1 — `GET /{bucket}`.
async fn s3_list_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(auth) = authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await
    else {
        return s3_error::access_denied(&bucket);
    };
    if let Some(reason) = state
        .control
        .authorize(&auth.user_id, RequestKind::Read)
        .await
    {
        return s3_error::payment_required(&bucket, reason.message);
    }

    // Prefer a configured S3 backend, then the in-memory store.
    let mut client = state.s3_client.clone();
    if client.is_none() {
        client = get_user_s3_client(&state, &auth.user_id).await;
    }
    if let Some(s3) = client {
        return match list_from_s3(&s3, &bucket, &params).await {
            Ok(xml) => s3_xml_ok(xml),
            Err(e) => {
                warn!("list from S3 backend failed for {bucket}: {e}");
                s3_error::internal_error(&bucket, &e.to_string())
            }
        };
    }
    if !state.service_storage.is_empty() {
        warn!(
            "listing is not supported against service storage; returning an empty page for {bucket}"
        );
    }
    s3_xml_ok(list_from_memory(&state, &bucket, &params))
}

/// Forward a ListObjectsV2 request to an S3 backend.
async fn list_from_s3(s3: &Client, bucket: &str, params: &S3Query) -> anyhow::Result<String> {
    let mut req = s3.list_objects_v2().bucket(bucket);
    if let Some(p) = params.prefix.as_deref() {
        req = req.prefix(p);
    }
    if let Some(d) = params.delimiter.as_deref() {
        req = req.delimiter(d);
    }
    if let Some(t) = params.continuation_token.as_deref() {
        req = req.continuation_token(t);
    }
    if let Some(s) = params.start_after.as_deref() {
        req = req.start_after(s);
    }
    if let Some(m) = params.max_keys {
        req = req.max_keys(m.min(1000) as i32);
    }
    let out = req.send().await?;

    let encoding = params.encoding_type.as_deref() == Some("url");
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        xml_escape(params.prefix.as_deref().unwrap_or(""))
    ));
    if let Some(d) = params.delimiter.as_deref() {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    xml.push_str(&format!(
        "<KeyCount>{}</KeyCount>",
        out.key_count().unwrap_or(0)
    ));
    xml.push_str(&format!(
        "<MaxKeys>{}</MaxKeys>",
        out.max_keys().unwrap_or(1000)
    ));
    xml.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        out.is_truncated().unwrap_or(false)
    ));
    if let Some(token) = out.continuation_token() {
        xml.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(token)
        ));
    }
    if let Some(token) = out.next_continuation_token() {
        xml.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            xml_escape(token)
        ));
    }
    if let Some(start) = params.start_after.as_deref() {
        xml.push_str(&format!("<StartAfter>{}</StartAfter>", xml_escape(start)));
    }
    for c in out.contents().iter() {
        let k = c.key().unwrap_or_default();
        let display = if encoding {
            url_encode(k)
        } else {
            k.to_string()
        };
        let etag = c.e_tag().unwrap_or_default();
        let size = c.size().unwrap_or(0);
        let lm = c.last_modified().map(|d| d.to_string()).unwrap_or_default();
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{lm}</LastModified><ETag>{}</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&display),
            xml_escape(etag)
        ));
    }
    for cp in out.common_prefixes() {
        if let Some(p) = cp.prefix() {
            let display = if encoding {
                url_encode(p)
            } else {
                p.to_string()
            };
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(&display)
            ));
        }
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}

/// ListObjectsV2 against the in-memory store.
fn list_from_memory(state: &AppState, bucket: &str, params: &S3Query) -> String {
    let prefix = params.prefix.as_deref().unwrap_or("");
    let delimiter = params.delimiter.as_deref();
    let max_keys = params.max_keys.unwrap_or(1000).min(1000) as usize;
    let encoding = params.encoding_type.as_deref() == Some("url");
    let resume_after = params
        .continuation_token
        .as_deref()
        .or(params.start_after.as_deref())
        .or(params.marker.as_deref());

    let bucket_prefix = format!("{bucket}/");
    let mut keys: Vec<String> = state
        .store
        .list_keys()
        .into_iter()
        .filter_map(|full| full.strip_prefix(&bucket_prefix).map(|k| k.to_string()))
        .filter(|k| k.starts_with(prefix))
        .collect();
    keys.sort();
    keys.retain(|k| match resume_after {
        Some(t) => k.as_str() > t,
        None => true,
    });

    enum Output {
        Content((String, String, u64)),
        Common(String),
    }
    let mut outputs: Vec<Output> = Vec::new();
    let mut prev_common: Option<String> = None;
    for k in keys {
        if let Some(delim) = delimiter.filter(|d| !d.is_empty())
            && let Some(rel) = k.strip_prefix(prefix)
            && let Some(idx) = rel.find(delim)
        {
            let cp = format!("{prefix}{}", &rel[..=idx]);
            if prev_common.as_deref() != Some(cp.as_str()) {
                prev_common = Some(cp.clone());
                outputs.push(Output::Common(cp));
            }
            continue;
        }
        prev_common = None;
        let obj = state.store.get(bucket, &k);
        let (etag, size) = obj
            .map(|o| (o.etag, o.data.len() as u64))
            .unwrap_or_default();
        outputs.push(Output::Content((k, etag, size)));
    }

    let mut contents: Vec<(String, String, u64)> = Vec::new();
    let mut commons: Vec<String> = Vec::new();
    let mut seen = 0usize;
    for out in outputs.iter().take(max_keys) {
        match out {
            Output::Content(entry) => contents.push(entry.clone()),
            Output::Common(cp) => commons.push(cp.clone()),
        }
        seen += 1;
    }
    let truncated = outputs.len() > seen;
    let next_token = if truncated {
        outputs.get(seen - 1).map(|out| match out {
            Output::Content((k, _, _)) => k.clone(),
            Output::Common(cp) => cp.clone(),
        })
    } else {
        None
    };

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
    if let Some(d) = delimiter {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    let is_v2 = params.list_type.as_deref() == Some("2");
    xml.push_str(&format!(
        "<KeyCount>{}</KeyCount>",
        contents.len() + commons.len()
    ));
    xml.push_str(&format!("<MaxKeys>{max_keys}</MaxKeys>"));
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    if let Some(t) = resume_after {
        let elem = if is_v2 {
            format!("<ContinuationToken>{}</ContinuationToken>", xml_escape(t))
        } else {
            format!("<Marker>{}</Marker>", xml_escape(t))
        };
        xml.push_str(&elem);
    }
    if let Some(t) = next_token {
        let elem = if is_v2 {
            format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                xml_escape(&t)
            )
        } else {
            format!("<NextMarker>{}</NextMarker>", xml_escape(&t))
        };
        xml.push_str(&elem);
    }
    for (k, etag, size) in &contents {
        let display = if encoding { url_encode(k) } else { k.clone() };
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>1970-01-01T00:00:00.000Z</LastModified><ETag>{}</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&display),
            xml_escape(etag)
        ));
    }
    for cp in &commons {
        let display = if encoding { url_encode(cp) } else { cp.clone() };
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            xml_escape(&display)
        ));
    }
    xml.push_str("</ListBucketResult>");
    xml
}

/// `GET /` — serve the dashboard to browsers, ListBuckets to S3 clients.
async fn root(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let is_s3 = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|a| a.starts_with("AWS4-"))
        .unwrap_or(false)
        || headers.contains_key("x-s4-access-key");
    if !is_s3 {
        return Html(dashboard_html()).into_response();
    }
    let Some(auth) = authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await
    else {
        return s3_error::access_denied("").into_response();
    };
    match list_buckets(&state, &auth).await {
        Ok(xml) => s3_xml_ok(xml).into_response(),
        Err(e) => s3_error::internal_error("", &e.to_string()).into_response(),
    }
}

async fn list_buckets(state: &AppState, auth: &Auth) -> anyhow::Result<String> {
    let mut names: Vec<String> = Vec::new();
    if let Some(s3) = get_user_s3_client(state, &auth.user_id).await {
        let out = s3.list_buckets().send().await?;
        for b in out.buckets().iter() {
            if let Some(n) = b.name() {
                names.push(n.to_string());
            }
        }
    } else {
        let mut set = std::collections::BTreeSet::new();
        for full in state.store.list_keys() {
            if let Some((b, _)) = full.split_once('/') {
                set.insert(b.to_string());
            }
        }
        names.extend(set);
    }
    names.sort();
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>s4</ID><DisplayName>s4</DisplayName></Owner><Buckets>"#,
    );
    for n in names {
        xml.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>1970-01-01T00:00:00.000Z</CreationDate></Bucket>",
            xml_escape(&n)
        ));
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml)
}

/// CreateBucket is not allowed — buckets map to configured backends.
async fn s3_bucket_put(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    if authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state)
        .await
        .is_none()
    {
        return s3_error::access_denied(&bucket);
    }
    s3_error::bucket_not_allowed(&bucket)
}

/// DeleteBucket is not allowed for the same reason as CreateBucket.
async fn s3_bucket_delete(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    if authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state)
        .await
        .is_none()
    {
        return s3_error::access_denied(&bucket);
    }
    s3_error::bucket_not_allowed(&bucket)
}

fn dashboard_html() -> String {
    let html = include_str!("../static/dashboard.html");
    let auth_disabled = std::env::var("AUTH_DISABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let supabase_url =
        std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:54321".to_string());
    let anon_key = std::env::var("SUPABASE_ANON_KEY")
        .unwrap_or_else(|_| "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH".to_string());
    let has_supabase = anon_key.starts_with("sb_");

    let supabase_script = if has_supabase {
        format!(
            "<script src=\"https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js\"></script>\n<script>var supabase = window.supabase.createClient('{supabase_url}', '{anon_key}');\nvar HAS_SUPABASE = true;</script>"
        )
    } else {
        "<script>var HAS_SUPABASE = false;</script>".to_string()
    };

    // Local mode (AUTH_DISABLED=true): skip the auth modal entirely, go
    // straight into the dashboard as the local demo user.
    let boot = if auth_disabled || !has_supabase {
        "isDemo = true; onAuthReady();".to_string()
    } else {
        "supabase.auth.getSession().then(function(r) { if (r.data.session) { session = r.data.session; sessionToken = session.access_token; onAuthReady(); } });".to_string()
    };

    let auth_flag = format!(
        "<script>var AUTH_DISABLED = {};</script>",
        if auth_disabled { "true" } else { "false" }
    );

    html.replace("<!--SUPABASE-->", &format!("{auth_flag}{supabase_script}"))
        .replace("/*BOOT*/", &boot)
}

async fn health() -> impl IntoResponse {
    "ok"
}

/// List API keys for the authenticated user
#[utoipa::path(
    get,
    path = "/dashboard/api/keys",
    responses((status = 200, description = "API keys", body = Vec<ListKeyResponse>)),
    tag = "keys"
)]
async fn get_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let keys = state.keys.list_for_user(&uid).await;
    let resp: Vec<ListKeyResponse> = keys
        .into_iter()
        .map(|k| ListKeyResponse {
            key_id: k.key_id,
            label: k.label,
            created_at: k.created_at,
            expires_at: k.expires_at,
            public_key_pem: k.public_key_pem,
        })
        .collect();
    Json(resp).into_response()
}

/// Create a new API key
#[utoipa::path(
    post,
    path = "/dashboard/api/keys",
    request_body = CreateKeyRequest,
    responses(
        (status = 200, description = "Created key with secret", body = ApiKeyResponse),
        (status = 500, description = "Key persistence failed", body = InternalErrorResponse)
    ),
    tag = "keys"
)]
async fn create_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let result = state
        .keys
        .create_key(&uid, &body.label, body.expires_in, body.public_key_pem)
        .await;
    let (key_id, secret) = match result {
        Ok(created) => created,
        Err(error) => {
            tracing::error!(
                user_id = uid,
                error = %error,
                "API key creation persistence failed"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(InternalErrorResponse {
                    error: "internal_error".to_string(),
                }),
            )
                .into_response();
        }
    };
    let key = state.keys.get_key(&key_id).await;
    let created_at = key
        .as_ref()
        .map_or_else(|| "0".to_string(), |k| k.created_at.clone());
    let expires_at = key.as_ref().and_then(|k| k.expires_at.clone());
    let public_key_pem = key.as_ref().and_then(|k| k.public_key_pem.clone());
    Json(ApiKeyResponse {
        key_id,
        secret,
        label: body.label,
        created_at,
        expires_at,
        public_key_pem,
    })
    .into_response()
}

/// Revoke an API key
#[utoipa::path(
    delete,
    path = "/dashboard/api/keys",
    request_body = DeleteKeyRequest,
    responses((status = 204, description = "Key revoked"), (status = 404, description = "Key not found")),
    tag = "keys"
)]
async fn delete_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteKeyRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if state.keys.delete_key(&body.key_id, &uid).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "key not found").into_response()
    }
}

/// List MCP bearer tokens for the authenticated user (hashes only).
#[utoipa::path(
    get,
    path = "/dashboard/api/mcp-tokens",
    responses((status = 200, description = "MCP tokens", body = Vec<McpTokenResponse>)),
    tag = "mcp"
)]
async fn get_mcp_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let tokens = state.keys.list_mcp_tokens(&uid).await;
    let resp: Vec<McpTokenResponse> = tokens
        .into_iter()
        .map(|t| McpTokenResponse {
            token_hash: t.token_hash,
            label: t.label,
            created_at: t.created_at,
            expires_at: t.expires_at,
        })
        .collect();
    Json(resp).into_response()
}

/// Create an MCP bearer token (`s4m_...`). The plaintext token is returned
/// once and only its hash is stored.
#[utoipa::path(
    post,
    path = "/dashboard/api/mcp-tokens",
    request_body = CreateMcpTokenRequest,
    responses((status = 200, description = "Created MCP token", body = McpTokenCreatedResponse)),
    tag = "mcp"
)]
async fn create_mcp_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateMcpTokenRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let token = state
        .keys
        .create_mcp_token(&uid, &body.label, body.expires_in)
        .await;
    let hash = sha256_hash(&token);
    let created_at = state
        .keys
        .list_mcp_tokens(&uid)
        .await
        .into_iter()
        .find(|t| t.token_hash == hash)
        .map(|t| t.created_at)
        .unwrap_or_default();
    Json(McpTokenCreatedResponse {
        token,
        label: body.label,
        created_at,
        expires_at: None,
    })
    .into_response()
}

/// Revoke an MCP bearer token.
#[utoipa::path(
    delete,
    path = "/dashboard/api/mcp-tokens",
    request_body = DeleteMcpTokenRequest,
    responses((status = 204, description = "Token revoked"), (status = 404, description = "Token not found")),
    tag = "mcp"
)]
async fn delete_mcp_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteMcpTokenRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if state.keys.delete_mcp_token(&body.token_hash, &uid).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "token not found").into_response()
    }
}

async fn get_backend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let config = state.backends.get(&uid).unwrap_or(BackendConfig {
        backend_type: String::new(),
        role_arn: String::new(),
        external_id: state.backends.generate_external_id(&uid),
        endpoint: String::new(),
        access_key: String::new(),
        secret_key: String::new(),
        region: String::new(),
    });
    Json(config).into_response()
}

async fn put_backend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(config): Json<BackendConfig>,
) -> impl IntoResponse {
    let uid = get_user_id(&headers, &state);
    let mut config = config;
    if config.external_id.is_empty() {
        config.external_id = state.backends.generate_external_id(&uid);
    }
    state.backends.set(&uid, config);
    StatusCode::OK.into_response()
}

async fn get_plugins(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.plugins.list())
}

#[derive(Deserialize)]
struct SetPublicKeyRequest {
    key_id: String,
    public_key_pem: String,
}

async fn set_public_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SetPublicKeyRequest>,
) -> impl IntoResponse {
    let uid = get_user_id(&headers, &state);
    if state
        .keys
        .set_public_key(&body.key_id, &uid, &body.public_key_pem)
        .await
    {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "key not found or not owned by user").into_response()
    }
}

async fn create_plugin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let name = headers
        .get("x-s4-plugin-name")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("imported")
        .to_string();
    match state.plugins.import(&name, &body) {
        Ok(info) => (StatusCode::CREATED, Json(info)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct PluginUpdate {
    enabled: Option<bool>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct PluginReorder {
    order: Vec<String>,
}

async fn reorder_plugins(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PluginReorder>,
) -> impl IntoResponse {
    state.plugins.reorder(body.order);
    StatusCode::OK.into_response()
}

async fn update_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(update): Json<PluginUpdate>,
) -> impl IntoResponse {
    let found = update
        .enabled
        .is_some_and(|enabled| state.plugins.set_enabled(&id, enabled).is_some())
        || update
            .name
            .is_some_and(|name| state.plugins.set_name(&id, &name).is_some());
    if let Some(info) = state.plugins.get_info(&id) {
        Json(info).into_response()
    } else if found {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "plugin not found").into_response()
    }
}

async fn delete_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.plugins.remove(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "plugin not found").into_response()
    }
}

/// List all objects in the store
#[utoipa::path(
    get,
    path = "/dashboard/api/objects",
    responses((status = 200, description = "Objects", body = Vec<ObjectResponse>)),
    tag = "objects"
)]
async fn list_objects(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let objects: Vec<ObjectResponse> = state
        .store
        .list_keys()
        .into_iter()
        .map(|k| {
            let parts: Vec<&str> = k.splitn(2, '/').collect();
            let bucket = parts[0];
            let obj_key = parts.get(1).unwrap_or(&"");
            let size = state
                .store
                .get(bucket, obj_key)
                .map(|o| o.data.len())
                .unwrap_or(0);
            ObjectResponse { key: k, size }
        })
        .collect();
    Json(objects)
}

fn component_path() -> PathBuf {
    std::env::var("S4_FILTER_COMPONENT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("..");
            p.push("..");
            p.push("target");
            p.push("components");
            p.push("pii-default.component.wasm");
            p
        })
}

/// Build the engine state from environment variables, injecting the given
/// control plane and key-wrapping backend. This is the shared construction
/// path for both the OSS self-host binary (`NoopControlPlane` +
/// [`crate::key_cipher::default_wrapping`]) and the private SaaS control
/// plane (KMS/Vault-backed wrapping).
pub async fn build_state(
    control: Arc<dyn ControlPlane>,
    wrapping: Arc<dyn KeyWrapping>,
) -> anyhow::Result<Arc<AppState>> {
    let s3_endpoint = std::env::var("S3_ENDPOINT").ok();

    let component_bytes = std::fs::read(component_path())?;
    let pipeline_fuel = std::env::var("S4_WASM_FUEL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(crate::plugin_registry::DEFAULT_PIPELINE_FUEL);
    let engine = s4_wasm_runtime::FilterEngine::with_fuel(&component_bytes, pipeline_fuel)?;
    let plugins = Arc::new(PluginRegistry::with_fuel(pipeline_fuel));

    // Load default filter plugin
    plugins.import("pii-default", &component_bytes)?;

    // Auto-load plugins from S4_PLUGINS_DIR if set
    if let Ok(plugin_dir) = std::env::var("S4_PLUGINS_DIR") {
        let dir = std::path::Path::new(&plugin_dir);
        if dir.exists() {
            plugins.load_from_dir(dir)?;
        }
    }

    let gateway = Gateway::with_registry(engine, plugins.clone());

    // Envelope encryption for API key secrets (needed to verify SigV4).
    // The wrapping backend is injected by the caller so the engine stays
    // policy-free: OSS uses `default_wrapping()`, SaaS injects KMS/Vault.
    let cipher = Arc::new(SecretCipher::new(wrapping));

    let s3_client = match &s3_endpoint {
        Some(endpoint) => {
            let access_key = std::env::var("S3_ACCESS_KEY_ID")
                .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
                .ok();
            let secret_key = std::env::var("S3_SECRET_ACCESS_KEY")
                .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
                .ok();
            let region = std::env::var("S3_REGION")
                .or_else(|_| std::env::var("AWS_REGION"))
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .unwrap_or_else(|_| "us-east-1".to_string());
            match (access_key, secret_key) {
                (Some(ak), Some(sk)) => {
                    let creds = Credentials::new(ak, sk, None, None, "env");
                    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                        .region(Region::new(region))
                        .endpoint_url(endpoint)
                        .credentials_provider(creds)
                        .load()
                        .await;
                    Some(Client::new(&config))
                }
                _ => {
                    warn!(
                        "S3_ENDPOINT is set but S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY are missing; falling back to in-memory storage"
                    );
                    None
                }
            }
        }
        None => None,
    };

    let supabase_url =
        std::env::var("SUPABASE_URL").unwrap_or_else(|_| "http://127.0.0.1:54321".to_string());
    let supabase_jwt_secret = std::env::var("SUPABASE_JWT_SECRET").ok();

    let jwt_decoder = supabase_jwt_secret
        .map(|secret| Arc::new(jsonwebtoken::DecodingKey::from_secret(secret.as_bytes())));

    // Local mode: skip all auth UI and allow unauthenticated S3 access.
    let auth_disabled = std::env::var("AUTH_DISABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let service_backends = std::env::var("S4_SERVICE_BUCKETS")
        .ok()
        .map(|v| parse_service_backends(&v))
        .unwrap_or_default();
    let service_storage = Arc::new(ServiceStorage::new(service_backends));

    // API key persistence: Postgres (Supabase) when DATABASE_URL is set,
    // a JSON file when S4_KEYS_FILE is set, a default JSON file in local
    // mode (AUTH_DISABLED=true), and otherwise the in-memory KeyStore.
    let keys: Arc<dyn KeyRepository> = if let Ok(database_url) = std::env::var("DATABASE_URL") {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        let mut migrator = sqlx::migrate!("../../migrations");
        // The SaaS control plane applies its own migrations (workspaces, usage,
        // billing) to the same database and shares the `_sqlx_migrations` table.
        // Ignore migrations we don't know about so both binaries can coexist.
        migrator.set_ignore_missing(true);
        migrator.run(&pool).await.expect("failed to run migrations");
        info!("Key store: Postgres (migrations applied)");
        Arc::new(PostgresKeyStore::with_cipher(pool, cipher.clone()))
    } else if let Ok(keys_file) = std::env::var("S4_KEYS_FILE") {
        info!("Key store: file ({keys_file})");
        Arc::new(FileKeyStore::with_cipher(
            PathBuf::from(keys_file),
            cipher.clone(),
        ))
    } else if auth_disabled {
        let path = FileKeyStore::default_path();
        info!("Key store: file ({}) (local mode)", path.display());
        Arc::new(FileKeyStore::with_cipher(path, cipher))
    } else {
        info!("Key store: in-memory (set DATABASE_URL or S4_KEYS_FILE for persistence)");
        Arc::new(KeyStore::with_cipher(cipher))
    };

    // Local mode: ensure a demo key exists and print it so SDK demos and
    // `aws s3 --endpoint-url` work out of the box.
    if auth_disabled {
        let existing = keys.list_for_user("demo-user").await;
        if existing.is_empty() {
            let (key_id, secret) = keys
                .create_key("demo-user", "local-default", 0, None)
                .await?;
            println!("S4_ACCESS_KEY={key_id}");
            println!("S4_SECRET_KEY={secret}");
        } else if let Some(k) = existing.into_iter().find(|k| k.label == "local-default")
            && let Some(secret) = keys.decrypt_secret(&k.key_id).await
        {
            println!("S4_ACCESS_KEY={}", k.key_id);
            println!("S4_SECRET_KEY={secret}");
        }
    }

    Ok(Arc::new(AppState {
        gateway: Arc::new(gateway),
        store: Arc::new(MemoryStore::new()),
        keys,
        backends: Arc::new(BackendRegistry::new()),
        plugins,
        service_storage,
        s3_client,
        supabase_url,
        jwt_decoder,
        auth_disabled,
        control,
        legacy_max_object_bytes: legacy_max_object_bytes(),
    }))
}

/// Build the axum router for the engine. The SaaS crate merges its own
/// control-plane routes (workspaces, billing, dashboard) onto this.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/", get(root))
        .route("/dashboard/api/keys", get(get_keys))
        .route("/dashboard/api/keys", post(create_key))
        .route("/dashboard/api/keys", delete(delete_key))
        .route("/dashboard/api/keys/public-key", put(set_public_key))
        .route("/dashboard/api/mcp-tokens", get(get_mcp_tokens))
        .route("/dashboard/api/mcp-tokens", post(create_mcp_token))
        .route("/dashboard/api/mcp-tokens", delete(delete_mcp_token))
        .route("/dashboard/api/me", get(get_me))
        .route("/dashboard/api/demo/redact", post(demo_redact))
        .route("/dashboard/api/demo/store", post(demo_store))
        .route("/dashboard/api/demo/read", get(demo_read))
        .route("/dashboard/api/backend", get(get_backend))
        .route("/dashboard/api/backend", put(put_backend))
        .route("/dashboard/api/plugins", get(get_plugins))
        .route("/dashboard/api/plugins", post(create_plugin))
        .route("/dashboard/api/plugins/reorder", put(reorder_plugins))
        .route("/dashboard/api/plugins/{id}", put(update_plugin))
        .route("/dashboard/api/plugins/{id}", delete(delete_plugin))
        .route("/dashboard/api/objects", get(list_objects))
        .route("/{bucket}", get(s3_list_objects))
        .route("/{bucket}", put(s3_bucket_put))
        .route("/{bucket}", delete(s3_bucket_delete))
        .route("/{bucket}/{*key}", put(s3_put))
        .route("/{bucket}/{*key}", get(s3_get))
        .route("/{bucket}/{*key}", head(s3_head))
        .route("/{bucket}/{*key}", delete(s3_delete))
        .route("/{bucket}/{*key}", post(s3_post))
        .layer(CorsLayer::permissive())
        .with_state(state)
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
}

#[cfg(test)]
mod auth_tests {
    use super::supabase_jwt_validation;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, decode, encode};

    #[test]
    fn accepts_supabase_authenticated_audience() {
        let secret = b"test-secret";
        let issuer = "https://example.supabase.co/auth/v1";
        let claims = serde_json::json!({
            "sub": "user-123",
            "iss": issuer,
            "aud": "authenticated",
            "exp": u64::MAX,
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("encode token");
        let validation = supabase_jwt_validation(Algorithm::HS256, issuer);

        let decoded =
            decode::<serde_json::Value>(&token, &DecodingKey::from_secret(secret), &validation)
                .expect("valid Supabase token");

        assert_eq!(decoded.claims["sub"], "user-123");
    }
}
