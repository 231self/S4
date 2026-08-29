//! S3 front door integration tests: filter roundtrip, listing, bucket
//! rejection, multipart, and SigV4 verification.
//!
//! These build the real gateway state (in-memory keystore + MemoryStore) via
//! `build_state`, so the Wasm filter component must exist first
//! (`just build-filters`).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bytes::Bytes;
use http_body::{Frame, SizeHint};
use s4_gateway::backend::{PresignedHttpPolicy, TokioAddressResolver};
use s4_gateway::control::{
    AuthenticatedRequestContext, ControlPlane, NoopControlPlane, RequestKind, StreamingWriteMode,
};
use s4_gateway::key_cipher::default_wrapping;
use s4_gateway::object::BodyLimits;
use s4_gateway::server::{AppState, StreamingReadMode, build_router, build_state};
use s4_gateway::sigv4::SigV4Policy;
use s4_gateway::store::{
    FileKeyStore, KeyRepository, MAX_CREDENTIAL_LABEL_BYTES, MAX_CREDENTIAL_TTL_SECONDS,
    MAX_PUBLIC_KEY_PEM_BYTES,
};
use s4_gateway::transaction::SpoolQuota;
use s4_gateway::workspace_storage::InMemoryWorkspaceStorageRepository;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use tower::ServiceExt;

const TEST_PUBLIC_KEY_PEM: &str = include_str!("../../../tests/fixtures/pii/crypto/pub.pem");
const TEST_CERTIFICATE_PEM: &str = include_str!("../../../tests/fixtures/pii/crypto/cert.pem");

struct PollTrackingBody {
    polls: Arc<AtomicUsize>,
    data: Option<Bytes>,
}

struct FrameSequenceBody {
    frames: VecDeque<Result<Frame<Bytes>, std::io::Error>>,
}

impl FrameSequenceBody {
    fn data(frames: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            frames: frames
                .into_iter()
                .map(|frame| Ok(Frame::data(frame)))
                .collect(),
        }
    }
}

impl http_body::Body for FrameSequenceBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }
}

#[derive(Debug)]
struct StreamingOffControl;

#[async_trait::async_trait]
impl ControlPlane for StreamingOffControl {
    async fn authorize(
        &self,
        _context: &AuthenticatedRequestContext,
        _kind: RequestKind,
    ) -> Option<s4_gateway::control::BlockReason> {
        None
    }

    async fn record(
        &self,
        _context: &AuthenticatedRequestContext,
        _bucket: &str,
        _kind: RequestKind,
        _bytes: u64,
    ) {
    }

    async fn streaming_write_mode(
        &self,
        _context: &AuthenticatedRequestContext,
    ) -> Option<StreamingWriteMode> {
        Some(StreamingWriteMode::Off)
    }
}

impl http_body::Body for PollTrackingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map_or(0, Bytes::len) as u64)
    }
}

async fn test_state() -> Arc<AppState> {
    // SAFETY: test-only env mutation; every test in this file sets the same
    // values so concurrent runs stay deterministic.
    unsafe {
        std::env::set_var("AUTH_DISABLED", "0");
        std::env::set_var("S4_SINGLE_TENANT", "1");
        std::env::set_var("S4_WORKSPACE_ENDPOINT_PRIVATE_ALLOWLIST", "127.0.0.1");
        std::env::remove_var("S4_WORKSPACE_ENDPOINT_ALLOWLIST");
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("S4_KEYS_FILE");
        std::env::remove_var("S3_ENDPOINT");
        std::env::remove_var("S4_SECRET_KEK");
        std::env::remove_var("S4_SERVICE_BUCKETS");
        std::env::remove_var("S4_LEGACY_MAX_OBJECT_BYTES");
        std::env::remove_var("S4_STREAMING_READ_MODE");
        std::env::remove_var("S4_STREAMING_WRITE_MODE");
        std::env::remove_var("S4_TRANSFORMED_READ_SPOOL");
        std::env::remove_var("S4_PREFIX_SAFE_COMPONENT_HASHES");
        std::env::remove_var("S4_SPOOL_DIR");
        std::env::remove_var("S4_SPOOL_MAX_OBJECT_BYTES");
        std::env::remove_var("S4_SPOOL_QUOTA_BYTES");
        std::env::remove_var("S4_STREAMING_S3_PROVIDER");
        std::env::remove_var("S4_MANAGED_STREAMING_MODE");
        std::env::remove_var("S4_MANAGED_STREAMING_TRANSACTIONAL");
        std::env::remove_var("S4_MANAGED_PLACEMENT_VERSION");
        std::env::remove_var("S4_DEV_MEMORY_STREAMING");
        std::env::remove_var("S4_MULTIPART_MODE");
        // Phase 12 removed the legacy buffered PUT/GET path entirely; the
        // streaming in-memory dev backend is the only write/read path left.
        std::env::set_var("S4_STREAMING_WRITE_MODE", "single");
        std::env::set_var("S4_STREAMING_READ_MODE", "passthrough");
        std::env::set_var("S4_DEV_MEMORY_STREAMING", "1");
        // Load the built filter components so the full pipeline (including
        // stable-encrypt) is available for joinable-read tests.
        let components =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/components");
        std::env::set_var("S4_PLUGINS_DIR", components);
    }
    build_state(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
    )
    .await
    .expect("build_state")
}

async fn router() -> (Router, Arc<AppState>) {
    let state = test_state().await;
    (build_router(state.clone()), state)
}

#[tokio::test]
async fn backend_api_requires_real_auth_rejects_unsupported_config_and_never_returns_secrets() {
    let mut state = test_state().await;
    let secret = b"dashboard-test-secret";
    let issuer = "https://example.supabase.co/auth/v1";
    let claims = serde_json::json!({
        "sub": "dashboard-user",
        "iss": issuer,
        "aud": "authenticated",
        "exp": u64::MAX,
    });
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .unwrap();
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.supabase_url = "https://example.supabase.co".to_string();
    state_mut.jwt_decoder = Some(Arc::new(jsonwebtoken::DecodingKey::from_secret(secret)));
    let app = build_router(state);

    let unauthenticated = Request::builder()
        .method("PUT")
        .uri("/dashboard/api/backend")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"backend_type":"s3_compatible","endpoint":"http://127.0.0.1:9000","access_key":"access","secret_key":"secret","region":"us-east-1"}"#,
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(unauthenticated).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let unsupported = Request::builder()
        .method("PUT")
        .uri("/dashboard/api/backend")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"backend_type":"aws_role","role_arn":"arn:aws:iam::123456789012:role/s4"}"#,
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(unsupported).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let configured = Request::builder()
        .method("PUT")
        .uri("/dashboard/api/backend")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"backend_type":"s3_compatible","endpoint":"http://127.0.0.1:9000","access_key":"access","secret_key":"secret","region":"us-east-1"}"#,
        ))
        .unwrap();
    let response = app.clone().oneshot(configured).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response_json["configured"], true);
    assert!(response_json.get("access_key").is_none());
    assert!(response_json.get("secret_key").is_none());

    let get = Request::builder()
        .uri("/dashboard/api/backend")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_json["endpoint"], "http://127.0.0.1:9000");
    assert_eq!(response_json["access_key_configured"], true);
    assert_eq!(response_json["secret_key_configured"], true);
    assert!(!String::from_utf8_lossy(&body).contains("\"access_key\":"));
    assert!(!String::from_utf8_lossy(&body).contains("\"secret_key\":"));

    let managed = Request::builder()
        .method("PUT")
        .uri("/dashboard/api/backend")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"backend_type":"managed"}"#))
        .unwrap();
    let response = app.oneshot(managed).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        response_json,
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
}

#[tokio::test]
async fn create_key_persistence_failure_returns_internal_error_without_secret() {
    let mut state = test_state().await;
    let blocking_parent =
        std::env::temp_dir().join(format!("s4-create-key-failure-{}", uuid::Uuid::new_v4()));
    std::fs::write(&blocking_parent, "not a directory").unwrap();
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.keys = Arc::new(FileKeyStore::new(blocking_parent.join("keys.json")));
    state_mut.auth_disabled = true;
    let app = build_router(state);

    let request = Request::builder()
        .method("POST")
        .uri("/dashboard/api/keys")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"label":"failure-test"}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), br#"{"error":"internal_error"}"#);
    assert!(!String::from_utf8_lossy(&body).contains("s4s_"));
    std::fs::remove_file(blocking_parent).unwrap();
}

#[tokio::test]
async fn public_key_persistence_failure_returns_generic_500_and_rolls_back() {
    let mut state = test_state().await;
    let parent =
        std::env::temp_dir().join(format!("s4-public-key-handler-{}", uuid::Uuid::new_v4()));
    let durable_parent = parent.with_extension("durable");
    std::fs::create_dir_all(&parent).unwrap();
    let path = parent.join("keys.json");
    let file_store = Arc::new(FileKeyStore::new(path.clone()));
    let (key_id, secret_key) = file_store
        .create_key("test-user", "persist-failure", 0, None)
        .await
        .unwrap();
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .keys = file_store.clone();
    let app = build_router(state);
    std::fs::rename(&parent, &durable_parent).unwrap();
    std::fs::write(&parent, "not a directory").unwrap();

    let request = add_headers(
        public_key_request(&key_id, TEST_PUBLIC_KEY_PEM),
        &auth_headers(&key_id, &secret_key),
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.is_empty(), "persistence failure body must be generic");
    assert!(!String::from_utf8_lossy(&body).contains("BEGIN PUBLIC KEY"));
    assert!(!String::from_utf8_lossy(&body).contains(&secret_key));
    assert!(
        file_store
            .get_key(&key_id)
            .await
            .unwrap()
            .public_key_pem
            .is_none(),
        "failed persistence must roll back the in-memory value"
    );
    std::fs::remove_file(&parent).unwrap();
    std::fs::rename(&durable_parent, &parent).unwrap();
    drop(file_store);

    let restarted = FileKeyStore::new(path);
    assert!(
        restarted
            .get_key(&key_id)
            .await
            .unwrap()
            .public_key_pem
            .is_none(),
        "failed persistence must not appear after restart"
    );
    std::fs::remove_dir_all(parent).unwrap();
}

async fn make_key(state: &Arc<AppState>) -> (String, String) {
    make_key_for(state, "test-user").await
}

async fn make_key_for(state: &Arc<AppState>, user_id: &str) -> (String, String) {
    state
        .keys
        .create_key(user_id, "sigv4-test", 0, None)
        .await
        .expect("create test API key")
}

fn configure_dashboard_jwt(state: &mut Arc<AppState>, user_id: &str) -> String {
    let secret = b"public-key-dashboard-secret";
    let issuer = "https://example.supabase.co/auth/v1";
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({
            "sub": user_id,
            "iss": issuer,
            "aud": "authenticated",
            "exp": u64::MAX,
        }),
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .unwrap();
    let state_mut = Arc::get_mut(state).expect("test state is uniquely owned");
    state_mut.supabase_url = "https://example.supabase.co".to_string();
    state_mut.jwt_decoder = Some(Arc::new(jsonwebtoken::DecodingKey::from_secret(secret)));
    token
}

fn public_key_request(key_id: &str, public_key_pem: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri("/dashboard/api/keys/public-key")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "key_id": key_id,
                "public_key_pem": public_key_pem,
            })
            .to_string(),
        ))
        .unwrap()
}

fn test_filter_component() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-components/test-filter.component.wasm");
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{}: run `just build-filters` first: {error}",
            path.display()
        )
    })
}

async fn unsafe_transformed_test_state(later_filter: bool) -> Arc<AppState> {
    let mut state = test_state().await;
    let spool_dir =
        std::env::temp_dir().join(format!("s4-read-spool-failure-{}", uuid::Uuid::now_v7()));
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state_mut.spool_config.directory = spool_dir;
    state_mut.spool_config.max_object_bytes = 1024;
    state_mut.spool_quota = Arc::new(SpoolQuota::new(2048));
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    if later_filter {
        state
            .plugins
            .import(
                "test-noop-before-reject",
                &read_component("noop.component.wasm"),
            )
            .unwrap();
    }
    state
        .plugins
        .import("test-failure", &test_filter_component())
        .unwrap();
    state
}

fn read_component(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/components")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{}: run `just build-filters` first: {error}",
            path.display()
        )
    })
}

fn auth_headers(ak: &str, sk: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-s4-access-key", ak.to_string()),
        ("x-s4-secret-key", sk.to_string()),
    ]
}

fn add_headers(req: Request<Body>, hdrs: &[(&'static str, String)]) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    for (k, v) in hdrs {
        parts.headers.insert(*k, v.parse().unwrap());
    }
    Request::from_parts(parts, body)
}

fn append_headers(req: Request<Body>, hdrs: &[(&'static str, String)]) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    for (name, value) in hdrs {
        parts.headers.append(*name, value.parse().unwrap());
    }
    Request::from_parts(parts, body)
}

fn assert_hardened_object_headers(headers: &axum::http::HeaderMap) {
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-store");
    assert!(!headers.contains_key(header::AGE));
    assert!(!headers.contains_key(header::EXPIRES));
    assert_eq!(headers[header::CONTENT_DISPOSITION], "attachment");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(
        headers["content-security-policy"],
        "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'"
    );
}

fn assert_s3_error_has_only_expected_xml_elements(document: &str) {
    let elements: Vec<_> = xmlparser::Tokenizer::from(document)
        .map(|token| token.expect("generated error must be well-formed XML"))
        .filter_map(|token| match token {
            xmlparser::Token::ElementStart { local, .. } => Some(local.as_str().to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(elements, ["Error", "Code", "Message", "Key", "RequestId"]);
}

#[tokio::test]
async fn public_key_mutation_rejects_unauthenticated_requests_in_production_and_local_mode() {
    for auth_disabled in [false, true] {
        let mut state = test_state().await;
        let (key_id, _) = make_key(&state).await;
        Arc::get_mut(&mut state)
            .expect("test state is uniquely owned")
            .auth_disabled = auth_disabled;
        let app = build_router(state.clone());

        let response = app
            .oneshot(public_key_request(&key_id, "rejected-pem"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .public_key_pem
                .is_none(),
            "rejected request must not mutate the key"
        );
    }
}

#[tokio::test]
async fn public_key_mutation_rejects_incomplete_or_invalid_api_key_credentials() {
    let state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());
    let requests = [
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("x-s4-access-key", key_id.clone())],
        ),
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("x-s4-secret-key", secret_key.clone())],
        ),
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &auth_headers(&key_id, "wrong-secret"),
        ),
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("authorization", format!("Bearer {key_id}:wrong-secret"))],
        ),
    ];

    for request in requests {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .public_key_pem
                .is_none(),
            "rejected credentials must not mutate the key"
        );
    }
}

#[tokio::test]
async fn public_key_mutation_rejects_duplicate_security_headers_without_mutation() {
    let state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    let mcp_token = state
        .keys
        .create_mcp_token("test-user", "duplicate-test", 0)
        .await
        .unwrap()
        .0;
    let app = build_router(state.clone());
    let bearer = format!("Bearer {key_id}:{secret_key}");
    let requests = [
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("authorization", bearer.clone()),
                ("authorization", bearer.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-s4-access-key", key_id.clone()),
                ("x-s4-access-key", key_id.clone()),
                ("x-s4-secret-key", secret_key.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-s4-access-key", key_id.clone()),
                ("x-s4-secret-key", secret_key.clone()),
                ("x-s4-secret-key", secret_key.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-s4-mcp-token", mcp_token.clone()),
                ("x-s4-mcp-token", mcp_token.clone()),
            ],
        ),
    ];

    for request in requests {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .public_key_pem
                .is_none(),
            "duplicate credential headers must not mutate the key"
        );
    }
}

#[tokio::test]
async fn public_key_mutation_rejects_mixed_credential_classes_without_mutation() {
    let mut state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    let mcp_token = state
        .keys
        .create_mcp_token("test-user", "mixed-test", 0)
        .await
        .unwrap()
        .0;
    let jwt = configure_dashboard_jwt(&mut state, "test-user");
    let app = build_router(state.clone());
    let api_bearer = format!("Bearer {key_id}:{secret_key}");
    let requests = [
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-s4-access-key", key_id.clone()),
                ("x-s4-secret-key", secret_key.clone()),
                ("authorization", api_bearer.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-s4-access-key", key_id.clone()),
                ("x-s4-secret-key", secret_key.clone()),
                ("authorization", format!("Bearer {jwt}")),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-s4-mcp-token", mcp_token.clone()),
                ("x-s4-access-key", key_id.clone()),
                ("x-s4-secret-key", secret_key.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-s4-mcp-token", mcp_token.clone()),
                ("authorization", format!("Bearer {jwt}")),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("x-s4-mcp-token", mcp_token), ("authorization", api_bearer)],
        ),
    ];

    for request in requests {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .public_key_pem
                .is_none(),
            "mixed credential classes must not mutate the key"
        );
    }
}

#[tokio::test]
async fn public_key_mutation_accepts_own_key_via_headers_and_bearer() {
    let state = test_state().await;
    let (header_key, header_secret) = make_key(&state).await;
    let (bearer_key, bearer_secret) = make_key(&state).await;
    let app = build_router(state.clone());

    let header_request = add_headers(
        public_key_request(&header_key, TEST_PUBLIC_KEY_PEM),
        &auth_headers(&header_key, &header_secret),
    );
    assert_eq!(
        app.clone().oneshot(header_request).await.unwrap().status(),
        StatusCode::OK
    );

    let bearer_request = add_headers(
        public_key_request(&bearer_key, TEST_CERTIFICATE_PEM),
        &[(
            "authorization",
            format!("Bearer {bearer_key}:{bearer_secret}"),
        )],
    );
    assert_eq!(
        app.oneshot(bearer_request).await.unwrap().status(),
        StatusCode::OK
    );

    assert_eq!(
        state
            .keys
            .get_key(&header_key)
            .await
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_PEM.trim())
    );
    assert_eq!(
        state
            .keys
            .get_key(&bearer_key)
            .await
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_CERTIFICATE_PEM.trim())
    );
}

#[tokio::test]
async fn local_public_key_mutation_accepts_real_target_credentials() {
    let mut state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .auth_disabled = true;
    let app = build_router(state.clone());
    let request = add_headers(
        public_key_request(&key_id, TEST_PUBLIC_KEY_PEM),
        &auth_headers(&key_id, &secret_key),
    );

    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        state
            .keys
            .get_key(&key_id)
            .await
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_PEM.trim())
    );
}

#[tokio::test]
async fn public_key_mutation_rejects_invalid_pem_before_persistence() {
    let state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());

    for public_key_pem in [
        "not an RSA public key".to_string(),
        "x".repeat(MAX_PUBLIC_KEY_PEM_BYTES + 1),
    ] {
        let request = add_headers(
            public_key_request(&key_id, &public_key_pem),
            &auth_headers(&key_id, &secret_key),
        );
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(
        state
            .keys
            .get_key(&key_id)
            .await
            .unwrap()
            .public_key_pem
            .is_none()
    );
}

#[tokio::test]
async fn api_key_public_key_mutation_hides_and_rejects_sibling_and_foreign_keys() {
    let state = test_state().await;
    let (credential_key, credential_secret) = make_key_for(&state, "owner-a").await;
    let (sibling_key, _) = make_key_for(&state, "owner-a").await;
    let (foreign_key, _) = make_key_for(&state, "owner-b").await;
    let app = build_router(state.clone());
    let mut rejection_bodies = Vec::new();

    for target in [&sibling_key, &foreign_key] {
        let request = add_headers(
            public_key_request(target, "rejected-pem"),
            &auth_headers(&credential_key, &credential_secret),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        rejection_bodies.push(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        );
    }
    assert_eq!(rejection_bodies[0], rejection_bodies[1]);
    assert_eq!(rejection_bodies[0].as_ref(), b"key not found");
    for key_id in [&credential_key, &sibling_key, &foreign_key] {
        assert!(
            state
                .keys
                .get_key(key_id)
                .await
                .unwrap()
                .public_key_pem
                .is_none(),
            "rejected cross-key request must not mutate any key"
        );
    }
}

#[tokio::test]
async fn jwt_public_key_mutation_is_scoped_to_dashboard_user_ownership() {
    let mut state = test_state().await;
    let (owned_key, _) = make_key_for(&state, "dashboard-user").await;
    let (second_owned_key, _) = make_key_for(&state, "dashboard-user").await;
    let (foreign_key, _) = make_key_for(&state, "another-user").await;
    let token = configure_dashboard_jwt(&mut state, "dashboard-user");
    let app = build_router(state.clone());

    for (key_id, pem) in [
        (&owned_key, TEST_PUBLIC_KEY_PEM),
        (&second_owned_key, TEST_CERTIFICATE_PEM),
    ] {
        let request = add_headers(
            public_key_request(key_id, pem),
            &[("authorization", format!("Bearer {token}"))],
        );
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }

    let foreign_request = add_headers(
        public_key_request(&foreign_key, TEST_PUBLIC_KEY_PEM),
        &[("authorization", format!("Bearer {token}"))],
    );
    assert_eq!(
        app.oneshot(foreign_request).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        state
            .keys
            .get_key(&owned_key)
            .await
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_PEM.trim())
    );
    assert_eq!(
        state
            .keys
            .get_key(&second_owned_key)
            .await
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_CERTIFICATE_PEM.trim())
    );
    assert!(
        state
            .keys
            .get_key(&foreign_key)
            .await
            .unwrap()
            .public_key_pem
            .is_none(),
        "wrong-owner JWT must not mutate the target"
    );
}

#[tokio::test]
async fn mcp_tokens_cannot_mutate_public_keys() {
    let state = test_state().await;
    let (key_id, _) = make_key_for(&state, "mcp-user").await;
    let token = state
        .keys
        .create_mcp_token("mcp-user", "mutation-test", 0)
        .await
        .unwrap()
        .0;
    let app = build_router(state.clone());
    let requests = [
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("authorization", format!("Bearer {token}"))],
        ),
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("x-s4-mcp-token", token)],
        ),
    ];

    for request in requests {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .public_key_pem
                .is_none(),
            "MCP rejection must leave the target unchanged"
        );
    }
}

#[tokio::test]
async fn create_key_still_accepts_an_initial_public_key() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .auth_disabled = true;
    let app = build_router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/dashboard/api/keys")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "label": "created-with-public-key",
                "public_key_pem": TEST_CERTIFICATE_PEM,
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let key_id = body["key_id"].as_str().unwrap();
    assert_eq!(body["public_key_pem"], TEST_CERTIFICATE_PEM.trim());
    assert_eq!(
        state
            .keys
            .get_key(key_id)
            .await
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_CERTIFICATE_PEM.trim())
    );
}

#[tokio::test]
async fn credential_mutation_endpoints_enforce_input_and_body_boundaries() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .auth_disabled = true;
    let app = build_router(state);

    for (label, expected) in [
        ("a".repeat(MAX_CREDENTIAL_LABEL_BYTES), StatusCode::OK),
        (
            "a".repeat(MAX_CREDENTIAL_LABEL_BYTES + 1),
            StatusCode::BAD_REQUEST,
        ),
        ("control\nlabel".to_string(), StatusCode::BAD_REQUEST),
        ("   ".to_string(), StatusCode::BAD_REQUEST),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/dashboard/api/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "label": label }).to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }

    for (expires_in, expected) in [
        (MAX_CREDENTIAL_TTL_SECONDS, StatusCode::OK),
        (MAX_CREDENTIAL_TTL_SECONDS + 1, StatusCode::BAD_REQUEST),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/dashboard/api/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "label": "ttl", "expires_in": expires_in }).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(body["expires_at"].as_str().is_some());
        }
    }

    for public_key_pem in [
        "not a PEM".to_string(),
        "x".repeat(MAX_PUBLIC_KEY_PEM_BYTES + 1),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/dashboard/api/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "label": "invalid pem",
                    "public_key_pem": public_key_pem,
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    for (expires_in, expected) in [
        (MAX_CREDENTIAL_TTL_SECONDS, StatusCode::OK),
        (MAX_CREDENTIAL_TTL_SECONDS + 1, StatusCode::BAD_REQUEST),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/dashboard/api/mcp-tokens")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "label": "agent", "expires_in": expires_in }).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(body["expires_at"].as_str().is_some());
        }
    }

    for (method, uri, body) in [
        ("POST", "/dashboard/api/keys", "x".repeat(20 * 1024)),
        (
            "PUT",
            "/dashboard/api/keys/public-key",
            "x".repeat(20 * 1024),
        ),
        ("DELETE", "/dashboard/api/keys", "x".repeat(2048)),
        ("POST", "/dashboard/api/mcp-tokens", "x".repeat(2048)),
        ("DELETE", "/dashboard/api/mcp-tokens", "x".repeat(2048)),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}

#[tokio::test]
async fn global_admin_routes_only_mount_in_local_auth_disabled_mode() {
    let state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let headers = auth_headers(&access_key, &secret_key);
    let app = build_router(state.clone());
    let plugin_count = state.plugins.list().len();

    let import = add_headers(
        Request::builder()
            .method("POST")
            .uri("/dashboard/api/plugins")
            .header(header::CONTENT_TYPE, "application/wasm")
            .body(Body::from("not a wasm component"))
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(import).await.unwrap().status(),
        StatusCode::NOT_IMPLEMENTED
    );
    assert_eq!(state.plugins.list().len(), plugin_count);

    let objects = add_headers(
        Request::builder()
            .uri("/dashboard/api/objects")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.oneshot(objects).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    let mut local_state = test_state().await;
    Arc::get_mut(&mut local_state)
        .expect("test state is uniquely owned")
        .auth_disabled = true;
    let local_app = build_router(local_state);
    let response = local_app
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/plugins")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn put_get_roundtrip_filters_pii() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/demo/notes.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("contact a@b.com now"))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "PUT should succeed");

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/demo/notes.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("[REDACTED_EMAIL]"), "email redacted: {text}");
    assert!(
        !text.contains("a@b.com"),
        "raw email must not be stored: {text}"
    );
}

#[tokio::test]
async fn streaming_put_is_frame_invariant_and_preserves_separators() {
    let input = b"contact a@b.com now\r\nsecond line\n";
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.auth_disabled = true;
    state_mut.dev_memory_streaming_enabled = true;
    state_mut.streaming_write_mode = StreamingWriteMode::Single;
    state_mut.source_body_limits.max_frame_bytes = input.len().max(1);
    let app = build_router(state.clone());
    for split in 0..=input.len() {
        let key = format!("split-{split}.txt");
        let body = Body::new(FrameSequenceBody::data([
            Bytes::copy_from_slice(&input[..split]),
            Bytes::copy_from_slice(&input[split..]),
        ]));
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/stream/{key}"))
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "split {split}");
        let stored = state.store.get("stream", &key).expect("committed object");
        assert_eq!(
            stored.data,
            Bytes::from_static(b"contact [REDACTED_EMAIL] now\r\nsecond line\n"),
            "split {split}"
        );
    }
}

#[tokio::test]
async fn streaming_put_limit_failure_has_no_partial_visibility() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.auth_disabled = true;
    state_mut.dev_memory_streaming_enabled = true;
    state_mut.streaming_write_mode = StreamingWriteMode::Single;
    state_mut.source_body_limits.max_frame_bytes = 4;
    state_mut.source_body_limits.max_bytes = 7;
    let app = build_router(state.clone());
    let request = Request::builder()
        .method("PUT")
        .uri("/stream/too-large.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::new(FrameSequenceBody::data([
            Bytes::from_static(b"1234"),
            Bytes::from_static(b"5678"),
        ])))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&response_body).contains("<Code>EntityTooLarge</Code>"));
    assert!(state.store.get("stream", "too-large.txt").is_none());
}

#[tokio::test]
async fn tenant_mode_can_only_lower_the_deployment_ceiling() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.auth_disabled = true;
    state_mut.streaming_write_mode = StreamingWriteMode::All;
    state_mut.control = Arc::new(StreamingOffControl);
    let app = build_router(state.clone());
    let request = Request::builder()
        .method("PUT")
        .uri("/stream/tenant-off.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("12345"))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    // Phase 12: a write-mode below `single` rejects outright; there is no
    // legacy buffered fallback to run a size cap against.
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>NotImplemented</Code>"));
    assert!(state.store.get("stream", "tenant-off.txt").is_none());
}

#[tokio::test]
async fn streaming_off_rejects_put_without_polling_and_get_without_buffering() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_write_mode = StreamingWriteMode::Off;
    state_mut.streaming_read_mode = StreamingReadMode::Off;
    state_mut.dev_memory_streaming_enabled = true;
    let app = build_router(state.clone());

    // Write mode off: PUT rejects without polling the request body.
    let polls = Arc::new(AtomicUsize::new(0));
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/off/object.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not be read")),
            }))
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );
    let response = app.clone().oneshot(put).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "write-mode-off PUT must not poll the body"
    );
    assert!(state.store.get("off", "object.txt").is_none());

    // Read mode off: GET rejects without buffering or disclosing the object.
    state.store.put(
        "off",
        "object.txt",
        Bytes::from_static(b"payload"),
        "text/plain",
    );
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/off/object.txt")
            .body(Body::empty())
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );
    let response = app.oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&body).contains("payload"),
        "read-mode-off GET must not buffer the object body"
    );
}

#[tokio::test]
async fn unsupported_streaming_backend_is_rejected_without_polling_body() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_write_mode = StreamingWriteMode::Single;
    state_mut.dev_memory_streaming_enabled = false;
    let app = build_router(state);
    let polls = Arc::new(AtomicUsize::new(0));
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/stream/unsupported.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not be read")),
            }))
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn put_with_unsupported_content_encoding_is_rejected_without_polling_body() {
    let state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());

    for encoding in ["gzip", "aws-chunked,gzip", "br"] {
        let polls = Arc::new(AtomicUsize::new(0));
        let request = add_headers(
            Request::builder()
                .method("PUT")
                .uri("/enc/object.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .header(header::CONTENT_ENCODING, encoding)
                .body(Body::new(PollTrackingBody {
                    polls: polls.clone(),
                    data: Some(Bytes::from_static(b"compressed bytes must not be read")),
                }))
                .unwrap(),
            &auth_headers(&access_key, &secret_key),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Content-Encoding {encoding} must be rejected"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "Content-Encoding {encoding} PUT must not buffer the body"
        );
    }
    assert!(state.store.get("enc", "object.txt").is_none());
}

#[tokio::test]
#[ignore = "soak: run via `just soak-streaming` or the weekly workflow"]
async fn soak_streaming_roundtrip_holds_under_repetition() {
    let iterations = std::env::var("S4_SOAK_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200);
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    let headers = auth_headers(&access_key, &secret_key);

    for i in 0..iterations {
        let key = format!("roundtrip-{i}.txt");
        let body = format!("contact person-{i}@example.com card 4111111111111111");

        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("/soak/{key}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(body))
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(put).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "soak PUT {i}");

        let get = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/soak/{key}"))
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(get).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "soak GET {i}");
        let stored = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&stored);
        assert!(
            text.contains("REDACTED_EMAIL"),
            "soak GET {i} redacted: {text}"
        );
        assert!(
            !text.contains("@example.com"),
            "soak GET {i} leaked PII: {text}"
        );
    }
}

#[tokio::test]
async fn list_objects_returns_keys_and_prefixes() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    for key in ["logs/a.txt", "logs/b.txt", "meta.json"] {
        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("/bkt/{key}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("data"))
                .unwrap(),
            &hdrs,
        );
        assert_eq!(
            app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::OK
        );
    }

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bkt?list-type=2")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(list).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_hardened_object_headers(resp.headers());
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Key>logs/a.txt</Key>"), "missing key: {xml}");
    assert!(xml.contains("<Key>logs/b.txt</Key>"), "missing key: {xml}");
    assert!(xml.contains("<Key>meta.json</Key>"), "missing key: {xml}");
    assert!(xml.contains("<KeyCount>3</KeyCount>"), "bad count: {xml}");

    // Prefix listing with delimiter groups logs/ into a CommonPrefix.
    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bkt?list-type=2&prefix=&delimiter=%2F")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(list).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(
        xml.contains("<CommonPrefixes><Prefix>logs/</Prefix></CommonPrefixes>"),
        "no common prefix: {xml}"
    );
    assert!(
        xml.contains("<Key>meta.json</Key>"),
        "top-level key missing: {xml}"
    );
    assert!(
        !xml.contains("logs/a.txt"),
        "folder keys should be grouped: {xml}"
    );
}

#[tokio::test]
async fn memory_list_continuations_are_opaque_bound_and_tamper_resistant() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    for key in ["a.txt", "b.txt"] {
        state
            .store
            .put("page", key, Bytes::from_static(b"x"), "text/plain");
    }
    let page = add_headers(
        Request::builder()
            .method("GET")
            .uri("/page?list-type=2&max-keys=1")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(page).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let xml = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let token = xml
        .split("<NextContinuationToken>")
        .nth(1)
        .and_then(|value| value.split("</NextContinuationToken>").next())
        .expect("truncated listing has next token");
    assert!(!token.contains("a.txt"));

    let next = add_headers(
        Request::builder()
            .method("GET")
            .uri(format!(
                "/page?list-type=2&max-keys=1&continuation-token={token}"
            ))
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(next).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Key>b.txt</Key>"));

    let bad = add_headers(
        Request::builder()
            .method("GET")
            .uri("/page?list-type=2&continuation-token=not-a-token")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(bad).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let zero_page = add_headers(
        Request::builder()
            .method("GET")
            .uri("/page?list-type=2&max-keys=0")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(zero_page).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<IsTruncated>false</IsTruncated>"));

    for key in ["logs/one/a.txt", "logs/two/a.txt"] {
        state
            .store
            .put("page", key, Bytes::from_static(b"x"), "text/plain");
    }
    let delimiter_page = add_headers(
        Request::builder()
            .method("GET")
            .uri("/page?list-type=2&prefix=logs%2F&delimiter=%2F&max-keys=1")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(delimiter_page).await.unwrap();
    let xml = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(xml.contains("<Prefix>logs/one/</Prefix>"));
    let token = xml
        .split("<NextContinuationToken>")
        .nth(1)
        .and_then(|value| value.split("</NextContinuationToken>").next())
        .expect("delimiter page has a next token");
    let next_delimiter_page = add_headers(
        Request::builder()
            .method("GET")
            .uri(format!(
                "/page?list-type=2&prefix=logs%2F&delimiter=%2F&max-keys=1&continuation-token={token}"
            ))
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.oneshot(next_delimiter_page).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Prefix>logs/two/</Prefix>"));
    assert!(!xml.contains("<Prefix>logs/one/</Prefix>"));
}

#[tokio::test]
async fn list_buckets_at_root() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/mybkt/obj")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x"))
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::OK
    );

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(list).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Name>mybkt</Name>"), "bucket missing: {xml}");
}

#[tokio::test]
async fn create_bucket_is_rejected() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let mb = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/new-bucket")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(mb).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(
        xml.contains("AccessDenied"),
        "expected S3 AccessDenied: {xml}"
    );
}

#[tokio::test]
async fn head_and_delete_remain_available() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bkt/lifecycle.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("payload"))
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::OK
    );

    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/bkt/lifecycle.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let head_response = app.clone().oneshot(head).await.unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    assert!(head_response.headers().contains_key(header::CONTENT_LENGTH));

    let delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri("/bkt/lifecycle.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(delete).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bkt/lifecycle.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.oneshot(get).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn conditional_get_and_head_preserve_object_identity_without_a_body() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    state.store.put(
        "conditional",
        "object.txt",
        Bytes::from_static(b"conditional payload"),
        "text/plain",
    );
    let etag = state
        .store
        .metadata("conditional", "object.txt")
        .expect("stored object metadata")
        .2;

    let not_modified = add_headers(
        Request::builder()
            .method("GET")
            .uri("/conditional/object.txt")
            .header(header::IF_NONE_MATCH, &etag)
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(not_modified).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.headers()[header::ETAG], etag);
    assert_hardened_object_headers(response.headers());
    assert!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );

    let failed_match = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/conditional/object.txt")
            .header(header::IF_MATCH, "\"different\"")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.oneshot(failed_match).await.unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(response.headers()[header::ETAG], etag);
    assert_hardened_object_headers(response.headers());
}

#[tokio::test]
async fn streaming_memory_get_preserves_range_and_head_metadata() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.store.put(
        "range",
        "object.txt",
        bytes::Bytes::from_static(b"0123456789"),
        "text/plain",
    );
    state_mut.store.put(
        "range",
        "unsafe<name>&.txt",
        bytes::Bytes::from_static(b"0123456789"),
        "text/plain",
    );
    state_mut
        .store
        .put("range", "empty.txt", bytes::Bytes::new(), "text/plain");
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/range/object.txt")
            .header(header::RANGE, "bytes=2-5")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
    assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
    assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes");
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "2345"
    );

    let suffix = add_headers(
        Request::builder()
            .method("GET")
            .uri("/range/object.txt")
            .header(header::RANGE, "bytes=-3")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(suffix).await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "3");
    assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 7-9/10");
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "789"
    );

    for (uri, range, object_length, escaped_key) in [
        (
            "/range/unsafe%3Cname%3E%26.txt",
            "bytes=20-30",
            10,
            "unsafe&lt;name&gt;&amp;.txt",
        ),
        ("/range/object.txt", "not-a-byte-range", 10, "object.txt"),
        ("/range/empty.txt", "bytes=0-0", 0, "empty.txt"),
    ] {
        let invalid = add_headers(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::RANGE, range)
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(invalid).await.unwrap();
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response.headers()[header::CONTENT_RANGE],
            format!("bytes */{object_length}")
        );
        assert_hardened_object_headers(response.headers());
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_s3_error_has_only_expected_xml_elements(&body);
        assert!(body.contains("<Code>InvalidRange</Code>"), "{body}");
        assert!(
            body.contains(&format!("<Key>{escaped_key}</Key>")),
            "{body}"
        );
        assert!(!body.contains("<name>"), "{body}");
    }

    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/range/object.txt")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "10");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    assert_hardened_object_headers(response.headers());
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn object_get_forces_browser_safe_download_headers_for_html() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.store.put(
        "download",
        "attacker-name.html",
        bytes::Bytes::from_static(b"<script>document.cookie='stolen=1'</script>"),
        "text/html; charset=utf-8",
    );
    let (ak, sk) = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/download/attacker-name.html")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "<script>document.cookie='stolen=1'</script>"
    );
}

#[tokio::test]
async fn percent_decoded_object_and_bucket_resources_cannot_inject_s3_error_xml() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let encoded = "%3CInjected%3Eresource%3C%2FInjected%3E%26%22%27";

    for (method, uri, status) in [
        ("GET", format!("/escape/{encoded}"), StatusCode::NOT_FOUND),
        ("PUT", format!("/{encoded}"), StatusCode::FORBIDDEN),
    ] {
        let response = app
            .clone()
            .oneshot(add_headers(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
                &headers,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_hardened_object_headers(response.headers());
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        assert_s3_error_has_only_expected_xml_elements(&body);
        assert!(!body.contains("<Injected>"));
        assert!(
            body.contains("&lt;Injected&gt;resource&lt;/Injected&gt;&amp;&quot;&apos;"),
            "escaped resource missing from {body}"
        );
    }
}

async fn spawn_presigned_upstream() -> (String, tokio::task::JoinHandle<()>) {
    async fn object(
        method: axum::http::Method,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response {
        let range = headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok());
        let (status, body, content_range) = if range == Some("bytes=2-5") {
            (StatusCode::PARTIAL_CONTENT, "2345", Some("bytes 2-5/10"))
        } else {
            (StatusCode::OK, "0123456789", None)
        };
        let mut response = axum::response::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_ENCODING, "identity")
            .header(
                header::CONTENT_DISPOSITION,
                "inline; filename=attacker-controlled.html",
            )
            .header("content-security-policy", "default-src * 'unsafe-inline'")
            .header("x-content-type-options", "off")
            .header(header::CONTENT_LANGUAGE, "en")
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .header(header::AGE, "600")
            .header(header::EXPIRES, "Wed, 19 Aug 2026 10:00:00 GMT")
            .header(header::ETAG, "\"upstream-etag\"")
            .header(header::LAST_MODIFIED, "Wed, 19 Aug 2026 09:00:00 GMT")
            .header("x-amz-checksum-sha256", "checksum")
            .header("x-amz-meta-project", "safe-metadata")
            .header("x-amz-version-id", "version-7")
            .header("x-goog-component-count", "2")
            .header("x-goog-custom-time", "2026-08-19T09:00:00Z")
            .header("x-goog-encryption-algorithm", "AES256")
            .header("x-goog-encryption-key-sha256", "key-checksum")
            .header("x-goog-expiration", "Wed, 19 Aug 2026 10:00:00 GMT")
            .header("x-goog-generation", "123456")
            .header("x-goog-hash", "crc32c=abcd")
            .header("x-goog-meta-project", "safe-gcs-metadata")
            .header("x-goog-metageneration", "9")
            .header("x-goog-object-lock-mode", "GOVERNANCE")
            .header(
                "x-goog-object-lock-retain-until-date",
                "2027-08-19T09:00:00Z",
            )
            .header("x-goog-storage-class", "STANDARD")
            .header("x-goog-stored-content-encoding", "identity")
            .header("x-goog-stored-content-length", "10")
            .header(header::SET_COOKIE, "session=attacker; Secure")
            .header("access-control-allow-origin", "https://attacker.example")
            .header(header::LOCATION, "https://attacker.example/redirect")
            .header("refresh", "0;url=https://attacker.example/redirect")
            .header("report-to", r#"{"group":"attacker"}"#)
            .header(
                "reporting-endpoints",
                "attacker=\"https://attacker.example\"",
            )
            .header(header::WWW_AUTHENTICATE, "Basic realm=attacker")
            .header("authentication-info", "nextnonce=attacker")
            .header("connection", "x-upstream-private")
            .header("x-upstream-private", "remove-me")
            .header(header::ACCEPT_RANGES, "bytes");
        if let Some(checksum_mode) = headers.get("x-amz-checksum-mode") {
            response = response.header("x-amz-meta-request-checksum-mode", checksum_mode.clone());
        }
        if let Some(content_range) = content_range {
            response = response.header(header::CONTENT_RANGE, content_range);
        }
        if method == axum::http::Method::HEAD {
            response = response.header(header::CONTENT_LENGTH, "10");
            response.body(Body::empty()).unwrap()
        } else {
            response = response.header(header::CONTENT_LENGTH, body.len().to_string());
            response.body(Body::from(body)).unwrap()
        }
    }

    async fn redirect() -> axum::response::Response {
        axum::response::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/object")
            .body(Body::empty())
            .unwrap()
    }

    async fn html_error() -> axum::response::Response {
        axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/html")
            .header(header::CONTENT_DISPOSITION, "inline; filename=error.html")
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .header(header::AGE, "600")
            .header(header::EXPIRES, "Wed, 19 Aug 2026 10:00:00 GMT")
            .header("content-security-policy", "default-src * 'unsafe-inline'")
            .header("x-content-type-options", "off")
            .header(header::SET_COOKIE, "error=attacker")
            .body(Body::from("<script>attack()</script>"))
            .unwrap()
    }

    let app = axum::Router::new()
        .route("/object", axum::routing::get(object).head(object))
        .route("/not-found", axum::routing::get(html_error))
        .route("/redirect", axum::routing::get(redirect));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn presigned_transport_failure_never_discloses_signed_url_material() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.presigned_http_policy = PresignedHttpPolicy::new(
        Vec::<String>::new(),
        ["127.0.0.1".to_string()],
        true,
        Duration::ZERO,
        Arc::new(TokioAddressResolver),
    )
    .unwrap();
    let (ak, sk) = make_key(&state).await;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let signed_url = format!(
        "http://{address}/object?X-Amz-Credential=AKIA_TEST%2F20260828%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=DO_NOT_DISCLOSE&Expires={expires}"
    );
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/proxy/transport-failure")
                .header("x-s4-backend-url", &signed_url)
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_hardened_object_headers(response.headers());
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("presigned backend request failed"), "{body}");
    let address = address.to_string();
    for sensitive in [
        signed_url.as_str(),
        "AKIA_TEST",
        "X-Amz-Credential",
        "X-Amz-Signature",
        "DO_NOT_DISCLOSE",
        address.as_str(),
    ] {
        assert!(
            !body.contains(sensitive),
            "response leaked {sensitive}: {body}"
        );
    }
}

#[tokio::test]
async fn presigned_http_responses_are_hardened_without_losing_object_semantics() {
    let (upstream, task) = spawn_presigned_upstream().await;
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.presigned_http_policy = PresignedHttpPolicy::new(
        Vec::<String>::new(),
        ["127.0.0.1".to_string()],
        true,
        Duration::ZERO,
        Arc::new(TokioAddressResolver),
    )
    .unwrap();
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/proxy/object")
            .header(header::RANGE, "bytes=2-5")
            .header("x-amz-checksum-mode", "ENABLED")
            .header(
                "x-s4-backend-url",
                format!("{upstream}/object?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    for (name, expected) in [
        (header::CONTENT_LENGTH.as_str(), "4"),
        (header::CONTENT_RANGE.as_str(), "bytes 2-5/10"),
        (header::CONTENT_TYPE.as_str(), "text/plain"),
        (header::CONTENT_ENCODING.as_str(), "identity"),
        (header::CONTENT_LANGUAGE.as_str(), "en"),
        (header::ETAG.as_str(), "\"upstream-etag\""),
        (
            header::LAST_MODIFIED.as_str(),
            "Wed, 19 Aug 2026 09:00:00 GMT",
        ),
        ("x-amz-checksum-sha256", "checksum"),
        ("x-amz-meta-project", "safe-metadata"),
        ("x-amz-meta-request-checksum-mode", "ENABLED"),
        ("x-amz-version-id", "version-7"),
        ("x-goog-component-count", "2"),
        ("x-goog-custom-time", "2026-08-19T09:00:00Z"),
        ("x-goog-encryption-algorithm", "AES256"),
        ("x-goog-encryption-key-sha256", "key-checksum"),
        ("x-goog-expiration", "Wed, 19 Aug 2026 10:00:00 GMT"),
        ("x-goog-generation", "123456"),
        ("x-goog-hash", "crc32c=abcd"),
        ("x-goog-meta-project", "safe-gcs-metadata"),
        ("x-goog-metageneration", "9"),
        ("x-goog-object-lock-mode", "GOVERNANCE"),
        (
            "x-goog-object-lock-retain-until-date",
            "2027-08-19T09:00:00Z",
        ),
        ("x-goog-storage-class", "STANDARD"),
        ("x-goog-stored-content-encoding", "identity"),
        ("x-goog-stored-content-length", "10"),
    ] {
        assert_eq!(response.headers()[name], expected, "header {name}");
    }
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "*",
        "the gateway CORS policy must replace the untrusted upstream value"
    );
    for dropped in [
        "set-cookie",
        "location",
        "refresh",
        "report-to",
        "reporting-endpoints",
        "www-authenticate",
        "authentication-info",
        "connection",
        "x-upstream-private",
    ] {
        assert!(
            !response.headers().contains_key(dropped),
            "untrusted upstream header {dropped} was forwarded"
        );
    }
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "2345"
    );

    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/proxy/object")
            .header(
                "x-s4-backend-url",
                format!("{upstream}/object?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "10");
    assert_eq!(response.headers()[header::ETAG], "\"upstream-etag\"");
    assert_hardened_object_headers(response.headers());
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/proxy?list-type=2")
            .header(
                "x-s4-backend-url",
                format!("{upstream}/object?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "0123456789"
    );

    let non_success = add_headers(
        Request::builder()
            .method("GET")
            .uri("/proxy/missing")
            .header(
                "x-s4-backend-url",
                format!("{upstream}/not-found?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(non_success).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
    assert_hardened_object_headers(response.headers());
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "<script>attack()</script>"
    );

    let redirect = add_headers(
        Request::builder()
            .method("GET")
            .uri("/proxy/redirect")
            .header(
                "x-s4-backend-url",
                format!("{upstream}/redirect?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.oneshot(redirect).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    task.abort();
}

#[tokio::test]
async fn all_multipart_operations_are_rejected() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .legacy_max_object_bytes = 1;
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    for (method, uri, body) in [
        ("POST", "/bkt/object?uploads", "create"),
        (
            "PUT",
            "/bkt/object?partNumber=1&uploadId=untrusted",
            "raw part must not be stored",
        ),
        ("GET", "/bkt/object?uploadId=untrusted", ""),
        (
            "POST",
            "/bkt/object?uploadId=untrusted",
            "complete body must not be consumed",
        ),
        ("DELETE", "/bkt/object?uploadId=untrusted", ""),
    ] {
        let request = add_headers(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(body))
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED, "{method} {uri}");
        let response_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&response_body).contains("<Code>NotImplemented</Code>"),
            "{method} {uri}"
        );
    }

    assert!(state.store.get("bkt", "object").is_none());
}

fn signed_request(
    access_key: &str,
    secret: &str,
    method: &str,
    uri: &str,
    body: &[u8],
    headers: &[(&'static str, &str)],
) -> Request<Body> {
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningParams,
        SigningSettings, UriPathNormalizationMode, sign,
    };
    use aws_sigv4::sign::v4;
    use std::time::SystemTime;

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    let identity: aws_smithy_runtime_api::client::identity::Identity =
        Credentials::new(access_key, secret, None, None, "test").into();
    let params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("s3")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();

    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body.to_vec()))
        .unwrap();
    for &(name, value) in headers {
        req.headers_mut().append(name, value.parse().unwrap());
    }
    let signable = SignableRequest::new(
        method,
        uri,
        req.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap())),
        SignableBody::Bytes(body),
    )
    .unwrap();
    let instructions = sign(signable, &params).unwrap().into_parts().0;
    instructions.apply_to_request_http1x(&mut req);
    // The signer covered `host`; the outgoing request must carry it too.
    let authority = req
        .uri()
        .authority()
        .expect("absolute uri")
        .as_str()
        .to_string();
    req.headers_mut().insert("host", authority.parse().unwrap());
    req
}

fn presigned_request(
    access_key: &str,
    secret: &str,
    method: &str,
    uri: &str,
    headers: &[(&'static str, &str)],
) -> Request<Body> {
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation, SigningParams,
        SigningSettings, UriPathNormalizationMode, sign,
    };
    use aws_sigv4::sign::v4;
    use std::time::SystemTime;

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(Duration::from_secs(300));

    let identity: aws_smithy_runtime_api::client::identity::Identity =
        Credentials::new(access_key, secret, None, None, "test").into();
    let params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("s3")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();

    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    for &(name, value) in headers {
        req.headers_mut().append(name, value.parse().unwrap());
    }
    let signable = SignableRequest::new(
        method,
        uri,
        req.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap())),
        SignableBody::UnsignedPayload,
    )
    .unwrap();
    let instructions = sign(signable, &params).unwrap().into_parts().0;
    instructions.apply_to_request_http1x(&mut req);
    let authority = req
        .uri()
        .authority()
        .expect("absolute uri")
        .as_str()
        .to_string();
    req.headers_mut().insert("host", authority.parse().unwrap());
    req
}

#[tokio::test]
async fn sigv4_signed_request_accepted_and_rejected() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let uri = "http://s4.local/demo/signed.txt";

    // Correct signature → 200.
    let req = signed_request(
        &ak,
        &sk,
        "PUT",
        uri,
        b"hello world",
        &[("content-type", "text/plain")],
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    if status != StatusCode::OK {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        eprintln!("DEBUG first resp body: {:?}", body);
    }
    assert_eq!(status, StatusCode::OK, "valid SigV4 should pass");

    // Wrong secret → 403.
    let req = signed_request(&ak, "not-the-secret", "PUT", uri, b"hello world", &[]);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "tampered signature must fail"
    );

    // Unknown access key → 403.
    let req = signed_request("s4_unknown", &sk, "PUT", uri, b"hello world", &[]);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "unknown key must fail"
    );
}

#[tokio::test]
async fn sigv4_signed_semantic_headers_accept_and_detect_mutation_or_removal() {
    enum HeaderChange {
        None,
        Replace(&'static str, &'static str),
        Remove(&'static str),
    }

    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    for (index, (name, change, expected)) in [
        ("unchanged", HeaderChange::None, StatusCode::OK),
        (
            "mutated content type",
            HeaderChange::Replace("content-type", "application/json"),
            StatusCode::FORBIDDEN,
        ),
        (
            "removed content type",
            HeaderChange::Remove("content-type"),
            StatusCode::FORBIDDEN,
        ),
        (
            "mutated dynamic metadata",
            HeaderChange::Replace("x-amz-meta-dynamic-name", "two"),
            StatusCode::FORBIDDEN,
        ),
        (
            "removed S4 semantic header",
            HeaderChange::Remove("x-s4-process"),
            StatusCode::FORBIDDEN,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let uri = format!("http://s4.local/semantic/signed-{index}.txt");
        let request = signed_request(
            &access_key,
            &secret_key,
            "PUT",
            &uri,
            b"semantic body",
            &[
                ("content-type", "text/plain"),
                ("x-s4-process", "write"),
                ("x-amz-meta-dynamic-name", "one"),
            ],
        );
        let (mut parts, body) = request.into_parts();
        match change {
            HeaderChange::None => {}
            HeaderChange::Replace(header, value) => {
                parts.headers.insert(header, value.parse().unwrap());
            }
            HeaderChange::Remove(header) => {
                parts.headers.remove(header);
            }
        }
        let response = app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{name}");
        if expected == StatusCode::FORBIDDEN {
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                String::from_utf8_lossy(&body).contains("<Code>SignatureDoesNotMatch</Code>"),
                "{name}: {}",
                String::from_utf8_lossy(&body)
            );
        }
    }
}

#[tokio::test]
async fn sigv4_rejects_ambiguous_or_noncanonical_integrity_headers_before_body_polling() {
    enum HeaderShape {
        Raw(&'static str),
        Duplicate {
            signed: &'static str,
            first: &'static str,
            second: &'static str,
        },
    }

    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    for (index, (name, shape)) in [
        (
            "x-s4-stable-fields",
            HeaderShape::Duplicate {
                signed: "email,account_id",
                first: "email",
                second: "account_id",
            },
        ),
        (
            "x-s4-backend-url",
            HeaderShape::Duplicate {
                signed: "https://storage.example/one,https://storage.example/two",
                first: "https://storage.example/one",
                second: "https://storage.example/two",
            },
        ),
        (
            "content-type",
            HeaderShape::Duplicate {
                signed: "text/plain;charset=utf-8",
                first: "text/plain",
                second: "charset=utf-8",
            },
        ),
        (
            "x-amz-meta-project",
            HeaderShape::Duplicate {
                signed: "one,two",
                first: "one",
                second: "two",
            },
        ),
        ("x-s4-stable-fields", HeaderShape::Raw(" email, account_id")),
        ("x-s4-stable-fields", HeaderShape::Raw("email, account_id ")),
        (
            "x-s4-backend-url",
            HeaderShape::Raw("\thttps://storage.example/object"),
        ),
        (
            "content-type",
            HeaderShape::Raw("text/plain;  charset=utf-8"),
        ),
        (
            "content-md5",
            HeaderShape::Raw("CY9rzUYh03PK3k6DJie09g==\t"),
        ),
        ("x-amz-tagging", HeaderShape::Raw(" project=one&owner=two")),
    ]
    .into_iter()
    .enumerate()
    {
        let signed_value = match &shape {
            HeaderShape::Raw(value) => *value,
            HeaderShape::Duplicate { signed, .. } => *signed,
        };
        let mut signed_headers = Vec::with_capacity(2);
        if name != "content-type" {
            signed_headers.push(("content-type", "text/plain"));
        }
        signed_headers.push((name, signed_value));
        let uri = format!("http://s4.local/semantic/shape-{index}.txt");
        let request = signed_request(
            &access_key,
            &secret_key,
            "PUT",
            &uri,
            b"must not be polled",
            &signed_headers,
        );
        let (mut parts, _) = request.into_parts();
        if let HeaderShape::Duplicate { first, second, .. } = shape {
            parts.headers.remove(name);
            parts.headers.append(name, first.parse().unwrap());
            parts.headers.append(name, second.parse().unwrap());
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let request = Request::from_parts(
            parts,
            Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not be polled")),
            }),
        );

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}");
        assert_eq!(polls.load(Ordering::SeqCst), 0, "{name}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("<Code>SignatureDoesNotMatch</Code>"),
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn sigv4_rejects_unsigned_integrity_header_injection_before_polling_the_body() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    for (index, (name, value)) in [
        ("x-s4-storage-mode", "managed"),
        ("x-s4-backend-url", "https://storage.example/object"),
        ("x-s4-process", "read"),
        ("x-s4-stable-fields", "email"),
        ("content-type", "text/plain"),
        ("content-encoding", "gzip"),
        ("content-md5", "CY9rzUYh03PK3k6DJie09g=="),
        ("x-amz-meta-dynamic-name", "metadata"),
    ]
    .into_iter()
    .enumerate()
    {
        let uri = format!("http://s4.local/semantic/unsigned-{index}.txt");
        let request = signed_request(
            &access_key,
            &secret_key,
            "PUT",
            &uri,
            b"must not be polled",
            &[],
        );
        let (mut parts, _) = request.into_parts();
        parts.headers.insert(name, value.parse().unwrap());
        let polls = Arc::new(AtomicUsize::new(0));
        let request = Request::from_parts(
            parts,
            Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not be polled")),
            }),
        );

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}");
        assert_eq!(polls.load(Ordering::SeqCst), 0, "{name}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("<Code>SignatureDoesNotMatch</Code>"),
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            String::from_utf8_lossy(&body).contains(
                "The request signature we calculated does not match the signature you provided."
            ),
            "{name} must use the generic 403 message"
        );
        assert!(
            !String::from_utf8_lossy(&body).contains(name),
            "{name} must not be disclosed by the generic rejection"
        );
    }
}

#[tokio::test]
async fn presigned_host_only_get_accepts_but_appended_protected_headers_are_rejected() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    state.store.put(
        "presigned",
        "object.txt",
        Bytes::from_static(b"presigned body"),
        "text/plain",
    );
    let uri = "https://s4.local/presigned/object.txt";

    let response = app
        .clone()
        .oneshot(presigned_request(&access_key, &secret_key, "GET", uri, &[]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "presigned body"
    );

    for (name, value) in [
        ("x-amz-user-agent", "unsigned-agent"),
        ("x-amz-checksum-mode", "ENABLED"),
    ] {
        let request = presigned_request(&access_key, &secret_key, "GET", uri, &[]);
        let (mut parts, body) = request.into_parts();
        parts.headers.insert(name, value.parse().unwrap());
        let response = app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "unsigned signer exclusion {name}"
        );
    }

    let response = app
        .clone()
        .oneshot(presigned_request(
            &access_key,
            &secret_key,
            "GET",
            uri,
            &[("x-amz-meta-dynamic-name", "signed")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    for (name, value) in [
        ("x-s4-process", "read"),
        ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ("x-amz-meta-dynamic-name", "appended"),
        ("x-amz-tagging", "project=appended"),
    ] {
        let request = presigned_request(&access_key, &secret_key, "GET", uri, &[]);
        let (mut parts, body) = request.into_parts();
        parts.headers.insert(name, value.parse().unwrap());
        let response = app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("<Code>SignatureDoesNotMatch</Code>"),
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn non_sigv4_api_key_auth_keeps_raw_semantic_header_behavior() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    let request = append_headers(
        add_headers(
            Request::builder()
                .method("PUT")
                .uri("/semantic/api-key.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .header("x-amz-meta-dynamic-name", "metadata")
                .body(Body::from("API key body"))
                .unwrap(),
            &auth_headers(&access_key, &secret_key),
        ),
        &[
            ("x-s4-process", " write ".to_string()),
            ("x-s4-process", "read".to_string()),
        ],
    );

    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
    assert!(state.store.get("semantic", "api-key.txt").is_some());
}

#[tokio::test]
async fn streaming_sigv4_hash_is_checked_before_atomic_commit() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_write_mode = StreamingWriteMode::Single;
    state_mut.dev_memory_streaming_enabled = true;
    let (access_key, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());
    let uri = "http://s4.local/stream/signed-stream.txt";
    let input = b"contact a@b.com now\n";

    let request = signed_request(
        &access_key,
        &secret_key,
        "PUT",
        uri,
        input,
        &[("content-type", "text/plain")],
    );
    let (parts, _) = request.into_parts();
    let request = Request::from_parts(
        parts,
        Body::new(FrameSequenceBody::data([
            Bytes::copy_from_slice(&input[..7]),
            Bytes::copy_from_slice(&input[7..]),
        ])),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        state
            .store
            .get("stream", "signed-stream.txt")
            .expect("committed object")
            .data,
        Bytes::from_static(b"contact [REDACTED_EMAIL] now\n")
    );

    let bad_uri = "http://s4.local/stream/tampered-stream.txt";
    let request = signed_request(
        &access_key,
        &secret_key,
        "PUT",
        bad_uri,
        input,
        &[("content-type", "text/plain")],
    );
    let (parts, _) = request.into_parts();
    let request = Request::from_parts(parts, Body::from("tampered body\n"));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(state.store.get("stream", "tampered-stream.txt").is_none());
}

#[tokio::test]
async fn sigv4_get_object_roundtrip() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;

    // PUT via SigV4.
    let uri = "http://s4.local/bkt/signed.txt";
    let req = signed_request(
        &ak,
        &sk,
        "PUT",
        uri,
        b"content a@b.com",
        &[("content-type", "text/plain")],
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET via SigV4 returns the filtered object.
    let req = signed_request(&ak, &sk, "GET", uri, b"", &[]);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("[REDACTED_EMAIL]"),
        "sigv4 GET filtered: {text}"
    );
}

#[tokio::test]
async fn tsv_roundtrip_filters_and_preserves() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let body = "email\tcard\tnote\nalice@example.com\t4111111111111111\thi\nbob@test.org\t5500005555555559\tbye\n";
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/demo/data.tsv")
            .header(header::CONTENT_TYPE, "text/tab-separated-values")
            .body(Body::from(body))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "TSV PUT should succeed");

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/demo/data.tsv")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let out = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .to_string();

    assert!(
        out.contains("[REDACTED_EMAIL]"),
        "TSV email redacted: {out}"
    );
    assert!(out.contains("[REDACTED_CARD]"), "TSV card redacted: {out}");
    assert!(out.contains("note"), "TSV header preserved: {out}");
    assert!(out.contains("hi"), "TSV non-PII value preserved: {out}");
    assert!(out.contains("bye"), "TSV second record preserved: {out}");
}

#[tokio::test]
async fn managed_storage_isolates_users() {
    // The per-user namespace ({uid}/{bucket}/{key}) is the isolation guarantee
    // for S4-managed storage. It is enforced by the key prefix the gateway
    // builds in s3_put/s3_get when service storage is configured, and by
    // per-key authentication. This test asserts the authentication half:
    // user1's credentials authenticate as user1, user2's as user2, and neither
    // can act as the other. The namespace prefix itself is exercised
    // end-to-end against real B2 by e2e-b2.sh / e2e-hosted.sh.
    let (app, state) = router().await;
    let (ak1, sk1) = state
        .keys
        .create_key("user-one", "ns-test", 0, None)
        .await
        .expect("create user-one API key");
    let (ak2, sk2) = state
        .keys
        .create_key("user-two", "ns-test", 0, None)
        .await
        .expect("create user-two API key");
    let h1 = auth_headers(&ak1, &sk1);
    let h2 = auth_headers(&ak2, &sk2);

    // Each key can write with its own credentials.
    let put1 = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/u1/obj.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("one"))
            .unwrap(),
        &h1,
    );
    assert_eq!(
        app.clone().oneshot(put1).await.unwrap().status(),
        StatusCode::OK,
        "user1 write"
    );

    let put2 = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/u2/obj.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("two"))
            .unwrap(),
        &h2,
    );
    assert_eq!(
        app.clone().oneshot(put2).await.unwrap().status(),
        StatusCode::OK,
        "user2 write"
    );

    // Cross-credential attempts must fail: user1's secret is not valid for
    // user2's access key (and vice versa).
    let cross = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/u2/obj.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("evil"))
            .unwrap(),
        &[
            ("x-s4-access-key", ak2.clone()),
            ("x-s4-secret-key", sk1.clone()),
        ],
    );
    let resp = app.clone().oneshot(cross).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "user1 secret must not work for user2 key"
    );

    let cross2 = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/u1/obj.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("evil"))
            .unwrap(),
        &[
            ("x-s4-access-key", ak1.clone()),
            ("x-s4-secret-key", sk2.clone()),
        ],
    );
    let resp = app.oneshot(cross2).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "user2 secret must not work for user1 key"
    );
}

#[tokio::test]
async fn sigv4_tampered_body_rejected() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let uri = "http://s4.local/bkt/tamper.txt";

    // Sign body A, then send body B with the A-signature -> 403.
    let req = signed_request(
        &ak,
        &sk,
        "PUT",
        uri,
        b"AAAA",
        &[("content-type", "text/plain")],
    );
    let (parts, _old_body) = req.into_parts();
    let req = Request::from_parts(parts, Body::from("BBBB"));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "body tampering must be rejected by SigV4"
    );
}

#[tokio::test]
async fn invalid_sigv4_headers_are_rejected_without_polling_put_body() {
    let (app, state) = router().await;
    let (ak, _sk) = make_key(&state).await;
    let uri = "http://s4.local/bkt/unpolled.txt";
    let signed = signed_request(&ak, "wrong-secret", "PUT", uri, b"sensitive body", &[]);
    let (parts, _) = signed.into_parts();
    let polls = Arc::new(AtomicUsize::new(0));
    let request = Request::from_parts(
        parts,
        Body::new(PollTrackingBody {
            polls: polls.clone(),
            data: Some(Bytes::from_static(b"sensitive body")),
        }),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn valid_sigv4_seed_polls_then_rejects_payload_hash_mismatch() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let uri = "http://s4.local/bkt/hash-mismatch.txt";
    let signed = signed_request(
        &ak,
        &sk,
        "PUT",
        uri,
        b"claimed body",
        &[("content-type", "text/plain")],
    );
    let (parts, _) = signed.into_parts();
    let polls = Arc::new(AtomicUsize::new(0));
    let request = Request::from_parts(
        parts,
        Body::new(PollTrackingBody {
            polls: polls.clone(),
            data: Some(Bytes::from_static(b"different body")),
        }),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(polls.load(Ordering::SeqCst) > 0);
    assert!(state.store.get("bkt", "hash-mismatch.txt").is_none());
}

#[tokio::test]
async fn unmodified_rust_sdk_default_put_is_accepted() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .sigv4_policy = SigV4Policy::new("us-east-1", true);
    let (access_key, secret) = make_key(&state).await;
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            access_key,
            secret,
            None,
            None,
            "phase-4-rust-sdk",
        ))
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(format!("http://{address}"))
        .force_path_style(true)
        .build();
    let client = aws_sdk_s3::Client::from_conf(config);
    client
        .put_object()
        .bucket("sdk-bucket")
        .key("default-put.txt")
        .content_type("text/plain")
        .body(aws_sdk_s3::primitives::ByteStream::from_static(
            b"SDK contact sdk@example.com",
        ))
        .send()
        .await
        .expect("unmodified Rust SDK PUT");

    let stored = state
        .store
        .get("sdk-bucket", "default-put.txt")
        .expect("SDK object stored only after integrity verification");
    let text = String::from_utf8_lossy(&stored.data);
    assert!(text.contains("[REDACTED_EMAIL]"), "stored body: {text}");
    assert!(!text.contains("sdk@example.com"), "stored body: {text}");
    server.abort();
}

#[tokio::test]
async fn available_aws_cli_and_boto3_interoperate() {
    let aws_available = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("aws")
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|output| output.status.success()));
    let boto3_available = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("python3")
            .args(["-c", "import boto3"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|output| output.status.success()));
    if !aws_available && !boto3_available {
        return;
    }

    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .sigv4_policy = SigV4Policy::new("us-east-1", true);
    let (access_key, secret) = make_key(&state).await;
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = format!("http://{address}");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    if aws_available {
        let endpoint = endpoint.clone();
        let access_key = access_key.clone();
        let secret = secret.clone();
        let mut child = Command::new("aws")
            .args([
                "s3",
                "cp",
                "-",
                "s3://cli-bucket/default.txt",
                "--endpoint-url",
                &endpoint,
                "--region",
                "us-east-1",
                "--no-progress",
                "--content-type",
                "text/plain",
            ])
            .env("AWS_ACCESS_KEY_ID", access_key)
            .env("AWS_SECRET_ACCESS_KEY", secret)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start AWS CLI");
        child
            .stdin
            .take()
            .expect("AWS CLI stdin")
            .write_all(b"CLI contact cli@example.com")
            .await
            .expect("write AWS CLI body");
        let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
            .await
            .expect("AWS CLI timed out")
            .expect("wait for AWS CLI");
        assert!(
            output.status.success(),
            "AWS CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(state.store.get("cli-bucket", "default.txt").is_some());
    }

    if boto3_available {
        let script = r#"
import boto3, os
from botocore.config import Config
boto3.client(
    "s3",
    endpoint_url=os.environ["S4_TEST_ENDPOINT"],
    region_name="us-east-1",
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    config=Config(s3={"addressing_style": "path"}),
).put_object(Bucket="boto-bucket", Key="default.txt", Body=b"boto contact boto@example.com", ContentType="text/plain")
"#;
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            Command::new("python3")
                .args(["-c", script])
                .env("S4_TEST_ENDPOINT", &endpoint)
                .env("AWS_ACCESS_KEY_ID", &access_key)
                .env("AWS_SECRET_ACCESS_KEY", &secret)
                .env("AWS_EC2_METADATA_DISABLED", "true")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("boto3 timed out")
        .expect("run boto3");
        assert!(
            output.status.success(),
            "boto3 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(state.store.get("boto-bucket", "default.txt").is_some());
    }
    server.abort();
}

#[tokio::test]
async fn non_expiring_key_works() {
    let (app, state) = router().await;
    // expires_in=0 means never expires.
    let (ak, sk) = state
        .keys
        .create_key("never-exp", "exp", 0, None)
        .await
        .expect("create non-expiring API key");
    let hdrs = auth_headers(&ak, &sk);
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/demo/x.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x"))
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "non-expiring key must work");
}

#[tokio::test]
async fn mcp_token_roundtrip_and_auth() {
    let (app, state) = router().await;

    // Create an MCP token.
    let token = state
        .keys
        .create_mcp_token("mcp-user", "agent", 0)
        .await
        .unwrap()
        .0;
    assert!(token.starts_with("s4m_"), "token prefix: {token}");

    // Use it as a Bearer token to write.
    let put = Request::builder()
        .method("PUT")
        .uri("/mcpbkt/obj.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from("hello a@b.com"))
        .unwrap();
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "MCP bearer write");

    // Read back (filtered).
    let get = Request::builder()
        .method("GET")
        .uri("/mcpbkt/obj.txt")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("[REDACTED_EMAIL]"),
        "MCP write filtered: {text}"
    );

    // A forged token must be rejected.
    let bad = Request::builder()
        .method("PUT")
        .uri("/mcpbkt/obj.txt")
        .header("Authorization", "Bearer s4m_forged_token_0000")
        .body(Body::from("x"))
        .unwrap();
    let resp = app.clone().oneshot(bad).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "forged MCP token rejected"
    );

    // Delete works (returns 200/204).
    let hash = s4_gateway::store::sha256_hash(&token);
    assert!(state.keys.delete_mcp_token(&hash, "mcp-user").await);
    assert!(!state.keys.delete_mcp_token(&hash, "mcp-user").await);
}

#[tokio::test]
async fn mcp_token_identity_is_per_user() {
    let (app, state) = router().await;
    let t1 = state
        .keys
        .create_mcp_token("user-a", "agent", 0)
        .await
        .unwrap()
        .0;
    let t2 = state
        .keys
        .create_mcp_token("user-b", "agent", 0)
        .await
        .unwrap()
        .0;

    // user-a can write; user-b's token cannot read user-a's in-memory object
    // under a different identity via the dashboard key list (identity binding).
    let put = Request::builder()
        .method("PUT")
        .uri("/abkt/o.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .header("Authorization", format!("Bearer {t1}"))
        .body(Body::from("data"))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::OK
    );

    // Tokens resolve to distinct users.
    let uid1 = state.keys.resolve_mcp_token(&t1).await.unwrap();
    let uid2 = state.keys.resolve_mcp_token(&t2).await.unwrap();
    assert_ne!(uid1, uid2, "tokens must bind to distinct users");
    assert_eq!(uid1, "user-a");
}

#[tokio::test]
async fn demo_redact_runs_pipeline() {
    let (app, _state) = router().await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/demo/redact")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"text":"contact alice@example.com card 4111111111111111"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "private, no-store");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let redacted = v["redacted"].as_str().unwrap_or("");
    assert!(
        redacted.contains("[REDACTED_EMAIL]"),
        "email redacted: {redacted}"
    );
    assert!(
        redacted.contains("[REDACTED_CARD]"),
        "card redacted: {redacted}"
    );
}

async fn post_demo_process(app: &Router, body: serde_json::Value) -> axum::response::Response {
    post_demo_process_body(app, Body::from(body.to_string())).await
}

async fn post_demo_process_body(app: &Router, body: Body) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/demo/process")
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap()
}

fn assert_demo_security_headers(response: &axum::response::Response) {
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

fn assert_demo_response_headers(response: &axum::response::Response) {
    assert_demo_security_headers(response);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
}

async fn demo_response_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn demo_process_is_stateless_ordered_and_supports_safe_and_join_modes() {
    let (app, state) = router().await;
    assert!(state.store.list_keys().is_empty());
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    let records = serde_json::json!([
        {
            "email": "alice@example.com",
            "card": "4111111111111111",
            "note": "first"
        },
        {
            "email": "alice@example.com",
            "card": "4111111111111111",
            "note": "second"
        },
        {
            "email": "bob@example.com",
            "card": "4111111111111111",
            "note": "third"
        }
    ]);

    let safe = post_demo_process(
        &app,
        serde_json::json!({"records": records, "mode": "safe"}),
    )
    .await;
    assert_eq!(safe.status(), StatusCode::OK);
    assert_demo_response_headers(&safe);
    let safe = demo_response_json(safe).await;
    assert_eq!(safe["mode"], "safe");
    assert_eq!(safe["records"][0]["record"], 1);
    assert_eq!(safe["records"][1]["record"], 2);
    assert_eq!(safe["records"][2]["record"], 3);
    for (index, note) in ["first", "second", "third"].into_iter().enumerate() {
        let body: serde_json::Value =
            serde_json::from_str(safe["records"][index]["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["email"], "[REDACTED_EMAIL]");
        assert_eq!(body["card"], "[REDACTED_CARD]");
        assert_eq!(body["note"], note);
    }

    let join = post_demo_process(
        &app,
        serde_json::json!({"records": records, "mode": "join"}),
    )
    .await;
    assert_eq!(join.status(), StatusCode::OK);
    assert_demo_response_headers(&join);
    let join = demo_response_json(join).await;
    assert_eq!(join["mode"], "join");
    let first: serde_json::Value =
        serde_json::from_str(join["records"][0]["body"].as_str().unwrap()).unwrap();
    let second: serde_json::Value =
        serde_json::from_str(join["records"][1]["body"].as_str().unwrap()).unwrap();
    let third: serde_json::Value =
        serde_json::from_str(join["records"][2]["body"].as_str().unwrap()).unwrap();
    assert_ne!(first["email"], "alice@example.com");
    assert_eq!(first["email"], second["email"]);
    assert_ne!(first["email"], third["email"]);
    assert_eq!(first["note"], "first");
    assert_eq!(second["note"], "second");
    assert_eq!(third["note"], "third");
    assert_eq!(first["card"], "[REDACTED_CARD]");

    let next_request = post_demo_process(
        &app,
        serde_json::json!({
            "records": [{"email": "alice@example.com"}],
            "mode": "join"
        }),
    )
    .await;
    assert_eq!(next_request.status(), StatusCode::OK);
    let next_request = demo_response_json(next_request).await;
    let next_email: serde_json::Value =
        serde_json::from_str(next_request["records"][0]["body"].as_str().unwrap()).unwrap();
    assert_ne!(first["email"], next_email["email"]);
    assert!(state.store.list_keys().is_empty());
}

#[tokio::test]
async fn demo_process_rejects_raw_unknown_and_malformed_modes() {
    let (app, _state) = router().await;
    for mode in ["raw", "unknown", "SAFE"] {
        let response = post_demo_process(
            &app,
            serde_json::json!({"records": [{"value": 1}], "mode": mode}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_demo_response_headers(&response);
        let body = demo_response_json(response).await;
        assert_eq!(body["code"], "invalid_request");
        assert_eq!(body["message"], "Invalid demo request");
    }
}

#[tokio::test]
async fn demo_process_enforces_record_and_canonical_input_limits() {
    let (app, _state) = router().await;
    for records in [
        serde_json::json!([]),
        serde_json::Value::Array(vec![serde_json::Value::Null; 11]),
    ] {
        let response = post_demo_process(
            &app,
            serde_json::json!({"records": records, "mode": "safe"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_demo_response_headers(&response);
        assert_eq!(
            demo_response_json(response).await["code"],
            "invalid_record_count"
        );
    }

    let response = post_demo_process(
        &app,
        serde_json::json!({
            "records": ["x".repeat(64 * 1024)],
            "mode": "safe"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_demo_response_headers(&response);
    assert_eq!(
        demo_response_json(response).await["code"],
        "input_too_large"
    );

    let response = post_demo_process_body(&app, Body::from(vec![b' '; 512 * 1024 + 1])).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_demo_response_headers(&response);
    assert_eq!(
        demo_response_json(response).await["code"],
        "input_too_large"
    );
}

#[tokio::test]
async fn demo_process_enforces_aggregate_output_limit() {
    let state = test_state().await;
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    let app = build_router(state);
    let response = post_demo_process(
        &app,
        serde_json::json!({
            "records": ["a@b.co ".repeat(7_000)],
            "mode": "safe"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_demo_response_headers(&response);
    let body = demo_response_json(response).await;
    assert_eq!(body["code"], "output_too_large");
    assert_eq!(body["message"], "Demo output exceeds 64 KiB");
}

#[tokio::test]
async fn demo_process_enforces_serialized_json_response_limit() {
    let (app, _state) = router().await;
    let response = post_demo_process(
        &app,
        serde_json::json!({
            "records": ["\\".repeat(30_000)],
            "mode": "safe"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_demo_response_headers(&response);
    assert_eq!(
        demo_response_json(response).await["code"],
        "output_too_large"
    );
}

#[tokio::test]
async fn malformed_demo_bodies_consume_the_global_start_allowance() {
    let (app, _state) = router().await;
    for _ in 0..30 {
        let response = post_demo_process_body(&app, Body::from("{")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_demo_response_headers(&response);
    }
    let response = post_demo_process(
        &app,
        serde_json::json!({"records": [{"value": 1}], "mode": "safe"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_demo_response_headers(&response);
    assert_eq!(demo_response_json(response).await["code"], "rate_limited");
}

#[tokio::test]
async fn transformed_read_is_rejected_without_exposing_raw_data() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    // Seed RAW data at rest — as if written by the user's own S3 client or a
    // pre-existing bucket (write-time pipeline not involved).
    state.store.put(
        "rawbkt",
        "doc.json",
        br#"{"email":"alice@example.com","card":"4111111111111111","note":"hi"}"#.to_vec(),
        "application/json",
    );

    // Plain GET returns raw (PII intact).
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/rawbkt/doc.json")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(get).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&body);
    assert!(
        raw.contains("alice@example.com"),
        "raw read keeps PII: {raw}"
    );

    let transformed_get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/rawbkt/doc.json")
            .header("x-s4-process", "read")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(transformed_get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let rejected = String::from_utf8_lossy(&body);
    assert!(
        rejected.contains("<Code>NotImplemented</Code>"),
        "typed rejection: {rejected}"
    );
    assert!(
        !rejected.contains("alice@example.com") && !rejected.contains("4111111111111111"),
        "rejection must not leak raw PII: {rejected}"
    );
}

#[tokio::test]
async fn transformed_read_is_rejected_before_object_lookup() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/rawbkt/does-not-exist.json")
            .header("x-s4-process", "true")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Code>NotImplemented</Code>"), "{xml}");
    assert!(!xml.contains("NoSuchKey"), "lookup must not run: {xml}");
}

#[tokio::test]
async fn legacy_body_limit_never_exceeds_hard_ceiling() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .legacy_max_object_bytes = usize::MAX;
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/limits/default.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(vec![b'x'; 16 * 1024 * 1024 + 1]))
            .unwrap(),
        &auth_headers(&ak, &sk),
    );

    let resp = app.oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Code>EntityTooLarge</Code>"), "{xml}");
}

#[tokio::test]
async fn legacy_body_limit_no_longer_bounds_streaming_put_or_passthrough_get() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .legacy_max_object_bytes = 8;
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    // The legacy buffered PUT path is gone: the configured legacy cap no
    // longer bounds a streaming PUT, which is instead capped by the dev
    // memory sink (16 MiB default).
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/limits/custom.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("abcdefghij"))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "legacy cap must not bound PUT"
    );
    assert!(state.store.get("limits", "custom.txt").is_some());

    // Passthrough GET streams the stored object regardless of the legacy cap.
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/limits/custom.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body.as_ref(),
        b"abcdefghij",
        "passthrough GET must not buffer or reject against the legacy cap"
    );
}

#[tokio::test]
async fn stable_transformed_reads_are_rejected_without_disclosure() {
    let (app, state) = router().await;

    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    // Two raw records sharing a join key (email), different notes.
    state.store.put(
        "j1",
        "a.json",
        br#"{"email":"alice@example.com","note":"first"}"#.to_vec(),
        "application/json",
    );
    state.store.put(
        "j1",
        "b.json",
        br#"{"email":"alice@example.com","note":"second"}"#.to_vec(),
        "application/json",
    );

    let get = |key: &str| {
        add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/j1/{key}"))
                .header("x-s4-process", "read")
                .header("x-s4-stable-fields", "email")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        )
    };

    let ra = app.clone().oneshot(get("a.json")).await.unwrap();
    let rb = app.clone().oneshot(get("b.json")).await.unwrap();
    assert_eq!(ra.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(rb.status(), StatusCode::NOT_IMPLEMENTED);
    let ta = String::from_utf8_lossy(
        &axum::body::to_bytes(ra.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .to_string();
    let tb = String::from_utf8_lossy(
        &axum::body::to_bytes(rb.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .to_string();

    assert!(!ta.contains("alice@example.com"), "a leaks PII: {ta}");
    assert!(!tb.contains("alice@example.com"), "b leaks PII: {tb}");
    assert!(ta.contains("<Code>NotImplemented</Code>"), "{ta}");
    assert!(tb.contains("<Code>NotImplemented</Code>"), "{tb}");
}

#[tokio::test]
async fn unsafe_transformed_read_stages_then_sanitizes_source_headers() {
    let mut state = test_state().await;
    let spool_dir =
        std::env::temp_dir().join(format!("s4-read-spool-router-{}", uuid::Uuid::now_v7()));
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state_mut.spool_config.directory = spool_dir.clone();
    state_mut.spool_config.max_object_bytes = 1024;
    state_mut.spool_quota = Arc::new(SpoolQuota::new(2048));
    state.store.put(
        "read",
        "raw.txt",
        Bytes::from_static(b"contact alice@example.com\n"),
        "text/plain; charset=utf-8",
    );
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state);
    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/raw.txt")
                .header("x-s4-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_hardened_object_headers(response.headers());
    assert!(!response.headers().contains_key(header::ETAG));
    assert!(!response.headers().contains_key(header::ACCEPT_RANGES));
    assert!(!response.headers().contains_key(header::CONTENT_RANGE));
    assert!(!response.headers().contains_key("x-amz-version-id"));
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "contact [REDACTED_EMAIL]\n"
    );
    assert!(
        std::fs::read_dir(&spool_dir).unwrap().next().is_none(),
        "staged ciphertext must be removed after replay"
    );
}

#[tokio::test]
async fn transformed_read_rejects_range_part_head_encoding_and_unknown_format() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state.store.put(
        "read",
        "good.txt",
        Bytes::from_static(b"secret"),
        "text/plain",
    );
    state.store.put(
        "read",
        "unknown.bin",
        Bytes::from_static(b"alice@example.com"),
        "application/octet-stream",
    );
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state);
    for (method, uri, extra_header) in [
        ("GET", "/read/good.txt", Some((header::RANGE, "bytes=0-1"))),
        ("GET", "/read/good.txt?partNumber=1", None),
        ("HEAD", "/read/good.txt", None),
        ("GET", "/read/unknown.bin", None),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-s4-process", "read");
        if let Some((name, value)) = extra_header {
            request = request.header(name, value);
        }
        let response = app
            .clone()
            .oneshot(add_headers(
                request.body(Body::empty()).unwrap(),
                &auth_headers(&ak, &sk),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        if method != "HEAD" {
            assert!(String::from_utf8_lossy(&body).contains("<Code>InvalidRequest</Code>"));
        }
        assert!(!String::from_utf8_lossy(&body).contains("alice@example.com"));
    }
}

#[tokio::test]
async fn unsafe_transformed_read_refuses_unavailable_staging_without_disclosure() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state_mut.spool_config.max_object_bytes = 4;
    state_mut.spool_quota = Arc::new(SpoolQuota::new(4));
    state.store.put(
        "read",
        "large.txt",
        Bytes::from_static(b"alice@example.com"),
        "text/plain",
    );
    let (ak, sk) = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/large.txt")
                .header("x-s4-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>ServiceUnavailable</Code>"));
    assert!(!String::from_utf8_lossy(&body).contains("alice@example.com"));
}

#[tokio::test]
async fn unsafe_transformed_failures_never_disclose_early_late_or_finish_output() {
    for (name, payload, stable_fields, later_filter, status) in [
        (
            "early reject",
            "reject sensitive-source",
            None,
            false,
            StatusCode::BAD_REQUEST,
        ),
        (
            "later reject",
            "reject sensitive-source",
            None,
            true,
            StatusCode::BAD_REQUEST,
        ),
        (
            "transform trap",
            "trap sensitive-source",
            None,
            false,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "finish trap",
            "safe-before-finish",
            Some("finish-trap"),
            false,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ] {
        let state = unsafe_transformed_test_state(later_filter).await;
        state
            .store
            .put("read", "failure.txt", payload, "text/plain");
        let (ak, sk) = make_key(&state).await;
        let mut request = Request::builder()
            .method("GET")
            .uri("/read/failure.txt")
            .header("x-s4-process", "read");
        if let Some(stable_fields) = stable_fields {
            request = request.header("x-s4-stable-fields", stable_fields);
        }
        let response = build_router(state)
            .oneshot(add_headers(
                request.body(Body::empty()).unwrap(),
                &auth_headers(&ak, &sk),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{name}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&body).contains(payload),
            "{name} disclosed source bytes: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn unsafe_transformed_source_limit_has_no_disclosure() {
    let mut state = unsafe_transformed_test_state(false).await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .source_body_limits = BodyLimits {
        max_frame_bytes: 4,
        max_bytes: 4,
    };
    state.store.put("read", "limit.txt", "12345", "text/plain");
    let (ak, sk) = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/limit.txt")
                .header("x-s4-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("12345"));
}

#[tokio::test]
async fn empty_prefix_safe_snapshot_streams_without_length_or_staging() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = false;
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    state.store.put(
        "read",
        "direct.txt",
        Bytes::from_static(b"one\ntwo\n"),
        "text/plain",
    );
    let (ak, sk) = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/direct.txt")
                .header("x-s4-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
    assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "one\ntwo\n"
    );
}

#[tokio::test]
async fn legacy_demo_paths_are_gone_without_storage_or_plaintext() {
    let (app, state) = router().await;
    let plaintext = "legacy-user@example.com";

    let store = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/demo/store")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"records":[{{"email":"{plaintext}"}}]}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(store.status(), StatusCode::GONE);
    assert_demo_security_headers(&store);
    let body = axum::body::to_bytes(store.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains(plaintext));
    assert!(state.store.list_keys().is_empty());

    let read = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/api/demo/read?id=1&mode=raw")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::GONE);
    assert_demo_security_headers(&read);
    let body = axum::body::to_bytes(read.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains(plaintext));
    assert!(state.store.list_keys().is_empty());

    let process = post_demo_process(
        &app,
        serde_json::json!({
            "records": [{"email": plaintext}],
            "mode": "safe"
        }),
    )
    .await;
    assert_eq!(process.status(), StatusCode::OK);
    assert_demo_response_headers(&process);
    let process = demo_response_json(process).await;
    let processed: serde_json::Value =
        serde_json::from_str(process["records"][0]["body"].as_str().unwrap()).unwrap();
    assert_eq!(processed["email"], "[REDACTED_EMAIL]");
    assert!(state.store.list_keys().is_empty());
}

#[tokio::test]
async fn legacy_demo_tombstones_handle_every_method_before_cors_and_s3() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    let plaintext = "must-not-be-stored@example.com";

    for base_path in ["/dashboard/api/demo/store", "/dashboard/api/demo/read"] {
        for (method, query) in [
            ("CONNECT", "transport=legacy"),
            ("DELETE", "versionId=legacy"),
            ("GET", "id=1&mode=raw"),
            ("HEAD", "id=1&mode=raw"),
            ("OPTIONS", "preflight=legacy"),
            ("PATCH", "mode=raw"),
            ("POST", "uploads"),
            ("PUT", "overwrite=true"),
            ("TRACE", "mode=raw"),
        ] {
            let path = format!("{base_path}?{query}");
            let mut request = Request::builder()
                .method(method)
                .uri(path.as_str())
                .header(header::CONTENT_TYPE, "text/plain");
            if method == "OPTIONS" {
                request = request
                    .header(header::ORIGIN, "https://example.test")
                    .header("access-control-request-method", "POST");
            }
            let response = app
                .clone()
                .oneshot(add_headers(
                    request.body(Body::from(plaintext)).unwrap(),
                    &auth_headers(&access_key, &secret_key),
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::GONE,
                "method: {method}, path: {path}"
            );
            assert_demo_security_headers(&response);
            if method == "OPTIONS" {
                assert!(
                    !response
                        .headers()
                        .contains_key("access-control-allow-origin")
                );
            }
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(body.is_empty(), "method: {method}, path: {path}");
            assert!(!String::from_utf8_lossy(&body).contains(plaintext));
            assert!(state.store.list_keys().is_empty());
        }
    }

    let cors = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/dashboard/api/demo/process")
                .header(header::ORIGIN, "https://example.test")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cors.status(), StatusCode::OK);
    assert_eq!(cors.headers()["access-control-allow-origin"], "*");
}
