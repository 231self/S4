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
use s4_gateway::control::{ControlPlane, NoopControlPlane, RequestKind, StreamingWriteMode};
use s4_gateway::key_cipher::default_wrapping;
use s4_gateway::object::BodyLimits;
use s4_gateway::server::{AppState, StreamingReadMode, build_router, build_state};
use s4_gateway::sigv4::SigV4Policy;
use s4_gateway::store::FileKeyStore;
use s4_gateway::transaction::SpoolQuota;
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
        _user_id: &str,
        _kind: RequestKind,
    ) -> Option<s4_gateway::control::BlockReason> {
        None
    }

    async fn record(&self, _user_id: &str, _kind: RequestKind, _bytes: u64) {}

    async fn streaming_write_mode(&self, _user_id: &str) -> Option<StreamingWriteMode> {
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
        // Load the built filter components so the full pipeline (including
        // stable-encrypt) is available for joinable-read tests.
        let components =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/components");
        std::env::set_var("S4_PLUGINS_DIR", components);
    }
    build_state(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
    )
    .await
    .expect("build_state")
}

async fn router() -> (Router, Arc<AppState>) {
    let state = test_state().await;
    (build_router(state.clone()), state)
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

async fn make_key(state: &Arc<AppState>) -> (String, String) {
    state
        .keys
        .create_key("test-user", "sigv4-test", 0, None)
        .await
        .expect("create test API key")
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
    state_mut.legacy_max_object_bytes = 4;
    state_mut.control = Arc::new(StreamingOffControl);
    let app = build_router(state.clone());
    let request = Request::builder()
        .method("PUT")
        .uri("/stream/tenant-off.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("12345"))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(state.store.get("stream", "tenant-off.txt").is_none());
}

#[tokio::test]
async fn unsupported_streaming_backend_is_rejected_without_polling_body() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_write_mode = StreamingWriteMode::Single;
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
async fn list_objects_returns_keys_and_prefixes() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    for key in ["logs/a.txt", "logs/b.txt", "meta.json"] {
        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("/bkt/{key}"))
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
async fn list_buckets_at_root() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/mybkt/obj")
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
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "2345"
    );

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
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );
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
                "attachment; filename=object.txt",
            )
            .header(header::CONTENT_LANGUAGE, "en")
            .header(header::CACHE_CONTROL, "private, max-age=60")
            .header(header::ETAG, "\"upstream-etag\"")
            .header(header::LAST_MODIFIED, "Wed, 19 Aug 2026 09:00:00 GMT")
            .header("x-amz-checksum-sha256", "checksum")
            .header("x-amz-version-id", "version-7")
            .header("connection", "x-upstream-private")
            .header("x-upstream-private", "remove-me")
            .header(header::ACCEPT_RANGES, "bytes");
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

    let app = axum::Router::new()
        .route("/object", axum::routing::get(object).head(object))
        .route("/redirect", axum::routing::get(redirect));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn real_router_streams_presigned_http_range_headers_and_rejects_redirects() {
    let (upstream, task) = spawn_presigned_upstream().await;
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.presigned_http_policy = PresignedHttpPolicy::new(
        ["127.0.0.1".to_string()],
        ["127.0.0.1".to_string()],
        true,
        Duration::ZERO,
        Arc::new(TokioAddressResolver),
    );
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
        (header::CACHE_CONTROL.as_str(), "private, max-age=60"),
        (header::ETAG.as_str(), "\"upstream-etag\""),
        ("x-amz-checksum-sha256", "checksum"),
        ("x-amz-version-id", "version-7"),
    ] {
        assert_eq!(response.headers()[name], expected, "header {name}");
    }
    assert!(!response.headers().contains_key("connection"));
    assert!(!response.headers().contains_key("x-upstream-private"));
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
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
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

    let signable =
        SignableRequest::new(method, uri, std::iter::empty(), SignableBody::Bytes(body)).unwrap();
    let output = sign(signable, &params).unwrap();
    let instructions = output.into_parts().0;

    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body.to_vec()))
        .unwrap();
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

#[tokio::test]
async fn sigv4_signed_request_accepted_and_rejected() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let uri = "http://s4.local/demo/signed.txt";

    // Correct signature → 200.
    let req = signed_request(&ak, &sk, "PUT", uri, b"hello world");
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
    let req = signed_request(&ak, "not-the-secret", "PUT", uri, b"hello world");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "tampered signature must fail"
    );

    // Unknown access key → 403.
    let req = signed_request("s4_unknown", &sk, "PUT", uri, b"hello world");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "unknown key must fail"
    );
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

    let request = signed_request(&access_key, &secret_key, "PUT", uri, input);
    let (mut parts, _) = request.into_parts();
    parts
        .headers
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
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
    let request = signed_request(&access_key, &secret_key, "PUT", bad_uri, input);
    let (mut parts, _) = request.into_parts();
    parts
        .headers
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
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
    let req = signed_request(&ak, &sk, "PUT", uri, b"content a@b.com");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET via SigV4 returns the filtered object.
    let req = signed_request(&ak, &sk, "GET", uri, b"");
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
    let req = signed_request(&ak, &sk, "PUT", uri, b"AAAA");
    let (mut parts, _old_body) = req.into_parts();
    parts
        .headers
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
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
    let signed = signed_request(&ak, "wrong-secret", "PUT", uri, b"sensitive body");
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
    let signed = signed_request(&ak, &sk, "PUT", uri, b"claimed body");
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
).put_object(Bucket="boto-bucket", Key="default.txt", Body=b"boto contact boto@example.com")
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
    let token = state.keys.create_mcp_token("mcp-user", "agent", 0).await;
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
    let t1 = state.keys.create_mcp_token("user-a", "agent", 0).await;
    let t2 = state.keys.create_mcp_token("user-b", "agent", 0).await;

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
async fn custom_legacy_body_limit_caps_put_and_passthrough_get() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .legacy_max_object_bytes = 8;
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/limits/custom.txt")
            .body(Body::from("123456789"))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>EntityTooLarge</Code>"));

    // The line-oriented pipeline appends a separator, so an input exactly at
    // the cap must still be rejected when transformed output exceeds it.
    let expanded = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/limits/expanded.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("12345678"))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(expanded).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>EntityTooLarge</Code>"));

    state.store.put(
        "limits",
        "upstream.txt",
        b"123456789".to_vec(),
        "text/plain",
    );
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/limits/upstream.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>EntityTooLarge</Code>"));
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
        response.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
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
async fn demo_transformed_read_modes_are_rejected() {
    let (app, _state) = router().await;

    // 1. Store two records sharing an email.
    let store = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/demo/store")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"records":[
                    {"email":"alice@example.com","card":"4111111111111111","note":"first"},
                    {"email":"alice@example.com","card":"4111111111111111","note":"second"}
                ]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(store.status(), StatusCode::OK);

    // 2. Raw read keeps PII.
    let raw = app
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
    let raw_body = axum::body::to_bytes(raw.into_body(), usize::MAX)
        .await
        .unwrap();
    let raw_text = String::from_utf8_lossy(&raw_body);
    assert!(
        raw_text.contains("alice@example.com"),
        "raw keeps PII: {raw_text}"
    );

    // 3. Safe and join modes are rejected before reading stored data.
    let safe = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/api/demo/read?id=1&mode=safe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(safe.status(), StatusCode::NOT_IMPLEMENTED);
    let safe_body = axum::body::to_bytes(safe.into_body(), usize::MAX)
        .await
        .unwrap();
    let safe_text = String::from_utf8_lossy(&safe_body);
    assert!(
        safe_text.contains("<Code>NotImplemented</Code>")
            && !safe_text.contains("alice@example.com"),
        "safe mode must fail without disclosure: {safe_text}"
    );

    // 4. Joinable reads are also unavailable until Phase 8.
    let j1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/api/demo/read?id=1&mode=join")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(j1.status(), StatusCode::NOT_IMPLEMENTED);
    let j2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/api/demo/read?id=2&mode=join")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(j2.status(), StatusCode::NOT_IMPLEMENTED);
    let t1 = String::from_utf8_lossy(
        &axum::body::to_bytes(j1.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .to_string();
    let t2 = String::from_utf8_lossy(
        &axum::body::to_bytes(j2.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .to_string();
    assert!(
        !t1.contains("alice@example.com") && !t2.contains("alice@example.com"),
        "join leaks PII"
    );
    assert!(t1.contains("<Code>NotImplemented</Code>"), "{t1}");
    assert!(t2.contains("<Code>NotImplemented</Code>"), "{t2}");
}
