//! S3 front door integration tests: filter roundtrip, listing, bucket
//! rejection, multipart, and SigV4 verification.
//!
//! These build the real gateway state (in-memory keystore + MemoryStore) via
//! `build_state`, so the Wasm filter component must exist first
//! (`just build-filters`).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use s4_gateway::control::NoopControlPlane;
use s4_gateway::key_cipher::default_wrapping;
use s4_gateway::server::{AppState, build_router, build_state};
use s4_gateway::store::FileKeyStore;
use std::sync::Arc;
use tower::ServiceExt;

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
