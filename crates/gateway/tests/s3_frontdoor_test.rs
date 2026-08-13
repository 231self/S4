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

async fn make_key(state: &Arc<AppState>) -> (String, String) {
    state
        .keys
        .create_key("test-user", "sigv4-test", 0, None)
        .await
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
async fn multipart_upload_assembles_and_filters() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    // Initiate
    let init = add_headers(
        Request::builder()
            .method("POST")
            .uri("/bkt/big.txt?uploads")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(init).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("upload id in init XML")
        .to_string();

    // Upload part 1 (>= 5 MiB) and part 2 (last part, any size).
    let part1 = vec![b'a'; 5 * 1024 * 1024];
    let part2 = b"\ncontact b@c.com now".to_vec();
    for (n, data) in [(1, &part1), (2, &part2)] {
        let uri = format!("/bkt/big.txt?partNumber={n}&uploadId={upload_id}");
        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .body(Body::from(data.clone()))
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "upload part {n}");
        let etag = resp.headers().get("ETag").cloned();
        assert!(etag.is_some(), "part {n} must return an ETag");
    }

    // Complete
    let complete_xml = r#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"x"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"x"</ETag></Part></CompleteMultipartUpload>"#;
    let complete = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/bkt/big.txt?uploadId={upload_id}"))
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(complete_xml))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(complete).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "complete should succeed");

    // Read back: assembled bytes must have gone through the filter pipeline.
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bkt/big.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        body.len() >= part1.len() + part2.len() - 2,
        "assembled content preserved"
    );
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("[REDACTED_EMAIL]"),
        "filtered at complete: {text}"
    );
    assert!(!text.contains("b@c.com"), "raw email must not be stored");
}

#[tokio::test]
async fn multipart_abort_drops_parts() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let init = add_headers(
        Request::builder()
            .method("POST")
            .uri("/bkt/abort.txt?uploads")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(init).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap()
        .to_string();

    let abort = add_headers(
        Request::builder()
            .method("DELETE")
            .uri(format!("/bkt/abort.txt?uploadId={upload_id}"))
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(abort).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn multipart_too_small_part_rejected() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let init = add_headers(
        Request::builder()
            .method("POST")
            .uri("/bkt/small.txt?uploads")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(init).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    let upload_id = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap()
        .to_string();

    // Two tiny parts: the first must be >= 5 MiB, so Complete fails.
    for n in 1..=2 {
        let uri = format!("/bkt/small.txt?partNumber={n}&uploadId={upload_id}");
        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .body(Body::from("tiny"))
                .unwrap(),
            &hdrs,
        );
        assert_eq!(
            app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::OK
        );
    }
    let complete = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/bkt/small.txt?uploadId={upload_id}"))
            .body(Body::from(
                "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part><Part><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>",
            ))
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(complete).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("InvalidPart"));
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
    let (ak1, sk1) = state.keys.create_key("user-one", "ns-test", 0, None).await;
    let (ak2, sk2) = state.keys.create_key("user-two", "ns-test", 0, None).await;
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
    let (ak, sk) = state.keys.create_key("never-exp", "exp", 0, None).await;
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
async fn read_time_processing_scrubs_agent_output() {
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

    // GET with x-s4-process: read scrubs the output for agents.
    let get_scrubbed = add_headers(
        Request::builder()
            .method("GET")
            .uri("/rawbkt/doc.json")
            .header("x-s4-process", "read")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get_scrubbed).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let scrubbed = String::from_utf8_lossy(&body);
    assert!(
        scrubbed.contains("[REDACTED_EMAIL]"),
        "email scrubbed: {scrubbed}"
    );
    assert!(
        scrubbed.contains("[REDACTED_CARD]"),
        "card scrubbed: {scrubbed}"
    );
    assert!(
        !scrubbed.contains("alice@example.com"),
        "no raw PII leaks: {scrubbed}"
    );
    assert!(scrubbed.contains("note"), "non-PII preserved: {scrubbed}");
}

#[tokio::test]
async fn read_time_stable_encrypt_is_joinable() {
    // The joinable-read story: an agent reads two records through S4 with
    // x-s4-process: read AND x-s4-stable-fields set. Stable-encrypt (AES-SIV,
    // zero nonce) turns the join field into deterministic ciphertext: the same
    // email yields the same ciphertext across records, so the agent can JOIN
    // on it without ever seeing the plaintext.
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

    // Neither leaks the plaintext email.
    assert!(!ta.contains("alice@example.com"), "a leaks PII: {ta}");
    assert!(!tb.contains("alice@example.com"), "b leaks PII: {tb}");

    // The email field is present (stable-encrypted), not redacted away.
    assert!(ta.contains("email"), "a keeps the join field: {ta}");
    assert!(tb.contains("email"), "b keeps the join field: {tb}");

    // Deterministic: the ciphertext of the shared email is identical in both.
    let extract = |t: &str| {
        let v: serde_json::Value = serde_json::from_str(t).unwrap();
        v["email"].as_str().unwrap().to_string()
    };
    let ea = extract(&ta);
    let eb = extract(&tb);
    assert_eq!(ea, eb, "same value must join: '{ea}' vs '{eb}'");
    assert_ne!(ea, "alice@example.com", "must be ciphertext, not plaintext");
}

#[tokio::test]
async fn demo_store_read_safe_and_joinable() {
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

    // 3. Safe read redacts.
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
    let safe_body = axum::body::to_bytes(safe.into_body(), usize::MAX)
        .await
        .unwrap();
    let safe_text = String::from_utf8_lossy(&safe_body);
    assert!(
        safe_text.contains("[REDACTED_EMAIL]"),
        "safe redacts: {safe_text}"
    );

    // 4. Joinable read: same email ciphertext across both records, no leak.
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
    let email_of = |t: &str| -> String {
        let brace = t.find('{').unwrap_or(0);
        let v: serde_json::Value =
            serde_json::from_str(&t[brace..]).unwrap_or(serde_json::Value::Null);
        let body_str = v["body"].as_str().unwrap_or("{}");
        let body: serde_json::Value =
            serde_json::from_str(body_str).unwrap_or(serde_json::Value::Null);
        body["email"].as_str().unwrap_or("").to_string()
    };
    let e1 = email_of(&t1);
    let e2 = email_of(&t2);
    assert_eq!(e1, e2, "joinable emails must match: '{e1}' vs '{e2}'");
    assert_ne!(e1, "alice@example.com", "must be ciphertext");
}
