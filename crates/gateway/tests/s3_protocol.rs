use axum::http::StatusCode;
use s4_gateway::s3_error;

fn body_of(resp: axum::response::Response) -> String {
    let body = resp.into_body();
    let bytes = pollster::block_on(axum::body::to_bytes(body, 1024 * 1024)).unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn status_of(resp: &axum::response::Response) -> StatusCode {
    resp.status()
}

#[test]
fn s3_no_such_key_returns_404_xml() {
    let resp = s3_error::no_such_key("my-object.json");
    assert_eq!(status_of(&resp), StatusCode::NOT_FOUND);
    let body = body_of(resp);
    assert!(body.contains("<Code>NoSuchKey</Code>"));
    assert!(body.contains("<Key>my-object.json</Key>"));
    assert!(body.contains("<?xml version=\"1.0\""));
}

#[test]
fn s3_internal_error_returns_500_xml() {
    let resp = s3_error::internal_error("test-key", "something broke");
    assert_eq!(status_of(&resp), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_of(resp);
    assert!(body.contains("<Code>InternalError</Code>"));
    assert!(body.contains("something broke"));
}

#[test]
fn s3_not_implemented_returns_501() {
    let resp = s3_error::not_implemented("bucket/key");
    assert_eq!(status_of(&resp), StatusCode::NOT_IMPLEMENTED);
    let body = body_of(resp);
    assert!(body.contains("<Code>NotImplemented</Code>"));
}

#[test]
fn s3_access_denied_returns_403() {
    let resp = s3_error::access_denied("secret-key");
    assert_eq!(status_of(&resp), StatusCode::FORBIDDEN);
    let body = body_of(resp);
    assert!(body.contains("<Code>AccessDenied</Code>"));
}

#[test]
fn s3_error_xml_is_well_formed() {
    for error_fn in [
        s3_error::no_such_key as fn(&str) -> _,
        |k| s3_error::internal_error(k, "detail"),
        s3_error::not_implemented as fn(&str) -> _,
        s3_error::access_denied as fn(&str) -> _,
    ] {
        let body = body_of(error_fn("test-key"));
        let tag = body
            .lines()
            .find(|l| l.contains("<Code>"))
            .map(|l| l.trim().to_string())
            .unwrap_or_default();
        assert!(
            body.starts_with("<?xml"),
            "{tag}: XML must start with declaration: {body}"
        );
        assert!(body.contains("<Error>"), "{tag}: must contain Error");
        assert!(body.contains("</Error>"), "{tag}: must close Error");
        assert!(
            body.contains("<RequestId>"),
            "{tag}: must contain RequestId"
        );
    }
}

#[test]
fn s3_error_has_content_type_header() {
    let resp = s3_error::no_such_key("k");
    assert_eq!(
        resp.headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok()),
        Some("application/xml")
    );
}

#[test]
fn s3_error_contains_key_in_xml() {
    let body = body_of(s3_error::internal_error("key-name-123", "detail"));
    assert!(body.contains("<Key>key-name-123</Key>"));
}

#[test]
fn s3_error_request_ids_are_unique() {
    let b1 = body_of(s3_error::no_such_key("k1"));
    let b2 = body_of(s3_error::no_such_key("k2"));
    let id1 = b1.lines().find(|l| l.contains("<RequestId>")).unwrap();
    let id2 = b2.lines().find(|l| l.contains("<RequestId>")).unwrap();
    assert_ne!(id1, id2, "each error must have a unique RequestId");
}

#[test]
fn s3_error_request_id_is_uuid4() {
    let b = body_of(s3_error::no_such_key("k"));
    let id = b
        .lines()
        .find(|l| l.contains("<RequestId>"))
        .unwrap()
        .trim()
        .strip_prefix("<RequestId>")
        .unwrap()
        .strip_suffix("</RequestId>")
        .unwrap();
    assert_eq!(id.len(), 36, "UUIDv4 must be 36 chars, got {id}");
    assert_eq!(
        id.chars().nth(14),
        Some('4'),
        "UUIDv4 must have version 4 at index 14"
    );
}

#[test]
fn s3_error_status_codes_match_aws_spec() {
    assert_eq!(
        status_of(&s3_error::no_such_key("k")),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status_of(&s3_error::internal_error("k", "d")),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        status_of(&s3_error::not_implemented("k")),
        StatusCode::NOT_IMPLEMENTED
    );
    assert_eq!(
        status_of(&s3_error::access_denied("k")),
        StatusCode::FORBIDDEN
    );
}
