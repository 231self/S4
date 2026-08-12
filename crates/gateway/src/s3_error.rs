use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

fn s3_error_xml(
    code: &str,
    message: &str,
    key: &str,
    status: StatusCode,
) -> axum::response::Response {
    let request_id = Uuid::new_v4();
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>{code}</Code>
  <Message>{message}</Message>
  <Key>{key}</Key>
  <RequestId>{request_id}</RequestId>
</Error>"#
    );
    axum::response::Response::builder()
        .status(status)
        .header("Content-Type", "application/xml")
        .body(axum::body::Body::from(body))
        .unwrap()
        .into_response()
}

pub fn no_such_key(key: &str) -> axum::response::Response {
    s3_error_xml(
        "NoSuchKey",
        "The specified key does not exist.",
        key,
        StatusCode::NOT_FOUND,
    )
}

pub fn internal_error(key: &str, detail: &str) -> axum::response::Response {
    s3_error_xml(
        "InternalError",
        &format!("We encountered an internal error: {detail}"),
        key,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

pub fn not_implemented(key: &str) -> axum::response::Response {
    s3_error_xml(
        "NotImplemented",
        "This operation is not supported by the S4 gateway.",
        key,
        StatusCode::NOT_IMPLEMENTED,
    )
}

pub fn access_denied(key: &str) -> axum::response::Response {
    s3_error_xml("AccessDenied", "Access Denied", key, StatusCode::FORBIDDEN)
}

pub fn payment_required(key: &str, detail: &str) -> axum::response::Response {
    s3_error_xml("PaymentRequired", detail, key, StatusCode::PAYMENT_REQUIRED)
}
