use axum::http::{HeaderValue, StatusCode, header};
use uuid::Uuid;

use crate::object::harden_object_response_headers;

const MAX_S3_ERROR_FIELD_BYTES: usize = 1024;

fn bounded_field(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_S3_ERROR_FIELD_BYTES));
    for character in value.chars() {
        if output.len() + character.len_utf8() > MAX_S3_ERROR_FIELD_BYTES {
            break;
        }
        output.push(character);
    }
    output
}

fn push_xml_text(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            '\t'
            | '\n'
            | '\r'
            | '\u{20}'..='\u{d7ff}'
            | '\u{e000}'..='\u{fffd}'
            | '\u{10000}'..='\u{10ffff}' => output.push(character),
            _ => output.push('\u{fffd}'),
        }
    }
}

fn push_xml_element(output: &mut String, name: &'static str, value: &str) {
    output.push_str("  <");
    output.push_str(name);
    output.push('>');
    push_xml_text(output, value);
    output.push_str("</");
    output.push_str(name);
    output.push_str(">\n");
}

fn s3_error_body(code: &str, message: &str, resource: &str, request_id: &str) -> String {
    let mut body = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error>\n");
    push_xml_element(&mut body, "Code", &bounded_field(code));
    push_xml_element(&mut body, "Message", &bounded_field(message));
    push_xml_element(&mut body, "Key", &bounded_field(resource));
    push_xml_element(&mut body, "RequestId", request_id);
    body.push_str("</Error>");
    body
}

fn s3_error_xml(
    code: &str,
    message: &str,
    resource: &str,
    status: StatusCode,
) -> axum::response::Response {
    let request_id = Uuid::new_v4().to_string();
    let body = s3_error_body(code, message, resource, &request_id);
    let mut response = axum::response::Response::new(axum::body::Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    harden_object_response_headers(response.headers_mut());
    response
}

pub fn no_such_key(key: &str) -> axum::response::Response {
    s3_error_xml(
        "NoSuchKey",
        "The specified key does not exist.",
        key,
        StatusCode::NOT_FOUND,
    )
}

pub fn internal_error(key: &str, _detail: &str) -> axum::response::Response {
    s3_error_xml(
        "InternalError",
        "We encountered an internal error.",
        key,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

pub fn transformed_read_not_supported(key: &str) -> axum::response::Response {
    s3_error_xml(
        "NotImplemented",
        "Transformed reads are disabled until the streaming disclosure model is available.",
        key,
        StatusCode::NOT_IMPLEMENTED,
    )
}

pub fn entity_too_large(key: &str) -> axum::response::Response {
    s3_error_xml(
        "EntityTooLarge",
        "The object exceeds the maximum allowed size.",
        key,
        StatusCode::BAD_REQUEST,
    )
}

pub fn multipart_not_supported(key: &str) -> axum::response::Response {
    s3_error_xml(
        "NotImplemented",
        "Multipart operations are disabled until staged multipart storage is available.",
        key,
        StatusCode::NOT_IMPLEMENTED,
    )
}

pub fn not_implemented(key: &str) -> axum::response::Response {
    s3_error_xml(
        "NotImplemented",
        "This operation is not supported by the Maskura Gateway.",
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

pub fn no_such_upload(key: &str) -> axum::response::Response {
    s3_error_xml(
        "NoSuchUpload",
        "The specified multipart upload does not exist.",
        key,
        StatusCode::NOT_FOUND,
    )
}

pub fn invalid_part(key: &str, detail: &str) -> axum::response::Response {
    s3_error_xml("InvalidPart", detail, key, StatusCode::BAD_REQUEST)
}

pub fn invalid_part_order(key: &str) -> axum::response::Response {
    s3_error_xml(
        "InvalidPartOrder",
        "The list of parts was not in ascending order.",
        key,
        StatusCode::BAD_REQUEST,
    )
}

pub fn signature_mismatch(key: &str) -> axum::response::Response {
    s3_error_xml(
        "SignatureDoesNotMatch",
        "The request signature we calculated does not match the signature you provided.",
        key,
        StatusCode::FORBIDDEN,
    )
}

pub fn bad_digest(key: &str, detail: &str) -> axum::response::Response {
    s3_error_xml("BadDigest", detail, key, StatusCode::BAD_REQUEST)
}

pub fn invalid_request(key: &str, detail: &str) -> axum::response::Response {
    s3_error_xml("InvalidRequest", detail, key, StatusCode::BAD_REQUEST)
}

pub fn invalid_range(key: &str, object_length: u64) -> axum::response::Response {
    let mut response = s3_error_xml(
        "InvalidRange",
        "The requested range is not satisfiable.",
        key,
        StatusCode::RANGE_NOT_SATISFIABLE,
    );
    let value = HeaderValue::from_str(&format!("bytes */{object_length}"))
        .expect("numeric object length is a valid Content-Range");
    response.headers_mut().insert(header::CONTENT_RANGE, value);
    response
}

pub fn slow_down(key: &str) -> axum::response::Response {
    s3_error_xml(
        "SlowDown",
        "Please reduce your request rate.",
        key,
        StatusCode::SERVICE_UNAVAILABLE,
    )
}

pub fn service_unavailable(key: &str, detail: &str) -> axum::response::Response {
    s3_error_xml(
        "ServiceUnavailable",
        detail,
        key,
        StatusCode::SERVICE_UNAVAILABLE,
    )
}

pub fn bucket_not_allowed(bucket: &str) -> axum::response::Response {
    s3_error_xml(
        "AccessDenied",
        "Bucket creation and deletion are not allowed on the Maskura Gateway; use an existing bucket on a configured backend.",
        bucket,
        StatusCode::FORBIDDEN,
    )
}

#[cfg(test)]
mod tests {
    use super::{MAX_S3_ERROR_FIELD_BYTES, internal_error, s3_error_body};
    use http_body_util::BodyExt as _;

    #[test]
    fn every_dynamic_error_field_is_xml_text_not_markup() {
        let body = s3_error_body(
            "Bad</Code><Injected code=\"1\">",
            "message & </Message><Injected message='1'>",
            "bucket/<Injected>resource</Injected>&\"'\u{1}",
            "request</RequestId><Injected request=\"1\">",
        );
        let elements: Vec<_> = xmlparser::Tokenizer::from(body.as_str())
            .map(|token| token.expect("generated error must be well-formed XML"))
            .filter_map(|token| match token {
                xmlparser::Token::ElementStart { local, .. } => Some(local.as_str().to_string()),
                _ => None,
            })
            .collect();

        assert_eq!(elements, ["Error", "Code", "Message", "Key", "RequestId"]);
        assert!(!body.contains("<Injected"));
        assert!(body.contains("Bad&lt;/Code&gt;&lt;Injected code=&quot;1&quot;&gt;"));
        assert!(body.contains("message &amp; &lt;/Message&gt;"));
        assert!(
            body.contains("bucket/&lt;Injected&gt;resource&lt;/Injected&gt;&amp;&quot;&apos;�")
        );
        assert!(body.contains("request&lt;/RequestId&gt;&lt;Injected request=&quot;1&quot;&gt;"));
    }

    #[tokio::test]
    async fn dynamic_fields_are_globally_bounded_and_internal_detail_is_opaque() {
        let secret = "PRINTABLE_GRANTED_SECRET";
        let response = internal_error(&"k".repeat(4096), &format!("{secret}{}", "x".repeat(4096)));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains(secret));
        assert!(body.contains("We encountered an internal error."));
        assert!(body.len() < MAX_S3_ERROR_FIELD_BYTES + 512);
    }
}
