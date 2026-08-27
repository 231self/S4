use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use bytes::Bytes;
use http_body::{Frame, SizeHint};
use s4_wasm_runtime::CancellationToken;

pub const DEFAULT_MAX_SOURCE_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_SOURCE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

const OBJECT_DOWNLOAD_CSP: &str =
    "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'";

pub(crate) fn harden_object_response_headers(headers: &mut HeaderMap) {
    headers.remove(header::AGE);
    headers.remove(header::EXPIRES);
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(OBJECT_DOWNLOAD_CSP),
    );
}

/// Keep only object representation and S3-compatible response metadata from an
/// untrusted presigned HTTP backend.
pub(crate) fn filter_presigned_response_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop_headers(headers);
    let blocked: Vec<HeaderName> = headers
        .keys()
        .filter(|name| !is_allowed_presigned_response_header(name))
        .cloned()
        .collect();
    for name in blocked {
        headers.remove(name);
    }
}

fn is_allowed_presigned_response_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    name.starts_with("x-amz-meta-")
        || name.starts_with("x-goog-meta-")
        || matches!(
            name,
            // Representation, range, and validator metadata. Backend cache
            // policy is intentionally excluded and replaced at the boundary.
            "accept-ranges"
                | "content-encoding"
                | "content-language"
                | "content-length"
                | "content-range"
                | "content-type"
                | "etag"
                | "last-modified"
                // S3 object metadata surfaced by GetObject/HeadObject.
                | "x-amz-archive-status"
                | "x-amz-checksum-crc32"
                | "x-amz-checksum-crc32c"
                | "x-amz-checksum-crc64nvme"
                | "x-amz-checksum-md5"
                | "x-amz-checksum-sha1"
                | "x-amz-checksum-sha256"
                | "x-amz-checksum-sha512"
                | "x-amz-checksum-type"
                | "x-amz-checksum-xxhash3"
                | "x-amz-checksum-xxhash64"
                | "x-amz-checksum-xxhash128"
                | "x-amz-delete-marker"
                | "x-amz-expiration"
                | "x-amz-missing-meta"
                | "x-amz-mp-parts-count"
                | "x-amz-object-lock-legal-hold"
                | "x-amz-object-lock-mode"
                | "x-amz-object-lock-retain-until-date"
                | "x-amz-replication-status"
                | "x-amz-request-charged"
                | "x-amz-restore"
                | "x-amz-server-side-encryption"
                | "x-amz-server-side-encryption-aws-kms-key-id"
                | "x-amz-server-side-encryption-bucket-key-enabled"
                | "x-amz-server-side-encryption-customer-algorithm"
                | "x-amz-server-side-encryption-customer-key-md5"
                | "x-amz-storage-class"
                | "x-amz-tagging-count"
                | "x-amz-version-id"
                | "x-amz-website-redirect-location"
                // GCS representation, version, and checksum metadata.
                | "x-goog-component-count"
                | "x-goog-custom-time"
                | "x-goog-encryption-algorithm"
                | "x-goog-encryption-key-sha256"
                | "x-goog-expiration"
                | "x-goog-generation"
                | "x-goog-hash"
                | "x-goog-metageneration"
                | "x-goog-object-lock-mode"
                | "x-goog-object-lock-retain-until-date"
                | "x-goog-storage-class"
                | "x-goog-stored-content-encoding"
                | "x-goog-stored-content-length"
        )
}

fn filter_object_response_trailers(trailers: &mut HeaderMap) {
    let blocked: Vec<HeaderName> = trailers
        .keys()
        .filter(|name| !is_allowed_object_response_trailer(name))
        .cloned()
        .collect();
    for name in blocked {
        trailers.remove(name);
    }
}

fn is_allowed_object_response_trailer(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "content-digest"
            | "content-md5"
            | "digest"
            | "repr-digest"
            | "x-amz-checksum-crc32"
            | "x-amz-checksum-crc32c"
            | "x-amz-checksum-crc64nvme"
            | "x-amz-checksum-md5"
            | "x-amz-checksum-sha1"
            | "x-amz-checksum-sha256"
            | "x-amz-checksum-sha512"
            | "x-amz-checksum-type"
            | "x-amz-checksum-xxhash3"
            | "x-amz-checksum-xxhash64"
            | "x-amz-checksum-xxhash128"
            | "x-goog-hash"
    )
}

#[derive(Clone, Debug, Default)]
pub struct ObjectMetadata {
    pub headers: HeaderMap,
    pub version_id: Option<String>,
}

impl ObjectMetadata {
    pub fn insert(&mut self, name: HeaderName, value: impl AsRef<str>) {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.insert(name, value);
        }
    }

    pub fn append(&mut self, name: HeaderName, value: impl AsRef<str>) {
        if let Ok(value) = HeaderValue::from_str(value.as_ref()) {
            self.headers.append(name, value);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BodyLimits {
    pub max_frame_bytes: usize,
    pub max_bytes: u64,
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_SOURCE_FRAME_BYTES,
            max_bytes: DEFAULT_MAX_SOURCE_BYTES,
        }
    }
}

#[derive(Debug, Default)]
struct CounterState {
    bytes: AtomicU64,
    frames: AtomicU64,
}

#[derive(Clone, Debug, Default)]
pub struct SourceCounters(Arc<CounterState>);

impl SourceCounters {
    pub fn bytes(&self) -> u64 {
        self.0.bytes.load(Ordering::Acquire)
    }

    pub fn frames(&self) -> u64 {
        self.0.frames.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub enum SourceError {
    FrameTooLarge { actual: usize, limit: usize },
    ObjectTooLarge { actual: u64, limit: u64 },
    Upstream(axum::Error),
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { actual, limit } => {
                write!(f, "source frame is {actual} bytes, limit is {limit}")
            }
            Self::ObjectTooLarge { actual, limit } => {
                write!(
                    f,
                    "source body is at least {actual} bytes, limit is {limit}"
                )
            }
            Self::Upstream(error) => write!(f, "upstream source error: {error}"),
        }
    }
}

impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Upstream(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct CountedBody {
    inner: Body,
    limits: BodyLimits,
    counters: SourceCounters,
    cancellation: CancellationToken,
    finished: bool,
}

impl CountedBody {
    pub fn new(
        inner: Body,
        limits: BodyLimits,
        counters: SourceCounters,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            inner,
            limits,
            counters,
            cancellation,
            finished: false,
        }
    }
}

impl http_body::Body for CountedBody {
    type Data = Bytes;
    type Error = SourceError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let frame_len = data.len();
                    if frame_len > self.limits.max_frame_bytes {
                        self.cancellation.cancel();
                        return Poll::Ready(Some(Err(SourceError::FrameTooLarge {
                            actual: frame_len,
                            limit: self.limits.max_frame_bytes,
                        })));
                    }
                    let total = self
                        .counters
                        .0
                        .bytes
                        .fetch_add(frame_len as u64, Ordering::AcqRel)
                        + frame_len as u64;
                    self.counters.0.frames.fetch_add(1, Ordering::AcqRel);
                    if total > self.limits.max_bytes {
                        self.cancellation.cancel();
                        return Poll::Ready(Some(Err(SourceError::ObjectTooLarge {
                            actual: total,
                            limit: self.limits.max_bytes,
                        })));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.cancellation.cancel();
                Poll::Ready(Some(Err(SourceError::Upstream(error))))
            }
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CountedBody {
    fn drop(&mut self) {
        if !self.finished {
            self.cancellation.cancel();
        }
    }
}

#[derive(Debug)]
pub struct OpenedObject {
    pub status: StatusCode,
    pub metadata: ObjectMetadata,
    pub body: Body,
    pub counters: SourceCounters,
    pub cancellation: CancellationToken,
}

impl OpenedObject {
    pub fn new(
        status: StatusCode,
        metadata: ObjectMetadata,
        body: Body,
        limits: BodyLimits,
    ) -> Self {
        let counters = SourceCounters::default();
        let cancellation = CancellationToken::new();
        let counted = CountedBody::new(body, limits, counters.clone(), cancellation.clone());
        Self {
            status,
            metadata,
            body: Body::new(counted),
            counters,
            cancellation,
        }
    }

    pub fn into_response(self) -> Response {
        let mut response = Response::builder().status(self.status);
        if let Some(headers) = response.headers_mut() {
            headers.extend(self.metadata.headers);
            harden_object_response_headers(headers);
        }
        response
            .body(Body::new(ObjectResponseBody { inner: self.body }))
            .expect("valid object response")
    }
}

#[derive(Debug)]
struct ObjectResponseBody {
    inner: Body,
}

impl http_body::Body for ObjectResponseBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_trailers() {
                Ok(mut trailers) => {
                    filter_object_response_trailers(&mut trailers);
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                }
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
            result => result,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Debug)]
pub struct ChunkedBytesBody {
    bytes: Bytes,
    offset: usize,
    frame_bytes: usize,
}

impl ChunkedBytesBody {
    pub fn new(bytes: Bytes, frame_bytes: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            frame_bytes: frame_bytes.max(1),
        }
    }
}

impl http_body::Body for ChunkedBytesBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.offset == self.bytes.len() {
            return Poll::Ready(None);
        }
        let end = self
            .offset
            .saturating_add(self.frame_bytes)
            .min(self.bytes.len());
        let data = self.bytes.slice(self.offset..end);
        self.offset = end;
        Poll::Ready(Some(Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact((self.bytes.len() - self.offset) as u64)
    }
}

pub fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
    let connection_extensions: Vec<HeaderName> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();

    for name in connection_extensions {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;

    use http_body::Body as _;
    use http_body_util::BodyExt;

    #[derive(Debug)]
    struct ScriptedBody {
        polls: Arc<AtomicUsize>,
        frames: VecDeque<Result<Frame<Bytes>, io::Error>>,
        hint: SizeHint,
    }

    impl http_body::Body for ScriptedBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(self.frames.pop_front())
        }

        fn size_hint(&self) -> SizeHint {
            self.hint
        }
    }

    fn opened(body: ScriptedBody) -> OpenedObject {
        OpenedObject::new(
            StatusCode::OK,
            ObjectMetadata::default(),
            Body::new(body),
            BodyLimits::default(),
        )
    }

    #[tokio::test]
    async fn construction_does_not_poll_and_counts_exact_data_frames() {
        let polls = Arc::new(AtomicUsize::new(0));
        let body = ScriptedBody {
            polls: polls.clone(),
            frames: VecDeque::from([
                Ok(Frame::data(Bytes::from_static(b"abc"))),
                Ok(Frame::data(Bytes::from_static(b"de"))),
            ]),
            hint: SizeHint::with_exact(5),
        };
        let object = opened(body);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(object.counters.bytes(), 0);
        assert_eq!(object.counters.frames(), 0);

        let counters = object.counters.clone();
        let bytes = object.body.collect().await.unwrap().to_bytes();
        assert_eq!(bytes, Bytes::from_static(b"abcde"));
        assert_eq!(counters.bytes(), 5);
        assert_eq!(counters.frames(), 2);
    }

    #[tokio::test]
    async fn response_trailers_keep_only_integrity_fields_and_preserve_size_hint() {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "x-amz-checksum-sha256",
            HeaderValue::from_static("checksum"),
        );
        trailers.insert("x-goog-hash", HeaderValue::from_static("crc32c=abcd"));
        trailers.insert("set-cookie", HeaderValue::from_static("attacker=1"));
        trailers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        trailers.insert("www-authenticate", HeaderValue::from_static("Basic"));
        trailers.insert("x-unknown", HeaderValue::from_static("attacker"));
        let body = ScriptedBody {
            polls: Arc::new(AtomicUsize::new(0)),
            frames: VecDeque::from([
                Ok(Frame::data(Bytes::from_static(b"data"))),
                Ok(Frame::trailers(trailers)),
            ]),
            hint: SizeHint::with_exact(4),
        };
        let mut body = opened(body).into_response().into_body();
        assert_eq!(body.size_hint().exact(), Some(4));
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"data")
        );
        let trailers = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert_eq!(trailers["x-amz-checksum-sha256"], "checksum");
        assert_eq!(trailers["x-goog-hash"], "crc32c=abcd");
        for dropped in [
            "set-cookie",
            "access-control-allow-origin",
            "www-authenticate",
            "x-unknown",
        ] {
            assert!(
                !trailers.contains_key(dropped),
                "trailer {dropped} survived"
            );
        }
    }

    #[tokio::test]
    async fn upstream_errors_remain_body_errors_and_cancel_source() {
        let body = ScriptedBody {
            polls: Arc::new(AtomicUsize::new(0)),
            frames: VecDeque::from([Err(io::Error::other("upstream exploded"))]),
            hint: SizeHint::default(),
        };
        let object = opened(body);
        let cancellation = object.cancellation.clone();
        let error = object.body.collect().await.unwrap_err();
        assert!(error.to_string().contains("upstream exploded"), "{error}");
        assert!(cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn dropping_unfinished_body_cancels_but_eof_does_not() {
        let body = ScriptedBody {
            polls: Arc::new(AtomicUsize::new(0)),
            frames: VecDeque::from([Ok(Frame::data(Bytes::from_static(b"one")))]),
            hint: SizeHint::with_exact(3),
        };
        let mut object = opened(body);
        let cancellation = object.cancellation.clone();
        let _ = object.body.frame().await;
        drop(object.body);
        assert!(cancellation.is_cancelled());

        let completed = opened(ScriptedBody {
            polls: Arc::new(AtomicUsize::new(0)),
            frames: VecDeque::new(),
            hint: SizeHint::with_exact(0),
        });
        let cancellation = completed.cancellation.clone();
        completed.body.collect().await.unwrap();
        assert!(!cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn chunked_bytes_keep_frame_memory_bounded_and_preserve_exact_length() {
        let bytes = Bytes::from(vec![b'x'; 1024 * 1024]);
        let body = Body::new(ChunkedBytesBody::new(bytes, 64 * 1024));
        let object = OpenedObject::new(
            StatusCode::OK,
            ObjectMetadata::default(),
            body,
            BodyLimits {
                max_frame_bytes: 64 * 1024,
                max_bytes: 1024 * 1024,
            },
        );
        assert_eq!(object.body.size_hint().exact(), Some(1024 * 1024));
        let counters = object.counters.clone();
        let collected = object.body.collect().await.unwrap().to_bytes();
        assert_eq!(collected.len(), 1024 * 1024);
        assert_eq!(counters.frames(), 16);
        assert_eq!(counters.bytes(), 1024 * 1024);
    }

    #[tokio::test]
    async fn oversized_source_frame_fails_and_cancels() {
        let body = Body::new(ScriptedBody {
            polls: Arc::new(AtomicUsize::new(0)),
            frames: VecDeque::from([Ok(Frame::data(Bytes::from_static(b"12345")))]),
            hint: SizeHint::with_exact(5),
        });
        let object = OpenedObject::new(
            StatusCode::OK,
            ObjectMetadata::default(),
            body,
            BodyLimits {
                max_frame_bytes: 4,
                max_bytes: 10,
            },
        );
        let cancellation = object.cancellation.clone();
        let error = object.body.collect().await.unwrap_err();
        assert!(error.to_string().contains("source frame is 5 bytes"));
        assert!(cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn cumulative_source_limit_fails_on_crossing_frame() {
        let body = Body::new(ScriptedBody {
            polls: Arc::new(AtomicUsize::new(0)),
            frames: VecDeque::from([
                Ok(Frame::data(Bytes::from_static(b"123"))),
                Ok(Frame::data(Bytes::from_static(b"45"))),
            ]),
            hint: SizeHint::with_exact(5),
        });
        let object = OpenedObject::new(
            StatusCode::OK,
            ObjectMetadata::default(),
            body,
            BodyLimits {
                max_frame_bytes: 4,
                max_bytes: 4,
            },
        );
        let counters = object.counters.clone();
        let cancellation = object.cancellation.clone();
        let error = object.body.collect().await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("source body is at least 5 bytes")
        );
        assert_eq!(counters.bytes(), 5);
        assert_eq!(counters.frames(), 2);
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn strips_standard_and_connection_nominated_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-private"),
        );
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-private", HeaderValue::from_static("secret"));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        strip_hop_by_hop_headers(&mut headers);
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-private"));
        assert_eq!(headers["content-type"], "text/plain");
    }

    #[test]
    fn presigned_response_headers_use_a_strict_allowlist() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        headers.insert("etag", HeaderValue::from_static("\"safe\""));
        headers.insert("cache-control", HeaderValue::from_static("public"));
        headers.insert("age", HeaderValue::from_static("600"));
        headers.insert(
            "expires",
            HeaderValue::from_static("Wed, 19 Aug 2026 10:00:00 GMT"),
        );
        headers.insert(
            "x-amz-meta-project",
            HeaderValue::from_static("safe-metadata"),
        );
        headers.insert("x-amz-version-id", HeaderValue::from_static("version-1"));
        headers.insert(
            "x-goog-meta-project",
            HeaderValue::from_static("safe-gcs-metadata"),
        );
        headers.insert("x-goog-generation", HeaderValue::from_static("123"));
        headers.insert(
            "x-goog-stored-content-length",
            HeaderValue::from_static("4"),
        );
        headers.insert("set-cookie", HeaderValue::from_static("attacker=1"));
        headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
        headers.insert(
            "location",
            HeaderValue::from_static("https://attacker.example"),
        );
        headers.insert("report-to", HeaderValue::from_static("attacker"));
        headers.insert("x-unknown-extension", HeaderValue::from_static("attacker"));
        headers.insert("connection", HeaderValue::from_static("x-amz-meta-project"));

        filter_presigned_response_headers(&mut headers);

        assert_eq!(headers["content-type"], "text/html");
        assert_eq!(headers["etag"], "\"safe\"");
        assert_eq!(headers["x-amz-version-id"], "version-1");
        assert_eq!(headers["x-goog-meta-project"], "safe-gcs-metadata");
        assert_eq!(headers["x-goog-generation"], "123");
        assert_eq!(headers["x-goog-stored-content-length"], "4");
        assert!(!headers.contains_key("x-amz-meta-project"));
        for dropped in [
            "cache-control",
            "age",
            "expires",
            "set-cookie",
            "access-control-allow-origin",
            "location",
            "report-to",
            "x-unknown-extension",
            "connection",
        ] {
            assert!(!headers.contains_key(dropped), "header {dropped} survived");
        }
    }

    #[test]
    fn opened_object_hardens_non_success_and_overrides_backend_values() {
        let mut metadata = ObjectMetadata::default();
        metadata.insert(header::CONTENT_TYPE, "text/html");
        metadata.insert(header::CONTENT_RANGE, "bytes 0-3/10");
        metadata.insert(
            header::CONTENT_DISPOSITION,
            "inline; filename=attacker.html",
        );
        metadata.insert(header::CACHE_CONTROL, "public, max-age=3600");
        metadata.insert(header::AGE, "600");
        metadata.insert(header::EXPIRES, "Wed, 19 Aug 2026 10:00:00 GMT");
        metadata.insert(HeaderName::from_static("x-content-type-options"), "off");
        metadata.insert(
            HeaderName::from_static("content-security-policy"),
            "default-src *",
        );
        let response = OpenedObject::new(
            StatusCode::NOT_FOUND,
            metadata,
            Body::from("data"),
            BodyLimits::default(),
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["content-type"], "text/html");
        assert_eq!(response.headers()["content-range"], "bytes 0-3/10");
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        assert!(!response.headers().contains_key("age"));
        assert!(!response.headers().contains_key("expires"));
        assert_eq!(response.headers()["content-disposition"], "attachment");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(
            response.headers()["content-security-policy"],
            OBJECT_DOWNLOAD_CSP
        );
    }
}
