use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use bytes::Bytes;
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use s4_gateway::object::{BodyLimits, ObjectMetadata, OpenedObject};

const GIB: u64 = 1024 * 1024 * 1024;
const FRAME_BYTES: usize = 64 * 1024;
const MAX_RSS_GROWTH: u64 = 128 * 1024 * 1024;

#[derive(Debug)]
struct GeneratedBody {
    remaining: u64,
}

impl http_body::Body for GeneratedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let len = self.remaining.min(FRAME_BYTES as u64) as usize;
        self.remaining -= len as u64;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![0x53; len])))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

fn peak_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the provided rusage on success, and the
    // pointer is valid for the duration of the call.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(result, 0, "getrusage failed");
    // SAFETY: the successful getrusage call initialized the value.
    let usage = unsafe { usage.assume_init() };
    #[cfg(target_os = "macos")]
    {
        usage.ru_maxrss as u64
    }
    #[cfg(not(target_os = "macos"))]
    {
        usage.ru_maxrss as u64 * 1024
    }
}

#[tokio::test(flavor = "current_thread")]
async fn one_gib_source_has_fixed_rss_and_exact_counters() {
    let before = peak_rss_bytes();
    let object = OpenedObject::new(
        axum::http::StatusCode::OK,
        ObjectMetadata::default(),
        Body::new(GeneratedBody { remaining: GIB }),
        BodyLimits {
            max_frame_bytes: FRAME_BYTES,
            max_bytes: GIB,
        },
    );
    let counters = object.counters.clone();
    let mut body = object.body;
    let mut consumed = 0_u64;
    while let Some(frame) = body.frame().await {
        consumed += frame.unwrap().into_data().unwrap().len() as u64;
    }
    let after = peak_rss_bytes();

    assert_eq!(consumed, GIB);
    assert_eq!(counters.bytes(), GIB);
    assert_eq!(counters.frames(), GIB / FRAME_BYTES as u64);
    assert!(
        after.saturating_sub(before) <= MAX_RSS_GROWTH,
        "1 GiB stream grew peak RSS by {} MiB (limit {} MiB)",
        after.saturating_sub(before) / (1024 * 1024),
        MAX_RSS_GROWTH / (1024 * 1024),
    );
}
