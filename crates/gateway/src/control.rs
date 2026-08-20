//! Extension point for the SaaS control plane.
//!
//! The engine is policy-free: it proxies S3 requests through the Wasm
//! pipeline and authenticates via API keys. Authorization (rate limits,
//! quotas, billing) and usage metering are injected through [`ControlPlane`].
//! The OSS self-host binary uses [`NoopControlPlane`]; the hosted SaaS
//! implements this trait to add workspaces, metering, and billing.

use async_trait::async_trait;

/// Kind of S3 operation, for metering and authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    Write,
    Read,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum StreamingWriteMode {
    #[default]
    Off,
    Single,
    All,
}

/// Why a request was blocked. `code` is S3-style, `message` is human-readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReason {
    pub code: &'static str,
    pub message: &'static str,
}

impl BlockReason {
    pub fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

/// SaaS control-plane seam. The engine calls [`ControlPlane::authorize`]
/// before running the pipeline and [`ControlPlane::record`] after a
/// successful operation.
#[async_trait]
pub trait ControlPlane: Send + Sync + 'static {
    /// Authorize a request for `user_id`. Return `Some(BlockReason)` to reject
    /// (e.g. 402 Payment Required), or `None` to allow.
    async fn authorize(&self, user_id: &str, kind: RequestKind) -> Option<BlockReason>;

    /// Record usage after a successful operation (`bytes` processed).
    async fn record(&self, user_id: &str, kind: RequestKind, bytes: u64);

    /// Optional tenant ceiling. `None` inherits the deployment ceiling; a
    /// tenant can only lower, never raise, the configured mode.
    async fn streaming_write_mode(&self, _user_id: &str) -> Option<StreamingWriteMode> {
        None
    }
}

/// No-op control plane for the OSS self-host binary: authorizes everything,
/// records nothing.
#[derive(Debug, Default, Clone)]
pub struct NoopControlPlane;

#[async_trait]
impl ControlPlane for NoopControlPlane {
    async fn authorize(&self, _user_id: &str, _kind: RequestKind) -> Option<BlockReason> {
        None
    }

    async fn record(&self, _user_id: &str, _kind: RequestKind, _bytes: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_authorizes_everything() {
        let cp = NoopControlPlane;
        assert_eq!(cp.authorize("any-user", RequestKind::Write).await, None);
        assert_eq!(cp.authorize("any-user", RequestKind::Read).await, None);
    }

    #[tokio::test]
    async fn noop_records_without_effect() {
        let cp = NoopControlPlane;
        cp.record("u", RequestKind::Write, 12345).await;
    }

    #[test]
    fn block_reason_is_constructible() {
        let r = BlockReason::new("PaymentRequired", "out of credit");
        assert_eq!(r.code, "PaymentRequired");
        assert_eq!(r.message, "out of credit");
    }
}
