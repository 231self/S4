//! Extension point for the SaaS control plane.
//!
//! The engine is policy-free: it proxies S3 requests through the Wasm
//! pipeline and authenticates via API keys. Authorization (rate limits,
//! quotas, billing) and usage metering are injected through [`ControlPlane`].
//! The OSS self-host binary uses [`NoopControlPlane`]; the hosted SaaS
//! implements this trait to add workspaces, metering, and billing.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::workspace_storage::WorkspaceId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedRequestContext {
    pub user_id: String,
    pub workspace_id: WorkspaceId,
}

/// Kind of S3 operation, for metering and authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    Write,
    Read,
}

impl RequestKind {
    /// Canonical lowercase name used in durable usage evidence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Read => "read",
        }
    }
}

/// Canonical S3 route that produced a usage receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UsageRoute {
    PutObject,
    GetObject,
    HeadObject,
    ListObjects,
    DeleteObject,
    AbortMultipartUpload,
    CompleteMultipartUpload,
}

impl UsageRoute {
    /// Canonical S3 method name used in durable usage evidence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PutObject => "PutObject",
            Self::GetObject => "GetObject",
            Self::HeadObject => "HeadObject",
            Self::ListObjects => "ListObjects",
            Self::DeleteObject => "DeleteObject",
            Self::AbortMultipartUpload => "AbortMultipartUpload",
            Self::CompleteMultipartUpload => "CompleteMultipartUpload",
        }
    }
}

/// Canonical server-generated reservation request for one billable operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageAuthorization {
    operation_id: Uuid,
    receipt_id: Uuid,
    bucket: String,
    route: UsageRoute,
    kind: RequestKind,
    max_processed_bytes: u64,
}

impl UsageAuthorization {
    pub(crate) fn new(
        operation_id: Uuid,
        receipt_id: Uuid,
        bucket: impl Into<String>,
        route: UsageRoute,
        kind: RequestKind,
        max_processed_bytes: u64,
    ) -> Self {
        Self {
            operation_id,
            receipt_id,
            bucket: bucket.into(),
            route,
            kind,
            max_processed_bytes,
        }
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn route(&self) -> UsageRoute {
        self.route
    }

    pub fn kind(&self) -> RequestKind {
        self.kind
    }

    pub fn max_processed_bytes(&self) -> u64 {
        self.max_processed_bytes
    }
}

/// Immutable authorization facts selected before an operation can begin.
///
/// Protected request facts are copied from [`UsageAuthorization`]. The gateway
/// validates every returned grant against its request before using the grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationGrant {
    operation_id: Uuid,
    receipt_id: Uuid,
    occurred_at: DateTime<Utc>,
    rate_version: i32,
    bucket: String,
    route: UsageRoute,
    kind: RequestKind,
    max_processed_bytes: u64,
}

impl AuthorizationGrant {
    /// Create a grant for exactly the supplied gateway authorization request.
    pub fn new(
        authorization: &UsageAuthorization,
        occurred_at: DateTime<Utc>,
        rate_version: i32,
    ) -> Self {
        Self {
            operation_id: authorization.operation_id,
            receipt_id: authorization.receipt_id,
            occurred_at,
            rate_version,
            bucket: authorization.bucket.clone(),
            route: authorization.route,
            kind: authorization.kind,
            max_processed_bytes: authorization.max_processed_bytes,
        }
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }

    pub fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub fn rate_version(&self) -> i32 {
        self.rate_version
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn route(&self) -> UsageRoute {
        self.route
    }

    pub fn kind(&self) -> RequestKind {
        self.kind
    }

    pub fn max_processed_bytes(&self) -> u64 {
        self.max_processed_bytes
    }

    pub(crate) fn matches(&self, authorization: &UsageAuthorization) -> bool {
        self.operation_id == authorization.operation_id
            && self.receipt_id == authorization.receipt_id
            && self.bucket == authorization.bucket
            && self.route == authorization.route
            && self.kind == authorization.kind
            && self.max_processed_bytes == authorization.max_processed_bytes
    }
}

/// Typed control-plane authorization outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Granted(AuthorizationGrant),
    Blocked(BlockReason),
}

/// Durable, idempotent usage receipt submitted after a billable operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageEvent {
    /// Receipt idempotency key generated by the gateway.
    receipt_id: Uuid,
    /// Canonical server-derived parent operation identity.
    operation_id: Uuid,
    occurred_at: DateTime<Utc>,
    rate_version: i32,
    bucket: String,
    kind: RequestKind,
    route: UsageRoute,
    source_bytes: u64,
    output_bytes: u64,
    processed_bytes: u64,
    /// Immutable pipeline evidence for COGS accounting (revision, fingerprint,
    /// measured fuel and duration). `None` for operations without a filter
    /// pipeline.
    pipeline_evidence: Option<PipelineEvidence>,
}

/// COGS evidence for one operation's pipeline execution.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PipelineEvidence {
    /// Immutable revision identifier (relational revision UUID or `static`).
    pub revision: String,
    /// Canonical fingerprint of the executed chain.
    pub fingerprint: String,
    /// Component count/digests fingerprint for caching cost attribution.
    pub components: String,
    /// Measured guest fuel consumed, if the pipeline reported it.
    pub fuel_consumed: u64,
    /// Measured execution duration in milliseconds.
    pub duration_ms: u64,
    /// Spool mode (`none` or `encrypted`) for unsafe-read evidence.
    pub spool_mode: String,
}

impl UsageEvent {
    /// Derive a settlement event from the immutable authorization grant.
    pub fn from_grant(grant: &AuthorizationGrant, source_bytes: u64, output_bytes: u64) -> Self {
        Self {
            receipt_id: grant.receipt_id,
            operation_id: grant.operation_id,
            occurred_at: grant.occurred_at,
            rate_version: grant.rate_version,
            bucket: grant.bucket.clone(),
            kind: grant.kind,
            route: grant.route,
            source_bytes,
            output_bytes,
            processed_bytes: source_bytes.max(output_bytes),
            pipeline_evidence: None,
        }
    }

    /// Attach the immutable pipeline COGS evidence for this operation.
    pub fn with_pipeline_evidence(mut self, evidence: PipelineEvidence) -> Self {
        self.pipeline_evidence = Some(evidence);
        self
    }

    pub fn receipt_id(&self) -> Uuid {
        self.receipt_id
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub fn rate_version(&self) -> i32 {
        self.rate_version
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn kind(&self) -> RequestKind {
        self.kind
    }

    pub fn route(&self) -> UsageRoute {
        self.route
    }

    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    pub fn processed_bytes(&self) -> u64 {
        self.processed_bytes
    }

    pub fn pipeline_evidence(&self) -> Option<&PipelineEvidence> {
        self.pipeline_evidence.as_ref()
    }
}

/// Stable control-plane outcomes that the data plane can safely map to S3.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MeteringError {
    #[error("usage metering is unavailable")]
    Unavailable,
    #[error("usage event conflicts with an existing receipt")]
    IdempotencyConflict,
    #[error("usage event was rejected")]
    Rejected,
}

/// Stable authorization dependency failures that the data plane can safely map to S3.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorizationError {
    #[error("authorization is unavailable")]
    Unavailable,
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
/// before running a billable operation, [`ControlPlane::release`] after a
/// non-billable outcome, and [`ControlPlane::record`] after success.
#[async_trait]
pub trait ControlPlane: Send + Sync + 'static {
    /// Authorize an authenticated user/workspace context. Return an immutable
    /// grant, a policy block, or an error when authorization cannot decide.
    async fn authorize(
        &self,
        context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError>;

    /// Release a successful reservation when the operation did not become
    /// billable. Implementations must make exact replays idempotent.
    async fn release(
        &self,
        context: &AuthenticatedRequestContext,
        operation_id: Uuid,
    ) -> Result<(), AuthorizationError>;

    /// Durably record usage after a successful operation. The gateway supplies
    /// canonical route and byte counts, with `processed_bytes` equal to
    /// `max(source_bytes, output_bytes)`; HEAD, LIST, and DELETE report zeroes.
    /// Implementations must treat an exact replay of `event.receipt_id()` as
    /// success and reject conflicting reuse with
    /// [`MeteringError::IdempotencyConflict`].
    async fn record(
        &self,
        context: &AuthenticatedRequestContext,
        event: &UsageEvent,
    ) -> Result<(), MeteringError>;

    /// Optional tenant ceiling. `None` inherits the deployment ceiling; a
    /// tenant can only lower, never raise, the configured mode.
    async fn streaming_write_mode(
        &self,
        _context: &AuthenticatedRequestContext,
    ) -> Option<StreamingWriteMode> {
        None
    }
}

/// No-op control plane for the OSS self-host binary: authorizes everything,
/// records nothing.
#[derive(Debug, Default, Clone)]
pub struct NoopControlPlane;

#[async_trait]
impl ControlPlane for NoopControlPlane {
    async fn authorize(
        &self,
        _context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        Ok(AuthorizationDecision::Granted(AuthorizationGrant::new(
            authorization,
            Utc::now(),
            0,
        )))
    }

    async fn release(
        &self,
        _context: &AuthenticatedRequestContext,
        _operation_id: Uuid,
    ) -> Result<(), AuthorizationError> {
        Ok(())
    }

    async fn record(
        &self,
        _context: &AuthenticatedRequestContext,
        _event: &UsageEvent,
    ) -> Result<(), MeteringError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_authorizes_everything() {
        let cp = NoopControlPlane;
        let context = AuthenticatedRequestContext {
            user_id: "any-user".to_string(),
            workspace_id: WorkspaceId::new("workspace").unwrap(),
        };
        let write = UsageAuthorization::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "bucket",
            UsageRoute::PutObject,
            RequestKind::Write,
            64,
        );
        let read = UsageAuthorization::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "bucket",
            UsageRoute::GetObject,
            RequestKind::Read,
            64,
        );
        let AuthorizationDecision::Granted(write_grant) =
            cp.authorize(&context, &write).await.unwrap()
        else {
            panic!("no-op control plane blocked a write")
        };
        let AuthorizationDecision::Granted(read_grant) =
            cp.authorize(&context, &read).await.unwrap()
        else {
            panic!("no-op control plane blocked a read")
        };
        assert!(write_grant.matches(&write));
        assert!(read_grant.matches(&read));
        assert_eq!(write_grant.rate_version(), 0);
        assert_eq!(read_grant.rate_version(), 0);
        assert_eq!(cp.release(&context, write.operation_id()).await, Ok(()));
    }

    #[tokio::test]
    async fn noop_records_without_effect() {
        let cp = NoopControlPlane;
        let context = AuthenticatedRequestContext {
            user_id: "u".to_string(),
            workspace_id: WorkspaceId::new("workspace").unwrap(),
        };
        let authorization = UsageAuthorization::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "bucket",
            UsageRoute::PutObject,
            RequestKind::Write,
            67890,
        );
        let grant = AuthorizationGrant::new(&authorization, Utc::now(), 0);
        let event = UsageEvent::from_grant(&grant, 12345, 67890);
        assert_eq!(cp.record(&context, &event).await, Ok(()));
    }

    #[test]
    fn usage_event_preserves_grant_facts_and_pipeline_evidence() {
        let authorization = UsageAuthorization::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "bucket",
            UsageRoute::PutObject,
            RequestKind::Write,
            34,
        );
        let occurred_at = DateTime::parse_from_rfc3339("2026-08-31T12:34:56.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let grant = AuthorizationGrant::new(&authorization, occurred_at, 7);
        let pipeline_evidence = PipelineEvidence {
            revision: "revision-7".to_string(),
            fingerprint: "fingerprint".to_string(),
            components: "component-a,component-b".to_string(),
            fuel_consumed: 123,
            duration_ms: 45,
            spool_mode: "encrypted".to_string(),
        };
        let event = UsageEvent::from_grant(&grant, 12, 34)
            .with_pipeline_evidence(pipeline_evidence.clone());
        assert_eq!(event.processed_bytes(), 34);
        assert_eq!(event.operation_id(), authorization.operation_id());
        assert_eq!(event.receipt_id(), authorization.receipt_id());
        assert_eq!(event.occurred_at(), occurred_at);
        assert_eq!(event.rate_version(), 7);
        assert_eq!(event.route(), UsageRoute::PutObject);
        assert_eq!(event.kind(), RequestKind::Write);
        assert_eq!(event.bucket(), "bucket");
        assert_eq!(event.pipeline_evidence(), Some(&pipeline_evidence));
        assert_eq!(grant.max_processed_bytes(), 34);
    }

    #[test]
    fn grant_validation_rejects_swapped_request_facts() {
        let operation_id = Uuid::now_v7();
        let receipt_id = Uuid::now_v7();
        let request = UsageAuthorization::new(
            operation_id,
            receipt_id,
            "bucket",
            UsageRoute::PutObject,
            RequestKind::Write,
            64,
        );
        let grant = AuthorizationGrant::new(&request, Utc::now(), 1);
        for mismatch in [
            UsageAuthorization::new(
                Uuid::now_v7(),
                receipt_id,
                "bucket",
                UsageRoute::PutObject,
                RequestKind::Write,
                64,
            ),
            UsageAuthorization::new(
                operation_id,
                Uuid::now_v7(),
                "bucket",
                UsageRoute::PutObject,
                RequestKind::Write,
                64,
            ),
            UsageAuthorization::new(
                operation_id,
                receipt_id,
                "other",
                UsageRoute::PutObject,
                RequestKind::Write,
                64,
            ),
            UsageAuthorization::new(
                operation_id,
                receipt_id,
                "bucket",
                UsageRoute::GetObject,
                RequestKind::Write,
                64,
            ),
            UsageAuthorization::new(
                operation_id,
                receipt_id,
                "bucket",
                UsageRoute::PutObject,
                RequestKind::Read,
                64,
            ),
            UsageAuthorization::new(
                operation_id,
                receipt_id,
                "bucket",
                UsageRoute::PutObject,
                RequestKind::Write,
                63,
            ),
        ] {
            assert!(!grant.matches(&mismatch));
        }
    }

    #[test]
    fn blocked_decision_preserves_reason() {
        let reason = BlockReason::new("PaymentRequired", "out of credit");
        assert_eq!(
            AuthorizationDecision::Blocked(reason.clone()),
            AuthorizationDecision::Blocked(reason)
        );
    }

    #[test]
    fn block_reason_is_constructible() {
        let r = BlockReason::new("PaymentRequired", "out of credit");
        assert_eq!(r.code, "PaymentRequired");
        assert_eq!(r.message, "out of credit");
    }
}
