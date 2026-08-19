use std::collections::BTreeMap;
use std::time::SystemTime;

use async_trait::async_trait;
use reqwest::{Method, Url};

use super::{ObjectDestination, StoredObjectMeta, UploadedPart};

/// One administrator-issued request in a multipart-presign transaction.
/// Request bodies and signed headers are immutable after issuance.
#[derive(Clone, Debug)]
pub struct PresignedOperation {
    pub method: Method,
    pub url: Url,
    pub headers: BTreeMap<String, String>,
    pub expires_at: SystemTime,
}

/// Preferred presigned destination contract. A single PUT URL cannot provide
/// the create/part/complete/abort recovery guarantees represented here.
#[async_trait]
pub trait MultipartPresignContract: Send + Sync {
    async fn create(
        &self,
        operation_id: uuid::Uuid,
        destination: &ObjectDestination,
        metadata: &BTreeMap<String, String>,
    ) -> anyhow::Result<PresignedOperation>;

    async fn upload_part(
        &self,
        operation_id: uuid::Uuid,
        destination: &ObjectDestination,
        upload_id: &str,
        part_number: i32,
        content_length: u64,
        checksum_sha256: &str,
    ) -> anyhow::Result<PresignedOperation>;

    async fn complete(
        &self,
        operation_id: uuid::Uuid,
        destination: &ObjectDestination,
        upload_id: &str,
        parts: &[UploadedPart],
    ) -> anyhow::Result<PresignedOperation>;

    async fn abort(
        &self,
        operation_id: uuid::Uuid,
        destination: &ObjectDestination,
        upload_id: &str,
    ) -> anyhow::Result<PresignedOperation>;

    async fn reconcile_completion(
        &self,
        operation_id: uuid::Uuid,
        destination: &ObjectDestination,
    ) -> anyhow::Result<Option<StoredObjectMeta>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presigned_operation_keeps_signed_request_material_explicit() {
        let operation = PresignedOperation {
            method: Method::PUT,
            url: Url::parse("https://objects.example/key?Expires=9999999999").unwrap(),
            headers: BTreeMap::from([("x-checksum".to_string(), "fixed".to_string())]),
            expires_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(9_999_999_999),
        };
        assert_eq!(operation.method, Method::PUT);
        assert_eq!(operation.headers["x-checksum"], "fixed");
    }
}
