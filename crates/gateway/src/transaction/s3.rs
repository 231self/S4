use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, ServerSideEncryption};
use bytes::{Buf, Bytes, BytesMut};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::s3_safety::record_s3_failure;

use super::{
    AbortSignal, BackendCapabilities, BackendError, CompletionProbe, DIRECT_PART_BYTES,
    DiscoveredMultipartPart, DiscoveredObjectVersion, DiscoveredUpload, EvidenceRecord,
    MultipartUploadInspection, ObjectDestination, ObjectSinkTransaction, OperationJournal,
    OperationRecord, OperationState, PartRecord, SinkCommitState, StoredObjectMeta,
    TransactionBackend, TransactionError, UploadedPart, sha256_hex, unix_time_ms,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S3ServerSideEncryption {
    Aes256,
}

impl S3ServerSideEncryption {
    fn sdk_value(self) -> ServerSideEncryption {
        match self {
            Self::Aes256 => ServerSideEncryption::Aes256,
        }
    }
}

#[derive(Clone)]
pub struct AwsS3TransactionBackend {
    client: Client,
    capabilities: BackendCapabilities,
    server_side_encryption: Option<S3ServerSideEncryption>,
    exact_version_recovery: bool,
}

impl AwsS3TransactionBackend {
    /// Capabilities are supplied by exact-provider configuration. They are not
    /// guessed from endpoints or error text.
    pub fn new(client: Client, capabilities: BackendCapabilities) -> Self {
        Self {
            client,
            capabilities,
            server_side_encryption: None,
            exact_version_recovery: false,
        }
    }

    /// Opt in to destination encryption without changing the default BYO path.
    pub fn with_server_side_encryption(mut self, encryption: S3ServerSideEncryption) -> Self {
        self.server_side_encryption = Some(encryption);
        self
    }

    /// Managed B2 writes require explicit AES-256 SSE and exact version recovery.
    pub fn new_managed_b2(client: Client, capabilities: BackendCapabilities) -> Self {
        Self::new(client, capabilities)
            .with_server_side_encryption(S3ServerSideEncryption::Aes256)
            .with_exact_version_recovery()
    }

    fn with_exact_version_recovery(mut self) -> Self {
        self.exact_version_recovery = true;
        self
    }

    fn encryption_matches(&self, actual: Option<&ServerSideEncryption>) -> bool {
        self.server_side_encryption
            .is_none_or(|expected| actual == Some(&expected.sdk_value()))
    }

    async fn resolve_exact_version_history(
        &self,
        operation: &OperationRecord,
        preferred_version_id: Option<&str>,
    ) -> Result<Option<StoredObjectMeta>, BackendError> {
        if !self.exact_version_recovery {
            return Ok(None);
        }
        let versions = self.inspect_object_versions(operation).await?;
        let candidate = match preferred_version_id {
            Some(preferred) => versions.iter().find(|version| {
                version.version_id == preferred
                    && version.operation_matches
                    && version.expected_metadata_matches
                    && version.encryption_matches
                    && !version.delete_marker
            }),
            None => versions.iter().find(|version| {
                version.is_latest
                    && version.operation_matches
                    && version.expected_metadata_matches
                    && version.encryption_matches
                    && !version.delete_marker
            }),
        };
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let superseded_version_ids = versions
            .iter()
            .filter(|version| {
                version.operation_matches
                    && !version.delete_marker
                    && version.version_id != candidate.version_id
            })
            .map(|version| version.version_id.clone())
            .collect();
        Ok(Some(StoredObjectMeta {
            etag: candidate.etag.clone(),
            version_id: Some(candidate.version_id.clone()),
            superseded_version_ids,
            version_history_complete: true,
        }))
    }

    async fn rewrite_completed_multipart_metadata(
        &self,
        operation: &OperationRecord,
        source_version_id: Option<&str>,
    ) -> Result<StoredObjectMeta, BackendError> {
        let size = operation.expected.size.ok_or_else(|| {
            BackendError::definitive("verified multipart output is missing an expected size")
        })?;
        if size == 0 {
            return Err(BackendError::definitive(
                "cannot rewrite a zero-byte multipart object",
            ));
        }

        let upload = self
            .client
            .create_multipart_upload()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .set_content_type(operation.expected.metadata.get("content-type").cloned())
            .set_metadata(Some(object_metadata(operation)))
            .set_server_side_encryption(self.server_side_encryption.map(|value| value.sdk_value()))
            .send()
            .await
            .map_err(|error| ambiguous("rewrite_create_multipart", &error))?;
        let upload_id = upload.upload_id().ok_or_else(|| {
            BackendError::ambiguous("metadata rewrite create-multipart response omitted upload ID")
        })?;
        if self.exact_version_recovery && source_version_id.is_none() {
            return Err(BackendError::ambiguous(
                "metadata rewrite source omitted its exact provider version ID",
            ));
        }
        let source = copy_source(operation, source_version_id);
        let part_size = DIRECT_PART_BYTES as u64;
        let part_count = size.div_ceil(part_size);
        if part_count > 10_000 {
            return Err(BackendError::definitive(
                "multipart object has too many parts",
            ));
        }
        let result = async {
            let mut parts =
                Vec::with_capacity(usize::try_from(part_count).map_err(|_| {
                    BackendError::definitive("multipart object has too many parts")
                })?);
            for part_number in 1..=part_count {
                let start = (part_number - 1) * part_size;
                let end = (start + part_size - 1).min(size - 1);
                let part_number = i32::try_from(part_number)
                    .map_err(|_| BackendError::definitive("multipart object has too many parts"))?;
                let output = self
                    .client
                    .upload_part_copy()
                    .bucket(&operation.destination.bucket)
                    .key(&operation.destination.physical_key)
                    .upload_id(upload_id)
                    .part_number(part_number)
                    .copy_source(&source)
                    .copy_source_range(format!("bytes={start}-{end}"))
                    .send()
                    .await
                    .map_err(|error| ambiguous("rewrite_upload_part_copy", &error))?;
                let etag = output
                    .copy_part_result()
                    .and_then(|result| result.e_tag())
                    .ok_or_else(|| {
                        BackendError::ambiguous(
                            "metadata rewrite upload-part-copy response omitted ETag",
                        )
                    })?;
                parts.push(
                    CompletedPart::builder()
                        .part_number(part_number)
                        .e_tag(etag)
                        .build(),
                );
            }
            let output = self
                .client
                .complete_multipart_upload()
                .bucket(&operation.destination.bucket)
                .key(&operation.destination.physical_key)
                .upload_id(upload_id)
                .multipart_upload(
                    CompletedMultipartUpload::builder()
                        .set_parts(Some(parts))
                        .build(),
                )
                .send()
                .await
                .map_err(|error| ambiguous("rewrite_complete_multipart", &error))?;
            let stored = StoredObjectMeta {
                etag: output.e_tag().map(ToOwned::to_owned),
                version_id: output.version_id().map(ToOwned::to_owned),
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            };
            if self.exact_version_recovery {
                let version_id = stored.version_id.as_deref().ok_or_else(|| {
                    BackendError::ambiguous(
                        "metadata rewrite completion response omitted its provider version ID",
                    )
                })?;
                self.resolve_exact_version_history(operation, Some(version_id))
                    .await?
                    .ok_or_else(|| {
                        BackendError::ambiguous(
                            "metadata rewrite completed but its exact provider version was not enumerable",
                        )
                    })
            } else {
                Ok(stored)
            }
        }
        .await;
        if result.is_err()
            && let Err(error) = self
                .client
                .abort_multipart_upload()
                .bucket(&operation.destination.bucket)
                .key(&operation.destination.physical_key)
                .upload_id(upload_id)
                .send()
                .await
        {
            record_s3_failure("rewrite_abort_multipart", &error);
        }
        result
    }

    async fn finalized_multipart(
        &self,
        operation: &OperationRecord,
    ) -> Result<CompletionProbe, BackendError> {
        if self.exact_version_recovery
            && let Some(stored) = self.resolve_exact_version_history(operation, None).await?
        {
            return Ok(CompletionProbe::Committed(stored));
        }
        match self
            .client
            .head_object()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .send()
            .await
        {
            Ok(output) => {
                let matches_operation = output
                    .metadata()
                    .and_then(|metadata| metadata.get("s4-operation-id"))
                    .is_some_and(|id| id == &operation.id.to_string());
                let matches_size = operation.expected.size.is_none_or(|expected| {
                    output
                        .content_length()
                        .and_then(|size| u64::try_from(size).ok())
                        == Some(expected)
                });
                if !matches_operation || !matches_size {
                    return Ok(CompletionProbe::Inconclusive);
                }
                if metadata_matches(output.metadata(), operation) {
                    let stored = StoredObjectMeta {
                        etag: output.e_tag().map(ToOwned::to_owned),
                        version_id: output.version_id().map(ToOwned::to_owned),
                        superseded_version_ids: Vec::new(),
                        version_history_complete: false,
                    };
                    if !self.encryption_matches(output.server_side_encryption()) {
                        return Ok(CompletionProbe::Inconclusive);
                    }
                    if self.exact_version_recovery {
                        return self
                            .resolve_exact_version_history(operation, stored.version_id.as_deref())
                            .await?
                            .map(CompletionProbe::Committed)
                            .ok_or_else(|| {
                                BackendError::ambiguous(
                                    "completed object was not found in exact version history",
                                )
                            });
                    }
                    return Ok(CompletionProbe::Committed(stored));
                }
                self.rewrite_completed_multipart_metadata(operation, output.version_id())
                    .await
                    .map(CompletionProbe::Committed)
            }
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_not_found()) =>
            {
                if self.exact_version_recovery {
                    let versions = self.inspect_object_versions(operation).await?;
                    if versions.iter().any(|version| version.operation_matches) {
                        return Ok(CompletionProbe::Inconclusive);
                    }
                    if self.inspect_multipart_uploads(operation).await?.is_empty() {
                        Ok(CompletionProbe::ProvenAbsentExact)
                    } else {
                        Ok(CompletionProbe::Inconclusive)
                    }
                } else {
                    Ok(CompletionProbe::ProvenAbsent)
                }
            }
            Err(error) => Err(ambiguous("probe_head_object", &error)),
        }
    }
}

fn object_metadata(operation: &OperationRecord) -> std::collections::HashMap<String, String> {
    operation
        .expected
        .metadata
        .iter()
        .filter(|(key, _)| key.as_str() != "content-type")
        .map(|(key, value)| (key.clone(), value.clone()))
        .chain([("s4-operation-id".to_string(), operation.id.to_string())])
        .chain(
            operation
                .expected
                .digest
                .as_ref()
                .map(|digest| ("s4-sha256".to_string(), digest.clone())),
        )
        .chain(
            operation
                .expected
                .size
                .map(|size| ("s4-size".to_string(), size.to_string())),
        )
        .collect()
}

fn metadata_matches(
    actual: Option<&std::collections::HashMap<String, String>>,
    operation: &OperationRecord,
) -> bool {
    let expected = object_metadata(operation);
    actual.is_some_and(|actual| {
        expected
            .iter()
            .all(|(key, value)| actual.get(key) == Some(value))
    })
}

fn copy_source(operation: &OperationRecord, version_id: Option<&str>) -> String {
    let mut source = format!("{}/", operation.destination.bucket);
    for byte in operation.destination.physical_key.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            source.push(char::from(byte));
        } else {
            use std::fmt::Write;

            write!(source, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    if let Some(version_id) = version_id {
        source.push_str("?versionId=");
        for byte in version_id.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                source.push(char::from(byte));
            } else {
                use std::fmt::Write;

                write!(source, "%{byte:02X}").expect("writing to a String cannot fail");
            }
        }
    }
    source
}

fn ambiguous<E, R>(
    operation: &'static str,
    error: &aws_smithy_runtime_api::client::result::SdkError<E, R>,
) -> BackendError {
    BackendError::ambiguous(record_s3_failure(operation, error).to_string())
}

#[async_trait]
impl TransactionBackend for AwsS3TransactionBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities
    }

    fn has_exact_version_recovery(&self) -> bool {
        self.exact_version_recovery
    }

    async fn put_object(
        &self,
        operation: &OperationRecord,
        body: Bytes,
    ) -> Result<StoredObjectMeta, BackendError> {
        let output = self
            .client
            .put_object()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .set_content_type(operation.expected.metadata.get("content-type").cloned())
            .set_metadata(Some(object_metadata(operation)))
            .set_server_side_encryption(self.server_side_encryption.map(|value| value.sdk_value()))
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|error| ambiguous("put_object", &error))?;
        let stored = StoredObjectMeta {
            etag: output.e_tag().map(ToOwned::to_owned),
            version_id: output.version_id().map(ToOwned::to_owned),
            superseded_version_ids: Vec::new(),
            version_history_complete: true,
        };
        if self.exact_version_recovery {
            let version_id = stored.version_id.as_deref().ok_or_else(|| {
                BackendError::ambiguous("PUT response omitted its provider version ID")
            })?;
            self.resolve_exact_version_history(operation, Some(version_id))
                .await?
                .ok_or_else(|| {
                    BackendError::ambiguous(
                        "PUT completed but its exact provider version was not enumerable",
                    )
                })
        } else {
            Ok(stored)
        }
    }

    async fn create_multipart(&self, operation: &OperationRecord) -> Result<String, BackendError> {
        let output = self
            .client
            .create_multipart_upload()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .set_content_type(operation.expected.metadata.get("content-type").cloned())
            .set_metadata(Some(object_metadata(operation)))
            .set_server_side_encryption(self.server_side_encryption.map(|value| value.sdk_value()))
            .send()
            .await
            .map_err(|error| ambiguous("create_multipart", &error))?;
        output
            .upload_id()
            .map(ToOwned::to_owned)
            .ok_or_else(|| BackendError::ambiguous("create-multipart response omitted upload ID"))
    }

    async fn upload_part(
        &self,
        operation: &OperationRecord,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<String, BackendError> {
        let output = self
            .client
            .upload_part()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|error| ambiguous("upload_part", &error))?;
        output
            .e_tag()
            .map(ToOwned::to_owned)
            .ok_or_else(|| BackendError::ambiguous("upload-part response omitted ETag"))
    }

    async fn complete_multipart(
        &self,
        operation: &OperationRecord,
        upload_id: &str,
        parts: &[UploadedPart],
    ) -> Result<StoredObjectMeta, BackendError> {
        if let CompletionProbe::Committed(meta) = self.finalized_multipart(operation).await? {
            return Ok(meta);
        }
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(
                parts
                    .iter()
                    .map(|part| {
                        CompletedPart::builder()
                            .part_number(part.part_number)
                            .e_tag(&part.etag)
                            .build()
                    })
                    .collect(),
            ))
            .build();
        let first = self
            .client
            .complete_multipart_upload()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|error| ambiguous("complete_multipart", &error))?;
        let mut rewritten = self
            .rewrite_completed_multipart_metadata(operation, first.version_id())
            .await?;
        if let Some(version_id) = first.version_id()
            && rewritten.version_id.as_deref() != Some(version_id)
            && !rewritten
                .superseded_version_ids
                .iter()
                .any(|existing| existing == version_id)
        {
            rewritten
                .superseded_version_ids
                .push(version_id.to_string());
        }
        Ok(rewritten)
    }

    async fn abort_multipart(
        &self,
        operation: &OperationRecord,
        upload_id: &str,
    ) -> Result<(), BackendError> {
        self.client
            .abort_multipart_upload()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|error| ambiguous("abort_multipart", &error))?;
        Ok(())
    }

    async fn discover_incomplete(
        &self,
        operation: &OperationRecord,
    ) -> Result<Vec<DiscoveredUpload>, BackendError> {
        let mut key_marker: Option<String> = None;
        let mut upload_id_marker: Option<String> = None;
        let mut discovered = Vec::new();
        loop {
            let output = self
                .client
                .list_multipart_uploads()
                .bucket(&operation.destination.bucket)
                .prefix(&operation.destination.physical_key)
                .set_key_marker(key_marker.clone())
                .set_upload_id_marker(upload_id_marker.clone())
                .send()
                .await
                .map_err(|error| ambiguous("list_multipart_uploads", &error))?;
            for upload in output.uploads() {
                let (Some(key), Some(upload_id)) = (upload.key(), upload.upload_id()) else {
                    continue;
                };
                if key != operation.destination.physical_key {
                    continue;
                }
                let initiated_at_ms = upload
                    .initiated()
                    .and_then(|initiated| initiated.to_millis().ok());
                if initiated_at_ms.is_none_or(|initiated| {
                    initiated >= operation.created_at_ms.saturating_sub(1_000)
                }) {
                    discovered.push(DiscoveredUpload {
                        upload_id: upload_id.to_string(),
                        key: key.to_string(),
                        initiated_at_ms,
                    });
                }
            }
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            let next_key = output.next_key_marker().map(ToOwned::to_owned);
            let next_upload_id = output.next_upload_id_marker().map(ToOwned::to_owned);
            if next_key.is_none() || (next_key == key_marker && next_upload_id == upload_id_marker)
            {
                return Err(BackendError::ambiguous(
                    "multipart discovery was truncated without advancing its markers",
                ));
            }
            key_marker = next_key;
            upload_id_marker = next_upload_id;
        }
        Ok(discovered)
    }

    async fn inspect_object_versions(
        &self,
        operation: &OperationRecord,
    ) -> Result<Vec<DiscoveredObjectVersion>, BackendError> {
        let mut key_marker = None;
        let mut version_id_marker = None;
        let mut discovered = Vec::new();
        let mut seen_version_ids = HashSet::new();
        loop {
            let output = self
                .client
                .list_object_versions()
                .bucket(&operation.destination.bucket)
                .prefix(&operation.destination.physical_key)
                .set_key_marker(key_marker.clone())
                .set_version_id_marker(version_id_marker.clone())
                .send()
                .await
                .map_err(|error| ambiguous("list_object_versions", &error))?;
            for version in output.versions() {
                let (Some(key), Some(version_id)) = (version.key(), version.version_id()) else {
                    continue;
                };
                if key != operation.destination.physical_key {
                    continue;
                }
                if !seen_version_ids.insert(version_id.to_string()) {
                    continue;
                }
                let head = self
                    .client
                    .head_object()
                    .bucket(&operation.destination.bucket)
                    .key(&operation.destination.physical_key)
                    .version_id(version_id)
                    .send()
                    .await
                    .map_err(|error| ambiguous("inspect_object_version", &error))?;
                let operation_matches = head
                    .metadata()
                    .and_then(|metadata| metadata.get("s4-operation-id"))
                    .is_some_and(|id| id == &operation.id.to_string());
                discovered.push(DiscoveredObjectVersion {
                    version_id: version_id.to_string(),
                    etag: head
                        .e_tag()
                        .or_else(|| version.e_tag())
                        .map(ToOwned::to_owned),
                    size: head
                        .content_length()
                        .or_else(|| version.size())
                        .and_then(|size| u64::try_from(size).ok()),
                    is_latest: version.is_latest().unwrap_or(false),
                    last_modified_ms: version
                        .last_modified()
                        .and_then(|timestamp| timestamp.to_millis().ok()),
                    delete_marker: false,
                    operation_matches,
                    expected_metadata_matches: metadata_matches(head.metadata(), operation),
                    encryption_matches: self.encryption_matches(head.server_side_encryption()),
                });
            }
            for marker in output.delete_markers() {
                let (Some(key), Some(version_id)) = (marker.key(), marker.version_id()) else {
                    continue;
                };
                if key == operation.destination.physical_key {
                    if !seen_version_ids.insert(version_id.to_string()) {
                        continue;
                    }
                    discovered.push(DiscoveredObjectVersion {
                        version_id: version_id.to_string(),
                        etag: None,
                        size: None,
                        is_latest: marker.is_latest().unwrap_or(false),
                        last_modified_ms: marker
                            .last_modified()
                            .and_then(|timestamp| timestamp.to_millis().ok()),
                        delete_marker: true,
                        operation_matches: false,
                        expected_metadata_matches: false,
                        encryption_matches: false,
                    });
                }
            }
            if !output.is_truncated().unwrap_or(false) {
                break;
            }
            let next_key = output.next_key_marker().map(ToOwned::to_owned);
            let next_version = output.next_version_id_marker().map(ToOwned::to_owned);
            if next_key.is_none() || (next_key == key_marker && next_version == version_id_marker) {
                return Err(BackendError::ambiguous(
                    "object-version listing was truncated without advancing its markers",
                ));
            }
            key_marker = next_key;
            version_id_marker = next_version;
        }
        Ok(discovered)
    }

    async fn delete_object_version(
        &self,
        operation: &OperationRecord,
        version_id: &str,
    ) -> Result<(), BackendError> {
        if version_id.is_empty() {
            return Err(BackendError::definitive(
                "exact object-version deletion requires a version ID",
            ));
        }
        self.client
            .delete_object()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .version_id(version_id)
            .send()
            .await
            .map_err(|error| ambiguous("delete_object_version", &error))?;
        Ok(())
    }

    async fn inspect_multipart_uploads(
        &self,
        operation: &OperationRecord,
    ) -> Result<Vec<MultipartUploadInspection>, BackendError> {
        let uploads = self.discover_incomplete(operation).await?;
        let mut inspected = Vec::with_capacity(uploads.len());
        for upload in uploads {
            let mut part_number_marker = None;
            let mut parts = Vec::new();
            loop {
                let output = self
                    .client
                    .list_parts()
                    .bucket(&operation.destination.bucket)
                    .key(&operation.destination.physical_key)
                    .upload_id(&upload.upload_id)
                    .set_part_number_marker(part_number_marker.clone())
                    .send()
                    .await
                    .map_err(|error| ambiguous("list_multipart_parts", &error))?;
                parts.extend(output.parts().iter().filter_map(|part| {
                    Some(DiscoveredMultipartPart {
                        part_number: part.part_number()?,
                        etag: part.e_tag().map(ToOwned::to_owned),
                        size: part.size().and_then(|size| u64::try_from(size).ok()),
                        last_modified_ms: part
                            .last_modified()
                            .and_then(|timestamp| timestamp.to_millis().ok()),
                    })
                }));
                if !output.is_truncated().unwrap_or(false) {
                    break;
                }
                let next = output.next_part_number_marker().map(ToOwned::to_owned);
                if next.is_none() || next == part_number_marker {
                    return Err(BackendError::ambiguous(
                        "multipart part listing was truncated without advancing its marker",
                    ));
                }
                part_number_marker = next;
            }
            inspected.push(MultipartUploadInspection { upload, parts });
        }
        Ok(inspected)
    }

    async fn probe_completion(
        &self,
        operation: &OperationRecord,
    ) -> Result<CompletionProbe, BackendError> {
        self.finalized_multipart(operation).await
    }
}

pub struct DirectS3Sink {
    journal: Arc<dyn OperationJournal>,
    backend: Arc<dyn TransactionBackend>,
    operation: OperationRecord,
    buffer: BytesMut,
    upload_id: Option<String>,
    parts: Vec<UploadedPart>,
    max_attempts: usize,
    abort_signal: AbortSignal,
    output_hasher: Sha256,
    output_bytes: u64,
    output_verified: bool,
    finished: bool,
}

impl DirectS3Sink {
    pub async fn new(
        journal: Arc<dyn OperationJournal>,
        backend: Arc<dyn TransactionBackend>,
        destination: ObjectDestination,
        expected: super::ExpectedObject,
        max_attempts: usize,
        abort_signal: AbortSignal,
    ) -> Result<Self, TransactionError> {
        Self::from_operation(
            journal,
            backend,
            OperationRecord::intent(destination, expected),
            max_attempts,
            abort_signal,
        )
        .await
    }

    pub async fn new_scoped(
        journal: Arc<dyn OperationJournal>,
        backend: Arc<dyn TransactionBackend>,
        scope: super::ManagedOperationScope,
        destination: ObjectDestination,
        expected: super::ExpectedObject,
        max_attempts: usize,
        abort_signal: AbortSignal,
    ) -> Result<Self, TransactionError> {
        Self::from_operation(
            journal,
            backend,
            OperationRecord::scoped_intent(
                scope.operation_id,
                destination,
                expected,
                scope.tenant_id,
                scope.namespace_epoch,
            ),
            max_attempts,
            abort_signal,
        )
        .await
    }

    pub async fn new_direct(
        journal: Arc<dyn OperationJournal>,
        backend: Arc<dyn TransactionBackend>,
        scope: super::DirectOperationScope,
        destination: ObjectDestination,
        expected: super::ExpectedObject,
        max_attempts: usize,
        abort_signal: AbortSignal,
    ) -> Result<Self, TransactionError> {
        Self::from_operation(
            journal,
            backend,
            OperationRecord::direct_intent(scope, destination, expected),
            max_attempts,
            abort_signal,
        )
        .await
    }

    async fn from_operation(
        journal: Arc<dyn OperationJournal>,
        backend: Arc<dyn TransactionBackend>,
        operation: OperationRecord,
        max_attempts: usize,
        abort_signal: AbortSignal,
    ) -> Result<Self, TransactionError> {
        backend.capabilities().streaming_eligibility()?;
        journal.insert_intent(operation.clone()).await?;
        Ok(Self {
            journal,
            backend,
            operation,
            buffer: BytesMut::with_capacity(DIRECT_PART_BYTES),
            upload_id: None,
            parts: Vec::new(),
            max_attempts: max_attempts.max(1),
            abort_signal,
            output_hasher: Sha256::new(),
            output_bytes: 0,
            output_verified: false,
            finished: false,
        })
    }

    pub fn operation_id(&self) -> uuid::Uuid {
        self.operation.id
    }

    async fn evidence(
        &self,
        kind: &str,
        detail: serde_json::Value,
    ) -> Result<(), TransactionError> {
        self.journal
            .append_evidence(EvidenceRecord::new(self.operation.id, kind, detail))
            .await?;
        Ok(())
    }

    async fn ensure_multipart(&mut self) -> Result<(), TransactionError> {
        if self.upload_id.is_some() {
            return Ok(());
        }
        self.evidence("create_multipart_before", json!({})).await?;
        let upload_id = match self.backend.create_multipart(&self.operation).await {
            Ok(upload_id) => upload_id,
            Err(error) => {
                self.evidence(
                    "create_multipart_unknown",
                    json!({"kind": format!("{:?}", error.kind)}),
                )
                .await?;
                return Err(error.into());
            }
        };
        self.journal
            .set_open(self.operation.id, Some(&upload_id))
            .await?;
        self.operation.state = OperationState::Open;
        self.operation.upload_id = Some(upload_id.clone());
        self.upload_id = Some(upload_id.clone());
        self.evidence(
            "create_multipart_after",
            json!({"upload_id_recorded": true}),
        )
        .await?;
        Ok(())
    }

    async fn upload_buffered_part(&mut self, body: Bytes) -> Result<(), TransactionError> {
        let upload_id = self.upload_id.as_deref().ok_or_else(|| {
            TransactionError::Backend(BackendError::definitive("multipart upload is not open"))
        })?;
        let part_number =
            i32::try_from(self.parts.len() + 1).map_err(|_| TransactionError::TooManyParts)?;
        if part_number > 10_000 {
            return Err(TransactionError::TooManyParts);
        }
        let digest = sha256_hex(&body);
        let mut last_error = None;
        for attempt in 1..=self.max_attempts {
            self.evidence(
                "upload_part_before",
                json!({"part_number": part_number, "attempt": attempt, "digest": digest}),
            )
            .await?;
            match self
                .backend
                .upload_part(&self.operation, upload_id, part_number, body.clone())
                .await
            {
                Ok(etag) => {
                    self.journal
                        .record_part(PartRecord {
                            operation_id: self.operation.id,
                            part_number,
                            etag: etag.clone(),
                            size_bytes: body.len() as u64,
                            digest: digest.clone(),
                            created_at_ms: unix_time_ms(),
                        })
                        .await?;
                    self.evidence(
                        "upload_part_after",
                        json!({"part_number": part_number, "attempt": attempt}),
                    )
                    .await?;
                    self.parts.push(UploadedPart { part_number, etag });
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| BackendError::ambiguous("upload part retry budget exhausted"))
            .into())
    }

    async fn complete_single_put(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        self.journal.set_open(self.operation.id, None).await?;
        self.operation.state = OperationState::Open;
        self.journal
            .transition(
                self.operation.id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await?;
        self.operation.state = OperationState::Completing;
        let body = self.buffer.split().freeze();
        let digest = sha256_hex(&body);
        let mut last_error = None;
        for attempt in 1..=self.max_attempts {
            self.evidence(
                "put_object_before",
                json!({"attempt": attempt, "digest": digest, "size": body.len()}),
            )
            .await?;
            match self.backend.put_object(&self.operation, body.clone()).await {
                Ok(mut meta) => {
                    if attempt > 1 && !self.backend.has_exact_version_recovery() {
                        meta.version_history_complete = false;
                    }
                    if let Err(error) = self
                        .journal
                        .transition(
                            self.operation.id,
                            OperationState::Completing,
                            OperationState::Committed,
                            Some(&meta),
                        )
                        .await
                    {
                        if let Ok(Some(recovered)) = self.reconcile_completion().await {
                            return Ok(recovered);
                        }
                        return Err(error.into());
                    }
                    self.operation.state = OperationState::Committed;
                    let evidence_kind = if meta.version_history_complete {
                        "provider_version_history_complete"
                    } else {
                        "provider_version_history_ambiguous"
                    };
                    let _ = self
                        .evidence(
                            evidence_kind,
                            json!({
                                "version_id": meta.version_id.as_deref(),
                                "superseded_version_ids": &meta.superseded_version_ids,
                                "attempt": attempt,
                            }),
                        )
                        .await;
                    let _ = self
                        .evidence("put_object_after", json!({"attempt": attempt}))
                        .await;
                    return Ok(meta);
                }
                Err(error) => {
                    let _ = self
                        .evidence(
                            "put_object_attempt_ambiguous",
                            json!({"attempt": attempt, "kind": format!("{:?}", error.kind)}),
                        )
                        .await;
                    last_error = Some(error);
                }
            }
        }
        self.mark_commit_unknown().await?;
        let error =
            last_error.unwrap_or_else(|| BackendError::ambiguous("PUT retry budget exhausted"));
        if let Some(recovered) = self.reconcile_completion().await? {
            return Ok(recovered);
        }
        Err(error.into())
    }

    async fn complete_multipart(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        if !self.buffer.is_empty() {
            let body = self.buffer.split().freeze();
            self.upload_buffered_part(body).await?;
        }
        self.journal
            .transition(
                self.operation.id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await?;
        self.operation.state = OperationState::Completing;
        let upload_id = self
            .upload_id
            .as_deref()
            .expect("multipart completion requires upload ID");
        let mut last_error = None;
        for attempt in 1..=self.max_attempts {
            self.evidence(
                "complete_multipart_before",
                json!({"attempt": attempt, "part_count": self.parts.len()}),
            )
            .await?;
            match self
                .backend
                .complete_multipart(&self.operation, upload_id, &self.parts)
                .await
            {
                Ok(mut meta) => {
                    if attempt > 1 && !self.backend.has_exact_version_recovery() {
                        meta.version_history_complete = false;
                    }
                    if let Err(error) = self
                        .journal
                        .transition(
                            self.operation.id,
                            OperationState::Completing,
                            OperationState::Committed,
                            Some(&meta),
                        )
                        .await
                    {
                        if let Ok(Some(recovered)) = self.reconcile_completion().await {
                            return Ok(recovered);
                        }
                        return Err(error.into());
                    }
                    self.operation.state = OperationState::Committed;
                    let evidence_kind = if meta.version_history_complete {
                        "provider_version_history_complete"
                    } else {
                        "provider_version_history_ambiguous"
                    };
                    let _ = self
                        .evidence(
                            evidence_kind,
                            json!({
                                "version_id": meta.version_id.as_deref(),
                                "superseded_version_ids": &meta.superseded_version_ids,
                                "attempt": attempt,
                            }),
                        )
                        .await;
                    let _ = self
                        .evidence("complete_multipart_after", json!({"attempt": attempt}))
                        .await;
                    return Ok(meta);
                }
                Err(error) => {
                    let _ = self
                        .evidence(
                            "complete_multipart_attempt_ambiguous",
                            json!({"attempt": attempt, "kind": format!("{:?}", error.kind)}),
                        )
                        .await;
                    last_error = Some(error);
                }
            }
        }
        self.mark_commit_unknown().await?;
        let error = last_error
            .unwrap_or_else(|| BackendError::ambiguous("complete retry budget exhausted"));
        if let Some(recovered) = self.reconcile_completion().await? {
            return Ok(recovered);
        }
        Err(error.into())
    }

    async fn mark_commit_unknown(&mut self) -> Result<(), TransactionError> {
        self.journal
            .transition(
                self.operation.id,
                OperationState::Completing,
                OperationState::CommitUnknown,
                None,
            )
            .await?;
        self.operation.state = OperationState::CommitUnknown;
        self.evidence("completion_unknown", json!({})).await
    }

    async fn reconcile_completion(&mut self) -> Result<Option<StoredObjectMeta>, TransactionError> {
        let mut operation =
            self.journal
                .get(self.operation.id)
                .await?
                .ok_or(TransactionError::Journal(super::JournalError::NotFound(
                    self.operation.id,
                )))?;
        if operation.state == OperationState::Completing {
            self.journal
                .transition(
                    operation.id,
                    OperationState::Completing,
                    OperationState::CommitUnknown,
                    None,
                )
                .await?;
            operation.state = OperationState::CommitUnknown;
        }
        if operation.state == OperationState::CommitUnknown {
            match self.backend.probe_completion(&operation).await? {
                CompletionProbe::Committed(mut meta) => {
                    if !self.backend.has_exact_version_recovery() {
                        meta.version_history_complete = false;
                    }
                    let evidence_kind = if meta.version_history_complete {
                        "provider_version_history_complete"
                    } else {
                        "provider_version_history_ambiguous"
                    };
                    self.evidence(
                        evidence_kind,
                        json!({
                            "version_id": meta.version_id.as_deref(),
                            "superseded_version_ids": &meta.superseded_version_ids,
                            "reconciled": true,
                        }),
                    )
                    .await?;
                    self.journal
                        .transition(
                            operation.id,
                            OperationState::CommitUnknown,
                            OperationState::Committed,
                            Some(&meta),
                        )
                        .await?;
                    operation.state = OperationState::Committed;
                    operation.committed = Some(meta);
                }
                CompletionProbe::ProvenAbsentExact => {
                    self.journal
                        .transition(
                            operation.id,
                            OperationState::CommitUnknown,
                            OperationState::ProvenAborted,
                            None,
                        )
                        .await?;
                    operation.state = OperationState::ProvenAborted;
                }
                CompletionProbe::ProvenAbsent | CompletionProbe::Inconclusive => {}
            }
        }
        self.operation = operation;
        if self.operation.state == OperationState::Committed {
            return self.operation.committed.clone().map(Some).ok_or_else(|| {
                TransactionError::Journal(super::JournalError::Corrupt(
                    "committed operation has no destination metadata".to_string(),
                ))
            });
        }
        Ok(None)
    }

    async fn abort_discovered(&self) -> Result<(), TransactionError> {
        for upload in self.backend.discover_incomplete(&self.operation).await? {
            self.evidence(
                "abort_discovered_before",
                json!({"upload_id": upload.upload_id}),
            )
            .await?;
            self.backend
                .abort_multipart(&self.operation, &upload.upload_id)
                .await?;
            self.evidence(
                "abort_discovered_after",
                json!({"upload_id": upload.upload_id}),
            )
            .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl ObjectSinkTransaction for DirectS3Sink {
    fn commit_state(&self) -> SinkCommitState {
        match self.operation.state {
            OperationState::Completing | OperationState::CommitUnknown => {
                SinkCommitState::CommitUnknown
            }
            OperationState::Committed => SinkCommitState::Committed,
            OperationState::Intent
            | OperationState::Open
            | OperationState::Aborting
            | OperationState::ProvenAborted => SinkCommitState::PreCommit,
        }
    }

    fn durable_operation_id(&self) -> Option<uuid::Uuid> {
        Some(self.operation.id)
    }

    async fn write(&mut self, mut chunk: Bytes) -> Result<(), TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        self.output_bytes = self
            .output_bytes
            .checked_add(chunk.len() as u64)
            .ok_or(TransactionError::OutputMismatch)?;
        self.output_hasher.update(&chunk);
        self.output_verified = false;
        while !chunk.is_empty() {
            let available = DIRECT_PART_BYTES - self.buffer.len();
            let copied = available.min(chunk.len());
            self.buffer.extend_from_slice(&chunk[..copied]);
            chunk.advance(copied);
            if self.buffer.len() == DIRECT_PART_BYTES && !chunk.is_empty() {
                self.ensure_multipart().await?;
                let body = self.buffer.split().freeze();
                self.upload_buffered_part(body).await?;
            } else if self.buffer.len() == DIRECT_PART_BYTES && self.upload_id.is_some() {
                let body = self.buffer.split().freeze();
                self.upload_buffered_part(body).await?;
            }
        }
        Ok(())
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        let actual_digest = hex::encode(self.output_hasher.clone().finalize());
        if self.output_bytes != expected_size || actual_digest != expected_sha256 {
            return Err(TransactionError::OutputMismatch);
        }
        self.operation.expected.digest = Some(actual_digest);
        self.operation.expected.size = Some(expected_size);
        self.journal
            .set_expected(self.operation.id, &self.operation.expected)
            .await?;
        self.output_verified = true;
        Ok(())
    }

    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        if !self.output_verified {
            return Err(TransactionError::OutputMismatch);
        }
        let result = if self.upload_id.is_some() {
            self.complete_multipart().await
        } else {
            self.complete_single_put().await
        };
        if result.is_ok() {
            self.finished = true;
        }
        result
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        if self.finished {
            return Ok(());
        }
        match self.operation.state {
            OperationState::Intent => {
                self.journal
                    .transition(
                        self.operation.id,
                        OperationState::Intent,
                        OperationState::Aborting,
                        None,
                    )
                    .await?;
            }
            OperationState::Open => {
                self.journal
                    .transition(
                        self.operation.id,
                        OperationState::Open,
                        OperationState::Aborting,
                        None,
                    )
                    .await?;
            }
            OperationState::Aborting => {}
            OperationState::Completing | OperationState::CommitUnknown => {
                return Err(TransactionError::CompletionAmbiguous);
            }
            OperationState::Committed | OperationState::ProvenAborted => {
                self.finished = true;
                return Ok(());
            }
        }
        self.operation.state = OperationState::Aborting;
        if let Some(upload_id) = &self.upload_id {
            self.evidence("abort_multipart_before", json!({})).await?;
            self.backend
                .abort_multipart(&self.operation, upload_id)
                .await?;
            self.evidence("abort_multipart_after", json!({})).await?;
        }
        self.abort_discovered().await?;
        self.journal
            .transition(
                self.operation.id,
                OperationState::Aborting,
                OperationState::ProvenAborted,
                None,
            )
            .await?;
        self.operation.state = OperationState::ProvenAborted;
        self.finished = true;
        Ok(())
    }
}

impl Drop for DirectS3Sink {
    fn drop(&mut self) {
        if !self.finished {
            self.abort_signal.signal(self.operation.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;
    use std::time::Duration;

    use aws_sdk_s3::config::{Credentials, Region};
    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::routing::any;

    use super::*;
    use crate::transaction::{
        CompletionReconciliation, ExpectedObject, InMemoryOperationJournal,
        IncompleteUploadDiscovery, OperationReconciler, VersioningCapability,
    };

    type ProviderRequests = Arc<Mutex<Vec<(Method, String, HeaderMap)>>>;

    async fn provider_mock(
        State(requests): State<ProviderRequests>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
    ) -> axum::response::Response {
        requests
            .lock()
            .unwrap()
            .push((method.clone(), uri.to_string(), headers));
        let query = uri.query().unwrap_or_default();
        if method == Method::GET && query.contains("versions") && query.contains("prefix=paginated")
        {
            let body = if query.contains("version-id-marker=version-1") {
                r#"<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><Prefix>paginated</Prefix><IsTruncated>false</IsTruncated><Version><Key>paginated</Key><VersionId>version-1</VersionId><IsLatest>false</IsLatest><LastModified>2026-08-31T11:59:00.000Z</LastModified><ETag>&quot;etag-1&quot;</ETag><Size>3</Size><StorageClass>STANDARD</StorageClass></Version><Version><Key>paginated</Key><VersionId>version-2</VersionId><IsLatest>true</IsLatest><LastModified>2026-08-31T12:00:00.000Z</LastModified><ETag>&quot;etag-2&quot;</ETag><Size>3</Size><StorageClass>STANDARD</StorageClass></Version></ListVersionsResult>"#
            } else {
                r#"<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><Prefix>paginated</Prefix><IsTruncated>true</IsTruncated><NextKeyMarker>paginated</NextKeyMarker><NextVersionIdMarker>version-1</NextVersionIdMarker><Version><Key>paginated</Key><VersionId>version-1</VersionId><IsLatest>false</IsLatest><LastModified>2026-08-31T11:59:00.000Z</LastModified><ETag>&quot;etag-1&quot;</ETag><Size>3</Size><StorageClass>STANDARD</StorageClass></Version></ListVersionsResult>"#
            };
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(body))
                .unwrap();
        }
        if method == Method::GET && query.contains("versions") {
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(
                    r#"<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><Prefix>physical</Prefix><IsTruncated>false</IsTruncated><Version><Key>physical</Key><VersionId>version-2</VersionId><IsLatest>true</IsLatest><LastModified>2026-08-31T12:00:00.000Z</LastModified><ETag>&quot;etag-2&quot;</ETag><Size>3</Size><StorageClass>STANDARD</StorageClass></Version><Version><Key>physical</Key><VersionId>version-1</VersionId><IsLatest>false</IsLatest><LastModified>2026-08-31T11:59:00.000Z</LastModified><ETag>&quot;etag-1&quot;</ETag><Size>3</Size><StorageClass>STANDARD</StorageClass></Version></ListVersionsResult>"#,
                ))
                .unwrap();
        }
        if method == Method::GET && query.contains("uploads") {
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(
                    r#"<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>bucket</Bucket><KeyMarker></KeyMarker><UploadIdMarker></UploadIdMarker><NextKeyMarker></NextKeyMarker><NextUploadIdMarker></NextUploadIdMarker><MaxUploads>1000</MaxUploads><IsTruncated>false</IsTruncated><Upload><Key>physical</Key><UploadId>incomplete-upload</UploadId><Initiated>2026-08-31T12:00:00.000Z</Initiated></Upload></ListMultipartUploadsResult>"#,
                ))
                .unwrap();
        }
        if method == Method::GET && query.contains("uploadId=incomplete-upload") {
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(
                    r#"<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>bucket</Bucket><Key>physical</Key><UploadId>incomplete-upload</UploadId><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>1</NextPartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated><Part><PartNumber>1</PartNumber><LastModified>2026-08-31T12:00:01.000Z</LastModified><ETag>&quot;part-etag&quot;</ETag><Size>3</Size></Part></ListPartsResult>"#,
                ))
                .unwrap();
        }
        if method == Method::HEAD {
            let version = if query.contains("versionId=version-1") {
                "version-1"
            } else {
                "version-2"
            };
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(
                    "etag",
                    format!("\"etag-{}\"", &version[version.len() - 1..]),
                )
                .header("content-length", "3")
                .header("x-amz-version-id", version)
                .header("x-amz-server-side-encryption", "AES256")
                .header(
                    "x-amz-meta-s4-operation-id",
                    "018f0000-0000-7000-8000-000000000001",
                )
                .header("x-amz-meta-s4-sha256", "digest")
                .header("x-amz-meta-s4-size", "3")
                .body(Body::empty())
                .unwrap();
        }
        if method == Method::POST && query.contains("uploads") {
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(
                    r#"<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>bucket</Bucket><Key>physical</Key><UploadId>new-upload</UploadId></InitiateMultipartUploadResult>"#,
                ))
                .unwrap();
        }
        if method == Method::PUT && query.contains("uploadId=new-upload") {
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(
                    r#"<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LastModified>2026-08-31T12:00:00.000Z</LastModified><ETag>&quot;copy-etag&quot;</ETag></CopyPartResult>"#,
                ))
                .unwrap();
        }
        if method == Method::POST && query.contains("uploadId=new-upload") {
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .header("x-amz-version-id", "rewrite-version")
                .body(Body::from(
                    r#"<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Location>http://localhost/bucket/physical</Location><Bucket>bucket</Bucket><Key>physical</Key><ETag>&quot;rewrite-etag&quot;</ETag></CompleteMultipartUploadResult>"#,
                ))
                .unwrap();
        }
        if method == Method::PUT && !query.contains("uploadId") {
            return axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("etag", "\"put-etag\"")
                .header("x-amz-version-id", "put-version")
                .body(Body::empty())
                .unwrap();
        }
        axum::response::Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap()
    }

    async fn provider_client() -> (Client, ProviderRequests, tokio::task::JoinHandle<()>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .fallback(any(provider_mock))
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .credentials_provider(Credentials::new("key", "secret", None, None, "test"))
            .load()
            .await;
        let client = Client::from_conf(
            aws_sdk_s3::config::Builder::from(&config)
                .force_path_style(true)
                .build(),
        );
        (client, requests, server)
    }

    #[derive(Default)]
    struct ScriptState {
        events: Vec<String>,
        failures: VecDeque<String>,
        bodies: HashMap<String, Vec<Vec<u8>>>,
        committed: HashMap<uuid::Uuid, StoredObjectMeta>,
        uploads: HashMap<uuid::Uuid, String>,
        force_absent_probe: bool,
    }

    #[derive(Default)]
    struct ScriptBackend {
        state: Mutex<ScriptState>,
    }

    impl ScriptBackend {
        fn fail_next(&self, event: &str) {
            self.state
                .lock()
                .unwrap()
                .failures
                .push_back(event.to_string());
        }

        fn event(&self, event: &str) -> Result<(), BackendError> {
            let mut state = self.state.lock().unwrap();
            state.events.push(event.to_string());
            if state
                .failures
                .front()
                .is_some_and(|failure| failure == event)
            {
                state.failures.pop_front();
                return Err(BackendError::ambiguous(format!("scripted {event}")));
            }
            Ok(())
        }

        fn bodies(&self, event: &str) -> Vec<Vec<u8>> {
            self.state
                .lock()
                .unwrap()
                .bodies
                .get(event)
                .cloned()
                .unwrap_or_default()
        }

        fn force_absent_probe(&self) {
            self.state.lock().unwrap().force_absent_probe = true;
        }
    }

    #[async_trait]
    impl TransactionBackend for ScriptBackend {
        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                incomplete_upload_discovery: IncompleteUploadDiscovery::OperationIdentity,
                abort_incomplete_upload: true,
                cleanup_sla: Some(Duration::from_secs(60)),
                lifecycle_rule: true,
                versioning: VersioningCapability::Optional,
                conditional_reads: crate::transaction::ConditionalReadCapability::VersionAndEtag,
                response_checksums: crate::transaction::ResponseChecksumCapability::Standard,
                list_operations: crate::transaction::ListCapability::V1AndV2,
                multipart_responses: crate::transaction::MultipartResponseCapability::Standard,
                completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
            }
        }

        async fn put_object(
            &self,
            operation: &OperationRecord,
            body: Bytes,
        ) -> Result<StoredObjectMeta, BackendError> {
            self.state
                .lock()
                .unwrap()
                .bodies
                .entry("put".to_string())
                .or_default()
                .push(body.to_vec());
            self.event("put")?;
            let meta = StoredObjectMeta {
                etag: Some("put-etag".to_string()),
                version_id: None,
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            };
            self.state
                .lock()
                .unwrap()
                .committed
                .insert(operation.id, meta.clone());
            Ok(meta)
        }

        async fn create_multipart(
            &self,
            operation: &OperationRecord,
        ) -> Result<String, BackendError> {
            self.event("create")?;
            let upload_id = format!("upload-{}", operation.id);
            self.state
                .lock()
                .unwrap()
                .uploads
                .insert(operation.id, upload_id.clone());
            Ok(upload_id)
        }

        async fn upload_part(
            &self,
            _operation: &OperationRecord,
            _upload_id: &str,
            part_number: i32,
            body: Bytes,
        ) -> Result<String, BackendError> {
            self.state
                .lock()
                .unwrap()
                .bodies
                .entry(format!("part-{part_number}"))
                .or_default()
                .push(body.to_vec());
            self.event(&format!("part-{part_number}"))?;
            Ok(format!("etag-{part_number}"))
        }

        async fn complete_multipart(
            &self,
            operation: &OperationRecord,
            _upload_id: &str,
            _parts: &[UploadedPart],
        ) -> Result<StoredObjectMeta, BackendError> {
            let meta = StoredObjectMeta {
                etag: Some("multipart-etag".to_string()),
                version_id: None,
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            };
            self.state
                .lock()
                .unwrap()
                .committed
                .insert(operation.id, meta.clone());
            self.event("complete")?;
            Ok(meta)
        }

        async fn abort_multipart(
            &self,
            operation: &OperationRecord,
            _upload_id: &str,
        ) -> Result<(), BackendError> {
            self.event("abort")?;
            self.state.lock().unwrap().uploads.remove(&operation.id);
            Ok(())
        }

        async fn discover_incomplete(
            &self,
            operation: &OperationRecord,
        ) -> Result<Vec<DiscoveredUpload>, BackendError> {
            self.event("discover")?;
            Ok(self
                .state
                .lock()
                .unwrap()
                .uploads
                .get(&operation.id)
                .map(|upload_id| {
                    vec![DiscoveredUpload {
                        upload_id: upload_id.clone(),
                        key: operation.destination.physical_key.clone(),
                        initiated_at_ms: Some(operation.created_at_ms),
                    }]
                })
                .unwrap_or_default())
        }

        async fn probe_completion(
            &self,
            operation: &OperationRecord,
        ) -> Result<CompletionProbe, BackendError> {
            self.event("probe")?;
            let state = self.state.lock().unwrap();
            if state.force_absent_probe {
                return Ok(CompletionProbe::ProvenAbsent);
            }
            Ok(state
                .committed
                .get(&operation.id)
                .cloned()
                .map(CompletionProbe::Committed)
                .unwrap_or(CompletionProbe::ProvenAbsent))
        }
    }

    fn destination() -> ObjectDestination {
        ObjectDestination {
            backend_id: "script".to_string(),
            bucket: "bucket".to_string(),
            logical_key: "key".to_string(),
            physical_key: "key".to_string(),
        }
    }

    async fn sink(
        journal: Arc<InMemoryOperationJournal>,
        backend: Arc<ScriptBackend>,
        attempts: usize,
    ) -> (DirectS3Sink, tokio::sync::mpsc::Receiver<uuid::Uuid>) {
        let (signal, receiver) = AbortSignal::channel(8);
        let sink = DirectS3Sink::new(
            journal,
            backend,
            destination(),
            ExpectedObject::default(),
            attempts,
            signal,
        )
        .await
        .unwrap();
        (sink, receiver)
    }

    async fn verify_buffered_output(sink: &mut DirectS3Sink) {
        let digest = hex::encode(sink.output_hasher.clone().finalize());
        sink.verify_output(sink.output_bytes, &digest)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn aes256_is_explicit_for_managed_put_and_multipart_but_not_default_byo() {
        let (client, requests, server) = provider_client().await;
        let operation = OperationRecord::intent(destination(), ExpectedObject::default());
        let capabilities = ScriptBackend::default().capabilities();

        let direct = AwsS3TransactionBackend::new(client.clone(), capabilities);
        direct
            .put_object(&operation, Bytes::from_static(b"direct"))
            .await
            .unwrap();
        assert!(
            !requests.lock().unwrap()[0]
                .2
                .contains_key("x-amz-server-side-encryption")
        );

        requests.lock().unwrap().clear();
        let encrypted = AwsS3TransactionBackend::new(client, capabilities)
            .with_server_side_encryption(S3ServerSideEncryption::Aes256);
        encrypted
            .put_object(&operation, Bytes::from_static(b"managed"))
            .await
            .unwrap();
        encrypted.create_multipart(&operation).await.unwrap();
        {
            let recorded = requests.lock().unwrap();
            let write_requests: Vec<_> = recorded
                .iter()
                .filter(|(method, _, _)| *method == Method::PUT || *method == Method::POST)
                .collect();
            assert_eq!(write_requests.len(), 2);
            for (_, _, headers) in write_requests {
                assert_eq!(
                    headers
                        .get("x-amz-server-side-encryption")
                        .and_then(|value| value.to_str().ok()),
                    Some("AES256")
                );
            }
        }

        requests.lock().unwrap().clear();
        let mut rewrite = operation;
        rewrite.expected.digest = Some("digest".to_string());
        rewrite.expected.size = Some(3);
        encrypted
            .rewrite_completed_multipart_metadata(&rewrite, Some("source/version +1"))
            .await
            .unwrap();
        let recorded = requests.lock().unwrap();
        assert!(recorded.iter().any(|(method, uri, headers)| {
            *method == Method::POST
                && uri.contains("uploads")
                && headers
                    .get("x-amz-server-side-encryption")
                    .and_then(|value| value.to_str().ok())
                    == Some("AES256")
        }));
        assert!(recorded.iter().any(|(method, uri, _)| {
            *method == Method::PUT
                && uri.contains("partNumber=1")
                && uri.contains("uploadId=new-upload")
        }));
        assert!(recorded.iter().any(|(method, uri, headers)| {
            *method == Method::PUT
                && uri.contains("uploadId=new-upload")
                && headers
                    .get("x-amz-copy-source")
                    .and_then(|value| value.to_str().ok())
                    == Some("bucket/key?versionId=source%2Fversion%20%2B1")
        }));
        server.abort();
    }

    #[tokio::test]
    async fn provider_put_accepts_a_zero_byte_object() {
        let (client, requests, server) = provider_client().await;
        let operation = OperationRecord::intent(destination(), ExpectedObject::default());
        let stored = AwsS3TransactionBackend::new(client, ScriptBackend::default().capabilities())
            .with_server_side_encryption(S3ServerSideEncryption::Aes256)
            .put_object(&operation, Bytes::new())
            .await
            .unwrap();

        assert_eq!(stored.version_id.as_deref(), Some("put-version"));
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, Method::PUT);
        assert_eq!(
            requests[0]
                .2
                .get("x-amz-server-side-encryption")
                .and_then(|value| value.to_str().ok()),
            Some("AES256")
        );
        drop(requests);
        server.abort();
    }

    #[tokio::test]
    async fn b2_recovery_enumerates_versions_inspects_mpu_and_deletes_exact_version() {
        let (client, requests, server) = provider_client().await;
        let capabilities = ScriptBackend::default().capabilities();
        let backend = AwsS3TransactionBackend::new_managed_b2(client, capabilities);
        let mut exact_destination = destination();
        exact_destination.physical_key = "physical".to_string();
        let mut operation = OperationRecord::scoped_intent(
            uuid::Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
            exact_destination,
            ExpectedObject {
                digest: Some("digest".to_string()),
                size: Some(3),
                metadata: std::collections::BTreeMap::new(),
            },
            "workspace".to_string(),
            1,
        );
        operation.created_at_ms = 0;

        let versions = backend.inspect_object_versions(&operation).await.unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().all(|version| {
            version.operation_matches
                && version.expected_metadata_matches
                && version.encryption_matches
        }));
        assert_eq!(
            backend
                .resolve_exact_version_history(&operation, Some("missing-version"))
                .await
                .unwrap(),
            None,
            "a missing response version must not fall back to another matching retry"
        );
        let error = backend
            .put_object(&operation, Bytes::from_static(b"new"))
            .await
            .unwrap_err();
        assert!(
            error
                .message
                .contains("exact provider version was not enumerable"),
            "unexpected managed PUT error: {}",
            error.message
        );
        assert_eq!(
            backend.probe_completion(&operation).await.unwrap(),
            CompletionProbe::Committed(StoredObjectMeta {
                etag: Some("\"etag-2\"".to_string()),
                version_id: Some("version-2".to_string()),
                superseded_version_ids: vec!["version-1".to_string()],
                version_history_complete: true,
            })
        );

        let uploads = backend.inspect_multipart_uploads(&operation).await.unwrap();
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].upload.upload_id, "incomplete-upload");
        assert_eq!(uploads[0].parts.len(), 1);
        assert_eq!(uploads[0].parts[0].part_number, 1);

        backend
            .delete_object_version(&operation, "version-1")
            .await
            .unwrap();
        assert!(requests.lock().unwrap().iter().any(|(method, uri, _)| {
            *method == Method::DELETE && uri.contains("versionId=version-1")
        }));
        server.abort();
    }

    #[tokio::test]
    async fn b2_version_history_paginates_and_deduplicates_version_ids() {
        let (client, requests, server) = provider_client().await;
        let backend = AwsS3TransactionBackend::new_managed_b2(
            client,
            ScriptBackend::default().capabilities(),
        );
        let mut exact_destination = destination();
        exact_destination.physical_key = "paginated".to_string();
        let mut operation = OperationRecord::scoped_intent(
            uuid::Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
            exact_destination,
            ExpectedObject {
                digest: Some("digest".to_string()),
                size: Some(3),
                metadata: std::collections::BTreeMap::new(),
            },
            "workspace".to_string(),
            1,
        );
        operation.created_at_ms = 0;

        let versions = backend.inspect_object_versions(&operation).await.unwrap();
        assert_eq!(
            versions
                .iter()
                .map(|version| version.version_id.as_str())
                .collect::<Vec<_>>(),
            ["version-1", "version-2"]
        );
        assert_eq!(
            backend
                .resolve_exact_version_history(&operation, Some("version-2"))
                .await
                .unwrap()
                .unwrap()
                .superseded_version_ids,
            ["version-1"]
        );
        let version_pages: Vec<_> = requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, uri, _)| *method == Method::GET && uri.contains("versions"))
            .map(|(_, uri, _)| uri.clone())
            .collect();
        assert_eq!(
            version_pages.len(),
            4,
            "both inspections must read two pages"
        );
        assert!(
            version_pages
                .iter()
                .any(|uri| uri.contains("version-id-marker=version-1"))
        );
        server.abort();
    }

    #[tokio::test]
    async fn direct_scope_persists_authorization_operation_and_workspace() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        let backend = Arc::new(ScriptBackend::default());
        let authorization = crate::control::UsageAuthorization::new(
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            "bucket",
            crate::control::UsageRoute::PutObject,
            crate::control::RequestKind::Write,
            64 * 1024 * 1024,
        );
        let (signal, _receiver) = AbortSignal::channel(1);
        let sink = DirectS3Sink::new_direct(
            journal.clone(),
            backend,
            super::super::DirectOperationScope {
                operation_id: authorization.operation_id(),
                tenant_id: "workspace-a".to_string(),
            },
            destination(),
            ExpectedObject::default(),
            1,
            signal,
        )
        .await
        .unwrap();

        assert_eq!(sink.operation_id(), authorization.operation_id());
        let operation = journal
            .get(authorization.operation_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(operation.tenant_id.as_deref(), Some("workspace-a"));
        assert_eq!(operation.namespace_epoch, None);
    }

    #[test]
    fn verified_multipart_metadata_replaces_initiation_metadata() {
        let mut operation = OperationRecord::intent(
            destination(),
            ExpectedObject {
                metadata: std::collections::BTreeMap::from([(
                    "s4-generation".to_string(),
                    "generation".to_string(),
                )]),
                ..ExpectedObject::default()
            },
        );
        let initiation_metadata = object_metadata(&operation);

        assert!(metadata_matches(Some(&initiation_metadata), &operation));
        assert!(!initiation_metadata.contains_key("s4-sha256"));
        assert!(!initiation_metadata.contains_key("s4-size"));

        operation.expected.digest = Some("verified-digest".to_string());
        operation.expected.size = Some((DIRECT_PART_BYTES + 1) as u64);

        assert!(!metadata_matches(Some(&initiation_metadata), &operation));
        let completed_metadata = object_metadata(&operation);
        assert!(metadata_matches(Some(&completed_metadata), &operation));
        assert_eq!(
            completed_metadata.get("s4-sha256"),
            Some(&"verified-digest".to_string())
        );
        assert_eq!(
            completed_metadata.get("s4-size"),
            Some(&(DIRECT_PART_BYTES + 1).to_string())
        );
    }

    #[tokio::test]
    async fn below_or_at_threshold_is_one_retryable_put() {
        for size in [0, DIRECT_PART_BYTES - 1, DIRECT_PART_BYTES] {
            let journal = Arc::new(InMemoryOperationJournal::new());
            let backend = Arc::new(ScriptBackend::default());
            backend.fail_next("put");
            let (mut sink, _) = sink(journal.clone(), backend.clone(), 2).await;
            sink.write(Bytes::from(vec![7; size])).await.unwrap();
            verify_buffered_output(&mut sink).await;
            sink.complete().await.unwrap();
            let bodies = backend.bodies("put");
            assert_eq!(bodies.len(), 2);
            assert_eq!(bodies[0], bodies[1]);
            assert_eq!(bodies[0].len(), size);
            assert_eq!(
                journal
                    .get(sink.operation_id())
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                OperationState::Committed
            );
        }
    }

    #[tokio::test]
    async fn threshold_crossing_uses_sequential_immutable_parts() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        let backend = Arc::new(ScriptBackend::default());
        backend.fail_next("part-1");
        let (mut sink, _) = sink(journal.clone(), backend.clone(), 2).await;
        sink.write(Bytes::from(vec![9; DIRECT_PART_BYTES + 17]))
            .await
            .unwrap();
        verify_buffered_output(&mut sink).await;
        sink.complete().await.unwrap();
        let first = backend.bodies("part-1");
        assert_eq!(first.len(), 2);
        assert_eq!(first[0], first[1]);
        assert_eq!(first[0].len(), DIRECT_PART_BYTES);
        assert_eq!(backend.bodies("part-2")[0].len(), 17);
        let parts = journal.parts(sink.operation_id()).await.unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[1].part_number, 2);
    }

    #[tokio::test]
    async fn lost_complete_response_is_reconciled_before_returning() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        let backend = Arc::new(ScriptBackend::default());
        backend.fail_next("complete");
        let (mut sink, _) = sink(journal.clone(), backend.clone(), 1).await;
        sink.write(Bytes::from(vec![1; DIRECT_PART_BYTES + 1]))
            .await
            .unwrap();
        verify_buffered_output(&mut sink).await;
        sink.complete().await.unwrap();
        let operation_id = sink.operation_id();
        assert_eq!(
            journal.get(operation_id).await.unwrap().unwrap().state,
            OperationState::Committed
        );
        assert!(
            !journal
                .get(operation_id)
                .await
                .unwrap()
                .unwrap()
                .committed
                .unwrap()
                .version_history_complete
        );
        assert!(
            journal
                .evidence(operation_id)
                .await
                .unwrap()
                .iter()
                .any(|evidence| evidence.kind == "provider_version_history_ambiguous")
        );
        assert!(
            !backend
                .state
                .lock()
                .unwrap()
                .events
                .contains(&"abort".to_string())
        );
    }

    #[tokio::test]
    async fn provider_commit_survives_transient_committed_journal_failure() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        journal.fail_next_committed_transitions(1);
        let backend = Arc::new(ScriptBackend::default());
        let (mut sink, _) = sink(journal.clone(), backend, 1).await;
        sink.write(Bytes::from_static(b"committed")).await.unwrap();
        verify_buffered_output(&mut sink).await;

        sink.complete().await.unwrap();

        assert_eq!(sink.commit_state(), SinkCommitState::Committed);
        assert_eq!(
            journal
                .get(sink.operation_id())
                .await
                .unwrap()
                .unwrap()
                .state,
            OperationState::Committed
        );
    }

    #[tokio::test]
    async fn unresolved_committed_journal_failure_reports_commit_unknown() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        journal.fail_next_committed_transitions(2);
        let backend = Arc::new(ScriptBackend::default());
        let (mut sink, _) = sink(journal.clone(), backend.clone(), 1).await;
        sink.write(Bytes::from_static(b"committed")).await.unwrap();
        verify_buffered_output(&mut sink).await;

        assert!(sink.complete().await.is_err());
        assert_eq!(sink.commit_state(), SinkCommitState::CommitUnknown);
        assert_eq!(
            journal
                .get(sink.operation_id())
                .await
                .unwrap()
                .unwrap()
                .state,
            OperationState::CommitUnknown
        );

        let reconciler = OperationReconciler::new(journal.clone(), backend, "retry").unwrap();
        reconciler
            .reconcile_operation(sink.operation_id(), Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            journal
                .get(sink.operation_id())
                .await
                .unwrap()
                .unwrap()
                .state,
            OperationState::Committed
        );
    }

    #[tokio::test]
    async fn confirmed_provider_success_with_absent_probe_stays_commit_unknown() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        journal.fail_next_committed_transitions(1);
        let backend = Arc::new(ScriptBackend::default());
        backend.force_absent_probe();
        let (mut sink, _) = sink(journal.clone(), backend, 1).await;
        sink.write(Bytes::from_static(b"committed")).await.unwrap();
        verify_buffered_output(&mut sink).await;

        assert!(sink.complete().await.is_err());
        assert_eq!(sink.commit_state(), SinkCommitState::CommitUnknown);
        assert_eq!(
            journal
                .get(sink.operation_id())
                .await
                .unwrap()
                .unwrap()
                .state,
            OperationState::CommitUnknown
        );
    }

    #[tokio::test]
    async fn ambiguous_provider_result_with_absent_probe_stays_commit_unknown() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        let backend = Arc::new(ScriptBackend::default());
        backend.fail_next("put");
        backend.force_absent_probe();
        let (mut sink, _) = sink(journal.clone(), backend, 1).await;
        sink.write(Bytes::from_static(b"ambiguous")).await.unwrap();
        verify_buffered_output(&mut sink).await;

        assert!(sink.complete().await.is_err());
        assert_eq!(sink.commit_state(), SinkCommitState::CommitUnknown);
        assert_eq!(
            journal
                .get(sink.operation_id())
                .await
                .unwrap()
                .unwrap()
                .state,
            OperationState::CommitUnknown
        );
    }

    #[tokio::test]
    async fn exact_reconciliation_never_claims_another_backend_operation() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        let backend = Arc::new(ScriptBackend::default());
        let first = OperationRecord::intent(destination(), ExpectedObject::default());
        let mut second_destination = destination();
        second_destination.backend_id = "other-backend".to_string();
        let second = OperationRecord::intent(second_destination, ExpectedObject::default());
        for operation in [&first, &second] {
            journal.insert_intent(operation.clone()).await.unwrap();
            journal.set_open(operation.id, None).await.unwrap();
            journal
                .transition(
                    operation.id,
                    OperationState::Open,
                    OperationState::Completing,
                    None,
                )
                .await
                .unwrap();
        }
        backend.state.lock().unwrap().committed.insert(
            first.id,
            StoredObjectMeta {
                etag: Some("first".to_string()),
                version_id: None,
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            },
        );

        let reconciler = OperationReconciler::new(journal.clone(), backend, "exact").unwrap();
        reconciler
            .reconcile_operation(first.id, Duration::ZERO)
            .await
            .unwrap();

        assert_eq!(
            journal.get(first.id).await.unwrap().unwrap().state,
            OperationState::Committed
        );
        assert_eq!(
            journal.get(second.id).await.unwrap().unwrap().state,
            OperationState::Completing
        );
    }

    #[tokio::test]
    async fn source_failure_aborts_and_drop_signals_supervisor() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        let backend = Arc::new(ScriptBackend::default());
        let (mut transaction, mut signals) = sink(journal.clone(), backend, 1).await;
        transaction
            .write(Bytes::from_static(b"first"))
            .await
            .unwrap();
        // A future source pump calls abort when its next frame fails.
        transaction.abort().await.unwrap();
        assert_eq!(
            journal
                .get(transaction.operation_id())
                .await
                .unwrap()
                .unwrap()
                .state,
            OperationState::ProvenAborted
        );

        let (unfinished, _) = sink(
            Arc::new(InMemoryOperationJournal::new()),
            Arc::new(ScriptBackend::default()),
            1,
        )
        .await;
        let unfinished_id = unfinished.operation_id();
        drop(unfinished);
        // The receiver paired with the first, completed sink remains empty.
        assert!(signals.try_recv().is_err());

        let (signal, mut receiver) = AbortSignal::channel(1);
        signal.signal(unfinished_id);
        assert_eq!(receiver.recv().await, Some(unfinished_id));
    }

    #[tokio::test]
    async fn create_before_id_crash_is_discovered_within_sla() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        let backend = Arc::new(ScriptBackend::default());
        let operation = OperationRecord::intent(destination(), ExpectedObject::default());
        journal.insert_intent(operation.clone()).await.unwrap();
        backend
            .state
            .lock()
            .unwrap()
            .uploads
            .insert(operation.id, "lost-response-upload".to_string());

        let reconciler =
            OperationReconciler::new(journal.clone(), backend.clone(), "restart").unwrap();
        reconciler
            .reconcile_operation(operation.id, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(
            journal.get(operation.id).await.unwrap().unwrap().state,
            OperationState::ProvenAborted
        );
        assert!(backend.state.lock().unwrap().uploads.is_empty());
        assert!(
            backend.capabilities().cleanup_sla.unwrap()
                <= crate::transaction::MAX_RECONCILIATION_SLA
        );
    }
}
