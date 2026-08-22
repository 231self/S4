use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use bytes::{Buf, Bytes, BytesMut};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    AbortSignal, BackendCapabilities, BackendError, CompletionProbe, DIRECT_PART_BYTES,
    DiscoveredUpload, EvidenceRecord, ObjectDestination, ObjectSinkTransaction, OperationJournal,
    OperationRecord, OperationState, PartRecord, StoredObjectMeta, TransactionBackend,
    TransactionError, UploadedPart, sha256_hex, unix_time_ms,
};

#[derive(Clone)]
pub struct AwsS3TransactionBackend {
    client: Client,
    capabilities: BackendCapabilities,
}

impl AwsS3TransactionBackend {
    /// Capabilities are supplied by exact-provider configuration. They are not
    /// guessed from endpoints or error text.
    pub fn new(client: Client, capabilities: BackendCapabilities) -> Self {
        Self {
            client,
            capabilities,
        }
    }

    async fn rewrite_completed_multipart_metadata(
        &self,
        operation: &OperationRecord,
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
            .send()
            .await
            .map_err(ambiguous)?;
        let upload_id = upload.upload_id().ok_or_else(|| {
            BackendError::ambiguous("metadata rewrite create-multipart response omitted upload ID")
        })?;
        let source = copy_source(operation);
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
                    .map_err(ambiguous)?;
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
                .map_err(ambiguous)?;
            Ok(StoredObjectMeta {
                etag: output.e_tag().map(ToOwned::to_owned),
                version_id: output.version_id().map(ToOwned::to_owned),
            })
        }
        .await;
        if result.is_err() {
            let _ = self
                .client
                .abort_multipart_upload()
                .bucket(&operation.destination.bucket)
                .key(&operation.destination.physical_key)
                .upload_id(upload_id)
                .send()
                .await;
        }
        result
    }

    async fn finalized_multipart(
        &self,
        operation: &OperationRecord,
    ) -> Result<CompletionProbe, BackendError> {
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
                    return Ok(CompletionProbe::Committed(StoredObjectMeta {
                        etag: output.e_tag().map(ToOwned::to_owned),
                        version_id: output.version_id().map(ToOwned::to_owned),
                    }));
                }
                self.rewrite_completed_multipart_metadata(operation)
                    .await
                    .map(CompletionProbe::Committed)
            }
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_not_found()) =>
            {
                Ok(CompletionProbe::ProvenAbsent)
            }
            Err(error) => Err(ambiguous(error)),
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

fn copy_source(operation: &OperationRecord) -> String {
    let mut source = format!("{}/", operation.destination.bucket);
    for byte in operation.destination.physical_key.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            source.push(char::from(byte));
        } else {
            use std::fmt::Write;

            write!(source, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    source
}

fn ambiguous(error: impl std::fmt::Display) -> BackendError {
    BackendError::ambiguous(error.to_string())
}

#[async_trait]
impl TransactionBackend for AwsS3TransactionBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities
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
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(ambiguous)?;
        Ok(StoredObjectMeta {
            etag: output.e_tag().map(ToOwned::to_owned),
            version_id: output.version_id().map(ToOwned::to_owned),
        })
    }

    async fn create_multipart(&self, operation: &OperationRecord) -> Result<String, BackendError> {
        let output = self
            .client
            .create_multipart_upload()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .set_content_type(operation.expected.metadata.get("content-type").cloned())
            .set_metadata(Some(object_metadata(operation)))
            .send()
            .await
            .map_err(ambiguous)?;
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
            .map_err(ambiguous)?;
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
        self.client
            .complete_multipart_upload()
            .bucket(&operation.destination.bucket)
            .key(&operation.destination.physical_key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(ambiguous)?;
        self.rewrite_completed_multipart_metadata(operation).await
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
            .map_err(ambiguous)?;
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
                .set_key_marker(key_marker)
                .set_upload_id_marker(upload_id_marker)
                .send()
                .await
                .map_err(ambiguous)?;
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
            key_marker = output.next_key_marker().map(ToOwned::to_owned);
            upload_id_marker = output.next_upload_id_marker().map(ToOwned::to_owned);
            if key_marker.is_none() {
                return Err(BackendError::ambiguous(
                    "multipart discovery was truncated without a continuation marker",
                ));
            }
        }
        Ok(discovered)
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
        backend.capabilities().streaming_eligibility()?;
        let operation = OperationRecord::intent(destination, expected);
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
                Ok(meta) => {
                    self.journal
                        .transition(
                            self.operation.id,
                            OperationState::Completing,
                            OperationState::Committed,
                            Some(&meta),
                        )
                        .await?;
                    self.evidence("put_object_after", json!({"attempt": attempt}))
                        .await?;
                    return Ok(meta);
                }
                Err(error) => last_error = Some(error),
            }
        }
        self.mark_commit_unknown().await?;
        Err(last_error
            .unwrap_or_else(|| BackendError::ambiguous("PUT retry budget exhausted"))
            .into())
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
                Ok(meta) => {
                    self.journal
                        .transition(
                            self.operation.id,
                            OperationState::Completing,
                            OperationState::Committed,
                            Some(&meta),
                        )
                        .await?;
                    self.evidence("complete_multipart_after", json!({"attempt": attempt}))
                        .await?;
                    return Ok(meta);
                }
                Err(error) => last_error = Some(error),
            }
        }
        self.mark_commit_unknown().await?;
        Err(last_error
            .unwrap_or_else(|| BackendError::ambiguous("complete retry budget exhausted"))
            .into())
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

    use super::*;
    use crate::transaction::{
        CompletionReconciliation, ExpectedObject, InMemoryOperationJournal,
        IncompleteUploadDiscovery, OperationReconciler, VersioningCapability,
    };

    #[derive(Default)]
    struct ScriptState {
        events: Vec<String>,
        failures: VecDeque<String>,
        bodies: HashMap<String, Vec<Vec<u8>>>,
        committed: HashMap<uuid::Uuid, StoredObjectMeta>,
        uploads: HashMap<uuid::Uuid, String>,
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
            Ok(self
                .state
                .lock()
                .unwrap()
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
    async fn lost_complete_response_is_never_aborted_and_restart_reconciles_commit() {
        let journal = Arc::new(InMemoryOperationJournal::new());
        let backend = Arc::new(ScriptBackend::default());
        backend.fail_next("complete");
        let (mut sink, _) = sink(journal.clone(), backend.clone(), 1).await;
        sink.write(Bytes::from(vec![1; DIRECT_PART_BYTES + 1]))
            .await
            .unwrap();
        verify_buffered_output(&mut sink).await;
        assert!(sink.complete().await.is_err());
        let operation_id = sink.operation_id();
        assert_eq!(
            journal.get(operation_id).await.unwrap().unwrap().state,
            OperationState::CommitUnknown
        );
        assert!(matches!(
            sink.abort().await,
            Err(TransactionError::CompletionAmbiguous)
        ));

        let reconciler =
            OperationReconciler::new(journal.clone(), backend.clone(), "restart").unwrap();
        reconciler.reconcile_due(Duration::ZERO, 10).await.unwrap();
        assert_eq!(
            journal.get(operation_id).await.unwrap().unwrap().state,
            OperationState::Committed
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
        reconciler.reconcile_due(Duration::ZERO, 10).await.unwrap();
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
