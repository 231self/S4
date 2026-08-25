use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use sha2::{Digest, Sha256};

use crate::store::MemoryStore;

use super::{ObjectSinkTransaction, StoredObjectMeta, TransactionError};

/// Development-only atomic sink. Its configured limit is a hard memory bound;
/// bytes are published to MemoryStore only after complete validation.
pub struct MemorySinkTransaction {
    store: Arc<MemoryStore>,
    bucket: String,
    key: String,
    content_type: String,
    max_bytes: usize,
    buffer: BytesMut,
    hasher: Sha256,
    output_verified: bool,
    finished: bool,
}

impl MemorySinkTransaction {
    pub fn new(
        store: Arc<MemoryStore>,
        bucket: impl Into<String>,
        key: impl Into<String>,
        content_type: impl Into<String>,
        max_bytes: usize,
    ) -> Result<Self, TransactionError> {
        if max_bytes == 0 {
            return Err(TransactionError::OutputMismatch);
        }
        Ok(Self {
            store,
            bucket: bucket.into(),
            key: key.into(),
            content_type: content_type.into(),
            max_bytes,
            buffer: BytesMut::new(),
            hasher: Sha256::new(),
            output_verified: false,
            finished: false,
        })
    }
}

#[async_trait]
impl ObjectSinkTransaction for MemorySinkTransaction {
    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        if self.buffer.len().saturating_add(chunk.len()) > self.max_bytes {
            return Err(TransactionError::CapacityExceeded);
        }
        self.hasher.update(&chunk);
        self.output_verified = false;
        self.buffer.extend_from_slice(&chunk);
        Ok(())
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        let size_matches = u64::try_from(self.buffer.len()) == Ok(expected_size);
        let digest_matches = hex::encode(self.hasher.clone().finalize()) == expected_sha256;
        if !size_matches || !digest_matches {
            return Err(TransactionError::OutputMismatch);
        }
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
        let object = self.store.put(
            &self.bucket,
            &self.key,
            self.buffer.split().freeze(),
            &self.content_type,
        );
        self.finished = true;
        Ok(StoredObjectMeta {
            etag: Some(object.etag),
            version_id: None,
            superseded_version_ids: Vec::new(),
            version_history_complete: true,
        })
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        self.buffer.clear();
        self.finished = true;
        Ok(())
    }
}
