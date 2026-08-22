//! Encrypted, bounded staging for transformed reads.
//!
//! The key deliberately lives only in the request task. A stale file is
//! unreadable after a restart and is removed by the existing spool cleanup.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use bytes::Bytes;
use http_body::Frame;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::transaction::{READ_FILE_PREFIX, SpoolQuota, TransactionError};
use s4_wasm_runtime::CancellationToken;

const NONCE_BYTES: usize = 12;
const PLAINTEXT_FRAME_BYTES: usize = 64 * 1024;
const FRAME_OVERHEAD_BYTES: u64 = 4 + NONCE_BYTES as u64 + 16;

/// The response-side counterpart of the compatibility upload spool. It writes
/// independently authenticated chunks, so neither the complete plaintext nor
/// ciphertext object is retained in memory.
pub struct EncryptedReadSpool {
    path: PathBuf,
    file: Option<File>,
    quota: Arc<SpoolQuota>,
    reserved_bytes: u64,
    max_object_bytes: u64,
    bytes: u64,
    key: [u8; 32],
    chunk_number: u64,
    pending: Vec<u8>,
}

impl EncryptedReadSpool {
    pub async fn begin(
        directory: PathBuf,
        max_object_bytes: u64,
        quota: Arc<SpoolQuota>,
    ) -> Result<Self, TransactionError> {
        if max_object_bytes == 0 {
            return Err(TransactionError::Spool(
                "transformed-read spool object limit must be greater than zero".to_string(),
            ));
        }
        let reserved_bytes = disk_reservation(max_object_bytes)?;
        quota.reserve_bytes(reserved_bytes)?;
        if let Err(error) = tokio::fs::create_dir_all(&directory).await {
            quota.release_bytes(reserved_bytes);
            return Err(TransactionError::Spool(error.to_string()));
        }
        let path = directory.join(format!("{READ_FILE_PREFIX}{}.tmp", Uuid::now_v7()));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let file = match options.open(&path).await {
            Ok(file) => file,
            Err(error) => {
                quota.release_bytes(reserved_bytes);
                return Err(TransactionError::Spool(error.to_string()));
            }
        };
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Ok(Self {
            path,
            file: Some(file),
            quota,
            reserved_bytes,
            max_object_bytes,
            bytes: 0,
            key,
            chunk_number: 0,
            pending: Vec::with_capacity(PLAINTEXT_FRAME_BYTES),
        })
    }

    pub async fn write(&mut self, plaintext: Bytes) -> Result<(), TransactionError> {
        let next = self
            .bytes
            .checked_add(plaintext.len() as u64)
            .ok_or(TransactionError::CapacityExceeded)?;
        if next > self.max_object_bytes {
            return Err(TransactionError::CapacityExceeded);
        }
        self.bytes = next;
        let mut remaining = plaintext.as_ref();
        if !self.pending.is_empty() {
            let take = (PLAINTEXT_FRAME_BYTES - self.pending.len()).min(remaining.len());
            self.pending.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.pending.len() == PLAINTEXT_FRAME_BYTES {
                self.flush_pending().await?;
            }
        }
        while remaining.len() >= PLAINTEXT_FRAME_BYTES {
            let (chunk, rest) = remaining.split_at(PLAINTEXT_FRAME_BYTES);
            self.write_frame(chunk).await?;
            remaining = rest;
        }
        if !remaining.is_empty() {
            self.pending.extend_from_slice(remaining);
        }
        Ok(())
    }

    pub async fn into_body(
        mut self,
        cancellation: CancellationToken,
    ) -> Result<(axum::body::Body, u64), TransactionError> {
        self.flush_pending().await?;
        let file = self.file.take().ok_or(TransactionError::Finished)?;
        file.sync_all().await.map_err(spool_error)?;
        drop(file);
        let path = self.path.clone();
        let bytes = self.bytes;
        let key = self.key;
        let quota = Arc::clone(&self.quota);
        let reserved_bytes = self.reserved_bytes;
        self.reserved_bytes = 0;
        let (sender, receiver) = mpsc::channel(2);
        let task_cancellation = cancellation.clone();
        tokio::spawn(async move {
            let result =
                stream_decrypted_file(&path, key, task_cancellation.clone(), sender.clone()).await;
            if let Err(error) = result {
                task_cancellation.cancel();
                tracing::warn!("encrypted transformed-read spool failed: {error}");
                // Headers have already been emitted. Surface a body error so the
                // HTTP server terminates the representation instead of claiming a
                // successful, complete transformed response.
                let _ = sender.send(Err(error)).await;
            }
            let _ = tokio::fs::remove_file(&path).await;
            quota.release_bytes(reserved_bytes);
        });
        Ok((
            axum::body::Body::new(ChannelBody::new(receiver, cancellation)),
            bytes,
        ))
    }

    pub async fn abort(mut self) {
        self.file.take();
        let _ = tokio::fs::remove_file(&self.path).await;
        self.quota.release_bytes(self.reserved_bytes);
        self.reserved_bytes = 0;
    }

    async fn flush_pending(&mut self) -> Result<(), TransactionError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);
        self.write_frame(&pending).await
    }

    async fn write_frame(&mut self, plaintext: &[u8]) -> Result<(), TransactionError> {
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let aad = self.chunk_number.to_be_bytes();
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|error| TransactionError::Spool(error.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                TransactionError::Spool("transformed-read spool encryption failed".to_string())
            })?;
        let file = self.file.as_mut().ok_or(TransactionError::Finished)?;
        file.write_all(&(plaintext.len() as u32).to_be_bytes())
            .await
            .map_err(spool_error)?;
        file.write_all(&nonce).await.map_err(spool_error)?;
        file.write_all(&ciphertext).await.map_err(spool_error)?;
        self.chunk_number = self.chunk_number.saturating_add(1);
        Ok(())
    }

    #[cfg(test)]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for EncryptedReadSpool {
    fn drop(&mut self) {
        if self.reserved_bytes == 0 {
            return;
        }
        self.file.take();
        let _ = std::fs::remove_file(&self.path);
        self.quota.release_bytes(self.reserved_bytes);
        self.reserved_bytes = 0;
    }
}

async fn stream_decrypted_file(
    path: &std::path::Path,
    key: [u8; 32],
    cancellation: CancellationToken,
    sender: mpsc::Sender<Result<Bytes, io::Error>>,
) -> Result<(), io::Error> {
    let mut file = File::open(path).await?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(io::Error::other)?;
    let mut chunk_number = 0u64;
    loop {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        let mut length = [0u8; 4];
        let read = file.read(&mut length).await?;
        if read == 0 {
            return Ok(());
        }
        file.read_exact(&mut length[read..]).await?;
        let plaintext_len = u32::from_be_bytes(length) as usize;
        if plaintext_len > PLAINTEXT_FRAME_BYTES {
            return Err(io::Error::other(
                "transformed-read spool frame exceeds the encrypted staging bound",
            ));
        }
        let mut nonce = [0u8; NONCE_BYTES];
        file.read_exact(&mut nonce).await?;
        let mut ciphertext = vec![0u8; plaintext_len.saturating_add(16)];
        file.read_exact(&mut ciphertext).await?;
        let aad = chunk_number.to_be_bytes();
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| io::Error::other("transformed-read spool authentication failed"))?;
        chunk_number = chunk_number.saturating_add(1);
        if sender.send(Ok(Bytes::from(plaintext))).await.is_err() {
            cancellation.cancel();
            return Ok(());
        }
    }
}

fn spool_error(error: io::Error) -> TransactionError {
    TransactionError::Spool(error.to_string())
}

fn disk_reservation(max_object_bytes: u64) -> Result<u64, TransactionError> {
    let frames = max_object_bytes
        .checked_add(PLAINTEXT_FRAME_BYTES as u64 - 1)
        .ok_or(TransactionError::CapacityExceeded)?
        / PLAINTEXT_FRAME_BYTES as u64;
    max_object_bytes
        .checked_add(
            frames
                .checked_mul(FRAME_OVERHEAD_BYTES)
                .ok_or(TransactionError::CapacityExceeded)?,
        )
        .ok_or(TransactionError::CapacityExceeded)
}

/// Bounded response body backed by a worker. Dropping it interrupts both a
/// direct pipeline and an encrypted spool replay.
pub struct ChannelBody {
    receiver: mpsc::Receiver<Result<Bytes, io::Error>>,
    cancellation: CancellationToken,
    done: bool,
}

impl ChannelBody {
    pub fn new(
        receiver: mpsc::Receiver<Result<Bytes, io::Error>>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            receiver,
            cancellation,
            done: false,
        }
    }
}

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(error))) => {
                self.done = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        if !self.done {
            self.cancellation.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;

    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!("s4-read-spool-test-{}", Uuid::now_v7()))
    }

    async fn wait_for_release(quota: &SpoolQuota) {
        for _ in 0..20 {
            if quota.reserved_bytes() == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn encrypted_staging_never_contains_plaintext_and_replays_after_validation() {
        let directory = directory();
        let quota = Arc::new(SpoolQuota::new(128));
        let mut spool = EncryptedReadSpool::begin(directory.clone(), 64, Arc::clone(&quota))
            .await
            .unwrap();
        spool
            .write(Bytes::from_static(b"sensitive-email@example.com"))
            .await
            .unwrap();
        let ciphertext = std::fs::read(spool.path()).unwrap();
        assert!(
            !ciphertext
                .windows(b"sensitive-email@example.com".len())
                .any(|window| window == b"sensitive-email@example.com")
        );

        let (body, length) = spool.into_body(CancellationToken::new()).await.unwrap();
        assert_eq!(length, 27);
        assert_eq!(
            body.collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"sensitive-email@example.com")
        );
        wait_for_release(&quota).await;
        assert_eq!(quota.reserved_bytes(), 0);
        assert!(std::fs::read_dir(&directory).unwrap().next().is_none());
        let _ = tokio::fs::remove_dir(directory).await;
    }

    #[tokio::test]
    async fn quota_is_reserved_before_source_disclosure_and_released_on_abort() {
        let directory = directory();
        let quota = Arc::new(SpoolQuota::new(64));
        let spool = EncryptedReadSpool::begin(directory.clone(), 8, Arc::clone(&quota))
            .await
            .unwrap();
        assert_eq!(quota.reserved_bytes(), 40);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(spool.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(
            EncryptedReadSpool::begin(directory.clone(), 8, Arc::clone(&quota))
                .await
                .is_err()
        );
        spool.abort().await;
        assert_eq!(quota.reserved_bytes(), 0);
        let _ = tokio::fs::remove_dir(directory).await;
    }

    #[tokio::test]
    async fn dropping_replay_body_cancels_and_releases_the_staging_reservation() {
        let directory = directory();
        let quota = Arc::new(SpoolQuota::new(128));
        let mut spool = EncryptedReadSpool::begin(directory.clone(), 64, Arc::clone(&quota))
            .await
            .unwrap();
        spool.write(Bytes::from(vec![b'x'; 32])).await.unwrap();
        let cancellation = CancellationToken::new();
        let (body, _) = spool.into_body(cancellation.clone()).await.unwrap();
        drop(body);
        wait_for_release(&quota).await;
        assert!(cancellation.is_cancelled());
        assert_eq!(quota.reserved_bytes(), 0);
        let _ = tokio::fs::remove_dir(directory).await;
    }

    #[tokio::test]
    async fn truncated_staging_file_terminates_the_response_body() {
        let directory = directory();
        let quota = Arc::new(SpoolQuota::new(128 * 1024));
        let mut spool = EncryptedReadSpool::begin(
            directory.clone(),
            PLAINTEXT_FRAME_BYTES as u64,
            Arc::clone(&quota),
        )
        .await
        .unwrap();
        spool
            .write(Bytes::from(vec![b'x'; PLAINTEXT_FRAME_BYTES]))
            .await
            .unwrap();
        spool.file.as_mut().unwrap().sync_all().await.unwrap();
        let length = std::fs::metadata(spool.path()).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(spool.path())
            .unwrap()
            .set_len(length - 1)
            .unwrap();

        let (body, _) = spool.into_body(CancellationToken::new()).await.unwrap();
        assert!(body.collect().await.is_err());
        wait_for_release(&quota).await;
        assert_eq!(quota.reserved_bytes(), 0);
        let _ = tokio::fs::remove_dir(directory).await;
    }

    #[tokio::test]
    async fn corrupt_length_prefix_is_rejected_without_unbounded_allocation() {
        let directory = directory();
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let path = directory.join("corrupt.tmp");
        tokio::fs::write(&path, u32::MAX.to_be_bytes())
            .await
            .unwrap();
        let (sender, _receiver) = mpsc::channel(1);
        let error = stream_decrypted_file(&path, [0; 32], CancellationToken::new(), sender)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        let _ = tokio::fs::remove_file(path).await;
        let _ = tokio::fs::remove_dir(directory).await;
    }
}
