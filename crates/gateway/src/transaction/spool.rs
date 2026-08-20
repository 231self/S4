use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use super::{ObjectSinkTransaction, StoredObjectMeta, TransactionError};

const FILE_PREFIX: &str = "s4-spool-";

#[derive(Clone, Debug)]
pub struct CompatibilitySpoolConfig {
    pub directory: PathBuf,
    pub max_object_bytes: u64,
    pub stale_after: Duration,
}

#[derive(Debug)]
pub struct SpoolQuota {
    max_bytes: u64,
    reserved_bytes: AtomicU64,
}

impl SpoolQuota {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            reserved_bytes: AtomicU64::new(0),
        }
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes.load(Ordering::Acquire)
    }

    fn reserve(&self, bytes: u64) -> Result<(), TransactionError> {
        let mut current = self.reserved_bytes.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(bytes)
                .ok_or_else(|| TransactionError::Spool("spool quota overflow".to_string()))?;
            if next > self.max_bytes {
                return Err(TransactionError::CapacityExceeded);
            }
            match self.reserved_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    fn release(&self, bytes: u64) {
        self.reserved_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }
}

#[async_trait]
pub trait CompatibilitySpoolUploader: Send + Sync {
    async fn upload_file(
        &self,
        path: &Path,
        content_length: u64,
    ) -> Result<StoredObjectMeta, TransactionError>;
}

pub struct CompatibilitySpoolTransaction {
    config: CompatibilitySpoolConfig,
    quota: Arc<SpoolQuota>,
    uploader: Arc<dyn CompatibilitySpoolUploader>,
    path: PathBuf,
    file: Option<File>,
    bytes: u64,
    reserved_bytes: u64,
    output_hasher: Sha256,
    output_verified: bool,
    finished: bool,
}

impl CompatibilitySpoolTransaction {
    pub async fn begin(
        config: CompatibilitySpoolConfig,
        quota: Arc<SpoolQuota>,
        uploader: Arc<dyn CompatibilitySpoolUploader>,
    ) -> Result<Self, TransactionError> {
        if config.max_object_bytes == 0 || config.max_object_bytes > quota.max_bytes {
            return Err(TransactionError::Spool(
                "invalid compatibility spool object limit".to_string(),
            ));
        }
        quota.reserve(config.max_object_bytes)?;
        tokio::fs::create_dir_all(&config.directory)
            .await
            .map_err(|error| {
                quota.release(config.max_object_bytes);
                spool_error(error)
            })?;
        let path = config
            .directory
            .join(format!("{FILE_PREFIX}{}.tmp", Uuid::now_v7()));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true).read(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let file = options.open(&path).await.map_err(|error| {
            quota.release(config.max_object_bytes);
            spool_error(error)
        })?;
        let reserved_bytes = config.max_object_bytes;
        Ok(Self {
            config,
            quota,
            uploader,
            path,
            file: Some(file),
            bytes: 0,
            reserved_bytes,
            output_hasher: Sha256::new(),
            output_verified: false,
            finished: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn cleanup_stale(
        config: &CompatibilitySpoolConfig,
    ) -> Result<usize, TransactionError> {
        let mut entries = match tokio::fs::read_dir(&config.directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(spool_error(error)),
        };
        let cutoff = SystemTime::now()
            .checked_sub(config.stale_after)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut removed = 0;
        while let Some(entry) = entries.next_entry().await.map_err(spool_error)? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(FILE_PREFIX) || !name.ends_with(".tmp") {
                continue;
            }
            let metadata = entry.metadata().await.map_err(spool_error)?;
            if !metadata.is_file() || metadata.modified().map_err(spool_error)? > cutoff {
                continue;
            }
            tokio::fs::remove_file(entry.path())
                .await
                .map_err(spool_error)?;
            removed += 1;
        }
        Ok(removed)
    }

    async fn remove_file(&mut self) -> Result<(), TransactionError> {
        self.file.take();
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(spool_error(error)),
        }
    }
}

#[async_trait]
impl ObjectSinkTransaction for CompatibilitySpoolTransaction {
    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        let chunk_bytes = chunk.len() as u64;
        let next = self
            .bytes
            .checked_add(chunk_bytes)
            .ok_or_else(|| TransactionError::Spool("spool size overflow".to_string()))?;
        if next > self.config.max_object_bytes {
            return Err(TransactionError::CapacityExceeded);
        }
        let result = self
            .file
            .as_mut()
            .ok_or(TransactionError::Finished)?
            .write_all(&chunk)
            .await;
        if let Err(error) = result {
            return Err(spool_error(error));
        }
        self.bytes = next;
        self.output_hasher.update(&chunk);
        self.output_verified = false;
        Ok(())
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        let actual_digest = hex::encode(self.output_hasher.clone().finalize());
        if self.bytes != expected_size || actual_digest != expected_sha256 {
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
        let file = self.file.as_mut().ok_or(TransactionError::Finished)?;
        file.flush().await.map_err(spool_error)?;
        file.sync_all().await.map_err(spool_error)?;
        let result = self.uploader.upload_file(&self.path, self.bytes).await?;
        self.remove_file().await?;
        self.quota.release(self.reserved_bytes);
        self.reserved_bytes = 0;
        self.bytes = 0;
        self.finished = true;
        Ok(result)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        if self.finished {
            return Ok(());
        }
        self.remove_file().await?;
        self.quota.release(self.reserved_bytes);
        self.reserved_bytes = 0;
        self.bytes = 0;
        self.finished = true;
        Ok(())
    }
}

impl Drop for CompatibilitySpoolTransaction {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.file.take();
        let _ = std::fs::remove_file(&self.path);
        self.quota.release(self.reserved_bytes);
        self.reserved_bytes = 0;
        self.bytes = 0;
    }
}

fn spool_error(error: std::io::Error) -> TransactionError {
    TransactionError::Spool(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingUploader {
        attempts: Mutex<Vec<Vec<u8>>>,
        fail_first: Mutex<bool>,
    }

    #[async_trait]
    impl CompatibilitySpoolUploader for RecordingUploader {
        async fn upload_file(
            &self,
            path: &Path,
            content_length: u64,
        ) -> Result<StoredObjectMeta, TransactionError> {
            let body = tokio::fs::read(path).await.map_err(spool_error)?;
            assert_eq!(body.len() as u64, content_length);
            self.attempts.lock().unwrap().push(body);
            let mut fail_first = self.fail_first.lock().unwrap();
            if *fail_first {
                *fail_first = false;
                return Err(TransactionError::Spool(
                    "injected upload failure".to_string(),
                ));
            }
            Ok(StoredObjectMeta::default())
        }
    }

    fn config(directory: PathBuf, max_object_bytes: u64) -> CompatibilitySpoolConfig {
        CompatibilitySpoolConfig {
            directory,
            max_object_bytes,
            stale_after: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn quota_object_limit_abort_and_permissions_are_enforced() {
        let directory = std::env::temp_dir().join(format!("s4-spool-test-{}", Uuid::now_v7()));
        let quota = Arc::new(SpoolQuota::new(5));
        let uploader = Arc::new(RecordingUploader::default());
        let mut transaction = CompatibilitySpoolTransaction::begin(
            config(directory.clone(), 4),
            quota.clone(),
            uploader,
        )
        .await
        .unwrap();
        transaction
            .write(Bytes::from_static(b"1234"))
            .await
            .unwrap();
        assert!(transaction.write(Bytes::from_static(b"5")).await.is_err());
        assert_eq!(quota.reserved_bytes(), 4);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(transaction.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let path = transaction.path().to_path_buf();
        transaction.abort().await.unwrap();
        assert!(!path.exists());
        assert_eq!(quota.reserved_bytes(), 0);
        let _ = std::fs::remove_dir(directory);
    }

    #[tokio::test]
    async fn failed_upload_retries_the_identical_immutable_file() {
        let directory = std::env::temp_dir().join(format!("s4-spool-test-{}", Uuid::now_v7()));
        let quota = Arc::new(SpoolQuota::new(1024));
        let uploader = Arc::new(RecordingUploader {
            attempts: Mutex::default(),
            fail_first: Mutex::new(true),
        });
        let mut transaction = CompatibilitySpoolTransaction::begin(
            config(directory.clone(), 1024),
            quota.clone(),
            uploader.clone(),
        )
        .await
        .unwrap();
        transaction
            .write(Bytes::from_static(b"immutable"))
            .await
            .unwrap();
        let digest = hex::encode(transaction.output_hasher.clone().finalize());
        transaction
            .verify_output(transaction.bytes, &digest)
            .await
            .unwrap();
        assert!(transaction.complete().await.is_err());
        assert!(transaction.path().exists());
        transaction.complete().await.unwrap();
        let attempts = uploader.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0], attempts[1]);
        assert_eq!(quota.reserved_bytes(), 0);
        let _ = std::fs::remove_dir(directory);
    }

    #[tokio::test]
    async fn cleanup_removes_only_recognized_stale_regular_files() {
        let directory = std::env::temp_dir().join(format!("s4-spool-test-{}", Uuid::now_v7()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let stale = directory.join(format!("{FILE_PREFIX}old.tmp"));
        let unrelated = directory.join("keep.tmp");
        tokio::fs::write(&stale, b"stale").await.unwrap();
        tokio::fs::write(&unrelated, b"keep").await.unwrap();
        let removed = CompatibilitySpoolTransaction::cleanup_stale(&config(directory.clone(), 1))
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(!stale.exists());
        assert!(unrelated.exists());
        let _ = std::fs::remove_file(unrelated);
        let _ = std::fs::remove_dir(directory);
    }
}
