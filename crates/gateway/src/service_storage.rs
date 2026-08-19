use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use tokio::sync::RwLock;
use tracing::{info, warn};

pub const VIRTUAL_NODES: usize = 150;

#[derive(Debug, PartialEq, Eq)]
pub enum ServiceStorageReadError {
    EntityTooLarge,
}

enum CollectBodyError {
    EntityTooLarge,
    Backend,
}

async fn collect_body(mut body: ByteStream, max_bytes: usize) -> Result<Vec<u8>, CollectBodyError> {
    let (_, upper) = body.size_hint();
    if upper.is_some_and(|size| size > max_bytes as u64) {
        return Err(CollectBodyError::EntityTooLarge);
    }
    let mut data = Vec::with_capacity(upper.unwrap_or(0).min(max_bytes as u64) as usize);
    while let Some(chunk) = body
        .try_next()
        .await
        .map_err(|_| CollectBodyError::Backend)?
    {
        if chunk.len() > max_bytes.saturating_sub(data.len()) {
            return Err(CollectBodyError::EntityTooLarge);
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

#[derive(Debug, Clone)]
pub struct ServiceBackend {
    pub provider: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

impl ServiceBackend {
    pub fn id(&self) -> String {
        format!("{}:{}", self.provider, self.bucket)
    }

    pub async fn build_client(&self) -> Option<Client> {
        let access_key = self.access_key.clone();
        let secret_key = self.secret_key.clone();
        let region = self.region.clone();
        let endpoint = self.endpoint.clone();
        let creds = Credentials::new(access_key, secret_key, None, None, "s4-service");
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(region))
            .endpoint_url(&endpoint)
            .credentials_provider(creds)
            .load()
            .await;
        Some(Client::new(&config))
    }
}

fn hash_key(key: &str) -> u64 {
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    h.finish()
}

fn vnode_hash(backend_id: &str, vnode: usize) -> u64 {
    let mut h = DefaultHasher::new();
    format!("{}:{}", backend_id, vnode).hash(&mut h);
    h.finish()
}

#[derive(Debug)]
pub struct ServiceStorage {
    pub backends: Vec<ServiceBackend>,
    ring: BTreeMap<u64, usize>,
    clients: RwLock<Vec<Option<Client>>>,
}

impl ServiceStorage {
    pub fn new(backends: Vec<ServiceBackend>) -> Self {
        let n = backends.len();
        let mut ring = BTreeMap::new();
        for (bi, backend) in backends.iter().enumerate() {
            for vi in 0..VIRTUAL_NODES {
                let pos = vnode_hash(&backend.id(), vi);
                ring.insert(pos, bi);
            }
        }
        let clients = RwLock::new(vec![None; n]);
        Self {
            backends,
            ring,
            clients,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    fn primary_index(&self, key: &str) -> usize {
        let h = hash_key(key);
        self.ring
            .range(h..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, &bi)| bi)
            .unwrap_or(0)
    }

    fn replica_index(&self, key: &str, primary: usize) -> Option<usize> {
        if self.backends.len() < 2 {
            return None;
        }
        let h = hash_key(key);
        self.ring
            .range(h..)
            .chain(self.ring.iter())
            .find(|&(_, bi)| *bi != primary)
            .map(|(_, &bi)| bi)
    }

    fn get_backend_ids(&self, key: &str) -> (usize, Option<usize>) {
        let primary = self.primary_index(key);
        let replica = self.replica_index(key, primary);
        (primary, replica)
    }

    async fn client_for(&self, index: usize) -> Option<Client> {
        {
            let clients = self.clients.read().await;
            if let Some(Some(c)) = clients.get(index) {
                return Some(c.clone());
            }
        }
        let client = self.backends[index].build_client().await;
        if let Some(ref c) = client {
            let mut clients = self.clients.write().await;
            clients[index] = Some(c.clone());
        }
        client
    }

    pub async fn put(&self, key: &str, data: Bytes, content_type: &str) -> anyhow::Result<()> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        info!(
            "service storage PUT {key} -> primary={} replica={:?}",
            self.backends[primary].id(),
            replica_opt.map(|r| self.backends[r].id())
        );

        let primary_client = self.client_for(primary).await.ok_or_else(|| {
            anyhow::anyhow!(
                "No client for primary backend {}",
                self.backends[primary].id()
            )
        })?;

        let put_fut = primary_client
            .put_object()
            .bucket(&self.backends[primary].bucket)
            .key(key)
            .content_type(content_type)
            .body(ByteStream::from(data.clone()))
            .send();

        let replica_fut = if let Some(ri) = replica_opt {
            let bucket = self.backends[ri].bucket.clone();
            let bid = self.backends[ri].id();
            self.client_for(ri).await.map(|rc| async move {
                let _ = rc
                    .put_object()
                    .bucket(&bucket)
                    .key(key)
                    .content_type(content_type)
                    .body(ByteStream::from(data))
                    .send()
                    .await
                    .map_err(|e| warn!("replica PUT failed for {bid}: {e}"));
            })
        } else {
            None
        };

        if let Some(rf) = replica_fut {
            let (primary_result, _) = tokio::join!(put_fut, rf);
            primary_result?;
        } else {
            put_fut.await?;
        }

        Ok(())
    }

    pub async fn open(
        &self,
        key: &str,
        range: Option<&str>,
    ) -> Option<aws_sdk_s3::operation::get_object::GetObjectOutput> {
        let (primary, replica_opt) = self.get_backend_ids(key);

        let try_get = |index: usize| async move {
            let client = self.client_for(index).await?;
            let mut request = client
                .get_object()
                .bucket(&self.backends[index].bucket)
                .key(key);
            if let Some(range) = range {
                request = request.range(range);
            }
            request.send().await.ok()
        };

        if let Some(output) = try_get(primary).await {
            return Some(output);
        }
        info!("primary miss for {key}, trying replica");
        if let Some(replica) = replica_opt {
            return try_get(replica).await;
        }
        None
    }

    pub async fn get(
        &self,
        key: &str,
        max_bytes: usize,
    ) -> Result<Option<(Vec<u8>, String)>, ServiceStorageReadError> {
        let (primary, replica_opt) = self.get_backend_ids(key);

        let try_get = |index: usize| async move {
            let Some(client) = self.client_for(index).await else {
                return Ok(None);
            };
            let Ok(resp) = client
                .get_object()
                .bucket(&self.backends[index].bucket)
                .key(key)
                .send()
                .await
            else {
                return Ok(None);
            };
            let ct = resp
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string());
            match collect_body(resp.body, max_bytes).await {
                Ok(data) => Ok(Some((data, ct))),
                Err(CollectBodyError::EntityTooLarge) => {
                    Err(ServiceStorageReadError::EntityTooLarge)
                }
                Err(CollectBodyError::Backend) => Ok(None),
            }
        };

        if let Some(result) = try_get(primary).await? {
            return Ok(Some(result));
        }

        info!("primary miss for {key}, trying replica");
        if let Some(ri) = replica_opt {
            return try_get(ri).await;
        }

        Ok(None)
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        let primary_client = self
            .client_for(primary)
            .await
            .ok_or_else(|| anyhow::anyhow!("No client for primary"))?;
        let _ = primary_client
            .delete_object()
            .bucket(&self.backends[primary].bucket)
            .key(key)
            .send()
            .await;

        if let Some(ri) = replica_opt
            && let Some(rc) = self.client_for(ri).await
        {
            let _ = rc
                .delete_object()
                .bucket(&self.backends[ri].bucket)
                .key(key)
                .send()
                .await;
        }
        Ok(())
    }

    pub async fn head(&self, key: &str) -> Option<(u64, String)> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        let try_head = |index: usize| async move {
            let client = self.client_for(index).await?;
            let resp = client
                .head_object()
                .bucket(&self.backends[index].bucket)
                .key(key)
                .send()
                .await
                .ok()?;
            let size = resp.content_length.map(|s| s as u64).unwrap_or(0);
            let etag = resp.e_tag.unwrap_or_default();
            Some((size, etag))
        };

        if let Some(result) = try_head(primary).await {
            return Some(result);
        }
        if let Some(ri) = replica_opt {
            return try_head(ri).await;
        }
        None
    }

    pub async fn head_output(
        &self,
        key: &str,
    ) -> Option<aws_sdk_s3::operation::head_object::HeadObjectOutput> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        let try_head = |index: usize| async move {
            let client = self.client_for(index).await?;
            client
                .head_object()
                .bucket(&self.backends[index].bucket)
                .key(key)
                .send()
                .await
                .ok()
        };
        if let Some(output) = try_head(primary).await {
            return Some(output);
        }
        if let Some(replica) = replica_opt {
            return try_head(replica).await;
        }
        None
    }
}

pub fn parse_service_backends(env_value: &str) -> Vec<ServiceBackend> {
    env_value
        .split(';')
        .filter(|s| !s.is_empty())
        .filter_map(|def| {
            let parts: Vec<&str> = def.split('|').collect();
            if parts.len() >= 6 {
                Some(ServiceBackend {
                    provider: parts[0].to_string(),
                    endpoint: parts[1].to_string(),
                    region: parts[2].to_string(),
                    bucket: parts[3].to_string(),
                    access_key: parts[4].to_string(),
                    secret_key: parts[5].to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}
