use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tracing::{info, warn};

use crate::managed::{
    CopyStatus, LogicalObjectKey, ManagedError, ManagedRepository, ManagedStreamingMode,
    ObjectAuthority, PLACEMENT_VERSION_V1, Placement, RepairKind, RepairRecord, RepairTargetRole,
    generation_physical_key, rendezvous_placement,
};
use crate::transaction::{
    AbortSignal, AwsS3TransactionBackend, BackendCapabilities, DirectS3Sink, ExpectedObject,
    ObjectDestination, ObjectSinkTransaction, OperationJournal, OperationReconciler,
    OperationState, StoredObjectMeta, TransactionBackend, TransactionError,
};

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

#[derive(Debug)]
pub struct ServiceStorage {
    pub backends: Vec<ServiceBackend>,
    clients: RwLock<Vec<Option<Client>>>,
    authority: Option<Arc<dyn ManagedRepository>>,
    managed_mode: ManagedStreamingMode,
    placement_version: u32,
}

const LEGACY_VIRTUAL_NODES: usize = 150;

fn legacy_hash(value: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

impl std::fmt::Debug for dyn ManagedRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedRepository")
            .field("durable", &self.is_durable())
            .finish()
    }
}

impl ServiceStorage {
    pub fn new(backends: Vec<ServiceBackend>) -> Self {
        let n = backends.len();
        let clients = RwLock::new(vec![None; n]);
        Self {
            backends,
            clients,
            authority: None,
            managed_mode: ManagedStreamingMode::Off,
            placement_version: PLACEMENT_VERSION_V1,
        }
    }

    pub fn with_management(
        backends: Vec<ServiceBackend>,
        authority: Arc<dyn ManagedRepository>,
        managed_mode: ManagedStreamingMode,
        placement_version: u32,
    ) -> Self {
        let mut storage = Self::new(backends);
        storage.authority = Some(authority);
        storage.managed_mode = managed_mode;
        storage.placement_version = placement_version.max(1);
        storage
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn managed_mode(&self) -> ManagedStreamingMode {
        self.managed_mode
    }

    pub fn authority_repository(&self) -> Option<&Arc<dyn ManagedRepository>> {
        self.authority.as_ref()
    }

    pub fn placement(&self, logical: &LogicalObjectKey) -> Option<Placement> {
        rendezvous_placement(
            self.placement_version,
            &logical.tenant_id,
            &logical.object_key(),
            self.backends.iter().map(ServiceBackend::id),
        )
    }

    fn get_backend_ids(&self, key: &str) -> (usize, Option<usize>) {
        // Keep direct and pre-authority managed objects on the exact legacy
        // ring. New rendezvous placement applies only to authority-backed
        // immutable generations.
        let hash = legacy_hash(key);
        let mut ring = BTreeMap::new();
        for (backend_index, backend) in self.backends.iter().enumerate() {
            for vnode in 0..LEGACY_VIRTUAL_NODES {
                ring.insert(
                    legacy_hash(format!("{}:{vnode}", backend.id())),
                    backend_index,
                );
            }
        }
        let primary = ring
            .range(hash..)
            .next()
            .or_else(|| ring.iter().next())
            .map(|(_, &backend_index)| backend_index)
            .unwrap_or(0);
        let replica = (self.backends.len() > 1)
            .then(|| {
                ring.range(hash..)
                    .chain(ring.iter())
                    .find(|&(_, backend_index)| *backend_index != primary)
                    .map(|(_, &backend_index)| backend_index)
            })
            .flatten();
        (primary, replica)
    }

    fn index_for_id(&self, backend_id: &str) -> Option<usize> {
        self.backends
            .iter()
            .position(|backend| backend.id() == backend_id)
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

    fn authority_repository_required(&self) -> Result<Arc<dyn ManagedRepository>, ManagedError> {
        self.authority.clone().ok_or_else(|| {
            ManagedError::Persistence("managed authority repository is not configured".to_string())
        })
    }

    pub async fn has_authority(&self, logical: &LogicalObjectKey) -> Result<bool, ManagedError> {
        Ok(self
            .authority_repository_required()?
            .get(logical)
            .await?
            .is_some())
    }

    fn metadata_matches(
        metadata: Option<&std::collections::HashMap<String, String>>,
        content_length: Option<i64>,
        authority: &ObjectAuthority,
        ranged: bool,
    ) -> bool {
        let Some(metadata) = metadata else {
            return false;
        };
        let generation_matches = metadata
            .get("s4-generation")
            .is_some_and(|value| value == &authority.generation.to_string());
        let digest_matches = metadata
            .get("s4-sha256")
            .is_some_and(|value| value == &authority.digest);
        let size_metadata_matches = metadata
            .get("s4-size")
            .and_then(|value| value.parse::<u64>().ok())
            == Some(authority.size);
        let response_size_matches = ranged
            || content_length
                .and_then(|value| u64::try_from(value).ok())
                .is_some_and(|value| value == authority.size);
        generation_matches && digest_matches && size_metadata_matches && response_size_matches
    }

    async fn enqueue_read_repairs(
        &self,
        authority: &ObjectAuthority,
        valid_source: &str,
        primary_failed: bool,
    ) -> Result<(), ManagedError> {
        let repository = self.authority_repository_required()?;
        if primary_failed && valid_source != authority.primary_backend_id {
            repository
                .enqueue(RepairRecord::copy(
                    RepairKind::Replica,
                    authority,
                    Some(valid_source.to_string()),
                    authority.primary_backend_id.clone(),
                    RepairTargetRole::Primary,
                    authority.placement_version,
                ))
                .await?;
        }
        let Some(current) = self.placement(&authority.logical) else {
            return Ok(());
        };
        if current.version == authority.placement_version {
            return Ok(());
        }
        if current.primary_backend_id != authority.primary_backend_id {
            repository
                .enqueue(RepairRecord::placement(
                    authority,
                    Some(valid_source.to_string()),
                    current.primary_backend_id.clone(),
                    RepairTargetRole::Primary,
                    &current,
                ))
                .await?;
        }
        if let Some(replica) = current.replica_backend_id.clone()
            && authority.replica_backend_id.as_deref() != Some(replica.as_str())
        {
            repository
                .enqueue(RepairRecord::placement(
                    authority,
                    Some(valid_source.to_string()),
                    replica,
                    RepairTargetRole::Replica,
                    &current,
                ))
                .await?;
        }
        Ok(())
    }

    async fn authoritative_get_from(
        &self,
        backend_id: &str,
        physical_key: &str,
        range: Option<&str>,
        authority: &ObjectAuthority,
    ) -> Option<aws_sdk_s3::operation::get_object::GetObjectOutput> {
        let index = self.index_for_id(backend_id)?;
        let client = self.client_for(index).await?;
        let mut request = client
            .get_object()
            .bucket(&self.backends[index].bucket)
            .key(physical_key);
        if let Some(range) = range {
            request = request.range(range);
        }
        let output = request.send().await.ok()?;
        Self::metadata_matches(
            output.metadata(),
            output.content_length(),
            authority,
            range.is_some(),
        )
        .then_some(output)
    }

    pub async fn open_authoritative(
        &self,
        logical: &LogicalObjectKey,
        range: Option<&str>,
    ) -> Result<Option<aws_sdk_s3::operation::get_object::GetObjectOutput>, ManagedError> {
        let repository = self.authority_repository_required()?;
        let Some(authority) = repository.get(logical).await? else {
            return Ok(None);
        };
        if authority.tombstone {
            return Ok(None);
        }
        let physical_key = generation_physical_key(logical, authority.generation);
        if let Some(output) = self
            .authoritative_get_from(
                &authority.primary_backend_id,
                &physical_key,
                range,
                &authority,
            )
            .await
        {
            self.enqueue_read_repairs(&authority, &authority.primary_backend_id, false)
                .await?;
            return Ok(Some(output));
        }

        if authority.replica_status == CopyStatus::Ready
            && let Some(replica) = &authority.replica_backend_id
            && let Some(output) = self
                .authoritative_get_from(replica, &physical_key, range, &authority)
                .await
        {
            self.enqueue_read_repairs(&authority, replica, true).await?;
            return Ok(Some(output));
        }

        // During a placement-version migration, a previously repaired new
        // destination may be read only after validating the exact generation.
        if let Some(current) = self.placement(logical)
            && current.version != authority.placement_version
        {
            for backend_id in
                std::iter::once(current.primary_backend_id).chain(current.replica_backend_id)
            {
                if let Some(output) = self
                    .authoritative_get_from(&backend_id, &physical_key, range, &authority)
                    .await
                {
                    self.enqueue_read_repairs(&authority, &backend_id, true)
                        .await?;
                    return Ok(Some(output));
                }
            }
        }
        Ok(None)
    }

    async fn authoritative_head_from(
        &self,
        backend_id: &str,
        physical_key: &str,
        authority: &ObjectAuthority,
    ) -> Option<aws_sdk_s3::operation::head_object::HeadObjectOutput> {
        let index = self.index_for_id(backend_id)?;
        let client = self.client_for(index).await?;
        let output = client
            .head_object()
            .bucket(&self.backends[index].bucket)
            .key(physical_key)
            .send()
            .await
            .ok()?;
        Self::metadata_matches(output.metadata(), output.content_length(), authority, false)
            .then_some(output)
    }

    pub async fn head_authoritative(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<aws_sdk_s3::operation::head_object::HeadObjectOutput>, ManagedError> {
        let repository = self.authority_repository_required()?;
        let Some(authority) = repository.get(logical).await? else {
            return Ok(None);
        };
        if authority.tombstone {
            return Ok(None);
        }
        let physical_key = generation_physical_key(logical, authority.generation);
        if let Some(output) = self
            .authoritative_head_from(&authority.primary_backend_id, &physical_key, &authority)
            .await
        {
            self.enqueue_read_repairs(&authority, &authority.primary_backend_id, false)
                .await?;
            return Ok(Some(output));
        }
        if authority.replica_status == CopyStatus::Ready
            && let Some(replica) = &authority.replica_backend_id
            && let Some(output) = self
                .authoritative_head_from(replica, &physical_key, &authority)
                .await
        {
            self.enqueue_read_repairs(&authority, replica, true).await?;
            return Ok(Some(output));
        }
        if let Some(current) = self.placement(logical)
            && current.version != authority.placement_version
        {
            for backend_id in
                std::iter::once(current.primary_backend_id).chain(current.replica_backend_id)
            {
                if let Some(output) = self
                    .authoritative_head_from(&backend_id, &physical_key, &authority)
                    .await
                {
                    self.enqueue_read_repairs(&authority, &backend_id, true)
                        .await?;
                    return Ok(Some(output));
                }
            }
        }
        Ok(None)
    }

    pub async fn tombstone_authoritative(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<(), ManagedError> {
        if !self.managed_mode.allows_mutations() {
            return Err(ManagedError::MutationDisabled(self.managed_mode));
        }
        let repository = self.authority_repository_required()?;
        let existing = repository.get(logical).await?;
        let placement = self.placement(logical).ok_or_else(|| {
            ManagedError::Persistence("managed storage has no backends".to_string())
        })?;
        repository
            .tombstone(
                logical,
                existing.as_ref().map(|authority| authority.cas_version),
                &placement,
            )
            .await?;
        Ok(())
    }

    pub async fn begin_authoritative_sink(
        self: &Arc<Self>,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        logical: LogicalObjectKey,
        content_type: &str,
    ) -> Result<Box<dyn ObjectSinkTransaction>, TransactionError> {
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Err(TransactionError::Publication(
                ManagedError::MutationDisabled(self.managed_mode).to_string(),
            ));
        }
        let repository = self
            .authority_repository_required()
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let existing = repository
            .get(&logical)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let placement = self.placement(&logical).ok_or_else(|| {
            TransactionError::Publication("managed storage has no backends".to_string())
        })?;
        let generation = uuid::Uuid::now_v7();
        let physical_key = generation_physical_key(&logical, generation);
        let mut metadata = BTreeMap::from([
            ("content-type".to_string(), content_type.to_string()),
            ("s4-generation".to_string(), generation.to_string()),
        ]);
        let primary = self
            .direct_sink_for(
                &journal,
                capabilities,
                &placement.primary_backend_id,
                &logical,
                &physical_key,
                metadata.clone(),
            )
            .await?;
        let replica = if let Some(replica_id) = &placement.replica_backend_id {
            match self
                .direct_sink_for(
                    &journal,
                    capabilities,
                    replica_id,
                    &logical,
                    &physical_key,
                    metadata.clone(),
                )
                .await
            {
                Ok(replica) => Some(replica),
                Err(error) => {
                    warn!("managed replica transaction initialization failed: {error}");
                    None
                }
            }
        } else {
            None
        };
        metadata.remove("s4-generation");
        Ok(Box::new(ManagedReplicatedSink {
            repository,
            logical,
            generation,
            placement,
            expected_cas: existing.map(|authority| authority.cas_version),
            metadata,
            primary,
            replica,
            output: None,
            finished: false,
        }))
    }

    async fn direct_sink_for(
        &self,
        journal: &Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        backend_id: &str,
        logical: &LogicalObjectKey,
        physical_key: &str,
        metadata: BTreeMap<String, String>,
    ) -> Result<Box<dyn ManagedDestination>, TransactionError> {
        let index = self.index_for_id(backend_id).ok_or_else(|| {
            TransactionError::Publication(format!("unknown managed backend {backend_id}"))
        })?;
        let client = self.client_for(index).await.ok_or_else(|| {
            TransactionError::Publication(format!("managed backend {backend_id} is unavailable"))
        })?;
        let backend: Arc<dyn TransactionBackend> =
            Arc::new(AwsS3TransactionBackend::new(client, capabilities));
        let destination = ObjectDestination {
            backend_id: backend_id.to_string(),
            bucket: self.backends[index].bucket.clone(),
            logical_key: logical.object_key(),
            physical_key: physical_key.to_string(),
        };
        let (abort_signal, mut abort_receiver) = AbortSignal::channel(1);
        let reconciler = OperationReconciler::new(
            journal.clone(),
            backend.clone(),
            format!("managed-request-{}", uuid::Uuid::now_v7()),
        )?;
        tokio::spawn(async move {
            while abort_receiver.recv().await.is_some() {
                if let Err(error) = reconciler.reconcile_due(Duration::ZERO, 16).await {
                    warn!("managed transaction cleanup failed: {error}");
                }
            }
        });
        let sink = DirectS3Sink::new(
            journal.clone(),
            backend.clone(),
            destination,
            ExpectedObject {
                metadata,
                ..ExpectedObject::default()
            },
            3,
            abort_signal,
        )
        .await?;
        let operation_id = sink.operation_id();
        Ok(Box::new(ManagedDirectSink {
            sink,
            backend,
            journal: journal.clone(),
            operation_id,
        }))
    }

    pub async fn repair_due(
        self: &Arc<Self>,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        owner: &str,
        limit: u64,
    ) -> Result<usize, ManagedError> {
        let repository = self.authority_repository_required()?;
        let lease_until = crate::transaction::unix_time_ms() + 30_000;
        let repairs = repository.claim_repairs(owner, lease_until, limit).await?;
        let count = repairs.len();
        for repair in repairs {
            let (stop_heartbeat, mut heartbeat_stopped) = watch::channel(());
            let heartbeat_repository = repository.clone();
            let lease_token = repair.id;
            let heartbeat = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = heartbeat_stopped.changed() => break,
                        _ = interval.tick() => {
                            let lease_until = crate::transaction::unix_time_ms() + 30_000;
                            match heartbeat_repository.renew_repair(lease_token, lease_until).await {
                                Ok(()) => {}
                                Err(ManagedError::Conflict) => break,
                                Err(error) => warn!("managed repair lease heartbeat failed: {error}"),
                            }
                        }
                    }
                }
            });
            let result = self
                .execute_repair(journal.clone(), capabilities, &repair)
                .await;
            let _ = stop_heartbeat.send(());
            if let Err(error) = heartbeat.await {
                warn!("managed repair lease heartbeat task failed: {error}");
            }
            match result {
                Ok(()) => match repository.complete_repair(&repair).await {
                    Ok(_) | Err(ManagedError::Conflict) => {}
                    Err(error) => return Err(error),
                },
                Err(error) => match repository.fail_repair(repair.id, &error).await {
                    Ok(()) | Err(ManagedError::Conflict) => {}
                    Err(error) => return Err(error),
                },
            }
        }
        Ok(count)
    }

    async fn execute_repair(
        &self,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        repair: &RepairRecord,
    ) -> Result<(), String> {
        if repair.kind == RepairKind::DeleteGeneration {
            return self.delete_generation(repair).await;
        }
        let source_id = repair
            .source_backend_id
            .as_deref()
            .ok_or_else(|| "repair has no source backend".to_string())?;
        let source_index = self
            .index_for_id(source_id)
            .ok_or_else(|| format!("unknown repair source backend {source_id}"))?;
        let source = self
            .client_for(source_index)
            .await
            .ok_or_else(|| format!("repair source backend {source_id} is unavailable"))?;
        let output = source
            .get_object()
            .bucket(&self.backends[source_index].bucket)
            .key(&repair.physical_key)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let authority = ObjectAuthority {
            logical: repair.logical.clone(),
            generation: repair.generation,
            digest: repair.digest.clone(),
            size: repair.size,
            metadata: repair.metadata.clone(),
            placement_version: repair.placement_version,
            primary_backend_id: source_id.to_string(),
            replica_backend_id: None,
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::Absent,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        if !Self::metadata_matches(
            output.metadata(),
            output.content_length(),
            &authority,
            false,
        ) {
            return Err("repair source generation metadata does not match authority".to_string());
        }
        let mut metadata = repair.metadata.clone();
        metadata.insert("s4-generation".to_string(), repair.generation.to_string());
        let mut target = self
            .direct_sink_for(
                &journal,
                capabilities,
                &repair.target_backend_id,
                &repair.logical,
                &repair.physical_key,
                metadata,
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut body = output.body;
        while let Some(chunk) = body.try_next().await.map_err(|error| error.to_string())? {
            target
                .write(chunk)
                .await
                .map_err(|error| error.to_string())?;
        }
        target
            .verify_output(repair.size, &repair.digest)
            .await
            .map_err(|error| error.to_string())?;
        target.complete().await.map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn delete_generation(&self, repair: &RepairRecord) -> Result<(), String> {
        let index = self
            .index_for_id(&repair.target_backend_id)
            .ok_or_else(|| format!("unknown cleanup backend {}", repair.target_backend_id))?;
        let client = self
            .client_for(index)
            .await
            .ok_or_else(|| "cleanup backend is unavailable".to_string())?;
        client
            .delete_object()
            .bucket(&self.backends[index].bucket)
            .key(&repair.physical_key)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

struct ManagedDirectSink {
    sink: DirectS3Sink,
    backend: Arc<dyn TransactionBackend>,
    journal: Arc<dyn OperationJournal>,
    operation_id: uuid::Uuid,
}

#[async_trait::async_trait]
trait ManagedDestination: Send {
    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError>;
    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError>;
    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError>;
    async fn abort(&mut self) -> Result<(), TransactionError>;
}

#[async_trait::async_trait]
impl ManagedDestination for ManagedDirectSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        self.sink.write(chunk).await
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        self.sink
            .verify_output(expected_size, expected_sha256)
            .await
    }

    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        let journal = self.journal.clone();
        complete_reconciled(self, &journal).await
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        self.sink.abort().await
    }
}

async fn complete_reconciled(
    destination: &mut ManagedDirectSink,
    journal: &Arc<dyn OperationJournal>,
) -> Result<StoredObjectMeta, TransactionError> {
    match destination.sink.complete().await {
        Ok(stored) => Ok(stored),
        Err(original) => {
            let reconciler = OperationReconciler::new(
                journal.clone(),
                destination.backend.clone(),
                format!("managed-complete-{}", uuid::Uuid::now_v7()),
            )?;
            reconciler.reconcile_due(Duration::ZERO, 16).await?;
            let operation = journal
                .get(destination.operation_id)
                .await?
                .ok_or_else(|| {
                    TransactionError::Publication("managed operation disappeared".to_string())
                })?;
            if operation.state == OperationState::Committed {
                operation.committed.ok_or_else(|| {
                    TransactionError::Publication(
                        "committed managed operation has no result metadata".to_string(),
                    )
                })
            } else {
                Err(original)
            }
        }
    }
}

struct ManagedReplicatedSink {
    repository: Arc<dyn ManagedRepository>,
    logical: LogicalObjectKey,
    generation: uuid::Uuid,
    placement: Placement,
    expected_cas: Option<u64>,
    metadata: BTreeMap<String, String>,
    primary: Box<dyn ManagedDestination>,
    replica: Option<Box<dyn ManagedDestination>>,
    output: Option<(u64, String)>,
    finished: bool,
}

impl ManagedReplicatedSink {
    async fn abandon_replica(&mut self) {
        if let Some(mut replica) = self.replica.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), replica.abort()).await;
        }
    }
}

#[async_trait::async_trait]
impl ObjectSinkTransaction for ManagedReplicatedSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        self.primary.write(chunk.clone()).await?;
        if let Some(replica) = &mut self.replica {
            let result = tokio::time::timeout(Duration::from_secs(30), replica.write(chunk)).await;
            if !matches!(result, Ok(Ok(()))) {
                self.abandon_replica().await;
            }
        }
        Ok(())
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        self.primary
            .verify_output(expected_size, expected_sha256)
            .await?;
        if let Some(replica) = &mut self.replica
            && replica
                .verify_output(expected_size, expected_sha256)
                .await
                .is_err()
        {
            self.abandon_replica().await;
        }
        self.output = Some((expected_size, expected_sha256.to_string()));
        Ok(())
    }

    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        let (size, digest) = self
            .output
            .clone()
            .ok_or(TransactionError::OutputMismatch)?;
        let primary = self.primary.complete().await?;
        let replica_status = if let Some(replica) = &mut self.replica {
            match tokio::time::timeout(Duration::from_secs(30), replica.complete()).await {
                Ok(Ok(_)) => CopyStatus::Ready,
                _ => CopyStatus::RepairPending,
            }
        } else if self.placement.replica_backend_id.is_some() {
            CopyStatus::RepairPending
        } else {
            CopyStatus::Absent
        };
        let now = crate::transaction::unix_time_ms();
        let authority = ObjectAuthority {
            logical: self.logical.clone(),
            generation: self.generation,
            digest,
            size,
            metadata: self.metadata.clone(),
            placement_version: self.placement.version,
            primary_backend_id: self.placement.primary_backend_id.clone(),
            replica_backend_id: self.placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Ready,
            replica_status,
            tombstone: false,
            cas_version: 0,
            created_at_ms: now,
            updated_at_ms: now,
        };
        if let Err(error) = self
            .repository
            .publish(authority.clone(), self.expected_cas)
            .await
        {
            for backend_id in std::iter::once(authority.primary_backend_id.clone())
                .chain(authority.replica_backend_id.clone())
            {
                let _ = self
                    .repository
                    .enqueue(RepairRecord::copy(
                        RepairKind::DeleteGeneration,
                        &authority,
                        None,
                        backend_id,
                        RepairTargetRole::Cleanup,
                        authority.placement_version,
                    ))
                    .await;
            }
            return Err(TransactionError::Publication(error.to_string()));
        }
        self.finished = true;
        Ok(primary)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        if self.finished {
            return Ok(());
        }
        let primary = self.primary.abort().await;
        self.abandon_replica().await;
        self.finished = primary.is_ok();
        primary
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::InMemoryManagedRepository;
    use std::sync::Mutex;

    fn authority() -> ObjectAuthority {
        ObjectAuthority {
            logical: LogicalObjectKey::new("tenant", "bucket", "key"),
            generation: uuid::Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
            digest: "abc123".to_string(),
            size: 42,
            metadata: BTreeMap::new(),
            placement_version: 1,
            primary_backend_id: "primary".to_string(),
            replica_backend_id: Some("replica".to_string()),
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::Ready,
            tombstone: false,
            cas_version: 1,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }

    #[test]
    fn stale_replica_metadata_can_never_match_current_authority() {
        let authority = authority();
        let current = std::collections::HashMap::from([
            (
                "s4-generation".to_string(),
                authority.generation.to_string(),
            ),
            ("s4-sha256".to_string(), authority.digest.clone()),
            ("s4-size".to_string(), authority.size.to_string()),
        ]);
        assert!(ServiceStorage::metadata_matches(
            Some(&current),
            Some(authority.size as i64),
            &authority,
            false,
        ));

        let mut stale_generation = current.clone();
        stale_generation.insert(
            "s4-generation".to_string(),
            uuid::Uuid::now_v7().to_string(),
        );
        assert!(!ServiceStorage::metadata_matches(
            Some(&stale_generation),
            Some(authority.size as i64),
            &authority,
            false,
        ));
        let mut stale_digest = current.clone();
        stale_digest.insert("s4-sha256".to_string(), "old".to_string());
        assert!(!ServiceStorage::metadata_matches(
            Some(&stale_digest),
            Some(authority.size as i64),
            &authority,
            false,
        ));
        assert!(!ServiceStorage::metadata_matches(
            Some(&current),
            Some(41),
            &authority,
            false,
        ));
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailurePoint {
        Write,
        Verify,
        Complete,
    }

    #[derive(Default)]
    struct FakeDestinationState {
        pointers: Vec<usize>,
    }

    type SharedFakeState = Arc<Mutex<FakeDestinationState>>;
    type SharedEvents = Arc<Mutex<Vec<String>>>;
    type FakeManagedSink = (
        ManagedReplicatedSink,
        SharedFakeState,
        SharedFakeState,
        SharedEvents,
    );

    struct FakeDestination {
        label: &'static str,
        failure: Option<FailurePoint>,
        state: SharedFakeState,
        events: SharedEvents,
    }

    impl FakeDestination {
        fn new(
            label: &'static str,
            failure: Option<FailurePoint>,
            events: SharedEvents,
        ) -> (Self, SharedFakeState) {
            let state = Arc::new(Mutex::new(FakeDestinationState::default()));
            (
                Self {
                    label,
                    failure,
                    state: state.clone(),
                    events,
                },
                state,
            )
        }

        fn fail(&self, point: FailurePoint) -> Result<(), TransactionError> {
            if self.failure == Some(point) {
                Err(TransactionError::Publication(format!(
                    "scripted {} {point:?} failure",
                    self.label
                )))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait::async_trait]
    impl ManagedDestination for FakeDestination {
        async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}-write", self.label));
            self.state
                .lock()
                .unwrap()
                .pointers
                .push(chunk.as_ptr() as usize);
            self.fail(FailurePoint::Write)
        }

        async fn verify_output(
            &mut self,
            _expected_size: u64,
            _expected_sha256: &str,
        ) -> Result<(), TransactionError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}-verify", self.label));
            self.fail(FailurePoint::Verify)
        }

        async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}-complete", self.label));
            self.fail(FailurePoint::Complete)?;
            Ok(StoredObjectMeta::default())
        }

        async fn abort(&mut self) -> Result<(), TransactionError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}-abort", self.label));
            Ok(())
        }
    }

    fn fake_managed_sink(
        repository: Arc<InMemoryManagedRepository>,
        logical: LogicalObjectKey,
        expected_cas: Option<u64>,
        primary_failure: Option<FailurePoint>,
        replica_failure: Option<FailurePoint>,
    ) -> FakeManagedSink {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (primary, primary_state) =
            FakeDestination::new("primary", primary_failure, events.clone());
        let (replica, replica_state) =
            FakeDestination::new("replica", replica_failure, events.clone());
        (
            ManagedReplicatedSink {
                repository,
                logical,
                generation: uuid::Uuid::now_v7(),
                placement: Placement {
                    version: 1,
                    primary_backend_id: "primary".to_string(),
                    replica_backend_id: Some("replica".to_string()),
                },
                expected_cas,
                metadata: BTreeMap::from([("content-type".to_string(), "text/plain".to_string())]),
                primary: Box::new(primary),
                replica: Some(Box::new(replica)),
                output: None,
                finished: false,
            },
            primary_state,
            replica_state,
            events,
        )
    }

    #[tokio::test]
    async fn managed_replica_failures_never_block_authoritative_primary() {
        for failure in [
            FailurePoint::Write,
            FailurePoint::Verify,
            FailurePoint::Complete,
        ] {
            let repository = Arc::new(InMemoryManagedRepository::new());
            let logical = LogicalObjectKey::new("tenant", "bucket", &format!("key-{failure:?}"));
            let (mut sink, primary, replica, events) = fake_managed_sink(
                repository.clone(),
                logical.clone(),
                None,
                None,
                Some(failure),
            );
            let chunk = Bytes::from_static(b"abc");
            sink.write(chunk).await.unwrap();
            sink.verify_output(
                3,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )
            .await
            .unwrap();
            sink.complete().await.unwrap();

            let authority = repository.get(&logical).await.unwrap().unwrap();
            assert_eq!(authority.primary_status, CopyStatus::Ready);
            assert_eq!(authority.replica_status, CopyStatus::RepairPending);
            if failure == FailurePoint::Write {
                assert_eq!(
                    primary.lock().unwrap().pointers,
                    replica.lock().unwrap().pointers,
                    "Bytes sent to primary and replica are shallow clones"
                );
            }
            let events = events.lock().unwrap();
            if let (Some(primary), Some(replica)) = (
                events.iter().position(|event| event == "primary-complete"),
                events.iter().position(|event| event == "replica-complete"),
            ) {
                assert!(primary < replica, "primary completes before replica");
            }
        }
    }

    #[tokio::test]
    async fn managed_primary_failures_and_cas_races_never_publish_stale_data() {
        for failure in [
            FailurePoint::Write,
            FailurePoint::Verify,
            FailurePoint::Complete,
        ] {
            let repository = Arc::new(InMemoryManagedRepository::new());
            let logical =
                LogicalObjectKey::new("tenant", "bucket", &format!("primary-{failure:?}"));
            let (mut sink, _, _, _) = fake_managed_sink(
                repository.clone(),
                logical.clone(),
                None,
                Some(failure),
                None,
            );
            let write = sink.write(Bytes::from_static(b"abc")).await;
            if failure == FailurePoint::Write {
                assert!(write.is_err());
            } else {
                write.unwrap();
                let verify = sink
                    .verify_output(
                        3,
                        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    )
                    .await;
                if failure == FailurePoint::Verify {
                    assert!(verify.is_err());
                } else {
                    verify.unwrap();
                    assert!(sink.complete().await.is_err());
                }
            }
            assert!(repository.get(&logical).await.unwrap().is_none());
        }

        let repository = Arc::new(InMemoryManagedRepository::new());
        let logical = LogicalObjectKey::new("tenant", "bucket", "cas-race");
        let (mut stale, _, _, _) =
            fake_managed_sink(repository.clone(), logical.clone(), None, None, None);
        stale.write(Bytes::from_static(b"abc")).await.unwrap();
        stale
            .verify_output(
                3,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )
            .await
            .unwrap();
        let mut winner = authority();
        winner.logical = logical.clone();
        repository.publish(winner.clone(), None).await.unwrap();
        assert!(stale.complete().await.is_err());
        assert_eq!(
            repository.get(&logical).await.unwrap().unwrap().generation,
            winner.generation
        );
    }
}
