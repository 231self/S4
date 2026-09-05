use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use bytes::Bytes;
use std::collections::{BTreeMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tracing::{info, warn};

use crate::control::{RequestKind, UsageEvent, UsageRoute};
use crate::managed::{
    AuthorityListPage, AuthorityListQuery, AuthorityPlacementCursor, AuthorityPlacementPage,
    AuthorityPlacementPageQuery, BackendVersioningCapability, BackendVersioningMode, CopyStatus,
    DurablePhysicalWriteIntent, LogicalObjectKey, ManagedError, ManagedLogicalOperationIntent,
    ManagedLogicalOperationState, ManagedMutationKind, ManagedRepository, ManagedStreamingMode,
    ManagedUsageEvidence, NamespacePurgeRequest, NamespacePurgeStatus, ObjectAuthority,
    PLACEMENT_VERSION_V1, PhysicalVersionTarget, PhysicalWriteIntent, Placement,
    ProviderStorageIdentity, RepairKind, RepairRecord, RepairTargetRole, generation_physical_key,
    weighted_rendezvous_placement,
};
use crate::s3_safety::{
    record_s3_body_failure, record_s3_failure, s3_retry_config, s3_timeout_config,
};
use crate::transaction::{
    AbortSignal, AwsS3TransactionBackend, BackendCapabilities, DirectS3Sink, ExpectedObject,
    ManagedChildRole, ManagedOperationScope, ObjectDestination, ObjectSinkTransaction,
    OperationJournal, OperationReconciler, OperationState, SinkCommitState, StoredObjectMeta,
    TransactionBackend, TransactionError, VersioningCapability,
};

/// Reservation headroom for physical versions a managed generation may accrue
/// across exact-version recovery before its logical commit settles.
const MANAGED_STREAMING_PUT_HEADROOM: u64 = 4;

#[derive(Debug, Clone)]
pub struct ServiceBackend {
    pub provider: String,
    pub provider_instance_id: Option<String>,
    pub provider_account_id: Option<String>,
    pub credential_epoch: Option<u64>,
    pub placement_weight: u64,
    pub placement_capacity_units: u64,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

impl ServiceBackend {
    pub fn provider_kind(&self) -> &str {
        &self.provider
    }

    pub fn provider_instance_id(&self) -> Option<&str> {
        self.provider_instance_id.as_deref()
    }

    pub fn provider_account_id(&self) -> Option<&str> {
        self.provider_account_id.as_deref()
    }

    pub fn credential_epoch(&self) -> Option<u64> {
        self.credential_epoch
    }

    pub fn is_b2(&self) -> bool {
        self.provider_kind().eq_ignore_ascii_case("b2")
    }

    pub fn id(&self) -> String {
        self.provider_instance_id().map_or_else(
            || format!("{}:{}", self.provider, self.bucket),
            |instance_id| format!("{}:{instance_id}", self.provider),
        )
    }

    pub fn placement_weight(&self) -> Option<u64> {
        self.placement_weight
            .checked_mul(self.placement_capacity_units)
    }

    pub fn storage_identity(&self) -> Option<ProviderStorageIdentity> {
        Some(ProviderStorageIdentity {
            provider_kind: self.provider.clone(),
            provider_instance_id: self.provider_instance_id.clone()?,
            provider_account_id: self.provider_account_id.clone()?,
            canonical_endpoint: canonical_provider_endpoint(&self.endpoint)?,
            region: self.region.clone(),
        })
    }

    fn matches_persisted_identity(
        &self,
        identity: &ProviderStorageIdentity,
        credential_epoch: u64,
    ) -> bool {
        self.storage_identity().as_ref() == Some(identity)
            && self
                .credential_epoch()
                .is_some_and(|current| current >= credential_epoch)
    }

    pub async fn build_client(&self) -> Option<Client> {
        let access_key = self.access_key.clone();
        let secret_key = self.secret_key.clone();
        let region = self.region.clone();
        let endpoint = self.endpoint.clone();
        let creds = Credentials::new(access_key, secret_key, None, None, "maskura-service");
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(region))
            .endpoint_url(&endpoint)
            .credentials_provider(creds)
            .retry_config(s3_retry_config())
            .timeout_config(s3_timeout_config())
            .load()
            .await;
        Some(Client::from_conf(
            aws_sdk_s3::config::Builder::from(&config)
                .force_path_style(true)
                .build(),
        ))
    }
}

fn canonical_provider_endpoint(endpoint: &str) -> Option<String> {
    let mut endpoint = reqwest::Url::parse(endpoint).ok()?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return None;
    }
    if endpoint.path().is_empty() {
        endpoint.set_path("/");
    }
    Some(endpoint.to_string())
}

#[derive(Debug)]
pub struct ServiceStorage {
    pub backends: Vec<ServiceBackend>,
    clients: RwLock<Vec<Option<Client>>>,
    authority: Option<Arc<dyn ManagedRepository>>,
    managed_mode: ManagedStreamingMode,
    placement_version: u32,
    managed_versioning_capability: Option<BackendVersioningCapability>,
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
            managed_versioning_capability: None,
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

    pub fn with_managed_capabilities(mut self, capabilities: Option<BackendCapabilities>) -> Self {
        self.managed_versioning_capability =
            capabilities.map(|capabilities| match capabilities.versioning {
                VersioningCapability::Unsupported => BackendVersioningCapability::Unsupported,
                VersioningCapability::Optional => BackendVersioningCapability::Optional,
                VersioningCapability::Required => BackendVersioningCapability::Required,
            });
        self
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

    /// Lists only authoritative logical objects. Provider buckets hold opaque
    /// generation keys and must never be exposed through the S3 front door.
    pub async fn list_authority(
        &self,
        query: AuthorityListQuery,
    ) -> Result<AuthorityListPage, ManagedError> {
        self.authority_repository_required()?
            .list_authority(query)
            .await
    }

    /// Reconciles one stale authority to a desired placement. A ready authority
    /// that already occupies every desired location advances by CAS without a
    /// provider copy; otherwise only the missing placement repair legs are
    /// enqueued from an already verified ready authority location.
    pub async fn reconcile_authority_placement(
        &self,
        authority: &ObjectAuthority,
        desired: &Placement,
    ) -> Result<(), ManagedError> {
        if authority.tombstone || authority.placement_version >= desired.version {
            return Ok(());
        }
        let repository = self.authority_repository_required()?;
        let locations_match = authority.primary_backend_id == desired.primary_backend_id
            && authority.primary_status == CopyStatus::Ready
            && match desired.replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            };
        if locations_match {
            repository
                .advance_placement_version(&authority.logical, authority.cas_version, desired)
                .await?;
            return Ok(());
        }

        let source = if authority.primary_status == CopyStatus::Ready {
            Some(authority.primary_backend_id.clone())
        } else if authority.replica_status == CopyStatus::Ready {
            authority.replica_backend_id.clone()
        } else {
            None
        }
        .ok_or_else(|| {
            ManagedError::Persistence(
                "stale authority has no verified ready source for placement repair".to_string(),
            )
        })?;

        let primary_matches = authority.primary_backend_id == desired.primary_backend_id
            && authority.primary_status == CopyStatus::Ready;
        // A primary leg is also the durable way to remove an obsolete replica.
        if !primary_matches
            || (desired.replica_backend_id.is_none() && authority.replica_backend_id.is_some())
        {
            repository
                .enqueue(RepairRecord::placement(
                    authority,
                    Some(source.clone()),
                    desired.primary_backend_id.clone(),
                    RepairTargetRole::Primary,
                    desired,
                ))
                .await?;
        }
        if let Some(replica) = &desired.replica_backend_id
            && (authority.replica_backend_id.as_deref() != Some(replica)
                || authority.replica_status != CopyStatus::Ready)
        {
            repository
                .enqueue(RepairRecord::placement(
                    authority,
                    Some(source),
                    replica.clone(),
                    RepairTargetRole::Replica,
                    desired,
                ))
                .await?;
        }
        Ok(())
    }

    /// Processes one bounded global page of authorities behind this storage's
    /// placement version. The returned cursor can resume the same keyset scan.
    pub async fn reconcile_authority_placement_page(
        &self,
        after: Option<AuthorityPlacementCursor>,
        limit: u64,
    ) -> Result<AuthorityPlacementPage, ManagedError> {
        let repository = self.authority_repository_required()?;
        let page = repository
            .list_authority_below_placement_version(AuthorityPlacementPageQuery {
                target_placement_version: self.placement_version,
                after,
                limit,
            })
            .await?;
        for authority in &page.objects {
            let desired = self.placement(&authority.logical).ok_or_else(|| {
                ManagedError::Persistence("managed storage has no backends".to_string())
            })?;
            self.reconcile_authority_placement(authority, &desired)
                .await?;
        }
        Ok(page)
    }

    /// Validate the launch topology before enabling transactional managed
    /// mutations. Observe/off modes retain the legacy multi-provider topology.
    pub fn validate_managed_launch_configuration(&self) -> Result<(), String> {
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Ok(());
        }
        if self.backends.is_empty() {
            return Err(
                "transactional managed mode requires one or more managed B2 backends at launch"
                    .to_string(),
            );
        }
        let mut backend_ids = HashSet::with_capacity(self.backends.len());
        for backend in &self.backends {
            if !backend.is_b2() {
                return Err(
                    "transactional managed mode supports only B2 backend pools at launch"
                        .to_string(),
                );
            }
            if reqwest::Url::parse(&backend.endpoint)
                .ok()
                .is_none_or(|endpoint| endpoint.scheme() != "https")
            {
                return Err(
                    "transactional managed B2 requires HTTPS provider endpoints".to_string()
                );
            }
            if backend.storage_identity().is_none()
                || backend.provider_account_id().is_none()
                || !backend.credential_epoch().is_some_and(|epoch| epoch > 0)
            {
                return Err(
                    "transactional managed B2 requires explicit provider instance/account identity and a positive credential epoch"
                        .to_string(),
                );
            }
            if backend.placement_weight().is_none_or(|weight| weight == 0) {
                return Err(
                    "transactional managed B2 requires positive static placement weight and capacity units"
                        .to_string(),
                );
            }
            if !backend_ids.insert(backend.id()) {
                return Err(
                    "transactional managed B2 requires unique stable backend IDs".to_string(),
                );
            }
        }
        Ok(())
    }

    pub async fn assert_namespace_active(&self, tenant_id: &str) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .assert_namespace_active(tenant_id)
            .await
    }

    pub async fn begin_managed_multipart(
        &self,
        upload_id: &str,
        tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        self.authority_repository_required()?
            .begin_multipart_activity(upload_id, tenant_id)
            .await
    }

    pub async fn assert_managed_multipart(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
        allow_purging: bool,
    ) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .assert_multipart_activity(upload_id, tenant_id, namespace_epoch, allow_purging)
            .await
    }

    pub async fn confirm_managed_multipart(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .confirm_multipart_activity(upload_id, tenant_id, namespace_epoch)
            .await
    }

    pub async fn reconcile_managed_multipart_activities(
        &self,
        limit: u64,
    ) -> Result<u64, ManagedError> {
        self.authority_repository_required()?
            .reconcile_multipart_activities(limit)
            .await
    }

    pub async fn finish_managed_multipart(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .finish_multipart_activity(upload_id, tenant_id, namespace_epoch)
            .await
    }

    /// Start an idempotent authority-backed namespace purge. Physical deletion
    /// policy belongs to the authority implementation; this method never lists
    /// or deletes backend objects itself.
    pub async fn purge_namespace(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let Some(authority) = &self.authority else {
            return Ok(NamespacePurgeStatus::Unsupported {
                reason: "managed namespace purge requires an authority repository".to_string(),
            });
        };
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Ok(NamespacePurgeStatus::Unsupported {
                reason: "complete managed namespace purge requires enforce mode and its exact physical-version ledger"
                    .to_string(),
            });
        }
        let status = authority.purge_namespace(request).await?;
        if matches!(
            status,
            NamespacePurgeStatus::Running | NamespacePurgeStatus::Blocked { .. }
        ) {
            self.drive_namespace_purge(authority, request).await
        } else {
            Ok(status)
        }
    }

    /// Query an authority-backed namespace purge without starting or advancing
    /// it. An unconfigured authority is explicitly unsupported, not complete.
    pub async fn namespace_purge_status(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let Some(authority) = &self.authority else {
            return Ok(NamespacePurgeStatus::Unsupported {
                reason: "managed namespace purge status requires an authority repository"
                    .to_string(),
            });
        };
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Ok(NamespacePurgeStatus::Unsupported {
                reason: "complete managed namespace purge requires enforce mode and its exact physical-version ledger"
                    .to_string(),
            });
        }
        let status = authority.namespace_purge_status(request).await?;
        if matches!(
            status,
            NamespacePurgeStatus::Running | NamespacePurgeStatus::Blocked { .. }
        ) {
            self.drive_namespace_purge(authority, request).await
        } else {
            Ok(status)
        }
    }

    async fn drive_namespace_purge(
        &self,
        authority: &Arc<dyn ManagedRepository>,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        for target in authority.purge_targets(request, 64).await? {
            if let Err(reason) = self.delete_and_verify_purge_target(&target).await {
                authority
                    .mark_purge_target_blocked(request, &target, &reason)
                    .await?;
                continue;
            }
            authority
                .mark_purge_target_deleted(request, &target)
                .await?;
        }
        authority.namespace_purge_status(request).await
    }

    async fn delete_and_verify_purge_target(
        &self,
        target: &PhysicalVersionTarget,
    ) -> Result<(), String> {
        let index = self
            .index_for_id(&target.backend_id)
            .ok_or_else(|| format!("unknown managed backend {}", target.backend_id))?;
        if !self.backends[index]
            .matches_persisted_identity(&target.storage_identity, target.credential_epoch)
        {
            return Err(format!(
                "managed backend {} storage identity changed or its credential epoch moved backwards since the physical version was written",
                target.backend_id
            ));
        }
        if self.backends[index].bucket != target.provider_bucket {
            return Err(format!(
                "managed backend {} bucket changed from {} to {}",
                target.backend_id, target.provider_bucket, self.backends[index].bucket
            ));
        }
        let current_versioning = self.versioning_mode(index).await;
        if target.versioning_mode == BackendVersioningMode::Unknown
            || current_versioning == BackendVersioningMode::Unknown
        {
            return Err(format!(
                "managed backend {} bucket versioning mode is unknown",
                target.backend_id
            ));
        }
        if current_versioning != target.versioning_mode {
            return Err(format!(
                "managed backend {} bucket versioning mode changed from {} to {}",
                target.backend_id,
                target.versioning_mode.as_str(),
                current_versioning.as_str()
            ));
        }
        if self.managed_versioning_capability != Some(target.versioning_capability) {
            return Err(format!(
                "managed backend {} versioning capability is unknown or changed",
                target.backend_id
            ));
        }
        if target.version_id.is_none()
            && (target.versioning_mode != BackendVersioningMode::Unversioned
                || target.versioning_capability != BackendVersioningCapability::Unsupported)
        {
            return Err(format!(
                "managed backend {} cannot prove an unversioned ledger target has no historical versions",
                target.backend_id
            ));
        }
        let client = self
            .client_for(index)
            .await
            .ok_or_else(|| format!("managed backend {} is unavailable", target.backend_id))?;
        let mut delete = client
            .delete_object()
            .bucket(&target.provider_bucket)
            .key(&target.physical_key);
        if let Some(version_id) = &target.version_id {
            delete = delete.version_id(version_id);
        }
        if let Err(error) = delete.send().await
            && !error
                .raw_response()
                .is_some_and(|response| response.status().as_u16() == 404)
        {
            return Err(record_s3_failure("managed_delete_version", &error).to_string());
        }

        let mut head = client
            .head_object()
            .bucket(&target.provider_bucket)
            .key(&target.physical_key);
        if let Some(version_id) = &target.version_id {
            head = head.version_id(version_id);
        }
        match head.send().await {
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_not_found()) =>
            {
                Ok(())
            }
            Err(error) => Err(record_s3_failure("managed_verify_delete", &error).to_string()),
            Ok(_) => Err(format!(
                "managed physical version on {} is still present after deletion",
                target.backend_id
            )),
        }
    }

    pub fn placement(&self, logical: &LogicalObjectKey) -> Option<Placement> {
        weighted_rendezvous_placement(
            self.placement_version,
            &logical.tenant_id,
            &logical.object_key(),
            self.backends.iter().filter_map(|backend| {
                backend
                    .placement_weight()
                    .map(|weight| (backend.id(), weight))
            }),
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

    async fn versioning_mode(&self, index: usize) -> BackendVersioningMode {
        let Some(client) = self.client_for(index).await else {
            return BackendVersioningMode::Unknown;
        };
        match client
            .get_bucket_versioning()
            .bucket(&self.backends[index].bucket)
            .send()
            .await
        {
            Ok(output) => match output.status().map(|status| status.as_str()) {
                Some("Enabled") => BackendVersioningMode::Enabled,
                Some("Suspended") => BackendVersioningMode::Suspended,
                None => BackendVersioningMode::Unversioned,
                Some(_) => BackendVersioningMode::Unknown,
            },
            Err(error) => {
                record_s3_failure("managed_get_bucket_versioning", &error);
                BackendVersioningMode::Unknown
            }
        }
    }

    async fn validate_durable_intent_backend(
        &self,
        durable: &DurablePhysicalWriteIntent,
    ) -> Result<usize, String> {
        let intent = &durable.intent;
        let index = self
            .index_for_id(&intent.backend_id)
            .ok_or_else(|| format!("unknown managed backend {}", intent.backend_id))?;
        if !self.backends[index]
            .matches_persisted_identity(&intent.storage_identity, intent.credential_epoch)
        {
            return Err(format!(
                "managed backend {} storage identity changed or its credential epoch moved backwards while a write intent was unresolved",
                intent.backend_id
            ));
        }
        if self.backends[index].bucket != intent.provider_bucket {
            return Err(format!(
                "managed backend {} bucket changed while a write intent was unresolved",
                intent.backend_id
            ));
        }
        let current_versioning = self.versioning_mode(index).await;
        if current_versioning == BackendVersioningMode::Unknown
            || intent.versioning_mode == BackendVersioningMode::Unknown
            || current_versioning != intent.versioning_mode
        {
            return Err(format!(
                "managed backend {} versioning mode is unknown or changed while a write intent was unresolved",
                intent.backend_id
            ));
        }
        if self.managed_versioning_capability != Some(intent.versioning_capability) {
            return Err(format!(
                "managed backend {} versioning capability changed while a write intent was unresolved",
                intent.backend_id
            ));
        }
        Ok(index)
    }

    pub async fn reconcile_managed_write_intents(
        &self,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        stale_after: Duration,
        limit: u64,
    ) -> Result<usize, ManagedError> {
        let repository = self.authority_repository_required()?;
        let intents = repository.pending_physical_write_intents(limit).await?;
        let count = intents.len();
        for durable in intents {
            if durable.lease_expires_at_ms > crate::transaction::unix_time_ms() {
                continue;
            }
            let intent = &durable.intent;
            let owner = format!("managed-reconciler-{}", uuid::Uuid::now_v7());
            let Some(lease) = repository
                .claim_expired_physical_write_intent(
                    intent.intent_id,
                    &owner,
                    crate::transaction::unix_time_ms()
                        .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
                )
                .await?
            else {
                continue;
            };
            let index = match self.validate_durable_intent_backend(&durable).await {
                Ok(index) => index,
                Err(reason) => {
                    repository.block_physical_write(&lease, &reason).await?;
                    continue;
                }
            };
            let Some(mut operation) = journal
                .get(intent.intent_id)
                .await
                .map_err(|error| ManagedError::Persistence(error.to_string()))?
            else {
                repository
                    .block_physical_write(
                        &lease,
                        "managed write intent has no operation journal row",
                    )
                    .await?;
                continue;
            };
            if operation.tenant_id.as_deref() != Some(intent.tenant_id.as_str())
                || operation.namespace_epoch != Some(durable.namespace_epoch)
                || operation.destination.backend_id != intent.backend_id
                || operation.destination.bucket != intent.provider_bucket
                || operation.destination.physical_key != intent.physical_key
            {
                repository
                    .block_physical_write(
                        &lease,
                        "managed write intent does not match its operation journal identity",
                    )
                    .await?;
                continue;
            }
            if !operation.state.is_terminal() {
                let client = self.client_for(index).await.ok_or_else(|| {
                    ManagedError::Persistence(format!(
                        "managed backend {} is unavailable",
                        intent.backend_id
                    ))
                })?;
                let backend: Arc<dyn TransactionBackend> = if self.backends[index].is_b2() {
                    Arc::new(AwsS3TransactionBackend::new_managed_b2(
                        client,
                        capabilities,
                    ))
                } else {
                    Arc::new(AwsS3TransactionBackend::new(client, capabilities))
                };
                let reconciler = OperationReconciler::new(
                    journal.clone(),
                    backend,
                    format!("managed-intent-{}", uuid::Uuid::now_v7()),
                )
                .map_err(|error| ManagedError::Persistence(error.to_string()))?;
                if let Err(error) = reconciler
                    .reconcile_operation(intent.intent_id, stale_after)
                    .await
                {
                    repository
                        .block_physical_write(
                            &lease,
                            &format!("managed operation reconciliation failed: {error}"),
                        )
                        .await?;
                    continue;
                }
                operation = journal
                    .get(intent.intent_id)
                    .await
                    .map_err(|error| ManagedError::Persistence(error.to_string()))?
                    .ok_or_else(|| {
                        ManagedError::Persistence(
                            "managed operation disappeared after reconciliation".to_string(),
                        )
                    })?;
            }
            match (operation.state, operation.committed) {
                (OperationState::ProvenAborted, _) => {
                    repository.abort_physical_write(&lease).await?;
                }
                (OperationState::Committed, Some(stored)) if stored.version_history_complete => {
                    repository
                        .commit_physical_write(
                            &lease,
                            &stored.superseded_version_ids,
                            stored.version_id.as_deref(),
                        )
                        .await?;
                }
                (OperationState::Committed, _) => {
                    repository
                        .block_physical_write(
                            &lease,
                            "managed operation committed with ambiguous or missing version history",
                        )
                        .await?;
                }
                (state, _) => {
                    // A fresh operation not claimed by the stale lease remains
                    // pending. Purge cannot complete while its intent exists.
                    if operation.updated_at_ms
                        <= crate::transaction::unix_time_ms()
                            .saturating_sub(stale_after.as_millis() as i64)
                    {
                        repository
                            .block_physical_write(
                                &lease,
                                &format!(
                                    "managed operation remains unresolved in journal state {}",
                                    state.as_str()
                                ),
                            )
                            .await?;
                    }
                }
            }
        }
        Ok(count)
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
            match request.send().await {
                Ok(output) => Some(output),
                Err(error) => {
                    if !error
                        .as_service_error()
                        .is_some_and(|service| service.is_no_such_key())
                    {
                        record_s3_failure("managed_get_object", &error);
                    }
                    None
                }
            }
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

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        let primary_client = self
            .client_for(primary)
            .await
            .ok_or_else(|| anyhow::anyhow!("No client for primary"))?;
        if let Err(error) = primary_client
            .delete_object()
            .bucket(&self.backends[primary].bucket)
            .key(key)
            .send()
            .await
        {
            record_s3_failure("managed_delete_object", &error);
        }

        if let Some(ri) = replica_opt
            && let Some(rc) = self.client_for(ri).await
            && let Err(error) = rc
                .delete_object()
                .bucket(&self.backends[ri].bucket)
                .key(key)
                .send()
                .await
        {
            record_s3_failure("managed_delete_replica", &error);
        }
        Ok(())
    }

    pub async fn head(&self, key: &str) -> Option<(u64, String)> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        let try_head = |index: usize| async move {
            let client = self.client_for(index).await?;
            let resp = match client
                .head_object()
                .bucket(&self.backends[index].bucket)
                .key(key)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    if !error
                        .as_service_error()
                        .is_some_and(|service| service.is_not_found())
                    {
                        record_s3_failure("managed_head_object", &error);
                    }
                    return None;
                }
            };
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
            match client
                .head_object()
                .bucket(&self.backends[index].bucket)
                .key(key)
                .send()
                .await
            {
                Ok(output) => Some(output),
                Err(error) => {
                    if !error
                        .as_service_error()
                        .is_some_and(|service| service.is_not_found())
                    {
                        record_s3_failure("managed_head_output", &error);
                    }
                    None
                }
            }
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
        let version_id = (backend_id == authority.primary_backend_id)
            .then(|| authority.primary_version_id.clone())
            .flatten();
        let mut request = client
            .get_object()
            .bucket(&self.backends[index].bucket)
            .key(physical_key)
            .set_version_id(version_id);
        if let Some(range) = range {
            request = request.range(range);
        }
        let output = match request.send().await {
            Ok(output) => output,
            Err(error) => {
                if !error
                    .as_service_error()
                    .is_some_and(|service| service.is_no_such_key())
                {
                    record_s3_failure("managed_authoritative_get", &error);
                }
                return None;
            }
        };
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
        let version_id = (backend_id == authority.primary_backend_id)
            .then(|| authority.primary_version_id.clone())
            .flatten();
        let output = match client
            .head_object()
            .bucket(&self.backends[index].bucket)
            .key(physical_key)
            .set_version_id(version_id)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                if !error
                    .as_service_error()
                    .is_some_and(|service| service.is_not_found())
                {
                    record_s3_failure("managed_authoritative_head", &error);
                }
                return None;
            }
        };
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

    /// Start a managed generation with the exact physical child identity
    /// persisted by its logical parent.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_authoritative_sink_for_operation(
        self: &Arc<Self>,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        logical: LogicalObjectKey,
        content_type: &str,
        logical_operation_id: uuid::Uuid,
        child_scope: ManagedOperationScope,
        generation: uuid::Uuid,
    ) -> Result<Box<dyn ObjectSinkTransaction>, TransactionError> {
        if child_scope.tenant_id != logical.tenant_id {
            return Err(TransactionError::Publication(
                "managed child scope belongs to a different tenant".to_string(),
            ));
        }
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Err(TransactionError::Publication(
                ManagedError::MutationDisabled(self.managed_mode).to_string(),
            ));
        }
        self.validate_managed_launch_configuration()
            .map_err(TransactionError::Publication)?;
        let repository = self
            .authority_repository_required()
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let placement = self.placement(&logical).ok_or_else(|| {
            TransactionError::Publication("managed storage has no backends".to_string())
        })?;
        let physical_key = generation_physical_key(&logical, generation);
        let parent = repository
            .logical_operation(logical_operation_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?
            .ok_or_else(|| {
                TransactionError::Publication(
                    "managed logical parent operation was not found".to_string(),
                )
            })?;
        let usage = repository
            .workspace_usage(&logical.tenant_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        if parent.intent.kind != ManagedMutationKind::Put
            || parent.state != ManagedLogicalOperationState::Open
            || usage
                .as_ref()
                .is_none_or(|usage| usage.active_operation_id != Some(logical_operation_id))
            || parent.intent.logical != logical
            || parent.intent.generation != generation
            || parent.intent.primary_child_operation_id != child_scope.operation_id
            || parent.intent.fence.namespace_epoch != child_scope.namespace_epoch
            || parent.intent.backend_id != placement.primary_backend_id
            || parent.intent.provider_bucket != self.backends[0].bucket
            || parent.intent.physical_key != physical_key
        {
            return Err(TransactionError::Publication(
                "managed logical parent does not match its reserved physical child".to_string(),
            ));
        }
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
                ManagedChildIdentity::Supplied(child_scope),
            )
            .await?;
        metadata.remove("s4-generation");
        Ok(Box::new(ManagedReplicatedSink {
            repository,
            logical,
            generation,
            placement,
            logical_operation_id: Some(logical_operation_id),
            expected_cas: None,
            metadata,
            primary,
            replica: None,
            output: None,
            finished: false,
        }))
    }

    /// Admit a single-object streaming PUT against managed storage and begin
    /// its authoritative sink. The logical operation is journaled in the
    /// managed repository under the operator routing fence captured from the
    /// persisted namespace, while the request authorization grant remains the
    /// tenant-side identity; the returned sink records the canonical usage
    /// evidence into the same authority ledger before publishing object
    /// authority at commit. This separation is what makes managed commit an
    /// operator-fenced act rather than one the tenant grant could forge.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_managed_put_sink(
        self: &Arc<Self>,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        logical: LogicalObjectKey,
        content_type: &str,
        operation_id: uuid::Uuid,
        receipt_id: uuid::Uuid,
        occurred_at_ms: i64,
        rate_version: i32,
        max_processed_bytes: u64,
        expected_authority_cas: Option<u64>,
        prior_logical_size: u64,
    ) -> Result<Box<dyn ObjectSinkTransaction>, TransactionError> {
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Err(TransactionError::Publication(
                ManagedError::MutationDisabled(self.managed_mode).to_string(),
            ));
        }
        self.validate_managed_launch_configuration()
            .map_err(TransactionError::Publication)?;
        if !journal.is_durable() {
            return Err(TransactionError::Publication(
                "managed streaming requires a durable operation journal".to_string(),
            ));
        }
        let repository = self
            .authority_repository_required()
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        repository
            .assert_namespace_active(&logical.tenant_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let fence = repository
            .route_fence(&logical.tenant_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let placement = self.placement(&logical).ok_or_else(|| {
            TransactionError::Publication("managed storage has no backends".to_string())
        })?;
        let backend_index = self
            .index_for_id(&placement.primary_backend_id)
            .ok_or_else(|| {
                TransactionError::Publication(format!(
                    "unknown managed backend {}",
                    placement.primary_backend_id
                ))
            })?;
        let provider_bucket = self.backends[backend_index].bucket.clone();
        let generation = uuid::Uuid::now_v7();
        let physical_key = generation_physical_key(&logical, generation);
        let child_scope = ManagedOperationScope::deterministic_child(
            operation_id,
            logical.tenant_id.clone(),
            fence.namespace_epoch,
            &ObjectDestination {
                backend_id: placement.primary_backend_id.clone(),
                bucket: provider_bucket.clone(),
                logical_key: logical.object_key(),
                physical_key: physical_key.clone(),
                workspace_binding: None,
            },
            ManagedChildRole::Primary,
        );
        let intent = ManagedLogicalOperationIntent {
            operation_id,
            receipt_id,
            logical: logical.clone(),
            kind: ManagedMutationKind::Put,
            generation,
            fence,
            expected_authority_cas,
            prior_logical_size,
            primary_child_operation_id: child_scope.operation_id,
            backend_id: placement.primary_backend_id.clone(),
            provider_bucket: provider_bucket.clone(),
            physical_key: physical_key.clone(),
            occurred_at_ms,
            rate_version,
            route: UsageRoute::PutObject,
            request_kind: RequestKind::Write,
            max_processed_bytes,
        };
        if let Err(error) = repository.insert_logical_operation(intent.clone()).await {
            return Err(TransactionError::Publication(format!(
                "managed logical admission failed: {error}"
            )));
        }
        // Reserve the maximum exposure this request could publish, bounded by
        // the workspace's physical headroom so an arbitrary per-object limit
        // can never overflow the launch usage budget. The workspace admits one
        // managed mutation at a time, so the reservation is always released
        // before the next operation reserves again.
        let usage = repository
            .workspace_usage(&logical.tenant_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let available = usage
            .map(|usage| {
                usage
                    .visible_limit_bytes
                    .saturating_add(usage.replacement_headroom_bytes)
                    .saturating_sub(usage.physical_allocated_bytes)
                    .saturating_sub(usage.reserved_bytes)
            })
            .unwrap_or(crate::managed::MANAGED_VISIBLE_LIMIT_BYTES)
            .max(1);
        let reservation = max_processed_bytes
            .saturating_mul(MANAGED_STREAMING_PUT_HEADROOM)
            .min(available);
        if let Err(error) = repository
            .reserve_logical_operation(operation_id, reservation)
            .await
        {
            let _ = repository
                .prove_logical_abort(operation_id, "reservation_failed", None)
                .await;
            return Err(TransactionError::Publication(format!(
                "managed physical reservation failed: {error}"
            )));
        }
        let sink = match self
            .begin_authoritative_sink_for_operation(
                journal,
                capabilities,
                logical.clone(),
                content_type,
                operation_id,
                child_scope,
                generation,
            )
            .await
        {
            Ok(sink) => sink,
            Err(error) => {
                let _ = repository
                    .prove_logical_abort(operation_id, "sink_begin_failed", None)
                    .await;
                return Err(error);
            }
        };
        Ok(Box::new(ManagedLogicalSink {
            inner: sink,
            repository,
            operation_id,
            expected_output_size: None,
            expected_output_digest: None,
            usage_recorded: false,
            committed: false,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn direct_sink_for(
        &self,
        journal: &Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        backend_id: &str,
        logical: &LogicalObjectKey,
        physical_key: &str,
        mut metadata: BTreeMap<String, String>,
        child_identity: ManagedChildIdentity,
    ) -> Result<Box<dyn ManagedDestination>, TransactionError> {
        let index = self.index_for_id(backend_id).ok_or_else(|| {
            TransactionError::Publication(format!("unknown managed backend {backend_id}"))
        })?;
        let client = self.client_for(index).await.ok_or_else(|| {
            TransactionError::Publication(format!("managed backend {backend_id} is unavailable"))
        })?;
        let backend: Arc<dyn TransactionBackend> = if self.backends[index].is_b2() {
            Arc::new(AwsS3TransactionBackend::new_managed_b2(
                client,
                capabilities,
            ))
        } else {
            Arc::new(AwsS3TransactionBackend::new(client, capabilities))
        };
        if let Some(instance_id) = self.backends[index].provider_instance_id() {
            metadata.insert("s4-provider-instance".to_string(), instance_id.to_string());
        }
        if let Some(account_id) = self.backends[index].provider_account_id() {
            metadata.insert("s4-provider-account".to_string(), account_id.to_string());
        }
        if let Some(credential_epoch) = self.backends[index].credential_epoch() {
            metadata.insert(
                "s4-credential-epoch".to_string(),
                credential_epoch.to_string(),
            );
        }
        let destination = ObjectDestination {
            backend_id: backend_id.to_string(),
            bucket: self.backends[index].bucket.clone(),
            logical_key: logical.object_key(),
            physical_key: physical_key.to_string(),
            workspace_binding: None,
        };
        let (operation_id, expected_namespace_epoch) = match child_identity {
            ManagedChildIdentity::Supplied(scope) => {
                (scope.operation_id, Some(scope.namespace_epoch))
            }
            ManagedChildIdentity::Deterministic { parent, role } => (
                ManagedOperationScope::deterministic_child(
                    parent,
                    logical.tenant_id.clone(),
                    0,
                    &destination,
                    role,
                )
                .operation_id,
                None,
            ),
        };
        let repository = self
            .authority_repository_required()
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let versioning_mode = self.versioning_mode(index).await;
        let storage_identity = self.backends[index].storage_identity().ok_or_else(|| {
            TransactionError::Publication(format!(
                "managed backend {backend_id} has no immutable storage identity"
            ))
        })?;
        let credential_epoch = self.backends[index].credential_epoch().ok_or_else(|| {
            TransactionError::Publication(format!(
                "managed backend {backend_id} has no credential epoch"
            ))
        })?;
        let writer_owner = format!("managed-writer-{}", uuid::Uuid::now_v7());
        let lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id: operation_id,
                tenant_id: logical.tenant_id.clone(),
                backend_id: backend_id.to_string(),
                storage_identity,
                credential_epoch,
                provider_bucket: self.backends[index].bucket.clone(),
                physical_key: physical_key.to_string(),
                versioning_mode,
                versioning_capability: match capabilities.versioning {
                    VersioningCapability::Unsupported => BackendVersioningCapability::Unsupported,
                    VersioningCapability::Optional => BackendVersioningCapability::Optional,
                    VersioningCapability::Required => BackendVersioningCapability::Required,
                },
                lease_owner: writer_owner,
            })
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        if expected_namespace_epoch.is_some_and(|expected| expected != lease.namespace_epoch) {
            repository
                .abort_physical_write(&lease)
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))?;
            return Err(TransactionError::Publication(
                "managed child scope namespace epoch is stale".to_string(),
            ));
        }
        let (abort_signal, mut abort_receiver) = AbortSignal::channel(1);
        let reconciler = OperationReconciler::new(
            journal.clone(),
            backend.clone(),
            format!("managed-request-{}", uuid::Uuid::now_v7()),
        )?;
        tokio::spawn(async move {
            while let Some(operation_id) = abort_receiver.recv().await {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Err(error) = reconciler
                    .reconcile_operation(operation_id, Duration::from_secs(1))
                    .await
                {
                    warn!("managed transaction cleanup failed: {error}");
                }
            }
        });
        let sink = match DirectS3Sink::new_scoped(
            journal.clone(),
            backend.clone(),
            ManagedOperationScope {
                operation_id,
                tenant_id: logical.tenant_id.clone(),
                namespace_epoch: lease.namespace_epoch,
            },
            destination,
            ExpectedObject {
                metadata,
                ..ExpectedObject::default()
            },
            3,
            abort_signal,
        )
        .await
        {
            Ok(sink) => sink,
            Err(error) => {
                repository
                    .abort_physical_write(&lease)
                    .await
                    .map_err(|ledger_error| {
                        TransactionError::Publication(format!(
                            "managed journal initialization failed: {error}; intent cleanup failed: {ledger_error}"
                        ))
                    })?;
                return Err(error);
            }
        };
        let (lease_stop, mut lease_stopped) = watch::channel(());
        let lease_repository = repository.clone();
        let heartbeat_lease = lease.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = lease_stopped.changed() => break,
                    _ = interval.tick() => {
                        if lease_repository
                            .renew_physical_write_intent(
                                &heartbeat_lease,
                                crate::transaction::unix_time_ms()
                                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Box::new(ManagedDirectSink {
            sink,
            journal: journal.clone(),
            operation_id,
            repository,
            lease,
            lease_stop: Some(lease_stop),
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
            .map_err(|error| record_s3_failure("managed_repair_get", &error).to_string())?;
        let authority = ObjectAuthority {
            logical: repair.logical.clone(),
            generation: repair.generation,
            digest: repair.digest.clone(),
            size: repair.size,
            metadata: repair.metadata.clone(),
            placement_version: repair.placement_version,
            primary_backend_id: source_id.to_string(),
            primary_version_id: output.version_id().map(ToOwned::to_owned),
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
                ManagedChildIdentity::Deterministic {
                    parent: repair.id,
                    role: ManagedChildRole::Repair,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut body = output.body;
        while let Some(chunk) = body
            .try_next()
            .await
            .map_err(|_| record_s3_body_failure("managed_repair_get_body").to_string())?
        {
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
        let repository = self
            .authority_repository_required()
            .map_err(|error| error.to_string())?;
        if let Some(authority) = repository
            .get(&repair.logical)
            .await
            .map_err(|error| error.to_string())?
            && !authority.tombstone
            && authority.generation == repair.generation
            && (authority.primary_backend_id == repair.target_backend_id
                || authority.replica_backend_id.as_deref() == Some(&repair.target_backend_id))
        {
            return Err(
                "cleanup target is currently authoritative for this generation".to_string(),
            );
        }
        let versions = repository
            .physical_versions(
                &repair.logical.tenant_id,
                &repair.target_backend_id,
                &self.backends[index].bucket,
                &repair.physical_key,
            )
            .await
            .map_err(|error| error.to_string())?;
        if versions.is_empty() {
            return Err("cleanup has no exact physical-version ledger targets".to_string());
        }
        for target in versions {
            self.delete_and_verify_purge_target(&target).await?;
            repository
                .forget_physical_version(&target)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum ManagedChildIdentity {
    Supplied(ManagedOperationScope),
    Deterministic {
        parent: uuid::Uuid,
        role: ManagedChildRole,
    },
}

struct ManagedDirectSink {
    sink: DirectS3Sink,
    journal: Arc<dyn OperationJournal>,
    operation_id: uuid::Uuid,
    repository: Arc<dyn ManagedRepository>,
    lease: crate::managed::PhysicalWriteLease,
    lease_stop: Option<watch::Sender<()>>,
}

impl Drop for ManagedDirectSink {
    fn drop(&mut self) {
        if let Some(stop) = self.lease_stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn settle_managed_intent_from_journal(
    repository: &Arc<dyn ManagedRepository>,
    lease: &crate::managed::PhysicalWriteLease,
    operation: &crate::transaction::OperationRecord,
) -> Result<(), TransactionError> {
    match operation.state {
        OperationState::ProvenAborted => repository
            .abort_physical_write(lease)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string())),
        OperationState::Committed => {
            let Some(stored) = &operation.committed else {
                let reason = "committed managed operation has no provider result metadata";
                repository
                    .block_physical_write(lease, reason)
                    .await
                    .map_err(|error| TransactionError::Publication(error.to_string()))?;
                return Err(TransactionError::Publication(reason.to_string()));
            };
            if !stored.version_history_complete {
                let reason = "committed managed operation has ambiguous provider version history";
                repository
                    .block_physical_write(lease, reason)
                    .await
                    .map_err(|error| TransactionError::Publication(error.to_string()))?;
                return Err(TransactionError::CompletionAmbiguous);
            }
            repository
                .commit_physical_write(
                    lease,
                    &stored.superseded_version_ids,
                    stored.version_id.as_deref(),
                )
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))
        }
        state => {
            let reason = format!(
                "managed operation remains unresolved in journal state {}",
                state.as_str()
            );
            repository
                .block_physical_write(lease, &reason)
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))?;
            Err(TransactionError::CompletionAmbiguous)
        }
    }
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
        self.repository
            .renew_physical_write_intent(
                &self.lease,
                crate::transaction::unix_time_ms()
                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        self.sink.write(chunk).await
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        self.repository
            .renew_physical_write_intent(
                &self.lease,
                crate::transaction::unix_time_ms()
                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        self.sink
            .verify_output(expected_size, expected_sha256)
            .await
    }

    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        self.repository
            .renew_physical_write_intent(
                &self.lease,
                crate::transaction::unix_time_ms()
                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let journal = self.journal.clone();
        let stored = match complete_reconciled(self, &journal).await {
            Ok(stored) => stored,
            Err(error) => {
                let reason =
                    format!("provider completion did not prove exact version history: {error}");
                self.repository
                    .block_physical_write(&self.lease, &reason)
                    .await
                    .map_err(|ledger_error| {
                        TransactionError::Publication(format!(
                            "{reason}; additionally failed to block its physical write intent: {ledger_error}"
                        ))
                    })?;
                return Err(error);
            }
        };
        if !stored.version_history_complete {
            let reason = "provider version history is ambiguous; exact namespace purge is blocked";
            self.repository
                .block_physical_write(&self.lease, reason)
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))?;
            return Err(TransactionError::Publication(reason.to_string()));
        }
        if let Err(error) = self
            .repository
            .commit_physical_write(
                &self.lease,
                &stored.superseded_version_ids,
                stored.version_id.as_deref(),
            )
            .await
        {
            let reason = format!("physical version ledger commit failed: {error}");
            let _ = self
                .repository
                .block_physical_write(&self.lease, &reason)
                .await;
            return Err(TransactionError::Publication(reason));
        }
        Ok(stored)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        self.repository
            .renew_physical_write_intent(
                &self.lease,
                crate::transaction::unix_time_ms()
                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        if let Some(operation) = self.journal.get(self.operation_id).await?
            && matches!(
                operation.state,
                OperationState::Committed
                    | OperationState::CommitUnknown
                    | OperationState::Completing
            )
        {
            settle_managed_intent_from_journal(&self.repository, &self.lease, &operation).await?;
            return Err(TransactionError::CompletionAmbiguous);
        }
        self.sink.abort().await?;
        let operation = self.journal.get(self.operation_id).await?.ok_or_else(|| {
            TransactionError::Publication("managed operation journal row disappeared".to_string())
        })?;
        settle_managed_intent_from_journal(&self.repository, &self.lease, &operation).await
    }
}

async fn complete_reconciled(
    destination: &mut ManagedDirectSink,
    journal: &Arc<dyn OperationJournal>,
) -> Result<StoredObjectMeta, TransactionError> {
    match destination.sink.complete().await {
        Ok(stored) => Ok(stored),
        Err(original) => {
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
    logical_operation_id: Option<uuid::Uuid>,
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
    fn commit_state(&self) -> crate::transaction::SinkCommitState {
        if self.finished {
            crate::transaction::SinkCommitState::Committed
        } else if self.output.is_some() {
            crate::transaction::SinkCommitState::CommitUnknown
        } else {
            crate::transaction::SinkCommitState::PreCommit
        }
    }

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
            primary_version_id: primary.version_id.clone(),
            replica_backend_id: self.placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Ready,
            replica_status,
            tombstone: false,
            cas_version: 0,
            created_at_ms: now,
            updated_at_ms: now,
        };
        if let Some(logical_operation_id) = self.logical_operation_id {
            let physical_version_count = u64::try_from(primary.superseded_version_ids.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(TransactionError::CapacityExceeded)?;
            let physical_allocated_bytes = size
                .checked_mul(physical_version_count)
                .ok_or(TransactionError::CapacityExceeded)?;
            self.repository
                .commit_logical_put(logical_operation_id, authority, physical_allocated_bytes)
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))?;
        } else if let Err(error) = self
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

/// Logical-operation wrapper around a managed authoritative sink. The inner
/// replicated sink writes the generation to the provider and publishes object
/// authority; this wrapper records the canonical usage evidence into the
/// managed authority ledger before commit and proves the logical abort on a
/// clean failure so the workspace's mutation slot and reservation are released.
struct ManagedLogicalSink {
    inner: Box<dyn ObjectSinkTransaction>,
    repository: Arc<dyn ManagedRepository>,
    operation_id: uuid::Uuid,
    expected_output_size: Option<u64>,
    expected_output_digest: Option<String>,
    usage_recorded: bool,
    committed: bool,
}

#[async_trait::async_trait]
impl ObjectSinkTransaction for ManagedLogicalSink {
    fn commit_state(&self) -> SinkCommitState {
        if self.committed {
            SinkCommitState::Committed
        } else if self.usage_recorded {
            SinkCommitState::CommitUnknown
        } else {
            SinkCommitState::PreCommit
        }
    }

    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        if self.committed {
            return Err(TransactionError::Finished);
        }
        self.inner.write(chunk).await
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        if self.committed {
            return Err(TransactionError::Finished);
        }
        self.inner
            .verify_output(expected_size, expected_sha256)
            .await?;
        self.expected_output_size = Some(expected_size);
        self.expected_output_digest = Some(expected_sha256.to_string());
        Ok(())
    }

    async fn record_usage_evidence(&mut self, event: &UsageEvent) -> Result<(), TransactionError> {
        if self.usage_recorded {
            return Ok(());
        }
        let expected_output_size = self.expected_output_size.ok_or_else(|| {
            TransactionError::Publication(
                "managed logical usage evidence requires a verified output size".to_string(),
            )
        })?;
        let expected_output_digest = self.expected_output_digest.clone().ok_or_else(|| {
            TransactionError::Publication(
                "managed logical usage evidence requires a verified output digest".to_string(),
            )
        })?;
        let logical = self
            .repository
            .logical_operation(self.operation_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?
            .ok_or_else(|| {
                TransactionError::Publication("managed logical operation disappeared".to_string())
            })?;
        if logical.intent.kind != ManagedMutationKind::Put {
            return Err(TransactionError::Publication(
                "managed logical operation is not a put".to_string(),
            ));
        }
        if event.processed_bytes() != event.source_bytes().max(expected_output_size) {
            return Err(TransactionError::Publication(
                "managed usage evidence is inconsistent with the request".to_string(),
            ));
        }
        let evidence = ManagedUsageEvidence {
            expected_output_digest: Some(expected_output_digest),
            expected_output_size,
            source_bytes: event.source_bytes(),
            processed_bytes: event.processed_bytes(),
            payload: serde_json::json!({
                "route": event.route().as_str(),
                "kind": event.kind().as_str(),
                "bucket": event.bucket(),
                "pipeline_evidence": event.pipeline_evidence(),
            }),
        };
        self.repository
            .record_logical_usage(self.operation_id, evidence)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        self.repository
            .transition_logical_operation(
                self.operation_id,
                ManagedLogicalOperationState::Open,
                ManagedLogicalOperationState::Completing,
                None,
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        self.usage_recorded = true;
        Ok(())
    }

    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        if self.committed {
            return Err(TransactionError::Finished);
        }
        if !self.usage_recorded {
            return Err(TransactionError::Publication(
                "managed logical usage evidence was not recorded before commit".to_string(),
            ));
        }
        let stored = self.inner.complete().await?;
        self.committed = true;
        Ok(stored)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        if self.committed {
            return Ok(());
        }
        self.inner.abort().await?;
        if self.usage_recorded {
            return Ok(());
        }
        self.repository
            .prove_logical_abort(self.operation_id, "client_abort", None)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        Ok(())
    }
}

pub fn parse_service_backends(env_value: &str) -> Result<Vec<ServiceBackend>, String> {
    fn valid_identifier(value: &str, max_len: usize) -> bool {
        (1..=max_len).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }

    fn valid_credential(value: &str) -> bool {
        value.len() <= 4096 && value.bytes().all(|byte| byte.is_ascii_graphic())
    }

    let mut backends = Vec::new();
    for (index, definition) in env_value.split(';').enumerate() {
        let entry = index + 1;
        let parts: Vec<&str> = definition.split('|').collect();
        let (
            provider,
            instance,
            account,
            credential_epoch,
            placement_weight,
            placement_capacity_units,
            endpoint,
            region,
            bucket,
            access_key,
            secret_key,
        ) = match parts.as_slice() {
            [provider, endpoint, region, bucket, access_key, secret_key] => (
                *provider,
                None,
                None,
                None,
                None,
                None,
                *endpoint,
                *region,
                *bucket,
                *access_key,
                *secret_key,
            ),
            [
                provider,
                instance,
                account,
                credential_epoch,
                endpoint,
                region,
                bucket,
                access_key,
                secret_key,
            ] => (
                *provider,
                Some(*instance),
                Some(*account),
                Some(*credential_epoch),
                None,
                None,
                *endpoint,
                *region,
                *bucket,
                *access_key,
                *secret_key,
            ),
            [
                provider,
                instance,
                account,
                credential_epoch,
                placement_weight,
                placement_capacity_units,
                endpoint,
                region,
                bucket,
                access_key,
                secret_key,
            ] => (
                *provider,
                Some(*instance),
                Some(*account),
                Some(*credential_epoch),
                Some(*placement_weight),
                Some(*placement_capacity_units),
                *endpoint,
                *region,
                *bucket,
                *access_key,
                *secret_key,
            ),
            _ => {
                return Err(format!(
                    "invalid S4_SERVICE_BUCKETS entry {entry}: expected six legacy fields, nine managed identity fields, or eleven managed placement fields"
                ));
            }
        };
        if parts.iter().any(|part| part.trim().is_empty()) {
            return Err(format!(
                "invalid S4_SERVICE_BUCKETS entry {entry}: fields must be non-empty"
            ));
        }
        if !valid_identifier(provider, 128) {
            return Err(format!(
                "invalid S4_SERVICE_BUCKETS entry {entry}: malformed provider"
            ));
        }
        let explicit_identity = instance
            .zip(account)
            .zip(credential_epoch)
            .map(|((instance, account), credential_epoch)| {
                if !valid_identifier(instance, 128) {
                    return Err(format!(
                        "invalid S4_SERVICE_BUCKETS entry {entry}: malformed provider instance ID"
                    ));
                }
                if !valid_identifier(account, 256) {
                    return Err(format!(
                        "invalid S4_SERVICE_BUCKETS entry {entry}: malformed provider account ID"
                    ));
                }
                let credential_epoch = credential_epoch.parse::<u64>().map_err(|_| {
                    format!(
                        "invalid S4_SERVICE_BUCKETS entry {entry}: malformed credential epoch"
                    )
                })?;
                if credential_epoch == 0 {
                    return Err(format!(
                        "invalid S4_SERVICE_BUCKETS entry {entry}: credential epoch must be positive"
                    ));
                }
                Ok((instance, account, credential_epoch))
            })
            .transpose()?;
        let placement_policy = placement_weight
            .zip(placement_capacity_units)
            .map(|(weight, capacity_units)| {
                let weight = weight.parse::<u64>().map_err(|_| {
                    format!("invalid S4_SERVICE_BUCKETS entry {entry}: malformed placement weight")
                })?;
                let capacity_units = capacity_units.parse::<u64>().map_err(|_| {
                    format!("invalid S4_SERVICE_BUCKETS entry {entry}: malformed placement capacity units")
                })?;
                if weight == 0 || capacity_units == 0 || weight.checked_mul(capacity_units).is_none() {
                    return Err(format!(
                        "invalid S4_SERVICE_BUCKETS entry {entry}: placement weight and capacity units must be positive without overflow"
                    ));
                }
                Ok((weight, capacity_units))
            })
            .transpose()?
            // S7a's deployed managed identity form had no placement policy.
            // Its single backend retains the equivalent 1x1 static policy.
            .unwrap_or((1, 1));
        let endpoint_url = reqwest::Url::parse(endpoint)
            .map_err(|_| format!("invalid S4_SERVICE_BUCKETS entry {entry}: malformed endpoint"))?;
        if endpoint.len() > 2048
            || !endpoint.bytes().all(|byte| byte.is_ascii_graphic())
            || !matches!(endpoint_url.scheme(), "http" | "https")
            || endpoint_url.host_str().is_none()
            || !endpoint_url.username().is_empty()
            || endpoint_url.password().is_some()
            || endpoint_url.query().is_some()
            || endpoint_url.fragment().is_some()
        {
            return Err(format!(
                "invalid S4_SERVICE_BUCKETS entry {entry}: malformed endpoint"
            ));
        }
        let canonical_endpoint = canonical_provider_endpoint(endpoint).ok_or_else(|| {
            format!("invalid S4_SERVICE_BUCKETS entry {entry}: malformed endpoint")
        })?;
        if !valid_identifier(region, 128) {
            return Err(format!(
                "invalid S4_SERVICE_BUCKETS entry {entry}: malformed region"
            ));
        }
        if !valid_identifier(bucket, 255) {
            return Err(format!(
                "invalid S4_SERVICE_BUCKETS entry {entry}: malformed bucket"
            ));
        }
        if !valid_credential(access_key) {
            return Err(format!(
                "invalid S4_SERVICE_BUCKETS entry {entry}: malformed access key"
            ));
        }
        if !valid_credential(secret_key) {
            return Err(format!(
                "invalid S4_SERVICE_BUCKETS entry {entry}: malformed secret key"
            ));
        }
        backends.push(ServiceBackend {
            provider: provider.to_string(),
            provider_instance_id: explicit_identity
                .as_ref()
                .map(|(instance, _, _)| (*instance).to_string()),
            provider_account_id: explicit_identity
                .as_ref()
                .map(|(_, account, _)| (*account).to_string()),
            credential_epoch: explicit_identity.map(|(_, _, epoch)| epoch),
            placement_weight: placement_policy.0,
            placement_capacity_units: placement_policy.1,
            endpoint: canonical_endpoint,
            region: region.to_string(),
            bucket: bucket.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        });
    }
    Ok(backends)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::{InMemoryManagedRepository, PostgresManagedRepository};
    use std::sync::Mutex;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Method, StatusCode, Uri};
    use axum::routing::any;

    type ProviderRequests = Arc<Mutex<Vec<(Method, String)>>>;

    #[test]
    fn service_backend_parser_accepts_exact_valid_entries() {
        let backends = parse_service_backends(
            "aws|https://s3.us-east-1.amazonaws.com|us-east-1|bucket.one|AKIA123|secret+/=;r2|https://account.r2.cloudflarestorage.com|auto|bucket-two|key|secret",
        )
        .unwrap();

        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0].provider, "aws");
        assert_eq!(backends[1].bucket, "bucket-two");

        let managed = parse_service_backends(
            "b2|managed-primary|account-123|2|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|rotated-key|rotated-secret",
        )
        .unwrap()
        .pop()
        .unwrap();
        assert_eq!(managed.provider_kind(), "b2");
        assert_eq!(managed.provider_instance_id(), Some("managed-primary"));
        assert_eq!(managed.provider_account_id(), Some("account-123"));
        assert_eq!(managed.credential_epoch(), Some(2));
        assert_eq!(managed.placement_weight, 1);
        assert_eq!(managed.placement_capacity_units, 1);
        assert_eq!(managed.id(), "b2:managed-primary");
        assert_eq!(
            managed.storage_identity().unwrap().canonical_endpoint,
            "https://s3.us-east-005.backblazeb2.com/"
        );
        let weighted = parse_service_backends(
            "b2|managed-secondary|account-123|3|4|5|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket-two|rotated-key|rotated-secret",
        )
        .unwrap()
        .pop()
        .unwrap();
        assert_eq!(weighted.placement_weight, 4);
        assert_eq!(weighted.placement_capacity_units, 5);
        assert!(
            parse_service_backends(
                "b2|managed-primary|2|https://s3.example|us-east-1|bucket|key|secret"
            )
            .unwrap_err()
            .contains("nine managed identity fields")
        );
    }

    #[test]
    fn transactional_managed_launch_requires_identified_b2_pool_with_static_policy() {
        let repository = Arc::new(InMemoryManagedRepository::new());
        let managed = parse_service_backends(
            "b2|managed-primary|account-123|1|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|key|secret",
        )
        .unwrap();
        let storage = ServiceStorage::with_management(
            managed,
            repository.clone(),
            ManagedStreamingMode::Enforce,
            PLACEMENT_VERSION_V1,
        );
        assert!(storage.validate_managed_launch_configuration().is_ok());

        let multi_b2 = parse_service_backends(
            "b2|managed-primary|account-123|1|1|1|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|key|secret;b2|managed-replica|account-123|1|3|2|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket-two|key|secret",
        )
        .unwrap();
        assert!(
            ServiceStorage::with_management(
                multi_b2,
                repository.clone(),
                ManagedStreamingMode::Enforce,
                PLACEMENT_VERSION_V1,
            )
            .validate_managed_launch_configuration()
            .is_ok()
        );

        for invalid in [
            Vec::new(),
            parse_service_backends(
                "aws|provider-one|account-123|1|https://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "b2|https://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "b2|managed-primary|account-123|1|http://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "b2|one|account-1|1|1|1|https://s3.example|us-east-1|bucket-one|key|secret;aws|two|account-2|1|1|1|https://s3.example|us-east-1|bucket-two|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "b2|duplicate|account-1|1|1|1|https://s3.example|us-east-1|bucket-one|key|secret;b2|duplicate|account-2|1|1|1|https://s3.example|us-east-1|bucket-two|key|secret",
            )
            .unwrap(),
        ] {
            let storage = ServiceStorage::with_management(
                invalid,
                repository.clone(),
                ManagedStreamingMode::Enforce,
                PLACEMENT_VERSION_V1,
            );
            assert!(storage.validate_managed_launch_configuration().is_err());
        }
        for invalid_policy in [
            "b2|one|account-1|1|0|1|https://s3.example|us-east-1|bucket|key|secret",
            "b2|one|account-1|1|1|0|https://s3.example|us-east-1|bucket|key|secret",
            "b2|one|account-1|1|18446744073709551615|2|https://s3.example|us-east-1|bucket|key|secret",
        ] {
            assert!(parse_service_backends(invalid_policy).is_err());
        }
    }

    #[test]
    fn managed_placement_is_weighted_order_independent_and_has_distinct_replica() {
        let first = parse_service_backends(
            "b2|one|account-1|1|1|1|https://s3.example|us-east-1|bucket-one|key|secret;b2|two|account-2|1|3|1|https://s3.example|us-east-1|bucket-two|key|secret;b2|three|account-3|1|2|1|https://s3.example|us-east-1|bucket-three|key|secret",
        )
        .unwrap();
        let second = vec![first[2].clone(), first[0].clone(), first[1].clone()];
        let logical = LogicalObjectKey::new("tenant", "bucket", "key");
        let first_placement = ServiceStorage::new(first).placement(&logical).unwrap();
        let second_placement = ServiceStorage::new(second).placement(&logical).unwrap();
        assert_eq!(first_placement, second_placement);
        assert_ne!(
            first_placement.primary_backend_id,
            first_placement.replica_backend_id.unwrap()
        );
    }

    #[test]
    fn service_backend_parser_rejects_missing_extra_and_empty_fields() {
        for value in [
            "aws|https://s3.example|us-east-1|bucket|access",
            "aws|https://s3.example|us-east-1|bucket|access|secret|extra",
            "aws|https://s3.example|us-east-1|bucket|access|secret;",
            "",
        ] {
            assert!(parse_service_backends(value).is_err(), "accepted {value:?}");
        }

        for empty_field in 0..6 {
            let mut fields = [
                "aws",
                "https://s3.example",
                "us-east-1",
                "bucket",
                "access",
                "secret",
            ];
            fields[empty_field] = " ";
            assert!(
                parse_service_backends(&fields.join("|")).is_err(),
                "accepted empty field {empty_field}",
            );
        }
    }

    #[test]
    fn service_backend_parser_rejects_malformed_fields_without_echoing_values() {
        let malformed = [
            "aws/provider|https://s3.example|us-east-1|bucket|access|secret",
            "aws|not-a-url|us-east-1|bucket|access|secret",
            "aws|https://user@s3.example|us-east-1|bucket|access|secret",
            "aws|https://s3.example?credential=secret|us-east-1|bucket|access|secret",
            "aws|https://s3.example|us/east/1|bucket|access|secret",
            "aws|https://s3.example|us-east-1|bucket/name|access|secret",
            "aws|https://s3.example|us-east-1|bucket|ACCESS KEY VALUE|secret",
            "aws|https://s3.example|us-east-1|bucket|access|secret\nvalue",
        ];
        for value in malformed {
            let error = parse_service_backends(value).unwrap_err();
            assert!(!error.contains(value));
            assert!(!error.contains("credential=secret"));
            assert!(!error.contains("ACCESS KEY VALUE"));
            assert!(!error.contains("secret\nvalue"));
        }
    }

    async fn purge_provider_mock(
        State(requests): State<ProviderRequests>,
        method: Method,
        uri: Uri,
    ) -> axum::response::Response {
        requests
            .lock()
            .unwrap()
            .push((method.clone(), uri.to_string()));
        if method == Method::GET && uri.query() == Some("versioning") {
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(
                    r#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#,
                ))
                .unwrap()
        } else if method == Method::HEAD {
            axum::response::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap()
        } else {
            axum::response::Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
    }

    fn authority() -> ObjectAuthority {
        ObjectAuthority {
            logical: LogicalObjectKey::new("tenant", "bucket", "key"),
            generation: uuid::Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
            digest: "abc123".to_string(),
            size: 42,
            metadata: BTreeMap::new(),
            placement_version: 1,
            primary_backend_id: "primary".to_string(),
            primary_version_id: None,
            replica_backend_id: Some("replica".to_string()),
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::Ready,
            tombstone: false,
            cas_version: 1,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }

    fn purge_request() -> NamespacePurgeRequest {
        NamespacePurgeRequest {
            tenant_id: "tenant".to_string(),
            operation_id: uuid::Uuid::now_v7(),
        }
    }

    fn managed_test_capabilities() -> BackendCapabilities {
        BackendCapabilities {
            incomplete_upload_discovery:
                crate::transaction::IncompleteUploadDiscovery::ExactKeyAndStartTime,
            abort_incomplete_upload: true,
            cleanup_sla: Some(Duration::from_secs(60)),
            lifecycle_rule: true,
            versioning: crate::transaction::VersioningCapability::Optional,
            conditional_reads: crate::transaction::ConditionalReadCapability::VersionAndEtag,
            response_checksums: crate::transaction::ResponseChecksumCapability::Standard,
            list_operations: crate::transaction::ListCapability::V1AndV2,
            multipart_responses: crate::transaction::MultipartResponseCapability::Standard,
            completion_reconciliation:
                crate::transaction::CompletionReconciliation::HeadWithOperationIdentity,
        }
    }

    fn test_storage_identity() -> ProviderStorageIdentity {
        ProviderStorageIdentity {
            provider_kind: "test".to_string(),
            provider_instance_id: "managed-primary".to_string(),
            provider_account_id: "test-account".to_string(),
            canonical_endpoint: "https://provider.example/".to_string(),
            region: "test-region-1".to_string(),
        }
    }

    async fn assert_default_purge_is_unsupported(storage: &ServiceStorage) {
        let request = purge_request();
        assert!(matches!(
            storage.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Unsupported { .. }
        ));
        assert!(matches!(
            storage.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Unsupported { .. }
        ));
    }

    #[tokio::test]
    async fn namespace_purge_without_authority_is_explicitly_unsupported() {
        let storage = ServiceStorage::new(Vec::new());
        let request = purge_request();
        assert_eq!(
            storage.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Unsupported {
                reason: "managed namespace purge requires an authority repository".to_string(),
            }
        );
        assert_eq!(
            storage.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Unsupported {
                reason: "managed namespace purge status requires an authority repository"
                    .to_string(),
            }
        );
    }

    #[tokio::test]
    async fn empty_namespace_purge_delegates_and_completes_in_memory() {
        let storage = ServiceStorage::with_management(
            Vec::new(),
            Arc::new(InMemoryManagedRepository::new()),
            ManagedStreamingMode::Enforce,
            PLACEMENT_VERSION_V1,
        )
        .with_managed_capabilities(Some(managed_test_capabilities()));
        assert_eq!(
            storage.purge_namespace(&purge_request()).await.unwrap(),
            NamespacePurgeStatus::Complete {
                deleted_versions: 0,
            }
        );
    }

    #[tokio::test]
    async fn namespace_purge_requires_enforce_mode_without_connecting_to_postgres() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/postgres")
            .unwrap();
        let storage = ServiceStorage::with_management(
            Vec::new(),
            Arc::new(PostgresManagedRepository::new(pool)),
            ManagedStreamingMode::Off,
            PLACEMENT_VERSION_V1,
        );
        assert_default_purge_is_unsupported(&storage).await;
    }

    #[tokio::test]
    async fn namespace_purge_deletes_and_verifies_exact_provider_version() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .fallback(any(purge_provider_mock))
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = parse_service_backends(&format!(
            "b2|managed-primary|account-123|1|{endpoint}|us-east-005|bucket|key-one|secret-one"
        ))
        .unwrap()
        .pop()
        .unwrap();
        let repository = Arc::new(InMemoryManagedRepository::new());
        let intent_id = uuid::Uuid::now_v7();
        let lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id,
                tenant_id: "tenant".to_string(),
                backend_id: provider.id(),
                storage_identity: provider.storage_identity().unwrap(),
                credential_epoch: provider.credential_epoch().unwrap(),
                provider_bucket: "bucket".to_string(),
                physical_key: "managed/physical".to_string(),
                versioning_mode: BackendVersioningMode::Unversioned,
                versioning_capability: BackendVersioningCapability::Optional,
                lease_owner: "writer".to_string(),
            })
            .await
            .unwrap();
        repository
            .commit_physical_write(&lease, &[], Some("version-1"))
            .await
            .unwrap();
        let rotated_provider = parse_service_backends(&format!(
            "b2|managed-primary|account-123|2|{endpoint}|us-east-005|bucket|key-two|secret-two"
        ))
        .unwrap()
        .pop()
        .unwrap();
        assert_eq!(provider.id(), rotated_provider.id());
        assert_eq!(
            provider.storage_identity(),
            rotated_provider.storage_identity()
        );
        assert!(rotated_provider.matches_persisted_identity(
            &provider.storage_identity().unwrap(),
            provider.credential_epoch().unwrap()
        ));
        assert!(!provider.matches_persisted_identity(
            &rotated_provider.storage_identity().unwrap(),
            rotated_provider.credential_epoch().unwrap()
        ));
        let storage = ServiceStorage::with_management(
            vec![rotated_provider],
            repository,
            ManagedStreamingMode::Enforce,
            PLACEMENT_VERSION_V1,
        )
        .with_managed_capabilities(Some(managed_test_capabilities()));
        assert_eq!(
            storage.purge_namespace(&purge_request()).await.unwrap(),
            NamespacePurgeStatus::Complete {
                deleted_versions: 1,
            }
        );
        {
            let requests = requests.lock().unwrap();
            assert!(requests.iter().any(|(method, uri)| {
                method == Method::DELETE
                    && uri.starts_with("/bucket/managed/physical?")
                    && uri.contains("versionId=version-1")
            }));
            assert!(requests.iter().any(|(method, uri)| {
                method == Method::HEAD
                    && uri.starts_with("/bucket/managed/physical?")
                    && uri.contains("versionId=version-1")
            }));
        }
        let request_count_after_valid_deletion = requests.lock().unwrap().len();
        let mismatched_identity = PhysicalVersionTarget {
            tenant_id: "tenant".to_string(),
            namespace_epoch: 1,
            backend_id: "b2:managed-primary".to_string(),
            storage_identity: ProviderStorageIdentity {
                provider_account_id: "different-account".to_string(),
                ..storage.backends[0].storage_identity().unwrap()
            },
            credential_epoch: storage.backends[0].credential_epoch().unwrap(),
            provider_bucket: "bucket".to_string(),
            physical_key: "managed/physical".to_string(),
            version_id: Some("version-2".to_string()),
            versioning_mode: BackendVersioningMode::Unversioned,
            versioning_capability: BackendVersioningCapability::Optional,
            write_operation_id: uuid::Uuid::now_v7(),
        };
        assert!(
            storage
                .delete_and_verify_purge_target(&mismatched_identity)
                .await
                .unwrap_err()
                .contains("identity changed")
        );
        let mismatched_endpoint = PhysicalVersionTarget {
            storage_identity: ProviderStorageIdentity {
                canonical_endpoint: "https://other-location.example/".to_string(),
                ..storage.backends[0].storage_identity().unwrap()
            },
            ..mismatched_identity.clone()
        };
        assert!(
            storage
                .delete_and_verify_purge_target(&mismatched_endpoint)
                .await
                .unwrap_err()
                .contains("identity changed")
        );
        assert_eq!(
            requests.lock().unwrap().len(),
            request_count_after_valid_deletion,
            "account or endpoint rotation must fail before issuing deletion"
        );
        let changed_versioning = PhysicalVersionTarget {
            storage_identity: storage.backends[0].storage_identity().unwrap(),
            version_id: None,
            versioning_mode: BackendVersioningMode::Enabled,
            ..mismatched_identity
        };
        assert!(
            storage
                .delete_and_verify_purge_target(&changed_versioning)
                .await
                .unwrap_err()
                .contains("versioning mode changed")
        );
        let unprovable_unversioned = PhysicalVersionTarget {
            versioning_mode: BackendVersioningMode::Unversioned,
            ..changed_versioning
        };
        assert!(
            storage
                .delete_and_verify_purge_target(&unprovable_unversioned)
                .await
                .unwrap_err()
                .contains("cannot prove an unversioned ledger target")
        );
        server.abort();
    }

    #[tokio::test]
    async fn namespace_purge_blocks_unknown_provider_without_forgetting_target() {
        let repository = Arc::new(InMemoryManagedRepository::new());
        let intent_id = uuid::Uuid::now_v7();
        let lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id,
                tenant_id: "tenant".to_string(),
                backend_id: "missing:bucket".to_string(),
                storage_identity: test_storage_identity(),
                credential_epoch: 1,
                provider_bucket: "bucket".to_string(),
                physical_key: "managed/physical".to_string(),
                versioning_mode: BackendVersioningMode::Enabled,
                versioning_capability: BackendVersioningCapability::Optional,
                lease_owner: "writer".to_string(),
            })
            .await
            .unwrap();
        repository
            .commit_physical_write(&lease, &[], Some("version-1"))
            .await
            .unwrap();
        let storage = ServiceStorage::with_management(
            Vec::new(),
            repository,
            ManagedStreamingMode::Enforce,
            PLACEMENT_VERSION_V1,
        );
        assert!(matches!(
            storage.purge_namespace(&purge_request()).await.unwrap(),
            NamespacePurgeStatus::Blocked { reason }
                if reason.contains("unknown managed backend")
        ));
    }

    #[tokio::test]
    async fn abort_after_lost_put_response_and_retry_ambiguity_preserves_blocking_intent() {
        let repository = Arc::new(InMemoryManagedRepository::new());
        let operation_id = uuid::Uuid::now_v7();
        let lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id: operation_id,
                tenant_id: "tenant".to_string(),
                backend_id: "mock:bucket".to_string(),
                storage_identity: test_storage_identity(),
                credential_epoch: 1,
                provider_bucket: "bucket".to_string(),
                physical_key: "managed/physical".to_string(),
                versioning_mode: BackendVersioningMode::Enabled,
                versioning_capability: BackendVersioningCapability::Optional,
                lease_owner: "writer".to_string(),
            })
            .await
            .unwrap();
        let journal = Arc::new(crate::transaction::InMemoryOperationJournal::new());
        let operation = crate::transaction::OperationRecord::scoped_intent(
            operation_id,
            ObjectDestination {
                backend_id: "mock:bucket".to_string(),
                bucket: "bucket".to_string(),
                logical_key: "bucket/key".to_string(),
                physical_key: "managed/physical".to_string(),
                workspace_binding: None,
            },
            ExpectedObject::default(),
            "tenant".to_string(),
            lease.namespace_epoch,
        );
        journal.insert_intent(operation).await.unwrap();
        journal.set_open(operation_id, None).await.unwrap();
        journal
            .transition(
                operation_id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await
            .unwrap();
        journal
            .transition(
                operation_id,
                OperationState::Completing,
                OperationState::Committed,
                Some(&StoredObjectMeta {
                    etag: Some("retry-etag".to_string()),
                    version_id: Some("observed-retry-version".to_string()),
                    superseded_version_ids: Vec::new(),
                    version_history_complete: false,
                }),
            )
            .await
            .unwrap();
        let committed = journal.get(operation_id).await.unwrap().unwrap();
        let authority: Arc<dyn ManagedRepository> = repository.clone();
        assert!(matches!(
            settle_managed_intent_from_journal(&authority, &lease, &committed).await,
            Err(TransactionError::CompletionAmbiguous)
        ));
        let request = NamespacePurgeRequest {
            tenant_id: "tenant".to_string(),
            operation_id: uuid::Uuid::now_v7(),
        };
        assert!(matches!(
            repository.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Blocked { reason }
                if reason.contains("ambiguous provider version history")
        ));
        assert_eq!(
            repository
                .pending_physical_write_intents(10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn multi_instance_reconciler_skips_fresh_and_recovers_expired_terminal_intent() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .fallback(any(purge_provider_mock))
            .with_state(requests);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = ServiceBackend {
            provider: "mock".to_string(),
            provider_instance_id: Some("managed-primary".to_string()),
            provider_account_id: Some("test-account".to_string()),
            credential_epoch: Some(1),
            placement_weight: 1,
            placement_capacity_units: 1,
            endpoint: format!("http://{}", listener.local_addr().unwrap()),
            region: "us-east-1".to_string(),
            bucket: "bucket".to_string(),
            access_key: "key".to_string(),
            secret_key: "secret".to_string(),
        };
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let repository = Arc::new(InMemoryManagedRepository::new());
        let operation_id = uuid::Uuid::now_v7();
        let lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id: operation_id,
                tenant_id: "tenant".to_string(),
                backend_id: provider.id(),
                storage_identity: provider.storage_identity().unwrap(),
                credential_epoch: provider.credential_epoch().unwrap(),
                provider_bucket: provider.bucket.clone(),
                physical_key: "managed/physical".to_string(),
                versioning_mode: BackendVersioningMode::Unversioned,
                versioning_capability: BackendVersioningCapability::Optional,
                lease_owner: "writer".to_string(),
            })
            .await
            .unwrap();
        let journal = Arc::new(crate::transaction::InMemoryOperationJournal::new());
        journal
            .insert_intent(crate::transaction::OperationRecord::scoped_intent(
                operation_id,
                ObjectDestination {
                    backend_id: provider.id(),
                    bucket: provider.bucket.clone(),
                    logical_key: "bucket/key".to_string(),
                    physical_key: "managed/physical".to_string(),
                    workspace_binding: None,
                },
                ExpectedObject::default(),
                "tenant".to_string(),
                lease.namespace_epoch,
            ))
            .await
            .unwrap();
        journal.set_open(operation_id, None).await.unwrap();
        journal
            .transition(
                operation_id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await
            .unwrap();
        journal
            .transition(
                operation_id,
                OperationState::Completing,
                OperationState::Committed,
                Some(&StoredObjectMeta {
                    etag: Some("etag".to_string()),
                    version_id: None,
                    superseded_version_ids: Vec::new(),
                    version_history_complete: true,
                }),
            )
            .await
            .unwrap();
        let storage = ServiceStorage::with_management(
            vec![provider],
            repository.clone(),
            ManagedStreamingMode::Enforce,
            PLACEMENT_VERSION_V1,
        )
        .with_managed_capabilities(Some(managed_test_capabilities()));
        assert_eq!(
            storage
                .reconcile_managed_write_intents(
                    journal.clone(),
                    managed_test_capabilities(),
                    Duration::ZERO,
                    10,
                )
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            repository
                .pending_physical_write_intents(10)
                .await
                .unwrap()
                .len(),
            1,
            "another instance must not claim a fresh leased intent"
        );
        repository
            .renew_physical_write_intent(
                &lease,
                crate::transaction::unix_time_ms().saturating_sub(1),
            )
            .await
            .unwrap();
        storage
            .reconcile_managed_write_intents(
                journal,
                managed_test_capabilities(),
                Duration::ZERO,
                10,
            )
            .await
            .unwrap();
        assert!(
            repository
                .pending_physical_write_intents(10)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            repository
                .physical_versions(
                    "tenant",
                    &storage.backends[0].id(),
                    "bucket",
                    "managed/physical",
                )
                .await
                .unwrap()
                .len(),
            1
        );
        server.abort();
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
                logical_operation_id: None,
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

    #[tokio::test]
    async fn managed_streaming_put_admission_fails_closed_without_durable_prerequisites() {
        let repository = Arc::new(InMemoryManagedRepository::new());
        let backends = parse_service_backends(
            "b2|managed-primary|account-123|1|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|key|secret",
        )
        .unwrap();
        let enforce = Arc::new(ServiceStorage::with_management(
            backends,
            repository.clone(),
            ManagedStreamingMode::Enforce,
            PLACEMENT_VERSION_V1,
        ));
        let logical = LogicalObjectKey::new("tenant-streaming-admission", "bucket", "key.json");

        // A non-durable journal fails closed before admission.
        let journal = Arc::new(crate::transaction::InMemoryOperationJournal::new());
        let error = match enforce
            .clone()
            .begin_managed_put_sink(
                journal.clone(),
                managed_test_capabilities(),
                logical.clone(),
                "application/json",
                uuid::Uuid::now_v7(),
                uuid::Uuid::now_v7(),
                crate::transaction::unix_time_ms(),
                1,
                1024,
                None,
                0,
            )
            .await
        {
            Ok(_) => panic!("managed admission unexpectedly succeeded without a durable journal"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("durable operation journal"),
            "unexpected admission error: {error}"
        );

        // Off mode fails closed even when every other prerequisite is present.
        let off = Arc::new(ServiceStorage::with_management(
            parse_service_backends(
                "b2|managed-primary|account-123|1|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|key|secret",
            )
            .unwrap(),
            repository.clone(),
            ManagedStreamingMode::Off,
            PLACEMENT_VERSION_V1,
        ));
        let error = match off
            .begin_managed_put_sink(
                journal,
                managed_test_capabilities(),
                logical,
                "application/json",
                uuid::Uuid::now_v7(),
                uuid::Uuid::now_v7(),
                crate::transaction::unix_time_ms(),
                1,
                1024,
                None,
                0,
            )
            .await
        {
            Ok(_) => panic!("managed admission unexpectedly succeeded in off mode"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("mutation"),
            "unexpected admission error: {error}"
        );
    }

    #[tokio::test]
    async fn placement_reconciliation_advances_without_copy_and_deduplicates_repairs() {
        let repository = Arc::new(InMemoryManagedRepository::new());
        let storage = ServiceStorage::with_management(
            parse_service_backends(
                "b2|one|account-1|1|https://s3.example|us-east-1|bucket-one|key|secret;b2|two|account-2|1|https://s3.example|us-east-1|bucket-two|key|secret",
            ).unwrap(),
            repository.clone(),
            ManagedStreamingMode::Enforce,
            2,
        );
        let logical = LogicalObjectKey::new("tenant-placement", "bucket", "ready");
        let desired = storage.placement(&logical).unwrap();
        let ready = ObjectAuthority {
            logical: logical.clone(),
            generation: uuid::Uuid::now_v7(),
            digest: "digest".to_string(),
            size: 3,
            metadata: BTreeMap::new(),
            placement_version: 1,
            primary_backend_id: desired.primary_backend_id.clone(),
            primary_version_id: None,
            replica_backend_id: desired.replica_backend_id.clone(),
            primary_status: CopyStatus::Ready,
            replica_status: if desired.replica_backend_id.is_some() {
                CopyStatus::Ready
            } else {
                CopyStatus::Absent
            },
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        let ready = repository.publish(ready, None).await.unwrap();
        storage
            .reconcile_authority_placement(&ready, &desired)
            .await
            .unwrap();
        assert_eq!(
            repository
                .get(&logical)
                .await
                .unwrap()
                .unwrap()
                .placement_version,
            2
        );
        assert!(
            repository
                .claim_repairs("no-copy", crate::transaction::unix_time_ms() + 1_000, 10)
                .await
                .unwrap()
                .is_empty()
        );

        let stale = LogicalObjectKey::new("tenant-placement", "bucket", "stale");
        let mut stale_authority = repository.get(&logical).await.unwrap().unwrap();
        stale_authority.logical = stale.clone();
        stale_authority.generation = uuid::Uuid::now_v7();
        stale_authority.placement_version = 1;
        stale_authority.primary_backend_id = "old".to_string();
        stale_authority.replica_backend_id = None;
        stale_authority.primary_status = CopyStatus::Ready;
        stale_authority.replica_status = CopyStatus::Absent;
        let stale_authority = repository.publish(stale_authority, None).await.unwrap();
        storage
            .reconcile_authority_placement(&stale_authority, &storage.placement(&stale).unwrap())
            .await
            .unwrap();
        storage
            .reconcile_authority_placement(&stale_authority, &storage.placement(&stale).unwrap())
            .await
            .unwrap();
        let repairs = repository
            .claim_repairs(
                "deduplicated",
                crate::transaction::unix_time_ms() + 1_000,
                10,
            )
            .await
            .unwrap();
        assert_eq!(repairs.len(), 2, "one leg per desired primary and replica");
    }
}
