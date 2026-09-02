//! Postgres-backed key store integration tests.
//!
//! These run only when `DATABASE_URL` points at a reachable Postgres
//! (e.g. local Supabase: `postgresql://postgres:postgres@127.0.0.1:54322/postgres`).
//! Migrations are applied automatically. Without `DATABASE_URL` the tests
//! skip.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use s4_gateway::entity::api_key;
use s4_gateway::entity::managed_list_cursor;
use s4_gateway::entity::managed_logical_operation;
use s4_gateway::entity::managed_namespace;
use s4_gateway::entity::managed_namespace_purge;
use s4_gateway::entity::managed_object_authority;
use s4_gateway::entity::managed_object_repair;
use s4_gateway::entity::managed_physical_object_version;
use s4_gateway::entity::managed_workspace_usage;
use s4_gateway::entity::multipart_upload;
use s4_gateway::entity::object_operation;
use s4_gateway::key_cipher::{KeyWrapping, LocalKeyWrapping, SecretCipher};
use s4_gateway::managed::{
    AuthorityListQuery, BackendVersioningCapability, BackendVersioningMode, CopyStatus,
    InMemoryManagedRepository, LogicalObjectKey, MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES,
    MANAGED_LIST_CURSOR_WORKSPACE_LIMIT, ManagedListCursorBinding, ManagedListCursorPosition,
    ManagedListCursorRequest, ManagedListCursorState, ManagedListVersion,
    ManagedLogicalOperationIntent, ManagedLogicalOperationState, ManagedMutationKind,
    ManagedProvenPhysicalAllocation, ManagedRepository, ManagedRouteFence, ManagedUsageEvidence,
    NamespacePurgeRequest, NamespacePurgeStatus, ObjectAuthority, PhysicalWriteIntent, Placement,
    PostgresManagedRepository, ProviderStorageIdentity, generation_physical_key,
};
use s4_gateway::multipart_staging::{
    ARTIFACT_PREFIX, CompletePart, CompletionAcquire, MultipartCompletionResult, MultipartIdentity,
    MultipartLifecycle, MultipartPart, MultipartRepository, MultipartSnapshot, MultipartUpload,
    PostgresMultipartRepository,
};
use s4_gateway::store::{KeyRepository, PostgresKeyStore, sha256_hash};
use s4_gateway::transaction::{
    EvidenceRecord, ExpectedObject, ObjectDestination, OperationJournal, OperationRecord,
    OperationState, PartRecord, PostgresOperationJournal, StoredObjectMeta,
    WorkspaceDestinationBinding,
};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    SqlxPostgresConnector,
};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, header};
use s4_gateway::control::{
    AuthenticatedRequestContext, AuthorizationDecision, AuthorizationError, AuthorizationGrant,
    ControlPlane, MeteringError, RequestKind, UsageAuthorization, UsageEvent, UsageRoute,
};
use s4_gateway::server::{build_router, build_state};
use tower::ServiceExt;

const TEST_KEK: [u8; 32] = [7; 32];
const TEST_PUBLIC_KEY_PEM: &str = include_str!("../../../tests/fixtures/pii/crypto/pub.pem");
const TEST_CERTIFICATE_PEM: &str = include_str!("../../../tests/fixtures/pii/crypto/cert.pem");
static DB_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct MultipartBillingControl {
    authorizations: Mutex<Vec<(AuthenticatedRequestContext, UsageAuthorization)>>,
    grants: Mutex<HashMap<uuid::Uuid, AuthorizationGrant>>,
    releases: Mutex<Vec<(AuthenticatedRequestContext, uuid::Uuid)>>,
    events: Mutex<Vec<(AuthenticatedRequestContext, UsageEvent)>>,
}

#[async_trait::async_trait]
impl ControlPlane for MultipartBillingControl {
    async fn authorize(
        &self,
        context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.authorizations
            .lock()
            .unwrap()
            .push((context.clone(), authorization.clone()));
        let grant = self
            .grants
            .lock()
            .unwrap()
            .entry(authorization.operation_id())
            .or_insert_with(|| AuthorizationGrant::new(authorization, chrono::Utc::now(), 1))
            .clone();
        Ok(AuthorizationDecision::Granted(grant))
    }

    async fn release(
        &self,
        context: &AuthenticatedRequestContext,
        operation_id: uuid::Uuid,
    ) -> Result<(), AuthorizationError> {
        self.releases
            .lock()
            .unwrap()
            .push((context.clone(), operation_id));
        Ok(())
    }

    async fn record(
        &self,
        context: &AuthenticatedRequestContext,
        event: &UsageEvent,
    ) -> Result<(), MeteringError> {
        self.events
            .lock()
            .unwrap()
            .push((context.clone(), event.clone()));
        Ok(())
    }
}

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
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

fn test_physical_intent(
    intent_id: uuid::Uuid,
    tenant_id: &str,
    backend_id: &str,
    provider_bucket: &str,
    physical_key: &str,
    lease_owner: &str,
) -> PhysicalWriteIntent {
    PhysicalWriteIntent {
        intent_id,
        tenant_id: tenant_id.to_string(),
        backend_id: backend_id.to_string(),
        storage_identity: test_storage_identity(),
        credential_epoch: 1,
        provider_bucket: provider_bucket.to_string(),
        physical_key: physical_key.to_string(),
        versioning_mode: BackendVersioningMode::Enabled,
        versioning_capability: BackendVersioningCapability::Optional,
        lease_owner: lease_owner.to_string(),
    }
}

async fn assert_physical_intent_duplicate_contract(
    repository: &dyn ManagedRepository,
    tenant_id: &str,
) {
    let intent = test_physical_intent(
        uuid::Uuid::now_v7(),
        tenant_id,
        "provider:managed-primary",
        "provider-bucket",
        "managed/physical-key",
        "contract-writer",
    );
    let lease = repository
        .begin_physical_write(intent.clone())
        .await
        .unwrap();
    assert_eq!(
        repository
            .begin_physical_write(intent.clone())
            .await
            .unwrap(),
        lease
    );

    let conflicts = [
        PhysicalWriteIntent {
            physical_key: "managed/other-key".to_string(),
            ..intent.clone()
        },
        PhysicalWriteIntent {
            lease_owner: "other-writer".to_string(),
            ..intent.clone()
        },
        PhysicalWriteIntent {
            credential_epoch: 2,
            ..intent.clone()
        },
        PhysicalWriteIntent {
            storage_identity: ProviderStorageIdentity {
                provider_account_id: "other-account".to_string(),
                ..intent.storage_identity.clone()
            },
            ..intent.clone()
        },
    ];
    for conflicting in conflicts {
        assert!(matches!(
            repository.begin_physical_write(conflicting).await,
            Err(s4_gateway::managed::ManagedError::Conflict)
        ));
    }
    let pending = repository.pending_physical_write_intents(10).await.unwrap();
    let matching: Vec<_> = pending
        .iter()
        .filter(|pending| pending.intent.intent_id == intent.intent_id)
        .collect();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].intent, intent);
    assert_eq!(matching[0].lease, lease);
    repository.abort_physical_write(&lease).await.unwrap();
}

#[test]
fn physical_intent_duplicate_contract_matches_memory_and_postgres() {
    with_pool(|pool| async move {
        let tenant = format!("physical-contract-{}", uuid::Uuid::new_v4());
        assert_physical_intent_duplicate_contract(
            &InMemoryManagedRepository::new(),
            "physical-contract-memory",
        )
        .await;
        assert_physical_intent_duplicate_contract(
            &PostgresManagedRepository::new(pool.clone()),
            &tenant,
        )
        .await;

        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&sea_db(pool))
            .await
            .unwrap();
    });
}

#[test]
fn engine_migration_helper_ignores_unknown_private_versions_but_rejects_checksum_mismatch() {
    with_pool(|pool| async move {
        let unknown_version = 99_999_999_999_999_i64;
        sqlx::query(
            "INSERT INTO _sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES ($1, $2, NOW(), TRUE, $3, 0)",
        )
        .bind(unknown_version)
        .bind("private integration migration")
        .bind(vec![0x5a_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        s4_gateway::run_engine_migrations(&pool)
            .await
            .expect("unknown private migration must be ignored");
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
            .bind(unknown_version)
            .execute(&pool)
            .await
            .unwrap();

        let (version, checksum): (i64, Vec<u8>) = sqlx::query_as(
            "SELECT version, checksum FROM _sqlx_migrations \
             WHERE success = TRUE ORDER BY version LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut mismatched = checksum.clone();
        mismatched[0] ^= 0xff;
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
            .bind(&mismatched)
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        let mismatch = s4_gateway::run_engine_migrations(&pool).await;
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
            .bind(&checksum)
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        assert!(mismatch.is_err(), "public checksum mismatch must fail");
        s4_gateway::run_engine_migrations(&pool)
            .await
            .expect("restored public checksum must migrate cleanly");
    });
}

#[test]
fn managed_store_migration_fails_closed_with_existing_authority_rows() {
    with_pool(|pool| async move {
        let schema = format!("managed_upgrade_{}", uuid::Uuid::new_v4().simple());
        let migration =
            include_str!("../../../migrations/20260901000003_managed_store_operations.sql");
        let upgrade = format!(
            "CREATE SCHEMA \"{schema}\"; SET search_path TO \"{schema}\"; \
             CREATE TABLE managed_object_authorities (\
                tenant_id text NOT NULL, bucket text NOT NULL, logical_key text NOT NULL, \
                tombstone boolean NOT NULL); \
             CREATE TABLE managed_physical_write_intents (intent_id uuid); \
             CREATE TABLE managed_physical_object_versions (tenant_id text); \
             INSERT INTO managed_object_authorities VALUES \
                ('existing-tenant', 'bucket', 'key', false); {migration}"
        );
        let error = sqlx::raw_sql(&upgrade)
            .execute(&pool)
            .await
            .expect_err("existing managed rows must make the upgrade fail closed");
        assert!(
            error.to_string().contains(
                "cannot enable managed store operations with existing managed authority or physical ledger state"
            ),
            "unexpected migration error: {error}"
        );

        sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
    });
}

async fn ledger_managed_test_version(
    repository: &PostgresManagedRepository,
    tenant_id: &str,
    backend_id: &str,
    physical_key: &str,
) -> String {
    let intent_id = uuid::Uuid::now_v7();
    let version_id = format!("version-{intent_id}");
    let lease = repository
        .begin_physical_write(test_physical_intent(
            intent_id,
            tenant_id,
            backend_id,
            "test-provider-bucket",
            physical_key,
            "db-test-writer",
        ))
        .await
        .unwrap();
    repository
        .commit_physical_write(&lease, &[], Some(&version_id))
        .await
        .unwrap();
    version_id
}

#[test]
fn postgres_namespace_purge_fences_late_writes_and_completes_idempotently() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let journal = PostgresOperationJournal::new(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("purge-unit-{}", uuid::Uuid::new_v4());
        let intent_id = uuid::Uuid::now_v7();
        let physical_intent = test_physical_intent(
            intent_id,
            &tenant,
            "provider:bucket",
            "bucket",
            "managed/physical-key",
            "db-test-writer",
        );
        let lease = repository
            .begin_physical_write(physical_intent.clone())
            .await
            .unwrap();
        let duplicate = repository
            .begin_physical_write(physical_intent.clone())
            .await
            .unwrap();
        assert_eq!(duplicate, lease);
        assert!(matches!(
            repository
                .begin_physical_write(PhysicalWriteIntent {
                    physical_key: "managed/different-key".to_string(),
                    ..physical_intent
                })
                .await,
            Err(s4_gateway::managed::ManagedError::Conflict)
        ));
        journal
            .insert_intent(OperationRecord::scoped_intent(
                intent_id,
                ObjectDestination {
                    backend_id: "provider:bucket".to_string(),
                    bucket: "bucket".to_string(),
                    logical_key: "bucket/key".to_string(),
                    physical_key: "managed/physical-key".to_string(),
                    workspace_binding: None,
                },
                ExpectedObject::default(),
                tenant.clone(),
                lease.namespace_epoch,
            ))
            .await
            .unwrap();
        journal.set_open(intent_id, None).await.unwrap();
        journal
            .transition(
                intent_id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await
            .unwrap();
        let unresolved_operation_id = uuid::Uuid::now_v7();
        journal
            .insert_intent(OperationRecord::scoped_intent(
                unresolved_operation_id,
                ObjectDestination {
                    backend_id: "provider:bucket".to_string(),
                    bucket: "bucket".to_string(),
                    logical_key: "bucket/unresolved".to_string(),
                    physical_key: "managed/unresolved".to_string(),
                    workspace_binding: None,
                },
                ExpectedObject::default(),
                tenant.clone(),
                lease.namespace_epoch,
            ))
            .await
            .unwrap();
        journal
            .transition(
                intent_id,
                OperationState::Completing,
                OperationState::Committed,
                Some(&StoredObjectMeta {
                    etag: Some("etag".to_string()),
                    version_id: Some("version-2".to_string()),
                    superseded_version_ids: vec!["version-1".to_string()],
                    version_history_complete: true,
                }),
            )
            .await
            .unwrap();
        let request = NamespacePurgeRequest {
            tenant_id: tenant.clone(),
            operation_id: uuid::Uuid::now_v7(),
        };

        assert_eq!(
            repository.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Running,
            "the pre-fence write intent prevents false completion"
        );
        assert!(matches!(
            repository.assert_namespace_active(&tenant).await,
            Err(s4_gateway::managed::ManagedError::NamespaceFenced)
        ));
        assert!(matches!(
            repository
                .begin_physical_write(test_physical_intent(
                    uuid::Uuid::now_v7(),
                    &tenant,
                    "provider:bucket",
                    "bucket",
                    "must-not-start",
                    "stale-writer",
                ))
                .await,
            Err(s4_gateway::managed::ManagedError::NamespaceFenced)
        ));

        repository
            .commit_physical_write(&lease, &["version-1".to_string()], Some("version-2"))
            .await
            .unwrap();
        let targets = repository.purge_targets(&request, 10).await.unwrap();
        assert_eq!(targets.len(), 2);
        for target in targets {
            repository
                .mark_purge_target_deleted(&request, &target)
                .await
                .unwrap();
        }
        assert!(matches!(
            repository.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Blocked { reason }
                if reason.contains("unresolved operation journal")
        ));
        journal
            .transition(
                unresolved_operation_id,
                OperationState::Intent,
                OperationState::Aborting,
                None,
            )
            .await
            .unwrap();
        journal
            .transition(
                unresolved_operation_id,
                OperationState::Aborting,
                OperationState::ProvenAborted,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            repository.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Complete {
                deleted_versions: 2,
            }
        );
        assert_eq!(
            repository.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Complete {
                deleted_versions: 2,
            },
            "restarting the same purge operation is idempotent"
        );
        repository
            .assert_namespace_active(&tenant)
            .await
            .expect("completion reactivates an empty next epoch");
        assert!(journal.get(intent_id).await.unwrap().is_none());
        assert!(
            journal
                .get(unresolved_operation_id)
                .await
                .unwrap()
                .is_none()
        );

        managed_namespace_purge::Entity::delete_many()
            .filter(managed_namespace_purge::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

fn sea_db(pool: PgPool) -> DatabaseConnection {
    SqlxPostgresConnector::from_sqlx_postgres_pool(pool)
}

fn v1_envelope(secret: &str) -> String {
    let wrapping = LocalKeyWrapping::with_kek(TEST_KEK);
    let dek = [3u8; 32];
    let wrapped = wrapping.wrap(&dek).expect("wrap v1 test DEK");
    let nonce = [4u8; 12];
    let cipher = Aes256Gcm::new_from_slice(&dek).expect("valid AES-256 key");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret.as_bytes())
        .expect("encrypt v1 test secret");
    format!(
        "v1:{}:{}:{}",
        B64.encode(wrapped),
        B64.encode(nonce),
        B64.encode(ciphertext)
    )
}

async fn update_secret_state(
    db: &DatabaseConnection,
    key_id: &str,
    secret_hash: Option<&str>,
    envelope: &str,
) {
    let mut update = api_key::Entity::update_many().col_expr(
        api_key::Column::SecretEncrypted,
        Expr::value(Some(envelope.to_string())),
    );
    if let Some(secret_hash) = secret_hash {
        update = update.col_expr(
            api_key::Column::SecretHash,
            Expr::value(secret_hash.to_string()),
        );
    }
    let result = update
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .exec(db)
        .await
        .expect("update test API key secret state");
    assert_eq!(result.rows_affected, 1);
}

async fn fetch_api_key(db: &DatabaseConnection, key_id: &str) -> api_key::Model {
    api_key::Entity::find()
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .one(db)
        .await
        .expect("fetch test API key")
        .expect("test API key exists")
}

async fn delete_api_key(db: &DatabaseConnection, key_id: &str) {
    let result = api_key::Entity::delete_many()
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .exec(db)
        .await
        .expect("delete test API key");
    assert_eq!(result.rows_affected, 1);
}

struct BlockingWrapping {
    inner: LocalKeyWrapping,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl std::fmt::Debug for BlockingWrapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingWrapping").finish_non_exhaustive()
    }
}

impl KeyWrapping for BlockingWrapping {
    fn wrap(&self, dek: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).expect("signal blocked rewrap");
            self.release
                .lock()
                .unwrap()
                .recv()
                .expect("release blocked rewrap");
        }
        self.inner.wrap(dek)
    }

    fn unwrap(&self, wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.inner.unwrap(wrapped)
    }
}

/// Connect to `DATABASE_URL` (skipping only if unset), apply
/// migrations, then run `body` on a single Tokio runtime.
fn with_pool<F, Fut>(body: F)
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let _guard = DB_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };
        // A concurrent rewrap intentionally has a reader, conditional writer,
        // and verifier in flight. Keep the test pool above the production
        // default so its cleanup cannot be starved by those handles.
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .expect("DATABASE_URL must be reachable when configured");
        s4_gateway::run_engine_migrations(&pool)
            .await
            .expect("migrations should apply");
        body(pool.clone()).await;
        pool.close().await;
    });
}

#[test]
fn postgres_secret_envelope_roundtrip() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let cipher = Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            TEST_KEK,
        ))));
        let store = PostgresKeyStore::with_cipher(pool, cipher);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(&user, "encrypted", 0, None)
            .await
            .expect("create encrypted Postgres API key");
        let key_id = created.key_id;

        let persisted = store
            .get_key(&key_id)
            .await
            .expect("read persisted key")
            .expect("persisted key");
        let envelope = persisted.secret_encrypted.expect("encrypted secret");
        assert!(envelope.starts_with("v2:"));
        assert!(!envelope.contains(&secret));
        assert_eq!(
            store.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_operation_journal_persists_canonical_ambiguous_completion() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let journal = PostgresOperationJournal::new(pool);
        let operation = OperationRecord::intent(
            ObjectDestination {
                backend_id: "db-test".to_string(),
                bucket: "bucket".to_string(),
                logical_key: format!("logical-{}", uuid::Uuid::new_v4()),
                physical_key: format!("physical-{}", uuid::Uuid::new_v4()),
                workspace_binding: None,
            },
            ExpectedObject {
                digest: Some("sha256:test".to_string()),
                size: Some(4),
                metadata: Default::default(),
            },
        );
        journal.insert_intent(operation.clone()).await.unwrap();
        journal
            .set_open(operation.id, Some("upload-id"))
            .await
            .unwrap();
        let part = PartRecord {
            operation_id: operation.id,
            part_number: 1,
            etag: "etag-1".to_string(),
            size_bytes: 4,
            digest: "sha256:part".to_string(),
            created_at_ms: 1,
        };
        journal.record_part(part.clone()).await.unwrap();
        journal.record_part(part).await.unwrap();
        journal
            .transition(
                operation.id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await
            .unwrap();
        journal
            .transition(
                operation.id,
                OperationState::Completing,
                OperationState::CommitUnknown,
                None,
            )
            .await
            .unwrap();
        journal
            .append_evidence(EvidenceRecord::new(
                operation.id,
                "lost_complete_response",
                serde_json::json!({"retry": false}),
            ))
            .await
            .unwrap();

        let persisted = journal.get(operation.id).await.unwrap().unwrap();
        assert_eq!(persisted.state, OperationState::CommitUnknown);
        assert_eq!(persisted.upload_id.as_deref(), Some("upload-id"));
        assert_eq!(journal.parts(operation.id).await.unwrap().len(), 1);
        assert_eq!(journal.evidence(operation.id).await.unwrap().len(), 1);

        object_operation::Entity::delete_by_id(operation.id)
            .exec(&db)
            .await
            .expect("delete operation journal test row");
    });
}

#[test]
fn postgres_workspace_destination_survives_restart_in_every_recovery_state() {
    with_pool(|pool| async move {
        for target_state in [
            OperationState::Open,
            OperationState::Completing,
            OperationState::CommitUnknown,
        ] {
            let journal = PostgresOperationJournal::new(pool.clone());
            let operation_id = uuid::Uuid::now_v7();
            let binding = WorkspaceDestinationBinding {
                backend_config_version: format!("config-{operation_id}"),
                capability_attestation_id: format!("attestation-{operation_id}"),
                routing_epoch: 7,
                routing_lease_id: uuid::Uuid::now_v7(),
                routing_fencing_token: 11,
            };
            let operation = OperationRecord::direct_intent(
                s4_gateway::transaction::DirectOperationScope {
                    operation_id,
                    tenant_id: "workspace-restart".to_string(),
                },
                ObjectDestination {
                    backend_id: "PerUserS3".to_string(),
                    bucket: "bucket".to_string(),
                    logical_key: "logical".to_string(),
                    physical_key: "physical".to_string(),
                    workspace_binding: Some(binding.clone()),
                },
                ExpectedObject::default(),
            );
            journal.insert_intent(operation).await.unwrap();
            journal
                .set_open(operation_id, Some("upload-id"))
                .await
                .unwrap();
            if matches!(
                target_state,
                OperationState::Completing | OperationState::CommitUnknown
            ) {
                journal
                    .transition(
                        operation_id,
                        OperationState::Open,
                        OperationState::Completing,
                        None,
                    )
                    .await
                    .unwrap();
            }
            if target_state == OperationState::CommitUnknown {
                journal
                    .transition(
                        operation_id,
                        OperationState::Completing,
                        OperationState::CommitUnknown,
                        None,
                    )
                    .await
                    .unwrap();
            }

            let restarted = PostgresOperationJournal::new(pool.clone())
                .get(operation_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(restarted.state, target_state);
            assert_eq!(restarted.destination.workspace_binding, Some(binding));
            let persisted = serde_json::to_string(&restarted.destination).unwrap();
            assert!(!persisted.contains("secret"));
            assert!(!persisted.contains("access-key"));
        }
    });
}

#[test]
fn postgres_evidence_foreign_key_requires_a_matching_operation_intent() {
    with_pool(|pool| async move {
        let journal = PostgresOperationJournal::new(pool);
        let missing_operation_id = uuid::Uuid::now_v7();
        let error = journal
            .append_evidence(EvidenceRecord::new(
                missing_operation_id,
                "usage",
                serde_json::json!({"source": "memory-sink-regression"}),
            ))
            .await
            .expect_err("evidence without an operation intent must violate the FK");
        assert!(error.to_string().contains("journal persistence failed"));
    });
}

#[test]
fn postgres_multipart_completion_cas_replay_and_fencing_are_durable() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresMultipartRepository::new(pool);
        let upload_id = format!("completion-{}", uuid::Uuid::new_v4());
        let now = unix_time_ms();
        let identity = MultipartIdentity {
            tenant_id: "multipart-integration".to_string(),
            credential_policy_id: "key".to_string(),
            bucket: "bucket".to_string(),
            key: format!("object-{}", uuid::Uuid::new_v4()),
            upload_id: upload_id.clone(),
        };
        repository
            .create(MultipartUpload {
                identity: identity.clone(),
                namespace_epoch: None,
                snapshot: MultipartSnapshot {
                    metadata: Default::default(),
                    tags: Default::default(),
                    checksum_mode: None,
                    destination: serde_json::json!({"kind":"test"}),
                    plugin_snapshot: serde_json::json!([]),
                    max_staged_bytes: 1024,
                },
                lifecycle: MultipartLifecycle::Open,
                staged_bytes: 0,
                reserved_bytes: 0,
                created_at_ms: now,
                expires_at_ms: now + 60_000,
                updated_at_ms: now,
                tombstone_until_ms: None,
                complete_request_fingerprint: None,
                completion_lease_owner: None,
                completion_lease_expires_at_ms: None,
                completion_fencing_token: 0,
                completion_result: None,
            })
            .await
            .expect("create multipart upload");
        repository
            .replace_part(
                &identity,
                MultipartPart {
                    upload_id: upload_id.clone(),
                    part_number: 1,
                    attempt: 1,
                    artifact_key: format!("artifact-{}", uuid::Uuid::new_v4()),
                    etag: "\"part\"".to_string(),
                    checksum_sha256: "part-sha".to_string(),
                    size_bytes: 3,
                    created_at_ms: now,
                },
            )
            .await
            .expect("persist part");
        let selected = [CompletePart {
            part_number: 1,
            etag: "\"part\"".to_string(),
            checksum_sha256: Some("part-sha".to_string()),
        }];
        let first = match repository
            .acquire_completion(&identity, "request", &selected, "worker-a", now + 10, now)
            .await
            .expect("acquire first lease")
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected acquired completion lease"),
        };
        let second = match repository
            .acquire_completion(
                &identity,
                "request",
                &selected,
                "worker-b",
                now + 30,
                now + 11,
            )
            .await
            .expect("take over expired lease")
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected takeover completion lease"),
        };
        assert!(second.fencing_token > first.fencing_token);
        assert!(
            repository
                .check_completion_lease(&identity, first.fencing_token, now + 12)
                .await
                .is_err()
        );
        repository
            .complete_completion(
                &identity,
                second.fencing_token,
                MultipartCompletionResult {
                    etag: Some("\"result\"".to_string()),
                    checksum_sha256: "result-sha".to_string(),
                    version_id: Some("version".to_string()),
                    source_bytes: 24,
                    size_bytes: 42,
                    pipeline_evidence: None,
                },
                now + 12,
            )
            .await
            .expect("persist immutable result");
        assert!(matches!(
            repository
                .acquire_completion(&identity, "request", &selected, "retry", now + 40, now + 13)
                .await,
            Ok(CompletionAcquire::Replayed(_))
        ));
        assert!(
            repository
                .acquire_completion(
                    &identity,
                    "conflict",
                    &selected,
                    "retry",
                    now + 40,
                    now + 13
                )
                .await
                .is_err()
        );
        multipart_upload::Entity::delete_many()
            .filter(multipart_upload::Column::UploadId.eq(upload_id))
            .exec(&db)
            .await
            .expect("delete multipart completion test rows");
    });
}

#[test]
fn postgres_managed_authority_publish_repair_lease_and_tombstone_are_atomic() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("managed-unit-{}", uuid::Uuid::new_v4());
        let logical = LogicalObjectKey::new(&tenant, "bucket", "path/to/key");
        let generation = uuid::Uuid::now_v7();
        let primary_version_id = ledger_managed_test_version(
            &repository,
            &tenant,
            "primary",
            &s4_gateway::managed::generation_physical_key(&logical, generation),
        )
        .await;
        let authority = ObjectAuthority {
            logical: logical.clone(),
            generation,
            digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
            size: 3,
            metadata: std::collections::BTreeMap::from([(
                "content-type".to_string(),
                "text/plain".to_string(),
            )]),
            placement_version: 1,
            primary_backend_id: "primary".to_string(),
            primary_version_id: Some(primary_version_id),
            replica_backend_id: Some("replica".to_string()),
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::RepairPending,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };

        let published = repository.publish(authority.clone(), None).await.unwrap();
        assert_eq!(published.cas_version, 1);
        let persisted = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(persisted.generation, generation);
        assert_eq!(persisted.replica_status, CopyStatus::RepairPending);
        assert_eq!(
            managed_object_repair::Entity::find()
                .filter(managed_object_repair::Column::TenantId.eq(&tenant))
                .all(&db)
                .await
                .unwrap()
                .len(),
            1,
            "authority and replica repair publish in one transaction"
        );

        assert!(
            repository.publish(authority.clone(), None).await.is_err(),
            "create CAS cannot overwrite authority"
        );
        let expired_lease = unix_time_ms() - 1;
        let first_claim = repository
            .claim_repairs("process-before-restart", expired_lease, 10)
            .await
            .unwrap();
        assert_eq!(first_claim.len(), 1);
        let restarted_claim = repository
            .claim_repairs("process-after-restart", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(restarted_claim.len(), 1);
        assert!(
            repository
                .renew_repair(uuid::Uuid::now_v7(), unix_time_ms() + 60_000)
                .await
                .is_err()
        );
        repository
            .renew_repair(restarted_claim[0].id, unix_time_ms() + 60_000)
            .await
            .unwrap();
        assert!(
            repository
                .claim_repairs("process-during-heartbeat", unix_time_ms() + 30_000, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(repository.complete_repair(&first_claim[0]).await.is_err());
        assert!(
            repository
                .fail_repair(first_claim[0].id, "stale process")
                .await
                .is_err()
        );
        let _ = ledger_managed_test_version(
            &repository,
            &tenant,
            &restarted_claim[0].target_backend_id,
            &restarted_claim[0].physical_key,
        )
        .await;
        assert!(
            repository
                .complete_repair(&restarted_claim[0])
                .await
                .unwrap()
        );
        let current_after_repair = repository.get(&logical).await.unwrap().unwrap();
        repository
            .enqueue(s4_gateway::managed::RepairRecord::copy(
                s4_gateway::managed::RepairKind::Replica,
                &current_after_repair,
                Some(current_after_repair.primary_backend_id.clone()),
                current_after_repair
                    .replica_backend_id
                    .clone()
                    .expect("replica backend"),
                s4_gateway::managed::RepairTargetRole::Replica,
                current_after_repair.placement_version,
            ))
            .await
            .expect("completed repair can be re-enqueued without poisoning the transaction");
        let requeued = repository
            .claim_repairs("process-requeued", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(requeued.len(), 1);
        repository.complete_repair(&requeued[0]).await.unwrap();
        let repaired = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(repaired.replica_status, CopyStatus::Ready);

        let replica_placement = Placement {
            version: repaired.placement_version + 1,
            primary_backend_id: "primary".to_string(),
            replica_backend_id: Some("replica-v2".to_string()),
        };
        repository
            .enqueue(s4_gateway::managed::RepairRecord::placement(
                &repaired,
                Some("primary".to_string()),
                "replica-v2".to_string(),
                s4_gateway::managed::RepairTargetRole::Replica,
                &replica_placement,
            ))
            .await
            .unwrap();
        let replica_migration = repository
            .claim_repairs("process-replica-migration", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(replica_migration.len(), 1);
        let _ = ledger_managed_test_version(
            &repository,
            &tenant,
            &replica_migration[0].target_backend_id,
            &replica_migration[0].physical_key,
        )
        .await;
        assert!(
            repository
                .complete_repair(&replica_migration[0])
                .await
                .unwrap()
        );
        let migrated = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(migrated.primary_backend_id, "primary");
        assert_eq!(migrated.replica_backend_id.as_deref(), Some("replica-v2"));
        assert_eq!(migrated.placement_version, repaired.placement_version + 1);

        let full_placement = Placement {
            version: migrated.placement_version + 1,
            primary_backend_id: "primary-v3".to_string(),
            replica_backend_id: Some("replica-v3".to_string()),
        };
        for (target_backend_id, target_role) in [
            (
                full_placement.primary_backend_id.clone(),
                s4_gateway::managed::RepairTargetRole::Primary,
            ),
            (
                full_placement.replica_backend_id.clone().unwrap(),
                s4_gateway::managed::RepairTargetRole::Replica,
            ),
        ] {
            repository
                .enqueue(s4_gateway::managed::RepairRecord::placement(
                    &migrated,
                    Some("primary".to_string()),
                    target_backend_id,
                    target_role,
                    &full_placement,
                ))
                .await
                .unwrap();
        }
        let migration_repairs = repository
            .claim_repairs("process-placement-race", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(migration_repairs.len(), 2);
        for repair in &migration_repairs {
            let _ = ledger_managed_test_version(
                &repository,
                &tenant,
                &repair.target_backend_id,
                &repair.physical_key,
            )
            .await;
        }
        let (left, right) = tokio::join!(
            repository.complete_repair(&migration_repairs[0]),
            repository.complete_repair(&migration_repairs[1]),
        );
        left.unwrap();
        right.unwrap();
        let converged = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(converged.primary_backend_id, "primary-v3");
        assert_eq!(converged.replica_backend_id.as_deref(), Some("replica-v3"));
        assert_eq!(converged.placement_version, full_placement.version);

        let tombstone = repository
            .tombstone(
                &logical,
                Some(converged.cas_version),
                &Placement {
                    version: 1,
                    primary_backend_id: "primary".to_string(),
                    replica_backend_id: Some("replica".to_string()),
                },
            )
            .await
            .unwrap();
        assert!(tombstone.tombstone);
        assert_ne!(tombstone.generation, generation);
        assert!(
            repository
                .publish(authority, Some(published.cas_version))
                .await
                .is_err(),
            "stale update cannot resurrect a tombstoned generation"
        );
        let cleanup_count = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::TenantId.eq(&tenant))
            .filter(managed_object_repair::Column::Kind.eq("DELETE_GENERATION"))
            .all(&db)
            .await
            .unwrap()
            .len();
        assert_eq!(cleanup_count, 2);

        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_managed_logical_quota_listing_cursor_and_release_contract() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("managed-logical-unit-{}", uuid::Uuid::new_v4());
        let logical = LogicalObjectKey::new(&tenant, "bucket", "prefix%/key");
        let generation = uuid::Uuid::now_v7();
        let fence = repository.route_fence(&tenant).await.unwrap();
        assert_eq!(
            fence,
            ManagedRouteFence {
                namespace_epoch: 1,
                routing_epoch: 1
            }
        );
        let intent = ManagedLogicalOperationIntent {
            operation_id: uuid::Uuid::now_v7(),
            receipt_id: uuid::Uuid::now_v7(),
            logical: logical.clone(),
            kind: ManagedMutationKind::Put,
            generation,
            fence,
            expected_authority_cas: None,
            prior_logical_size: 0,
            primary_child_operation_id: uuid::Uuid::now_v7(),
            backend_id: "primary".to_string(),
            provider_bucket: "provider-bucket".to_string(),
            physical_key: generation_physical_key(&logical, generation),
            occurred_at_ms: unix_time_ms(),
            rate_version: 7,
            route: UsageRoute::PutObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: 64,
        };
        let mut concurrent = intent.clone();
        concurrent.operation_id = uuid::Uuid::now_v7();
        concurrent.receipt_id = uuid::Uuid::now_v7();
        concurrent.logical = LogicalObjectKey::new(&tenant, "bucket", "other");
        concurrent.generation = uuid::Uuid::now_v7();
        concurrent.primary_child_operation_id = uuid::Uuid::now_v7();
        concurrent.physical_key =
            generation_physical_key(&concurrent.logical, concurrent.generation);

        let inserted = repository
            .insert_logical_operation(intent.clone())
            .await
            .unwrap();
        assert_eq!(inserted.intent, intent);
        assert_eq!(
            repository
                .insert_logical_operation(intent.clone())
                .await
                .unwrap()
                .intent,
            intent
        );
        assert!(
            managed_logical_operation::Entity::update_many()
                .col_expr(
                    managed_logical_operation::Column::RateVersion,
                    Expr::value(intent.rate_version + 1),
                )
                .filter(managed_logical_operation::Column::OperationId.eq(intent.operation_id),)
                .exec(&db)
                .await
                .is_err(),
            "canonical pricing identity must be database-immutable"
        );
        assert_eq!(
            repository
                .logical_operation(intent.operation_id)
                .await
                .unwrap()
                .unwrap()
                .intent
                .rate_version,
            intent.rate_version
        );
        repository
            .insert_logical_operation(concurrent.clone())
            .await
            .unwrap();
        let child = PhysicalWriteIntent {
            intent_id: intent.primary_child_operation_id,
            tenant_id: tenant.clone(),
            backend_id: intent.backend_id.clone(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: intent.provider_bucket.clone(),
            physical_key: intent.physical_key.clone(),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Required,
            lease_owner: "logical-db-test".to_string(),
        };
        assert!(
            repository
                .begin_physical_write(child.clone())
                .await
                .is_err()
        );
        repository
            .reserve_logical_operation(intent.operation_id, 6)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .reserve_logical_operation(concurrent.operation_id, 1)
                .await,
            Err(s4_gateway::managed::ManagedError::MutationInProgress)
        ));
        let lease = repository.begin_physical_write(child).await.unwrap();
        repository
            .commit_physical_write(
                &lease,
                &[
                    "ambiguous-retry-version".to_string(),
                    "ambiguous-retry-version".to_string(),
                ],
                Some("committed-version"),
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .insert_logical_operation(intent.clone())
                .await
                .unwrap()
                .intent,
            intent,
            "parent insertion must remain idempotent after child creation"
        );
        repository
            .record_logical_usage(
                intent.operation_id,
                ManagedUsageEvidence {
                    expected_output_digest: Some("digest".to_string()),
                    expected_output_size: 3,
                    source_bytes: 3,
                    processed_bytes: 3,
                    payload: serde_json::json!({"immutable": true}),
                },
            )
            .await
            .unwrap();
        repository
            .transition_logical_operation(
                intent.operation_id,
                ManagedLogicalOperationState::Open,
                ManagedLogicalOperationState::Completing,
                None,
            )
            .await
            .unwrap();
        let authority = ObjectAuthority {
            logical: logical.clone(),
            generation,
            digest: "digest".to_string(),
            size: 3,
            metadata: std::collections::BTreeMap::new(),
            placement_version: 1,
            primary_backend_id: intent.backend_id.clone(),
            primary_version_id: Some("committed-version".to_string()),
            replica_backend_id: None,
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::Absent,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        assert!(matches!(
            repository
                .commit_logical_put(intent.operation_id, authority.clone(), 3)
                .await,
            Err(s4_gateway::managed::ManagedError::Conflict)
        ));
        let committed = repository
            .commit_logical_put(intent.operation_id, authority.clone(), 6)
            .await
            .unwrap();
        assert_eq!(committed.operation.intent.receipt_id, intent.receipt_id);
        assert_eq!(committed.operation.intent.rate_version, 7);
        assert_eq!(committed.usage.visible_logical_bytes, 3);
        assert_eq!(committed.usage.physical_allocated_bytes, 6);
        assert_eq!(committed.usage.reserved_bytes, 0);
        assert_eq!(committed.usage.active_operation_id, None);
        repository
            .commit_logical_put(intent.operation_id, authority, 6)
            .await
            .unwrap();

        managed_object_authority::Entity::insert(managed_object_authority::ActiveModel {
            tenant_id: Set(tenant.clone()),
            bucket: Set("bucket".to_string()),
            logical_key: Set("prefixX/key".to_string()),
            generation: Set(uuid::Uuid::now_v7()),
            digest: Set("other".to_string()),
            size_bytes: Set(1),
            metadata: Set(serde_json::json!({})),
            placement_version: Set(1),
            primary_backend_id: Set("primary".to_string()),
            primary_version_id: Set(Some("other-version".to_string())),
            replica_backend_id: Set(None),
            primary_status: Set("READY".to_string()),
            replica_status: Set("ABSENT".to_string()),
            tombstone: Set(false),
            cas_version: Set(1),
            created_at_ms: Set(0),
            updated_at_ms: Set(0),
        })
        .exec(&db)
        .await
        .unwrap();
        let listed = repository
            .list_authority(AuthorityListQuery {
                tenant_id: tenant.clone(),
                bucket: "bucket".to_string(),
                prefix: "prefix%".to_string(),
                after: None,
                max_keys: 10,
            })
            .await
            .unwrap();
        assert_eq!(
            listed.objects.len(),
            1,
            "SQL wildcard bytes must stay literal"
        );
        assert_eq!(listed.objects[0].logical, logical);

        let now = unix_time_ms();
        let binding = ManagedListCursorBinding {
            tenant_id: tenant.clone(),
            bucket: "bucket".to_string(),
            prefix: "prefix%".to_string(),
            delimiter: Some("/".to_string()),
            version: ManagedListVersion::V2,
        };
        let cursor = repository
            .create_list_cursor(
                ManagedListCursorRequest {
                    binding: binding.clone(),
                    position: ManagedListCursorPosition {
                        last_key: Some("prefix%/key".to_string()),
                        last_common_prefix: None,
                    },
                    response_state: serde_json::json!({"keys": ["prefix%/key"]}),
                    final_page: false,
                },
                now,
            )
            .await
            .unwrap();
        assert_eq!(cursor.fence, fence);
        assert_eq!(
            cursor.response_state_bytes,
            serde_json::to_vec(&cursor.response_state).unwrap().len() as u64
        );
        assert!(matches!(
            repository
                .create_list_cursor(
                    ManagedListCursorRequest {
                        binding: binding.clone(),
                        position: ManagedListCursorPosition {
                            last_key: None,
                            last_common_prefix: None,
                        },
                        response_state: serde_json::Value::String(
                            "x".repeat(MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES as usize),
                        ),
                        final_page: false,
                    },
                    now,
                )
                .await,
            Err(s4_gateway::managed::ManagedError::CursorLimitExceeded)
        ));
        let oversized_bytes = vec![b'x'; MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES as usize + 1];
        assert!(
            managed_list_cursor::Entity::insert(managed_list_cursor::ActiveModel {
                cursor_id: Set(uuid::Uuid::new_v4()),
                predecessor_cursor_id: Set(None),
                tenant_id: Set(tenant.clone()),
                namespace_epoch: Set(fence.namespace_epoch as i64),
                routing_epoch: Set(fence.routing_epoch as i64),
                bucket: Set("bucket".to_string()),
                prefix: Set(String::new()),
                delimiter: Set(None),
                list_version: Set("V2".to_string()),
                last_key: Set(None),
                last_common_prefix: Set(None),
                response_state: Set(oversized_bytes.clone()),
                response_state_bytes: Set(oversized_bytes.len() as i64),
                final_page: Set(false),
                state: Set("ACTIVE".to_string()),
                created_at_ms: Set(now),
                expires_at_ms: Set(now + 60_000),
                first_used_at_ms: Set(None),
            })
            .exec(&db)
            .await
            .is_err(),
            "database cursor payload cap must reject direct oversized inserts"
        );
        let used = repository
            .use_list_cursor(cursor.id, &binding, now + 1)
            .await
            .unwrap();
        let replay = repository
            .use_list_cursor(cursor.id, &binding, now + 2)
            .await
            .unwrap();
        assert_eq!(used.state, ManagedListCursorState::Used);
        assert_eq!(replay.first_used_at_ms, used.first_used_at_ms);
        assert_eq!(replay.response_state, used.response_state);
        repository
            .advance_routing_epoch(&tenant, fence.routing_epoch)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .use_list_cursor(cursor.id, &binding, now + 3)
                .await,
            Err(s4_gateway::managed::ManagedError::CursorExpired)
        ));

        let versions = repository
            .physical_versions(
                &tenant,
                &intent.backend_id,
                &intent.provider_bucket,
                &intent.physical_key,
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        let (first_delete, second_delete) = tokio::join!(
            repository.forget_physical_version(&versions[0]),
            repository.forget_physical_version(&versions[1]),
        );
        first_delete.unwrap();
        second_delete.unwrap();
        assert_eq!(
            repository
                .workspace_usage(&tenant)
                .await
                .unwrap()
                .unwrap()
                .physical_allocated_bytes,
            0
        );
        assert_eq!(
            repository
                .logical_operation(intent.operation_id)
                .await
                .unwrap()
                .unwrap()
                .released_physical_bytes,
            6
        );

        managed_list_cursor::Entity::delete_many()
            .filter(managed_list_cursor::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_workspace_usage::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_managed_zero_byte_put_is_ledgered_and_committed() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("managed-zero-unit-{}", uuid::Uuid::new_v4());
        let logical = LogicalObjectKey::new(&tenant, "bucket", "empty");
        let generation = uuid::Uuid::now_v7();
        let fence = repository.route_fence(&tenant).await.unwrap();
        let intent = ManagedLogicalOperationIntent {
            operation_id: uuid::Uuid::now_v7(),
            receipt_id: uuid::Uuid::now_v7(),
            logical: logical.clone(),
            kind: ManagedMutationKind::Put,
            generation,
            fence,
            expected_authority_cas: None,
            prior_logical_size: 0,
            primary_child_operation_id: uuid::Uuid::now_v7(),
            backend_id: "primary".to_string(),
            provider_bucket: "provider-bucket".to_string(),
            physical_key: generation_physical_key(&logical, generation),
            occurred_at_ms: unix_time_ms(),
            rate_version: 1,
            route: UsageRoute::PutObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: 0,
        };
        repository
            .insert_logical_operation(intent.clone())
            .await
            .unwrap();
        let usage = repository
            .reserve_logical_operation(intent.operation_id, 0)
            .await
            .unwrap();
        assert_eq!(usage.active_operation_id, Some(intent.operation_id));
        let mut child = test_physical_intent(
            intent.primary_child_operation_id,
            &tenant,
            &intent.backend_id,
            &intent.provider_bucket,
            &intent.physical_key,
            "zero-byte-writer",
        );
        child.versioning_capability = BackendVersioningCapability::Required;
        let lease = repository.begin_physical_write(child).await.unwrap();
        repository
            .commit_physical_write(&lease, &[], Some("empty-version"))
            .await
            .unwrap();
        repository
            .record_logical_usage(
                intent.operation_id,
                ManagedUsageEvidence {
                    expected_output_digest: Some("empty-digest".to_string()),
                    expected_output_size: 0,
                    source_bytes: 0,
                    processed_bytes: 0,
                    payload: serde_json::json!({"zero_byte": true}),
                },
            )
            .await
            .unwrap();
        repository
            .transition_logical_operation(
                intent.operation_id,
                ManagedLogicalOperationState::Open,
                ManagedLogicalOperationState::Completing,
                None,
            )
            .await
            .unwrap();
        let committed = repository
            .commit_logical_put(
                intent.operation_id,
                ObjectAuthority {
                    logical,
                    generation,
                    digest: "empty-digest".to_string(),
                    size: 0,
                    metadata: std::collections::BTreeMap::new(),
                    placement_version: 1,
                    primary_backend_id: intent.backend_id.clone(),
                    primary_version_id: Some("empty-version".to_string()),
                    replica_backend_id: None,
                    primary_status: CopyStatus::Ready,
                    replica_status: CopyStatus::Absent,
                    tombstone: false,
                    cas_version: 0,
                    created_at_ms: 0,
                    updated_at_ms: 0,
                },
                0,
            )
            .await
            .unwrap();
        assert_eq!(committed.operation.committed_physical_bytes, 0);
        assert_eq!(committed.usage.visible_logical_bytes, 0);
        assert_eq!(committed.usage.physical_allocated_bytes, 0);
        assert_eq!(
            managed_physical_object_version::Entity::find()
                .filter(managed_physical_object_version::Column::TenantId.eq(&tenant))
                .count(&db)
                .await
                .unwrap(),
            1
        );

        managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_workspace_usage::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_proven_abort_rejects_under_counted_physical_allocation() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("managed-abort-unit-{}", uuid::Uuid::new_v4());
        let logical = LogicalObjectKey::new(&tenant, "bucket", "aborted");
        let generation = uuid::Uuid::now_v7();
        let intent = ManagedLogicalOperationIntent {
            operation_id: uuid::Uuid::now_v7(),
            receipt_id: uuid::Uuid::now_v7(),
            logical: logical.clone(),
            kind: ManagedMutationKind::Put,
            generation,
            fence: repository.route_fence(&tenant).await.unwrap(),
            expected_authority_cas: None,
            prior_logical_size: 0,
            primary_child_operation_id: uuid::Uuid::now_v7(),
            backend_id: "primary".to_string(),
            provider_bucket: "provider-bucket".to_string(),
            physical_key: generation_physical_key(&logical, generation),
            occurred_at_ms: unix_time_ms(),
            rate_version: 1,
            route: UsageRoute::PutObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: 3,
        };
        repository
            .insert_logical_operation(intent.clone())
            .await
            .unwrap();
        repository
            .reserve_logical_operation(intent.operation_id, 6)
            .await
            .unwrap();
        let lease = repository
            .begin_physical_write(test_physical_intent(
                intent.primary_child_operation_id,
                &tenant,
                &intent.backend_id,
                &intent.provider_bucket,
                &intent.physical_key,
                "abort-writer",
            ))
            .await
            .unwrap();
        repository
            .commit_physical_write(
                &lease,
                &["retry-version".to_string(), "retry-version".to_string()],
                Some("final-version"),
            )
            .await
            .unwrap();
        repository
            .record_logical_usage(
                intent.operation_id,
                ManagedUsageEvidence {
                    expected_output_digest: Some("digest".to_string()),
                    expected_output_size: 3,
                    source_bytes: 3,
                    processed_bytes: 3,
                    payload: serde_json::json!({}),
                },
            )
            .await
            .unwrap();
        repository
            .transition_logical_operation(
                intent.operation_id,
                ManagedLogicalOperationState::Open,
                ManagedLogicalOperationState::Completing,
                None,
            )
            .await
            .unwrap();
        let authority = ObjectAuthority {
            logical,
            generation,
            digest: "digest".to_string(),
            size: 3,
            metadata: std::collections::BTreeMap::new(),
            placement_version: 1,
            primary_backend_id: intent.backend_id.clone(),
            primary_version_id: Some("final-version".to_string()),
            replica_backend_id: None,
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::Absent,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        assert!(matches!(
            repository
                .prove_logical_abort(
                    intent.operation_id,
                    "publication_failed",
                    Some(ManagedProvenPhysicalAllocation {
                        authority: authority.clone(),
                        allocated_bytes: 3,
                    }),
                )
                .await,
            Err(s4_gateway::managed::ManagedError::Conflict)
        ));
        let aborted = repository
            .prove_logical_abort(
                intent.operation_id,
                "publication_failed",
                Some(ManagedProvenPhysicalAllocation {
                    authority,
                    allocated_bytes: 6,
                }),
            )
            .await
            .unwrap();
        assert_eq!(aborted.committed_physical_bytes, 6);
        assert_eq!(
            repository
                .workspace_usage(&tenant)
                .await
                .unwrap()
                .unwrap()
                .physical_allocated_bytes,
            6
        );
        let versions = repository
            .physical_versions(
                &tenant,
                &intent.backend_id,
                &intent.provider_bucket,
                &intent.physical_key,
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        for version in versions {
            repository.forget_physical_version(&version).await.unwrap();
        }
        assert_eq!(
            repository
                .workspace_usage(&tenant)
                .await
                .unwrap()
                .unwrap()
                .physical_allocated_bytes,
            0
        );

        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_workspace_usage::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_managed_quota_and_cursor_limits_hold_under_concurrency() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = Arc::new(PostgresManagedRepository::new(pool));
        let quota_tenant = format!("managed-quota-race-{}", uuid::Uuid::new_v4());
        let fence = repository.route_fence(&quota_tenant).await.unwrap();
        let make_intent = |key: &str| {
            let logical = LogicalObjectKey::new(&quota_tenant, "bucket", key);
            let generation = uuid::Uuid::now_v7();
            ManagedLogicalOperationIntent {
                operation_id: uuid::Uuid::now_v7(),
                receipt_id: uuid::Uuid::now_v7(),
                logical: logical.clone(),
                kind: ManagedMutationKind::Put,
                generation,
                fence,
                expected_authority_cas: None,
                prior_logical_size: 0,
                primary_child_operation_id: uuid::Uuid::now_v7(),
                backend_id: "primary".to_string(),
                provider_bucket: "provider-bucket".to_string(),
                physical_key: generation_physical_key(&logical, generation),
                occurred_at_ms: unix_time_ms(),
                rate_version: 1,
                route: UsageRoute::PutObject,
                request_kind: RequestKind::Write,
                max_processed_bytes: 1,
            }
        };
        let first_intent = make_intent("first");
        let second_intent = make_intent("second");
        repository
            .insert_logical_operation(first_intent.clone())
            .await
            .unwrap();
        repository
            .insert_logical_operation(second_intent.clone())
            .await
            .unwrap();
        let (first_reservation, second_reservation) = tokio::join!(
            repository.reserve_logical_operation(first_intent.operation_id, 1),
            repository.reserve_logical_operation(second_intent.operation_id, 1),
        );
        assert_eq!(
            usize::from(first_reservation.is_ok()) + usize::from(second_reservation.is_ok()),
            1
        );
        let winner = first_reservation
            .ok()
            .or_else(|| second_reservation.ok())
            .and_then(|usage| usage.active_operation_id)
            .unwrap();
        let loser = if winner == first_intent.operation_id {
            second_intent.operation_id
        } else {
            first_intent.operation_id
        };
        repository
            .prove_logical_abort(winner, "race_cleanup", None)
            .await
            .unwrap();
        repository
            .prove_logical_abort(loser, "race_cleanup", None)
            .await
            .unwrap();

        let cursor_tenant = format!("managed-cursor-race-{}", uuid::Uuid::new_v4());
        let binding = ManagedListCursorBinding {
            tenant_id: cursor_tenant.clone(),
            bucket: "bucket".to_string(),
            prefix: String::new(),
            delimiter: None,
            version: ManagedListVersion::V2,
        };
        let request = ManagedListCursorRequest {
            binding: binding.clone(),
            position: ManagedListCursorPosition {
                last_key: None,
                last_common_prefix: None,
            },
            response_state: serde_json::json!({}),
            final_page: false,
        };
        let now = unix_time_ms();
        for _ in 0..MANAGED_LIST_CURSOR_WORKSPACE_LIMIT - 1 {
            repository
                .create_list_cursor(request.clone(), now)
                .await
                .unwrap();
        }
        let (first_cursor, second_cursor) = tokio::join!(
            repository.create_list_cursor(request.clone(), now),
            repository.create_list_cursor(request, now),
        );
        assert_eq!(
            usize::from(first_cursor.is_ok()) + usize::from(second_cursor.is_ok()),
            1,
            "serializable cursor creation must admit only the final available slot"
        );
        assert_eq!(
            managed_list_cursor::Entity::find()
                .filter(managed_list_cursor::Column::TenantId.eq(&cursor_tenant))
                .count(&db)
                .await
                .unwrap(),
            MANAGED_LIST_CURSOR_WORKSPACE_LIMIT
        );

        managed_list_cursor::Entity::delete_many()
            .filter(managed_list_cursor::Column::TenantId.eq(&cursor_tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&cursor_tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_workspace_usage::Entity::delete_by_id(&quota_tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&quota_tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&quota_tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_v1_secret_is_rewrapped_to_identity_bound_v2() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let cipher = Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            TEST_KEK,
        ))));
        let store = PostgresKeyStore::with_cipher(pool, cipher.clone());
        let user = format!("unit-v1-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(&user, "legacy-rewrap", 0, None)
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id;
        let legacy = v1_envelope(&secret);
        update_secret_state(&db, &key_id, None, &legacy).await;

        assert_eq!(
            store.decrypt_secret(&key_id).await.unwrap().as_deref(),
            Some(secret.as_str())
        );

        let persisted = fetch_api_key(&db, &key_id).await;
        let rewrapped = persisted.secret_encrypted.expect("rewrapped envelope");
        assert!(rewrapped.starts_with("v2:"));
        assert_ne!(rewrapped, legacy);
        assert_eq!(
            cipher.decrypt(&key_id, &rewrapped).as_deref(),
            Some(secret.as_str())
        );
        assert_eq!(cipher.decrypt("different-key-id", &rewrapped), None);
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_v1_hash_mismatch_returns_none_without_rewrap() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let cipher = Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            TEST_KEK,
        ))));
        let store = PostgresKeyStore::with_cipher(pool, cipher);
        let user = format!("unit-v1-hash-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(&user, "legacy-hash-mismatch", 0, None)
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id;
        let legacy = v1_envelope(&secret);
        let mismatched_hash = sha256_hash("different-secret");
        update_secret_state(&db, &key_id, Some(&mismatched_hash), &legacy).await;

        assert_eq!(store.decrypt_secret(&key_id).await.unwrap(), None);

        let persisted = fetch_api_key(&db, &key_id).await;
        assert_eq!(persisted.secret_hash, mismatched_hash);
        assert_eq!(persisted.secret_encrypted.as_deref(), Some(legacy.as_str()));
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_v1_rewrap_cas_accepts_concurrent_matching_v2() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let initial_store = PostgresKeyStore::new(pool.clone());
        let user = format!("unit-v1-cas-{}", uuid::Uuid::new_v4());
        let (secret, created) = initial_store
            .create_key(&user, "legacy-cas", 0, None)
            .await
            .expect("create hash-only Postgres API key");
        let key_id = created.key_id;
        let legacy = v1_envelope(&secret);
        update_secret_state(&db, &key_id, None, &legacy).await;

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let blocking_cipher = Arc::new(SecretCipher::new(Arc::new(BlockingWrapping {
            inner: LocalKeyWrapping::with_kek(TEST_KEK),
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
        })));
        let decrypt_store = PostgresKeyStore::with_cipher(pool, blocking_cipher);
        let decrypt_key_id = key_id.clone();
        // Run the racing database operation on this test's Tokio runtime. A
        // short-lived second runtime can strand SQLx pool connections when it
        // shuts down, starving the fixture cleanup below in CI.
        let runtime = tokio::runtime::Handle::current();
        let decrypt = tokio::task::spawn_blocking(move || {
            runtime.block_on(decrypt_store.decrypt_secret(&decrypt_key_id))
        });

        tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .expect("join rewrap signal waiter")
            .expect("legacy rewrap reached conditional update window");
        let winner_cipher = SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)));
        let winner = winner_cipher
            .encrypt(&key_id, &secret)
            .expect("create concurrent v2 winner");
        update_secret_state(&db, &key_id, None, &winner).await;
        release_tx.send(()).expect("release legacy rewrap");

        assert_eq!(
            decrypt
                .await
                .expect("join legacy decrypt")
                .unwrap()
                .as_deref(),
            Some(secret.as_str())
        );
        let persisted = fetch_api_key(&db, &key_id).await;
        assert_eq!(persisted.secret_encrypted.as_deref(), Some(winner.as_str()));
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_key_roundtrip() {
    with_pool(|pool| async move {
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(&user, "roundtrip", 0, None)
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id.clone();
        let persisted = store
            .get_key(&key_id)
            .await
            .expect("read persisted key")
            .expect("persisted key");
        assert_eq!(created, persisted);
        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .unwrap()
            .expect("valid credentials resolve");
        assert_eq!(uid, user);
        assert!(pk.is_none());
        assert!(
            store
                .resolve_credentials(&key_id, "wrong-secret")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .resolve_credentials("missing-key", &secret)
                .await
                .unwrap()
                .is_none()
        );

        let keys = store.list_for_user(&user).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].secret_hash.is_empty(), "list must strip the hash");
        assert_eq!(keys[0].label, "roundtrip");

        assert!(store.delete_key(&key_id, &user).await.unwrap());
        assert!(!store.delete_key(&key_id, &user).await.unwrap());
        assert!(store.get_key(&key_id).await.unwrap().is_none());
    });
}

#[test]
fn postgres_public_key_binding() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(&user, "enc", 0, None)
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id;
        assert!(
            store
                .set_public_key(&key_id, &user, TEST_PUBLIC_KEY_PEM)
                .await
                .unwrap()
        );
        assert!(
            !store
                .set_public_key(&key_id, "someone-else", TEST_CERTIFICATE_PEM)
                .await
                .unwrap()
        );

        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .unwrap()
            .expect("resolve after binding");
        assert_eq!(uid, user);
        assert_eq!(pk.as_deref(), Some(TEST_PUBLIC_KEY_PEM.trim()));
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_expired_key_rejected() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (secret, created) = store
            .create_key(&user, "exp", 1, None)
            .await
            .expect("create Postgres API key");
        let key_id = created.key_id;
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            store
                .resolve_credentials(&key_id, &secret)
                .await
                .unwrap()
                .is_none(),
            "expired key must be rejected"
        );
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_mcp_creation_returns_persisted_metadata() {
    with_pool(|pool| async move {
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (token, created) = store
            .create_mcp_token(&user, "  agent  ", 3600)
            .await
            .expect("create Postgres MCP token");
        let listed = store
            .list_mcp_tokens(&user)
            .await
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.token_hash == created.token_hash)
            .expect("persisted MCP token is listed");

        assert!(token.starts_with("s4m_"));
        assert_eq!(created, listed);
        assert_eq!(created.label, "agent");
        assert!(created.expires_at.is_some());
        assert!(
            store
                .delete_mcp_token(&created.token_hash, &user)
                .await
                .unwrap()
        );
    });
}

fn auth_headers(ak: &str, sk: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-s4-access-key", ak.to_string()),
        ("x-s4-secret-key", sk.to_string()),
    ]
}

fn add_headers(req: Request<Body>, hdrs: &[(&'static str, String)]) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    for (name, value) in hdrs {
        parts.headers.insert(*name, value.parse().unwrap());
    }
    Request::from_parts(parts, body)
}

fn extract_xml(xml: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    xml.split(&open)
        .nth(1)
        .and_then(|rest| rest.split(&close).next())
        .unwrap_or_default()
        .to_string()
}

type MockObjects = Arc<tokio::sync::Mutex<HashMap<String, Vec<u8>>>>;

#[derive(Clone, Default)]
struct MockS3State {
    objects: MockObjects,
    block_destination_put: Arc<AtomicBool>,
    destination_put_count: Arc<AtomicUsize>,
    destination_put_started: Arc<tokio::sync::Notify>,
    release_destination_put: Arc<tokio::sync::Notify>,
    omit_destination_head_length: Arc<AtomicBool>,
    fail_destination_delete: Arc<AtomicBool>,
}

impl MockS3State {
    async fn wait_for_destination_put_after(&self, previous: usize) {
        loop {
            let notified = self.destination_put_started.notified();
            if self.destination_put_count.load(Ordering::Acquire) > previous {
                return;
            }
            notified.await;
        }
    }
}

struct UnknownSizeEmptyBody;

impl http_body::Body for UnknownSizeEmptyBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }
}

const MOCK_STAGING_BUCKET: &str = "staging-bucket";

/// Decodes the SigV4 streaming (`aws-chunked`) framing the SDK applies to a
/// non-replayable PutObject body. Frames are `<hex-size>;chunk-signature=...`
/// headers followed by the raw chunk bytes; a zero-size chunk ends the body.
fn decode_aws_chunked(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let line_end = data[pos..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| pos + index)
            .unwrap_or(data.len());
        let line = &data[pos..line_end];
        let size_str = line.split(|byte| *byte == b';').next().unwrap_or(b"");
        let size =
            usize::from_str_radix(std::str::from_utf8(size_str).unwrap_or_default().trim(), 16)
                .unwrap_or(0);
        pos = line_end.saturating_add(2);
        if size == 0 || pos.saturating_add(size) > data.len() {
            break;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size;
        if data.get(pos..pos + 2) == Some(b"\r\n") {
            pos += 2;
        }
    }
    out
}

/// Minimal S3-compatible object store backing `S3StagingArtifactStore`. The
/// staging store only needs PutObject/GetObject/DeleteObject/ListObjectsV2,
/// and the AWS SDK addresses a custom endpoint path-style (`/{bucket}/{key}`).
async fn mock_s3_handler(
    State(state): State<MockS3State>,
    request: Request<Body>,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().trim_start_matches('/').to_string();
    let query = parts.uri.query().unwrap_or_default().to_string();

    if parts.method == Method::GET && query.contains("list-type=2") {
        let prefix = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("prefix="))
            .unwrap_or_default()
            .replace("%2F", "/");
        let objects = state.objects.lock().await;
        let mut keys: Vec<String> = objects
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect();
        keys.sort();
        let mut xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{MOCK_STAGING_BUCKET}</Name><Prefix>{prefix}</Prefix><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"#,
            keys.len()
        );
        for object_key in keys {
            xml.push_str(&format!(
                "<Contents><Key>{object_key}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>{}</Size></Contents>",
                objects.get(&object_key).map_or(0, Vec::len)
            ));
        }
        xml.push_str("</ListBucketResult>");
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(xml))
            .unwrap();
    }

    let key = path
        .strip_prefix(&format!("{MOCK_STAGING_BUCKET}/"))
        .map(str::to_owned)
        .unwrap_or_else(|| path.clone());

    match parts.method {
        Method::PUT => {
            if !path.starts_with(&format!("{MOCK_STAGING_BUCKET}/"))
                && state.block_destination_put.load(Ordering::Acquire)
            {
                state.destination_put_count.fetch_add(1, Ordering::AcqRel);
                state.destination_put_started.notify_waiters();
                while state.block_destination_put.load(Ordering::Acquire) {
                    let released = state.release_destination_put.notified();
                    if !state.block_destination_put.load(Ordering::Acquire) {
                        break;
                    }
                    released.await;
                }
            }
            let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
                .await
                .unwrap_or_default();
            let decoded = if parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("aws-chunked"))
            {
                decode_aws_chunked(&bytes)
            } else {
                bytes.to_vec()
            };
            state.objects.lock().await.insert(key, decoded);
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(header::ETAG, "\"mock-etag\"")
                .body(Body::empty())
                .unwrap()
        }
        Method::GET => {
            let objects = state.objects.lock().await;
            match objects.get(&key) {
                Some(bytes) => axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, bytes.len().to_string())
                    .body(Body::from(bytes.clone()))
                    .unwrap(),
                None => axum::response::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap(),
            }
        }
        Method::HEAD => {
            let objects = state.objects.lock().await;
            match objects.get(&key) {
                Some(bytes) => {
                    let mut response = axum::response::Response::builder()
                        .status(StatusCode::OK)
                        .header(header::ETAG, "\"mock-etag\"");
                    if !state.omit_destination_head_length.load(Ordering::Acquire) {
                        response = response.header(header::CONTENT_LENGTH, bytes.len().to_string());
                    }
                    response.body(Body::new(UnknownSizeEmptyBody)).unwrap()
                }
                None => axum::response::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap(),
            }
        }
        Method::DELETE => {
            if !path.starts_with(&format!("{MOCK_STAGING_BUCKET}/"))
                && state.fail_destination_delete.load(Ordering::Acquire)
            {
                return axum::response::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap();
            }
            state.objects.lock().await.remove(&key);
            axum::response::Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        _ => axum::response::Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .unwrap(),
    }
}

async fn upload_part(
    app: &axum::Router,
    hdrs: &[(&'static str, String)],
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    body: &[u8],
) -> String {
    let req = add_headers(
        Request::builder()
            .method("PUT")
            .uri(format!(
                "/{bucket}/{key}?partNumber={part_number}&uploadId={upload_id}"
            ))
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body.to_vec()))
            .unwrap(),
        hdrs,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "UploadPart {part_number}");
    resp.headers()
        .get(header::ETAG)
        .expect("UploadPart ETag")
        .to_str()
        .unwrap()
        .to_string()
}

async fn state_assertions_for_unknown_head_and_ambiguous_delete(
    app: &axum::Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    key: &str,
    mock_state: &MockS3State,
    control: &MultipartBillingControl,
) {
    let releases_before = control.releases.lock().unwrap().len();
    mock_state
        .omit_destination_head_length
        .store(true, Ordering::Release);
    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri(format!("/{bucket}/{key}"))
            .body(Body::empty())
            .unwrap(),
        headers,
    );
    let response = app.clone().oneshot(head).await.unwrap();
    mock_state
        .omit_destination_head_length
        .store(false, Ordering::Release);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let head_operation = control
        .authorizations
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .1
        .operation_id();
    assert_eq!(control.releases.lock().unwrap().len(), releases_before + 1);
    assert_eq!(
        control.releases.lock().unwrap().last().unwrap().1,
        head_operation
    );

    mock_state
        .fail_destination_delete
        .store(true, Ordering::Release);
    let delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri(format!("/{bucket}/{key}"))
            .body(Body::empty())
            .unwrap(),
        headers,
    );
    let response = app.clone().oneshot(delete).await.unwrap();
    mock_state
        .fail_destination_delete
        .store(false, Ordering::Release);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let delete_authorization = control
        .authorizations
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .1
        .clone();
    assert_eq!(delete_authorization.route(), UsageRoute::DeleteObject);
    assert_eq!(control.releases.lock().unwrap().len(), releases_before + 1);
    assert!(
        control
            .releases
            .lock()
            .unwrap()
            .iter()
            .all(|(_, operation_id)| *operation_id != delete_authorization.operation_id())
    );
}

/// Drives the full S3 multipart HTTP surface through `build_router` against a
/// durable Postgres repository and a mock S3 service used for both encrypted
/// staging and the direct destination. Runs only when `DATABASE_URL` is set.
#[test]
fn router_staged_multipart_flow_is_durable_and_idempotent() {
    with_pool(|pool| async move {
        let staging_dir =
            std::env::temp_dir().join(format!("s4-multipart-staging-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&staging_dir).await.unwrap();

        let mock_state = MockS3State::default();
        let objects = mock_state.objects.clone();
        let mock_app = axum::Router::new()
            .fallback(mock_s3_handler)
            .with_state(mock_state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mock_task = tokio::spawn(async move {
            let _ = axum::serve(listener, mock_app).await;
        });

        // SAFETY: test-only process-global env mutation. Every test in this
        // binary is serialized on `DB_TEST_LOCK`, so no other test observes
        // these values concurrently.
        unsafe {
            std::env::set_var("AUTH_DISABLED", "0");
            std::env::set_var("S4_SINGLE_TENANT", "1");
            std::env::remove_var("S4_KEYS_FILE");
            std::env::set_var("S3_ENDPOINT", &endpoint);
            std::env::set_var("S3_ACCESS_KEY_ID", "destination-access");
            std::env::set_var("S3_SECRET_ACCESS_KEY", "destination-secret");
            std::env::remove_var("S4_SERVICE_BUCKETS");
            std::env::remove_var("S4_SECRET_KEK");
            std::env::set_var("S4_STREAMING_S3_PROVIDER", "minio");
            std::env::remove_var("S4_PLUGINS_DIR");
            std::env::remove_var("S4_FILTER_COMPONENT");
            std::env::remove_var("S4_MANAGED_STREAMING_MODE");
            std::env::remove_var("S4_MANAGED_STREAMING_TRANSACTIONAL");
            std::env::set_var("S4_STREAMING_WRITE_MODE", "all");
            std::env::set_var("S4_STREAMING_READ_MODE", "passthrough");
            std::env::set_var("S4_DEV_MEMORY_STREAMING", "1");
            std::env::set_var("S4_MULTIPART_MODE", "staged");
            std::env::set_var("S4_MULTIPART_STAGING_DIR", staging_dir.to_str().unwrap());
            std::env::set_var("S4_MULTIPART_STAGING_ENDPOINT", &endpoint);
            std::env::set_var("S4_MULTIPART_STAGING_BUCKET", MOCK_STAGING_BUCKET);
            std::env::set_var("S4_MULTIPART_STAGING_ACCESS_KEY_ID", "test-access");
            std::env::set_var("S4_MULTIPART_STAGING_SECRET_ACCESS_KEY", "test-secret");
            std::env::set_var("S4_MULTIPART_STAGING_REGION", "us-east-1");
            std::env::set_var("S4_MULTIPART_STAGING_TENANT_QUOTA_BYTES", "67108864");
            std::env::set_var("S4_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES", "268435456");
        }

        let control = Arc::new(MultipartBillingControl::default());
        let state = build_state(
            control.clone(),
            Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)),
            Arc::new(s4_gateway::workspace_storage::InMemoryWorkspaceStorageRepository::new()),
        )
        .await
        .expect("build_state with durable staged multipart");
        let (sk, created) = state
            .keys
            .create_key("test-user", "multipart-test", 0, None)
            .await
            .expect("create test API key");
        let ak = created.key_id;
        let app = build_router(state.clone());
        let hdrs = auth_headers(&ak, &sk);

        let bucket = format!("mp-bkt-{}", uuid::Uuid::new_v4());
        let key = format!("object-{}.txt", uuid::Uuid::new_v4());

        // CreateMultipartUpload.
        let create = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploads"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(create).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "CreateMultipartUpload");
        let create_xml = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let upload_id = extract_xml(&create_xml, "UploadId");
        assert!(!upload_id.is_empty());

        // UploadPart part 2 first, then part 1: assembly must still follow
        // part-number order, not upload order.
        let part1_body: &[u8] = b"first line: alice@example.com\n";
        let part2_body: &[u8] = b"second line: card 4111111111111111\n";
        let etag2 = upload_part(&app, &hdrs, &bucket, &key, &upload_id, 2, part2_body).await;
        let etag1 = upload_part(&app, &hdrs, &bucket, &key, &upload_id, 1, part1_body).await;

        // ListParts.
        let list = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(list).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "ListParts");
        let list_xml = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            list_xml.contains("<PartNumber>1</PartNumber>"),
            "{list_xml}"
        );
        assert!(
            list_xml.contains("<PartNumber>2</PartNumber>"),
            "{list_xml}"
        );

        // Rebuild a fully independent gateway process against the same
        // Postgres and staging backend. Completion must use the persisted
        // immutable resolution rather than process-local plugin identities.
        let restarted_state = build_state(
            control.clone(),
            Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)),
            Arc::new(s4_gateway::workspace_storage::InMemoryWorkspaceStorageRepository::new()),
        )
        .await
        .expect("restart gateway with durable staged multipart");
        let restarted_app = build_router(restarted_state);

        // CompleteMultipartUpload with the strict sorted XML document.
        let complete_xml = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part></CompleteMultipartUpload>"
        );
        let complete = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::from(complete_xml.clone()))
                .unwrap(),
            &hdrs,
        );
        mock_state
            .block_destination_put
            .store(true, Ordering::Release);
        let destination_puts_before = mock_state.destination_put_count.load(Ordering::Acquire);
        let first_completion = tokio::spawn(restarted_app.clone().oneshot(complete));
        tokio::time::timeout(
            Duration::from_secs(5),
            mock_state.wait_for_destination_put_after(destination_puts_before),
        )
        .await
        .expect("first completion reached the direct destination");
        let busy = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::from(complete_xml.clone()))
                .unwrap(),
            &hdrs,
        );
        let busy_response = restarted_app.clone().oneshot(busy).await.unwrap();
        assert_eq!(
            busy_response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "concurrent exact completion must observe Busy"
        );
        assert!(
            control.releases.lock().unwrap().is_empty(),
            "Busy must not release the active worker's reservation"
        );
        mock_state
            .block_destination_put
            .store(false, Ordering::Release);
        mock_state.release_destination_put.notify_waiters();
        let resp = first_completion.await.unwrap().unwrap();
        let status = resp.status();
        let complete_body = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "CompleteMultipartUpload: {complete_body}"
        );
        let final_etag = extract_xml(&complete_body, "ETag");
        assert!(!final_etag.is_empty());

        // GET the assembled object: PII redacted and parts in part-number order.
        let get = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/{bucket}/{key}"))
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(get).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET assembled object");
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("[REDACTED_EMAIL]"), "email redacted: {text}");
        assert!(text.contains("[REDACTED_CARD]"), "card redacted: {text}");
        assert!(
            !text.contains("alice@example.com"),
            "raw email leaked: {text}"
        );
        assert!(
            !text.contains("4111111111111111"),
            "raw card leaked: {text}"
        );
        let first = text.find("first line:").expect("first line present");
        let second = text.find("second line:").expect("second line present");
        assert!(
            first < second,
            "parts assembled in part-number order: {text}"
        );

        // Re-POSTing the same complete XML replays the stored result.
        let replay = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::from(complete_xml))
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(replay).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "idempotent completion replay"
        );
        let replay_body = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(extract_xml(&replay_body, "ETag"), final_etag);

        // A conflicting part set is rejected.
        let conflicting = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part></CompleteMultipartUpload>"
        );
        let conflict_req = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::from(conflicting))
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(conflict_req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "conflicting completion"
        );
        let completion_authorizations: Vec<_> = control
            .authorizations
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, authorization)| {
                authorization.route() == UsageRoute::CompleteMultipartUpload
            })
            .cloned()
            .collect();
        let completion_events: Vec<_> = control
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| event.route() == UsageRoute::CompleteMultipartUpload)
            .cloned()
            .collect();
        assert_eq!(completion_authorizations.len(), 4);
        assert_eq!(completion_events.len(), 2);
        assert_eq!(completion_authorizations[0], completion_authorizations[1]);
        assert_eq!(completion_authorizations[0], completion_authorizations[2]);
        assert_eq!(completion_events[0], completion_events[1]);
        assert_eq!(
            completion_authorizations[0].1.operation_id(),
            completion_events[0].1.operation_id()
        );
        let journal_operation =
            object_operation::Entity::find_by_id(completion_authorizations[0].1.operation_id())
                .one(&sea_db(pool.clone()))
                .await
                .unwrap()
                .expect("direct completion journal row");
        assert_eq!(journal_operation.tenant_id.as_deref(), Some("test-user"));
        assert_eq!(journal_operation.namespace_epoch, None);
        assert_eq!(journal_operation.state, OperationState::Committed.as_str());
        assert_ne!(
            completion_authorizations[0].1.operation_id(),
            completion_authorizations[3].1.operation_id()
        );
        assert_eq!(
            control.releases.lock().unwrap().as_slice(),
            &[(
                completion_authorizations[3].0.clone(),
                completion_authorizations[3].1.operation_id()
            )]
        );

        state_assertions_for_unknown_head_and_ambiguous_delete(
            &app,
            &hdrs,
            &bucket,
            &key,
            &mock_state,
            &control,
        )
        .await;

        // Abort is idempotent and removes the staged artifacts.
        let abort_key = format!("abort-{}.txt", uuid::Uuid::new_v4());
        let create = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{abort_key}?uploads"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(create).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "abort CreateMultipartUpload");
        let create_xml = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let abort_upload_id = extract_xml(&create_xml, "UploadId");
        upload_part(
            &app,
            &hdrs,
            &bucket,
            &abort_key,
            &abort_upload_id,
            1,
            b"abort me: bob@example.com\n",
        )
        .await;
        assert!(
            !objects.lock().await.is_empty(),
            "staged artifact exists before abort"
        );

        let releases_before_abort = control.releases.lock().unwrap().len();
        PostgresMultipartRepository::fail_next_abort_after_update();
        let ambiguous_abort = add_headers(
            Request::builder()
                .method("DELETE")
                .uri(format!("/{bucket}/{abort_key}?uploadId={abort_upload_id}"))
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let response = app.clone().oneshot(ambiguous_abort).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let abort_authorization = control
            .authorizations
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .1
            .clone();
        assert_eq!(
            abort_authorization.route(),
            UsageRoute::AbortMultipartUpload
        );
        assert_eq!(
            control.releases.lock().unwrap().len(),
            releases_before_abort,
            "post-mutation abort failure must preserve its reservation"
        );
        assert!(
            control
                .releases
                .lock()
                .unwrap()
                .iter()
                .all(|(_, operation_id)| *operation_id != abort_authorization.operation_id())
        );

        for _ in 0..2 {
            let abort = add_headers(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{bucket}/{abort_key}?uploadId={abort_upload_id}"))
                    .body(Body::empty())
                    .unwrap(),
                &hdrs,
            );
            let resp = app.clone().oneshot(abort).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NO_CONTENT,
                "AbortMultipartUpload"
            );
        }
        assert!(
            objects
                .lock()
                .await
                .keys()
                .any(|key| !key.starts_with(ARTIFACT_PREFIX)),
            "completed destination remains visible after abort reconciliation"
        );

        mock_task.abort();
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
    });
}
