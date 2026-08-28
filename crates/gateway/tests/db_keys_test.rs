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
use s4_gateway::entity::managed_namespace;
use s4_gateway::entity::managed_namespace_purge;
use s4_gateway::entity::managed_object_authority;
use s4_gateway::entity::managed_object_repair;
use s4_gateway::entity::managed_physical_object_version;
use s4_gateway::entity::multipart_upload;
use s4_gateway::entity::object_operation;
use s4_gateway::key_cipher::{KeyWrapping, LocalKeyWrapping, SecretCipher};
use s4_gateway::managed::{
    CopyStatus, LogicalObjectKey, ManagedRepository, NamespacePurgeRequest, NamespacePurgeStatus,
    ObjectAuthority, PhysicalWriteIntent, Placement, PostgresManagedRepository,
};
use s4_gateway::multipart_staging::{
    CompletePart, CompletionAcquire, MultipartCompletionResult, MultipartIdentity,
    MultipartLifecycle, MultipartPart, MultipartRepository, MultipartSnapshot, MultipartUpload,
    PostgresMultipartRepository,
};
use s4_gateway::store::{KeyRepository, PostgresKeyStore, sha256_hash};
use s4_gateway::transaction::{
    EvidenceRecord, ExpectedObject, ObjectDestination, OperationJournal, OperationRecord,
    OperationState, PartRecord, PostgresOperationJournal, StoredObjectMeta,
};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, SqlxPostgresConnector};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, header};
use s4_gateway::control::NoopControlPlane;
use s4_gateway::server::{build_router, build_state};
use tower::ServiceExt;

const TEST_KEK: [u8; 32] = [7; 32];
static DB_TEST_LOCK: Mutex<()> = Mutex::new(());

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

async fn ledger_managed_test_version(
    repository: &PostgresManagedRepository,
    tenant_id: &str,
    backend_id: &str,
    physical_key: &str,
) {
    let intent_id = uuid::Uuid::now_v7();
    let lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id,
            tenant_id: tenant_id.to_string(),
            backend_id: backend_id.to_string(),
            backend_fingerprint: "test-fingerprint".to_string(),
            provider_bucket: "test-provider-bucket".to_string(),
            physical_key: physical_key.to_string(),
            versioning_mode: s4_gateway::managed::BackendVersioningMode::Enabled,
            versioning_capability: s4_gateway::managed::BackendVersioningCapability::Optional,
            lease_owner: "db-test-writer".to_string(),
        })
        .await
        .unwrap();
    repository
        .commit_physical_write(&lease, &[], Some(&format!("version-{intent_id}")))
        .await
        .unwrap();
}

#[test]
fn postgres_namespace_purge_fences_late_writes_and_completes_idempotently() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let journal = PostgresOperationJournal::new(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("purge-unit-{}", uuid::Uuid::new_v4());
        let intent_id = uuid::Uuid::now_v7();
        let lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id,
                tenant_id: tenant.clone(),
                backend_id: "provider:bucket".to_string(),
                backend_fingerprint: "test-fingerprint".to_string(),
                provider_bucket: "bucket".to_string(),
                physical_key: "managed/physical-key".to_string(),
                versioning_mode: s4_gateway::managed::BackendVersioningMode::Enabled,
                versioning_capability: s4_gateway::managed::BackendVersioningCapability::Optional,
                lease_owner: "db-test-writer".to_string(),
            })
            .await
            .unwrap();
        let duplicate = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id,
                tenant_id: tenant.clone(),
                backend_id: "provider:bucket".to_string(),
                backend_fingerprint: "test-fingerprint".to_string(),
                provider_bucket: "bucket".to_string(),
                physical_key: "managed/physical-key".to_string(),
                versioning_mode: s4_gateway::managed::BackendVersioningMode::Enabled,
                versioning_capability: s4_gateway::managed::BackendVersioningCapability::Optional,
                lease_owner: "db-test-writer".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(duplicate, lease);
        assert!(matches!(
            repository
                .begin_physical_write(PhysicalWriteIntent {
                    intent_id,
                    tenant_id: tenant.clone(),
                    backend_id: "provider:bucket".to_string(),
                    backend_fingerprint: "test-fingerprint".to_string(),
                    provider_bucket: "bucket".to_string(),
                    physical_key: "managed/different-key".to_string(),
                    versioning_mode: s4_gateway::managed::BackendVersioningMode::Enabled,
                    versioning_capability:
                        s4_gateway::managed::BackendVersioningCapability::Optional,
                    lease_owner: "db-test-writer".to_string(),
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
                .begin_physical_write(PhysicalWriteIntent {
                    intent_id: uuid::Uuid::now_v7(),
                    tenant_id: tenant.clone(),
                    backend_id: "provider:bucket".to_string(),
                    backend_fingerprint: "test-fingerprint".to_string(),
                    provider_bucket: "bucket".to_string(),
                    physical_key: "must-not-start".to_string(),
                    versioning_mode: s4_gateway::managed::BackendVersioningMode::Enabled,
                    versioning_capability:
                        s4_gateway::managed::BackendVersioningCapability::Optional,
                    lease_owner: "stale-writer".to_string(),
                })
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
        sqlx::migrate!("../../migrations")
            .run(&pool)
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
        let (key_id, secret) = store
            .create_key(&user, "encrypted", 0, None)
            .await
            .expect("create encrypted Postgres API key");

        let persisted = store.get_key(&key_id).await.expect("persisted key");
        let envelope = persisted.secret_encrypted.expect("encrypted secret");
        assert!(envelope.starts_with("v2:"));
        assert!(!envelope.contains(&secret));
        assert_eq!(
            store.decrypt_secret(&key_id).await.as_deref(),
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
                    size_bytes: 42,
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
            replica_backend_id: Some("replica".to_string()),
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::RepairPending,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };

        ledger_managed_test_version(
            &repository,
            &tenant,
            "primary",
            &s4_gateway::managed::generation_physical_key(&logical, generation),
        )
        .await;

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
        ledger_managed_test_version(
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
        ledger_managed_test_version(
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
            ledger_managed_test_version(
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
fn postgres_v1_secret_is_rewrapped_to_identity_bound_v2() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let cipher = Arc::new(SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(
            TEST_KEK,
        ))));
        let store = PostgresKeyStore::with_cipher(pool, cipher.clone());
        let user = format!("unit-v1-{}", uuid::Uuid::new_v4());
        let (key_id, secret) = store
            .create_key(&user, "legacy-rewrap", 0, None)
            .await
            .expect("create Postgres API key");
        let legacy = v1_envelope(&secret);
        update_secret_state(&db, &key_id, None, &legacy).await;

        assert_eq!(
            store.decrypt_secret(&key_id).await.as_deref(),
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
        let (key_id, secret) = store
            .create_key(&user, "legacy-hash-mismatch", 0, None)
            .await
            .expect("create Postgres API key");
        let legacy = v1_envelope(&secret);
        let mismatched_hash = sha256_hash("different-secret");
        update_secret_state(&db, &key_id, Some(&mismatched_hash), &legacy).await;

        assert_eq!(store.decrypt_secret(&key_id).await, None);

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
        let (key_id, secret) = initial_store
            .create_key(&user, "legacy-cas", 0, None)
            .await
            .expect("create hash-only Postgres API key");
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
            decrypt.await.expect("join legacy decrypt").as_deref(),
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
        let (key_id, secret) = store
            .create_key(&user, "roundtrip", 0, None)
            .await
            .expect("create Postgres API key");
        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .expect("valid credentials resolve");
        assert_eq!(uid, user);
        assert!(pk.is_none());
        assert!(
            store
                .resolve_credentials(&key_id, "wrong-secret")
                .await
                .is_none()
        );
        assert!(
            store
                .resolve_credentials("missing-key", &secret)
                .await
                .is_none()
        );

        let keys = store.list_for_user(&user).await;
        assert_eq!(keys.len(), 1);
        assert!(keys[0].secret_hash.is_empty(), "list must strip the hash");
        assert_eq!(keys[0].label, "roundtrip");

        assert!(store.delete_key(&key_id, &user).await);
        assert!(!store.delete_key(&key_id, &user).await);
        assert!(store.get_key(&key_id).await.is_none());
    });
}

#[test]
fn postgres_public_key_binding() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (key_id, secret) = store
            .create_key(&user, "enc", 0, None)
            .await
            .expect("create Postgres API key");
        assert!(
            store
                .set_public_key(&key_id, &user, "-----BEGIN PUBLIC KEY-----\npem")
                .await
                .unwrap()
        );
        assert!(
            !store
                .set_public_key(&key_id, "someone-else", "pem2")
                .await
                .unwrap()
        );

        let (uid, pk) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .expect("resolve after binding");
        assert_eq!(uid, user);
        assert_eq!(pk.as_deref(), Some("-----BEGIN PUBLIC KEY-----\npem"));
        delete_api_key(&db, &key_id).await;
    });
}

#[test]
fn postgres_expired_key_rejected() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (key_id, secret) = store
            .create_key(&user, "exp", 1, None)
            .await
            .expect("create Postgres API key");
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            store.resolve_credentials(&key_id, &secret).await.is_none(),
            "expired key must be rejected"
        );
        delete_api_key(&db, &key_id).await;
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
    State(objects): State<MockObjects>,
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
        let objects = objects.lock().await;
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
        .unwrap_or(path);

    match parts.method {
        Method::PUT => {
            let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
                .await
                .unwrap_or_default();
            let decoded = if bytes.starts_with(b"S4MP10\0") {
                bytes.to_vec()
            } else {
                decode_aws_chunked(&bytes)
            };
            objects.lock().await.insert(key, decoded);
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        }
        Method::GET => {
            let objects = objects.lock().await;
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
        Method::DELETE => {
            objects.lock().await.remove(&key);
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

/// Drives the full S3 multipart HTTP surface through `build_router` against a
/// durable Postgres repository, an in-memory staging object store, and the
/// dev-memory destination. Runs only when `DATABASE_URL` is set.
#[test]
fn router_staged_multipart_flow_is_durable_and_idempotent() {
    with_pool(|pool| async move {
        let _ = &pool;

        let staging_dir =
            std::env::temp_dir().join(format!("s4-multipart-staging-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&staging_dir).await.unwrap();

        let objects: MockObjects = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let mock_app = axum::Router::new()
            .fallback(mock_s3_handler)
            .with_state(objects.clone());
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
            std::env::remove_var("S4_KEYS_FILE");
            std::env::remove_var("S3_ENDPOINT");
            std::env::remove_var("S4_SERVICE_BUCKETS");
            std::env::remove_var("S4_SECRET_KEK");
            std::env::remove_var("S4_STREAMING_S3_PROVIDER");
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
        }

        let state = build_state(
            Arc::new(NoopControlPlane),
            Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)),
            Arc::new(s4_gateway::workspace_storage::InMemoryWorkspaceStorageRepository::new()),
        )
        .await
        .expect("build_state with durable staged multipart");
        let (ak, sk) = state
            .keys
            .create_key("test-user", "multipart-test", 0, None)
            .await
            .expect("create test API key");
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
        let resp = app.clone().oneshot(complete).await.unwrap();
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
            objects.lock().await.is_empty(),
            "abort removed all staging artifacts"
        );

        mock_task.abort();
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
    });
}
