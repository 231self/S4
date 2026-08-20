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
use s4_gateway::entity::managed_object_authority;
use s4_gateway::entity::managed_object_repair;
use s4_gateway::entity::object_operation;
use s4_gateway::key_cipher::{KeyWrapping, LocalKeyWrapping, SecretCipher};
use s4_gateway::managed::{
    CopyStatus, LogicalObjectKey, ManagedRepository, ObjectAuthority, Placement,
    PostgresManagedRepository,
};
use s4_gateway::store::{KeyRepository, PostgresKeyStore, sha256_hash};
use s4_gateway::transaction::{
    EvidenceRecord, ExpectedObject, ObjectDestination, OperationJournal, OperationRecord,
    OperationState, PartRecord, PostgresOperationJournal,
};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, SqlxPostgresConnector};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const TEST_KEK: [u8; 32] = [7; 32];
static DB_TEST_LOCK: Mutex<()> = Mutex::new(());

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
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
        assert!(
            repository
                .complete_repair(&restarted_claim[0])
                .await
                .unwrap()
        );
        repository
            .enqueue(restarted_claim[0].clone())
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
        );
        assert!(!store.set_public_key(&key_id, "someone-else", "pem2").await);

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
