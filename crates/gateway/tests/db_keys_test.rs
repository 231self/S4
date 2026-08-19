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
use s4_gateway::entity::object_operation;
use s4_gateway::key_cipher::{KeyWrapping, LocalKeyWrapping, SecretCipher};
use s4_gateway::store::{KeyRepository, PostgresKeyStore, sha256_hash};
use s4_gateway::transaction::{
    EvidenceRecord, ExpectedObject, ObjectDestination, OperationJournal, OperationRecord,
    OperationState, PartRecord, PostgresOperationJournal,
};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, SqlxPostgresConnector};
use sqlx::PgPool;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const TEST_KEK: [u8; 32] = [7; 32];
static DB_TEST_LOCK: Mutex<()> = Mutex::new(());

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
        let pool = PgPool::connect(&url)
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
        let decrypt = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .expect("decrypt runtime")
                .block_on(decrypt_store.decrypt_secret(&decrypt_key_id))
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("legacy rewrap reached conditional update window");
        let winner_cipher = SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)));
        let winner = winner_cipher
            .encrypt(&key_id, &secret)
            .expect("create concurrent v2 winner");
        update_secret_state(&db, &key_id, None, &winner).await;
        release_tx.send(()).expect("release legacy rewrap");

        assert_eq!(
            decrypt.join().expect("join legacy decrypt").as_deref(),
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
