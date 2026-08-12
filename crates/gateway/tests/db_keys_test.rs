//! Postgres-backed key store integration tests.
//!
//! These run only when `DATABASE_URL` points at a reachable Postgres
//! (e.g. local Supabase: `postgresql://postgres:postgres@127.0.0.1:54322/postgres`).
//! Migrations are applied automatically. Without `DATABASE_URL` the tests
//! skip.

use s4_gateway::store::{KeyRepository, PostgresKeyStore};
use sqlx::PgPool;

/// Connect to `DATABASE_URL` (skipping if unset/unreachable), apply
/// migrations, then run `body` on a single Tokio runtime.
fn with_pool<F, Fut>(body: F)
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };
        let pool = match PgPool::connect(&url).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("SKIP: cannot connect to Postgres: {e}");
                return;
            }
        };
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations should apply");
        body(pool).await;
    });
}

#[test]
fn postgres_key_roundtrip() {
    with_pool(|pool| async move {
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (key_id, secret) = store.create_key(&user, "roundtrip", 0, None, None).await;
        let (uid, pk, _ws) = store
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
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (key_id, secret) = store.create_key(&user, "enc", 0, None, None).await;
        assert!(
            store
                .set_public_key(&key_id, &user, "-----BEGIN PUBLIC KEY-----\npem")
                .await
        );
        assert!(!store.set_public_key(&key_id, "someone-else", "pem2").await);

        let (uid, pk, _ws) = store
            .resolve_credentials(&key_id, &secret)
            .await
            .expect("resolve after binding");
        assert_eq!(uid, user);
        assert_eq!(pk.as_deref(), Some("-----BEGIN PUBLIC KEY-----\npem"));
    });
}

#[test]
fn postgres_expired_key_rejected() {
    with_pool(|pool| async move {
        let store = PostgresKeyStore::new(pool);
        let user = format!("unit-{}", uuid::Uuid::new_v4());
        let (key_id, secret) = store.create_key(&user, "exp", 1, None, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            store.resolve_credentials(&key_id, &secret).await.is_none(),
            "expired key must be rejected"
        );
    });
}
