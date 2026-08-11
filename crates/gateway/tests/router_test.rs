use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{Router, response::Html, routing::get};
use s4_gateway::Gateway;
use s4_gateway::store::{KeyStore, MemoryStore};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;

// Test double mirroring the gateway's AppState; fields are constructed to
// exercise the same plumbing but not read by the health/s3 stubs.
#[derive(Clone)]
#[allow(dead_code)]
struct AppState {
    gateway: Arc<Gateway>,
    store: Arc<MemoryStore>,
    keys: Arc<KeyStore>,
}

async fn health() -> &'static str {
    "ok"
}

fn component_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("target");
    p.push("components");
    p.push("pii-default.component.wasm");
    p
}

#[tokio::test]
async fn test_health_route() {
    let component = fs::read(component_path()).expect("component not found");
    let gateway = Gateway::new(&component).expect("gateway failed");

    let state = Arc::new(AppState {
        gateway: Arc::new(gateway),
        store: Arc::new(MemoryStore::new()),
        keys: Arc::new(KeyStore::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(|| async { Html("<h1>ok</h1>") }))
        .route("/{bucket}/{*key}", get(|| async { "s3" }))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_root_route() {
    let component = fs::read(component_path()).expect("component not found");
    let gateway = Gateway::new(&component).expect("gateway failed");

    let state = Arc::new(AppState {
        gateway: Arc::new(gateway),
        store: Arc::new(MemoryStore::new()),
        keys: Arc::new(KeyStore::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(|| async { Html("<h1>ok</h1>") }))
        .route("/{bucket}/{*key}", get(|| async { "s3" }))
        .with_state(state);

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_s3_route() {
    let component = fs::read(component_path()).expect("component not found");
    let gateway = Gateway::new(&component).expect("gateway failed");

    let state = Arc::new(AppState {
        gateway: Arc::new(gateway),
        store: Arc::new(MemoryStore::new()),
        keys: Arc::new(KeyStore::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(|| async { Html("<h1>ok</h1>") }))
        .route("/{bucket}/{*key}", get(|| async { "s3" }))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/demo/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
