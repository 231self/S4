use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_GATEWAY: &str = "http://localhost:9000";

#[derive(Parser)]
#[command(
    name = "s4ctl",
    about = "CLI for S4 — pluggable processing gateway for S3-compatible storage",
    version
)]
struct Cli {
    #[arg(short = 'e', long, env = "S4_GATEWAY_URL", default_value = DEFAULT_GATEWAY)]
    gateway: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in with an S4 API key (saves to ~/.s4/config.json)
    Login {
        #[arg(short, long, env = "S4_ACCESS_KEY")]
        access_key: String,
        #[arg(short = 's', long, env = "S4_SECRET_KEY")]
        secret_key: String,
        /// Bucket name for subsequent commands
        #[arg(short, long)]
        bucket: Option<String>,
    },

    /// Remove saved credentials
    Logout,

    /// Show current user info
    Whoami,

    /// Manage API keys
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },

    /// Manage backend storage configuration
    Backend {
        #[command(subcommand)]
        cmd: BackendCmd,
    },

    /// Manage Wasm filter plugins
    Plugin {
        #[command(subcommand)]
        cmd: PluginCmd,
    },

    /// Upload a file through S4 (runs it through the plugin pipeline)
    Put {
        /// Source file to upload
        file: PathBuf,
        /// Destination key (e.g. ingest/data.jsonl)
        key: String,
        /// Bucket name
        #[arg(short, long)]
        bucket: Option<String>,
    },

    /// Download an object through S4
    Get {
        /// Object key to retrieve
        key: String,
        /// Bucket name
        #[arg(short, long)]
        bucket: Option<String>,
    },

    /// List objects in the store
    List,

    /// Check gateway health
    Health,

    /// Local development environment
    Local {
        #[command(subcommand)]
        cmd: LocalCmd,
    },

    /// End-to-end filter test (uploads a fixture and verifies redaction)
    Test {
        #[command(subcommand)]
        cmd: TestCmd,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Create a new API key
    Create {
        #[arg(short, long)]
        label: Option<String>,
        /// Expiry: never, 30d, 90d, 1y
        #[arg(short, long, default_value = "never")]
        expiry: String,
    },

    /// List all API keys
    List,

    /// Revoke an API key
    Revoke { key_id: String },
}

#[derive(Subcommand)]
enum BackendCmd {
    /// Show current backend configuration
    Get,

    /// Configure AWS S3 backend (IAM Role)
    SetAws {
        /// IAM Role ARN (from Step 1 of AWS setup)
        #[arg(long)]
        role_arn: String,
    },

    /// Configure Cloudflare R2 backend
    SetR2 {
        /// R2 endpoint URL
        #[arg(long)]
        endpoint: String,
        /// R2 API token
        #[arg(long)]
        token: String,
    },

    /// Configure Backblaze B2 backend
    SetB2 {
        /// B2 S3 endpoint
        #[arg(long)]
        endpoint: String,
        /// B2 Key ID
        #[arg(long)]
        key_id: String,
        /// B2 Application Key
        #[arg(long)]
        app_key: String,
    },

    /// Configure MinIO backend
    SetMinio {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        access_key: String,
        #[arg(long)]
        secret_key: String,
    },

    /// Generate a presigned URL for your bucket (requires AWS CLI)
    Presign {
        /// Bucket name
        #[arg(short, long)]
        bucket: String,
        /// Object key
        key: String,
        /// Expiry in seconds (default 7 days)
        #[arg(short, long, default_value = "604800")]
        expires: u64,
    },
}

#[derive(Subcommand)]
enum PluginCmd {
    /// List installed plugins in pipeline order
    List,

    /// Upload a Wasm filter component
    Upload {
        /// Path to a .wasm component (e.g. target/components/*.component.wasm)
        file: PathBuf,
    },

    /// Enable a plugin (adds it to the pipeline)
    Enable { id: String },

    /// Disable a plugin (removes it from the pipeline)
    Disable { id: String },

    /// Delete a plugin from the registry
    Delete { id: String },

    /// Reorder the plugin pipeline (list all plugin ids in desired order)
    Reorder { ids: Vec<String> },
}

#[derive(Subcommand)]
enum LocalCmd {
    /// Start local dev environment (Docker)
    Init,
    /// Stop local dev environment
    Down,
}

#[derive(Subcommand)]
enum TestCmd {
    /// Upload PII fixture and verify redaction
    Upload,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Config {
    access_key: Option<String>,
    secret_key: Option<String>,
    gateway: Option<String>,
    bucket: Option<String>,
}

impl Config {
    fn path() -> PathBuf {
        config_dir().join("config.json")
    }

    fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) -> anyhow::Result<()> {
        let path = Self::path();
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir)?;
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("s4")
}

struct Client {
    gateway: String,
    access_key: String,
    secret_key: String,
    bucket: Option<String>,
    http: reqwest::Client,
}

impl Client {
    fn new(cli: &Cli, config: &Config) -> anyhow::Result<Self> {
        let access_key = config
            .access_key
            .clone()
            .or_else(|| std::env::var("S4_ACCESS_KEY").ok());
        let secret_key = config
            .secret_key
            .clone()
            .or_else(|| std::env::var("S4_SECRET_KEY").ok());
        let gateway = config
            .gateway
            .as_deref()
            .unwrap_or(&cli.gateway)
            .trim_end_matches('/')
            .to_string();
        let bucket = config.bucket.clone();
        Ok(Self {
            gateway,
            access_key: access_key.unwrap_or_default(),
            secret_key: secret_key.unwrap_or_default(),
            bucket,
            http: reqwest::Client::new(),
        })
    }

    fn bucket(&self, _cli: &Cli, cmd_bucket: Option<&str>) -> String {
        cmd_bucket
            .or(self.bucket.as_deref())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "default".to_string())
    }

    fn auth_headers(&self) -> anyhow::Result<HeaderMap> {
        let mut h = HeaderMap::new();
        h.insert("x-s4-access-key", HeaderValue::from_str(&self.access_key)?);
        h.insert("x-s4-secret-key", HeaderValue::from_str(&self.secret_key)?);
        Ok(h)
    }

    fn json_headers(&self) -> anyhow::Result<HeaderMap> {
        let mut h = self.auth_headers()?;
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(h)
    }

    async fn api_get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> anyhow::Result<T> {
        let resp = self
            .http
            .get(format!("{}{}", self.gateway, path))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            bail!("GET {}: {} — {}", path, status, body);
        }
        serde_json::from_str(&body).with_context(|| format!("parse GET {}: {}", path, body))
    }

    async fn api_post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> anyhow::Result<R> {
        let resp = self
            .http
            .post(format!("{}{}", self.gateway, path))
            .headers(self.json_headers()?)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("POST {}: {} — {}", path, status, text);
        }
        serde_json::from_str(&text).with_context(|| format!("parse POST {}: {}", path, text))
    }

    async fn api_put<T: Serialize>(&self, path: &str, body: &T) -> anyhow::Result<()> {
        let resp = self
            .http
            .put(format!("{}{}", self.gateway, path))
            .headers(self.json_headers()?)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            bail!("PUT {}: {} — {}", path, status, text);
        }
        Ok(())
    }

    async fn api_delete(&self, path: &str, body: &serde_json::Value) -> anyhow::Result<()> {
        let resp = self
            .http
            .delete(format!("{}{}", self.gateway, path))
            .headers(self.json_headers()?)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            bail!("DELETE {}: {} — {}", path, status, text);
        }
        Ok(())
    }

    /// POST a raw byte body (used for Wasm plugin uploads); `name` is sent
    /// as the `x-s4-plugin-name` header.
    async fn api_post_raw<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        name: &str,
        bytes: &[u8],
    ) -> anyhow::Result<R> {
        let mut headers = self.auth_headers()?;
        headers.insert(
            "x-s4-plugin-name",
            HeaderValue::from_str(name).context("invalid plugin name")?,
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/wasm"));
        let resp = self
            .http
            .post(format!("{}{}", self.gateway, path))
            .headers(headers)
            .body(bytes.to_vec())
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("POST {}: {} — {}", path, status, text);
        }
        serde_json::from_str(&text).with_context(|| format!("parse POST {}: {}", path, text))
    }

    async fn s3_put(&self, bucket: &str, key: &str, data: Vec<u8>) -> anyhow::Result<()> {
        let resp = self
            .http
            .put(format!("{}/{}/{}", self.gateway, bucket, key))
            .headers(self.auth_headers()?)
            .body(data)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let body = resp.text().await?;
            bail!("S3 PUT failed: {}", body);
        }
    }

    async fn s3_get(&self, bucket: &str, key: &str) -> anyhow::Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}/{}/{}", self.gateway, bucket, key))
            .headers(self.auth_headers()?)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(resp.bytes().await?.to_vec())
        } else {
            let body = resp.text().await?;
            bail!("S3 GET failed: {}", body);
        }
    }
}

fn project_root() -> anyhow::Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("local").join("docker-compose.yml").exists()
        {
            return Ok(dir);
        }
        if !dir.pop() {
            bail!("Could not find project root (Cargo.toml + local/docker-compose.yml)");
        }
    }
}

fn parse_expiry(expiry: &str) -> u64 {
    match expiry {
        "never" | "0" => 0,
        "30d" | "30" => 2592000,
        "90d" | "90" => 7776000,
        "1y" | "365" => 31536000,
        s => s.parse().unwrap_or(0),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load();

    match &cli.command {
        Command::Login {
            access_key,
            secret_key,
            bucket,
        } => {
            let mut cfg = config;
            cfg.access_key = Some(access_key.clone());
            cfg.secret_key = Some(secret_key.clone());
            cfg.gateway = Some(cli.gateway.clone());
            if let Some(b) = bucket {
                cfg.bucket = Some(b.clone());
            }
            cfg.save()?;
            println!("Logged in. Config saved to {:?}", Config::path());
        }

        Command::Logout => {
            let path = Config::path();
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            println!("Logged out.");
        }

        Command::Whoami => {
            let client = Client::new(&cli, &config)?;
            let keys: Vec<serde_json::Value> = client.api_get("/dashboard/api/keys").await?;
            println!("S4 Gateway: {}", client.gateway);
            println!(
                "Access Key: {}...",
                &client.access_key[..16.min(client.access_key.len())]
            );
            println!("API Keys: {}", keys.len());
        }

        Command::Key { cmd } => {
            let client = Client::new(&cli, &config)?;
            match cmd {
                KeyCmd::Create { label, expiry } => {
                    let body = serde_json::json!({
                        "label": label.as_deref().unwrap_or("cli"),
                        "expires_in": parse_expiry(expiry)
                    });
                    let resp: serde_json::Value =
                        client.api_post("/dashboard/api/keys", &body).await?;
                    println!("Key ID:     {}", resp["key_id"].as_str().unwrap_or("?"));
                    println!("Secret:     {}", resp["secret"].as_str().unwrap_or("?"));
                    println!("Label:      {}", resp["label"].as_str().unwrap_or("?"));
                    if let Some(exp) = resp["expires_at"].as_str() {
                        println!("Expires at: {}", exp);
                    }
                    println!("\nSave this secret — it won't be shown again.");
                }
                KeyCmd::List => {
                    let keys: Vec<serde_json::Value> =
                        client.api_get("/dashboard/api/keys").await?;
                    if keys.is_empty() {
                        println!("No keys. Create one with: s4ctl key create --label my-key");
                    } else {
                        for k in &keys {
                            let exp = k["expires_at"]
                                .as_str()
                                .map(|_| " (has expiry)")
                                .unwrap_or("");
                            println!(
                                "{}  {}  {}{}",
                                k["key_id"].as_str().unwrap_or("?"),
                                k["label"].as_str().unwrap_or("?"),
                                k["created_at"].as_str().unwrap_or("?"),
                                exp
                            );
                        }
                    }
                }
                KeyCmd::Revoke { key_id } => {
                    let body = serde_json::json!({"key_id": key_id});
                    client.api_delete("/dashboard/api/keys", &body).await?;
                    println!("Key {} revoked.", key_id);
                }
            }
        }

        Command::Backend { cmd } => {
            let client = Client::new(&cli, &config)?;
            match cmd {
                BackendCmd::Get => {
                    let cfg: serde_json::Value = client.api_get("/dashboard/api/backend").await?;
                    println!("{}", serde_json::to_string_pretty(&cfg)?);
                }
                BackendCmd::SetAws { role_arn } => {
                    let body = serde_json::json!({
                        "backend_type": "aws_role",
                        "role_arn": role_arn,
                    });
                    client.api_put("/dashboard/api/backend", &body).await?;
                    println!("Backend set to AWS IAM Role: {}", role_arn);
                    println!(
                        "Run 's4ctl backend get' to see your External ID for the trust policy."
                    );
                }
                BackendCmd::SetR2 { endpoint, token } => {
                    let body = serde_json::json!({
                        "backend_type": "s3_compatible",
                        "endpoint": endpoint,
                        "access_key": token,
                        "secret_key": token,
                        "region": "auto",
                    });
                    client.api_put("/dashboard/api/backend", &body).await?;
                    println!("Backend set to R2: {}", endpoint);
                }
                BackendCmd::SetB2 {
                    endpoint,
                    key_id,
                    app_key,
                } => {
                    let body = serde_json::json!({
                        "backend_type": "s3_compatible",
                        "endpoint": endpoint,
                        "access_key": key_id,
                        "secret_key": app_key,
                        "region": "us-west-004",
                    });
                    client.api_put("/dashboard/api/backend", &body).await?;
                    println!("Backend set to B2: {}", endpoint);
                }
                BackendCmd::SetMinio {
                    endpoint,
                    access_key,
                    secret_key,
                } => {
                    let body = serde_json::json!({
                        "backend_type": "s3_compatible",
                        "endpoint": endpoint,
                        "access_key": access_key,
                        "secret_key": secret_key,
                        "region": "us-east-1",
                    });
                    client.api_put("/dashboard/api/backend", &body).await?;
                    println!("Backend set to MinIO: {}", endpoint);
                }
                BackendCmd::Presign {
                    bucket,
                    key,
                    expires,
                } => {
                    // Generate a presigned URL using AWS CLI
                    let status = std::process::Command::new("aws")
                        .args([
                            "s3",
                            "presign",
                            &format!("s3://{}/{}", bucket, key),
                            "--expires-in",
                            &expires.to_string(),
                        ])
                        .output()
                        .with_context(|| "aws CLI not found. Install: brew install awscli")?;
                    if status.status.success() {
                        let url = String::from_utf8_lossy(&status.stdout).trim().to_string();
                        println!("Presigned PUT URL ({}s TTL):", expires);
                        println!("{}", url);
                        println!("\n# Use with s4ctl:");
                        println!("s4ctl put ./file --key {} --bucket {}", key, bucket);
                        println!("# Or with curl:");
                        println!("curl -X PUT \"{}\" \\", url);
                        println!("  -H \"x-s4-access-key: {}\" \\", client.access_key);
                        println!("  -H \"x-s4-secret-key: {}\"", client.secret_key);
                        println!("  --data-binary @file");
                    } else {
                        let err = String::from_utf8_lossy(&status.stderr);
                        bail!("aws CLI error: {}", err);
                    }
                }
            }
        }

        Command::Plugin { cmd } => {
            let client = Client::new(&cli, &config)?;
            match cmd {
                PluginCmd::List => {
                    let plugins: Vec<serde_json::Value> =
                        client.api_get("/dashboard/api/plugins").await?;
                    if plugins.is_empty() {
                        println!("No plugins installed.");
                    } else {
                        for p in &plugins {
                            let state = if p["enabled"].as_bool().unwrap_or(false) {
                                "enabled "
                            } else {
                                "disabled"
                            };
                            println!(
                                "{}  {}  {}  {}",
                                p["id"].as_str().unwrap_or("?"),
                                p["name"].as_str().unwrap_or("?"),
                                p["version"].as_str().unwrap_or("?"),
                                state
                            );
                        }
                    }
                }
                PluginCmd::Upload { file } => {
                    let bytes = std::fs::read(file)
                        .with_context(|| format!("Cannot read {}", file.display()))?;
                    let name = file
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("imported")
                        .to_string();
                    let plugin: serde_json::Value = client
                        .api_post_raw("/dashboard/api/plugins", &name, &bytes)
                        .await?;
                    println!(
                        "Uploaded plugin {} ({}) as {}",
                        plugin["name"].as_str().unwrap_or(&name),
                        bytes.len(),
                        plugin["id"].as_str().unwrap_or("?")
                    );
                }
                PluginCmd::Enable { id } => {
                    let body = serde_json::json!({"enabled": true});
                    client
                        .api_put(&format!("/dashboard/api/plugins/{}", id), &body)
                        .await?;
                    println!("Plugin {id} enabled.");
                }
                PluginCmd::Disable { id } => {
                    let body = serde_json::json!({"enabled": false});
                    client
                        .api_put(&format!("/dashboard/api/plugins/{}", id), &body)
                        .await?;
                    println!("Plugin {id} disabled.");
                }
                PluginCmd::Delete { id } => {
                    client
                        .api_delete(
                            &format!("/dashboard/api/plugins/{}", id),
                            &serde_json::Value::Null,
                        )
                        .await?;
                    println!("Plugin {id} deleted.");
                }
                PluginCmd::Reorder { ids } => {
                    let body = serde_json::json!({"order": ids});
                    client
                        .api_put("/dashboard/api/plugins/reorder", &body)
                        .await?;
                    println!("Plugin pipeline reordered.");
                }
            }
        }

        Command::Put { file, key, bucket } => {
            let client = Client::new(&cli, &config)?;
            let data = std::fs::read(file).with_context(|| {
                format!(
                    "Cannot read {} — create it first, e.g. `echo \"jane.doe@example.com 4111111111111111\" > {}`",
                    file.display(),
                    file.display()
                )
            })?;
            let len = data.len();
            let bucket = client.bucket(&cli, bucket.as_deref());
            client.s3_put(&bucket, key, data).await?;
            println!(
                "Uploaded {} -> {}/{} ({} bytes)",
                file.display(),
                bucket,
                key,
                len
            );
        }

        Command::Get { key, bucket } => {
            let client = Client::new(&cli, &config)?;
            let bucket = client.bucket(&cli, bucket.as_deref());
            let data = client.s3_get(&bucket, key).await?;
            std::io::Write::write_all(&mut std::io::stdout(), &data)?;
        }

        Command::List => {
            let client = Client::new(&cli, &config)?;
            let objects: Vec<serde_json::Value> = client.api_get("/dashboard/api/objects").await?;
            if objects.is_empty() {
                println!("No objects in store.");
            } else {
                for o in &objects {
                    println!(
                        "{}  {} bytes",
                        o["key"].as_str().unwrap_or("?"),
                        o["size"].as_u64().unwrap_or(0),
                    );
                }
            }
        }

        Command::Health => {
            let resp = reqwest::get(format!("{}/health", cli.gateway)).await?;
            if resp.status().is_success() {
                println!("S4 gateway is healthy at {}", cli.gateway);
            } else {
                bail!(
                    "Gateway unhealthy: {} {}",
                    resp.status(),
                    resp.text().await?
                );
            }
        }

        Command::Local { cmd } => {
            const LOCAL_GATEWAY_NAME: &str = "s4-local-gateway";
            const LOCAL_GATEWAY_IMAGE: &str = "ghcr.io/231self/s4/s4:latest";

            match cmd {
                LocalCmd::Init => {
                    // Runs the published gateway image standalone (no repo
                    // clone, no Postgres): in-memory storage, keys persisted
                    // on a named volume. Durable MinIO storage is available
                    // via `just dev-up` in the repo.
                    let docker_ok = std::process::Command::new("docker")
                        .args(["version", "--format", "{{.Server.Version}}"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    if !docker_ok {
                        bail!("docker is not running — start Docker/colima first");
                    }

                    // Pick a free host port (8080 is commonly taken) and
                    // publish on the loopback interface only.
                    let port = (8080u16..=8180u16)
                        .find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
                        .expect("no free port in 8080..8180");

                    let _ = std::process::Command::new("docker")
                        .args(["rm", "-f", LOCAL_GATEWAY_NAME])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                    let run_status = std::process::Command::new("docker")
                        .args([
                            "run",
                            "-d",
                            "--name",
                            LOCAL_GATEWAY_NAME,
                            "-p",
                            &format!("127.0.0.1:{port}:8080"),
                            "-v",
                            "s4-local-keys:/app/data",
                            "-e",
                            "AUTH_DISABLED=true",
                            "-e",
                            "S4_KEYS_FILE=/app/data/keys.json",
                            LOCAL_GATEWAY_IMAGE,
                        ])
                        .status()?;
                    if !run_status.success() {
                        bail!(
                            "failed to start gateway container — is {LOCAL_GATEWAY_IMAGE} pullable?"
                        );
                    }

                    let url = format!("http://127.0.0.1:{port}");
                    let mut healthy = false;
                    for _ in 0..30 {
                        if reqwest::get(format!("{url}/health"))
                            .await
                            .map(|r| r.status().is_success())
                            .unwrap_or(false)
                        {
                            healthy = true;
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    if !healthy {
                        // Surface the container logs so a broken image is easy to diagnose.
                        let logs = std::process::Command::new("docker")
                            .args(["logs", LOCAL_GATEWAY_NAME])
                            .output()
                            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                            .unwrap_or_default();
                        if !logs.is_empty() {
                            eprintln!("gateway logs:\n{logs}");
                        }
                        bail!("gateway did not become healthy at {url}/health");
                    }

                    // Point the CLI at the local gateway in demo mode so the
                    // quickstart works without any credentials.
                    let mut cfg = Config::load();
                    cfg.access_key = None;
                    cfg.secret_key = None;
                    cfg.gateway = Some(url.clone());
                    cfg.bucket = None;
                    cfg.save()?;

                    println!("S4 local gateway is running (published image).");
                    println!("  Gateway: {url}");
                    println!("  Storage: in-memory (durable MinIO via `just dev-up` in the repo)");
                    println!("  Keys:    persisted in the s4-local-keys volume");
                    println!();
                    println!("Quickstart:");
                    println!("  s4ctl put ./data.csv ingest/data.csv --bucket s4-local");
                    println!("  s4ctl get ingest/data.csv --bucket s4-local");
                    println!();
                    println!("Stop with: s4ctl local down");
                }
                LocalCmd::Down => {
                    let status = std::process::Command::new("docker")
                        .args(["rm", "-f", LOCAL_GATEWAY_NAME])
                        .status()?;
                    if status.success() {
                        println!("S4 local gateway stopped.");
                    } else {
                        println!("S4 local gateway is not running.");
                    }
                }
            }
        }

        Command::Test { cmd } => match cmd {
            TestCmd::Upload => {
                use std::io::Read;
                let root = project_root()?;
                let fixture = root
                    .join("tests")
                    .join("fixtures")
                    .join("pii")
                    .join("sample1.txt");
                let mut data = Vec::new();
                std::fs::File::open(&fixture)
                    .with_context(|| format!("Fixture not found at {}", fixture.display()))?
                    .read_to_end(&mut data)?;

                let client = Client::new(&cli, &config).unwrap_or_else(|_| Client {
                    gateway: cli.gateway.clone(),
                    access_key: String::new(),
                    secret_key: String::new(),
                    bucket: None,
                    http: reqwest::Client::new(),
                });

                let key = "test-upload.txt";
                let bucket = "s4-local";

                // PUT
                if !client.access_key.is_empty() {
                    client.s3_put(bucket, key, data.clone()).await?;
                } else {
                    // Demo mode — no auth
                    let resp = client
                        .http
                        .put(format!("{}/{}/{}", client.gateway, bucket, key))
                        .body(data.clone())
                        .send()
                        .await?;
                    if !resp.status().is_success() {
                        bail!("PUT failed: {}", resp.text().await?);
                    }
                }

                // GET
                let stored = if !client.access_key.is_empty() {
                    client.s3_get(bucket, key).await?
                } else {
                    let resp = client
                        .http
                        .get(format!("{}/{}/{}", client.gateway, bucket, key))
                        .send()
                        .await?;
                    if !resp.status().is_success() {
                        bail!("GET failed: {}", resp.text().await?);
                    }
                    resp.bytes().await?.to_vec()
                };

                let stored_str = String::from_utf8_lossy(&stored);

                let checks = [
                    (
                        "REDACTED_EMAIL",
                        stored_str.contains("[REDACTED_EMAIL]"),
                        "johndoe@example.com should not appear",
                    ),
                    (
                        "REDACTED_SSN",
                        stored_str.contains("[REDACTED_SSN]"),
                        "123-45-6789 should not appear",
                    ),
                    (
                        "REDACTED_CARD",
                        stored_str.contains("[REDACTED_CARD]"),
                        "4111-1111-1111-1111 should not appear",
                    ),
                ];

                let mut failed = false;
                for (name, ok, msg) in &checks {
                    if *ok {
                        println!("[PASS] Check {} passed", name);
                    } else {
                        println!("[FAIL] Check {} failed — {}", name, msg);
                        failed = true;
                    }
                }

                if !stored_str.contains("johndoe@example.com")
                    && !stored_str.contains("123-45-6789")
                    && !stored_str.contains("4111-1111-1111-1111")
                {
                    println!("\nPII redaction: PASS");
                } else {
                    println!("\nPII redaction: FAIL — original PII found in stored data");
                    failed = true;
                }

                if failed {
                    bail!("Some checks failed");
                }
            }
        },
    }

    Ok(())
}
