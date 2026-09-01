use anyhow::{Context, bail};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use maskura_customer_config::{EnvAlias, aliases as customer_env, resolve as resolve_customer_env};
use reqwest::Url;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_GATEWAY: &str = "http://localhost:9000";
const HOSTED_WORKSPACE_ID_ENV: EnvAlias = EnvAlias::new("MASKURA_WORKSPACE_ID", "S4_WORKSPACE_ID");
const HOSTED_ACCESS_TOKEN_ENV: EnvAlias = EnvAlias::new("MASKURA_ACCESS_TOKEN", "S4_ACCESS_TOKEN");

#[derive(Parser)]
#[command(
    name = "maskura",
    about = "CLI for Maskura, a pluggable processing gateway for S3-compatible storage",
    version
)]
struct Cli {
    #[arg(short = 'e', long)]
    gateway: Option<String>,

    #[command(subcommand)]
    command: Command,

    #[arg(skip)]
    customer_env: CustomerEnv,

    #[arg(skip)]
    program: Program,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Program {
    #[default]
    Maskura,
    S4ctl,
}

impl Program {
    fn from_executable(executable: &std::ffi::OsStr) -> Self {
        let stem = std::path::Path::new(executable)
            .file_stem()
            .and_then(|value| value.to_str());
        if stem == Some("s4ctl") {
            Self::S4ctl
        } else {
            Self::Maskura
        }
    }

    fn current() -> Self {
        std::env::args_os()
            .next()
            .as_deref()
            .map(Self::from_executable)
            .unwrap_or_default()
    }

    fn name(self) -> &'static str {
        match self {
            Self::Maskura => "maskura",
            Self::S4ctl => "s4ctl",
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Log in with a Maskura API key (uses the existing shared config path)
    Login {
        #[arg(short, long)]
        access_key: Option<String>,
        #[arg(short = 's', long)]
        secret_key: Option<String>,
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

    /// Manage hosted filter pipelines as a workspace owner. Authenticates with a
    /// Supabase access token (`MASKURA_ACCESS_TOKEN` / `--token`) - never a
    /// Maskura data-plane API key.
    Hosted {
        /// Workspace ID (UUID)
        #[arg(long)]
        workspace: Option<String>,
        /// Supabase access token (JWT)
        #[arg(long)]
        token: Option<String>,
        #[command(subcommand)]
        cmd: HostedCmd,
    },

    /// Upload a file through Maskura (runs it through the plugin pipeline)
    Put {
        /// Source file to upload
        file: PathBuf,
        /// Destination key (e.g. ingest/data.jsonl)
        key: String,
        /// Bucket name
        #[arg(short, long)]
        bucket: Option<String>,
    },

    /// Download an object through Maskura
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
enum HostedCmd {
    /// List the workspace plugin catalog (built-ins and custom, with versions
    /// and capability grants)
    Catalog,

    /// Stage a raw Wasm component into the private quarantine artifact store
    /// (content-addressed; no relational records are created)
    Stage {
        /// Path to a .wasm component
        file: PathBuf,
    },

    /// Stage a component and register a custom plugin version with a
    /// validation run (upload -> validate)
    Upload {
        /// Path to a .wasm component
        file: PathBuf,
        /// Unique plugin slug, e.g. `my-redactor`
        #[arg(long)]
        slug: String,
        /// Human-readable display name
        #[arg(long)]
        display_name: String,
        /// Human-readable version label, e.g. `1.0.0`
        #[arg(long)]
        version: String,
        /// WIT world, one of `s4-filter@0.1.0`, `s4-filter@0.2.0`
        #[arg(long, default_value = "s4-filter@0.1.0")]
        world: String,
        /// WIT version label, e.g. `0.1.0` or `0.2.0`
        #[arg(long, default_value = "0.1.0")]
        wit_version: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Requested capability, repeatable (e.g. `stable_fields`)
        #[arg(long = "capability")]
        capability: Vec<String>,
        /// Path to a JSON config schema (v0.2 world only)
        #[arg(long)]
        config_schema: Option<PathBuf>,
    },

    /// Poll the validation status of a plugin version
    Validation { version_id: String },

    /// Grant a capability to an installed plugin version
    Grant {
        /// Installation ID from the catalog
        #[arg(long)]
        installation_id: String,
        /// Capability name (e.g. `stable_fields`)
        #[arg(long)]
        capability: String,
        /// Plugin version ID being granted
        #[arg(long)]
        version_id: String,
    },

    /// Revoke a capability from an installed plugin version
    Revoke {
        #[arg(long)]
        installation_id: String,
        #[arg(long)]
        capability: String,
        #[arg(long)]
        version_id: String,
    },

    /// List, create, edit, publish, or roll back pipelines
    Pipelines {
        #[command(subcommand)]
        cmd: HostedPipelineCmd,
    },

    /// List pipeline assignments and bucket scopes
    Assignments,

    /// Set the workspace default pipeline for a direction
    AssignDefault {
        /// `write` or `read`
        direction: String,
        /// Pipeline ID
        #[arg(long)]
        pipeline_id: String,
    },

    /// Assign a pipeline to an exact logical bucket for a direction
    AssignBucket {
        /// `write` or `read`
        direction: String,
        /// Exact logical bucket name
        bucket: String,
        /// Pipeline ID
        #[arg(long)]
        pipeline_id: String,
    },

    /// Remove an exact bucket assignment (restores default inheritance)
    UnassignBucket {
        /// `write` or `read`
        direction: String,
        /// Exact logical bucket name
        bucket: String,
    },

    /// Show the workspace filter audit trail
    Audit {
        /// Maximum events to return (default 100, max 500)
        #[arg(long)]
        limit: Option<u64>,
    },
}

#[derive(Subcommand)]
enum HostedPipelineCmd {
    /// List pipelines with their published revisions
    List,

    /// Create a pipeline with an empty draft revision
    Create {
        /// `write` or `read`
        direction: String,
        /// Pipeline name
        name: String,
    },

    /// Replace the draft steps of a pipeline
    Draft {
        /// Pipeline ID
        pipeline_id: String,
        /// Explicitly publish an empty (pass-through) chain; false requires
        /// at least one step
        #[arg(long, default_value_t = false)]
        passthrough: bool,
        /// Step as `installation_id:version_id[:config.json]`, repeatable, in
        /// execution order
        #[arg(long = "step")]
        steps: Vec<String>,
    },

    /// Publish the current draft revision
    Publish { pipeline_id: String },

    /// Roll back to a prior published revision
    Rollback {
        /// Pipeline ID
        pipeline_id: String,
        /// Published revision ID to restore
        revision_id: String,
    },
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

#[derive(Debug, Default)]
struct CustomerEnv {
    gateway: Option<String>,
    access_key: Option<String>,
    secret_key: Option<String>,
    workspace_id: Option<String>,
    access_token: Option<String>,
}

impl CustomerEnv {
    fn from_process() -> anyhow::Result<Self> {
        Ok(Self {
            gateway: resolve_customer_env(customer_env::GATEWAY_URL)?,
            access_key: resolve_customer_env(customer_env::ACCESS_KEY)?,
            secret_key: resolve_customer_env(customer_env::SECRET_KEY)?,
            workspace_id: resolve_customer_env(HOSTED_WORKSPACE_ID_ENV)?,
            access_token: resolve_customer_env(HOSTED_ACCESS_TOKEN_ENV)?,
        })
    }
}

impl Cli {
    fn parse_for_program() -> Self {
        let program = Program::current();
        let matches = Self::command().name(program.name()).get_matches();
        let mut cli = Self::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
        cli.program = program;
        cli
    }

    fn requested_gateway(&self) -> &str {
        self.gateway
            .as_deref()
            .or(self.customer_env.gateway.as_deref())
            .unwrap_or(DEFAULT_GATEWAY)
    }
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
            .or_else(|| cli.customer_env.access_key.clone());
        let secret_key = config
            .secret_key
            .clone()
            .or_else(|| cli.customer_env.secret_key.clone());
        let gateway = config
            .gateway
            .as_deref()
            .unwrap_or_else(|| cli.requested_gateway())
            .trim_end_matches('/')
            .to_string();
        let bucket = config.bucket.clone();
        Ok(Self {
            gateway,
            access_key: access_key.unwrap_or_default(),
            secret_key: secret_key.unwrap_or_default(),
            bucket,
            http: reqwest::Client::builder()
                .user_agent(format!(
                    "{}/{}",
                    cli.program.name(),
                    env!("CARGO_PKG_VERSION")
                ))
                .build()?,
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
        h.insert(
            "x-maskura-access-key",
            HeaderValue::from_str(&self.access_key)?,
        );
        h.insert(
            "x-maskura-secret-key",
            HeaderValue::from_str(&self.secret_key)?,
        );
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
    /// as the `x-maskura-plugin-name` header.
    async fn api_post_raw<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        name: &str,
        bytes: &[u8],
    ) -> anyhow::Result<R> {
        let mut headers = self.auth_headers()?;
        headers.insert(
            "x-maskura-plugin-name",
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

/// Hosted (SaaS control plane) client. Authenticates exclusively with a
/// Supabase access token; a data-plane API key is never accepted here.
struct HostedApi {
    gateway: Url,
    workspace: String,
    token: String,
    http: reqwest::Client,
}

impl HostedApi {
    fn new(gateway: &str, workspace: &str, token: &str) -> anyhow::Result<Self> {
        let gateway = Url::parse(gateway).context("invalid hosted gateway URL")?;
        if gateway.cannot_be_a_base() {
            bail!("hosted gateway URL cannot be used as a base URL");
        }
        Ok(Self {
            gateway,
            workspace: workspace.to_string(),
            token: token.to_string(),
            http: reqwest::Client::new(),
        })
    }

    fn path(&self, segments: &[&str]) -> anyhow::Result<Url> {
        let mut url = self.gateway.clone();
        url.set_query(None);
        url.set_fragment(None);
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("hosted gateway URL cannot contain path segments"))?;
        path.pop_if_empty();
        path.extend(["dashboard", "api", "workspaces"]);
        path.push(&self.workspace);
        path.extend(segments.iter().copied());
        drop(path);
        Ok(url)
    }

    fn path_with_query(&self, segments: &[&str], query: &[(&str, String)]) -> anyhow::Result<Url> {
        let mut url = self.path(segments)?;
        url.query_pairs_mut()
            .extend_pairs(query.iter().map(|(key, value)| (*key, value.as_str())));
        Ok(url)
    }

    fn auth_headers(&self) -> anyhow::Result<HeaderMap> {
        let mut h = HeaderMap::new();
        h.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.token))?,
        );
        Ok(h)
    }

    fn json_headers(&self) -> anyhow::Result<HeaderMap> {
        let mut h = self.auth_headers()?;
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(h)
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, segments: &[&str]) -> anyhow::Result<T> {
        self.get_with_query(segments, &[]).await
    }

    async fn get_with_query<T: for<'de> Deserialize<'de>>(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> anyhow::Result<T> {
        let url = self.path_with_query(segments, query)?;
        let resp = self
            .http
            .get(url.clone())
            .headers(self.auth_headers()?)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            bail!("GET {}: {} — {}", url, status, body);
        }
        serde_json::from_str(&body).with_context(|| format!("parse GET {}: {}", url, body))
    }

    async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        segments: &[&str],
        body: &T,
    ) -> anyhow::Result<R> {
        let url = self.path(segments)?;
        let resp = self
            .http
            .post(url.clone())
            .headers(self.json_headers()?)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("POST {}: {} — {}", url, status, text);
        }
        serde_json::from_str(&text).with_context(|| format!("parse POST {}: {}", url, text))
    }

    async fn put<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        segments: &[&str],
        body: &T,
    ) -> anyhow::Result<R> {
        let url = self.path(segments)?;
        let resp = self
            .http
            .put(url.clone())
            .headers(self.json_headers()?)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("PUT {}: {} — {}", url, status, text);
        }
        serde_json::from_str(&text).with_context(|| format!("parse PUT {}: {}", url, text))
    }

    async fn put_unit<T: Serialize>(&self, segments: &[&str], body: &T) -> anyhow::Result<()> {
        let url = self.path(segments)?;
        let resp = self
            .http
            .put(url.clone())
            .headers(self.json_headers()?)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("PUT {}: {} — {}", url, status, text);
        }
        Ok(())
    }

    async fn delete_unit<T: Serialize>(&self, segments: &[&str], body: &T) -> anyhow::Result<()> {
        let url = self.path(segments)?;
        let resp = self
            .http
            .delete(url.clone())
            .headers(self.json_headers()?)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("DELETE {}: {} — {}", url, status, text);
        }
        Ok(())
    }

    /// Stage raw Wasm bytes into the private quarantine artifact store.
    async fn stage_artifact(&self, bytes: &[u8]) -> anyhow::Result<serde_json::Value> {
        let mut headers = self.auth_headers()?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/wasm"));
        let resp = self
            .http
            .post(self.path(&["filter-artifacts"])?)
            .headers(headers)
            .body(bytes.to_vec())
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("POST filter-artifacts: {} — {}", status, text);
        }
        serde_json::from_str(&text)
            .with_context(|| format!("parse POST filter-artifacts: {}", text))
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

/// Parse a hosted draft step of the form
/// `installation_id:version_id[:config.json]`. Config is optional and only
/// valid for v0.2 world components (the server rejects it otherwise).
fn parse_draft_step(raw: &str) -> anyhow::Result<serde_json::Value> {
    let parts = raw.split(':').collect::<Vec<_>>();
    if parts.len() < 2 || parts.len() > 3 {
        bail!("invalid step {raw:?}; expected installation_id:version_id[:config.json]");
    }
    let config_json = match parts.get(2) {
        Some(path) if !path.is_empty() => {
            let raw_config = std::fs::read_to_string(path)
                .with_context(|| format!("Cannot read step config {}", path))?;
            let config: serde_json::Value = serde_json::from_str(&raw_config)
                .with_context(|| format!("Invalid JSON in step config {}", path))?;
            Some(config)
        }
        _ => None,
    };
    Ok(serde_json::json!({
        "installation_id": parts[0],
        "plugin_version_id": parts[1],
        "config_json": config_json,
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse_for_program();
    cli.customer_env = CustomerEnv::from_process()?;
    let config = Config::load();

    match &cli.command {
        Command::Login {
            access_key,
            secret_key,
            bucket,
        } => {
            let access_key = access_key
                .as_ref()
                .or(cli.customer_env.access_key.as_ref())
                .context("missing access key: use --access-key or MASKURA_ACCESS_KEY")?;
            let secret_key = secret_key
                .as_ref()
                .or(cli.customer_env.secret_key.as_ref())
                .context("missing secret key: use --secret-key or MASKURA_SECRET_KEY")?;
            let mut cfg = config;
            cfg.access_key = Some(access_key.clone());
            cfg.secret_key = Some(secret_key.clone());
            cfg.gateway = Some(cli.requested_gateway().to_string());
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
            println!("Maskura Gateway: {}", client.gateway);
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
                        println!(
                            "No keys. Create one with: {} key create --label my-key",
                            cli.program.name()
                        );
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
                        "Run '{} backend get' to see your External ID for the trust policy.",
                        cli.program.name()
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
                        println!("\n# Use with {}:", cli.program.name());
                        println!(
                            "{} put ./file --key {} --bucket {}",
                            cli.program.name(),
                            key,
                            bucket
                        );
                        println!("# Or with curl:");
                        println!("curl -X PUT \"{}\" \\", url);
                        println!("  -H \"x-maskura-access-key: {}\" \\", client.access_key);
                        println!("  -H \"x-maskura-secret-key: {}\"", client.secret_key);
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

        Command::Hosted {
            workspace,
            token,
            cmd,
        } => {
            let workspace = workspace
                .as_deref()
                .or(cli.customer_env.workspace_id.as_deref())
                .context(
                    "hosted commands require a workspace via --workspace or MASKURA_WORKSPACE_ID",
                )?;
            let token = token
                .as_deref()
                .or(cli.customer_env.access_token.as_deref())
                .context(
                    "hosted commands require a Supabase access token via --token or MASKURA_ACCESS_TOKEN",
                )?;
            if token.is_empty() {
                bail!("MASKURA_ACCESS_TOKEN must not be empty");
            }
            let api = HostedApi::new(cli.requested_gateway(), workspace, token)?;
            match cmd {
                HostedCmd::Catalog => {
                    let value: serde_json::Value = api.get(&["filter-catalog"]).await?;
                    let plugins = value["plugins"].as_array().cloned().unwrap_or_default();
                    if plugins.is_empty() {
                        println!("No plugins in the workspace catalog.");
                    } else {
                        for entry in &plugins {
                            let installation = &entry["installation"];
                            let plugin = &entry["plugin"];
                            println!(
                                "{}  {}  install={}  world={}",
                                plugin["id"].as_str().unwrap_or("?"),
                                plugin["display_name"].as_str().unwrap_or("?"),
                                installation["id"].as_str().unwrap_or("?"),
                                installation["world"]
                                    .as_str()
                                    .or_else(|| plugin["world"].as_str())
                                    .unwrap_or("?")
                            );
                            for version in entry["versions"].as_array().unwrap_or(&vec![]) {
                                println!(
                                    "    version {}  digest={}  state={}",
                                    version["version"].as_str().unwrap_or("?"),
                                    version["digest"]
                                        .as_str()
                                        .unwrap_or("?")
                                        .chars()
                                        .take(12)
                                        .collect::<String>(),
                                    version["state"].as_str().unwrap_or("?")
                                );
                            }
                        }
                    }
                }
                HostedCmd::Stage { file } => {
                    let bytes = std::fs::read(file)
                        .with_context(|| format!("Cannot read {}", file.display()))?;
                    let staged = api.stage_artifact(&bytes).await?;
                    println!(
                        "Staged {} bytes",
                        staged["size_bytes"].as_u64().unwrap_or(0)
                    );
                    println!("Digest:    {}", staged["digest"].as_str().unwrap_or("?"));
                    println!(
                        "ObjectKey: {}",
                        staged["object_key"].as_str().unwrap_or("?")
                    );
                }
                HostedCmd::Upload {
                    file,
                    slug,
                    display_name,
                    version,
                    world,
                    wit_version,
                    description,
                    capability,
                    config_schema,
                } => {
                    let bytes = std::fs::read(file)
                        .with_context(|| format!("Cannot read {}", file.display()))?;
                    let staged = api.stage_artifact(&bytes).await?;
                    let digest = staged["digest"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("artifact staging returned no digest"))?
                        .to_string();
                    let object_key = staged["object_key"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("artifact staging returned no object key"))?
                        .to_string();
                    let config_schema = match &config_schema {
                        Some(path) => {
                            let raw = std::fs::read_to_string(path)
                                .with_context(|| format!("Cannot read {}", path.display()))?;
                            let schema: serde_json::Value = serde_json::from_str(&raw)
                                .with_context(|| {
                                    format!("Invalid JSON config schema in {}", path.display())
                                })?;
                            Some(schema)
                        }
                        None => None,
                    };
                    let body = serde_json::json!({
                        "slug": slug,
                        "display_name": display_name,
                        "description": description,
                        "version": version,
                        "world": world,
                        "wit_version": wit_version,
                        "digest": digest,
                        "artifact_object_key": object_key,
                        "capability_requests": capability,
                        "config_schema": config_schema,
                    });
                    let created: serde_json::Value = api.post(&["filter-plugins"], &body).await?;
                    println!(
                        "Uploaded {}: plugin={} version={} validation_run={}",
                        slug,
                        created["plugin_id"].as_str().unwrap_or("?"),
                        created["version_id"].as_str().unwrap_or("?"),
                        created["validation_run_id"].as_str().unwrap_or("?")
                    );
                    println!(
                        "Poll with: {} hosted --workspace {} validation {}",
                        cli.program.name(),
                        api.workspace,
                        created["version_id"].as_str().unwrap_or("?")
                    );
                }
                HostedCmd::Validation { version_id } => {
                    let value: serde_json::Value = api
                        .get(&["filter-plugin-versions", version_id, "validation"])
                        .await?;
                    let version = &value["version"];
                    println!(
                        "Version {} (world {})",
                        version["version"].as_str().unwrap_or("?"),
                        version["wit_world"].as_str().unwrap_or("?")
                    );
                    let runs = value["runs"].as_array().cloned().unwrap_or_default();
                    if runs.is_empty() {
                        println!("No validation runs yet.");
                    } else {
                        for run in &runs {
                            let state = run["state"].as_str().unwrap_or("?");
                            let diagnostic = run["diagnostic_code"]
                                .as_str()
                                .and_then(|code| {
                                    run["diagnostic_message"]
                                        .as_str()
                                        .map(|msg| format!("{code}: {msg}"))
                                })
                                .unwrap_or_else(|| "ok".to_string());
                            println!(
                                "run {}  state={}  {}",
                                run["id"].as_str().unwrap_or("?"),
                                state,
                                if state == "succeeded" {
                                    "succeeded"
                                } else {
                                    &diagnostic
                                }
                            );
                        }
                    }
                }
                HostedCmd::Grant {
                    installation_id,
                    capability,
                    version_id,
                } => {
                    let body = serde_json::json!({ "version_id": version_id });
                    api.put_unit(
                        &[
                            "filter-installations",
                            installation_id,
                            "capabilities",
                            capability,
                        ],
                        &body,
                    )
                    .await?;
                    println!("Capability {capability} granted on installation {installation_id}.");
                }
                HostedCmd::Revoke {
                    installation_id,
                    capability,
                    version_id,
                } => {
                    let body = serde_json::json!({ "version_id": version_id });
                    api.delete_unit(
                        &[
                            "filter-installations",
                            installation_id,
                            "capabilities",
                            capability,
                        ],
                        &body,
                    )
                    .await?;
                    println!("Capability {capability} revoked on installation {installation_id}.");
                }
                HostedCmd::Pipelines { cmd } => match cmd {
                    HostedPipelineCmd::List => {
                        let value: serde_json::Value = api.get(&["filter-pipelines"]).await?;
                        let pipelines = value["pipelines"].as_array().cloned().unwrap_or_default();
                        if pipelines.is_empty() {
                            println!("No pipelines.");
                        } else {
                            for pipeline in &pipelines {
                                let active = pipeline["active_revision_id"].as_str().unwrap_or("-");
                                println!(
                                    "{}  {}  {}  active_revision={}",
                                    pipeline["id"].as_str().unwrap_or("?"),
                                    pipeline["direction"].as_str().unwrap_or("?"),
                                    pipeline["name"].as_str().unwrap_or("?"),
                                    active
                                );
                                for revision in pipeline["published_revisions"]
                                    .as_array()
                                    .unwrap_or(&vec![])
                                {
                                    let passthrough =
                                        revision["explicit_passthrough"].as_bool().unwrap_or(false);
                                    println!(
                                        "    rev {}  published_at={}  passthrough={}",
                                        revision["revision_no"].as_u64().unwrap_or(0),
                                        revision["published_at"].as_str().unwrap_or("?"),
                                        passthrough
                                    );
                                }
                            }
                        }
                    }
                    HostedPipelineCmd::Create { direction, name } => {
                        let body = serde_json::json!({ "direction": direction, "name": name });
                        let created: serde_json::Value =
                            api.post(&["filter-pipelines"], &body).await?;
                        println!(
                            "Created pipeline {} (draft revision {})",
                            created["pipeline"]["id"].as_str().unwrap_or("?"),
                            created["draft_revision"]["id"].as_str().unwrap_or("?")
                        );
                    }
                    HostedPipelineCmd::Draft {
                        pipeline_id,
                        passthrough,
                        steps,
                    } => {
                        let parsed = steps
                            .iter()
                            .map(|raw| parse_draft_step(raw))
                            .collect::<anyhow::Result<Vec<_>>>()?;
                        let body = serde_json::json!({
                            "explicit_passthrough": passthrough,
                            "steps": parsed,
                        });
                        let updated: serde_json::Value = api
                            .put(&["filter-pipelines", pipeline_id, "draft"], &body)
                            .await?;
                        println!(
                            "Draft updated: revision {} fingerprint={} steps={}",
                            updated["revision_id"].as_str().unwrap_or("?"),
                            updated["fingerprint"].as_str().unwrap_or("?"),
                            updated["steps"].as_u64().unwrap_or(0)
                        );
                    }
                    HostedPipelineCmd::Publish { pipeline_id } => {
                        let body = serde_json::json!({});
                        let published: serde_json::Value = api
                            .post(&["filter-pipelines", pipeline_id, "publish"], &body)
                            .await?;
                        println!(
                            "Published revision {} (revision_no {}) fingerprint={}",
                            published["revision_id"].as_str().unwrap_or("?"),
                            published["revision_no"].as_u64().unwrap_or(0),
                            published["fingerprint"].as_str().unwrap_or("?")
                        );
                    }
                    HostedPipelineCmd::Rollback {
                        pipeline_id,
                        revision_id,
                    } => {
                        let body = serde_json::json!({});
                        let rolled_back: serde_json::Value = api
                            .post(
                                &["filter-pipelines", pipeline_id, "rollback", revision_id],
                                &body,
                            )
                            .await?;
                        println!(
                            "Rolled back to revision {} (revision_no {}) fingerprint={}",
                            rolled_back["revision_id"].as_str().unwrap_or("?"),
                            rolled_back["revision_no"].as_u64().unwrap_or(0),
                            rolled_back["fingerprint"].as_str().unwrap_or("?")
                        );
                    }
                },
                HostedCmd::Assignments => {
                    let value: serde_json::Value = api.get(&["filter-assignments"]).await?;
                    let assignments = value["assignments"].as_array().cloned().unwrap_or_default();
                    let scopes = value["bucket_scopes"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    if assignments.is_empty() {
                        println!("No assignments (workspace defaults inherit).");
                    } else {
                        for assignment in &assignments {
                            let scope_id = assignment["bucket_scope_id"].as_str().unwrap_or("-");
                            println!(
                                "{}  pipeline={}  scope={}",
                                assignment["direction"].as_str().unwrap_or("?"),
                                assignment["pipeline_id"].as_str().unwrap_or("?"),
                                scope_id
                            );
                        }
                    }
                    for scope in &scopes {
                        println!(
                            "bucket scope {} = {}",
                            scope["id"].as_str().unwrap_or("?"),
                            scope["bucket_name"].as_str().unwrap_or("?")
                        );
                    }
                }
                HostedCmd::AssignDefault {
                    direction,
                    pipeline_id,
                } => {
                    let body = serde_json::json!({ "pipeline_id": pipeline_id });
                    let _: serde_json::Value = api
                        .put(&["filter-assignments", direction, "default"], &body)
                        .await?;
                    println!("Default {direction} pipeline set to {pipeline_id}.");
                }
                HostedCmd::AssignBucket {
                    direction,
                    bucket,
                    pipeline_id,
                } => {
                    let body = serde_json::json!({ "pipeline_id": pipeline_id });
                    let _: serde_json::Value = api
                        .put(&["filter-assignments", direction, "buckets", bucket], &body)
                        .await?;
                    println!("{direction} pipeline {pipeline_id} assigned to bucket {bucket}.");
                }
                HostedCmd::UnassignBucket { direction, bucket } => {
                    let body = serde_json::json!({});
                    api.delete_unit(&["filter-assignments", direction, "buckets", bucket], &body)
                        .await?;
                    println!("Removed {direction} assignment for bucket {bucket}.");
                }
                HostedCmd::Audit { limit } => {
                    let query = limit
                        .map(|limit| vec![("limit", limit.to_string())])
                        .unwrap_or_default();
                    let value: serde_json::Value =
                        api.get_with_query(&["filter-audit"], &query).await?;
                    let events = value["events"].as_array().cloned().unwrap_or_default();
                    if events.is_empty() {
                        println!("No audit events.");
                    } else {
                        for event in &events {
                            println!(
                                "{}  {}  {}",
                                event["created_at"].as_str().unwrap_or("?"),
                                event["action"].as_str().unwrap_or("?"),
                                event["actor_user_id"].as_str().unwrap_or("?")
                            );
                        }
                    }
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
            let gateway = cli.requested_gateway();
            let resp = reqwest::get(format!("{gateway}/health")).await?;
            if resp.status().is_success() {
                println!("Maskura Gateway is healthy at {gateway}");
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
            // Pin the gateway image to the CLI version (v0.3.3 image for
            // maskura 0.3.3) so CLI and gateway always match; never :latest.
            let local_gateway_image = format!(
                "ghcr.io/231self/maskura/maskura:v{}",
                env!("CARGO_PKG_VERSION")
            );

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
                            "MASKURA_KEYS_FILE=/app/data/keys.json",
                            &local_gateway_image,
                        ])
                        .status()?;
                    if !run_status.success() {
                        bail!(
                            "failed to start gateway container — is {local_gateway_image} pullable? \
                             (the image tag must match the {} version; has v{} been released?)",
                            cli.program.name(),
                            env!("CARGO_PKG_VERSION")
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

                    println!("Maskura Gateway is running locally (published image).");
                    println!("  Gateway: {url}");
                    println!("  Storage: in-memory (durable MinIO via `just dev-up` in the repo)");
                    println!("  Keys:    persisted in the s4-local-keys volume");
                    println!();
                    println!("Quickstart:");
                    println!(
                        "  {} put ./data.csv ingest/data.csv --bucket s4-local",
                        cli.program.name()
                    );
                    println!(
                        "  {} get ingest/data.csv --bucket s4-local",
                        cli.program.name()
                    );
                    println!();
                    println!("Stop with: {} local down", cli.program.name());
                }
                LocalCmd::Down => {
                    let status = std::process::Command::new("docker")
                        .args(["rm", "-f", LOCAL_GATEWAY_NAME])
                        .status()?;
                    if status.success() {
                        println!("Maskura Gateway stopped locally.");
                    } else {
                        println!("Maskura Gateway is not running locally.");
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
                    gateway: cli.requested_gateway().to_string(),
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
                        .header("Content-Type", "text/plain")
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
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn success_server(body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 16 * 1024];
            let read = socket.read(&mut request).await.unwrap();
            request.truncate(read);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (format!("http://{address}"), task)
    }

    #[test]
    fn parse_draft_step_accepts_installation_and_version() {
        let step = parse_draft_step("install-1:version-2").unwrap();
        assert_eq!(step["installation_id"], "install-1");
        assert_eq!(step["plugin_version_id"], "version-2");
        assert!(step["config_json"].is_null());
    }

    #[test]
    fn parse_draft_step_reads_config_file() {
        let dir = std::env::temp_dir().join(format!(
            "s4ctl-step-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.json");
        std::fs::write(&config, r#"{"field": "pii"}"#).unwrap();
        let raw = format!("install-1:version-2:{}", config.display());
        let step = parse_draft_step(&raw).unwrap();
        assert_eq!(step["config_json"]["field"], "pii");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_draft_step_rejects_malformed_input() {
        assert!(parse_draft_step("only-one-part").is_err());
        assert!(parse_draft_step("a:b:c:d").is_err());
        assert!(parse_draft_step("").is_err());
    }

    #[test]
    fn hosted_api_path_scopes_to_the_workspace() {
        let api = HostedApi::new("http://localhost:9000/", "ws-abc", "token").unwrap();
        assert_eq!(
            api.path(&["filter-catalog"]).unwrap().as_str(),
            "http://localhost:9000/dashboard/api/workspaces/ws-abc/filter-catalog"
        );
    }

    #[test]
    fn hosted_api_percent_encodes_every_dynamic_path_segment() {
        let api = HostedApi::new("https://api.example/base", "ws/abc", "token").unwrap();
        assert_eq!(
            api.path(&["filter-assignments", "read/write", "buckets", "bucket name"])
                .unwrap()
                .as_str(),
            "https://api.example/base/dashboard/api/workspaces/ws%2Fabc/filter-assignments/read%2Fwrite/buckets/bucket%20name"
        );
    }

    #[test]
    fn hosted_token_is_never_fallback_to_data_plane_keys() {
        let api = HostedApi::new("http://localhost:9000", "ws-abc", "secret-token").unwrap();
        let headers = api.auth_headers().unwrap();
        assert_eq!(
            headers.get("Authorization").unwrap().to_str().unwrap(),
            "Bearer secret-token"
        );
        assert!(headers.get("x-maskura-access-key").is_none());
        assert!(headers.get("x-s4-access-key").is_none());
    }

    #[tokio::test]
    async fn hosted_unit_mutations_accept_text_and_empty_success_bodies() {
        let (gateway, put_request) = success_server("capability granted").await;
        let api = HostedApi::new(&gateway, "ws-abc", "secret-token").unwrap();
        api.put_unit(
            &[
                "filter-installations",
                "install-1",
                "capabilities",
                "stable_fields",
            ],
            &serde_json::json!({"version_id": "version-1"}),
        )
        .await
        .unwrap();
        let request = put_request.await.unwrap();
        assert!(request.starts_with("PUT /dashboard/api/workspaces/ws-abc/"));
        assert!(request.contains("authorization: Bearer secret-token\r\n"));

        let (gateway, delete_request) = success_server("").await;
        let api = HostedApi::new(&gateway, "ws-abc", "secret-token").unwrap();
        api.delete_unit(
            &["filter-assignments", "write", "buckets", "bucket-a"],
            &serde_json::json!({}),
        )
        .await
        .unwrap();
        let request = delete_request.await.unwrap();
        assert!(request.starts_with("DELETE /dashboard/api/workspaces/ws-abc/"));
    }

    #[test]
    fn executable_names_select_canonical_and_legacy_program_labels() {
        assert_eq!(
            Program::from_executable(std::ffi::OsStr::new("/tmp/maskura")),
            Program::Maskura
        );
        assert_eq!(
            Program::from_executable(std::ffi::OsStr::new("/tmp/s4ctl")),
            Program::S4ctl
        );
        assert_eq!(Program::Maskura.name(), "maskura");
        assert_eq!(Program::S4ctl.name(), "s4ctl");
    }

    #[test]
    fn hosted_env_names_are_canonical_with_permanent_legacy_aliases() {
        assert_eq!(HOSTED_WORKSPACE_ID_ENV.canonical, "MASKURA_WORKSPACE_ID");
        assert_eq!(HOSTED_WORKSPACE_ID_ENV.legacy, "S4_WORKSPACE_ID");
        assert_eq!(HOSTED_ACCESS_TOKEN_ENV.canonical, "MASKURA_ACCESS_TOKEN");
        assert_eq!(HOSTED_ACCESS_TOKEN_ENV.legacy, "S4_ACCESS_TOKEN");
    }
}
