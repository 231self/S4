use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;

const WORKSPACE: &str = "workspace/encoded";
const TOKEN: &str = "hosted-contract-token";
const BASE_PATH: &str = "/dashboard/api/workspaces/workspace%2Fencoded";
const ARTIFACT: &[u8] = b"contract-wasm";

struct Request {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Expected {
    method: &'static str,
    target: String,
    json_body: Option<Value>,
    raw_body: Option<&'static [u8]>,
    content_type: Option<&'static str>,
    response_status: &'static str,
    response_body: Value,
}

impl Expected {
    fn get(path: &str, response_body: Value) -> Self {
        Self::new("GET", path, response_body)
    }

    fn json(method: &'static str, path: &str, body: Value, response_body: Value) -> Self {
        let mut expected = Self::new(method, path, response_body);
        expected.json_body = Some(body);
        expected.content_type = Some("application/json");
        expected
    }

    fn wasm(path: &str, response_body: Value) -> Self {
        let mut expected = Self::new("POST", path, response_body);
        expected.raw_body = Some(ARTIFACT);
        expected.content_type = Some("application/wasm");
        expected
    }

    fn new(method: &'static str, path: &str, response_body: Value) -> Self {
        Self {
            method,
            target: format!("{BASE_PATH}{path}"),
            json_body: None,
            raw_body: None,
            content_type: None,
            response_status: "200 OK",
            response_body,
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Request {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).unwrap();
        assert_ne!(read, 0, "connection closed before request headers");
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end]).unwrap();
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines.next().unwrap().split_whitespace();
    let method = request_line.next().unwrap().to_string();
    let target = request_line.next().unwrap().to_string();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect::<HashMap<_, _>>();
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(0);
    while bytes.len() - header_end < content_length {
        let read = stream.read(&mut chunk).unwrap();
        assert_ne!(read, 0, "connection closed before request body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    Request {
        method,
        target,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

fn serve(expectations: Vec<Expected>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        for expected in expectations {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert_eq!(request.method, expected.method);
            assert_eq!(request.target, expected.target);
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bearer hosted-contract-token")
            );
            assert!(!request.headers.contains_key("x-maskura-access-key"));
            assert!(!request.headers.contains_key("x-maskura-secret-key"));
            assert!(!request.headers.contains_key("x-s4-access-key"));
            assert!(!request.headers.contains_key("x-s4-secret-key"));
            assert!(!request.target.contains(TOKEN));
            assert!(!String::from_utf8_lossy(&request.body).contains(TOKEN));
            if let Some(content_type) = expected.content_type {
                assert_eq!(
                    request.headers.get("content-type").map(String::as_str),
                    Some(content_type)
                );
            }
            if let Some(body) = expected.json_body {
                assert_eq!(
                    serde_json::from_slice::<Value>(&request.body).unwrap(),
                    body
                );
            }
            if let Some(body) = expected.raw_body {
                assert_eq!(request.body, body);
            }

            let body = serde_json::to_vec(&expected.response_body).unwrap();
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                expected.response_status,
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    (format!("http://{address}"), task)
}

fn run_hosted(binary: &str, gateway: &str, args: &[&str], legacy_env: bool) -> Output {
    let mut command = Command::new(binary);
    command
        .args(["--gateway", gateway, "hosted"])
        .env_remove("MASKURA_WORKSPACE_ID")
        .env_remove("MASKURA_ACCESS_TOKEN")
        .env_remove("S4_WORKSPACE_ID")
        .env_remove("S4_ACCESS_TOKEN");
    if legacy_env {
        command
            .env("S4_WORKSPACE_ID", WORKSPACE)
            .env("S4_ACCESS_TOKEN", TOKEN);
    } else {
        command.args(["--workspace", WORKSPACE, "--token", TOKEN]);
    }
    let output = command.args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{} {:?} failed:\nstdout: {}\nstderr: {}",
        binary,
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn output_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn artifact_file() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "maskura-hosted-contract-{}-{}.wasm",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, ARTIFACT).unwrap();
    path
}

fn pipelines_response() -> Value {
    json!({
        "pipelines": [{
            "id": "pipeline/1",
            "direction": "write",
            "name": "redact",
            "active_revision_id": null,
            "generation": 0,
            "draft_revision": {"id": "draft/1"},
            "published_revisions": []
        }]
    })
}

fn assignment_response(lock_version: Option<i64>) -> Value {
    match lock_version {
        Some(lock_version) => json!({
            "assignments": [{
                "id": "assignment/1",
                "direction": "write",
                "pipeline_id": "pipeline/1",
                "bucket_scope_id": "scope/1",
                "lock_version": lock_version
            }],
            "bucket_scopes": [{"id": "scope/1", "bucket_name": "bucket name/2026"}]
        }),
        None => json!({"assignments": [], "bucket_scopes": []}),
    }
}

#[test]
fn hosted_cli_contract_walkthrough() {
    let catalog = json!({
        "plugins": [{
            "plugin": {
                "id": "plugin/1",
                "display_name": "Contract Filter",
                "lifecycle_state": "active"
            },
            "installation": {"id": "install/1"},
            "versions": [{
                "id": "version/1",
                "version_label": "1.2.3",
                "artifact_digest": "abcdef0123456789",
                "lifecycle_state": "validated",
                "wit_world": "s4-filter@0.1.0"
            }]
        }]
    });
    let staged = json!({
        "digest": "artifact-digest",
        "object_key": "quarantine/artifact-digest",
        "size_bytes": ARTIFACT.len()
    });
    let expectations = vec![
        Expected::get("/filter-catalog", catalog),
        Expected::wasm("/filter-artifacts", staged.clone()),
        Expected::wasm("/filter-artifacts", staged),
        Expected::json(
            "POST",
            "/filter-plugins",
            json!({
                "slug": "contract-filter",
                "display_name": "Contract Filter",
                "description": null,
                "version": "1.2.3",
                "world": "s4-filter@0.1.0",
                "wit_version": "0.1.0",
                "digest": "artifact-digest",
                "artifact_object_key": "quarantine/artifact-digest",
                "capability_requests": ["stable_fields"],
                "config_schema": null
            }),
            json!({
                "plugin_id": "plugin/1",
                "version_id": "version/1",
                "installation_id": "install/1",
                "validation_run_id": "run/1"
            }),
        ),
        Expected::get(
            "/filter-plugin-versions/version%2F1/validation",
            json!({
                "version": {"version_label": "1.2.3", "wit_world": "s4-filter@0.1.0"},
                "runs": [{
                    "id": "run/1",
                    "state": "succeeded",
                    "diagnostic_code": null,
                    "diagnostic_message": null
                }]
            }),
        ),
        Expected::json(
            "PUT",
            "/filter-installations/install%2F1/capabilities/stable%20fields",
            json!({"version_id": "version/1"}),
            json!("capability granted"),
        ),
        Expected::json(
            "POST",
            "/filter-pipelines",
            json!({"direction": "write", "name": "redact"}),
            json!({"pipeline": {"id": "pipeline/1"}, "draft_revision": {"id": "draft/1"}}),
        ),
        Expected::get("/filter-pipelines", pipelines_response()),
        Expected::json(
            "PUT",
            "/filter-pipelines/pipeline%2F1/draft",
            json!({
                "draft_revision_id": "draft/1",
                "explicit_passthrough": false,
                "steps": [{
                    "installation_id": "install/1",
                    "plugin_version_id": "version/1",
                    "enabled": true,
                    "config_json": null
                }]
            }),
            json!({"revision_id": "draft/1", "fingerprint": "draft-fingerprint", "steps": 1}),
        ),
        Expected::get("/filter-pipelines", pipelines_response()),
        Expected::json(
            "POST",
            "/filter-pipelines/pipeline%2F1/publish",
            json!({"draft_revision_id": "draft/1"}),
            json!({"revision_id": "published/1", "revision_no": 1, "fingerprint": "published-fingerprint"}),
        ),
        Expected::get("/filter-assignments", assignment_response(None)),
        Expected::json(
            "PUT",
            "/filter-assignments/write/buckets/bucket%20name%2F2026",
            json!({"pipeline_id": "pipeline/1"}),
            json!({"assignment": {"lock_version": 1}}),
        ),
        Expected::get("/filter-assignments", assignment_response(Some(1))),
        Expected::json(
            "PUT",
            "/filter-assignments/write/buckets/bucket%20name%2F2026",
            json!({"pipeline_id": "pipeline/1", "lock_version": 1}),
            json!({"assignment": {"lock_version": 2}}),
        ),
        Expected::get("/filter-assignments", assignment_response(Some(2))),
        Expected::json(
            "DELETE",
            "/filter-assignments/write/buckets/bucket%20name%2F2026",
            json!({"lock_version": 2}),
            json!("bucket assignment deleted"),
        ),
        Expected::json(
            "POST",
            "/filter-pipelines/pipeline%2F1/rollback/revision%2Fold",
            json!({}),
            json!({"revision_id": "revision/old", "revision_no": 1, "fingerprint": "rollback-fingerprint"}),
        ),
        Expected::get(
            "/filter-audit?limit=25",
            json!({
                "events": [{
                    "created_at": "2026-09-01T16:00:00Z",
                    "event_type": "filter.pipeline.rollback",
                    "actor_user_id": "user/1"
                }]
            }),
        ),
    ];
    let (gateway, server) = serve(expectations);
    let artifact = artifact_file();
    let artifact_arg = artifact.to_str().unwrap();
    let maskura = env!("CARGO_BIN_EXE_maskura");
    let s4ctl = env!("CARGO_BIN_EXE_s4ctl");

    let catalog = run_hosted(maskura, &gateway, &["catalog"], false);
    assert!(output_text(&catalog).contains("version 1.2.3"));
    assert!(output_text(&catalog).contains("digest=abcdef012345"));
    assert!(output_text(&catalog).contains("state=validated"));

    let stage = run_hosted(maskura, &gateway, &["stage", artifact_arg], false);
    assert!(output_text(&stage).contains("Digest:    artifact-digest"));

    let upload = run_hosted(
        s4ctl,
        &gateway,
        &[
            "upload",
            artifact_arg,
            "--slug",
            "contract-filter",
            "--display-name",
            "Contract Filter",
            "--version",
            "1.2.3",
            "--capability",
            "stable_fields",
        ],
        true,
    );
    assert!(output_text(&upload).contains("validation_run=run/1"));

    let validation = run_hosted(maskura, &gateway, &["validation", "version/1"], false);
    assert!(output_text(&validation).contains("Version 1.2.3"));
    assert!(output_text(&validation).contains("run run/1  state=succeeded"));

    run_hosted(
        maskura,
        &gateway,
        &[
            "grant",
            "--installation-id",
            "install/1",
            "--capability",
            "stable fields",
            "--version-id",
            "version/1",
        ],
        false,
    );
    run_hosted(
        maskura,
        &gateway,
        &["pipelines", "create", "write", "redact"],
        false,
    );
    run_hosted(
        maskura,
        &gateway,
        &[
            "pipelines",
            "draft",
            "pipeline/1",
            "--step",
            "install/1:version/1",
        ],
        false,
    );
    run_hosted(
        maskura,
        &gateway,
        &["pipelines", "publish", "pipeline/1"],
        false,
    );
    let assignment_args = [
        "assign-bucket",
        "write",
        "bucket name/2026",
        "--pipeline-id",
        "pipeline/1",
    ];
    run_hosted(maskura, &gateway, &assignment_args, false);
    run_hosted(maskura, &gateway, &assignment_args, false);
    run_hosted(
        maskura,
        &gateway,
        &["unassign-bucket", "write", "bucket name/2026"],
        false,
    );
    run_hosted(
        maskura,
        &gateway,
        &["pipelines", "rollback", "pipeline/1", "revision/old"],
        false,
    );
    let audit = run_hosted(maskura, &gateway, &["audit", "--limit", "25"], false);
    assert!(output_text(&audit).contains("filter.pipeline.rollback"));

    std::fs::remove_file(artifact).unwrap();
    server.join().unwrap();
}
