//! Documentation contract test: the repo-root SECURITY.md must exist, contain
//! the required sections, and never leak private deployment details.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/gateway -> crates -> repo root (SECURITY.md lives at the root).
    for ancestor in manifest_dir.ancestors() {
        if ancestor.join("SECURITY.md").is_file() {
            return ancestor.to_path_buf();
        }
    }
    panic!(
        "SECURITY.md not found above CARGO_MANIFEST_DIR ({})",
        manifest_dir.display()
    );
}

fn security_doc() -> String {
    let path = repo_root().join("SECURITY.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn lower(content: &str) -> String {
    content.to_ascii_lowercase()
}

#[test]
fn security_doc_exists_at_repo_root() {
    let path = repo_root().join("SECURITY.md");
    assert!(path.is_file(), "missing {}", path.display());
}

#[test]
fn security_doc_has_supported_versions_section() {
    let content = security_doc();
    assert!(
        lower(&content).contains("supported versions"),
        "SECURITY.md must contain a 'Supported Versions' section"
    );
}

#[test]
fn security_doc_has_reporting_section() {
    let content = security_doc();
    assert!(
        lower(&content).contains("reporting"),
        "SECURITY.md must contain a 'Reporting' section"
    );
}

#[test]
fn security_doc_offers_private_reporting_channels() {
    let content = lower(&security_doc());
    assert!(
        content.contains("github private vulnerability reporting"),
        "SECURITY.md must reference GitHub private vulnerability reporting"
    );
    assert!(
        content.contains("security@231self.com"),
        "SECURITY.md must list security@231self.com"
    );
}

#[test]
fn security_doc_leaks_no_private_deployment_details() {
    let content = lower(&security_doc());
    let forbidden: Vec<(&str, &str)> = vec![
        ("1Password reference", "op://"),
        ("AWS access key assignment", "aws_access_key_id="),
        ("AWS secret key assignment", "aws_secret_access_key="),
        ("presigned URL signature", "x-amz-signature="),
        ("presigned URL credential", "x-amz-credential="),
        ("private hostname suffix", ".internal"),
        ("Supabase project ref", "ejbirxbgbsdmwgqtexmi"),
        ("account ID field", "account_id"),
    ];
    for (label, needle) in forbidden {
        assert!(
            !content.contains(needle),
            "SECURITY.md must not contain {label} ({needle:?})"
        );
    }
}

#[test]
fn security_doc_does_not_contain_aws_account_id_shaped_numbers() {
    // A 12-digit run is the shape of an AWS account ID. Guard against a
    // future edit pasting one in.
    let content = security_doc();
    let has_12_digit_run = content
        .split(|character: char| !character.is_ascii_digit())
        .any(|token| token.len() == 12);
    assert!(
        !has_12_digit_run,
        "SECURITY.md must not contain a 12-digit (AWS account ID shaped) number"
    );
}

#[test]
fn security_doc_links_nothing_that_needs_resolution() {
    // The security contract is self-contained markdown with no code fences
    // that could smuggle credentials or configuration examples.
    let content = security_doc();
    assert!(
        !content.contains("aws configure"),
        "SECURITY.md must not contain credential configuration examples"
    );
}

#[test]
fn docs_security_links_to_security_doc() {
    let path = repo_root().join("docs").join("security.md");
    assert!(path.is_file(), "missing {}", path.display());
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        lower(&content).contains("security.md"),
        "docs/security.md must link to SECURITY.md"
    );
}

#[test]
fn readme_links_to_security_doc() {
    let path = repo_root().join("README.md");
    assert!(path.is_file(), "missing {}", path.display());
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        lower(&content).contains("security.md"),
        "README.md must link to SECURITY.md"
    );
}
