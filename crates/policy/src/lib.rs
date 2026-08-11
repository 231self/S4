use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use s4_error::{S4Error, codes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyManifest {
    pub schema_version: u32,
    pub workspace_id: String,
    pub manifest_id: String,
    pub version: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub gateway_releases: Vec<String>,
    pub destination_id: String,
    pub encrypted_credential_version: u32,
    pub bucket_aliases: Vec<String>,
    pub routes: Vec<PolicyRoute>,
    pub content_types: Vec<String>,
    pub formats: Vec<String>,
    pub filters: Vec<FilterRef>,
    pub limits: PolicyLimits,
    pub signer_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRoute {
    pub prefix: String,
    pub fail: FailBehavior,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterRef {
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyLimits {
    pub record_max_bytes: u64,
    pub object_max_bytes: u64,
    pub memory_bytes: u64,
    pub fuel: u64,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailBehavior {
    Reject,
}

#[derive(Debug, Clone)]
pub struct SignedManifest {
    pub body: Vec<u8>,
    pub signer_id: String,
    pub signature: Vec<u8>,
}

fn vec_to_cbor(v: &[String]) -> Value {
    Value::Array(v.iter().map(|s| Value::Text(s.clone())).collect())
}

fn fail_to_cbor(fb: FailBehavior) -> Value {
    match fb {
        FailBehavior::Reject => Value::Text("reject".to_string()),
    }
}

fn route_to_cbor(r: &PolicyRoute) -> Value {
    let mut m = BTreeMap::new();
    m.insert("fail".to_string(), fail_to_cbor(r.fail));
    m.insert("prefix".to_string(), Value::Text(r.prefix.clone()));
    btree_to_cbor_value(m)
}

fn filter_ref_to_cbor(f: &FilterRef) -> Value {
    let mut m = BTreeMap::new();
    m.insert("sha256".to_string(), Value::Text(f.sha256.clone()));
    if let Some(ref h) = f.config_hash {
        m.insert("config_hash".to_string(), Value::Text(h.clone()));
    }
    btree_to_cbor_value(m)
}

fn limits_to_cbor(l: &PolicyLimits) -> Value {
    let mut m: BTreeMap<String, Value> = BTreeMap::new();
    m.insert(
        "deadline_ms".to_string(),
        Value::Integer(l.deadline_ms.into()),
    );
    m.insert("fuel".to_string(), Value::Integer(l.fuel.into()));
    m.insert(
        "memory_bytes".to_string(),
        Value::Integer(l.memory_bytes.into()),
    );
    m.insert(
        "object_max_bytes".to_string(),
        Value::Integer(l.object_max_bytes.into()),
    );
    m.insert(
        "record_max_bytes".to_string(),
        Value::Integer(l.record_max_bytes.into()),
    );
    btree_to_cbor_value(m)
}

fn btree_to_cbor_value(m: BTreeMap<String, Value>) -> Value {
    Value::Map(m.into_iter().map(|(k, v)| (Value::Text(k), v)).collect())
}

impl PolicyManifest {
    pub fn encode_canonical(&self) -> Vec<u8> {
        let value = self.to_canonical_value();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf)
            .expect("ciborium serialization of canonical value should not fail");
        buf
    }

    fn to_canonical_value(&self) -> Value {
        let routes_cbor = Value::Array(self.routes.iter().map(route_to_cbor).collect());
        let filters_cbor = Value::Array(self.filters.iter().map(filter_ref_to_cbor).collect());

        let mut m: BTreeMap<String, Value> = BTreeMap::new();
        m.insert("bucket_aliases".into(), vec_to_cbor(&self.bucket_aliases));
        m.insert("content_types".into(), vec_to_cbor(&self.content_types));
        m.insert(
            "destination_id".into(),
            Value::Text(self.destination_id.clone()),
        );
        m.insert(
            "encrypted_credential_version".into(),
            Value::Integer(self.encrypted_credential_version.into()),
        );
        m.insert("expires_at".into(), Value::Integer(self.expires_at.into()));
        m.insert("filters".into(), filters_cbor);
        m.insert("formats".into(), vec_to_cbor(&self.formats));
        m.insert(
            "gateway_releases".into(),
            vec_to_cbor(&self.gateway_releases),
        );
        m.insert("limits".into(), limits_to_cbor(&self.limits));
        m.insert("manifest_id".into(), Value::Text(self.manifest_id.clone()));
        m.insert("not_before".into(), Value::Integer(self.not_before.into()));
        m.insert("routes".into(), routes_cbor);
        m.insert(
            "schema_version".into(),
            Value::Integer(self.schema_version.into()),
        );
        m.insert("signer_id".into(), Value::Text(self.signer_id.clone()));
        m.insert("version".into(), Value::Integer(self.version.into()));
        m.insert(
            "workspace_id".into(),
            Value::Text(self.workspace_id.clone()),
        );
        btree_to_cbor_value(m)
    }

    pub fn decode_canonical(body: &[u8]) -> Result<Self, S4Error> {
        ciborium::de::from_reader(body)
            .map_err(|e| S4Error::new(codes::POLICY_TAMPERED, format!("CBOR decode failed: {e}")))
    }

    pub fn sign(&self, signing_key: &SigningKey) -> SignedManifest {
        let body = self.encode_canonical();
        let signature = signing_key.sign(&body);
        SignedManifest {
            body,
            signer_id: self.signer_id.clone(),
            signature: signature.to_bytes().to_vec(),
        }
    }
}

impl SignedManifest {
    pub fn verify(
        &self,
        trust_roots: &BTreeMap<String, VerifyingKey>,
    ) -> Result<PolicyManifest, S4Error> {
        let vk = trust_roots.get(&self.signer_id).ok_or_else(|| {
            S4Error::new(
                codes::POLICY_TAMPERED,
                format!("unknown signer: {}", self.signer_id),
            )
        })?;
        let sig = Signature::from_slice(&self.signature);
        let sig = sig.map_err(|e| S4Error::new(codes::POLICY_TAMPERED, e.to_string()))?;
        vk.verify_strict(&self.body, &sig).map_err(|e| {
            S4Error::new(
                codes::POLICY_TAMPERED,
                format!("signature verification failed: {e}"),
            )
        })?;
        let manifest = PolicyManifest::decode_canonical(&self.body)?;
        Ok(manifest)
    }

    pub fn decode_only(&self) -> Result<PolicyManifest, S4Error> {
        PolicyManifest::decode_canonical(&self.body)
    }
}

pub fn generate_signing_key() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let mut secret_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_bytes);
    let sk = SigningKey::from_bytes(&secret_bytes);
    let vk = sk.verifying_key();
    (sk, vk)
}

impl PolicyManifest {
    pub fn example() -> Self {
        let workspace_id = uuid::Uuid::new_v4().to_string();
        PolicyManifest {
            schema_version: 1,
            workspace_id: workspace_id.clone(),
            manifest_id: uuid::Uuid::new_v4().to_string(),
            version: 1,
            not_before: 1700000000,
            expires_at: 1800000000,
            gateway_releases: vec!["release-v1".into()],
            destination_id: uuid::Uuid::new_v4().to_string(),
            encrypted_credential_version: 1,
            bucket_aliases: vec!["my-bucket".into()],
            routes: vec![PolicyRoute {
                prefix: "data/".into(),
                fail: FailBehavior::Reject,
            }],
            content_types: vec!["application/json".into(), "text/csv".into()],
            formats: vec!["json".into(), "csv".into(), "jsonl".into(), "text".into()],
            filters: vec![FilterRef {
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                config_hash: None,
            }],
            limits: PolicyLimits {
                record_max_bytes: 10_485_760,
                object_max_bytes: 1_073_741_824,
                memory_bytes: 67_108_864,
                fuel: 10_000_000,
                deadline_ms: 30_000,
            },
            signer_id: "signer-1".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_manifest(id: u64) -> PolicyManifest {
        let mut m = PolicyManifest::example();
        m.version = id;
        m.manifest_id = format!("manifest-{id}");
        m.expires_at = 1800000000;
        m.not_before = 1700000000;
        m
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let m = make_manifest(1);
        let a = m.encode_canonical();
        let b = m.encode_canonical();
        assert_eq!(a, b, "same manifest must produce identical bytes");
    }

    #[test]
    fn canonical_encoding_differs_between_versions() {
        let m1 = make_manifest(1);
        let m2 = make_manifest(2);
        assert_ne!(
            m1.encode_canonical(),
            m2.encode_canonical(),
            "different versions must produce different bytes"
        );
    }

    #[test]
    fn canonical_encoding_differs_between_workspaces() {
        let mut m1 = make_manifest(1);
        let mut m2 = make_manifest(1);
        m1.workspace_id = "ws-a".into();
        m2.workspace_id = "ws-b".into();
        assert_ne!(m1.encode_canonical(), m2.encode_canonical());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let m = make_manifest(1);
        let (sk, vk) = generate_signing_key();
        let signer_id = m.signer_id.clone();

        let mut m = m;
        m.signer_id = signer_id.clone();

        let signed = m.sign(&sk);
        assert_eq!(signed.signer_id, signer_id);
        assert_eq!(signed.signature.len(), 64);

        let mut roots = BTreeMap::new();
        roots.insert(signer_id.clone(), vk);
        let decoded = signed.verify(&roots).expect("verification must succeed");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.manifest_id, m.manifest_id);
    }

    #[test]
    fn verify_rejects_unknown_signer() {
        let m = make_manifest(1);
        let (sk, _vk) = generate_signing_key();
        let signed = m.sign(&sk);
        let err = signed.verify(&BTreeMap::new()).unwrap_err();
        assert!(err.message().contains("unknown signer"));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let m = make_manifest(1);
        let (sk, vk) = generate_signing_key();
        let signer_id = m.signer_id.clone();

        let mut m = m;
        m.signer_id = signer_id.clone();
        let mut signed = m.sign(&sk);

        signed.body[0] ^= 0xff;

        let mut roots = BTreeMap::new();
        roots.insert(signer_id, vk);
        let err = signed.verify(&roots).unwrap_err();
        assert!(err.code() == codes::POLICY_TAMPERED || err.message().contains("signature"));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let m = make_manifest(1);
        let (sk1, _) = generate_signing_key();
        let (_sk2, vk2) = generate_signing_key();
        let signer_id = "signer-x".to_string();

        let mut m = m;
        m.signer_id = signer_id.clone();
        let signed = m.sign(&sk1);

        let mut roots = BTreeMap::new();
        roots.insert(signer_id, vk2);
        let err = signed.verify(&roots).unwrap_err();
        assert!(
            err.message().contains("signature"),
            "expected signature error, got: {err}"
        );
    }

    #[test]
    fn cbor_decode_roundtrip() {
        let m = make_manifest(42);
        let encoded = m.encode_canonical();
        let decoded = PolicyManifest::decode_canonical(&encoded).expect("decode must succeed");
        assert_eq!(decoded, m);
    }

    #[test]
    fn decode_rejects_garbage() {
        let err = PolicyManifest::decode_canonical(b"not cbor at all").unwrap_err();
        assert_eq!(err.code(), codes::POLICY_TAMPERED);
    }

    #[test]
    fn canonical_encoding_keys_are_sorted() {
        let m = make_manifest(1);
        let encoded = m.encode_canonical();

        let value: Value = ciborium::de::from_reader(&encoded[..]).unwrap();
        let entries = match value {
            Value::Map(entries) => entries,
            _ => panic!("expected map"),
        };
        let keys: Vec<String> = entries
            .iter()
            .map(|(k, _)| match k {
                Value::Text(s) => s.clone(),
                _ => panic!("expected text key"),
            })
            .collect();

        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "canonical encoding must have sorted map keys");
    }

    #[test]
    fn encode_canonical_is_stable_across_struct_orderings() {
        let m1 = make_manifest(1);
        let m2 = m1.clone();
        assert_eq!(m1.encode_canonical(), m2.encode_canonical());
    }

    #[test]
    fn signed_manifest_roundtrip_maintains_body() {
        let m = make_manifest(1);
        let (sk, vk) = generate_signing_key();
        let signer_id = m.signer_id.clone();
        let mut m = m;
        m.signer_id = signer_id.clone();
        let signed = m.sign(&sk);

        let mut roots = BTreeMap::new();
        roots.insert(signer_id, vk);
        let decoded = signed.verify(&roots).unwrap();
        assert_eq!(decoded.clone().encode_canonical(), signed.body);
    }

    #[test]
    fn uuid_and_id_roundtrip_preserved() {
        let m = make_manifest(1);
        let encoded = m.encode_canonical();
        let decoded = PolicyManifest::decode_canonical(&encoded).unwrap();
        assert_eq!(decoded.workspace_id, m.workspace_id);
        assert_eq!(decoded.destination_id, m.destination_id);
    }
}
