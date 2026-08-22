//! Strict, header-first AWS Signature Version 4 authorization.
//!
//! Parsing, scope checks, canonical seed-signature verification, and payload
//! mode selection complete before a request body is polled.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation,
    SigningParams, SigningSettings, UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use axum::http::{HeaderMap, Uri};
use sha2::{Digest as _, Sha256};

use crate::integrity::{BodyVerifier, IntegrityError, StreamingSigning};

const DEFAULT_REGION: &str = "us-east-1";
const MAX_PRESIGN_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigV4Error {
    AmbiguousAuthentication,
    CacheUnavailable,
    ClockSkew,
    DuplicateHeader(&'static str),
    Expired,
    InvalidAuthorization,
    InvalidCredential,
    InvalidDate,
    InvalidPresign,
    InvalidScope,
    InvalidSignedHeaders,
    MissingHeader(&'static str),
    Payload(IntegrityError),
    SignatureMismatch,
}

impl fmt::Display for SigV4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousAuthentication => f.write_str("multiple SigV4 authentication modes"),
            Self::CacheUnavailable => f.write_str("signing-key cache unavailable"),
            Self::ClockSkew => f.write_str("request timestamp outside the allowed clock skew"),
            Self::DuplicateHeader(name) => write!(f, "duplicate {name} header"),
            Self::Expired => f.write_str("presigned request expired"),
            Self::InvalidAuthorization => f.write_str("malformed SigV4 authorization"),
            Self::InvalidCredential => f.write_str("malformed SigV4 credential"),
            Self::InvalidDate => f.write_str("malformed SigV4 timestamp"),
            Self::InvalidPresign => f.write_str("malformed SigV4 query authentication"),
            Self::InvalidScope => f.write_str("invalid SigV4 credential scope"),
            Self::InvalidSignedHeaders => f.write_str("invalid SigV4 signed headers"),
            Self::MissingHeader(name) => write!(f, "missing required {name} header"),
            Self::Payload(error) => write!(f, "invalid payload mode: {error}"),
            Self::SignatureMismatch => f.write_str("SigV4 seed signature mismatch"),
        }
    }
}

impl std::error::Error for SigV4Error {}

impl From<IntegrityError> for SigV4Error {
    fn from(value: IntegrityError) -> Self {
        Self::Payload(value)
    }
}

#[derive(Clone, Debug)]
pub struct SigV4Policy {
    expected_region: String,
    max_clock_skew: Duration,
    trusted_tls_termination: bool,
}

impl SigV4Policy {
    pub fn new(expected_region: impl Into<String>, trusted_tls_termination: bool) -> Self {
        Self {
            expected_region: expected_region.into(),
            max_clock_skew: Duration::from_secs(15 * 60),
            trusted_tls_termination,
        }
    }

    pub fn from_env() -> Self {
        let expected_region =
            std::env::var("S4_SIGV4_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string());
        let trusted_tls_termination = std::env::var("S4_SIGV4_TRUSTED_TLS")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self::new(expected_region, trusted_tls_termination)
    }

    fn trusted_tls(&self, uri: &Uri) -> bool {
        uri.scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
            || self.trusted_tls_termination
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheKey {
    credential: String,
    date: String,
    region: String,
    service: String,
}

struct CacheEntry {
    key: CacheKey,
    secret_fingerprint: [u8; 32],
    signing_key: [u8; 32],
    expires_at: Instant,
}

/// Bounded TTL cache containing only derived signing keys and secret hashes.
pub struct SigningKeyCache {
    capacity: usize,
    ttl: Duration,
    entries: Mutex<VecDeque<CacheEntry>>,
}

impl SigningKeyCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl,
            entries: Mutex::new(VecDeque::with_capacity(capacity.max(1))),
        }
    }

    pub fn standard() -> Self {
        Self::new(1024, Duration::from_secs(15 * 60))
    }

    fn derive(
        &self,
        auth: &RequestAuthorization,
        secret: &str,
        timestamp: SystemTime,
    ) -> Result<[u8; 32], SigV4Error> {
        let cache_key = CacheKey {
            credential: auth.access_key.clone(),
            date: auth.scope_date.clone(),
            region: auth.region.clone(),
            service: auth.service.clone(),
        };
        let secret_fingerprint: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| SigV4Error::CacheUnavailable)?;
        entries.retain(|entry| entry.expires_at > now);
        if let Some(index) = entries.iter().position(|entry| {
            entry.key == cache_key && entry.secret_fingerprint == secret_fingerprint
        }) {
            let entry = entries.remove(index).expect("cache index remains valid");
            let signing_key = entry.signing_key;
            entries.push_back(entry);
            return Ok(signing_key);
        }

        let generated = v4::generate_signing_key(secret, timestamp, &auth.region, &auth.service);
        let mut signing_key = [0_u8; 32];
        signing_key.copy_from_slice(generated.as_ref());
        while entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(CacheEntry {
            key: cache_key,
            secret_fingerprint,
            signing_key,
            expires_at: now + self.ttl,
        });
        Ok(signing_key)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().expect("cache lock").len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Location {
    Header,
    Query { expires: Duration },
}

#[derive(Clone, Debug)]
pub struct RequestAuthorization {
    access_key: String,
    scope_date: String,
    region: String,
    service: String,
    terminator: String,
    signed_headers: Vec<String>,
    signature: String,
    timestamp: String,
    location: Location,
}

impl RequestAuthorization {
    pub fn parse(uri: &Uri, headers: &HeaderMap) -> Result<Option<Self>, SigV4Error> {
        let authorization = one_header(headers, "authorization")?;
        let query = QueryAuthentication::parse(uri)?;
        match (authorization, query) {
            (Some(_), Some(_)) => Err(SigV4Error::AmbiguousAuthentication),
            (Some(value), None) if value.starts_with("AWS4-") => {
                Self::from_header(value, headers).map(Some)
            }
            (Some(_), None) => Ok(None),
            (None, Some(query)) => Self::from_query(query).map(Some),
            (None, None) => Ok(None),
        }
    }

    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        method: &str,
        uri: &Uri,
        headers: &HeaderMap,
        secret: &str,
        cache: &SigningKeyCache,
        policy: &SigV4Policy,
        now: SystemTime,
    ) -> Result<BodyVerifier, SigV4Error> {
        self.validate_scope(policy)?;
        let timestamp = parse_timestamp(&self.timestamp).ok_or(SigV4Error::InvalidDate)?;
        if self.scope_date != self.timestamp.get(..8).ok_or(SigV4Error::InvalidDate)? {
            return Err(SigV4Error::InvalidScope);
        }
        validate_time(self.location, timestamp, now, policy.max_clock_skew)?;
        validate_signed_headers(&self.signed_headers, self.location, headers)?;

        let payload_hash = match self.location {
            Location::Header => one_header(headers, "x-amz-content-sha256")?
                .ok_or(SigV4Error::MissingHeader("x-amz-content-sha256"))?
                .to_string(),
            Location::Query { .. } => one_header(headers, "x-amz-content-sha256")?
                .unwrap_or("UNSIGNED-PAYLOAD")
                .to_string(),
        };
        let signed_values = collect_signed_header_values(headers, &self.signed_headers)?;
        let signing_key = cache.derive(self, secret, timestamp)?;
        self.verify_seed_signature(
            method,
            uri,
            secret,
            timestamp,
            &payload_hash,
            &signed_values,
        )?;

        let streaming = StreamingSigning {
            signing_key,
            timestamp: self.timestamp.clone(),
            scope: format!(
                "{}/{}/{}/{}",
                self.scope_date, self.region, self.service, self.terminator
            ),
            seed_signature: self.signature.clone(),
        };
        BodyVerifier::from_headers(
            headers,
            &payload_hash,
            Some(streaming),
            policy.trusted_tls(uri),
        )
        .map_err(Into::into)
    }

    fn from_header(value: &str, headers: &HeaderMap) -> Result<Self, SigV4Error> {
        let rest = value
            .strip_prefix("AWS4-HMAC-SHA256 ")
            .ok_or(SigV4Error::InvalidAuthorization)?;
        let mut credential = None;
        let mut signed_headers = None;
        let mut signature = None;
        let mut fields = 0;
        for part in rest.split(',') {
            fields += 1;
            let part = part.trim();
            if let Some(value) = part.strip_prefix("Credential=") {
                set_once(&mut credential, value.to_string())?;
            } else if let Some(value) = part.strip_prefix("SignedHeaders=") {
                set_once(&mut signed_headers, parse_signed_headers(value)?)?;
            } else if let Some(value) = part.strip_prefix("Signature=") {
                validate_signature(value)?;
                set_once(&mut signature, value.to_ascii_lowercase())?;
            } else {
                return Err(SigV4Error::InvalidAuthorization);
            }
        }
        if fields != 3 {
            return Err(SigV4Error::InvalidAuthorization);
        }
        let (access_key, scope_date, region, service, terminator) =
            parse_credential(&credential.ok_or(SigV4Error::InvalidCredential)?)?;
        let timestamp = one_header(headers, "x-amz-date")?
            .ok_or(SigV4Error::MissingHeader("x-amz-date"))?
            .to_string();
        Ok(Self {
            access_key,
            scope_date,
            region,
            service,
            terminator,
            signed_headers: signed_headers.ok_or(SigV4Error::InvalidSignedHeaders)?,
            signature: signature.ok_or(SigV4Error::InvalidAuthorization)?,
            timestamp,
            location: Location::Header,
        })
    }

    fn from_query(query: QueryAuthentication) -> Result<Self, SigV4Error> {
        let (access_key, scope_date, region, service, terminator) =
            parse_credential(&query.credential)?;
        Ok(Self {
            access_key,
            scope_date,
            region,
            service,
            terminator,
            signed_headers: parse_signed_headers(&query.signed_headers)?,
            signature: query.signature,
            timestamp: query.timestamp,
            location: Location::Query {
                expires: query.expires,
            },
        })
    }

    fn validate_scope(&self, policy: &SigV4Policy) -> Result<(), SigV4Error> {
        if self.access_key.is_empty()
            || self.scope_date.len() != 8
            || !self.scope_date.bytes().all(|byte| byte.is_ascii_digit())
            || self.region != policy.expected_region
            || self.service != "s3"
            || self.terminator != "aws4_request"
        {
            return Err(SigV4Error::InvalidScope);
        }
        Ok(())
    }

    fn verify_seed_signature(
        &self,
        method: &str,
        uri: &Uri,
        secret: &str,
        timestamp: SystemTime,
        payload_hash: &str,
        signed_values: &[(String, String)],
    ) -> Result<(), SigV4Error> {
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let target;
        let body;
        match self.location {
            Location::Header => {
                target = uri.path_and_query().map_or_else(
                    || uri.path().to_string(),
                    |value| value.as_str().to_string(),
                );
                body = SignableBody::Precomputed(payload_hash.to_ascii_lowercase());
            }
            Location::Query { expires } => {
                settings.signature_location = SignatureLocation::QueryParams;
                settings.expires_in = Some(expires);
                target = query_signing_target(uri)?;
                body = SignableBody::UnsignedPayload;
            }
        }

        let identity: aws_smithy_runtime_api::client::identity::Identity = Credentials::new(
            self.access_key.clone(),
            secret.to_string(),
            None,
            None,
            "s4-front-door",
        )
        .into();
        let params: SigningParams = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service)
            .time(timestamp)
            .settings(settings)
            .build()
            .map_err(|_| SigV4Error::InvalidAuthorization)?
            .into();
        let request = SignableRequest::new(
            method,
            target,
            signed_values
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            body,
        )
        .map_err(|_| SigV4Error::InvalidAuthorization)?;
        let output = sign(request, &params).map_err(|_| SigV4Error::InvalidAuthorization)?;
        if constant_time_signature_eq(output.signature(), &self.signature) {
            Ok(())
        } else {
            Err(SigV4Error::SignatureMismatch)
        }
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), SigV4Error> {
    if slot.replace(value).is_some() {
        Err(SigV4Error::InvalidAuthorization)
    } else {
        Ok(())
    }
}

fn parse_credential(value: &str) -> Result<(String, String, String, String, String), SigV4Error> {
    let parts: Vec<_> = value.split('/').collect();
    if parts.len() != 5 || parts.iter().any(|part| part.is_empty()) {
        return Err(SigV4Error::InvalidCredential);
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
        parts[3].to_string(),
        parts[4].to_string(),
    ))
}

fn parse_signed_headers(value: &str) -> Result<Vec<String>, SigV4Error> {
    if value.is_empty() {
        return Err(SigV4Error::InvalidSignedHeaders);
    }
    let headers: Vec<String> = value.split(';').map(str::to_string).collect();
    if headers.iter().any(|name| {
        name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) || headers.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(SigV4Error::InvalidSignedHeaders);
    }
    Ok(headers)
}

fn validate_signed_headers(
    signed: &[String],
    location: Location,
    headers: &HeaderMap,
) -> Result<(), SigV4Error> {
    if !signed.iter().any(|name| name == "host") {
        return Err(SigV4Error::InvalidSignedHeaders);
    }
    if location == Location::Header
        && (!signed.iter().any(|name| name == "x-amz-date")
            || !signed.iter().any(|name| name == "x-amz-content-sha256"))
    {
        return Err(SigV4Error::InvalidSignedHeaders);
    }
    for name in signed {
        if headers.get(name).is_none() {
            return Err(SigV4Error::MissingHeader("signed header"));
        }
    }
    for name in headers.keys() {
        let name = name.as_str();
        if name.starts_with("x-amz-")
            && name != "x-amz-content-sha256"
            && !signed.iter().any(|signed| signed == name)
        {
            return Err(SigV4Error::InvalidSignedHeaders);
        }
    }
    Ok(())
}

fn collect_signed_header_values(
    headers: &HeaderMap,
    signed: &[String],
) -> Result<Vec<(String, String)>, SigV4Error> {
    signed
        .iter()
        .map(|name| {
            let values: Result<Vec<_>, _> = headers
                .get_all(name)
                .iter()
                .map(|value| {
                    value
                        .to_str()
                        .map(str::to_string)
                        .map_err(|_| SigV4Error::InvalidSignedHeaders)
                })
                .collect();
            let values = values?;
            if values.is_empty() {
                return Err(SigV4Error::MissingHeader("signed header"));
            }
            Ok((name.clone(), values.join(",")))
        })
        .collect()
}

fn one_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, SigV4Error> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| SigV4Error::DuplicateHeader(name))
        })
        .transpose()?;
    if values.next().is_some() {
        return Err(SigV4Error::DuplicateHeader(name));
    }
    Ok(first)
}

fn validate_signature(value: &str) -> Result<(), SigV4Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(SigV4Error::InvalidAuthorization)
    } else {
        Ok(())
    }
}

fn constant_time_signature_eq(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (hex::decode(left), hex::decode(right)) else {
        return false;
    };
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn validate_time(
    location: Location,
    timestamp: SystemTime,
    now: SystemTime,
    skew: Duration,
) -> Result<(), SigV4Error> {
    match location {
        Location::Header => {
            let difference = now
                .duration_since(timestamp)
                .or_else(|_| timestamp.duration_since(now))
                .map_err(|_| SigV4Error::ClockSkew)?;
            if difference > skew {
                return Err(SigV4Error::ClockSkew);
            }
        }
        Location::Query { expires } => {
            if expires > MAX_PRESIGN_EXPIRY {
                return Err(SigV4Error::InvalidPresign);
            }
            if timestamp
                .duration_since(now)
                .is_ok_and(|future| future > skew)
            {
                return Err(SigV4Error::ClockSkew);
            }
            let expiry = timestamp
                .checked_add(expires)
                .ok_or(SigV4Error::InvalidPresign)?;
            if now > expiry {
                return Err(SigV4Error::Expired);
            }
        }
    }
    Ok(())
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let adjusted_month = (month + 9) % 12;
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn parse_timestamp(value: &str) -> Option<SystemTime> {
    let bytes = value.as_bytes();
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
        return None;
    }
    let two = |index: usize| -> Option<u64> {
        let high = bytes[index].checked_sub(b'0')? as u64;
        let low = bytes[index + 1].checked_sub(b'0')? as u64;
        (high < 10 && low < 10).then_some(high * 10 + low)
    };
    let year = two(0)? * 100 + two(2)?;
    let month = two(4)?;
    let day = two(6)?;
    let hour = two(9)?;
    let minute = two(11)?;
    let second = two(13)?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day == 0
        || day > month_days[month as usize - 1]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let seconds = days_from_civil(year as i64, month as i64, day as i64) * 86_400
        + hour as i64 * 3_600
        + minute as i64 * 60
        + second as i64;
    (seconds >= 0).then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds as u64))
}

struct QueryAuthentication {
    credential: String,
    timestamp: String,
    expires: Duration,
    signed_headers: String,
    signature: String,
}

impl QueryAuthentication {
    fn parse(uri: &Uri) -> Result<Option<Self>, SigV4Error> {
        let Some(query) = uri.query() else {
            return Ok(None);
        };
        let mut algorithm = None;
        let mut credential = None;
        let mut timestamp = None;
        let mut expires = None;
        let mut signed_headers = None;
        let mut signature = None;
        let mut saw_auth = false;
        for pair in query.split('&') {
            let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = percent_decode(raw_name)?;
            let value = percent_decode(raw_value)?;
            let target = match name.as_str() {
                "X-Amz-Algorithm" => Some(&mut algorithm),
                "X-Amz-Credential" => Some(&mut credential),
                "X-Amz-Date" => Some(&mut timestamp),
                "X-Amz-Expires" => Some(&mut expires),
                "X-Amz-SignedHeaders" => Some(&mut signed_headers),
                "X-Amz-Signature" => Some(&mut signature),
                _ => None,
            };
            if let Some(target) = target {
                saw_auth = true;
                if target.replace(value).is_some() {
                    return Err(SigV4Error::InvalidPresign);
                }
            }
        }
        if !saw_auth {
            return Ok(None);
        }
        if algorithm.as_deref() != Some("AWS4-HMAC-SHA256") {
            return Err(SigV4Error::InvalidPresign);
        }
        let expires = expires
            .ok_or(SigV4Error::InvalidPresign)?
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|_| SigV4Error::InvalidPresign)?;
        let signature = signature.ok_or(SigV4Error::InvalidPresign)?;
        validate_signature(&signature)?;
        Ok(Some(Self {
            credential: credential.ok_or(SigV4Error::InvalidPresign)?,
            timestamp: timestamp.ok_or(SigV4Error::InvalidPresign)?,
            expires,
            signed_headers: signed_headers.ok_or(SigV4Error::InvalidPresign)?,
            signature: signature.to_ascii_lowercase(),
        }))
    }
}

fn query_signing_target(uri: &Uri) -> Result<String, SigV4Error> {
    let retained = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| {
            let name = pair.split_once('=').map_or(*pair, |(name, _)| name);
            percent_decode(name)
                .map(|name| !name.starts_with("X-Amz-"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    if retained.is_empty() {
        Ok(uri.path().to_string())
    } else {
        Ok(format!("{}?{}", uri.path(), retained.join("&")))
    }
}

fn percent_decode(value: &str) -> Result<String, SigV4Error> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(SigV4Error::InvalidPresign);
            }
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|_| SigV4Error::InvalidPresign)?;
            decoded.push(u8::from_str_radix(pair, 16).map_err(|_| SigV4Error::InvalidPresign)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| SigV4Error::InvalidPresign)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sigv4::http_request::{SignableRequest, SigningParams};
    use axum::http::{HeaderValue, Method};

    const ACCESS: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const DATE: &str = "20260819T120000Z";

    fn signed_request(uri: &str, region: &str) -> (Uri, HeaderMap, SystemTime) {
        let time = parse_timestamp(DATE).unwrap();
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let identity: aws_smithy_runtime_api::client::identity::Identity =
            Credentials::new(ACCESS, SECRET, None, None, "test").into();
        let params: SigningParams = v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name("s3")
            .time(time)
            .settings(settings)
            .build()
            .unwrap()
            .into();
        let request = SignableRequest::new(
            Method::PUT.as_str(),
            uri,
            std::iter::empty(),
            SignableBody::Bytes(b"payload"),
        )
        .unwrap();
        let instructions = sign(request, &params).unwrap().into_parts().0;
        let uri: Uri = uri.parse().unwrap();
        let mut request = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(uri.clone())
            .body(())
            .unwrap();
        instructions.apply_to_request_http1x(&mut request);
        request.headers_mut().insert(
            "host",
            HeaderValue::from_str(uri.authority().unwrap().as_str()).unwrap(),
        );
        (uri, request.into_parts().0.headers, time)
    }

    fn presigned_request(uri: &str) -> (Uri, HeaderMap, SystemTime) {
        let time = parse_timestamp(DATE).unwrap();
        let mut settings = SigningSettings::default();
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(Duration::from_secs(300));
        let identity: aws_smithy_runtime_api::client::identity::Identity =
            Credentials::new(ACCESS, SECRET, None, None, "test").into();
        let params: SigningParams = v4::SigningParams::builder()
            .identity(&identity)
            .region("us-east-1")
            .name("s3")
            .time(time)
            .settings(settings)
            .build()
            .unwrap()
            .into();
        let request = SignableRequest::new(
            Method::GET.as_str(),
            uri,
            std::iter::empty(),
            SignableBody::UnsignedPayload,
        )
        .unwrap();
        let instructions = sign(request, &params).unwrap().into_parts().0;
        let mut request = axum::http::Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(())
            .unwrap();
        instructions.apply_to_request_http1x(&mut request);
        let authority = request.uri().authority().unwrap().as_str().to_string();
        request
            .headers_mut()
            .insert("host", HeaderValue::from_str(&authority).unwrap());
        let (parts, _) = request.into_parts();
        (parts.uri, parts.headers, time)
    }

    #[test]
    fn official_signing_key_vector() {
        let time = parse_timestamp("20150830T123600Z").unwrap();
        let key = v4::generate_signing_key(SECRET, time, "us-east-1", "iam");
        let signature = v4::calculate_signature(
            key,
            b"AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59",
        );
        assert_eq!(
            signature,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn validates_sdk_canonical_path_query_and_headers() {
        for uri in [
            "http://s4.local/bucket/a%20b//c?z=last&a=first",
            "http://s4.local/bucket/%E2%98%83?empty=&repeat=b&repeat=a",
        ] {
            let (uri, headers, time) = signed_request(uri, "us-east-1");
            let auth = RequestAuthorization::parse(&uri, &headers)
                .unwrap()
                .unwrap();
            auth.authorize(
                "PUT",
                &uri,
                &headers,
                SECRET,
                &SigningKeyCache::standard(),
                &SigV4Policy::new("us-east-1", false),
                time,
            )
            .unwrap();
        }
    }

    #[test]
    fn rejects_wrong_scope_skew_and_duplicate_or_unsorted_headers() {
        let (uri, headers, time) = signed_request("http://s4.local/bucket/key", "eu-west-1");
        let auth = RequestAuthorization::parse(&uri, &headers)
            .unwrap()
            .unwrap();
        assert_eq!(
            auth.authorize(
                "PUT",
                &uri,
                &headers,
                SECRET,
                &SigningKeyCache::standard(),
                &SigV4Policy::new("us-east-1", false),
                time,
            )
            .err()
            .unwrap(),
            SigV4Error::InvalidScope
        );

        let (uri, headers, time) = signed_request("http://s4.local/bucket/key", "us-east-1");
        let auth = RequestAuthorization::parse(&uri, &headers)
            .unwrap()
            .unwrap();
        assert_eq!(
            auth.authorize(
                "PUT",
                &uri,
                &headers,
                SECRET,
                &SigningKeyCache::standard(),
                &SigV4Policy::new("us-east-1", false),
                time + Duration::from_secs(901),
            )
            .err()
            .unwrap(),
            SigV4Error::ClockSkew
        );
        assert_eq!(
            parse_signed_headers("host;host;x-amz-date"),
            Err(SigV4Error::InvalidSignedHeaders)
        );
        assert_eq!(
            parse_signed_headers("x-amz-date;host"),
            Err(SigV4Error::InvalidSignedHeaders)
        );
    }

    #[test]
    fn cache_is_bounded_expires_and_isolates_credentials_and_secrets() {
        let cache = SigningKeyCache::new(2, Duration::ZERO);
        for credential in ["one", "two", "three"] {
            let auth = RequestAuthorization {
                access_key: credential.to_string(),
                scope_date: "20260819".to_string(),
                region: "us-east-1".to_string(),
                service: "s3".to_string(),
                terminator: "aws4_request".to_string(),
                signed_headers: vec!["host".to_string()],
                signature: "00".repeat(32),
                timestamp: DATE.to_string(),
                location: Location::Header,
            };
            let first = cache
                .derive(&auth, SECRET, parse_timestamp(DATE).unwrap())
                .unwrap();
            let second = cache
                .derive(&auth, "different-secret", parse_timestamp(DATE).unwrap())
                .unwrap();
            assert_ne!(first, second);
            assert!(cache.len() <= 2);
        }
        assert_eq!(cache.len(), 1, "zero-TTL entries expire naturally");
    }

    #[test]
    fn accepts_sdk_generated_presign_and_rejects_expiry_replay() {
        let (uri, headers, time) = presigned_request("https://s4.local/bucket/a%20b?versionId=one");
        let authorization = RequestAuthorization::parse(&uri, &headers)
            .unwrap()
            .unwrap();
        authorization
            .authorize(
                "GET",
                &uri,
                &headers,
                SECRET,
                &SigningKeyCache::standard(),
                &SigV4Policy::new("us-east-1", false),
                time + Duration::from_secs(299),
            )
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(
            authorization
                .authorize(
                    "GET",
                    &uri,
                    &headers,
                    SECRET,
                    &SigningKeyCache::standard(),
                    &SigV4Policy::new("us-east-1", false),
                    time + Duration::from_secs(301),
                )
                .err()
                .unwrap(),
            SigV4Error::Expired
        );
    }

    #[test]
    fn timestamp_rejects_impossible_calendar_dates() {
        assert!(parse_timestamp("20260229T120000Z").is_none());
        assert!(parse_timestamp("20240229T120000Z").is_some());
        assert!(parse_timestamp("20261301T120000Z").is_none());
        assert!(parse_timestamp("20260101T126000Z").is_none());
    }
}
