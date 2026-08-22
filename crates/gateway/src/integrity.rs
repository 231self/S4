//! Incremental verification and decoding for S3 request payloads.
//!
//! The verifier owns only fixed-size digest state and bounded aws-chunked
//! framing buffers. Decoded bytes are returned to the caller as they arrive;
//! complete objects are never retained here.

use std::fmt;

use axum::http::HeaderMap;
use base64::Engine as _;
use bytes::Bytes;
use crc::{CRC_32_ISCSI, CRC_32_ISO_HDLC, CRC_64_NVME, Crc};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MAX_CHUNK_HEADER_BYTES: usize = 8 * 1024;
const MAX_TRAILER_LINE_BYTES: usize = 8 * 1024;
const MAX_TRAILER_BYTES: usize = 16 * 1024;
const MAX_TRAILERS: usize = 16;
const MAX_CHUNKS: u64 = 100_000;
const MAX_CHUNK_BYTES: u64 = 16 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    ConflictingChecksum,
    DecodedLengthMismatch,
    DuplicateHeader(&'static str),
    DuplicateTrailer(String),
    Framing(&'static str),
    InvalidChecksum(&'static str),
    InvalidDecodedLength,
    InvalidPayloadHash,
    MissingChecksum,
    MissingDecodedLength,
    MissingTrailerDeclaration,
    OversizedFraming,
    PayloadHashMismatch,
    SignatureMismatch,
    TrailingData,
    Truncated,
    UnsupportedContentEncoding,
    UnsupportedPayloadMode,
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingChecksum => f.write_str("conflicting checksum declarations"),
            Self::DecodedLengthMismatch => f.write_str("decoded content length mismatch"),
            Self::DuplicateHeader(name) => write!(f, "duplicate {name} header"),
            Self::DuplicateTrailer(name) => write!(f, "duplicate {name} trailer"),
            Self::Framing(message) => write!(f, "invalid aws-chunked framing: {message}"),
            Self::InvalidChecksum(name) => write!(f, "invalid or mismatched {name} checksum"),
            Self::InvalidDecodedLength => f.write_str("invalid decoded content length"),
            Self::InvalidPayloadHash => f.write_str("invalid x-amz-content-sha256"),
            Self::MissingChecksum => f.write_str("required payload checksum is missing"),
            Self::MissingDecodedLength => f.write_str("x-amz-decoded-content-length is required"),
            Self::MissingTrailerDeclaration => f.write_str("x-amz-trailer is required"),
            Self::OversizedFraming => f.write_str("aws-chunked framing limit exceeded"),
            Self::PayloadHashMismatch => f.write_str("payload SHA-256 mismatch"),
            Self::SignatureMismatch => f.write_str("streaming payload signature mismatch"),
            Self::TrailingData => f.write_str("data follows the final aws-chunked frame"),
            Self::Truncated => f.write_str("truncated request payload"),
            Self::UnsupportedContentEncoding => f.write_str("unsupported content-encoding"),
            Self::UnsupportedPayloadMode => f.write_str("unsupported SigV4 payload mode"),
        }
    }
}

impl std::error::Error for IntegrityError {}

#[derive(Clone)]
pub struct StreamingSigning {
    pub signing_key: [u8; 32],
    pub timestamp: String,
    pub scope: String,
    pub seed_signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamingMode {
    Signed,
    SignedTrailer,
    UnsignedTrailer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChecksumAlgorithm {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
}

impl ChecksumAlgorithm {
    const ALL: [(Self, &'static str); 5] = [
        (Self::Crc32, "x-amz-checksum-crc32"),
        (Self::Crc32c, "x-amz-checksum-crc32c"),
        (Self::Crc64Nvme, "x-amz-checksum-crc64nvme"),
        (Self::Sha1, "x-amz-checksum-sha1"),
        (Self::Sha256, "x-amz-checksum-sha256"),
    ];

    fn header(self) -> &'static str {
        Self::ALL
            .iter()
            .find_map(|(algorithm, name)| (*algorithm == self).then_some(*name))
            .expect("every checksum algorithm has a header")
    }

    fn sdk_name(self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Crc64Nvme => "CRC64NVME",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    fn from_header(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find_map(|(algorithm, header)| name.eq_ignore_ascii_case(header).then_some(*algorithm))
    }
}

enum ChecksumState {
    Crc32(crc::Digest<'static, u32>),
    Crc32c(crc::Digest<'static, u32>),
    Crc64Nvme(crc::Digest<'static, u64>),
    Sha1(Sha1),
    Sha256(Sha256),
}

static CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
static CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);
static CRC64_NVME: Crc<u64> = Crc::<u64>::new(&CRC_64_NVME);

impl ChecksumState {
    fn new(algorithm: ChecksumAlgorithm) -> Self {
        match algorithm {
            ChecksumAlgorithm::Crc32 => Self::Crc32(CRC32.digest()),
            ChecksumAlgorithm::Crc32c => Self::Crc32c(CRC32C.digest()),
            ChecksumAlgorithm::Crc64Nvme => Self::Crc64Nvme(CRC64_NVME.digest()),
            ChecksumAlgorithm::Sha1 => Self::Sha1(Sha1::new()),
            ChecksumAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Crc32(digest) | Self::Crc32c(digest) => digest.update(bytes),
            Self::Crc64Nvme(digest) => digest.update(bytes),
            Self::Sha1(digest) => digest.update(bytes),
            Self::Sha256(digest) => digest.update(bytes),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Crc32(digest) | Self::Crc32c(digest) => digest.finalize().to_be_bytes().to_vec(),
            Self::Crc64Nvme(digest) => digest.finalize().to_be_bytes().to_vec(),
            Self::Sha1(digest) => digest.finalize().to_vec(),
            Self::Sha256(digest) => digest.finalize().to_vec(),
        }
    }
}

struct ChecksumVerifier {
    algorithm: ChecksumAlgorithm,
    state: ChecksumState,
    expected: Option<Vec<u8>>,
    trailer_required: bool,
}

impl ChecksumVerifier {
    fn update(&mut self, bytes: &[u8]) {
        self.state.update(bytes);
    }

    fn set_trailer(&mut self, name: &str, value: &str) -> Result<(), IntegrityError> {
        if !name.eq_ignore_ascii_case(self.algorithm.header()) || self.expected.is_some() {
            return Err(IntegrityError::ConflictingChecksum);
        }
        self.expected = Some(decode_checksum(self.algorithm, value)?);
        Ok(())
    }

    fn finish(self) -> Result<(), IntegrityError> {
        let expected = self.expected.ok_or(IntegrityError::MissingChecksum)?;
        if self.trailer_required && expected.is_empty() {
            return Err(IntegrityError::MissingChecksum);
        }
        if constant_time_eq(&self.state.finalize(), &expected) {
            Ok(())
        } else {
            Err(IntegrityError::InvalidChecksum(self.algorithm.header()))
        }
    }
}

enum PayloadState {
    Fixed {
        sha256: Option<Sha256>,
        expected_sha256: Option<[u8; 32]>,
    },
    Chunked(Box<AwsChunkedDecoder>),
    Finished,
}

/// Incremental source-payload verifier. `push` returns decoded source bytes.
pub struct BodyVerifier {
    state: PayloadState,
    checksum: Option<ChecksumVerifier>,
    decoded_bytes: u64,
}

impl BodyVerifier {
    pub fn from_headers(
        headers: &HeaderMap,
        payload_hash: &str,
        signing: Option<StreamingSigning>,
        trusted_tls: bool,
    ) -> Result<Self, IntegrityError> {
        let content_encoding = one_header(headers, "content-encoding")?;
        let decoded_length = one_header(headers, "x-amz-decoded-content-length")?;
        let trailer_declaration = one_header(headers, "x-amz-trailer")?;
        let (checksum, declared_trailer) = checksum_from_headers(headers, trailer_declaration)?;

        let state = match payload_hash {
            "UNSIGNED-PAYLOAD" => {
                if !trusted_tls || content_encoding.is_some() || trailer_declaration.is_some() {
                    return Err(IntegrityError::UnsupportedPayloadMode);
                }
                PayloadState::Fixed {
                    sha256: None,
                    expected_sha256: None,
                }
            }
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => {
                require_aws_chunked(content_encoding)?;
                if trailer_declaration.is_some() {
                    return Err(IntegrityError::ConflictingChecksum);
                }
                let signing = signing.ok_or(IntegrityError::UnsupportedPayloadMode)?;
                PayloadState::Chunked(Box::new(AwsChunkedDecoder::new(
                    StreamingMode::Signed,
                    parse_decoded_length(decoded_length)?,
                    None,
                    signing,
                )))
            }
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => {
                require_aws_chunked(content_encoding)?;
                let signing = signing.ok_or(IntegrityError::UnsupportedPayloadMode)?;
                let trailer = declared_trailer.ok_or(IntegrityError::MissingTrailerDeclaration)?;
                PayloadState::Chunked(Box::new(AwsChunkedDecoder::new(
                    StreamingMode::SignedTrailer,
                    parse_decoded_length(decoded_length)?,
                    Some(trailer),
                    signing,
                )))
            }
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => {
                if !trusted_tls {
                    return Err(IntegrityError::UnsupportedPayloadMode);
                }
                require_aws_chunked(content_encoding)?;
                let trailer = declared_trailer.ok_or(IntegrityError::MissingTrailerDeclaration)?;
                PayloadState::Chunked(Box::new(AwsChunkedDecoder::new(
                    StreamingMode::UnsignedTrailer,
                    parse_decoded_length(decoded_length)?,
                    Some(trailer),
                    signing.unwrap_or_else(empty_signing),
                )))
            }
            value if value.len() == 64 => {
                if content_encoding.is_some() || trailer_declaration.is_some() {
                    return Err(IntegrityError::UnsupportedContentEncoding);
                }
                PayloadState::Fixed {
                    sha256: Some(Sha256::new()),
                    expected_sha256: Some(parse_sha256(value)?),
                }
            }
            _ => return Err(IntegrityError::UnsupportedPayloadMode),
        };

        Ok(Self {
            state,
            checksum,
            decoded_bytes: 0,
        })
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Bytes>, IntegrityError> {
        let decoded = match &mut self.state {
            PayloadState::Fixed { sha256, .. } => {
                if let Some(sha256) = sha256 {
                    sha256.update(bytes);
                }
                vec![Bytes::copy_from_slice(bytes)]
            }
            PayloadState::Chunked(decoder) => decoder.push(bytes)?,
            PayloadState::Finished => return Err(IntegrityError::TrailingData),
        };
        for chunk in &decoded {
            self.decoded_bytes = self
                .decoded_bytes
                .checked_add(chunk.len() as u64)
                .ok_or(IntegrityError::DecodedLengthMismatch)?;
            if let Some(checksum) = &mut self.checksum {
                checksum.update(chunk);
            }
        }
        Ok(decoded)
    }

    pub fn finish(mut self) -> Result<u64, IntegrityError> {
        self.apply_chunked_trailer()?;
        match std::mem::replace(&mut self.state, PayloadState::Finished) {
            PayloadState::Fixed {
                sha256,
                expected_sha256,
            } => {
                if let (Some(sha256), Some(expected)) = (sha256, expected_sha256)
                    && !constant_time_eq(&sha256.finalize(), &expected)
                {
                    return Err(IntegrityError::PayloadHashMismatch);
                }
            }
            PayloadState::Chunked(decoder) => decoder.finish()?,
            PayloadState::Finished => return Err(IntegrityError::TrailingData),
        }
        if let Some(checksum) = self.checksum {
            checksum.finish()?;
        }
        Ok(self.decoded_bytes)
    }

    pub fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
}

fn empty_signing() -> StreamingSigning {
    StreamingSigning {
        signing_key: [0; 32],
        timestamp: String::new(),
        scope: String::new(),
        seed_signature: String::new(),
    }
}

fn require_aws_chunked(content_encoding: Option<&str>) -> Result<(), IntegrityError> {
    match content_encoding {
        Some(value) if value.trim().eq_ignore_ascii_case("aws-chunked") => Ok(()),
        _ => Err(IntegrityError::UnsupportedContentEncoding),
    }
}

fn parse_decoded_length(value: Option<&str>) -> Result<u64, IntegrityError> {
    value
        .ok_or(IntegrityError::MissingDecodedLength)?
        .parse::<u64>()
        .map_err(|_| IntegrityError::InvalidDecodedLength)
}

fn one_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, IntegrityError> {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| IntegrityError::DuplicateHeader(name))
        })
        .transpose()?;
    if values.next().is_some() {
        return Err(IntegrityError::DuplicateHeader(name));
    }
    Ok(first)
}

fn checksum_from_headers(
    headers: &HeaderMap,
    trailer_declaration: Option<&str>,
) -> Result<(Option<ChecksumVerifier>, Option<String>), IntegrityError> {
    let mut selected: Option<(ChecksumAlgorithm, Vec<u8>)> = None;
    for (algorithm, name) in ChecksumAlgorithm::ALL {
        if let Some(value) = one_header(headers, name)? {
            if selected.is_some() {
                return Err(IntegrityError::ConflictingChecksum);
            }
            selected = Some((algorithm, decode_checksum(algorithm, value)?));
        }
    }

    let declared = trailer_declaration
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    if let Some(value) = declared.as_deref()
        && (value.contains(',') || ChecksumAlgorithm::from_header(value).is_none())
    {
        return Err(IntegrityError::ConflictingChecksum);
    }
    if selected.is_some() && declared.is_some() {
        return Err(IntegrityError::ConflictingChecksum);
    }

    let sdk_algorithm = one_header(headers, "x-amz-sdk-checksum-algorithm")?;
    let algorithm = selected
        .as_ref()
        .map(|(algorithm, _)| *algorithm)
        .or_else(|| declared.as_deref().and_then(ChecksumAlgorithm::from_header));
    if let Some(sdk) = sdk_algorithm {
        let Some(algorithm) = algorithm else {
            return Err(IntegrityError::MissingChecksum);
        };
        if !sdk.trim().eq_ignore_ascii_case(algorithm.sdk_name()) {
            return Err(IntegrityError::ConflictingChecksum);
        }
    }

    let verifier = algorithm.map(|algorithm| ChecksumVerifier {
        algorithm,
        state: ChecksumState::new(algorithm),
        expected: selected.map(|(_, expected)| expected),
        trailer_required: declared.is_some(),
    });
    Ok((verifier, declared))
}

fn decode_checksum(algorithm: ChecksumAlgorithm, value: &str) -> Result<Vec<u8>, IntegrityError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| IntegrityError::InvalidChecksum(algorithm.header()))?;
    let expected_len = match algorithm {
        ChecksumAlgorithm::Crc32 | ChecksumAlgorithm::Crc32c => 4,
        ChecksumAlgorithm::Crc64Nvme => 8,
        ChecksumAlgorithm::Sha1 => 20,
        ChecksumAlgorithm::Sha256 => 32,
    };
    if decoded.len() != expected_len {
        return Err(IntegrityError::InvalidChecksum(algorithm.header()));
    }
    Ok(decoded)
}

fn parse_sha256(value: &str) -> Result<[u8; 32], IntegrityError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(IntegrityError::InvalidPayloadHash);
    }
    let mut output = [0; 32];
    hex::decode_to_slice(value, &mut output).map_err(|_| IntegrityError::InvalidPayloadHash)?;
    Ok(output)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
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

#[derive(Debug)]
enum DecodeState {
    Header,
    Data,
    DataCrlf(u8),
    FinalCrlf(u8),
    Trailers,
    Done,
}

struct AwsChunkedDecoder {
    mode: StreamingMode,
    signing: StreamingSigning,
    previous_signature: String,
    state: DecodeState,
    line: Vec<u8>,
    chunk_remaining: u64,
    chunk_hasher: Sha256,
    expected_chunk_signature: Option<String>,
    expected_decoded_length: u64,
    decoded_length: u64,
    chunks: u64,
    trailer_bytes: usize,
    trailer_count: usize,
    declared_trailer: Option<String>,
    checksum_trailer: Option<(String, String)>,
    trailer_signature: Option<String>,
}

impl AwsChunkedDecoder {
    fn new(
        mode: StreamingMode,
        expected_decoded_length: u64,
        declared_trailer: Option<String>,
        signing: StreamingSigning,
    ) -> Self {
        Self {
            previous_signature: signing.seed_signature.clone(),
            mode,
            signing,
            state: DecodeState::Header,
            line: Vec::new(),
            chunk_remaining: 0,
            chunk_hasher: Sha256::new(),
            expected_chunk_signature: None,
            expected_decoded_length,
            decoded_length: 0,
            chunks: 0,
            trailer_bytes: 0,
            trailer_count: 0,
            declared_trailer,
            checksum_trailer: None,
            trailer_signature: None,
        }
    }

    fn push(&mut self, mut input: &[u8]) -> Result<Vec<Bytes>, IntegrityError> {
        if matches!(self.state, DecodeState::Done) && !input.is_empty() {
            return Err(IntegrityError::TrailingData);
        }
        let mut output = Vec::new();
        while !input.is_empty() {
            match self.state {
                DecodeState::Header => {
                    if let Some(line) =
                        take_line(&mut self.line, &mut input, MAX_CHUNK_HEADER_BYTES)?
                    {
                        self.start_chunk(&line)?;
                    }
                }
                DecodeState::Data => {
                    let take = usize::try_from(self.chunk_remaining.min(input.len() as u64))
                        .map_err(|_| IntegrityError::OversizedFraming)?;
                    let bytes = &input[..take];
                    self.chunk_hasher.update(bytes);
                    self.chunk_remaining -= take as u64;
                    input = &input[take..];
                    if !bytes.is_empty() {
                        output.push(Bytes::copy_from_slice(bytes));
                    }
                    if self.chunk_remaining == 0 {
                        self.verify_chunk_signature()?;
                        self.state = DecodeState::DataCrlf(0);
                    }
                }
                DecodeState::DataCrlf(ref mut matched) => {
                    while !input.is_empty() && *matched < 2 {
                        let expected = if *matched == 0 { b'\r' } else { b'\n' };
                        if input[0] != expected {
                            return Err(IntegrityError::Framing("chunk data lacks CRLF"));
                        }
                        *matched += 1;
                        input = &input[1..];
                    }
                    if *matched == 2 {
                        self.state = DecodeState::Header;
                    }
                }
                DecodeState::FinalCrlf(ref mut matched) => {
                    while !input.is_empty() && *matched < 2 {
                        let expected = if *matched == 0 { b'\r' } else { b'\n' };
                        if input[0] != expected {
                            return Err(IntegrityError::Framing("final chunk lacks CRLF"));
                        }
                        *matched += 1;
                        input = &input[1..];
                    }
                    if *matched == 2 {
                        self.state = DecodeState::Done;
                        if !input.is_empty() {
                            return Err(IntegrityError::TrailingData);
                        }
                    }
                }
                DecodeState::Trailers => {
                    if let Some(line) =
                        take_line(&mut self.line, &mut input, MAX_TRAILER_LINE_BYTES)?
                    {
                        self.trailer_bytes = self
                            .trailer_bytes
                            .checked_add(line.len() + 2)
                            .ok_or(IntegrityError::OversizedFraming)?;
                        if self.trailer_bytes > MAX_TRAILER_BYTES {
                            return Err(IntegrityError::OversizedFraming);
                        }
                        if line.is_empty() {
                            self.verify_trailers()?;
                            self.state = DecodeState::Done;
                            if !input.is_empty() {
                                return Err(IntegrityError::TrailingData);
                            }
                        } else {
                            self.parse_trailer(&line)?;
                        }
                    }
                }
                DecodeState::Done => return Err(IntegrityError::TrailingData),
            }
        }
        Ok(output)
    }

    fn start_chunk(&mut self, line: &[u8]) -> Result<(), IntegrityError> {
        let line =
            std::str::from_utf8(line).map_err(|_| IntegrityError::Framing("non-ASCII header"))?;
        let (size, extension) = line
            .split_once(';')
            .map_or((line, None), |(size, ext)| (size, Some(ext)));
        if size.is_empty() || size.len() > 16 || !size.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(IntegrityError::Framing("invalid chunk size"));
        }
        let size = u64::from_str_radix(size, 16)
            .map_err(|_| IntegrityError::Framing("invalid chunk size"))?;
        if size > MAX_CHUNK_BYTES {
            return Err(IntegrityError::OversizedFraming);
        }
        self.chunks += 1;
        if self.chunks > MAX_CHUNKS {
            return Err(IntegrityError::OversizedFraming);
        }

        match self.mode {
            StreamingMode::Signed | StreamingMode::SignedTrailer => {
                let signature = extension
                    .and_then(|value| value.strip_prefix("chunk-signature="))
                    .ok_or(IntegrityError::Framing("missing chunk signature"))?;
                parse_sha256(signature)?;
                self.expected_chunk_signature = Some(signature.to_ascii_lowercase());
            }
            StreamingMode::UnsignedTrailer if extension.is_some() => {
                return Err(IntegrityError::Framing("unexpected chunk extension"));
            }
            StreamingMode::UnsignedTrailer => {}
        }

        self.chunk_remaining = size;
        self.chunk_hasher = Sha256::new();
        if size == 0 {
            self.verify_chunk_signature()?;
            self.state = match self.mode {
                StreamingMode::Signed => DecodeState::FinalCrlf(0),
                StreamingMode::SignedTrailer | StreamingMode::UnsignedTrailer => {
                    DecodeState::Trailers
                }
            };
        } else {
            self.decoded_length = self
                .decoded_length
                .checked_add(size)
                .ok_or(IntegrityError::DecodedLengthMismatch)?;
            if self.decoded_length > self.expected_decoded_length {
                return Err(IntegrityError::DecodedLengthMismatch);
            }
            self.state = DecodeState::Data;
        }
        Ok(())
    }

    fn verify_chunk_signature(&mut self) -> Result<(), IntegrityError> {
        let Some(expected) = self.expected_chunk_signature.take() else {
            return Ok(());
        };
        let chunk_hash = hex::encode(self.chunk_hasher.clone().finalize());
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.signing.timestamp,
            self.signing.scope,
            self.previous_signature,
            EMPTY_SHA256,
            chunk_hash
        );
        let actual = hmac_hex(&self.signing.signing_key, string_to_sign.as_bytes());
        if !constant_time_hex_eq(&actual, &expected) {
            return Err(IntegrityError::SignatureMismatch);
        }
        self.previous_signature = expected;
        Ok(())
    }

    fn parse_trailer(&mut self, line: &[u8]) -> Result<(), IntegrityError> {
        self.trailer_count += 1;
        if self.trailer_count > MAX_TRAILERS {
            return Err(IntegrityError::OversizedFraming);
        }
        let line =
            std::str::from_utf8(line).map_err(|_| IntegrityError::Framing("non-ASCII trailer"))?;
        let (name, value) = line
            .split_once(':')
            .ok_or(IntegrityError::Framing("malformed trailer"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || value.trim() != value
        {
            return Err(IntegrityError::Framing("non-canonical trailer"));
        }
        if name == "x-amz-trailer-signature" {
            if self.trailer_signature.is_some() || self.checksum_trailer.is_none() {
                return Err(IntegrityError::DuplicateTrailer(name.to_string()));
            }
            parse_sha256(value)?;
            self.trailer_signature = Some(value.to_ascii_lowercase());
            return Ok(());
        }
        if self.checksum_trailer.is_some() {
            return Err(IntegrityError::DuplicateTrailer(name.to_string()));
        }
        if self.declared_trailer.as_deref() != Some(name) {
            return Err(IntegrityError::ConflictingChecksum);
        }
        self.checksum_trailer = Some((name.to_string(), value.to_string()));
        Ok(())
    }

    fn verify_trailers(&mut self) -> Result<(), IntegrityError> {
        let (name, value) = self
            .checksum_trailer
            .as_ref()
            .ok_or(IntegrityError::MissingChecksum)?;
        if self.mode == StreamingMode::SignedTrailer {
            let expected = self
                .trailer_signature
                .as_ref()
                .ok_or(IntegrityError::Framing("missing trailer signature"))?;
            let canonical = format!("{name}:{value}\n");
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
                self.signing.timestamp,
                self.signing.scope,
                self.previous_signature,
                hex::encode(Sha256::digest(canonical.as_bytes()))
            );
            let actual = hmac_hex(&self.signing.signing_key, string_to_sign.as_bytes());
            if !constant_time_hex_eq(&actual, expected) {
                return Err(IntegrityError::SignatureMismatch);
            }
        } else if self.trailer_signature.is_some() {
            return Err(IntegrityError::Framing("unexpected trailer signature"));
        }
        Ok(())
    }

    fn finish(self) -> Result<(), IntegrityError> {
        if !matches!(self.state, DecodeState::Done) {
            return Err(IntegrityError::Truncated);
        }
        if self.decoded_length != self.expected_decoded_length {
            return Err(IntegrityError::DecodedLengthMismatch);
        }
        Ok(())
    }

    fn take_checksum_trailer(&self) -> Option<(&str, &str)> {
        self.checksum_trailer
            .as_ref()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

fn take_line(
    buffer: &mut Vec<u8>,
    input: &mut &[u8],
    limit: usize,
) -> Result<Option<Vec<u8>>, IntegrityError> {
    while let Some((&byte, rest)) = input.split_first() {
        buffer.push(byte);
        *input = rest;
        if buffer.ends_with(b"\r\n") {
            buffer.truncate(buffer.len() - 2);
            return Ok(Some(std::mem::take(buffer)));
        }
        if buffer.len() > limit
            && (buffer.len() != limit + 1 || buffer.last().copied() != Some(b'\r'))
        {
            return Err(IntegrityError::OversizedFraming);
        }
    }
    Ok(None)
}

fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts every key size");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (hex::decode(left), hex::decode(right)) else {
        return false;
    };
    constant_time_eq(&left, &right)
}

impl BodyVerifier {
    /// Applies an aws-chunked checksum trailer after framing validation.
    pub fn apply_chunked_trailer(&mut self) -> Result<(), IntegrityError> {
        let PayloadState::Chunked(decoder) = &self.state else {
            return Ok(());
        };
        if let Some((name, value)) = decoder.take_checksum_trailer() {
            self.checksum
                .as_mut()
                .ok_or(IntegrityError::MissingChecksum)?
                .set_trailer(name, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    fn headers(entries: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in entries {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn fixed(body: &[u8], extra: &[(&str, &str)]) -> BodyVerifier {
        let hash = hex::encode(Sha256::digest(body));
        BodyVerifier::from_headers(&headers(extra), &hash, None, false).unwrap()
    }

    #[test]
    fn fixed_payload_is_incremental_and_checks_empty_mismatch() {
        let mut verifier = fixed(b"abcdef", &[]);
        verifier.push(b"ab").unwrap();
        verifier.push(b"cdef").unwrap();
        assert_eq!(verifier.finish().unwrap(), 6);

        let mut mismatch = fixed(b"not empty", &[]);
        mismatch.push(b"").unwrap();
        assert_eq!(mismatch.finish(), Err(IntegrityError::PayloadHashMismatch));
    }

    #[test]
    fn every_flexible_checksum_algorithm_accepts_and_rejects() {
        let body = b"123456789";
        let cases = [
            ("x-amz-checksum-crc32", "y/Q5Jg=="),
            ("x-amz-checksum-crc32c", "4waSgw=="),
            ("x-amz-checksum-crc64nvme", "rosUhgp5mIg="),
            ("x-amz-checksum-sha1", "98O8HYCOBHMq32eZZczDTKeuNEE="),
            (
                "x-amz-checksum-sha256",
                "FeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiU=",
            ),
        ];
        for (name, expected) in cases {
            let mut verifier = fixed(body, &[(name, expected)]);
            verifier.push(body).unwrap();
            assert_eq!(verifier.finish().unwrap(), body.len() as u64, "{name}");

            let mut verifier = fixed(body, &[(name, expected)]);
            verifier.push(b"123456788").unwrap();
            assert!(matches!(
                verifier.finish(),
                Err(IntegrityError::PayloadHashMismatch | IntegrityError::InvalidChecksum(_))
            ));
        }
    }

    #[test]
    fn checksum_declarations_are_strict() {
        let hash = hex::encode(Sha256::digest(b""));
        assert!(matches!(
            BodyVerifier::from_headers(
                &headers(&[
                    ("x-amz-checksum-crc32", "AAAAAA=="),
                    (
                        "x-amz-checksum-sha256",
                        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
                    )
                ]),
                &hash,
                None,
                false
            ),
            Err(IntegrityError::ConflictingChecksum)
        ));
        assert!(
            BodyVerifier::from_headers(
                &headers(&[("x-amz-checksum-crc32", "not-base64")]),
                &hash,
                None,
                false
            )
            .is_err()
        );
    }

    fn signing() -> StreamingSigning {
        StreamingSigning {
            signing_key: [7; 32],
            timestamp: "20260819T120000Z".to_string(),
            scope: "20260819/us-east-1/s3/aws4_request".to_string(),
            seed_signature: "00".repeat(32),
        }
    }

    fn signed_chunk(previous: &str, data: &[u8], signing: &StreamingSigning) -> (String, String) {
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            signing.timestamp,
            signing.scope,
            previous,
            EMPTY_SHA256,
            hex::encode(Sha256::digest(data))
        );
        let signature = hmac_hex(&signing.signing_key, string_to_sign.as_bytes());
        (
            format!(
                "{:X};chunk-signature={}\r\n{}\r\n",
                data.len(),
                signature,
                String::from_utf8_lossy(data)
            ),
            signature,
        )
    }

    fn signed_fixture(data: &[u8]) -> Vec<u8> {
        let signing = signing();
        let (first, signature) = signed_chunk(&signing.seed_signature, data, &signing);
        let (last, _) = signed_chunk(&signature, b"", &signing);
        format!("{first}{last}").into_bytes()
    }

    fn checksum_value(algorithm: ChecksumAlgorithm, data: &[u8]) -> String {
        let mut state = ChecksumState::new(algorithm);
        state.update(data);
        base64::engine::general_purpose::STANDARD.encode(state.finalize())
    }

    fn signed_verifier(length: usize) -> BodyVerifier {
        BodyVerifier::from_headers(
            &headers(&[
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", &length.to_string()),
            ]),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            Some(signing()),
            false,
        )
        .unwrap()
    }

    #[test]
    fn aws_chunked_accepts_every_split_point() {
        let fixture = signed_fixture(b"hello streaming world");
        for split in 0..=fixture.len() {
            let mut verifier = signed_verifier(21);
            let mut decoded = Vec::new();
            for part in [&fixture[..split], &fixture[split..]] {
                for chunk in verifier.push(part).unwrap() {
                    decoded.extend_from_slice(&chunk);
                }
            }
            verifier.apply_chunked_trailer().unwrap();
            assert_eq!(verifier.finish().unwrap(), 21, "split {split}");
            assert_eq!(decoded, b"hello streaming world", "split {split}");
        }
    }

    #[test]
    fn aws_chunked_accepts_512_seeded_partitions() {
        let fixture = signed_fixture(b"partition-independent");
        for seed in 0..512_u64 {
            let mut verifier = signed_verifier(21);
            let mut decoded = Vec::new();
            let mut offset = 0;
            let mut random = seed.wrapping_add(1);
            while offset < fixture.len() {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let length = ((random >> 32) as usize % 17 + 1).min(fixture.len() - offset);
                for chunk in verifier.push(&fixture[offset..offset + length]).unwrap() {
                    decoded.extend_from_slice(&chunk);
                }
                offset += length;
            }
            verifier.apply_chunked_trailer().unwrap();
            verifier.finish().unwrap();
            assert_eq!(decoded, b"partition-independent", "seed {seed}");
        }
    }

    #[test]
    fn aws_chunked_rejects_all_signature_tampering_and_truncation() {
        let fixture = signed_fixture(b"tamper me");
        for index in fixture
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| byte.is_ascii_hexdigit().then_some(index))
        {
            let mut tampered = fixture.clone();
            tampered[index] = if tampered[index] == b'a' { b'b' } else { b'a' };
            let mut verifier = signed_verifier(9);
            if verifier.push(&tampered).is_ok() {
                assert!(verifier.finish().is_err(), "tampered index {index}");
            }
        }
        for end in 0..fixture.len() {
            let mut verifier = signed_verifier(9);
            if verifier.push(&fixture[..end]).is_ok() {
                assert!(verifier.finish().is_err(), "truncation {end}");
            }
        }
    }

    #[test]
    fn signed_and_unsigned_trailers_are_verified() {
        let data = b"trailer payload";
        let checksum = checksum_value(ChecksumAlgorithm::Crc32c, data);
        let signing = signing();
        let (first, first_signature) = signed_chunk(&signing.seed_signature, data, &signing);
        let (mut zero, zero_signature) = signed_chunk(&first_signature, b"", &signing);
        zero.truncate(zero.len() - 2);
        let canonical = format!("x-amz-checksum-crc32c:{checksum}\n");
        let trailer_to_sign = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            signing.timestamp,
            signing.scope,
            zero_signature,
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let trailer_signature = hmac_hex(&signing.signing_key, trailer_to_sign.as_bytes());
        let signed = format!(
            "{first}{zero}x-amz-checksum-crc32c:{checksum}\r\nx-amz-trailer-signature:{trailer_signature}\r\n\r\n"
        );
        let signed_headers = headers(&[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", &data.len().to_string()),
            ("x-amz-trailer", "x-amz-checksum-crc32c"),
            ("x-amz-sdk-checksum-algorithm", "CRC32C"),
        ]);
        let mut verifier = BodyVerifier::from_headers(
            &signed_headers,
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            Some(signing.clone()),
            false,
        )
        .unwrap();
        let decoded = verifier.push(signed.as_bytes()).unwrap();
        assert_eq!(decoded.concat(), data);
        assert_eq!(verifier.finish().unwrap(), data.len() as u64);

        let unsigned = format!(
            "{:X}\r\n{}\r\n0\r\nx-amz-checksum-crc32c:{checksum}\r\n\r\n",
            data.len(),
            String::from_utf8_lossy(data)
        );
        let mut verifier = BodyVerifier::from_headers(
            &signed_headers,
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            None,
            true,
        )
        .unwrap();
        assert_eq!(verifier.push(unsigned.as_bytes()).unwrap().concat(), data);
        verifier.finish().unwrap();

        let tampered = signed.replacen(&trailer_signature, &"f".repeat(64), 1);
        let mut verifier = BodyVerifier::from_headers(
            &signed_headers,
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            Some(signing),
            false,
        )
        .unwrap();
        assert_eq!(
            verifier.push(tampered.as_bytes()),
            Err(IntegrityError::SignatureMismatch)
        );
    }

    #[test]
    fn aws_chunked_rejects_oversized_framing_and_wrong_decoded_length() {
        let mut verifier = signed_verifier(0);
        assert_eq!(
            verifier.push(&vec![b'a'; MAX_CHUNK_HEADER_BYTES + 1]),
            Err(IntegrityError::OversizedFraming)
        );

        let fixture = signed_fixture(b"length");
        let mut verifier = signed_verifier(7);
        verifier.push(&fixture).unwrap();
        assert_eq!(
            verifier.finish(),
            Err(IntegrityError::DecodedLengthMismatch)
        );
    }

    #[test]
    fn verifier_state_is_constant_for_one_gibibyte() {
        let chunk = [0_u8; 64 * 1024];
        let mut verifier =
            BodyVerifier::from_headers(&HeaderMap::new(), "UNSIGNED-PAYLOAD", None, true).unwrap();
        for _ in 0..(1024 * 1024 * 1024 / chunk.len()) {
            assert_eq!(verifier.push(&chunk).unwrap().len(), 1);
        }
        assert_eq!(verifier.finish().unwrap(), 1024 * 1024 * 1024);
        assert!(std::mem::size_of::<BodyVerifier>() < 1024);
    }
}
