use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Jsonl,
    Json,
    Csv,
    Tsv,
    Text,
}

impl Format {
    pub fn as_str(&self) -> &str {
        match self {
            Format::Jsonl => "jsonl",
            Format::Json => "json",
            Format::Csv => "csv",
            Format::Tsv => "tsv",
            Format::Text => "text",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "jsonl" => Some(Self::Jsonl),
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "tsv" => Some(Self::Tsv),
            "text" => Some(Self::Text),
            _ => None,
        }
    }

    pub fn spec(self) -> &'static FormatSpec {
        FormatSpec::for_record_format(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecKind {
    Text,
    SequentialBinary,
    SeekableBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessedReadSafety {
    PrefixSafe,
    CompleteOutputRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagicRequirements {
    pub prefix: Option<&'static [u8]>,
    pub required_footer: Option<&'static [u8]>,
}

impl MagicRequirements {
    pub const NONE: Self = Self {
        prefix: None,
        required_footer: None,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureGate {
    pub name: &'static str,
    pub enabled_by_default: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnabledBinaryFormats {
    pub avro: bool,
    pub parquet: bool,
}

impl EnabledBinaryFormats {
    pub const NONE: Self = Self {
        avro: false,
        parquet: false,
    };

    pub const ALL: Self = Self {
        avro: true,
        parquet: true,
    };

    pub fn is_enabled(self, spec: &FormatSpec) -> bool {
        spec.feature_gate.is_none_or(|feature_gate| {
            feature_gate.enabled_by_default
                || match feature_gate.name {
                    "avro" => self.avro,
                    "parquet" => self.parquet,
                    _ => false,
                }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatResolutionPolicy {
    pub require_content_type: bool,
    pub allow_extension_fallback: bool,
    /// When false, the caller must validate required magic before decoding or committing bytes.
    pub require_binary_magic: bool,
}

impl FormatResolutionPolicy {
    /// General object detection policy for callers whose protocol permits inference.
    pub const INFERENCE: Self = Self {
        require_content_type: false,
        allow_extension_fallback: true,
        require_binary_magic: true,
    };

    /// Strict endpoint policy: Content-Type is mandatory and extensions are not consulted.
    pub const STRICT_CONTENT_TYPE: Self = Self {
        require_content_type: true,
        allow_extension_fallback: false,
        require_binary_magic: true,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatSpec {
    pub name: &'static str,
    pub codec_kind: CodecKind,
    pub canonical_media_type: &'static str,
    pub media_type_aliases: &'static [&'static str],
    pub extensions: &'static [&'static str],
    pub magic: MagicRequirements,
    pub processed_read_safety: ProcessedReadSafety,
    pub feature_gate: Option<FeatureGate>,
    /// The existing record decoder supports only these text formats.
    pub record_format: Option<Format>,
}

impl FormatSpec {
    pub fn for_name(name: &str) -> Option<&'static Self> {
        let name = name.trim();
        FORMAT_SPECS
            .iter()
            .copied()
            .find(|spec| spec.name.eq_ignore_ascii_case(name))
    }

    pub fn for_media_type(content_type: &str) -> Option<&'static Self> {
        let media_type = normalize_media_type(content_type);
        FORMAT_SPECS.iter().copied().find(|spec| {
            spec.canonical_media_type == media_type
                || spec
                    .media_type_aliases
                    .iter()
                    .any(|alias| *alias == media_type)
        })
    }

    pub fn for_extension(extension: &str) -> Option<&'static Self> {
        let extension = extension
            .strip_prefix('.')
            .unwrap_or(extension)
            .to_ascii_lowercase();
        FORMAT_SPECS.iter().copied().find(|spec| {
            spec.extensions
                .iter()
                .any(|candidate| *candidate == extension)
        })
    }

    pub fn for_record_format(format: Format) -> &'static Self {
        FORMAT_SPECS
            .iter()
            .copied()
            .find(|spec| spec.record_format == Some(format))
            .expect("every record format has a format spec")
    }

    pub fn enabled_by_default(&self) -> bool {
        self.feature_gate
            .is_none_or(|feature_gate| feature_gate.enabled_by_default)
    }
}

pub static JSONL_SPEC: FormatSpec = FormatSpec {
    name: "jsonl",
    codec_kind: CodecKind::Text,
    canonical_media_type: "application/x-ndjson",
    media_type_aliases: &["application/jsonlines"],
    extensions: &["jsonl", "ndjson"],
    magic: MagicRequirements::NONE,
    processed_read_safety: ProcessedReadSafety::PrefixSafe,
    feature_gate: None,
    record_format: Some(Format::Jsonl),
};

pub static JSON_SPEC: FormatSpec = FormatSpec {
    name: "json",
    codec_kind: CodecKind::Text,
    canonical_media_type: "application/json",
    media_type_aliases: &[],
    extensions: &["json"],
    magic: MagicRequirements::NONE,
    processed_read_safety: ProcessedReadSafety::PrefixSafe,
    feature_gate: None,
    record_format: Some(Format::Json),
};

pub static CSV_SPEC: FormatSpec = FormatSpec {
    name: "csv",
    codec_kind: CodecKind::Text,
    canonical_media_type: "text/csv",
    media_type_aliases: &[],
    extensions: &["csv"],
    magic: MagicRequirements::NONE,
    processed_read_safety: ProcessedReadSafety::PrefixSafe,
    feature_gate: None,
    record_format: Some(Format::Csv),
};

pub static TSV_SPEC: FormatSpec = FormatSpec {
    name: "tsv",
    codec_kind: CodecKind::Text,
    canonical_media_type: "text/tab-separated-values",
    media_type_aliases: &[],
    extensions: &["tsv"],
    magic: MagicRequirements::NONE,
    processed_read_safety: ProcessedReadSafety::PrefixSafe,
    feature_gate: None,
    record_format: Some(Format::Tsv),
};

pub static TEXT_SPEC: FormatSpec = FormatSpec {
    name: "text",
    codec_kind: CodecKind::Text,
    canonical_media_type: "text/plain",
    media_type_aliases: &[],
    extensions: &["txt", "text"],
    magic: MagicRequirements::NONE,
    processed_read_safety: ProcessedReadSafety::PrefixSafe,
    feature_gate: None,
    record_format: Some(Format::Text),
};

pub static AVRO_SPEC: FormatSpec = FormatSpec {
    name: "avro",
    codec_kind: CodecKind::SequentialBinary,
    canonical_media_type: "application/avro",
    media_type_aliases: &["application/x-avro", "application/vnd.apache.avro+binary"],
    extensions: &["avro"],
    magic: MagicRequirements {
        prefix: Some(b"Obj\x01"),
        required_footer: None,
    },
    processed_read_safety: ProcessedReadSafety::CompleteOutputRequired,
    feature_gate: Some(FeatureGate {
        name: "avro",
        enabled_by_default: false,
    }),
    record_format: None,
};

pub static PARQUET_SPEC: FormatSpec = FormatSpec {
    name: "parquet",
    codec_kind: CodecKind::SeekableBinary,
    canonical_media_type: "application/vnd.apache.parquet",
    media_type_aliases: &["application/x-parquet"],
    extensions: &["parquet"],
    magic: MagicRequirements {
        prefix: Some(b"PAR1"),
        required_footer: Some(b"PAR1"),
    },
    processed_read_safety: ProcessedReadSafety::CompleteOutputRequired,
    feature_gate: Some(FeatureGate {
        name: "parquet",
        enabled_by_default: false,
    }),
    record_format: None,
};

pub static FORMAT_SPECS: [&FormatSpec; 7] = [
    &JSONL_SPEC,
    &JSON_SPEC,
    &CSV_SPEC,
    &TSV_SPEC,
    &TEXT_SPEC,
    &AVRO_SPEC,
    &PARQUET_SPEC,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatSignal {
    Override,
    ContentType,
    Extension,
    Magic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedFormat {
    pub spec: &'static FormatSpec,
    pub source: FormatSignal,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatResolveError {
    #[error("unknown format override {0:?}")]
    UnknownOverride(String),
    #[error("Content-Type is required by this protocol")]
    MissingContentType,
    #[error("unsupported Content-Type {0:?}")]
    UnsupportedContentType(String),
    #[error("no format could be resolved")]
    UnknownFormat,
    #[error(
        "conflicting format signals: {first_signal:?} selected {first_format:?}, but {second_signal:?} selected {second_format:?}"
    )]
    Conflict {
        first_signal: FormatSignal,
        first_format: &'static str,
        second_signal: FormatSignal,
        second_format: &'static str,
    },
    #[error("format {format:?} is disabled by default; enable the {feature_gate:?} gate")]
    Disabled {
        format: &'static str,
        feature_gate: &'static str,
    },
    #[error("format {format:?} needs {required} prefix bytes before detection can complete")]
    PendingMagic {
        format: &'static str,
        required: usize,
    },
    #[error("format {format:?} requires {required} magic bytes, but only {actual} were provided")]
    InsufficientMagic {
        format: &'static str,
        required: usize,
        actual: usize,
    },
    #[error("prefix bytes do not match the required magic for format {format:?}")]
    MagicMismatch { format: &'static str },
    #[error("format {format:?} requires footer magic")]
    MissingFooterMagic { format: &'static str },
    #[error(
        "format {format:?} requires {required} footer magic bytes, but only {actual} were provided"
    )]
    InsufficientFooterMagic {
        format: &'static str,
        required: usize,
        actual: usize,
    },
    #[error("footer bytes do not match the required magic for format {format:?}")]
    FooterMagicMismatch { format: &'static str },
}

/// Resolves with inference enabled and all binary formats disabled.
///
/// Callers must validate an override as part of the signed request before passing it here.
pub fn resolve_format(
    format_override: Option<&str>,
    content_type: Option<&str>,
    object_key: Option<&str>,
    prefix: Option<&[u8]>,
) -> Result<ResolvedFormat, FormatResolveError> {
    resolve_format_with_policy(
        format_override,
        content_type,
        object_key,
        prefix,
        FormatResolutionPolicy::INFERENCE,
        EnabledBinaryFormats::NONE,
    )
}

/// Resolves format signals under endpoint-specific policy and runtime gates.
///
/// Callers must validate an override as part of the signed request before passing it here.
pub fn resolve_format_with_policy(
    format_override: Option<&str>,
    content_type: Option<&str>,
    object_key: Option<&str>,
    prefix: Option<&[u8]>,
    policy: FormatResolutionPolicy,
    enabled_binary_formats: EnabledBinaryFormats,
) -> Result<ResolvedFormat, FormatResolveError> {
    let mut resolved = None;

    if let Some(format_override) = format_override {
        let spec = FormatSpec::for_name(format_override).ok_or_else(|| {
            FormatResolveError::UnknownOverride(format_override.trim().to_string())
        })?;
        merge_signal(&mut resolved, spec, FormatSignal::Override)?;
    }

    let media_type = content_type.map(normalize_media_type);
    if policy.require_content_type && media_type.as_deref().is_none_or(str::is_empty) {
        return Err(FormatResolveError::MissingContentType);
    }
    let generic_media_type = media_type.as_deref().is_none_or(is_generic_media_type);
    if let Some(media_type) = media_type.as_deref()
        && !media_type.is_empty()
        && !is_generic_media_type(media_type)
    {
        if let Some(spec) = FormatSpec::for_media_type(media_type) {
            merge_signal(&mut resolved, spec, FormatSignal::ContentType)?;
        } else if resolved.is_none() {
            return Err(FormatResolveError::UnsupportedContentType(
                media_type.to_string(),
            ));
        }
    }

    if policy.allow_extension_fallback
        && generic_media_type
        && let Some(extension) = object_key.and_then(object_extension)
        && let Some(spec) = FormatSpec::for_extension(extension)
    {
        merge_signal(&mut resolved, spec, FormatSignal::Extension)?;
    }

    if let Some(prefix) = prefix
        && let Some(spec) = spec_for_magic(prefix)
    {
        merge_signal(&mut resolved, spec, FormatSignal::Magic)?;
    } else if resolved.is_none()
        && let Some(prefix) = prefix
        && let Some(spec) = spec_for_partial_magic(prefix)
    {
        merge_signal(&mut resolved, spec, FormatSignal::Magic)?;
    }

    let resolved = resolved.ok_or(FormatResolveError::UnknownFormat)?;
    validate_required_magic(resolved.spec, prefix, policy.require_binary_magic)?;
    if let Some(feature_gate) = resolved.spec.feature_gate
        && !enabled_binary_formats.is_enabled(resolved.spec)
    {
        return Err(FormatResolveError::Disabled {
            format: resolved.spec.name,
            feature_gate: feature_gate.name,
        });
    }
    Ok(resolved)
}

pub fn validate_footer_magic(
    spec: &FormatSpec,
    footer: Option<&[u8]>,
) -> Result<(), FormatResolveError> {
    let Some(required) = spec.magic.required_footer else {
        return Ok(());
    };
    let Some(footer) = footer else {
        return Err(FormatResolveError::MissingFooterMagic { format: spec.name });
    };
    if footer.len() < required.len() {
        return Err(FormatResolveError::InsufficientFooterMagic {
            format: spec.name,
            required: required.len(),
            actual: footer.len(),
        });
    }
    if !footer.ends_with(required) {
        return Err(FormatResolveError::FooterMagicMismatch { format: spec.name });
    }
    Ok(())
}

pub fn normalize_media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn is_generic_media_type(media_type: &str) -> bool {
    media_type.is_empty()
        || matches!(
            media_type,
            "application/octet-stream" | "binary/octet-stream"
        )
}

fn object_extension(object_key: &str) -> Option<&str> {
    let filename = object_key.rsplit('/').next()?;
    let (_, extension) = filename.rsplit_once('.')?;
    (!extension.is_empty()).then_some(extension)
}

fn spec_for_magic(prefix: &[u8]) -> Option<&'static FormatSpec> {
    FORMAT_SPECS.iter().copied().find(|spec| {
        spec.magic
            .prefix
            .is_some_and(|magic| prefix.starts_with(magic))
    })
}

fn spec_for_partial_magic(prefix: &[u8]) -> Option<&'static FormatSpec> {
    if prefix.is_empty() {
        return None;
    }
    let mut matches = FORMAT_SPECS.iter().copied().filter(|spec| {
        spec.magic
            .prefix
            .is_some_and(|magic| magic.starts_with(prefix))
    });
    let spec = matches.next()?;
    matches.next().is_none().then_some(spec)
}

fn merge_signal(
    resolved: &mut Option<ResolvedFormat>,
    spec: &'static FormatSpec,
    source: FormatSignal,
) -> Result<(), FormatResolveError> {
    if let Some(current) = resolved {
        if current.spec.name != spec.name {
            return Err(FormatResolveError::Conflict {
                first_signal: current.source,
                first_format: current.spec.name,
                second_signal: source,
                second_format: spec.name,
            });
        }
    } else {
        *resolved = Some(ResolvedFormat { spec, source });
    }
    Ok(())
}

fn validate_required_magic(
    spec: &'static FormatSpec,
    prefix: Option<&[u8]>,
    required_by_policy: bool,
) -> Result<(), FormatResolveError> {
    if !required_by_policy || spec.codec_kind == CodecKind::Text {
        return Ok(());
    }
    let Some(required) = spec.magic.prefix else {
        return Ok(());
    };
    let Some(prefix) = prefix else {
        return Err(FormatResolveError::PendingMagic {
            format: spec.name,
            required: required.len(),
        });
    };
    if prefix.len() < required.len() {
        return Err(FormatResolveError::InsufficientMagic {
            format: spec.name,
            required: required.len(),
            actual: prefix.len(),
        });
    }
    if !prefix.starts_with(required) {
        return Err(FormatResolveError::MagicMismatch { format: spec.name });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_text_names_and_media_types_are_unchanged() {
        let mappings = [
            (Format::Jsonl, "jsonl", "application/x-ndjson"),
            (Format::Json, "json", "application/json"),
            (Format::Csv, "csv", "text/csv"),
            (Format::Tsv, "tsv", "text/tab-separated-values"),
            (Format::Text, "text", "text/plain"),
        ];

        for (format, name, media_type) in mappings {
            assert_eq!(format.as_str(), name);
            assert_eq!(Format::parse(name), Some(format));
            assert_eq!(FormatSpec::for_media_type(media_type), Some(format.spec()));
        }
        assert_eq!(
            FormatSpec::for_media_type("application/jsonlines"),
            Some(&JSONL_SPEC)
        );
        assert_eq!(FormatSpec::for_media_type("application/ndjson"), None);
    }

    #[test]
    fn content_type_aliases_are_normalized() {
        assert_eq!(
            FormatSpec::for_media_type(" APPLICATION/JSONLINES; charset=utf-8"),
            Some(&JSONL_SPEC)
        );
        assert_eq!(
            FormatSpec::for_media_type("application/x-avro"),
            Some(&AVRO_SPEC)
        );
        assert_eq!(
            FormatSpec::for_media_type("application/x-parquet"),
            Some(&PARQUET_SPEC)
        );
    }

    #[test]
    fn extension_fallback_requires_generic_or_missing_media_type() {
        let missing = resolve_format(None, None, Some("events.JSONL"), None).unwrap();
        assert_eq!(missing.spec, &JSONL_SPEC);
        assert_eq!(missing.source, FormatSignal::Extension);

        let generic = resolve_format(
            None,
            Some("application/octet-stream"),
            Some("events.csv"),
            None,
        )
        .unwrap();
        assert_eq!(generic.spec, &CSV_SPEC);

        let specific =
            resolve_format(None, Some("application/json"), Some("events.csv"), None).unwrap();
        assert_eq!(specific.spec, &JSON_SPEC);
        assert_eq!(specific.source, FormatSignal::ContentType);

        assert_eq!(
            resolve_format(None, Some("application/xml"), Some("events.csv"), None),
            Err(FormatResolveError::UnsupportedContentType(
                "application/xml".to_string()
            ))
        );
    }

    #[test]
    fn protocol_policy_controls_content_type_and_extension_fallback() {
        assert_eq!(
            resolve_format_with_policy(
                None,
                None,
                Some("events.json"),
                None,
                FormatResolutionPolicy::STRICT_CONTENT_TYPE,
                EnabledBinaryFormats::NONE,
            ),
            Err(FormatResolveError::MissingContentType)
        );

        let no_extension_fallback = FormatResolutionPolicy {
            require_content_type: false,
            allow_extension_fallback: false,
            require_binary_magic: true,
        };
        assert_eq!(
            resolve_format_with_policy(
                None,
                None,
                Some("events.json"),
                None,
                no_extension_fallback,
                EnabledBinaryFormats::NONE,
            ),
            Err(FormatResolveError::UnknownFormat)
        );
        assert_eq!(
            resolve_format_with_policy(
                None,
                Some("application/json"),
                Some("events.csv"),
                None,
                FormatResolutionPolicy::STRICT_CONTENT_TYPE,
                EnabledBinaryFormats::NONE,
            )
            .unwrap()
            .spec,
            &JSON_SPEC
        );
    }

    #[test]
    fn avro_has_sequential_magic_and_is_disabled() {
        assert_eq!(AVRO_SPEC.codec_kind, CodecKind::SequentialBinary);
        assert_eq!(AVRO_SPEC.magic.prefix, Some(b"Obj\x01".as_slice()));
        assert_eq!(AVRO_SPEC.magic.required_footer, None);
        assert_eq!(
            AVRO_SPEC.processed_read_safety,
            ProcessedReadSafety::CompleteOutputRequired
        );
        assert!(!AVRO_SPEC.enabled_by_default());
        assert_eq!(
            resolve_format(None, None, None, Some(b"Obj\x01payload")),
            Err(FormatResolveError::Disabled {
                format: "avro",
                feature_gate: "avro",
            })
        );
    }

    #[test]
    fn parquet_has_seekable_prefix_and_required_footer_magic() {
        assert_eq!(PARQUET_SPEC.codec_kind, CodecKind::SeekableBinary);
        assert_eq!(PARQUET_SPEC.magic.prefix, Some(b"PAR1".as_slice()));
        assert_eq!(PARQUET_SPEC.magic.required_footer, Some(b"PAR1".as_slice()));
        assert_eq!(
            PARQUET_SPEC.processed_read_safety,
            ProcessedReadSafety::CompleteOutputRequired
        );
        assert!(!PARQUET_SPEC.enabled_by_default());
        assert_eq!(
            resolve_format(None, None, None, Some(b"PAR1payload")),
            Err(FormatResolveError::Disabled {
                format: "parquet",
                feature_gate: "parquet",
            })
        );
    }

    #[test]
    fn runtime_binary_gates_can_enable_avro_and_parquet() {
        let avro_only = EnabledBinaryFormats {
            avro: true,
            parquet: false,
        };
        let avro = resolve_format_with_policy(
            None,
            Some("application/avro"),
            None,
            Some(b"Obj\x01payload"),
            FormatResolutionPolicy::STRICT_CONTENT_TYPE,
            avro_only,
        )
        .unwrap();
        assert_eq!(avro.spec, &AVRO_SPEC);
        assert_eq!(avro.source, FormatSignal::ContentType);

        assert!(matches!(
            resolve_format_with_policy(
                None,
                Some("application/vnd.apache.parquet"),
                None,
                Some(b"PAR1payload"),
                FormatResolutionPolicy::STRICT_CONTENT_TYPE,
                avro_only,
            ),
            Err(FormatResolveError::Disabled {
                format: "parquet",
                ..
            })
        ));
        assert_eq!(
            resolve_format_with_policy(
                None,
                Some("application/vnd.apache.parquet"),
                None,
                Some(b"PAR1payload"),
                FormatResolutionPolicy::STRICT_CONTENT_TYPE,
                EnabledBinaryFormats::ALL,
            )
            .unwrap()
            .spec,
            &PARQUET_SPEC
        );
    }

    #[test]
    fn conflicting_recognized_signals_are_rejected() {
        assert!(matches!(
            resolve_format(Some("json"), Some("text/csv"), Some("ignored.tsv"), None),
            Err(FormatResolveError::Conflict {
                first_signal: FormatSignal::Override,
                first_format: "json",
                second_signal: FormatSignal::ContentType,
                second_format: "csv",
            })
        ));
        assert!(matches!(
            resolve_format(None, Some("application/json"), None, Some(b"Obj\x01")),
            Err(FormatResolveError::Conflict {
                first_signal: FormatSignal::ContentType,
                first_format: "json",
                second_signal: FormatSignal::Magic,
                second_format: "avro",
            })
        ));
    }

    #[test]
    fn disabled_formats_are_distinct_from_unknown_formats() {
        assert!(matches!(
            resolve_format(
                None,
                Some("application/avro"),
                None,
                Some(b"Obj\x01payload")
            ),
            Err(FormatResolveError::Disabled { format: "avro", .. })
        ));
        assert_eq!(
            resolve_format(None, None, Some("data.orc"), Some(b"ORC")),
            Err(FormatResolveError::UnknownFormat)
        );
        assert_eq!(
            resolve_format(Some("orc"), None, None, None),
            Err(FormatResolveError::UnknownOverride("orc".to_string()))
        );
    }

    #[test]
    fn required_binary_magic_reports_pending_short_and_mismatched_prefixes() {
        assert_eq!(
            resolve_format(None, Some("application/avro"), None, None),
            Err(FormatResolveError::PendingMagic {
                format: "avro",
                required: 4,
            })
        );
        assert_eq!(
            resolve_format(Some("avro"), None, None, Some(b"Obj")),
            Err(FormatResolveError::InsufficientMagic {
                format: "avro",
                required: 4,
                actual: 3,
            })
        );
        assert_eq!(
            resolve_format(None, None, None, Some(b"Obj")),
            Err(FormatResolveError::InsufficientMagic {
                format: "avro",
                required: 4,
                actual: 3,
            })
        );
        assert_eq!(
            resolve_format(Some("parquet"), None, None, Some(b"NOPE")),
            Err(FormatResolveError::MagicMismatch { format: "parquet" })
        );
    }

    #[test]
    fn policy_can_defer_binary_magic_validation() {
        let deferred_magic = FormatResolutionPolicy {
            require_binary_magic: false,
            ..FormatResolutionPolicy::STRICT_CONTENT_TYPE
        };
        assert_eq!(
            resolve_format_with_policy(
                None,
                Some("application/avro"),
                None,
                None,
                deferred_magic,
                EnabledBinaryFormats {
                    avro: true,
                    parquet: false,
                },
            )
            .unwrap()
            .spec,
            &AVRO_SPEC
        );
    }

    #[test]
    fn parquet_footer_magic_is_required_and_validated() {
        assert_eq!(
            validate_footer_magic(&PARQUET_SPEC, None),
            Err(FormatResolveError::MissingFooterMagic { format: "parquet" })
        );
        assert_eq!(
            validate_footer_magic(&PARQUET_SPEC, Some(b"PAR")),
            Err(FormatResolveError::InsufficientFooterMagic {
                format: "parquet",
                required: 4,
                actual: 3,
            })
        );
        assert_eq!(
            validate_footer_magic(&PARQUET_SPEC, Some(b"payloadNOPE")),
            Err(FormatResolveError::FooterMagicMismatch { format: "parquet" })
        );
        assert_eq!(
            validate_footer_magic(&PARQUET_SPEC, Some(b"payloadPAR1")),
            Ok(())
        );
        assert_eq!(validate_footer_magic(&AVRO_SPEC, None), Ok(()));
    }
}
