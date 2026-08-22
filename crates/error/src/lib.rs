#[derive(Debug, thiserror::Error)]
pub enum S4Error {
    #[error("{code}: {message}")]
    Generic { code: &'static str, message: String },
}

pub mod codes {
    pub const DECODE_JSON: &str = "decode.json";
    pub const DECODE_CSV: &str = "decode.csv";
    pub const DECODE_JSONL: &str = "decode.jsonl";
    pub const DECODE_ENCODING: &str = "decode.encoding";
    pub const CONFIG_INVALID: &str = "config.invalid";
    pub const LIMIT_INPUT_BYTES: &str = "limit.input_bytes";
    pub const LIMIT_OUTPUT_BYTES: &str = "limit.output_bytes";
    pub const LIMIT_EXPANSION: &str = "limit.expansion";
    pub const LIMIT_INTERMEDIATE_BYTES: &str = "limit.intermediate_bytes";
    pub const LIMIT_FINISH_BYTES: &str = "limit.finish_bytes";
    pub const LIMIT_PLUGIN_COUNT: &str = "limit.plugin_count";
    pub const RECORD_TOO_LARGE: &str = "record.too_large";
    pub const WASM_TRAP: &str = "wasm.trap";
    pub const WASM_REJECT: &str = "wasm.reject";
    pub const WASM_FUEL: &str = "wasm.fuel";
    pub const WASM_DEADLINE: &str = "wasm.deadline";
    pub const WASM_CANCELLED: &str = "wasm.cancelled";
    pub const WASM_ADMISSION: &str = "wasm.admission";
    pub const WASM_INIT: &str = "wasm.init";
    pub const POLICY_UNAVAILABLE: &str = "policy.unavailable";
    pub const POLICY_EXPIRED: &str = "policy.expired";
    pub const POLICY_TAMPERED: &str = "policy.tampered";
    pub const INTERNAL: &str = "internal";
    pub const UNSUPPORTED_FORMAT: &str = "unsupported.format";
    pub const WIT_INVALID: &str = "wit.invalid";
    pub const COMPONENT_LOAD: &str = "component.load";
}

impl S4Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self::Generic {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Generic { code, .. } => code,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic { message, .. } => message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_includes_code_and_message() {
        let err = S4Error::new(codes::INTERNAL, "something broke");
        let s = err.to_string();
        assert!(s.contains(codes::INTERNAL), "display should include code");
        assert!(
            s.contains("something broke"),
            "display should include message"
        );
    }

    #[test]
    fn error_code_accessor() {
        let err = S4Error::new(codes::WASM_TRAP, "trap");
        assert_eq!(err.code(), codes::WASM_TRAP);
    }

    #[test]
    fn error_message_accessor() {
        let err = S4Error::new(codes::DECODE_CSV, "bad csv");
        assert_eq!(err.message(), "bad csv");
    }

    #[test]
    fn error_is_std_error() {
        let err = S4Error::new(codes::INTERNAL, "x");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn all_codes_are_stable() {
        assert_eq!(codes::DECODE_JSON, "decode.json");
        assert_eq!(codes::WASM_REJECT, "wasm.reject");
        assert_eq!(codes::POLICY_TAMPERED, "policy.tampered");
    }
}
