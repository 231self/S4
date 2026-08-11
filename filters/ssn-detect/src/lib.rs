//! Social security number redaction filter plugin. Replaces SSNs (9 digits,
//! with or without dashes, SSA-valid) with `[REDACTED_SSN]`; all other
//! content passes through unchanged.

#[cfg(target_arch = "wasm32")]
mod guest {
    use pii_shared::redact_ssns;
    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter/world.wit",
    });

    struct SsnDetect;

    impl Guest for SsnDetect {
        fn begin(_context: Context) -> Result<(), String> {
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            let text = std::str::from_utf8(&payload).map_err(|e| e.to_string())?;
            Ok(Decision::Emit(redact_ssns(text).into_bytes()))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    export!(SsnDetect);
}
