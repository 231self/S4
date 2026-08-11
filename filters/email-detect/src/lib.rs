//! Email redaction filter plugin. Replaces email addresses with
//! `[REDACTED_EMAIL]`; all other content passes through unchanged.

#[cfg(target_arch = "wasm32")]
mod guest {
    use pii_shared::redact_emails;
    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter/world.wit",
    });

    struct EmailDetect;

    impl Guest for EmailDetect {
        fn begin(_context: Context) -> Result<(), String> {
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            let text = std::str::from_utf8(&payload).map_err(|e| e.to_string())?;
            Ok(Decision::Emit(redact_emails(text).into_bytes()))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    export!(EmailDetect);
}
