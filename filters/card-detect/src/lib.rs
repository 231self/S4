//! Credit card redaction filter plugin. Replaces valid card numbers
//! (13-19 digits, Luhn-checked) with `[REDACTED_CARD]`; all other content
//! passes through unchanged.

#[cfg(target_arch = "wasm32")]
mod guest {
    use pii_shared::redact_cards;
    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter/world.wit",
    });

    struct CardDetect;

    impl Guest for CardDetect {
        fn begin(_context: Context) -> Result<(), String> {
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            let text = std::str::from_utf8(&payload).map_err(|e| e.to_string())?;
            Ok(Decision::Emit(redact_cards(text).into_bytes()))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    export!(CardDetect);
}
