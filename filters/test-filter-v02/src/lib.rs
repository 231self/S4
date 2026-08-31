//! Test-only component built against the v0.2 `s4:filter` world. Exercises
//! `operation` and `config-json` context delivery.

#[cfg(target_arch = "wasm32")]
mod guest {
    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter-v0.2/world.wit",
    });

    struct TestFilterV02;

    impl Guest for TestFilterV02 {
        fn begin(context: Context) -> Result<(), String> {
            if context.content_type == "test/begin-reject" {
                return Err("begin rejected".to_string());
            }
            if context.content_type == "test/require-step-context"
                && (!matches!(context.operation, Operation::Read)
                    || context.config_json.as_deref() != Some(r#"{"region":"eu"}"#)
                    || context.public_key_pem.is_some()
                    || context.stable_key.is_some()
                    || context.stable_fields.is_some())
            {
                return Err("per-step context mismatch".to_string());
            }
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            Ok(Decision::Emit(payload))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    export!(TestFilterV02);
}
