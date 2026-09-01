//! Test-only component built against the v0.2 `s4:filter` world. Exercises
//! `operation` and `config-json` context delivery.

#[cfg(target_arch = "wasm32")]
mod guest {
    use std::sync::{LazyLock, Mutex};

    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter-v0.2/world.wit",
    });

    struct TestFilterV02;

    #[derive(Default)]
    struct GrantedValues {
        public_key_pem: String,
        entropy_seed: String,
        stable_key: String,
        stable_fields: String,
        finish_action: Option<String>,
    }

    impl GrantedValues {
        fn value(&self, field: &str) -> String {
            match field {
                "public-key" => format!("PUBLIC_KEY_SECRET={}", self.public_key_pem),
                "entropy" => format!("ENTROPY_SECRET={}", self.entropy_seed),
                "stable-key" => format!("STABLE_KEY_SECRET={}", self.stable_key),
                "stable-fields" => format!("STABLE_FIELDS_SECRET={}", self.stable_fields),
                _ => "UNKNOWN_SECRET_FIELD".to_string(),
            }
        }
    }

    static GRANTED: LazyLock<Mutex<GrantedValues>> =
        LazyLock::new(|| Mutex::new(GrantedValues::default()));

    fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0xf) as usize] as char);
        }
        output
    }

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
            let action = context.config_json.clone();
            let mut granted = GrantedValues {
                public_key_pem: context.public_key_pem.unwrap_or_default(),
                entropy_seed: encode(context.entropy_seed.as_deref().unwrap_or_default()),
                stable_key: encode(context.stable_key.as_deref().unwrap_or_default()),
                stable_fields: context.stable_fields.unwrap_or_default(),
                finish_action: action.clone(),
            };
            if let Some(field) = action
                .as_deref()
                .and_then(|value| value.strip_prefix("begin-error:"))
            {
                return Err(granted.value(field));
            }
            if let Some(field) = action
                .as_deref()
                .and_then(|value| value.strip_prefix("begin-trap:"))
            {
                panic!("{}", granted.value(field));
            }
            *GRANTED.lock().map_err(|error| error.to_string())? = std::mem::take(&mut granted);
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            let command = String::from_utf8(payload.clone()).unwrap_or_default();
            let granted = GRANTED.lock().map_err(|error| error.to_string())?;
            if let Some(field) = command.strip_prefix("reject:") {
                return Ok(Decision::Reject(granted.value(field)));
            }
            if let Some(field) = command.strip_prefix("error:") {
                return Err(granted.value(field));
            }
            if let Some(field) = command.strip_prefix("trap:") {
                panic!("{}", granted.value(field));
            }
            Ok(Decision::Emit(payload))
        }

        fn finish() -> Result<Vec<u8>, String> {
            let granted = GRANTED.lock().map_err(|error| error.to_string())?;
            if let Some(field) = granted
                .finish_action
                .as_deref()
                .and_then(|value| value.strip_prefix("finish-error:"))
            {
                return Err(granted.value(field));
            }
            if let Some(field) = granted
                .finish_action
                .as_deref()
                .and_then(|value| value.strip_prefix("finish-trap:"))
            {
                panic!("{}", granted.value(field));
            }
            Ok(Vec::new())
        }
    }

    export!(TestFilterV02);
}
