//! Test-only component used to exercise state and failure isolation in Wasmtime.

#[cfg(target_arch = "wasm32")]
mod guest {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{LazyLock, Mutex};

    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter/world.wit",
    });

    static RECORDS: AtomicUsize = AtomicUsize::new(0);
    static FINISH_OUTPUT: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));

    struct TestFilter;

    impl Guest for TestFilter {
        fn begin(context: Context) -> Result<(), String> {
            RECORDS.store(0, Ordering::SeqCst);
            let mut finish = FINISH_OUTPUT.lock().map_err(|error| error.to_string())?;
            finish.clear();
            if let Some(value) = context.content_type.strip_prefix("test/finish=") {
                finish.extend_from_slice(value.as_bytes());
            }
            if context.stable_fields.as_deref() == Some("finish-trap") {
                finish.extend_from_slice(b"trap");
            }
            if context.stable_fields.as_deref() == Some("finish-large") {
                finish.resize(64 * 1024 + 1, b'x');
            }
            if context.content_type == "test/begin-reject" {
                return Err("begin rejected".to_string());
            }
            if context.content_type == "test/begin-trap" {
                panic!("begin trapped");
            }
            if context.content_type == "test/print-to-stdout" {
                println!("PRINTED_SECRET_OUT");
            }
            if context.content_type == "test/print-to-stderr" {
                eprintln!("PRINTED_SECRET_ERR");
            }
            if context.content_type == "test/print-to-both" {
                println!("PRINTED_SECRET_OUT");
                eprintln!("PRINTED_SECRET_ERR");
            }
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            match payload.as_slice() {
                b"drop" => Ok(Decision::Drop),
                payload if payload.starts_with(b"reject") => {
                    Ok(Decision::Reject("record rejected".to_string()))
                }
                payload if payload.starts_with(b"reject-oversize") => {
                    Ok(Decision::Reject("R".repeat(64 * 1024)))
                }
                payload if payload.starts_with(b"err-oversize") => Err("E".repeat(64 * 1024)),
                payload if payload.starts_with(b"trap") => panic!("transform trapped"),
                payload if payload.starts_with(b"loop") => loop {
                    std::hint::black_box(());
                },
                b"memory" => {
                    let allocation = vec![0_u8; 70 * 1024 * 1024];
                    std::hint::black_box(&allocation);
                    Ok(Decision::Emit(Vec::new()))
                }
                b"state" => {
                    let value = RECORDS.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(Decision::Emit(value.to_string().into_bytes()))
                }
                b"env" => {
                    let home = std::env::var("HOME").unwrap_or_default();
                    Ok(Decision::Emit(format!("HOME={home}").into_bytes()))
                }
                b"fs" => {
                    let content = std::fs::read_to_string("/etc/hostname")
                        .unwrap_or_else(|_| "NO_FILE_ACCESS".to_string());
                    Ok(Decision::Emit(content.into_bytes()))
                }
                _ => Ok(Decision::Emit(payload)),
            }
        }

        fn finish() -> Result<Vec<u8>, String> {
            let finish = FINISH_OUTPUT.lock().map_err(|error| error.to_string())?;
            if finish.as_slice() == b"trap" {
                panic!("finish trapped");
            }
            Ok(finish.clone())
        }
    }

    export!(TestFilter);
}
