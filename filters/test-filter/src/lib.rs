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
            if context.content_type == "test/begin-reject" {
                return Err("begin rejected".to_string());
            }
            if context.content_type == "test/begin-trap" {
                panic!("begin trapped");
            }
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            match payload.as_slice() {
                b"drop" => Ok(Decision::Drop),
                b"reject" => Ok(Decision::Reject("record rejected".to_string())),
                b"trap" => panic!("transform trapped"),
                b"loop" => loop {
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
