//! Pass-through filter used as the baseline for pipeline performance
//! measurements. Every record is emitted unchanged.

#[cfg(target_arch = "wasm32")]
mod guest {
    wit_bindgen::generate!({
        world: "filter",
        path: "../../wit/s4-filter/world.wit",
    });

    struct NoopFilter;

    impl Guest for NoopFilter {
        fn begin(_context: Context) -> Result<(), String> {
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            Ok(Decision::Emit(payload))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    export!(NoopFilter);
}
