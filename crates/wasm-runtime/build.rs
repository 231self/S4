pub fn generate_bindings() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let wit_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("wit")
        .join("s4-filter")
        .join("world.wit");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed={}", wit_path.display());

    let status = std::process::Command::new("wit-bindgen")
        .args([
            "host",
            "--world",
            "filter",
            &wit_path.to_string_lossy(),
            "--out-dir",
            &out_dir.to_string_lossy(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!(
                "wit-bindgen host bindings generated in {}",
                out_dir.display()
            );
        }
        Ok(s) => {
            eprintln!("wit-bindgen exited with: {s}");
        }
        Err(e) => {
            eprintln!(
                "wit-bindgen not found ({}). Run 'cargo install wit-bindgen-cli' first.",
                e
            );
            std::fs::write(
                out_dir.join("filter_host.rs"),
                "// wit-bindgen not available\n",
            )
            .ok();
        }
    }
}

fn main() {
    generate_bindings();
}
