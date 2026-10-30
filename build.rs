//! Bakes the proxy's configs into the binary.
//!
//! The keychain trusts this exact binary, so whatever decides where a
//! credential goes has to be part of it. At runtime `--config` only selects one
//! of the configs embedded here, and a file whose contents do not match one of
//! them byte for byte is refused. Changing a config therefore means a rebuild,
//! and a rebuilt binary raises the keychain prompt again -- which is the point.
//!
//! Embedded: the `config.toml` of every `~/.config/agentic-credential-proxy*`
//! directory, so a second instance with its own config works the same way.
//! Each one is named in the build output, so a rebuild shows what went in.

use std::path::PathBuf;

fn main() {
    let mut found = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let base = PathBuf::from(home).join(".config");
        for entry in std::fs::read_dir(&base).into_iter().flatten().flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("agentic-credential-proxy")
            {
                continue;
            }
            let path = entry.path().join("config.toml");
            println!("cargo:rerun-if-changed={}", path.display());
            if path.is_file() {
                println!("cargo:warning=embedding {}", path.display());
                found.push(path);
            }
        }
    }
    found.sort();

    let entries: String = found
        .iter()
        .map(|p| format!("    include_str!({:?}),\n", p.display().to_string()))
        .collect();
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    std::fs::write(out.join("configs.rs"), format!("&[\n{entries}]\n"))
        .expect("writing configs.rs");
}
