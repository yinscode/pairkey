// A deployment pins these IDs into every host/SBF binary. Defaults preserve local fixtures.
fn program_id(variable: &str, default: &str) {
    println!("cargo:rerun-if-env-changed={variable}");
    let id = std::env::var(variable).unwrap_or_else(|_| default.to_owned());
    assert!((32..=44).contains(&id.len()) && id.bytes().all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b)), "invalid program ID");
    let file = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("program_id.rs");
    std::fs::write(file, format!("solana_program::declare_id!({id:?});\n")).unwrap();
}
