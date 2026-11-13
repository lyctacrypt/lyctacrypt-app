#![deny(unsafe_code)]

pub mod bridges;
pub mod hardening;
pub mod node;
pub mod qr;
pub mod sandbox;
pub mod tor;
pub mod update;

use std::path::{Path, PathBuf};

pub const VAULT_FILE: &str = "vault.lycta";
pub fn vault_path(data_dir: &Path) -> PathBuf {
    data_dir.join(VAULT_FILE)
}
