#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod windows;

#[derive(Debug)]
pub struct TpmError;

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TPM-backed key operation failed")
    }
}

impl std::error::Error for TpmError {}

#[cfg(windows)]
pub fn create_rsa_key(name: &str) -> Result<(), TpmError> {
    windows::create_rsa_key(name)
}

#[cfg(not(windows))]
pub fn create_rsa_key(_name: &str) -> Result<(), TpmError> {
    Err(TpmError)
}

#[cfg(windows)]
pub fn encrypt(name: &str, plaintext: &[u8]) -> Result<Vec<u8>, TpmError> {
    windows::encrypt(name, plaintext)
}

#[cfg(not(windows))]
pub fn encrypt(_name: &str, _plaintext: &[u8]) -> Result<Vec<u8>, TpmError> {
    Err(TpmError)
}

#[cfg(windows)]
pub fn decrypt(name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, TpmError> {
    windows::decrypt(name, ciphertext)
}

#[cfg(not(windows))]
pub fn decrypt(_name: &str, _ciphertext: &[u8]) -> Result<Vec<u8>, TpmError> {
    Err(TpmError)
}
