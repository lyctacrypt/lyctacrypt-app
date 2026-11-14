use std::iter;
use std::ptr::null_mut;

use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO,
    BCRYPT_SHA256_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_RSA_ALGORITHM,
};

const RSA_BITS: u32 = 2048;

struct Provider(NCRYPT_PROV_HANDLE);

impl Drop for Provider {
    fn drop(&mut self) {
        unsafe { NCryptFreeObject(self.0) };
    }
}

struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { NCryptFreeObject(self.0) };
    }
}

fn wide(value: &str) -> Result<Vec<u16>, super::TpmError> {
    if value.is_empty() || value.len() > 128 || value.contains('\0') {
        return Err(super::TpmError);
    }
    Ok(value.encode_utf16().chain(iter::once(0)).collect())
}

fn status(result: i32) -> Result<(), super::TpmError> {
    if result >= 0 {
        Ok(())
    } else {
        Err(super::TpmError)
    }
}

fn provider() -> Result<Provider, super::TpmError> {
    let mut handle = 0;
    status(unsafe { NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0) })?;
    Ok(Provider(handle))
}

fn open_key(provider: &Provider, name: &str) -> Result<Key, super::TpmError> {
    let name = wide(name)?;
    let mut handle = 0;
    status(unsafe { NCryptOpenKey(provider.0, &mut handle, name.as_ptr(), 0, 0) })?;
    Ok(Key(handle))
}

pub(super) fn create_rsa_key(name: &str) -> Result<(), super::TpmError> {
    let provider = provider()?;
    let name = wide(name)?;
    let mut handle = 0;
    status(unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut handle,
            NCRYPT_RSA_ALGORITHM,
            name.as_ptr(),
            0,
            0,
        )
    })?;
    let key = Key(handle);
    let bits = RSA_BITS.to_le_bytes();
    status(unsafe {
        NCryptSetProperty(
            key.0,
            NCRYPT_LENGTH_PROPERTY,
            bits.as_ptr(),
            bits.len() as u32,
            0,
        )
    })?;
    let export_policy = 0u32.to_le_bytes();
    status(unsafe {
        NCryptSetProperty(
            key.0,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            export_policy.as_ptr(),
            export_policy.len() as u32,
            0,
        )
    })?;
    status(unsafe { NCryptFinalizeKey(key.0, 0) })
}

fn crypt(name: &str, input: &[u8], decrypt: bool) -> Result<Vec<u8>, super::TpmError> {
    let provider = provider()?;
    let key = open_key(&provider, name)?;
    let mut padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: null_mut(),
        cbLabel: 0,
    };
    let operation = if decrypt {
        NCryptDecrypt
    } else {
        NCryptEncrypt
    };
    let mut size = 0;
    status(unsafe {
        operation(
            key.0,
            input.as_ptr(),
            input.len() as u32,
            (&mut padding as *mut BCRYPT_OAEP_PADDING_INFO).cast(),
            null_mut(),
            0,
            &mut size,
            NCRYPT_PAD_OAEP_FLAG,
        )
    })?;
    if size == 0 || size > 4096 {
        return Err(super::TpmError);
    }
    let mut output = vec![0; size as usize];
    status(unsafe {
        operation(
            key.0,
            input.as_ptr(),
            input.len() as u32,
            (&mut padding as *mut BCRYPT_OAEP_PADDING_INFO).cast(),
            output.as_mut_ptr(),
            output.len() as u32,
            &mut size,
            NCRYPT_PAD_OAEP_FLAG,
        )
    })?;
    output.truncate(size as usize);
    Ok(output)
}

pub(super) fn encrypt(name: &str, plaintext: &[u8]) -> Result<Vec<u8>, super::TpmError> {
    crypt(name, plaintext, false)
}

pub(super) fn decrypt(name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, super::TpmError> {
    crypt(name, ciphertext, true)
}
