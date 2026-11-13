use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand_core::OsRng;
use sha2::Sha512;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

pub type Key = Zeroizing<[u8; KEY_LEN]>;

pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(info, out).expect("valid HKDF length");
}

pub fn hkdf_keys<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> [Key; N] {
    let mut buf = Zeroizing::new(vec![0u8; N * KEY_LEN]);
    hkdf(salt, ikm, info, &mut buf);
    std::array::from_fn(|i| {
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        k.copy_from_slice(&buf[i * KEY_LEN..(i + 1) * KEY_LEN]);
        k
    })
}

pub fn hmac32(key: &[u8], data: &[u8]) -> Key {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepte toute taille");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    k.copy_from_slice(&out[..KEY_LEN]);
    k
}

pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

pub fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

pub fn seal(key: &[u8; KEY_LEN], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("AEAD encryption cannot fail at these sizes");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &[u8; KEY_LEN], ad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(Error::Crypto);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: ad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}
