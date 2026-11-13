use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hybrid::{HybridKeyPair, HybridPublic};
use crate::primitives::sha3_256;
use crate::{Error, Result};

const FP_DOMAIN: &[u8] = b"LyctaCrypt/identity/v2";
const INVITE_PREFIX: &str = "lycta:";
const INVITE_VERSION: u8 = 2;
const INVITE_RAW_LEN: usize = 1 + 32 + 32 + 32 + 4;

pub type Fingerprint = [u8; 32];

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct IdentityPublic {
    pub static_key: HybridPublic,
}

impl std::fmt::Debug for IdentityPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IdentityPublic({})",
            short_fingerprint(&self.fingerprint())
        )
    }
}

impl IdentityPublic {
    pub fn fingerprint(&self) -> Fingerprint {
        sha3_256(&[
            FP_DOMAIN,
            &self.static_key.x25519,
            &self.static_key.mlkem_ek,
        ])
    }

    pub fn validate(&self) -> Result<()> {
        self.static_key.validate()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serialization cannot fail")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let id: Self = bincode::deserialize(b)?;
        id.validate()?;
        Ok(id)
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    pub static_key: HybridKeyPair,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity(<secret>)")
    }
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            static_key: HybridKeyPair::generate(),
        }
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            static_key: self.static_key.public.clone(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Invite {
    pub onion_key: [u8; 32],

    pub auth_secret: [u8; 32],
    pub fingerprint: Fingerprint,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invite({})", short_fingerprint(&self.fingerprint))
    }
}

impl Invite {
    pub fn encode(&self) -> String {
        let mut raw = zeroize::Zeroizing::new(Vec::with_capacity(INVITE_RAW_LEN));
        raw.push(INVITE_VERSION);
        raw.extend_from_slice(&self.onion_key);
        raw.extend_from_slice(&self.auth_secret);
        raw.extend_from_slice(&self.fingerprint);
        let ck = sha3_256(&[b"LyctaCrypt/invite-ck", &raw]);
        raw.extend_from_slice(&ck[..4]);
        format!(
            "{INVITE_PREFIX}{}",
            BASE32_NOPAD.encode(&raw).to_lowercase()
        )
    }

    pub fn decode(s: &str) -> Result<Self> {
        let lower = zeroize::Zeroizing::new(s.trim().to_ascii_lowercase());
        let body = lower.strip_prefix(INVITE_PREFIX).ok_or(Error::BadInvite)?;
        let raw = zeroize::Zeroizing::new(
            BASE32_NOPAD
                .decode(body.to_uppercase().as_bytes())
                .map_err(|_| Error::BadInvite)?,
        );
        if raw.len() != INVITE_RAW_LEN || raw[0] != INVITE_VERSION {
            return Err(Error::BadInvite);
        }
        let ck = sha3_256(&[b"LyctaCrypt/invite-ck", &raw[..INVITE_RAW_LEN - 4]]);
        if !bool::from(ck[..4].ct_eq(&raw[INVITE_RAW_LEN - 4..])) {
            return Err(Error::BadInvite);
        }
        let mut inv = Self {
            onion_key: [0; 32],
            auth_secret: [0; 32],
            fingerprint: [0; 32],
        };
        inv.onion_key.copy_from_slice(&raw[1..33]);
        inv.auth_secret.copy_from_slice(&raw[33..65]);
        inv.fingerprint.copy_from_slice(&raw[65..97]);
        Ok(inv)
    }

    pub fn verify(&self, bundle: &IdentityPublic) -> Result<()> {
        if bool::from(bundle.fingerprint().ct_eq(&self.fingerprint)) {
            Ok(())
        } else {
            Err(Error::BadInvite)
        }
    }
}

pub fn onion_address(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([3u8]);
    let ck = h.finalize();
    let mut raw = Vec::with_capacity(35);
    raw.extend_from_slice(pubkey);
    raw.extend_from_slice(&ck[..2]);
    raw.push(3);
    format!("{}.onion", BASE32_NOPAD.encode(&raw).to_lowercase())
}

pub fn short_fingerprint(fp: &Fingerprint) -> String {
    let s = BASE32_NOPAD.encode(&fp[..20]);
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

pub fn safety_code(a: &Fingerprint, b: &Fingerprint) -> String {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    let h = sha3_256(&[b"LyctaCrypt/safety", x, y]);
    short_fingerprint(&h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_invite() -> (Invite, IdentityPublic) {
        let p = Identity::generate().public();
        let inv = Invite {
            onion_key: [7u8; 32],
            auth_secret: [8u8; 32],
            fingerprint: p.fingerprint(),
        };
        (inv, p)
    }

    #[test]
    fn invite_roundtrip() {
        let (inv, p) = sample_invite();
        let s = inv.encode();
        assert!(s.starts_with("lycta:"));
        let back = Invite::decode(&s).unwrap();
        assert_eq!(back, inv);
        back.verify(&p).unwrap();
        assert_eq!(
            Invite::decode(&s.to_uppercase()).unwrap(),
            inv,
            "forme QR (majuscules)"
        );
    }

    #[test]
    fn invite_rejects_tamper() {
        let (inv, _) = sample_invite();
        let mut s = inv.encode();
        let last = s.pop().unwrap();
        s.push(if last == 'a' { 'b' } else { 'a' });
        assert!(Invite::decode(&s).is_err());
    }

    #[test]
    fn invite_rejects_wrong_bundle() {
        let (inv, _) = sample_invite();
        assert!(inv.verify(&Identity::generate().public()).is_err());
    }

    #[test]
    fn onion_address_format() {
        let a = onion_address(&[0u8; 32]);
        assert_eq!(a.len(), 56 + 6);
        assert!(a.ends_with("d.onion"));
    }
}
