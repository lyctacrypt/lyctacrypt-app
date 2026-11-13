use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result};

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

pub const X25519_LEN: usize = 32;
pub const MLKEM_EK_LEN: usize = 1184;
pub const MLKEM_DK_LEN: usize = 2400;
pub const MLKEM_CT_LEN: usize = 1088;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct HybridPublic {
    pub x25519: [u8; X25519_LEN],
    pub mlkem_ek: Vec<u8>,
}

impl std::fmt::Debug for HybridPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HybridPublic(..)")
    }
}

impl HybridPublic {
    pub fn validate(&self) -> Result<()> {
        if self.mlkem_ek.len() != MLKEM_EK_LEN {
            return Err(Error::Malformed);
        }

        decode_ek(&self.mlkem_ek)?;
        Ok(())
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        let ek = decode_ek(&self.mlkem_ek)?;
        let (ct, ss) = ek.encapsulate(&mut OsRng).map_err(|_| Error::Crypto)?;
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(ss.as_slice());
        Ok((ct.as_slice().to_vec(), out))
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    x25519_secret: [u8; X25519_LEN],
    mlkem_dk: Vec<u8>,
    pub public: HybridPublic,
}

impl std::fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HybridKeyPair(<secret>)")
    }
}

impl HybridKeyPair {
    pub fn generate() -> Self {
        let xs = StaticSecret::random_from_rng(OsRng);
        let xp = PublicKey::from(&xs);
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        Self {
            x25519_secret: xs.to_bytes(),
            mlkem_dk: dk.as_bytes().as_slice().to_vec(),
            public: HybridPublic {
                x25519: xp.to_bytes(),
                mlkem_ek: ek.as_bytes().as_slice().to_vec(),
            },
        }
    }

    pub fn dh(&self, peer_x25519: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let s = StaticSecret::from(self.x25519_secret);
        let shared = s.diffie_hellman(&PublicKey::from(*peer_x25519));
        if !shared.was_contributory() {
            return Err(Error::Crypto);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }

    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        if ct.len() != MLKEM_CT_LEN || self.mlkem_dk.len() != MLKEM_DK_LEN {
            return Err(Error::Malformed);
        }
        let enc = ml_kem::Encoded::<Dk>::try_from(self.mlkem_dk.as_slice())
            .map_err(|_| Error::Malformed)?;
        let dk = Dk::from_bytes(&enc);
        let ct = Ciphertext::<MlKem768>::try_from(ct).map_err(|_| Error::Malformed)?;
        let ss = dk.decapsulate(&ct).map_err(|_| Error::Crypto)?;
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(ss.as_slice());
        Ok(out)
    }
}

pub fn x25519_pair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let s = StaticSecret::random_from_rng(OsRng);
    let p = PublicKey::from(&s);
    (Zeroizing::new(s.to_bytes()), p.to_bytes())
}

fn decode_ek(bytes: &[u8]) -> Result<Ek> {
    let enc = ml_kem::Encoded::<Ek>::try_from(bytes).map_err(|_| Error::Malformed)?;
    Ok(Ek::from_bytes(&enc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let kp = HybridKeyPair::generate();
        let (ct, ss1) = kp.public.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(*ss1, *ss2);
    }

    #[test]
    fn dh_agrees() {
        let a = HybridKeyPair::generate();
        let b = HybridKeyPair::generate();
        assert_eq!(
            *a.dh(&b.public.x25519).unwrap(),
            *b.dh(&a.public.x25519).unwrap()
        );
    }

    #[test]
    fn dh_rejects_low_order() {
        let a = HybridKeyPair::generate();
        assert!(a.dh(&[0u8; 32]).is_err());
    }
}
