use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hybrid::{HybridKeyPair, MLKEM_CT_LEN};
use crate::identity::{Identity, IdentityPublic};
use crate::primitives::{hkdf_keys, hmac32, open, random_bytes, seal, sha512};
use crate::{Error, Result};

const MAX_SKIP: u32 = 512;

const MAX_SKIPPED: usize = 128;

const PAD_BLOCK: usize = 128;

#[derive(Serialize, Deserialize)]
struct SealedBox {
    e_x25519: [u8; 32],
    ct: Vec<u8>,
    sealed: Vec<u8>,
}

fn box_transcript(sender: &IdentityPublic, recipient: &IdentityPublic, ad: &[u8]) -> [u8; 64] {
    sha512(&[
        b"LyctaCrypt/group-box/v1",
        &sender.to_bytes(),
        &recipient.to_bytes(),
        ad,
    ])
}

fn box_key(
    h: &[u8; 64],
    dh_e: &[u8; 32],
    ss: &[u8; 32],
    dh_s: &[u8; 32],
) -> crate::primitives::Key {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(dh_e);
    ikm.extend_from_slice(ss);
    ikm.extend_from_slice(dh_s);
    let [k] = hkdf_keys::<1>(h, &ikm, b"LyctaCrypt/group-box/key");
    k
}

pub fn seal_to(
    me: &Identity,
    recipient: &IdentityPublic,
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    recipient.validate()?;
    let h = box_transcript(&me.public(), recipient, ad);
    let e = HybridKeyPair::generate();
    let (ct, ss) = recipient.static_key.encapsulate()?;
    let dh_e = e.dh(&recipient.static_key.x25519)?;
    let dh_s = me.static_key.dh(&recipient.static_key.x25519)?;
    let k = box_key(&h, &dh_e, &ss, &dh_s);
    let mut ad2 = h.to_vec();
    ad2.extend_from_slice(&e.public.x25519);
    ad2.extend_from_slice(&ct);
    let sealed = seal(&k, &ad2, plaintext);
    Ok(bincode::serialize(&SealedBox {
        e_x25519: e.public.x25519,
        ct,
        sealed,
    })?)
}

pub fn open_from(
    me: &Identity,
    sender: &IdentityPublic,
    ad: &[u8],
    boxed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    sender.validate()?;
    let b: SealedBox = bincode::deserialize(boxed)?;
    if b.ct.len() != MLKEM_CT_LEN {
        return Err(Error::Malformed);
    }
    let h = box_transcript(sender, &me.public(), ad);
    let ss = me.static_key.decapsulate(&b.ct)?;
    let dh_e = me.static_key.dh(&b.e_x25519)?;
    let dh_s = me.static_key.dh(&sender.static_key.x25519)?;
    let k = box_key(&h, &dh_e, &ss, &dh_s);
    let mut ad2 = h.to_vec();
    ad2.extend_from_slice(&b.e_x25519);
    ad2.extend_from_slice(&b.ct);
    open(&k, &ad2, &b.sealed)
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderAnnounce {
    pub key_id: u32,
    pub chain: [u8; 32],
    pub n: u32,
    pub verify: [u8; 32],
}

pub fn key_ad(group_id: &[u8; 16]) -> Vec<u8> {
    let mut ad = b"LyctaCrypt/group-key/v1".to_vec();
    ad.extend_from_slice(group_id);
    ad
}

impl SenderAnnounce {
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(bincode::serialize(self).expect("infallible"))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(b)?)
    }
}

impl std::fmt::Debug for SenderAnnounce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SenderAnnounce(<secret>)")
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKey {
    pub key_id: u32,
    chain: [u8; 32],
    n: u32,
    signing: [u8; 32],

    pub given_to: Vec<[u8; 32]>,
}

impl std::fmt::Debug for SenderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SenderKey(<secret>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub key_id: u32,
    pub n: u32,
    pub ct: Vec<u8>,
    pub sig: Vec<u8>,
}

fn step(chain: &[u8; 32]) -> ([u8; 32], crate::primitives::Key) {
    let mk = hmac32(chain, &[1]);
    let next = hmac32(chain, &[2]);
    (*next, mk)
}

fn message_ad(group_id: &[u8; 16], author: &[u8; 32], key_id: u32, n: u32) -> Vec<u8> {
    let mut ad = b"LyctaCrypt/group-msg/v1".to_vec();
    ad.extend_from_slice(group_id);
    ad.extend_from_slice(author);
    ad.extend_from_slice(&key_id.to_be_bytes());
    ad.extend_from_slice(&n.to_be_bytes());
    ad
}

fn pad(pt: &[u8]) -> Zeroizing<Vec<u8>> {
    let total = (4 + pt.len()).div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&(pt.len() as u32).to_be_bytes());
    out.extend_from_slice(pt);
    out.resize(total, 0);
    out
}

fn unpad(mut padded: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    if padded.len() < 4 {
        return Err(Error::Malformed);
    }
    let n = u32::from_be_bytes(padded[..4].try_into().expect("4 bytes")) as usize;
    if n > padded.len() - 4 {
        return Err(Error::Malformed);
    }
    padded.copy_within(4..4 + n, 0);
    padded.truncate(n);
    Ok(padded)
}

impl SenderKey {
    pub fn generate() -> Self {
        Self {
            key_id: u32::from_be_bytes(random_bytes()),
            chain: random_bytes(),
            n: 0,
            signing: random_bytes(),
            given_to: Vec::new(),
        }
    }

    pub fn announce(&self) -> SenderAnnounce {
        SenderAnnounce {
            key_id: self.key_id,
            chain: self.chain,
            n: self.n,
            verify: SigningKey::from_bytes(&self.signing)
                .verifying_key()
                .to_bytes(),
        }
    }

    pub fn encrypt(&mut self, group_id: &[u8; 16], author: &[u8; 32], pt: &[u8]) -> Sealed {
        let (next, mk) = step(&self.chain);
        let n = self.n;
        let ad = message_ad(group_id, author, self.key_id, n);
        let ct = seal(&mk, &ad, &pad(pt));
        let mut signed = ad;
        signed.extend_from_slice(&ct);
        let sig = SigningKey::from_bytes(&self.signing).sign(&signed);
        self.chain.zeroize();
        self.chain = next;
        self.n += 1;
        Sealed {
            key_id: self.key_id,
            n,
            ct,
            sig: sig.to_bytes().to_vec(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PeerSender {
    pub author: [u8; 32],
    key_id: u32,
    chain: [u8; 32],
    n: u32,
    verify: [u8; 32],

    skipped: Vec<(u32, [u8; 32])>,
}

impl std::fmt::Debug for PeerSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerSender(<secret>)")
    }
}

impl PeerSender {
    pub fn new(author: [u8; 32], a: &SenderAnnounce) -> Result<Self> {
        VerifyingKey::from_bytes(&a.verify).map_err(|_| Error::Malformed)?;
        Ok(Self {
            author,
            key_id: a.key_id,
            chain: a.chain,
            n: a.n,
            verify: a.verify,
            skipped: Vec::new(),
        })
    }

    pub fn decrypt(&mut self, group_id: &[u8; 16], m: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
        if m.key_id != self.key_id {
            return Err(Error::Crypto);
        }
        let ad = message_ad(group_id, &self.author, m.key_id, m.n);
        let mut signed = ad.clone();
        signed.extend_from_slice(&m.ct);
        let sig: [u8; 64] = m.sig.as_slice().try_into().map_err(|_| Error::Malformed)?;
        VerifyingKey::from_bytes(&self.verify)
            .map_err(|_| Error::Malformed)?
            .verify_strict(&signed, &Signature::from_bytes(&sig))
            .map_err(|_| Error::Crypto)?;

        if m.n < self.n {
            let pos = self
                .skipped
                .iter()
                .position(|(n, _)| *n == m.n)
                .ok_or(Error::Crypto)?;
            let pt = open(&self.skipped[pos].1, &ad, &m.ct)?;
            let mut used = self.skipped.remove(pos);
            used.1.zeroize();
            return unpad(pt);
        }
        if m.n - self.n > MAX_SKIP {
            return Err(Error::Crypto);
        }

        let mut chain = Zeroizing::new(self.chain);
        let mut skipped: Vec<(u32, [u8; 32])> = Vec::new();
        for k in self.n..m.n {
            let (next, mk) = step(&chain);
            skipped.push((k, *mk));
            *chain = next;
        }
        let (next, mk) = step(&chain);
        let pt = match open(&mk, &ad, &m.ct) {
            Ok(pt) => pt,
            Err(e) => {
                skipped.zeroize();
                return Err(e);
            }
        };
        self.chain.zeroize();
        self.chain = next;
        self.n = m.n + 1;
        self.skipped.append(&mut skipped);
        if self.skipped.len() > MAX_SKIPPED {
            let excess = self.skipped.len() - MAX_SKIPPED;
            for mut s in self.skipped.drain(..excess) {
                s.1.zeroize();
            }
        }
        unpad(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_box_is_bound_to_sender_recipient_and_context() {
        let (a, b, c) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let boxed = seal_to(&a, &b.public(), b"group-1", b"secret").unwrap();
        assert_eq!(
            &**open_from(&b, &a.public(), b"group-1", &boxed).unwrap(),
            b"secret"
        );

        assert!(open_from(&c, &a.public(), b"group-1", &boxed).is_err());
        assert!(open_from(&b, &c.public(), b"group-1", &boxed).is_err());
        assert!(open_from(&b, &a.public(), b"group-2", &boxed).is_err());
        let mut bad = boxed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open_from(&b, &a.public(), b"group-1", &bad).is_err());
    }

    fn pair() -> (SenderKey, PeerSender, [u8; 16], [u8; 32]) {
        let sk = SenderKey::generate();
        let author = [7; 32];
        let ps = PeerSender::new(author, &sk.announce()).unwrap();
        (sk, ps, [1; 16], author)
    }

    #[test]
    fn messages_decrypt_in_and_out_of_order() {
        let (mut sk, mut ps, gid, author) = pair();
        let m0 = sk.encrypt(&gid, &author, b"zero");
        let m1 = sk.encrypt(&gid, &author, b"one");
        let m2 = sk.encrypt(&gid, &author, b"two");
        assert_eq!(&**ps.decrypt(&gid, &m2).unwrap(), b"two");
        assert_eq!(&**ps.decrypt(&gid, &m0).unwrap(), b"zero");
        assert_eq!(&**ps.decrypt(&gid, &m1).unwrap(), b"one");

        assert!(ps.decrypt(&gid, &m1).is_err());
        assert!(ps.decrypt(&gid, &m2).is_err());
    }

    #[test]
    fn length_is_hidden_and_forgeries_fail() {
        let (mut sk, mut ps, gid, author) = pair();
        let short = sk.encrypt(&gid, &author, b"a");
        let longer = sk.encrypt(&gid, &author, &[b'x'; 100]);
        assert_eq!(short.ct.len(), longer.ct.len());

        let mut forger = SenderKey::generate();
        forger.key_id = sk.key_id;
        forger.chain = sk.chain;
        forger.n = sk.n;
        let forged = forger.encrypt(&gid, &author, b"forged");
        assert!(ps.decrypt(&gid, &forged).is_err());

        let real = sk.encrypt(&gid, &author, b"real");
        assert!(ps.decrypt(&gid, &short).is_ok());
        assert_eq!(&**ps.decrypt(&gid, &real).unwrap(), b"real");

        let m = sk.encrypt(&gid, &author, b"x");
        assert!(ps.decrypt(&[2; 16], &m).is_err());
        let mut t = m.clone();
        t.ct[0] ^= 1;
        assert!(ps.decrypt(&gid, &t).is_err());
        assert!(ps.decrypt(&gid, &m).is_ok());
    }

    #[test]
    fn late_joiner_reads_only_from_the_announcement_on() {
        let mut sk = SenderKey::generate();
        let (gid, author) = ([3; 16], [9; 32]);
        let before = sk.encrypt(&gid, &author, b"before");
        let mut late = PeerSender::new(author, &sk.announce()).unwrap();
        let after = sk.encrypt(&gid, &author, b"after");
        assert!(late.decrypt(&gid, &before).is_err());
        assert_eq!(&**late.decrypt(&gid, &after).unwrap(), b"after");
    }
}
