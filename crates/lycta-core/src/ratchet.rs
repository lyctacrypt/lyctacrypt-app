use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hybrid::{HybridKeyPair, HybridPublic, MLKEM_CT_LEN};
use crate::primitives::{hkdf_keys, hmac32, open, seal, Key};
use crate::{Error, Result};

const MAX_SKIP: u32 = 1000;

const MAX_SKIPPED_TOTAL: usize = 2000;
const HEADER_AD: &[u8] = b"LyctaCrypt/header/v2";

#[derive(Clone, Serialize, Deserialize, Zeroize)]
struct Header {
    ratchet_pub: HybridPublic,

    kem_ct: Vec<u8>,
    pn: u32,
    n: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub enc_header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for RatchetMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RatchetMessage(..)")
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    hk: [u8; 32],
    n: u32,
    mk: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ratchet {
    rk: [u8; 32],
    self_kp: HybridKeyPair,
    peer_pub: Option<HybridPublic>,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhks: [u8; 32],
    nhkr: [u8; 32],
    ns: u32,
    nr: u32,
    pn: u32,

    pending_kem_ct: Vec<u8>,
    skipped: Vec<SkippedKey>,
}

impl std::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ratchet(ns={}, nr={})", self.ns, self.nr)
    }
}

fn kdf_rk(rk: &[u8; 32], dh: &[u8; 32], ss: &[u8; 32]) -> (Key, Key, Key) {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(ss);
    let [a, b, c] = hkdf_keys::<3>(rk, &*ikm, b"LyctaCrypt/ratchet/rk/v2");
    (a, b, c)
}

fn kdf_ck(ck: &[u8; 32]) -> (Key, Key) {
    (hmac32(ck, &[0x02]), hmac32(ck, &[0x01]))
}

fn header_ad(ad: &[u8]) -> Vec<u8> {
    let mut v = HEADER_AD.to_vec();
    v.extend_from_slice(ad);
    v
}

fn message_ad(ad: &[u8], enc_header: &[u8]) -> Vec<u8> {
    let mut v = ad.to_vec();
    v.extend_from_slice(enc_header);
    v
}

fn decrypt_header(hk: &[u8; 32], ad: &[u8], enc: &[u8]) -> Option<Header> {
    let pt = open(hk, &header_ad(ad), enc).ok()?;
    bincode::deserialize(&pt).ok()
}

impl Ratchet {
    pub fn init_initiator(
        root: &[u8; 32],
        peer: HybridPublic,
        hka: &[u8; 32],
        nhkb: &[u8; 32],
    ) -> Result<Self> {
        peer.validate()?;
        let self_kp = HybridKeyPair::generate();
        let dh = self_kp.dh(&peer.x25519)?;
        let (ct, ss) = peer.encapsulate()?;
        let (rk, cks, nhks) = kdf_rk(root, &dh, &ss);
        Ok(Self {
            rk: *rk,
            self_kp,
            peer_pub: Some(peer),
            cks: Some(*cks),
            ckr: None,
            hks: Some(*hka),
            hkr: None,
            nhks: *nhks,
            nhkr: *nhkb,
            ns: 0,
            nr: 0,
            pn: 0,
            pending_kem_ct: ct,
            skipped: Vec::new(),
        })
    }

    pub fn init_responder(
        root: &[u8; 32],
        self_kp: HybridKeyPair,
        hka: &[u8; 32],
        nhkb: &[u8; 32],
    ) -> Self {
        Self {
            rk: *root,
            self_kp,
            peer_pub: None,
            cks: None,
            ckr: None,
            hks: None,
            hkr: None,
            nhks: *nhkb,
            nhkr: *hka,
            ns: 0,
            nr: 0,
            pn: 0,
            pending_kem_ct: Vec::new(),
            skipped: Vec::new(),
        }
    }

    pub fn can_send(&self) -> bool {
        self.cks.is_some() && self.hks.is_some()
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<RatchetMessage> {
        let ck = self.cks.ok_or(Error::NoSendingChain)?;
        let hk = self.hks.ok_or(Error::NoSendingChain)?;
        let (next_ck, mk) = kdf_ck(&ck);
        let header = Header {
            ratchet_pub: self.self_kp.public.clone(),
            kem_ct: self.pending_kem_ct.clone(),
            pn: self.pn,
            n: self.ns,
        };
        let header_pt = Zeroizing::new(bincode::serialize(&header)?);
        let enc_header = seal(&hk, &header_ad(ad), &header_pt);
        let ciphertext = seal(&mk, &message_ad(ad, &enc_header), plaintext);
        self.cks = Some(*next_ck);
        self.ns = self.ns.checked_add(1).ok_or(Error::Crypto)?;
        Ok(RatchetMessage {
            enc_header,
            ciphertext,
        })
    }

    pub fn decrypt(&mut self, msg: &RatchetMessage, ad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut st = self.clone();
        let pt = st.decrypt_inner(msg, ad)?;
        *self = st;
        Ok(pt)
    }

    fn decrypt_inner(&mut self, msg: &RatchetMessage, ad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let full_ad = message_ad(ad, &msg.enc_header);

        let mut found = None;
        for (i, sk) in self.skipped.iter().enumerate() {
            if let Some(h) = decrypt_header(&sk.hk, ad, &msg.enc_header) {
                if h.n == sk.n {
                    found = Some(i);
                    break;
                }
            }
        }
        if let Some(i) = found {
            let sk = self.skipped.remove(i);
            return open(&sk.mk, &full_ad, &msg.ciphertext);
        }

        let current = self
            .hkr
            .and_then(|hk| decrypt_header(&hk, ad, &msg.enc_header));
        let header = match current {
            Some(h) => h,
            None => {
                let h = decrypt_header(&self.nhkr, ad, &msg.enc_header).ok_or(Error::Crypto)?;
                if self.ckr.is_some() {
                    self.skip_until(h.pn)?;
                }
                self.asym_step(&h)?;
                h
            }
        };

        self.skip_until(header.n)?;
        let ck = self.ckr.ok_or(Error::Crypto)?;
        let (next_ck, mk) = kdf_ck(&ck);
        let pt = open(&mk, &full_ad, &msg.ciphertext)?;
        self.ckr = Some(*next_ck);
        self.nr = self.nr.checked_add(1).ok_or(Error::Crypto)?;
        Ok(pt)
    }

    fn skip_until(&mut self, until: u32) -> Result<()> {
        let Some(mut ck) = self.ckr else {
            return Ok(());
        };
        if until <= self.nr {
            return Ok(());
        }
        if until - self.nr > MAX_SKIP {
            return Err(Error::TooManySkipped);
        }
        let hk = self.hkr.ok_or(Error::Crypto)?;
        while self.nr < until {
            let (next, mk) = kdf_ck(&ck);
            self.skipped.push(SkippedKey {
                hk,
                n: self.nr,
                mk: *mk,
            });
            ck = *next;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        while self.skipped.len() > MAX_SKIPPED_TOTAL {
            self.skipped.remove(0);
        }
        Ok(())
    }

    fn asym_step(&mut self, h: &Header) -> Result<()> {
        h.ratchet_pub.validate()?;
        if h.kem_ct.len() != MLKEM_CT_LEN {
            return Err(Error::Malformed);
        }

        let dh = self.self_kp.dh(&h.ratchet_pub.x25519)?;
        let ss = self.self_kp.decapsulate(&h.kem_ct)?;
        let (rk, ckr, nhkr) = kdf_rk(&self.rk, &dh, &ss);

        let new_kp = HybridKeyPair::generate();
        let dh2 = new_kp.dh(&h.ratchet_pub.x25519)?;
        let (ct, ss2) = h.ratchet_pub.encapsulate()?;
        let (rk2, cks, nhks) = kdf_rk(&rk, &dh2, &ss2);

        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = Some(self.nhks);
        self.hkr = Some(self.nhkr);
        self.nhkr = *nhkr;
        self.nhks = *nhks;
        self.rk = *rk2;
        self.ckr = Some(*ckr);
        self.cks = Some(*cks);
        self.self_kp = new_kp;
        self.peer_pub = Some(h.ratchet_pub.clone());
        self.pending_kem_ct = ct;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Ratchet, Ratchet) {
        let root = [42u8; 32];
        let (hka, nhkb) = ([1u8; 32], [2u8; 32]);
        let bob_kp = HybridKeyPair::generate();
        let bob_pub = bob_kp.public.clone();
        let bob = Ratchet::init_responder(&root, bob_kp, &hka, &nhkb);
        let alice = Ratchet::init_initiator(&root, bob_pub, &hka, &nhkb).unwrap();
        (alice, bob)
    }

    #[test]
    fn ping_pong() {
        let (mut a, mut b) = pair();
        for i in 0..5 {
            let m = a.encrypt(format!("a{i}").as_bytes(), b"ad").unwrap();
            assert_eq!(&**b.decrypt(&m, b"ad").unwrap(), format!("a{i}").as_bytes());
            let m = b.encrypt(format!("b{i}").as_bytes(), b"ad").unwrap();
            assert_eq!(&**a.decrypt(&m, b"ad").unwrap(), format!("b{i}").as_bytes());
        }
    }

    #[test]
    fn many_in_a_row_both_ways() {
        let (mut a, mut b) = pair();
        for _ in 0..3 {
            for i in 0..4u8 {
                let m = a.encrypt(&[i], b"").unwrap();
                assert_eq!(&**b.decrypt(&m, b"").unwrap(), &[i]);
            }
            for i in 0..4u8 {
                let m = b.encrypt(&[i], b"").unwrap();
                assert_eq!(&**a.decrypt(&m, b"").unwrap(), &[i]);
            }
        }
    }

    #[test]
    fn responder_cannot_send_first() {
        let (_a, mut b) = pair();
        assert!(b.encrypt(b"x", b"ad").is_err());
    }

    #[test]
    fn out_of_order() {
        let (mut a, mut b) = pair();
        let m1 = a.encrypt(b"1", b"").unwrap();
        let m2 = a.encrypt(b"2", b"").unwrap();
        let m3 = a.encrypt(b"3", b"").unwrap();
        assert_eq!(&**b.decrypt(&m3, b"").unwrap(), b"3");
        assert_eq!(&**b.decrypt(&m1, b"").unwrap(), b"1");
        let r = b.encrypt(b"r", b"").unwrap();
        a.decrypt(&r, b"").unwrap();
        let m4 = a.encrypt(b"4", b"").unwrap();
        assert_eq!(&**b.decrypt(&m4, b"").unwrap(), b"4");
        assert_eq!(&**b.decrypt(&m2, b"").unwrap(), b"2");
    }

    #[test]
    fn replay_and_tamper_rejected_without_state_change() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"hello", b"").unwrap();
        let mut bad = m.clone();
        let last = bad.ciphertext.len() - 1;
        bad.ciphertext[last] ^= 1;
        assert!(b.decrypt(&bad, b"").is_err());
        let mut bad_h = m.clone();
        bad_h.enc_header[30] ^= 1;
        assert!(b.decrypt(&bad_h, b"").is_err());
        assert_eq!(&**b.decrypt(&m, b"").unwrap(), b"hello");
        assert!(b.decrypt(&m, b"").is_err(), "replay refused");
    }

    #[test]
    fn wrong_ad_rejected() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"x", b"session-1").unwrap();
        assert!(b.decrypt(&m, b"session-2").is_err());
    }

    #[test]
    fn messages_have_constant_size() {
        let (mut a, _b) = pair();
        let m1 = a.encrypt(&[0u8; 1024], b"").unwrap();
        let m2 = a.encrypt(&[0u8; 1024], b"").unwrap();
        assert_eq!(m1.enc_header.len(), m2.enc_header.len());
        assert_eq!(m1.ciphertext.len(), m2.ciphertext.len());
    }
}
