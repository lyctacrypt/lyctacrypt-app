use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::hybrid::{HybridKeyPair, HybridPublic, MLKEM_CT_LEN, X25519_LEN};
use crate::identity::{Identity, IdentityPublic};
use crate::primitives::{hkdf_keys, open, seal, sha512, Key};
use crate::ratchet::Ratchet;
use crate::{Error, Result};

pub type SessionId = [u8; 16];

pub const MAX_EXTRA: usize = 512;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Hs1 {
    pub e_x25519: [u8; X25519_LEN],
    pub e_mlkem_ek: Vec<u8>,
    pub ct1: Vec<u8>,
    pub sealed_identity: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Hs2 {
    pub e_x25519: [u8; X25519_LEN],
    pub ct2: Vec<u8>,
    pub ct3: Vec<u8>,
    pub sealed_ratchet: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Hs1Payload {
    identity: Vec<u8>,
    extra: Vec<u8>,
}

pub struct Established {
    pub session_id: SessionId,
    pub ratchet: Ratchet,
    pub peer: IdentityPublic,

    pub peer_extra: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Established(<secret>)")
    }
}

pub struct InitiatorState {
    e: HybridKeyPair,
    ck: Key,
    h2: [u8; 64],
    peer: IdentityPublic,
}

impl std::fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InitiatorState(<secret>)")
    }
}

fn transcript(responder: &IdentityPublic) -> [u8; 64] {
    sha512(&[b"LyctaCrypt/handshake/v2", &responder.to_bytes()])
}

fn concat(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::new());
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

fn hs1_ad(h: &[u8; 64], m: &Hs1) -> Vec<u8> {
    concat(&[h, &m.e_x25519, &m.e_mlkem_ek, &m.ct1]).to_vec()
}

fn hs2_h(h: &[u8; 64], m: &Hs1) -> [u8; 64] {
    sha512(&[
        h,
        &bincode::serialize(m).expect("serialization cannot fail"),
    ])
}

fn hs2_ad(h2: &[u8; 64], m: &Hs2) -> Vec<u8> {
    concat(&[h2, &m.e_x25519, &m.ct2, &m.ct3]).to_vec()
}

fn final_keys(ck: &[u8; 32], ikm: &[u8], h2: &[u8; 64]) -> [Key; 5] {
    hkdf_keys::<5>(ck, ikm, &concat(&[b"LyctaCrypt/hs2", h2]))
}

fn sid_of(k: &Key) -> SessionId {
    let mut s = [0u8; 16];
    s.copy_from_slice(&k[..16]);
    s
}

pub fn initiate(
    me: &Identity,
    peer: &IdentityPublic,
    extra: &[u8],
) -> Result<(Hs1, InitiatorState)> {
    initiate_inner(&me.static_key, &me.public(), peer, extra)
}

fn initiate_inner(
    my_static: &HybridKeyPair,
    my_pub: &IdentityPublic,
    peer: &IdentityPublic,
    extra: &[u8],
) -> Result<(Hs1, InitiatorState)> {
    peer.validate()?;
    if extra.len() > MAX_EXTRA {
        return Err(Error::Malformed);
    }
    let h = transcript(peer);
    let e = HybridKeyPair::generate();

    let (ct1, ss1) = peer.static_key.encapsulate()?;
    let dh1 = e.dh(&peer.static_key.x25519)?;
    let [ck, k1] = hkdf_keys::<2>(&h, &concat(&[&*dh1, &*ss1]), b"LyctaCrypt/hs1");

    let mut m = Hs1 {
        e_x25519: e.public.x25519,
        e_mlkem_ek: e.public.mlkem_ek.clone(),
        ct1,
        sealed_identity: Vec::new(),
        tag: Vec::new(),
    };
    let ad = hs1_ad(&h, &m);
    let payload = Zeroizing::new(bincode::serialize(&Hs1Payload {
        identity: my_pub.to_bytes(),
        extra: extra.to_vec(),
    })?);
    m.sealed_identity = seal(&k1, &ad, &payload);

    let dh2 = my_static.dh(&peer.static_key.x25519)?;
    let [ck, k1b] = hkdf_keys::<2>(&*ck, &*dh2, b"LyctaCrypt/hs1b");
    m.tag = seal(&k1b, &ad, b"");

    let h2 = hs2_h(&h, &m);
    Ok((
        m,
        InitiatorState {
            e,
            ck,
            h2,
            peer: peer.clone(),
        },
    ))
}

pub fn respond(me: &Identity, m: &Hs1) -> Result<(Hs2, Established)> {
    let my_pub = me.public();
    if m.ct1.len() != MLKEM_CT_LEN {
        return Err(Error::Malformed);
    }
    let e_a = HybridPublic {
        x25519: m.e_x25519,
        mlkem_ek: m.e_mlkem_ek.clone(),
    };
    e_a.validate()?;
    let h = transcript(&my_pub);
    let ad = hs1_ad(&h, m);

    let ss1 = me.static_key.decapsulate(&m.ct1)?;
    let dh1 = me.static_key.dh(&m.e_x25519)?;
    let [ck, k1] = hkdf_keys::<2>(&h, &concat(&[&*dh1, &*ss1]), b"LyctaCrypt/hs1");
    let payload: Hs1Payload = bincode::deserialize(&open(&k1, &ad, &m.sealed_identity)?)?;
    if payload.extra.len() > MAX_EXTRA {
        return Err(Error::Malformed);
    }
    let peer = IdentityPublic::from_bytes(&payload.identity)?;

    let dh2 = me.static_key.dh(&peer.static_key.x25519)?;
    let [ck, k1b] = hkdf_keys::<2>(&*ck, &*dh2, b"LyctaCrypt/hs1b");
    open(&k1b, &ad, &m.tag)?;

    let e_b = HybridKeyPair::generate();
    let (ct2, ss2) = peer.static_key.encapsulate()?;
    let (ct3, ss3) = e_a.encapsulate()?;
    let dh3 = e_b.dh(&m.e_x25519)?;
    let dh4 = e_b.dh(&peer.static_key.x25519)?;
    let h2 = hs2_h(&h, m);
    let [rk, k2, sid, hka, nhkb] = final_keys(&ck, &concat(&[&*dh3, &*dh4, &*ss2, &*ss3]), &h2);

    let ratchet_kp = HybridKeyPair::generate();
    let mut out = Hs2 {
        e_x25519: e_b.public.x25519,
        ct2,
        ct3,
        sealed_ratchet: Vec::new(),
    };
    let ad2 = hs2_ad(&h2, &out);
    out.sealed_ratchet = seal(&k2, &ad2, &bincode::serialize(&ratchet_kp.public)?);

    let ratchet = Ratchet::init_responder(&rk, ratchet_kp, &hka, &nhkb);
    Ok((
        out,
        Established {
            session_id: sid_of(&sid),
            ratchet,
            peer,
            peer_extra: Zeroizing::new(payload.extra),
        },
    ))
}

pub fn finish(me: &Identity, st: InitiatorState, m: &Hs2) -> Result<Established> {
    if m.ct2.len() != MLKEM_CT_LEN || m.ct3.len() != MLKEM_CT_LEN {
        return Err(Error::Malformed);
    }
    let ss2 = me.static_key.decapsulate(&m.ct2)?;
    let ss3 = st.e.decapsulate(&m.ct3)?;
    let dh3 = st.e.dh(&m.e_x25519)?;
    let dh4 = me.static_key.dh(&m.e_x25519)?;
    let [rk, k2, sid, hka, nhkb] =
        final_keys(&st.ck, &concat(&[&*dh3, &*dh4, &*ss2, &*ss3]), &st.h2);
    let ad2 = hs2_ad(&st.h2, m);
    let ratchet_pub: HybridPublic = bincode::deserialize(&open(&k2, &ad2, &m.sealed_ratchet)?)?;
    let ratchet = Ratchet::init_initiator(&rk, ratchet_pub, &hka, &nhkb)?;
    Ok(Established {
        session_id: sid_of(&sid),
        ratchet,
        peer: st.peer,
        peer_extra: Zeroizing::new(Vec::new()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_then_chat() {
        let a = Identity::generate();
        let b = Identity::generate();
        let b_pub = b.public();
        let (hs1, st) = initiate(&a, &b_pub, b"return-address").unwrap();
        let (hs2, mut sb) = respond(&b, &hs1).unwrap();
        let mut sa = finish(&a, st, &hs2).unwrap();

        assert_eq!(sa.session_id, sb.session_id);
        assert_eq!(sb.peer, a.public());
        assert_eq!(sa.peer, b_pub);
        assert_eq!(&**sb.peer_extra, b"return-address");

        let m = sa.ratchet.encrypt(b"hello", &sa.session_id).unwrap();
        assert_eq!(&**sb.ratchet.decrypt(&m, &sb.session_id).unwrap(), b"hello");
        let m = sb.ratchet.encrypt(b"yo", &sb.session_id).unwrap();
        assert_eq!(&**sa.ratchet.decrypt(&m, &sa.session_id).unwrap(), b"yo");
    }

    #[test]
    fn impostor_initiator_rejected() {
        let a = Identity::generate();
        let b = Identity::generate();
        let m = Identity::generate();
        let (hs1, _) = initiate_inner(&m.static_key, &a.public(), &b.public(), b"").unwrap();
        assert!(respond(&b, &hs1).is_err());
    }

    #[test]
    fn wrong_responder_fails() {
        let a = Identity::generate();
        let b = Identity::generate();
        let c = Identity::generate();
        let (hs1, _) = initiate(&a, &b.public(), b"").unwrap();
        assert!(respond(&c, &hs1).is_err());
    }

    #[test]
    fn oversized_extra_rejected() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert!(initiate(&a, &b.public(), &[0u8; MAX_EXTRA + 1]).is_err());
    }
}
