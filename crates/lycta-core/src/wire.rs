use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::handshake::{Hs1, Hs2, SessionId};
use crate::ratchet::RatchetMessage;
use crate::{Error, Result};

pub const FRAME_BLOCK: usize = 4096;
pub const MAX_FRAME: usize = 64 * 1024;
pub const CONTENT_BLOCK: usize = 1024;
pub const MAX_TEXT: usize = 16 * 1024;

pub const MAX_BATCH: usize = 12;

pub const ONION_PORT: u16 = 7469;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Frame {
    GetBundle,
    Bundle(Vec<u8>),
    Hs1(Hs1),
    Hs2(Hs2),
    Msg {
        session_id: SessionId,
        msg: RatchetMessage,
    },
    Ack,

    Nack,

    Deposit {
        deposit_id: [u8; 32],
        frame: Vec<u8>,
    },

    Fetch {
        fetch_key: [u8; 32],
    },
    Batch(Vec<Vec<u8>>),
}

pub fn encode_frame(f: &Frame) -> Result<Vec<u8>> {
    let body = bincode::serialize(f)?;
    let inner = 4 + body.len();
    let padded = inner.div_ceil(FRAME_BLOCK) * FRAME_BLOCK;
    if padded > MAX_FRAME {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(4 + padded);
    out.extend_from_slice(&(padded as u32).to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.resize(4 + padded, 0);
    Ok(out)
}

pub fn decode_frame(padded: &[u8]) -> Result<Frame> {
    if padded.len() < 4 || padded.len() % FRAME_BLOCK != 0 || padded.len() > MAX_FRAME {
        return Err(Error::Malformed);
    }
    let n = u32::from_be_bytes(padded[..4].try_into().expect("4 bytes")) as usize;
    let body = padded
        .get(4..4usize.checked_add(n).ok_or(Error::Malformed)?)
        .ok_or(Error::Malformed)?;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_FRAME as u64)
        .deserialize(body)?)
}

pub fn decode_raw_frame(raw: &[u8]) -> Result<Frame> {
    if raw.len() < 4 {
        return Err(Error::Malformed);
    }
    let n = check_frame_len(u32::from_be_bytes(raw[..4].try_into().expect("4 bytes")))?;
    if raw.len() != 4 + n {
        return Err(Error::Malformed);
    }
    decode_frame(&raw[4..])
}

pub fn check_frame_len(n: u32) -> Result<usize> {
    let n = n as usize;
    if n == 0 || n > MAX_FRAME || n % FRAME_BLOCK != 0 {
        return Err(Error::Malformed);
    }
    Ok(n)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Content {
    Hello,
    Text(String),

    Cover,

    Timer(u32),

    MailboxRequest,

    MailboxGrant {
        onion_key: [u8; 32],
        auth_secret: [u8; 32],
    },

    MailboxInfo {
        onion_key: [u8; 32],
        auth_secret: [u8; 32],
        deposit_id: [u8; 32],
    },

    MailboxRevoke,

    FileStart {
        file_id: [u8; 16],
        name: String,
        size: u64,
        chunks: u32,
        hash: [u8; 32],
    },

    FileChunk {
        file_id: [u8; 16],
        index: u32,
        data: Vec<u8>,
    },

    GroupCreate {
        group_id: [u8; 16],
        members: Vec<[u8; 32]>,
    },

    GroupText {
        group_id: [u8; 16],
        author: [u8; 32],
        text: String,
    },
    GroupLeave {
        group_id: [u8; 16],
    },

    Rotate {
        identity: Vec<u8>,
    },

    Op(MsgOp),

    GroupOp {
        group_id: [u8; 16],
        author: [u8; 32],
        op: MsgOp,
    },

    GroupMember {
        group_id: [u8; 16],
        identity: Vec<u8>,
    },

    GroupKey {
        group_id: [u8; 16],
        author: [u8; 32],
        to: [u8; 32],
        sealed: Vec<u8>,
    },

    GroupSealed {
        group_id: [u8; 16],
        author: [u8; 32],
        key_id: u32,
        n: u32,
        ct: Vec<u8>,
        sig: Vec<u8>,
    },

    Device(DeviceMsg),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceMsg {
    Link,

    Accept,

    Unlink,

    Peer {
        fp: [u8; 32],
        note: Option<String>,
    },

    Sync {
        fp: [u8; 32],
        out: bool,
        ttl: u32,
        op: MsgOp,
    },

    Send {
        fp: [u8; 32],
        op: MsgOp,
    },
}

impl std::fmt::Debug for DeviceMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceMsg(<redacted>)")
    }
}

impl DeviceMsg {
    fn valid(&self) -> bool {
        match self {
            DeviceMsg::Peer { note, .. } => note.as_ref().is_none_or(|n| n.len() <= 256),
            DeviceMsg::Sync { op, .. } | DeviceMsg::Send { op, .. } => op.valid(),
            _ => true,
        }
    }
}

pub const MAX_GROUP_BLOB: usize = 2048;

pub fn encode_op(op: &MsgOp) -> Result<Zeroizing<Vec<u8>>> {
    if !op.valid() {
        return Err(Error::Malformed);
    }
    Ok(Zeroizing::new(bincode::serialize(op)?))
}

pub fn decode_op(b: &[u8]) -> Result<MsgOp> {
    let op: MsgOp = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit((MAX_TEXT * 2) as u64)
        .deserialize(b)?;
    if !op.valid() {
        return Err(Error::Malformed);
    }
    Ok(op)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MsgOp {
    Message {
        id: [u8; 16],
        text: String,
        reply_to: Option<[u8; 16]>,
    },

    React {
        target: [u8; 16],
        emoji: String,
    },

    Edit {
        target: [u8; 16],
        text: String,
    },

    Delete {
        target: [u8; 16],
    },
}

pub const MAX_EMOJI: usize = 32;

impl MsgOp {
    fn valid(&self) -> bool {
        match self {
            MsgOp::Message { text, .. } | MsgOp::Edit { text, .. } => text.len() <= MAX_TEXT,
            MsgOp::React { emoji, .. } => emoji.len() <= MAX_EMOJI,
            MsgOp::Delete { .. } => true,
        }
    }
}

pub const FILE_CHUNK: usize = 960;

pub const MAX_FILE: usize = 1024 * 1024;
pub const MAX_FILE_NAME: usize = 120;
pub const MAX_GROUP_MEMBERS: usize = 32;

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Content(<redacted>)")
    }
}

impl std::fmt::Debug for MsgOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MsgOp(<redacted>)")
    }
}

pub fn encode_content(c: &Content) -> Result<Zeroizing<Vec<u8>>> {
    let ok = match c {
        Content::Text(t) | Content::GroupText { text: t, .. } => t.len() <= MAX_TEXT,
        Content::FileStart { name, .. } => name.len() <= MAX_FILE_NAME,
        Content::FileChunk { data, .. } => data.len() <= FILE_CHUNK,
        Content::GroupCreate { members, .. } => members.len() <= MAX_GROUP_MEMBERS,
        Content::Op(op) | Content::GroupOp { op, .. } => op.valid(),
        Content::Device(d) => d.valid(),
        Content::GroupMember { identity, .. } => identity.len() <= MAX_GROUP_BLOB,
        Content::GroupKey { sealed, .. } => sealed.len() <= MAX_GROUP_BLOB,
        Content::GroupSealed { ct, sig, .. } => ct.len() <= MAX_TEXT + 1024 && sig.len() == 64,
        _ => true,
    };
    if !ok {
        return Err(Error::Malformed);
    }
    let body = Zeroizing::new(bincode::serialize(c)?);
    let inner = 4 + body.len();
    let padded = inner.div_ceil(CONTENT_BLOCK) * CONTENT_BLOCK;
    let mut out = Zeroizing::new(Vec::with_capacity(padded));
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.resize(padded, 0);
    Ok(out)
}

pub fn decode_content(b: &[u8]) -> Result<Content> {
    if b.len() < 4 || b.len() % CONTENT_BLOCK != 0 {
        return Err(Error::Malformed);
    }
    let n = u32::from_be_bytes(b[..4].try_into().expect("4 bytes")) as usize;
    let body = b
        .get(4..4usize.checked_add(n).ok_or(Error::Malformed)?)
        .ok_or(Error::Malformed)?;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit((MAX_TEXT * 2) as u64)
        .deserialize(body)?)
}

use bincode::Options as _;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, RngCore};

    #[test]
    fn frame_padding() {
        let e = encode_frame(&Frame::Ack).unwrap();
        assert_eq!(e.len(), 4 + FRAME_BLOCK);
        assert!(matches!(decode_raw_frame(&e).unwrap(), Frame::Ack));
    }

    #[test]
    fn content_sizes_are_bucketed() {
        let a = encode_content(&Content::Text("a".into())).unwrap();
        let b = encode_content(&Content::Text("b".repeat(900))).unwrap();
        let c = encode_content(&Content::Cover).unwrap();
        let d = encode_content(&Content::MailboxInfo {
            onion_key: [1; 32],
            auth_secret: [2; 32],
            deposit_id: [3; 32],
        })
        .unwrap();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), c.len());
        assert_eq!(a.len(), d.len());
        assert!(decode_content(&a).unwrap() == Content::Text("a".into()));

        let f = encode_content(&Content::FileChunk {
            file_id: [9; 16],
            index: u32::MAX,
            data: vec![0xAB; FILE_CHUNK],
        })
        .unwrap();
        assert_eq!(a.len(), f.len());
        assert!(encode_content(&Content::FileChunk {
            file_id: [0; 16],
            index: 0,
            data: vec![0; FILE_CHUNK + 1]
        })
        .is_err());
    }

    #[test]
    fn message_ops_roundtrip_and_hide_their_kind() {
        let ops = [
            MsgOp::Message {
                id: [1; 16],
                text: "hi".into(),
                reply_to: Some([2; 16]),
            },
            MsgOp::React {
                target: [1; 16],
                emoji: "👍".into(),
            },
            MsgOp::Edit {
                target: [1; 16],
                text: "hello".into(),
            },
            MsgOp::Delete { target: [1; 16] },
        ];
        let short = encode_content(&Content::Text("x".into())).unwrap();
        for op in ops {
            let enc = encode_content(&Content::Op(op.clone())).unwrap();
            assert_eq!(enc.len(), short.len(), "same size as any short message");
            assert!(decode_content(&enc).unwrap() == Content::Op(op));
        }
        assert!(encode_content(&Content::Op(MsgOp::React {
            target: [0; 16],
            emoji: "x".repeat(MAX_EMOJI + 1)
        }))
        .is_err());
    }

    #[test]
    fn decoders_never_panic_on_garbage() {
        let mut rng = rand::thread_rng();
        for _ in 0..3000 {
            let len = FRAME_BLOCK * rng.gen_range(1..=3);
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            if rng.gen_bool(0.5) {
                buf[..4].copy_from_slice(&(rng.gen_range(0..64u32)).to_be_bytes());
            }
            let _ = decode_frame(&buf);
            let _ = decode_raw_frame(&buf);
            let mut c = vec![0u8; CONTENT_BLOCK * rng.gen_range(1..=2)];
            rng.fill_bytes(&mut c);
            if rng.gen_bool(0.5) {
                c[..4].copy_from_slice(&(rng.gen_range(0..64u32)).to_be_bytes());
            }
            let _ = decode_content(&c);
            let _ = crate::identity::Invite::decode(&String::from_utf8_lossy(&buf[..200]));
        }
    }
}
