# LyctaCrypt protocol v2

## Primitives

| Role | Primitive |
|---|---|
| Post-quantum KEM | ML-KEM-768 (FIPS 203) |
| Classical exchange | X25519 (small-order points rejected) |
| KDF | HKDF-SHA512; ratchet chains use HMAC-SHA512 |
| AEAD | XChaCha20-Poly1305 (random 192-bit nonce) |
| Fingerprints | SHA3-256 with domain separation and length prefixes |
| Vault | Argon2id (64 MiB, t=3, p=1) |
| Signatures | Ed25519, only for group authors and updates |

Sessions between two people need no signatures: authentication relies on **static KEMs and
static Diffie-Hellman** (the "KEMTLS / Noise IK" approach).

## Identity

```
IdentityPublic = { x25519[32], mlkem_ek[1184] }
fingerprint    = SHA3-256("LyctaCrypt/identity/v2", x25519, mlkem_ek)
```

An identity contains **no address**. Onion addresses belong to each relationship.

## Onion services ("slots")

Each local onion service has an ed25519 seed (kept in the vault) and **a single authorized
client key** (restricted discovery: the descriptor can only be decrypted with the matching
x25519 key).

| Type | Use |
|---|---|
| Invite | Created by `/invite`, usable by a single identity |
| Contact | An address only that contact knows |
| Mailbox | Hosted for a friend, open to that friend's contacts |

## Invite (single use)

```
"lycta:" + base32( 0x02 || onion_key[32] || auth_secret[32] || fingerprint[32] || ck[4] )
```

`auth_secret` is the x25519 key that allows discovering the invite service. The other person
fetches the bundle (`GetBundle`) and **checks it against the fingerprint**. As soon as a
handshake succeeds on that service, it is bound to that identity: any other identity is refused.

## Handshake (A initiates, B responds)

```
h   = SHA512("LyctaCrypt/handshake/v2", bundle_B)

A → B : Hs1
  eA            new ephemeral hybrid key pair
  ct1, ss1      = Encap(B.static.mlkem)
  ck, k1        = HKDF(h, DH(eA, sB) || ss1, "hs1")
  sealed        = AEAD(k1, ad, { bundle_A, extra })    -- extra: return address + access key
  ck, k1b       = HKDF(ck, DH(sA, sB), "hs1b")
  tag           = AEAD(k1b, ad, "")

B → A : Hs2
  eB            new ephemeral X25519 key
  ct2, ss2      = Encap(A.static.mlkem)
  ct3, ss3      = Encap(eA.mlkem)
  RK, k2, sid, HKa, NHKb = HKDF(ck, DH(eB,eA) || DH(eB,sA) || ss2 || ss3, "hs2" || h2)
  sealed_ratchet = AEAD(k2, ad2, ratchet_B.public)
```

When a contact is added from an invite, `extra` (at most 512 bytes) carries the onion address A
dedicates to B and the x25519 key that lets B discover it. Formal model:
[formal/handshake.pv](formal/handshake.pv).

- Mutual authentication is implicit, both classical (static DH) and post-quantum
  (encapsulation to the static KEM keys).
- Forward secrecy is post-quantum through `ss3` and classical through `DH(eB, eA)`.
- A's identity and `extra` are encrypted: only B learns them.
- `HKa` and `NHKb` initialize header encryption in the ratchet.

## Hybrid double ratchet with encrypted headers

Each time the direction of the conversation changes:

```
RK, CKr, NHKr = HKDF(RK, DH(self, peer_new) || Decap(self.mlkem, kem_ct))
self          = new hybrid key pair
RK, CKs, NHKs = HKDF(RK, DH(self, peer_new) || ss)    where (kem_ct, ss) = Encap(peer_new.mlkem)
HKs, HKr      ← NHKs, NHKr (previous ones)
```

The header `{ ratchet_pub, kem_ct, pn, n }` is encrypted with HKs. The content is encrypted with
the message key, with the encrypted header as associated data. Initialization: the initiator
sets `HKs = HKa, NHKr = NHKb`; the responder sets `NHKs = NHKb, NHKr = HKa`. At most 1000
skipped keys per chain and 2000 in total. Decryption is transactional: a failed message changes
nothing.

## Contents

Contents are padded to a multiple of 1024 bytes and are indistinguishable from one another.
New variants are always added at the end, because the wire format numbers variants in order.

| Content | Role |
|---|---|
| `Hello` | sent by the initiator right after the handshake |
| `Text` | plain message from older versions (still read, no longer sent) |
| `Cover` | dummy traffic, ignored on receipt |
| `Timer(s)` | disappearing messages, lifetime in seconds |
| `MailboxRequest`, `MailboxGrant{onion, auth}`, `MailboxInfo{onion, auth, deposit_id}`, `MailboxRevoke` | mailbox setup |
| `FileStart{id, name, size, chunks, SHA3}` | announces a file (at most 1 MiB) |
| `FileChunk{id, index, 960 bytes}` | one chunk, same block size as a short message |
| `GroupCreate{gid, fingerprints}` | the creator (relay) announces the group or its new member list |
| `GroupLeave{gid}` | a member leaves (or the group is dissolved, if sent by the relay) |
| `Rotate{new identity}` | new static key, authenticated by the existing session, used for later handshakes |
| `Op(MsgOp)` | operation on a message in a conversation between two people |
| `GroupMember{gid, identity}` | the relay passes on a member's identity key |
| `GroupKey{gid, author, to, box}` | `author`'s sender key, sealed for `to` |
| `GroupSealed{gid, author, key_id, n, ct, sig}` | end-to-end encrypted group message |
| `Device(DeviceMsg)` | exchanges between two devices of the same person |

A reassembled file is checked (size and SHA3-256) before it is accepted. `GroupText` and
`GroupOp` (groups readable by the relay) are neither sent nor accepted any more.

## Message operations

`MsgOp` = `Message{id, text, reply_to}` | `React{target, emoji}` (empty emoji removes it) |
`Edit{target, text}` | `Delete{target}`. Each message carries a random 16-byte identifier known
to both sides. Rules applied on receipt: one reaction per person per message; `Edit` and
`Delete` only apply to messages **by their author**; an identifier already seen is ignored (no
duplicates).

## End-to-end groups

The creator remains the relay (star topology) but only sees ciphertext.

1. **Members.** `GroupCreate` announces the fingerprints. `GroupMember` passes on each member's
   identity key, which is only accepted if its fingerprint is in the announced list.
2. **Sender key.** On first send, each member draws a chain key (32 bytes), an Ed25519 signing
   key and a `key_id`. They hand these to every other member in a **sealed box**:
   `e ← ephemeral X25519 + ML-KEM`, `k = HKDF(H, DH(e, S_to) || ss || DH(S_from, S_to))` with
   `H = SHA-512("LyctaCrypt/group-box/v1" || id_from || id_to || context)`, then
   XChaCha20-Poly1305. Only the recipient can open it, and it is bound to the sender, the
   recipient and the group. The relay forwards it without being able to open it.
3. **Message.** `mk = HMAC(chain, 0x01)`, `chain ← HMAC(chain, 0x02)`. The plaintext (a `MsgOp`)
   is padded to a multiple of 128 bytes and encrypted with `mk`, with associated data
   `"LyctaCrypt/group-msg/v1" || gid || author || key_id || n`. The whole is then signed
   (Ed25519). The recipient verifies the signature **before** advancing the chain. Up to 512
   skipped messages, 128 keys kept for late arrivals, no replay.
4. **Leaving.** The relay broadcasts the new list. Everyone throws away their sender key and
   makes a new one on their next send.

## Linked devices

A **companion** device is an ordinary contact (added with an invite) that the main device
accepts as its own. `DeviceMsg`:

| Message | Direction | Role |
|---|---|---|
| `Link` / `Accept` / `Unlink` | companion → main / back / either | set up or end the link |
| `Peer{fingerprint, note}` | main → companion | someone the owner talks to |
| `Sync{fingerprint, out, ttl, op}` | main → companion | copy of an operation |
| `Send{fingerprint, op}` | companion → main | "do this in my name" |

`Sync` and `Peer` are only accepted from the chosen main device, and `Send` only from an
accepted device. The main device carries out `Send` as if it had been typed there, then copies
it (`Sync`) to all its companions: that echo is what confirms the message was sent. The people
you talk to see none of this: one identity, and sessions with the main device only.

## Cover traffic

For each contact, a Poisson process (mean 120 s in low mode, 20 s in high mode): at each slot
the waiting messages leave, and if there are none an encrypted `Cover` is sent. The connection
is established **before** the ratchet advances.

## Mailbox

1. B asks contact H (`MailboxRequest`).
2. H accepts: a new dedicated onion service, `MailboxGrant{onion, auth}` to B.
3. B draws a random `fetch_key`, computes `deposit_id = SHA3("…/deposit", fetch_key)` and sends
   `MailboxInfo{onion, auth, deposit_id}` to all contacts (including H, which fixes
   `deposit_id` that way).
4. If B is unreachable, A sends `Deposit{deposit_id, already encrypted Msg frame}` to the
   mailbox.
5. B collects (`Fetch{fetch_key}` → `Batch`, at most 12 frames) on a Poisson process (mean
   90 s).

H only sees fixed-size encrypted frames and does not know the senders. Depositors cannot
collect: they only know `deposit_id`.

## Local vault (format v3)

```
"LYCTA\0v3" || n:u8 (≤ 6) || n × ( length:u32 || salt[16] || nonce[24] || XChaCha20-Poly1305(State) )
```

Each slot has its own salt and its own passphrase (Argon2id). A new vault holds its slot and one
or two slots of random filler (8 to 96 KiB). On unlock, the passphrase is tried on **all** slots
in parallel. A decoy vault is a slot **added** at a random position; no existing slot is ever
overwritten. A passphrase that already opens a slot is refused for a new one.

The state inside a slot is CBOR (first byte `0xCB`). Older vaults stored it with bincode: they
are still read, through a frozen copy of the old layout, and rewritten as CBOR on the next save.
Version 2 files (a single slot) are converted on the first write.

## Frames

`u32 length || u32 useful_length || bincode(Frame) || padding`, a multiple of 4096 bytes, at
most 64 KiB. Types: `GetBundle`, `Bundle`, `Hs1`, `Hs2`, `Msg{sid, msg}`, `Ack`, `Nack`,
`Deposit`, `Fetch`, `Batch`. Virtual port of the onion services: 7469.

## Signed updates

`update.json` (version, list of `{target, name, url, sha256, size}`) and `update.json.sig`, an
Ed25519 signature (hex) of `"LyctaCrypt/update/v1\n" || update.json`. The client verifies the
signature with the compiled-in public key, **then** reads the manifest, requires a strictly
newer version, downloads the program through Tor (on circuits isolated from the conversation
ones) and checks its size and SHA-256 before installing it.
