# Post-quantum authentication review

## Finding

The current handshake mixes X25519 and ML-KEM-768. The KEM contributes post-quantum confidentiality to the key schedule, but it does not prove who owns the advertised identity key: anyone can encapsulate to a public KEM key. In `handshake.rs`, the initiator's identity is carried inside an encrypted payload, and the responder authenticates it using a static X25519 DH value (`dh2`). That identity-authentication step therefore remains classical. A sufficiently capable quantum adversary could break the X25519-based authentication assumption. This assessment is limited to source inspection; no formal proof or independent audit has been performed.

## Integrity and signature coverage

- Direct and mailbox messages use the ratchet's authenticated encryption. A separate signature would not create a stronger identity binding because the current long-term identity has no signing key.
- Group payloads use Ed25519 signatures, checked before advancing the sender chain. The group verification key is delivered through the group key flow; the hub-supplied roster is not backed by an all-member signed approval.
- Update manifests use Ed25519 signatures over the exact manifest bytes; each downloaded binary is checked against the signed size and SHA-256 digest. The update feature remains disabled in builds where no release public key is configured.
- Vault ciphertext is authenticated with AEAD, with a TPM-bound outer envelope where available. A detached signature is unnecessary for confidentiality or integrity of the vault file.
- Frame padding is required to be zero, preventing arbitrary hidden bytes in otherwise ignored padding.

## Recommended design

1. Preserve the existing human-checked safety code as an out-of-band identity pin; the application now stores the fingerprint after an explicit successful scan and blocks outbound sends if a pinned contact's key changes.
2. For protocol-level post-quantum authentication, add a versioned identity format with a FIPS 204 ML-DSA-65 signing key. Sign a domain-separated transcript binding protocol version, both identities, ephemeral X25519 values, KEM public keys/ciphertexts, and handshake roles. Verify before accepting identity or ratchet state.
3. Bind group roster changes and key rotations to the same signed identity. Require a policy for trust-on-first-use, key rotation, recovery, and old-client interop.
4. Keep the existing protocol version for interop; negotiate the new version explicitly and fail closed when a peer claims PQ authentication but the signature fails. Do not silently downgrade.
5. Benchmark larger signatures and identity payloads, and review key storage, backup, and migration before enabling it by default.

ML-DSA is standardized by NIST in FIPS 204. A PQ signature on an unpinned first-contact key still cannot prove that the key belongs to the person you intended to contact; the safety-code comparison or a trusted key directory remains important.

## Network and file metadata

Cover traffic now offers a five-second mean interval option. It reduces the visibility of idle periods but does not hide endpoints, packet sizes, or timing correlation from a global observer; it also increases bandwidth. JPEG application/comment segments, PNG ancillary chunks, WAV non-audio chunks, and WebP chunks outside the supported image/animation set are removed before sending. Unknown formats are refused. Update requests no longer send an application-specific User-Agent.

Update manifests bind their issue and expiry times under the release signature. Verification rejects timestamps more than five minutes in the future, expired manifests, and validity periods longer than 90 days. This limits replay of stale signed manifests but depends on a reasonably correct local clock.

## Group changes

The existing group protocol lets the hub distribute a roster; it does not implement an all-member cryptographic approval quorum for membership changes. A secure quorum requires signed, versioned roster proposals and protocol migration. Treat a group roster supplied by an untrusted relay as unverified until that design exists.
