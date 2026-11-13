# Preparing an audit and reproducing the binaries

LyctaCrypt **has not been audited**. This document tells a reviewer where to look, what the authors
have verified, and how to rebuild the binaries identically. It is not a substitute for an audit.

## Where the important parts are

| Topic | File | Tests |
|---|---|---|
| Hybrid X25519 + ML-KEM-768 keys | `crates/lycta-core/src/hybrid.rs` | unit |
| Two-message handshake | `crates/lycta-core/src/handshake.rs` | unit, `formal/handshake.pv` model |
| Double ratchet with encrypted headers | `crates/lycta-core/src/ratchet.rs` | unit |
| Groups: sealed boxes, sender keys | `crates/lycta-core/src/group.rs` | unit |
| Wire format, padding, decoders | `crates/lycta-core/src/wire.rs` | unit, fuzzing (`fuzz/`) |
| Vault, decoy vault, migrations | `crates/lycta-core/src/vault.rs`, `legacy.rs` | unit |
| Peer-to-peer logic, authorization rules | `crates/lycta-node/src/node.rs` | Tor test `examples/e2e.rs` |
| Signed updates | `crates/lycta-node/src/update.rs` | unit |
| Bridges | `crates/lycta-node/src/bridges.rs` | unit |

`lycta-core` forbids `unsafe` code and has no network dependencies: everything in it can be tested offline.

## Questions to ask first

1. **Handshake.** Authentication of the initiator relies on a static (classical) DH. Can an active
   quantum adversary impersonate the initiator before the second message?
2. **Ratchet.** Handling of skipped messages, bounds, key erasure.
3. **Groups.** Binding of the sealed box (sender, recipient, group); advancing the chain only after
   the signature has been verified; rekeying when a member leaves; trust placed in the member list
   supplied by the relay.
4. **Authorization in `node.rs`.** Is every received content rejected when it comes from the wrong
   peer? In particular `Device(Send)` (only from an accepted device), `Device(Sync)` (only from the
   primary device), `GroupKey`/`GroupSealed` (author = actual sender on the relay side),
   `Edit`/`Delete` (only the author).
5. **Vault.** Indistinguishability of the filler slots; leakage through file size; old copies of the
   file.
6. **Side channels.** Frame sizes and timing as seen by the network, by the host of a mailbox, by the
   relay of a group.
7. **Media decoders** (`image`, WAV) fed with received data.
8. **Updates.** Replay of an old manifest, substitution of the binary, replacement of the running
   program.

## What the authors have verified

- Unit tests: `cargo test --workspace`.
- `cargo clippy --workspace --all-targets -- -D warnings`.
- End-to-end test on the real Tor network: `cargo run -p lycta-node --example e2e -- <directory>`.
- Update transport and obfs4 bridges, tried by hand:
  `cargo run -p lycta-node --example fetch -- <directory> [url] [obfs4|snowflake]`.

What has **not** been done is listed in `SECURITY.md` ("Vérifications effectuées" and "Limites
connues").

## Reproducing a binary

Releases are built by `.github/workflows/release.yml`: pinned toolchain
(`rust-toolchain.toml`), pinned dependencies (`Cargo.lock`, `--locked`), normalized paths, date
fixed to the commit. The Linux binary is built twice there and the hashes must match.

To do it yourself, on Linux:

```bash
git checkout <tag>
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo -C link-arg=-Wl,--build-id=none -C strip=symbols" \
  cargo build --release --locked -p lycta-node -p lycta-gui
sha256sum target/release/lyctacrypt target/release/lyctacrypt-gui
```

Compare with the release's `SHA256SUMS`. `scripts/verify-release.sh` checks the minisign
signature, the hashes and the provenance attestation.

## Publishing an update (maintainers)

1. Once and for all: `lyctacrypt update-keygen`. Keep the secret key **offline**; paste the
   public key into `UPDATE_PUBLIC_KEY` (`crates/lycta-node/src/update.rs`) and fill in
   `UPDATE_MANIFEST_URL`.
2. For each version: write `update.json` with, for each binary, its target
   (`windows-x86_64`, `linux-x86_64`, `macos-aarch64`…), its name (`lyctacrypt` or `lyctacrypt-gui`),
   its HTTPS address, its SHA-256 and its size.
3. `lyctacrypt update-sign update.json <secret-key-file>` produces `update.json.sig`.
4. Attach both files to the release.
