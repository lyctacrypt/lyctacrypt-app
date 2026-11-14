# Preparing an audit and reproducing the programs

LyctaCrypt **has not been audited**. This document tells a reviewer where to look, what the
authors have checked, and how to rebuild the published programs identically. It does not
replace an audit.

The source code carries no comments. The design is described here, in
[PROTOCOL.md](../PROTOCOL.md) and in [SECURITY.md](../SECURITY.md).

## Where the important code is

| Topic | File | Tests |
|---|---|---|
| Hybrid keys X25519 + ML-KEM-768 | `crates/lycta-core/src/hybrid.rs` | unit |
| Two-message handshake | `crates/lycta-core/src/handshake.rs` | unit, model `formal/handshake.pv` |
| Double ratchet with encrypted headers | `crates/lycta-core/src/ratchet.rs` | unit |
| Groups: sealed boxes, sender keys | `crates/lycta-core/src/group.rs` | unit |
| Wire format, padding, decoders | `crates/lycta-core/src/wire.rs` | unit, fuzzing (`fuzz/`) |
| Vault, decoy vault, migrations | `crates/lycta-core/src/vault.rs`, `legacy.rs` | unit |
| Peer-to-peer logic, authorization rules | `crates/lycta-node/src/node.rs` | Tor test `examples/e2e.rs` |
| Signed updates | `crates/lycta-node/src/update.rs` | unit |
| Bridges | `crates/lycta-node/src/bridges.rs` | unit |

`lycta-core` forbids `unsafe` code and has no network dependency: everything in it can be
tested offline.

Two things a reviewer should know before changing anything:

- `legacy.rs` is a frozen copy of the old vault layout, used only to read old vaults. Its
  definitions must never change.
- New variants of `Content` (in `wire.rs`) must be added at the end: the wire format numbers
  variants in order.

## Questions to ask first

1. **Handshake.** The initiator is authenticated by a static Diffie-Hellman exchange
   (classical). Can an active quantum adversary impersonate it before the second message?
2. **Ratchet.** Handling of skipped messages, bounds, erasure of keys.
3. **Groups.** Binding of the sealed box (sender, recipient, group). The chain only advances
   after the signature is verified. Renewal when a member leaves. Trust placed in the member
   list supplied by the relay.
4. **Authorization in `node.rs`.** Is every received content refused when it comes from the
   wrong peer? In particular `Device(Send)` (only from an accepted device), `Device(Sync)` (only
   from the main device), `GroupKey` and `GroupSealed` (author must be the real sender, as seen
   by the relay), `Edit` and `Delete` (only the author).
5. **Vault.** Indistinguishability of filler slots, leaks through file size, older copies of the
   file.
6. **Side channels.** Sizes and timing of frames as seen by the network, by a mailbox host and
   by a group relay.
7. **Media decoders** (`image`, WAV) fed with received data.
8. **Updates.** Replay of an old manifest, substitution of the program, replacing the running
   program.

## What the authors checked

- Unit tests: `cargo test --workspace`.
- `cargo clippy --workspace --all-targets -- -D warnings`.
- End-to-end test on the real Tor network: `cargo run -p lycta-node --example e2e -- <folder>`.
- Update transport and obfs4 bridges, by hand:
  `cargo run -p lycta-node --example fetch -- <folder> [url] [obfs4|snowflake]`.

What has **not** been done is listed in `SECURITY.md`.

## Rebuilding a program

Releases are built by `.github/workflows/release.yml`: pinned toolchain
(`rust-toolchain.toml`), pinned dependencies (`Cargo.lock`, `--locked`), normalized paths, date
fixed to the commit. The Linux program is built twice there and both hashes must match.

To do it yourself on Linux:

```bash
git checkout <tag>
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME/.cargo=/cargo -C link-arg=-Wl,--build-id=none -C strip=symbols" \
  cargo build --release --locked -p lycta-node -p lycta-gui
sha256sum target/release/lyctacrypt target/release/lyctacrypt-gui
```

Compare with the release's `SHA256SUMS`. `scripts/verify-release.sh <release folder>` checks
the minisign signature of `SHA256SUMS`, the hash of each program present and, if `gh` is
installed, the Sigstore provenance attestation.

## Publishing an update (maintainers)

1. This checkout contains a generated release public key as its default. To rotate it, run
   `lyctacrypt update-keygen`, keep the secret key offline, and set the printed public key in
   the build environment variable `LYCTA_UPDATE_PUBLIC_KEY`. In PowerShell, set
   `$env:LYCTA_UPDATE_PUBLIC_KEY = '<public-key-hex>'` before running
   `cargo build --release -p lycta-node -p lycta-gui`. Set `UPDATE_MANIFEST_URL` in
   `crates/lycta-node/src/update.rs` if the release host differs from the default.
2. For each version: write `update.json` with `version`, Unix-second `issued_at` and
   `expires_at` timestamps (no more than 90 days apart), and for each program its target
   (`windows-x86_64`, `linux-x86_64`, `macos-aarch64`…), its name (`lyctacrypt` or
   `lyctacrypt-gui`), its HTTPS address, its SHA-256 and its size.
3. `lyctacrypt update-sign update.json <secret key file>` produces `update.json.sig`. On
   Windows, the signer can instead read `LYCTA_UPDATE_SECRET_KEY` from the current process
   environment. The command verifies that the signing key matches the public key embedded in
   that build before it writes the signature.
4. Attach both files to the release.
