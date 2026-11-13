# Security and threat model

## What LyctaCrypt protects

- **Content.** End-to-end encrypted with a hybrid of classical and post-quantum cryptography,
  with forward secrecy and recovery after a compromise.
- **Who talks to whom.** There is no central server. Traffic goes from one onion service to
  another.
- **Links between contacts.** Each contact gets a different onion address, so two of your
  contacts cannot tell they are talking to the same person by comparing addresses.
- **Presence.** Addresses use restricted discovery. Without the access key an address cannot be
  reached, not even to check whether you are online.
- **Use of Tor.** It can be hidden with bridges and pluggable transports.
- **Timing and volume.** Fixed-size padding, encrypted headers and cover traffic.
- **Data at rest.** One encrypted vault holds everything, onion keys included. The Tor keystore
  stays in memory.
- **"Harvest now, decrypt later".** ML-KEM-768 protects recorded exchanges.

## What has been checked

- Unit tests: cryptographic core (handshake, ratchet, invites, vault and migrations, decoders,
  message operations, end-to-end groups), signed updates, bridges, QR decoding, WAV encoding.
  Light fuzzing is built into the tests.
- End-to-end test on the real Tor network (`examples/e2e.rs`), passing: restricted discovery (a
  client without the key fails), single-use invite, messages both ways, intact file transfer,
  identity rotation, three-member encrypted group through the relay, linked device (copy of an
  incoming message, reply sent from the second device).
- Manual runs: HTTPS download through Tor with redirects (the update transport), connection
  through a Tor Browser obfs4 bridge, reading the bridge list of a real Tor Browser.
- `cargo fmt`, `cargo clippy -D warnings` and the tests pass.
- **Not tried with real hardware:** microphone recording, audio playback and webcam scanning
  (QR decoding and WAV encoding are tested, the devices are not), Snowflake bridges, actually
  installing an update (no signed release exists yet), clicking the tray menu.
- **Not run yet** (CI will run them on the first push): long fuzzing (`fuzz/`), ProVerif
  (`formal/`), cargo-deny, Linux build and sandbox, macOS build, bit-for-bit reproducibility.

## Known limits

1. **Not audited.** This is a prototype. The code and the protocol need review by
   cryptographers.
2. **The Tor layer is classical.** Tor circuits and onion keys (ed25519) are not post-quantum.
   Only LyctaCrypt's own end-to-end encryption is.
3. **Timing correlation.** An adversary watching both ends can try to correlate traffic. Cover
   traffic reduces this risk without removing it, and it costs bandwidth. Your contacts can see
   when you are reachable.
4. **Latency.** With cover traffic on, a message waits for the next slot (two minutes on average
   in low mode). `/cover off` sends immediately, at the cost of timing privacy.
5. **Mailbox.** The host sees the volume and timing of deposits and pickups, and can refuse or
   lose them. It sees neither content nor sender.
6. **Number of services.** One address per contact means many onion services. Reasonable for a
   few dozen contacts.
7. **Non-secret Tor state on disk.** The `tor-state/` folder (guards, consensus) stays on disk.
   Onion service state and the keystore are wiped at startup. The cache reveals that Tor is
   used: encrypt your disk.
8. **Memory.** `mlockall` only works on Linux and Unix, and only if `ulimit -l` is unlimited. On
   Windows, secrets can reach the page file: disable it or use BitLocker.
9. **Terminal.** Your terminal's scrollback can keep displayed messages.
10. **Invites.** An invite contains an access key. Pass it over a safe channel and check the
    `/verify` code out loud.
11. **Groups.** Group messages are end-to-end encrypted: the creator relays them without being
    able to read or forge them. What remains true:
    - the relay sees **who** writes, **when**, and the rounded size of messages, and it can
      delay or drop them;
    - the **member list comes from the relay**. A dishonest relay could slip in a key of its
      own: compare member fingerprints over another channel if you do not trust the relay;
    - sender keys are delivered in a sealed box that has no forward secrecy of its own. If a
      member's identity key is compromised later, the sender keys that member received are
      exposed;
    - author signatures are classical (Ed25519), not post-quantum;
    - when a member leaves, everyone renews their key. That member cannot read what follows but
      keeps what they already received;
    - after rotating your identity key, create the group again.
12. **Exported files.** `/export` writes the file **in clear** to disk. This is intended, but
    the file is then outside the vault's protection.
13. **Backups.** A backup contains all your keys: protect it like the vault. Once restored, it
    drops the sessions (new ones are opened). Never use two copies at the same time.
14. **Rotation.** Contacts that are unreachable during a rotation and have no session are not
    told. They will have to add you again.
15. **Sandbox.** Landlock on Linux only. Nothing equivalent on Windows and macOS yet.
16. **No mobile version** for now.
17. **Decoy vault: plausible deniability, not invisibility.**
    - The software is open source, so everyone knows the format *allows* extra vaults. What
      cannot be shown is that a given slot is one rather than filler.
    - A decoy that is never used stays frozen (same contacts, no recent messages). Open it now
      and then and keep it alive so that it stays believable.
    - The fake sessions lead to addresses that never answer: the decoy's contacts simply look
      offline.
    - Tor state (cache, guards) is shared by both vaults. It holds no keys and no contacts.
    - Someone who has an **older copy** of the file (automatic system backup, disk snapshot) can
      see that a slot was added in the meantime. Create the decoy early, before copies pile up,
      and be careful with automatic backups of the folder.
    - The decoy protects neither against spyware on the device nor against what the people you
      talk to keep on their side.
18. **Editing and deleting.** "Delete for everyone" and "edit" are **requests**. An honest app
    applies them, but nothing stops the recipient from having already read, copied or
    photographed the message.
19. **Several devices.** A linked device receives a copy of your conversations (text messages)
    and can write in your name through the main device. Consequences:
    - if it is compromised, so are your conversations. Only link a device you own, after
      checking its safety code;
    - it only works while the main device is online;
    - files, pictures, voice notes and groups are not copied for now;
    - the people you talk to see a single identity. They do not know how many devices you have.
20. **Updates.** The client checks an Ed25519 signature (compiled-in public key), then the
    SHA-256 of the program, and refuses any version that is not strictly newer. Until the key is
    set, the feature is off. The signing key becomes a central point of trust: whoever steals it
    can push a fake program. Keep it offline. The signature is classical (Ed25519).
21. **Bridges.** LyctaCrypt downloads no programs. It reuses the transports and bridge list of
    **your** Tor Browser, so their integrity is that of your installation. Built-in bridges are
    public: they get past simple blocking, not a censor who knows them.
22. **Pictures, sound, camera, microphone.** Received pictures and sounds are decoded by Rust
    libraries, with size limits and no unsafe code on our side. A flaw in these decoders is
    still possible. The microphone is only open while recording and the camera only while
    scanning. Nothing is written to disk outside the vault.
23. **Hiding from screenshots.** Works on Windows (the window shows as black). It does not
    protect against a photo of the screen or against spyware with elevated privileges.

## Reporting a vulnerability

Please do not publish details in a public issue. Contact the maintainers privately (address to
be set when the repository is published) with a description and, if possible, a proof of
concept.
