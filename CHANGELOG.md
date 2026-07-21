# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
## [1.0.0] - 2026-07-21

### Divers
- Scaffold realm-guard-core
- Add husky + commitlint for conventional commits
- **deps** : Ignore unmaintained atomic-polyfill advisory in cargo-deny

### Documentation
- **pairing** : Use plain backticks for the device_public_key parameter
- **core** : Refresh README + add AGENTS.md

### Fonctionnalités
- **crypto** : Key hierarchy — Argon2id KEK + vault key wrap/unwrap
- **crypto** : Per-entry AEAD + shared AEAD envelope
- **crypto** : Add BIP39 recovery kit for solo vault-key recovery
- **crypto** : Add BIP39 recovery kit for solo vault-key recovery
- **crdt** : Add hybrid logical clock and timestamp ordering
- **crdt** : Add last-writer-wins register
- **crdt** : Add add-wins OR-set with compact causal context
- **model** : Add replicated vault document
- **core** : Binary serialization (postcard) + versioned AEAD envelope
- **auth** : Add OPAQUE registration and login (opaque-ke)
- **auth** : Make server_login_start accept an optional password file
- **crypto** : Wrap the vault key under the OPAQUE export key
- **auth** : Harden OPAQUE KSF to Argon2id 64 MiB/t3
- **crypto** : Byte-oriented VaultKey wrap/unwrap for the FFI bridge
- **crypto** : Device pairing protocol (X25519 + sealed VaultKey + SAS)
- **pairing** : Carry device key and account id through pairing
- **device-key** : Ed25519 device identity primitives
- **pairing** : Return the transcript-bound device key from pairing_seal
- **pairing** : Make the SAS preventive with a two-round handshake
- **model** : Return deltas from vault mutations
- **model** : Enumerate an entry's fields for projection
- **crypto,crdt** : Byte-oriented wrappers for the sync FFI
- **sync** : Expose the vault doc's max HLC

### Intégration continue
- Enforce GitFlow branch naming + quality gates
- Add release pipeline
- **release** : Start the published version line at 1.0.0
