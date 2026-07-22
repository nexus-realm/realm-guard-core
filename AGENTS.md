# AGENTS.md — realm-guard-core

> Agent-oriented context. Dense, factual, scannable. Keep in sync with the code.
> Docstrings/user text are French; this doc is English for AI efficiency.

## 1. What this is

- The **shared Rust core** of Realm Guard: end-to-end-encryption primitives (key
  hierarchy, OPAQUE auth, device pairing, recovery) **and** a custom **delta-state
  CRDT** for local-first multi-device sync.
- **Consumers:** `realm-guard-server` (Cargo `path`/git dep) and
  `realm-guard-mobile` (FFI via `flutter_rust_bridge`). This crate has **no
  platform dependency** — pure, deterministic logic.
- **Hard invariants:** `#![forbid(unsafe_code)]`; **no home-made crypto** (only
  audited crates); physical time is **injected** (never read internally) so the
  CRDT is deterministic and testable; edition **2024**, MSRV **1.85**.

## 2. Modules (`src/`)

| Module | Responsibility |
|---|---|
| `crypto` | Argon2id (64 MiB, t=3) → **KEK**; random root **VaultKey** wrapped by the KEK; AEAD **XChaCha20-Poly1305** with a per-entry sub-key via **HKDF**; **Ed25519** device keys; **X25519** pairing (sealed-box + 6-digit SAS, two-round handshake); **BIP39** 24-word recovery kit; sealed server-backup blob. `Ciphertext` carries an authenticated AEAD version byte (crypto agility). Secrets zeroized. |
| `auth` | **OPAQUE** (aPAKE, Ristretto255 + Argon2id KSF): register/login byte APIs, mutual `session_key`, stable client `export_key`. |
| `crdt` | `LwwRegister` (join on `(Hlc, value)`, value tiebreak → total/deterministic), `AddWinsSet` (OR-Set, dots/DotContext), **HLC** `{wall_ms, counter}` + `DeviceId` tiebreak, `VaultDoc<V>` = presence ⊗ `{EntryId→{FieldId→LwwRegister}}`. Delta-interval model (ships deltas, not recomputed VVs). **Property-tested** (commutativity/associativity/idempotence/convergence). |
| `model` | Vault entities (credentials, profiles, TOTP) mapped onto the CRDT field ids. |
| `codec` | `postcard` (de)serialization of deltas/docs. |
| `error` | `Error` / `Result`. |

`core_version()` (`lib.rs`) — trivial entry point validating the FFI/server dep.

## 3. Key model (durable)

- **Two independent secrets:** the *master/local password* → Argon2id → **KEK**
  which wraps a random **VaultKey** (the VaultKey is the client's data key). The
  *account password* → **OPAQUE** (auth only; never derives the VaultKey).
- **Recovery of the VaultKey:** device pairing (default; the server never holds
  the plaintext VaultKey), a BIP39 24-word offline kit, or a server backup
  (`seal(export_key, wrap_KEK(VaultKey))`) that requires **both** the account and
  the master password.
- **CRDT ⇄ drift wire format** is owned by the mobile repo
  (`docs/SYNC_MAPPING.md`) — this crate produces/merges the deltas; changing field
  ids or the tagged value codec is a **cross-repo break**.

## 4. Consumers & propagation

- **Server:** Cargo dependency (`realm-guard-core = { path = "../realm-guard-core" }`).
- **Mobile:** FFI. After changing any exported signature, the mobile side must
  `flutter_rust_bridge_codegen generate`; after merging a new symbol, mobile does
  `cargo update -p realm-guard-core` (git pin) — otherwise the APK build breaks.
- **Version compatibility** is tracked via `CORE_VERSION`.

## 5. Dev workflow & gate

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test                                   # incl. proptest
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo deny check
```
All five must be green (the "Rust gate"). `.gitattributes` pins `*.sql`/sensitive
files to LF (stable checksums across OSes).

**Coverage** — `cargo-llvm-cov`, aliased in `.cargo/config.toml`:

```bash
rustup component add llvm-tools-preview && cargo install cargo-llvm-cov  # once
cargo cov        # per-file summary (watch the "Lines" column)
cargo cov-html   # target/llvm-cov/html/index.html
cargo cov-lcov   # lcov.info for an external consumer
```

**Nothing is excluded from the report** — the crate is pure Rust with no platform
layer and no generated code, so every line is reachable from `cargo test`. Any
future exclusion must be justified in `.cargo/config.toml` itself. Baseline:
**94.6 % of lines**, 103 tests. CI publishes the summary on every PR via a
`coverage` job that is **non-blocking** (`continue-on-error`, no threshold).

## 6. Release (GitFlow + git-cliff)

`publish = false` (not on crates.io) — **consumers pin a git tag**. CD mirrors the
mobile: push **`staging`** cuts the version (git-cliff conventional bump +
Cargo/Cargo.lock/CHANGELOG + tag, pre-release); **`staging→main`** (or dispatch)
promotes it. A `feat!` bumps `0.x → 1.0.0`. Don't hand-edit `version` where
git-cliff computes it.

## 7. When you change X

- **Exported (FFI-facing) signature** → expect a mobile codegen + pin bump (§4).
- **CRDT field ids / value codec / merge semantics** → coordinate with
  `realm-guard-mobile` `docs/SYNC_MAPPING.md` (cross-repo wire format).
- **Anything crypto** → audited primitives only, keep `#![forbid(unsafe_code)]`,
  keep the property tests green, run a security review before merging.
