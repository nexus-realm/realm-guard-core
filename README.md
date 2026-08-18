# realm-guard-core

Cœur partagé de **Realm Guard** : cryptographie E2EE (hiérarchie de clés,
authentification OPAQUE, appairage) et **CRDT delta-state custom** pour la
synchronisation multi-appareils *local-first*.

Consommé par :
- [`realm-guard-server`](https://github.com/nexus-realm/realm-guard-server) (Axum) — via dépendance Cargo (`path`/git) ;
- [`realm-guard-mobile`](https://github.com/nexus-realm/realm-guard-mobile) (Flutter) — via FFI `flutter_rust_bridge`.

**Logique pure, sans dépendance plateforme** : `#![forbid(unsafe_code)]`, temps
physique injecté (déterministe), CRDT *property-tested*. **Aucune cryptographie
maison** — uniquement des primitives auditées.

## Modules

- `crypto` — Argon2id → KEK, root **VaultKey** aléatoire, wrap/unwrap, AEAD
  XChaCha20-Poly1305 (sous-clé par entrée via HKDF), device keys Ed25519,
  appairage X25519 (sealed-box + SAS), kit de récupération BIP39, blob de backup.
- `auth` — protocole **OPAQUE** (aPAKE zero-knowledge) : register / login,
  `session_key` mutuelle, `export_key` client stable.
- `crdt` — `LwwRegister` + `AddWinsSet` (OR-Set), **HLC** (temps physique injecté)
  + tiebreak `DeviceId`, `VaultDoc` (présence ⊗ registres de champs), deltas.
- `model` — entités du coffre (credentials, profils, TOTP) mappées sur le CRDT.
- `codec` — sérialisation `postcard` des deltas / documents.
- `error` — types d'erreur (`Error` / `Result`).

`core_version()` : point d'entrée trivial de validation FFI / dépendance serveur.

## Développement

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo deny check    # chaîne d'approvisionnement (nécessite cargo-deny)
```

- Édition Rust **2024**, MSRV **1.85**.
- `.gitattributes` force `*.sql`/fichiers sensibles en LF (checksums stables).

### Couverture de tests

```bash
rustup component add llvm-tools-preview && cargo install cargo-llvm-cov  # une fois
cargo cov        # résumé par fichier (colonne « Lines »)
cargo cov-html   # rapport navigable : target/llvm-cov/html/index.html
cargo cov-lcov   # export lcov.info
```

Niveau actuel : **94,6 % de lignes** sur 103 tests, **sans aucune exclusion** — le
cœur est du Rust pur, tout y est atteignable depuis `cargo test`. Comme partout
avec `cargo-llvm-cov`, ce chiffre inclut les modules `#[cfg(test)]` ; sur le seul
code de production, la couverture est de **94,2 %**. La CI publie le
résumé à chaque PR sans jamais bloquer (job `coverage`, aucun seuil).

## Release

Bibliothèque **non publiée sur crates.io** (`publish = false`) : les consommateurs
**épinglent un tag git**. CD `release.yml` calquée sur le mobile
(*conventional-commits* → **git-cliff** : bump `Cargo.toml`/`Cargo.lock` +
CHANGELOG + tag) :

- **push `staging`** → coupe une version (pré-release GitHub) ;
- **`staging → main`** (ou dispatch) → promeut la pré-release en release.

Un changement `feat!` fait passer `0.x → 1.0.0`.
