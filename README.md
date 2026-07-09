# realm-guard-core

Cœur partagé de **Realm Guard v2** : cryptographie E2EE (hiérarchie de clés) et
**CRDT delta-state custom** pour la synchronisation multi-appareil *local-first*.

Consommé par :
- `realm-guard-server` (Axum) — via dépendance Cargo ;
- `realm-guard-mobile` (Flutter) — via FFI `flutter_rust_bridge`.

Aucune dépendance plateforme : logique pure, testable de façon déterministe.

## Modules
- `crypto` — Argon2id → KEK, root vault key, wrap/unwrap, AEAD par entrée, kit de récupération *(P0.2)*.
- `crdt` — LWW-Register + add-wins set, HLC, deltas + version vectors *(P0.3)*.
- `model` — entités du coffre (credentials, profils, TOTP) mappées sur le CRDT *(P0.3)*.
- `error` — types d'erreur.

## Développement
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo deny check   # chaîne d'approvisionnement (nécessite cargo-deny)
```

Statut : **P0.1 — scaffold**.
