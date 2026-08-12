# Mise à jour des dépendances — realm-guard-core

## Automatique — Dependabot (`.github/dependabot.yml`)

- **Alertes de sécurité** (CVE) : activer une fois dans *Settings → Code security →
  Dependabot alerts* **+** *Dependabot security updates*.
- **PR de version** — **mensuelles**, **groupées** minor+patch par écosystème
  (majors en PR séparées) pour `cargo`, `npm`, `github-actions`. Cible `develop`
  depuis des branches `dependabot/*` (autorisées par `check-branches`).
- **Aucun secret Dependabot requis** : la CI n'utilise que `GITHUB_TOKEN`.
- Le supply-chain reste gardé par **`cargo-deny`** (job `deny` du CI) : une PR qui
  introduit une advisory / licence interdite est bloquée.

## Manuel — procédure d'appoint

Utile pour piloter une mise à jour hors cadence, ou avancer un major que Dependabot
a isolé. `cargo update` respecte les `^` (semver) ; `cargo upgrade` (cargo-edit)
**bumpe** les bornes dans `Cargo.toml`.

```bash
cargo update                       # lock : versions semver-compatibles les + récentes
cargo update --dry-run             # aperçu sans modifier
cargo install cargo-edit           # une fois, pour `cargo upgrade`
cargo upgrade --incompatible       # bumpe les bornes `^` de Cargo.toml (majors compris)
npm outdated                       # husky / commitlint
```

**`Cargo.lock` est versionné** (builds reproductibles) → toujours committer le lock
avec la mise à jour.

## Avant de merger (toute PR de deps)

Le **gate Rust** doit être vert :

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo deny check
```

Mise à jour **manuelle** → branche `chore/rg-<N>`. Cadence : revue mensuelle des PR
Dependabot ; majors appliqués séparément après lecture des changelogs.
