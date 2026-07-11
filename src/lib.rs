//! `realm-guard-core` — cœur partagé (crypto E2EE + CRDT delta-state) de Realm Guard.
//!
//! Consommé par le serveur (`realm-guard-server`) et le client mobile (via FFI
//! `flutter_rust_bridge`). Aucune dépendance plateforme : logique pure et
//! testable de façon déterministe.

#![forbid(unsafe_code)]

pub mod auth;
pub mod codec;
pub mod crdt;
pub mod crypto;
pub mod error;
pub mod model;

pub use error::{Error, Result};

/// Version du cœur (suivi de compatibilité client ↔ serveur).
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Renvoie la version du cœur. Point d'entrée trivial servant à valider
/// l'intégration FFI (P0.5) et la dépendance serveur (P0.4).
#[must_use]
pub fn core_version() -> &'static str {
    CORE_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_core_version() {
        assert_eq!(core_version(), env!("CARGO_PKG_VERSION"));
        assert!(!core_version().is_empty());
    }
}
