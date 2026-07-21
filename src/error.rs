//! Types d'erreur du cœur.

use thiserror::Error;

/// Résultat spécialisé du cœur.
pub type Result<T> = core::result::Result<T, Error>;

/// Erreurs du cœur Realm Guard.
///
/// Volontairement minimal ; enrichi par les lots crypto (P0.2) et CRDT (P0.3).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Opération cryptographique invalide (déchiffrement, wrapping…).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// État ou delta CRDT invalide.
    #[error("crdt error: {0}")]
    Crdt(String),

    /// (Dé)sérialisation.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Authentification OPAQUE (register/login, message invalide, mot de passe…).
    #[error("auth error: {0}")]
    Auth(String),
}
