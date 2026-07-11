//! Sérialisation binaire compacte (**postcard**) — format d'échange du cœur,
//! partagé serveur ↔ mobile. Non auto-descriptif : les deux bouts utilisent ce
//! module pour garantir un encodage identique (stockage local et deltas de synchro).

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

/// Encode une valeur en octets compacts (postcard).
///
/// # Errors
/// Échec de sérialisation.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    postcard::to_allocvec(value).map_err(|e| Error::Serialization(e.to_string()))
}

/// Décode une valeur depuis des octets postcard.
///
/// # Errors
/// Octets invalides ou incompatibles avec le type attendu.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    postcard::from_bytes(bytes).map_err(|e| Error::Serialization(e.to_string()))
}
