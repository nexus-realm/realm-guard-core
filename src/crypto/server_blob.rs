//! Enrobage de la VaultKey (déjà enrobée par la KEK) sous la **clé exportée
//! OPAQUE**, pour stockage côté serveur (multi-appareils).
//!
//! Défense en profondeur : le serveur ne stocke que ce blob. Sans compléter le
//! protocole OPAQUE (pour obtenir l'`export_key`, dérivé du mot de passe), le blob
//! est **inutilisable** — une fuite de la base ne permet même pas de *commencer*
//! une attaque par dictionnaire sur la KEK. L'`export_key` ne quitte jamais le
//! client.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};

use super::KEY_LEN;
use super::aead::{Ciphertext, open, seal};

// Séparation de domaine pour la clé dérivée de l'export_key.
const SERVER_BLOB_INFO: &[u8] = b"realm-guard-core/v1/server-blob-key";

/// Dérive la clé AEAD du blob serveur depuis l'`export_key` (HKDF-SHA256).
fn blob_key(export_key: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, export_key);
    let mut key = [0u8; KEY_LEN];
    hk.expand(SERVER_BLOB_INFO, &mut key)
        .map_err(|_| Error::Crypto("dérivation HKDF (blob serveur) échouée".into()))?;
    Ok(key)
}

/// Enrobe un blob (typiquement la VaultKey déjà enrobée par la KEK) sous une clé
/// dérivée de l'`export_key`, pour stockage serveur.
///
/// # Errors
/// Échec HKDF, CSPRNG ou chiffrement.
pub fn seal_with_export_key(export_key: &[u8], plaintext: &[u8]) -> Result<Ciphertext> {
    let mut key = blob_key(export_key)?;
    let result = seal(&key, plaintext);
    key.zeroize();
    result
}

/// Désenrobe un blob serveur avec la clé dérivée de l'`export_key`.
///
/// # Errors
/// Mauvais `export_key`, ou blob altéré.
pub fn open_with_export_key(export_key: &[u8], sealed: &Ciphertext) -> Result<Vec<u8>> {
    let mut key = blob_key(export_key)?;
    let result = open(&key, sealed);
    key.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let export_key = [7u8; 64];
        let secret = b"vault key deja enrobee par la KEK";
        let sealed = seal_with_export_key(&export_key, secret).unwrap();
        assert_eq!(open_with_export_key(&export_key, &sealed).unwrap(), secret);
    }

    #[test]
    fn wrong_export_key_rejected() {
        let sealed = seal_with_export_key(&[7u8; 64], b"secret").unwrap();
        assert!(open_with_export_key(&[8u8; 64], &sealed).is_err());
    }

    #[test]
    fn tampered_blob_rejected() {
        let export_key = [7u8; 64];
        let mut sealed = seal_with_export_key(&export_key, b"secret").unwrap();
        sealed.ciphertext[0] ^= 0xFF;
        assert!(open_with_export_key(&export_key, &sealed).is_err());
    }
}
