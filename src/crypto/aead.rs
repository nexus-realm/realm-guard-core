//! Enveloppe AEAD partagée (XChaCha20-Poly1305) : version + nonce aléatoire +
//! ciphertext. Mutualisée par l'enrobage de clé ([`super::vault_key`]) et le
//! chiffrement par entrée ([`super::entry`]).
//!
//! L'octet de **version** identifie l'algorithme AEAD ; il est **authentifié**
//! (passé en données associées), donc toute altération le concernant fait échouer
//! le déchiffrement — pas de downgrade silencieux. Il ménage aussi l'agilité crypto
//! (rotation d'algorithme sans ambiguïté sur les données déjà stockées / synchro).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{KEY_LEN, XNONCE_LEN};

/// Version de l'enveloppe AEAD : `1` = XChaCha20-Poly1305.
pub(crate) const AEAD_VERSION: u8 = 1;

/// Texte chiffré AEAD auto-descriptif : version + nonce (192 bits) + données
/// chiffrées (tag inclus). Opaque et sérialisable.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    /// Version de l'algorithme AEAD (authentifiée via les données associées).
    pub version: u8,
    /// Nonce XChaCha20-Poly1305.
    pub nonce: [u8; XNONCE_LEN],
    /// Données chiffrées + tag d'authentification.
    pub ciphertext: Vec<u8>,
}

/// Chiffre `plaintext` sous `key` avec un nonce aléatoire ; la version est liée au
/// texte chiffré via les données associées.
pub(crate) fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Ciphertext> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Crypto("clé AEAD invalide".into()))?;
    let mut nonce = [0u8; XNONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &[AEAD_VERSION],
            },
        )
        .map_err(|_| Error::Crypto("échec du chiffrement".into()))?;
    Ok(Ciphertext {
        version: AEAD_VERSION,
        nonce,
        ciphertext,
    })
}

/// Déchiffre + authentifie un [`Ciphertext`] sous `key`. Rejette les versions
/// inconnues (agilité crypto) ; la version est liée au texte via l'authentification.
pub(crate) fn open(key: &[u8; KEY_LEN], sealed: &Ciphertext) -> Result<Vec<u8>> {
    if sealed.version != AEAD_VERSION {
        return Err(Error::Crypto("version AEAD inconnue".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Crypto("clé AEAD invalide".into()))?;
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: sealed.ciphertext.as_slice(),
                aad: &[sealed.version],
            },
        )
        .map_err(|_| Error::Crypto("authentification échouée".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    #[test]
    fn serialization_roundtrip_preserves_ciphertext() {
        let key = [7u8; KEY_LEN];
        let sealed = seal(&key, b"donnee secrete").unwrap();
        let bytes = codec::encode(&sealed).unwrap();
        let decoded: Ciphertext = codec::decode(&bytes).unwrap();
        assert_eq!(sealed, decoded);
        assert_eq!(open(&key, &decoded).unwrap(), b"donnee secrete");
    }

    #[test]
    fn version_is_recorded() {
        let sealed = seal(&[7u8; KEY_LEN], b"x").unwrap();
        assert_eq!(sealed.version, AEAD_VERSION);
    }

    #[test]
    fn unknown_version_is_rejected() {
        let key = [7u8; KEY_LEN];
        let mut sealed = seal(&key, b"x").unwrap();
        sealed.version = 99;
        assert!(open(&key, &sealed).is_err());
    }
}
