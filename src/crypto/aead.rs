//! Enveloppe AEAD partagée (XChaCha20-Poly1305) : nonce aléatoire + ciphertext.
//! Mutualisée par l'enrobage de clé ([`super::vault_key`]) et le chiffrement par
//! entrée ([`super::entry`]).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::error::{Error, Result};

use super::{KEY_LEN, XNONCE_LEN};

/// Texte chiffré AEAD : nonce (192 bits) + données chiffrées (tag inclus). Opaque.
#[derive(Clone, Debug)]
pub struct Ciphertext {
    /// Nonce XChaCha20-Poly1305.
    pub nonce: [u8; XNONCE_LEN],
    /// Données chiffrées + tag d'authentification.
    pub ciphertext: Vec<u8>,
}

/// Chiffre `plaintext` sous `key` avec un nonce aléatoire.
pub(crate) fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Ciphertext> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Crypto("clé AEAD invalide".into()))?;
    let mut nonce = [0u8; XNONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Crypto("échec du chiffrement".into()))?;
    Ok(Ciphertext { nonce, ciphertext })
}

/// Déchiffre + authentifie un [`Ciphertext`] sous `key`.
pub(crate) fn open(key: &[u8; KEY_LEN], sealed: &Ciphertext) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::Crypto("clé AEAD invalide".into()))?;
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            sealed.ciphertext.as_slice(),
        )
        .map_err(|_| Error::Crypto("authentification échouée".into()))
}
