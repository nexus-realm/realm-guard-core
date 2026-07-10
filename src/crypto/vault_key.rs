//! Clé racine du coffre ([`VaultKey`]) : génération aléatoire + enrobage.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

use crate::error::{Error, Result};

use super::{KEY_LEN, MasterKey, VaultKey, XNONCE_LEN};

impl VaultKey {
    /// Génère une clé de coffre aléatoire via le CSPRNG du système.
    ///
    /// # Errors
    /// Échec du générateur aléatoire de l'OS.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::getrandom(&mut bytes).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
        Ok(Self::from_bytes(bytes))
    }
}

/// Clé de coffre enrobée : nonce + texte chiffré (opaque). Format stocké/transmis.
#[derive(Clone, Debug)]
pub struct WrappedKey {
    /// Nonce XChaCha20-Poly1305 (192 bits).
    pub nonce: [u8; XNONCE_LEN],
    /// Texte chiffré (clé + tag d'authentification).
    pub ciphertext: Vec<u8>,
}

/// Enrobe (chiffre) la [`VaultKey`] avec la [`MasterKey`] (KEK) via
/// XChaCha20-Poly1305 et un nonce aléatoire.
///
/// # Errors
/// Échec du CSPRNG ou du chiffrement.
pub fn wrap_vault_key(vault_key: &VaultKey, kek: &MasterKey) -> Result<WrappedKey> {
    let cipher = XChaCha20Poly1305::new_from_slice(kek.as_bytes())
        .map_err(|_| Error::Crypto("clé d'enrobage invalide".into()))?;
    let mut nonce = [0u8; XNONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), vault_key.as_bytes().as_slice())
        .map_err(|_| Error::Crypto("échec de l'enrobage".into()))?;
    Ok(WrappedKey { nonce, ciphertext })
}

/// Désenrobe (déchiffre + authentifie) la [`VaultKey`].
///
/// # Errors
/// Mauvaise clé, texte chiffré altéré, ou taille de clé invalide.
pub fn unwrap_vault_key(wrapped: &WrappedKey, kek: &MasterKey) -> Result<VaultKey> {
    let cipher = XChaCha20Poly1305::new_from_slice(kek.as_bytes())
        .map_err(|_| Error::Crypto("clé d'enrobage invalide".into()))?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            wrapped.ciphertext.as_slice(),
        )
        .map_err(|_| Error::Crypto("désenrobage : authentification échouée".into()))?;
    let bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("taille de clé invalide".into()))?;
    plaintext.zeroize(); // efface la copie en clair de la clé
    Ok(VaultKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SALT_LEN, derive_master_key};

    fn kek(password: &[u8]) -> MasterKey {
        derive_master_key(password, &[9u8; SALT_LEN]).unwrap()
    }

    #[test]
    fn generate_is_random() {
        let a = VaultKey::generate().unwrap();
        let b = VaultKey::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = kek(b"master-password");
        let vk = VaultKey::generate().unwrap();
        let wrapped = wrap_vault_key(&vk, &kek).unwrap();
        let unwrapped = unwrap_vault_key(&wrapped, &kek).unwrap();
        assert_eq!(vk.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn distinct_nonces_across_wraps() {
        let kek = kek(b"pw");
        let vk = VaultKey::generate().unwrap();
        let w1 = wrap_vault_key(&vk, &kek).unwrap();
        let w2 = wrap_vault_key(&vk, &kek).unwrap();
        assert_ne!(w1.nonce, w2.nonce);
        assert_ne!(w1.ciphertext, w2.ciphertext);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let kek = kek(b"pw");
        let vk = VaultKey::generate().unwrap();
        let mut wrapped = wrap_vault_key(&vk, &kek).unwrap();
        wrapped.ciphertext[0] ^= 0xFF;
        assert!(unwrap_vault_key(&wrapped, &kek).is_err());
    }

    #[test]
    fn wrong_kek_rejected() {
        let vk = VaultKey::generate().unwrap();
        let wrapped = wrap_vault_key(&vk, &kek(b"password-1")).unwrap();
        assert!(unwrap_vault_key(&wrapped, &kek(b"password-2")).is_err());
    }
}
