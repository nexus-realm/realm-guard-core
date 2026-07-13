//! Clé racine du coffre ([`VaultKey`]) : génération aléatoire + enrobage.

use zeroize::Zeroize;

use crate::error::{Error, Result};

use super::aead::{Ciphertext, open, seal};
use super::{KEY_LEN, MasterKey, VaultKey};

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

/// Enrobe (chiffre) la [`VaultKey`] avec la [`MasterKey`] (KEK).
///
/// # Errors
/// Échec du CSPRNG ou du chiffrement.
pub fn wrap_vault_key(vault_key: &VaultKey, kek: &MasterKey) -> Result<Ciphertext> {
    seal(kek.as_bytes(), vault_key.as_bytes())
}

/// Désenrobe (déchiffre + authentifie) la [`VaultKey`].
///
/// # Errors
/// Mauvaise clé, texte chiffré altéré, ou taille de clé invalide.
pub fn unwrap_vault_key(wrapped: &Ciphertext, kek: &MasterKey) -> Result<VaultKey> {
    let mut plaintext = open(kek.as_bytes(), wrapped)?;
    let bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("taille de clé invalide".into()))?;
    plaintext.zeroize(); // efface la copie en clair de la clé
    Ok(VaultKey::from_bytes(bytes))
}

/// Génère une VaultKey aléatoire et renvoie ses octets bruts. Variante **orientée
/// octets** pour le pont FFI (le typage `VaultKey` reste interne au cœur).
///
/// # Errors
/// Échec du CSPRNG de l'OS.
pub fn generate_vault_key_bytes() -> Result<Vec<u8>> {
    Ok(VaultKey::generate()?.as_bytes().to_vec())
}

/// Enrobe une VaultKey (octets) sous la KEK (octets) — variante orientée octets de
/// [`wrap_vault_key`] pour le pont FFI. Les deux clés doivent faire [`KEY_LEN`] octets.
///
/// # Errors
/// Taille de clé invalide, ou échec du chiffrement.
pub fn wrap_vault_key_bytes(kek: &[u8], vault_key: &[u8]) -> Result<Ciphertext> {
    let kek = MasterKey::from_slice(kek)?;
    let vault_key = VaultKey::from_slice(vault_key)?;
    wrap_vault_key(&vault_key, &kek)
}

/// Désenrobe une VaultKey et renvoie ses octets bruts — variante orientée octets de
/// [`unwrap_vault_key`] pour le pont FFI.
///
/// # Errors
/// Taille de KEK invalide, mauvaise clé, ou texte chiffré altéré.
pub fn unwrap_vault_key_bytes(kek: &[u8], wrapped: &Ciphertext) -> Result<Vec<u8>> {
    let kek = MasterKey::from_slice(kek)?;
    Ok(unwrap_vault_key(wrapped, &kek)?.as_bytes().to_vec())
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

    #[test]
    fn byte_wrappers_roundtrip() {
        let kek = [7u8; KEY_LEN];
        let vk = generate_vault_key_bytes().unwrap();
        assert_eq!(vk.len(), KEY_LEN);
        let wrapped = wrap_vault_key_bytes(&kek, &vk).unwrap();
        assert_eq!(unwrap_vault_key_bytes(&kek, &wrapped).unwrap(), vk);
    }

    #[test]
    fn byte_wrap_rejects_bad_key_length() {
        assert!(wrap_vault_key_bytes(&[0u8; 16], &[1u8; KEY_LEN]).is_err());
        assert!(wrap_vault_key_bytes(&[0u8; KEY_LEN], &[1u8; 10]).is_err());
    }

    #[test]
    fn byte_unwrap_wrong_kek_rejected() {
        let vk = generate_vault_key_bytes().unwrap();
        let wrapped = wrap_vault_key_bytes(&[1u8; KEY_LEN], &vk).unwrap();
        assert!(unwrap_vault_key_bytes(&[2u8; KEY_LEN], &wrapped).is_err());
    }
}
