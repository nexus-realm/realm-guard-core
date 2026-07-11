//! Chiffrement par entrée : chaque entrée du coffre a sa **propre** clé, dérivée
//! de la clé racine et de l'identifiant de l'entrée.
//!
//! `HKDF-SHA256(ikm = VK, info = domaine ‖ entry_id)` → sous-clé, puis AEAD.
//! La sous-clé dépendant de `entry_id`, un texte chiffré ne se déchiffre que pour
//! la bonne entrée (liaison implicite entrée ↔ ciphertext ; pas de réutilisation
//! de clé entre entrées).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};

use super::aead::{Ciphertext, open, seal};
use super::{KEY_LEN, VaultKey};

// Séparation de domaine pour la dérivation des sous-clés d'entrée.
const ENTRY_KEY_INFO: &[u8] = b"realm-guard-core/v1/entry-key";

/// Dérive la sous-clé propre d'une entrée depuis la clé racine.
fn entry_subkey(vault_key: &VaultKey, entry_id: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, vault_key.as_bytes());
    let mut info = Vec::with_capacity(ENTRY_KEY_INFO.len() + entry_id.len());
    info.extend_from_slice(ENTRY_KEY_INFO);
    info.extend_from_slice(entry_id);
    let mut subkey = [0u8; KEY_LEN];
    hk.expand(&info, &mut subkey)
        .map_err(|_| Error::Crypto("dérivation HKDF échouée".into()))?;
    Ok(subkey)
}

/// Chiffre le contenu d'une entrée sous sa sous-clé propre (dérivée de
/// `vault_key` et `entry_id`).
///
/// # Errors
/// Échec HKDF, CSPRNG, ou chiffrement.
pub fn encrypt_entry(
    vault_key: &VaultKey,
    entry_id: &[u8],
    plaintext: &[u8],
) -> Result<Ciphertext> {
    let mut subkey = entry_subkey(vault_key, entry_id)?;
    let result = seal(&subkey, plaintext);
    subkey.zeroize();
    result
}

/// Déchiffre + authentifie le contenu d'une entrée.
///
/// # Errors
/// Mauvaise clé racine, mauvais `entry_id`, ou texte chiffré altéré.
pub fn decrypt_entry(
    vault_key: &VaultKey,
    entry_id: &[u8],
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>> {
    let mut subkey = entry_subkey(vault_key, entry_id)?;
    let result = open(&subkey, ciphertext);
    subkey.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vk() -> VaultKey {
        VaultKey::generate().unwrap()
    }

    #[test]
    fn roundtrip() {
        let vk = vk();
        let ct = encrypt_entry(&vk, b"entry-1", b"secret data").unwrap();
        assert_eq!(decrypt_entry(&vk, b"entry-1", &ct).unwrap(), b"secret data");
    }

    #[test]
    fn wrong_entry_id_rejected() {
        let vk = vk();
        let ct = encrypt_entry(&vk, b"entry-1", b"data").unwrap();
        assert!(decrypt_entry(&vk, b"entry-2", &ct).is_err());
    }

    #[test]
    fn wrong_vault_key_rejected() {
        let ct = encrypt_entry(&vk(), b"e", b"data").unwrap();
        assert!(decrypt_entry(&vk(), b"e", &ct).is_err());
    }

    #[test]
    fn tampered_rejected() {
        let vk = vk();
        let mut ct = encrypt_entry(&vk, b"e", b"data").unwrap();
        ct.ciphertext[0] ^= 0xFF;
        assert!(decrypt_entry(&vk, b"e", &ct).is_err());
    }

    #[test]
    fn distinct_entries_distinct_ciphertext() {
        let vk = vk();
        let a = encrypt_entry(&vk, b"a", b"data").unwrap();
        let b = encrypt_entry(&vk, b"b", b"data").unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let vk = vk();
        let ct = encrypt_entry(&vk, b"e", b"").unwrap();
        assert_eq!(decrypt_entry(&vk, b"e", &ct).unwrap(), b"");
    }
}
