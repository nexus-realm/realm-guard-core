//! Kit de récupération : la [`VaultKey`] est aussi enrobée par une clé dérivée
//! d'un **code de récupération** (mnémonique BIP39 de 24 mots, 256 bits).
//!
//! Permet la récupération **en solo** (sans appareil pairé) : l'utilisateur note
//! le code hors-ligne ; la VK enrobée est stockée (p. ex. côté serveur, opaque).
//! Le code étant à 256 bits, une simple dérivation HKDF suffit (pas de brute-force
//! possible — inutile d'un KDF lent).

use bip39::Mnemonic;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

use super::aead::{Ciphertext, open, seal};
use super::{KEY_LEN, VaultKey};

const RECOVERY_ENTROPY_LEN: usize = 32; // 256 bits → 24 mots
const RECOVERY_KEY_INFO: &[u8] = b"realm-guard-core/v1/recovery-key";

/// Code de récupération : phrase mnémonique BIP39 (24 mots). À conserver
/// hors-ligne par l'utilisateur ; effacé de la mémoire au drop.
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    /// La phrase (24 mots séparés par des espaces).
    #[must_use]
    pub fn phrase(&self) -> &str {
        self.0.as_str()
    }
}

/// Dérive la clé de récupération depuis l'entropie du code (HKDF-SHA256).
fn recovery_key(entropy: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, entropy);
    let mut key = [0u8; KEY_LEN];
    hk.expand(RECOVERY_KEY_INFO, &mut key)
        .map_err(|_| Error::Crypto("dérivation HKDF (récup) échouée".into()))?;
    Ok(key)
}

/// Crée un kit de récupération pour `vault_key` : un **code mnémonique** (à
/// montrer une fois à l'utilisateur) et la **VK enrobée** par la clé de récup
/// (à stocker).
///
/// # Errors
/// Échec du CSPRNG, de BIP39, ou du chiffrement.
pub fn create_recovery_kit(vault_key: &VaultKey) -> Result<(RecoveryCode, Ciphertext)> {
    let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
    getrandom::getrandom(&mut entropy).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let mnemonic =
        Mnemonic::from_entropy(&entropy).map_err(|e| Error::Crypto(format!("BIP39 : {e}")))?;
    let mut key = recovery_key(&entropy)?;
    entropy.zeroize();
    let wrapped = seal(&key, vault_key.as_bytes());
    key.zeroize();
    let code = RecoveryCode(Zeroizing::new(mnemonic.to_string()));
    Ok((code, wrapped?))
}

/// Récupère la [`VaultKey`] depuis le code de récupération et la VK enrobée.
///
/// # Errors
/// Code invalide, ou texte chiffré altéré / ne correspondant pas au code.
pub fn recover_vault_key(recovery_phrase: &str, wrapped: &Ciphertext) -> Result<VaultKey> {
    let mnemonic = Mnemonic::parse(recovery_phrase.trim())
        .map_err(|_| Error::Crypto("code de récupération invalide".into()))?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let mut key = recovery_key(&entropy)?;
    let plaintext = open(&key, wrapped);
    key.zeroize();
    let mut plaintext = plaintext?;
    let bytes: [u8; KEY_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("taille de clé invalide".into()))?;
    plaintext.zeroize();
    Ok(VaultKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let vk = VaultKey::generate().unwrap();
        let (code, wrapped) = create_recovery_kit(&vk).unwrap();
        let recovered = recover_vault_key(code.phrase(), &wrapped).unwrap();
        assert_eq!(vk.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn code_is_24_words() {
        let vk = VaultKey::generate().unwrap();
        let (code, _) = create_recovery_kit(&vk).unwrap();
        assert_eq!(code.phrase().split_whitespace().count(), 24);
    }

    #[test]
    fn wrong_code_rejected() {
        let vk = VaultKey::generate().unwrap();
        let (_, wrapped) = create_recovery_kit(&vk).unwrap();
        let (other, _) = create_recovery_kit(&VaultKey::generate().unwrap()).unwrap();
        assert!(recover_vault_key(other.phrase(), &wrapped).is_err());
    }

    #[test]
    fn invalid_code_rejected() {
        let vk = VaultKey::generate().unwrap();
        let (_, wrapped) = create_recovery_kit(&vk).unwrap();
        assert!(recover_vault_key("not a valid mnemonic phrase", &wrapped).is_err());
    }

    #[test]
    fn tampered_wrapped_rejected() {
        let vk = VaultKey::generate().unwrap();
        let (code, mut wrapped) = create_recovery_kit(&vk).unwrap();
        wrapped.ciphertext[0] ^= 0xFF;
        assert!(recover_vault_key(code.phrase(), &wrapped).is_err());
    }
}
