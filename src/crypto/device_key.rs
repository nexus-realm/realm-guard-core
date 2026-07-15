//! Clés d'identité d'appareil (Ed25519) : génération, signature, vérification.
//!
//! Servent à l'**authentification par appareil** (challenge-response serveur) : un
//! appareil appairé, qui ne connaît **pas** le mot de passe du compte, prouve son
//! identité en signant un défi avec sa clé privée. Le mobile génère + persiste la
//! clé (secure storage) et signe ; le serveur vérifie contre le registre. Crate
//! auditée (`ed25519-dalek`), aucune crypto maison.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Longueur d'une clé Ed25519 (publique) / d'une graine secrète.
const ED25519_KEY_LEN: usize = 32;
/// Longueur d'une signature Ed25519.
const ED25519_SIG_LEN: usize = 64;

/// Paire de clés d'appareil (octets, orientés FFI).
pub struct DeviceKeypair {
    /// Clé publique (32 octets) — publiée au registre du compte.
    pub public: Vec<u8>,
    /// Graine secrète (32 octets) — à conserver **hors-ligne** (secure storage).
    pub secret: Vec<u8>,
}

/// Génère une paire de clés d'appareil Ed25519.
///
/// # Errors
/// Échec du CSPRNG.
pub fn generate_device_keypair() -> Result<DeviceKeypair> {
    let mut seed = [0u8; ED25519_KEY_LEN];
    getrandom::getrandom(&mut seed).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes().to_vec();
    let secret = seed.to_vec();
    seed.zeroize();
    Ok(DeviceKeypair { public, secret })
}

/// Signe `message` avec la graine secrète (32 octets). Renvoie une signature de 64
/// octets.
///
/// # Errors
/// Longueur de graine invalide.
pub fn device_sign(secret: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut seed: [u8; ED25519_KEY_LEN] = secret.try_into().map_err(|_| {
        Error::Crypto(format!(
            "longueur de graine invalide (attendu {ED25519_KEY_LEN})"
        ))
    })?;
    let signing = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let signature = signing.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Vérifie une signature Ed25519. Renvoie `false` sur toute entrée malformée ou
/// signature invalide (pas d'oracle d'erreur détaillé).
#[must_use]
pub fn device_verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public_bytes) = <[u8; ED25519_KEY_LEN]>::try_from(public) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&public_bytes) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; ED25519_SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);
    verifying.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrip() {
        let kp = generate_device_keypair().unwrap();
        let message = b"challenge-nonce";
        let signature = device_sign(&kp.secret, message).unwrap();
        assert_eq!(kp.public.len(), ED25519_KEY_LEN);
        assert_eq!(signature.len(), ED25519_SIG_LEN);
        assert!(device_verify(&kp.public, message, &signature));
    }

    #[test]
    fn wrong_message_fails() {
        let kp = generate_device_keypair().unwrap();
        let signature = device_sign(&kp.secret, b"nonce-a").unwrap();
        assert!(!device_verify(&kp.public, b"nonce-b", &signature));
    }

    #[test]
    fn wrong_key_fails() {
        let signer = generate_device_keypair().unwrap();
        let other = generate_device_keypair().unwrap();
        let signature = device_sign(&signer.secret, b"nonce").unwrap();
        assert!(!device_verify(&other.public, b"nonce", &signature));
    }

    #[test]
    fn tampered_signature_fails() {
        let kp = generate_device_keypair().unwrap();
        let mut signature = device_sign(&kp.secret, b"nonce").unwrap();
        signature[0] ^= 0xFF;
        assert!(!device_verify(&kp.public, b"nonce", &signature));
    }

    #[test]
    fn malformed_inputs_fail() {
        let kp = generate_device_keypair().unwrap();
        let signature = device_sign(&kp.secret, b"nonce").unwrap();
        assert!(!device_verify(&[0u8; 10], b"nonce", &signature));
        assert!(!device_verify(&kp.public, b"nonce", &[0u8; 10]));
        assert!(device_sign(&[0u8; 10], b"nonce").is_err());
    }
}
