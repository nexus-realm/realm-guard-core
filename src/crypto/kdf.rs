//! Dérivation de la clé d'enrobage (KEK) du mot de passe maître via Argon2id.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{Error, Result};

use super::{ARGON2_M_COST_KIB, ARGON2_P_COST, ARGON2_T_COST, KEY_LEN, MasterKey, SALT_LEN};

/// Dérive la clé d'enrobage (KEK) du mot de passe maître via **Argon2id**
/// (m = 64 MiB, t = 3, p = 1, sortie 32 octets — aligné sur l'app v1).
///
/// # Errors
/// Mot de passe vide, ou échec interne d'Argon2.
pub fn derive_master_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<MasterKey> {
    if password.is_empty() {
        return Err(Error::Crypto("mot de passe vide".into()));
    }
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::Crypto(format!("paramètres Argon2 : {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| Error::Crypto(format!("Argon2 : {e}")))?;
    Ok(MasterKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];

    #[test]
    fn deterministic() {
        let a = derive_master_key(b"correct horse battery staple", &SALT).unwrap();
        let b = derive_master_key(b"correct horse battery staple", &SALT).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn depends_on_password() {
        let a = derive_master_key(b"password-a", &SALT).unwrap();
        let b = derive_master_key(b"password-b", &SALT).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn depends_on_salt() {
        let a = derive_master_key(b"pw", &[1u8; SALT_LEN]).unwrap();
        let b = derive_master_key(b"pw", &[2u8; SALT_LEN]).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn rejects_empty_password() {
        assert!(derive_master_key(b"", &SALT).is_err());
    }
}
