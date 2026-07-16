//! Cryptographie E2EE — hiérarchie de clés.
//!
//! master password —Argon2id→ **KEK** ([`MasterKey`]) —AEAD→ enrobe/désenrobe la
//! **root vault key** ([`VaultKey`], aléatoire, indépendante du mot de passe).
//! La VK chiffrera les entrées du coffre (AEAD par entrée, P0.2c) et sera aussi
//! enrobée par un code de récupération (kit de récup, P0.2d). Le serveur ne voit
//! jamais ni le mot de passe ni la VK.
//!
//! Primitives : Argon2id (KDF), XChaCha20-Poly1305 (AEAD) — crates auditées
//! (RustCrypto), aucune crypto maison. Les secrets sont effacés au drop (`zeroize`).

mod aead;
mod device_key;
mod entry;
mod kdf;
mod pairing;
mod recovery;
mod server_blob;
mod vault_key;

pub use aead::Ciphertext;
pub use device_key::{DeviceKeypair, device_sign, device_verify, generate_device_keypair};
pub use entry::{decrypt_entry, encrypt_entry};
pub use kdf::derive_master_key;
pub use pairing::{
    PairingConfirm, PairingOpenResult, PairingSourceBegin, PairingStart,
    pairing_new_device_confirm, pairing_open, pairing_source_begin, pairing_source_seal,
    pairing_start,
};
pub use recovery::{RecoveryCode, create_recovery_kit, recover_vault_key};
pub use server_blob::{open_with_export_key, seal_with_export_key};
pub use vault_key::{
    generate_vault_key_bytes, unwrap_vault_key, unwrap_vault_key_bytes, wrap_vault_key,
    wrap_vault_key_bytes,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Longueur des clés symétriques (256 bits).
pub const KEY_LEN: usize = 32;
/// Longueur du sel de dérivation (256 bits).
pub const SALT_LEN: usize = 32;
/// Longueur du nonce XChaCha20-Poly1305 (192 bits).
pub const XNONCE_LEN: usize = 24;

// Paramètres Argon2id, alignés sur l'app v1 (m = 64 MiB, t = 3, p = 1).
const ARGON2_M_COST_KIB: u32 = 65_536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// Clé d'enrobage (KEK) dérivée du mot de passe maître via Argon2id.
/// Jamais persistée ; sert uniquement à enrober/désenrober la [`VaultKey`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

/// Clé racine du coffre (VK), aléatoire et **indépendante du mot de passe**.
/// Chiffre les entrées ; transférée aux appareils au pairing, jamais au serveur.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

impl MasterKey {
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Construit une KEK depuis une tranche, en validant la longueur.
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
            Error::Crypto(format!(
                "KEK de taille invalide ({} octets, {KEY_LEN} attendus)",
                bytes.len()
            ))
        })?;
        Ok(Self::from_bytes(array))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl VaultKey {
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Construit une VaultKey depuis une tranche, en validant la longueur.
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
            Error::Crypto(format!(
                "VaultKey de taille invalide ({} octets, {KEY_LEN} attendus)",
                bytes.len()
            ))
        })?;
        Ok(Self::from_bytes(array))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}
