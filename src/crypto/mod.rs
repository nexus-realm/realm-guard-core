//! Cryptographie E2EE — hiérarchie de clés (implémenté au lot P0.2).
//!
//! Modèle cible :
//! - master password —Argon2id→ KEK (clé d'enrobage) ;
//! - KEK —AEAD→ wrap/unwrap de la *root vault key* (VK, aléatoire) ;
//! - VK —AEAD par entrée→ chiffrement des entrées du coffre ;
//! - kit de récupération : VK également wrappée par un code de récup haute entropie.
//!
//! Crates prévues : argon2, chacha20poly1305, hkdf, getrandom, zeroize, subtle.

// TODO(P0.2): KeyDerivator (Argon2id), VaultKey, wrap/unwrap, AEAD par entrée,
// kit de récupération. Revue sécurité requise avant merge.
