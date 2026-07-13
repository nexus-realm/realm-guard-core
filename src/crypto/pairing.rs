//! Pairing d'appareil : transfert **E2E** de la VaultKey d'un appareil source
//! (déjà déverrouillé) vers un nouvel appareil, via un canal authentifié par QR +
//! SAS. Le serveur ne relaie qu'un **blob opaque** ; la VaultKey ne lui est jamais
//! exposée (ni au serveur, ni enrobée par une clé qu'il connaît).
//!
//! Flux :
//! 1. le **nouvel appareil** génère une paire éphémère X25519 et affiche
//!    `{pairing_id, pk}` en QR ([`pairing_start`]) ;
//! 2. l'**appareil source** scanne, fait un ECDH, scelle la VaultKey et renvoie
//!    `{pk_src, blob}` ([`pairing_seal`]) — relayé, opaque ;
//! 3. le **nouvel appareil** refait l'ECDH et ouvre ([`pairing_open`]).
//!
//! Les deux côtés dérivent, du **même** secret partagé + transcript
//! (`pk_new ‖ pk_src`), une clé AEAD **et** un **SAS** (code court). La clé étant
//! liée au transcript, toute substitution de clé publique (MITM) change la clé →
//! l'ouverture échoue ; et le SAS diverge → l'utilisateur le détecte. Aucune crypto
//! maison : X25519 (dalek), HKDF-SHA256, AEAD partagé du cœur.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::codec;
use crate::error::{Error, Result};

use super::KEY_LEN;
use super::aead::{Ciphertext, open, seal};

const PAIRING_ID_LEN: usize = 16;
const X25519_LEN: usize = 32;

// Séparation de domaine pour les deux dérivations HKDF.
const AEAD_INFO: &[u8] = b"realm-guard-core/v1/pairing-aead";
const SAS_INFO: &[u8] = b"realm-guard-core/v1/pairing-sas";

/// Requête de pairing affichée en QR par le nouvel appareil.
#[derive(Serialize, Deserialize)]
struct PairingRequest {
    pairing_id: [u8; PAIRING_ID_LEN],
    public_key: [u8; X25519_LEN],
}

/// État conservé par le nouvel appareil entre l'affichage du QR et la réception.
/// **Contient le secret éphémère** ; à traiter comme sensible et éphémère.
#[derive(Serialize, Deserialize)]
struct PairingState {
    secret: [u8; X25519_LEN],
    pairing_id: [u8; PAIRING_ID_LEN],
}

/// Réponse scellée renvoyée par l'appareil source (relayée, opaque au serveur).
#[derive(Serialize, Deserialize)]
struct PairingSealed {
    source_public: [u8; X25519_LEN],
    ciphertext: Ciphertext,
}

/// Résultat du démarrage côté **nouvel appareil**.
pub struct PairingStart {
    /// État à conserver (contient le secret éphémère) jusqu'à la réception.
    pub state: Vec<u8>,
    /// Payload QR à afficher (`{pairing_id, pk}`, sérialisé).
    pub qr: Vec<u8>,
}

/// Résultat du scellage côté **appareil source**.
pub struct PairingSealResult {
    /// Réponse scellée à relayer au nouvel appareil.
    pub response: Vec<u8>,
    /// SAS à afficher (doit correspondre à celui du nouvel appareil).
    pub sas: String,
}

/// Résultat de l'ouverture côté **nouvel appareil**.
pub struct PairingOpenResult {
    /// VaultKey reçue (octets).
    pub vault_key: Vec<u8>,
    /// SAS à afficher (doit correspondre à celui de l'appareil source).
    pub sas: String,
}

/// **Nouvel appareil** — démarre le pairing : génère une paire éphémère X25519 + un
/// `pairing_id` aléatoire. Renvoie l'état à conserver et le payload QR à afficher.
///
/// # Errors
/// Échec du CSPRNG ou de la sérialisation.
pub fn pairing_start() -> Result<PairingStart> {
    let mut secret_bytes = [0u8; X25519_LEN];
    getrandom::getrandom(&mut secret_bytes).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    let mut pairing_id = [0u8; PAIRING_ID_LEN];
    getrandom::getrandom(&mut pairing_id).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;

    let request = PairingRequest {
        pairing_id,
        public_key: public.to_bytes(),
    };
    let mut state = PairingState {
        secret: secret_bytes,
        pairing_id,
    };
    let qr = codec::encode(&request)?;
    let encoded_state = codec::encode(&state)?;
    secret_bytes.zeroize();
    state.secret.zeroize();
    Ok(PairingStart {
        state: encoded_state,
        qr,
    })
}

/// **Appareil source** — scelle la `vault_key` vers le nouvel appareil décrit par le
/// QR. Renvoie la réponse à relayer + le SAS à afficher.
///
/// # Errors
/// QR invalide, échec du CSPRNG, ou échec du chiffrement.
pub fn pairing_seal(qr: &[u8], vault_key: &[u8]) -> Result<PairingSealResult> {
    let request: PairingRequest = codec::decode(qr)?;
    let their_public = PublicKey::from(request.public_key);

    let mut secret_bytes = [0u8; X25519_LEN];
    getrandom::getrandom(&mut secret_bytes).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let secret = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();
    let source_public = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&their_public);

    let (mut aead_key, sas) = derive(shared.as_bytes(), &request.public_key, &source_public)?;
    let ciphertext = seal(&aead_key, vault_key);
    aead_key.zeroize();
    let ciphertext = ciphertext?;

    let sealed = PairingSealed {
        source_public,
        ciphertext,
    };
    Ok(PairingSealResult {
        response: codec::encode(&sealed)?,
        sas,
    })
}

/// **Nouvel appareil** — ouvre la réponse scellée avec l'état conservé. Renvoie la
/// VaultKey + le SAS à afficher. **Échoue** si le blob ne s'ouvre pas (mauvais
/// destinataire, ou transcript/blob altéré).
///
/// # Errors
/// État ou réponse invalide, mauvaise clé, ou texte chiffré altéré.
pub fn pairing_open(state: &[u8], response: &[u8]) -> Result<PairingOpenResult> {
    let mut state: PairingState = codec::decode(state)?;
    let sealed: PairingSealed = codec::decode(response)?;

    let secret = StaticSecret::from(state.secret);
    let our_public = PublicKey::from(&secret).to_bytes();
    let their_public = PublicKey::from(sealed.source_public);
    let shared = secret.diffie_hellman(&their_public);

    let (mut aead_key, sas) = derive(shared.as_bytes(), &our_public, &sealed.source_public)?;
    let result = open(&aead_key, &sealed.ciphertext);
    aead_key.zeroize();
    state.secret.zeroize();
    let vault_key = result?;
    Ok(PairingOpenResult { vault_key, sas })
}

/// Dérive la clé AEAD et le SAS depuis le secret partagé ECDH + le transcript
/// (`pk_new ‖ pk_src`, ordre fixe). Lier le transcript à la clé rend une
/// substitution de clé publique (MITM) détectable : clé différente → ouverture qui
/// échoue, et SAS différent.
fn derive(shared: &[u8], pk_new: &[u8], pk_src: &[u8]) -> Result<([u8; KEY_LEN], String)> {
    let hk = Hkdf::<Sha256>::new(None, shared);

    let mut aead_key = [0u8; KEY_LEN];
    hk.expand_multi_info(&[AEAD_INFO, pk_new, pk_src], &mut aead_key)
        .map_err(|_| Error::Crypto("dérivation HKDF (pairing AEAD) échouée".into()))?;

    let mut sas_bytes = [0u8; 4];
    hk.expand_multi_info(&[SAS_INFO, pk_new, pk_src], &mut sas_bytes)
        .map_err(|_| Error::Crypto("dérivation HKDF (pairing SAS) échouée".into()))?;

    Ok((aead_key, format_sas(&sas_bytes)))
}

/// Formate le SAS en **6 chiffres** (code court à comparer par l'utilisateur).
fn format_sas(bytes: &[u8; 4]) -> String {
    let value = u32::from_be_bytes(*bytes) % 1_000_000;
    format!("{value:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_transfers_vault_key_with_matching_sas() {
        let vault_key = [42u8; KEY_LEN];
        let start = pairing_start().unwrap();
        let sealed = pairing_seal(&start.qr, &vault_key).unwrap();
        let opened = pairing_open(&start.state, &sealed.response).unwrap();

        assert_eq!(opened.vault_key, vault_key);
        // Les deux appareils affichent le **même** SAS (6 chiffres).
        assert_eq!(sealed.sas, opened.sas);
        assert_eq!(opened.sas.len(), 6);
        assert!(opened.sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let vault_key = [7u8; KEY_LEN];
        let target = pairing_start().unwrap();
        let other = pairing_start().unwrap();
        let sealed = pairing_seal(&target.qr, &vault_key).unwrap();
        // Un autre appareil (autre secret éphémère) ne peut pas ouvrir le blob.
        assert!(pairing_open(&other.state, &sealed.response).is_err());
    }

    #[test]
    fn tampered_response_rejected() {
        let vault_key = [9u8; KEY_LEN];
        let start = pairing_start().unwrap();
        let sealed = pairing_seal(&start.qr, &vault_key).unwrap();
        let mut tampered = sealed.response.clone();
        *tampered.last_mut().unwrap() ^= 0xFF;
        assert!(pairing_open(&start.state, &tampered).is_err());
    }
}
