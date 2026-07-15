//! Pairing d'appareil : transfert **E2E** de la VaultKey d'un appareil source
//! (déjà déverrouillé) vers un nouvel appareil, via un canal authentifié par QR +
//! SAS. Le serveur ne relaie qu'un **blob opaque** ; la VaultKey ne lui est jamais
//! exposée (ni au serveur, ni enrobée par une clé qu'il connaît).
//!
//! Flux :
//! 1. le **nouvel appareil** génère une paire éphémère X25519 et affiche
//!    `{pairing_id, pk, device_pk}` en QR ([`pairing_start`]) — `device_pk` est sa
//!    **clé d'identité d'appareil** (Ed25519, opaque ici), destinée à l'inscription
//!    au registre du compte (P3) ;
//! 2. l'**appareil source** scanne, fait un ECDH, scelle `{account_id, vault_key}`
//!    et renvoie `{pk_src, blob}` ([`pairing_seal`]) — relayé, opaque ;
//! 3. le **nouvel appareil** refait l'ECDH et ouvre ([`pairing_open`]) : il obtient
//!    la VaultKey **et** l'`account_id` du compte qu'il rejoint.
//!
//! Les deux côtés dérivent, du **même** secret partagé + transcript
//! (`pk_new ‖ pk_src ‖ device_pk`), une clé AEAD **et** un **SAS** (code court). La
//! clé étant liée au transcript, toute substitution de clé publique **ou** du
//! `device_pk` (MITM) change la clé → l'ouverture échoue ; et le SAS diverge →
//! l'utilisateur le détecte. Aucune crypto maison : X25519 (dalek), HKDF-SHA256,
//! AEAD partagé du cœur.

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
/// Clé d'identité d'appareil (Ed25519). Opaque pour le pairing : simplement liée au
/// transcript et acheminée jusqu'à l'inscription au registre (P3).
const DEVICE_PK_LEN: usize = 32;
/// Identifiant de compte (UUID) porté par le blob scellé.
const ACCOUNT_ID_LEN: usize = 16;

// Séparation de domaine pour les deux dérivations HKDF.
const AEAD_INFO: &[u8] = b"realm-guard-core/v1/pairing-aead";
const SAS_INFO: &[u8] = b"realm-guard-core/v1/pairing-sas";

/// Requête de pairing affichée en QR par le nouvel appareil.
#[derive(Serialize, Deserialize)]
struct PairingRequest {
    pairing_id: [u8; PAIRING_ID_LEN],
    public_key: [u8; X25519_LEN],
    device_public_key: [u8; DEVICE_PK_LEN],
}

/// État conservé par le nouvel appareil entre l'affichage du QR et la réception.
/// **Contient le secret éphémère** ; à traiter comme sensible et éphémère.
#[derive(Serialize, Deserialize)]
struct PairingState {
    secret: [u8; X25519_LEN],
    pairing_id: [u8; PAIRING_ID_LEN],
    device_public_key: [u8; DEVICE_PK_LEN],
}

/// Réponse scellée renvoyée par l'appareil source (relayée, opaque au serveur).
#[derive(Serialize, Deserialize)]
struct PairingSealed {
    source_public: [u8; X25519_LEN],
    ciphertext: Ciphertext,
}

/// Contenu chiffré transféré à l'intérieur du blob scellé.
#[derive(Serialize, Deserialize)]
struct PairingPayload {
    account_id: [u8; ACCOUNT_ID_LEN],
    vault_key: Vec<u8>,
}

/// Résultat du démarrage côté **nouvel appareil**.
pub struct PairingStart {
    /// État à conserver (contient le secret éphémère) jusqu'à la réception.
    pub state: Vec<u8>,
    /// Payload QR à afficher (`{pairing_id, pk, device_pk}`, sérialisé).
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
    /// Identifiant (UUID) du compte que le nouvel appareil rejoint.
    pub account_id: Vec<u8>,
    /// SAS à afficher (doit correspondre à celui de l'appareil source).
    pub sas: String,
}

/// **Nouvel appareil** — démarre le pairing : génère une paire éphémère X25519 + un
/// `pairing_id` aléatoire, et incorpore sa clé d'identité [`device_public_key`]
/// (Ed25519) au QR et à l'état. Renvoie l'état à conserver et le payload QR.
///
/// # Errors
/// `device_public_key` de longueur invalide, échec du CSPRNG ou de la sérialisation.
pub fn pairing_start(device_public_key: &[u8]) -> Result<PairingStart> {
    let device_pk = to_array::<DEVICE_PK_LEN>(device_public_key, "device_public_key")?;

    let mut secret_bytes = [0u8; X25519_LEN];
    getrandom::getrandom(&mut secret_bytes).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    let mut pairing_id = [0u8; PAIRING_ID_LEN];
    getrandom::getrandom(&mut pairing_id).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;

    let request = PairingRequest {
        pairing_id,
        public_key: public.to_bytes(),
        device_public_key: device_pk,
    };
    let mut state = PairingState {
        secret: secret_bytes,
        pairing_id,
        device_public_key: device_pk,
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

/// **Appareil source** — scelle `{account_id, vault_key}` vers le nouvel appareil
/// décrit par le QR. Le `device_public_key` du QR est lié au transcript (SAS/AEAD).
/// Renvoie la réponse à relayer + le SAS à afficher.
///
/// # Errors
/// `account_id` de longueur invalide, QR invalide, échec du CSPRNG ou du chiffrement.
pub fn pairing_seal(qr: &[u8], account_id: &[u8], vault_key: &[u8]) -> Result<PairingSealResult> {
    let account = to_array::<ACCOUNT_ID_LEN>(account_id, "account_id")?;
    let request: PairingRequest = codec::decode(qr)?;
    let their_public = PublicKey::from(request.public_key);

    let mut secret_bytes = [0u8; X25519_LEN];
    getrandom::getrandom(&mut secret_bytes).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let secret = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();
    let source_public = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&their_public);

    let (mut aead_key, sas) = derive(
        shared.as_bytes(),
        &request.public_key,
        &source_public,
        &request.device_public_key,
    )?;

    let mut payload = PairingPayload {
        account_id: account,
        vault_key: vault_key.to_vec(),
    };
    let mut plaintext = codec::encode(&payload)?;
    let ciphertext = seal(&aead_key, &plaintext);
    aead_key.zeroize();
    plaintext.zeroize();
    payload.vault_key.zeroize();
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
/// VaultKey + l'`account_id` + le SAS. **Échoue** si le blob ne s'ouvre pas (mauvais
/// destinataire, ou transcript/blob altéré — dont un `device_pk` substitué).
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

    let (mut aead_key, sas) = derive(
        shared.as_bytes(),
        &our_public,
        &sealed.source_public,
        &state.device_public_key,
    )?;
    let result = open(&aead_key, &sealed.ciphertext);
    aead_key.zeroize();
    state.secret.zeroize();

    let mut plaintext = result?;
    let payload: PairingPayload = codec::decode(&plaintext)?;
    plaintext.zeroize();
    Ok(PairingOpenResult {
        vault_key: payload.vault_key,
        account_id: payload.account_id.to_vec(),
        sas,
    })
}

/// Dérive la clé AEAD et le SAS depuis le secret partagé ECDH + le transcript
/// (`pk_new ‖ pk_src ‖ device_pk`, ordre fixe). Lier le transcript à la clé rend une
/// substitution de clé publique **ou** du `device_pk` (MITM) détectable : clé
/// différente → ouverture qui échoue, et SAS différent.
fn derive(
    shared: &[u8],
    pk_new: &[u8],
    pk_src: &[u8],
    device_pk: &[u8],
) -> Result<([u8; KEY_LEN], String)> {
    let hk = Hkdf::<Sha256>::new(None, shared);

    let mut aead_key = [0u8; KEY_LEN];
    hk.expand_multi_info(&[AEAD_INFO, pk_new, pk_src, device_pk], &mut aead_key)
        .map_err(|_| Error::Crypto("dérivation HKDF (pairing AEAD) échouée".into()))?;

    let mut sas_bytes = [0u8; 4];
    hk.expand_multi_info(&[SAS_INFO, pk_new, pk_src, device_pk], &mut sas_bytes)
        .map_err(|_| Error::Crypto("dérivation HKDF (pairing SAS) échouée".into()))?;

    Ok((aead_key, format_sas(&sas_bytes)))
}

/// Formate le SAS en **6 chiffres** (code court à comparer par l'utilisateur).
fn format_sas(bytes: &[u8; 4]) -> String {
    let value = u32::from_be_bytes(*bytes) % 1_000_000;
    format!("{value:06}")
}

/// Convertit une tranche en tableau de longueur fixe, en validant la longueur.
fn to_array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| Error::Crypto(format!("longueur {what} invalide (attendu {N} octets)")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE_PK: [u8; DEVICE_PK_LEN] = [3u8; DEVICE_PK_LEN];
    const ACCOUNT_ID: [u8; ACCOUNT_ID_LEN] = [7u8; ACCOUNT_ID_LEN];

    #[test]
    fn roundtrip_transfers_vault_key_and_account_with_matching_sas() {
        let vault_key = [42u8; KEY_LEN];
        let start = pairing_start(&DEVICE_PK).unwrap();
        let sealed = pairing_seal(&start.qr, &ACCOUNT_ID, &vault_key).unwrap();
        let opened = pairing_open(&start.state, &sealed.response).unwrap();

        assert_eq!(opened.vault_key, vault_key);
        assert_eq!(opened.account_id, ACCOUNT_ID);
        // Les deux appareils affichent le **même** SAS (6 chiffres).
        assert_eq!(sealed.sas, opened.sas);
        assert_eq!(opened.sas.len(), 6);
        assert!(opened.sas.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let vault_key = [7u8; KEY_LEN];
        let target = pairing_start(&DEVICE_PK).unwrap();
        let other = pairing_start(&DEVICE_PK).unwrap();
        let sealed = pairing_seal(&target.qr, &ACCOUNT_ID, &vault_key).unwrap();
        // Un autre appareil (autre secret éphémère) ne peut pas ouvrir le blob.
        assert!(pairing_open(&other.state, &sealed.response).is_err());
    }

    #[test]
    fn tampered_response_rejected() {
        let vault_key = [9u8; KEY_LEN];
        let start = pairing_start(&DEVICE_PK).unwrap();
        let sealed = pairing_seal(&start.qr, &ACCOUNT_ID, &vault_key).unwrap();
        let mut tampered = sealed.response.clone();
        *tampered.last_mut().unwrap() ^= 0xFF;
        assert!(pairing_open(&start.state, &tampered).is_err());
    }

    #[test]
    fn swapped_device_key_breaks_open() {
        let vault_key = [9u8; KEY_LEN];
        let start = pairing_start(&DEVICE_PK).unwrap();

        // MITM réécrit le device_pk du QR (conserve pairing_id + pk X25519).
        let mut request: PairingRequest = codec::decode(&start.qr).unwrap();
        request.device_public_key = [0xAAu8; DEVICE_PK_LEN];
        let tampered_qr = codec::encode(&request).unwrap();

        let sealed = pairing_seal(&tampered_qr, &ACCOUNT_ID, &vault_key).unwrap();
        // Le nouvel appareil dérive le transcript avec SON device_pk (via l'état) →
        // clé différente → ouverture impossible.
        assert!(pairing_open(&start.state, &sealed.response).is_err());
    }

    #[test]
    fn rejects_invalid_lengths() {
        assert!(pairing_start(&[0u8; 31]).is_err());
        let start = pairing_start(&DEVICE_PK).unwrap();
        assert!(pairing_seal(&start.qr, &[0u8; 15], &[1u8; KEY_LEN]).is_err());
    }
}
