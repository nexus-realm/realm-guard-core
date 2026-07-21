//! Pairing d'appareil : transfert **E2E** de la VaultKey d'un appareil source
//! (déjà déverrouillé) vers un nouvel appareil, via un canal authentifié par QR +
//! SAS. Le serveur ne relaie que des **blobs opaques** ; la VaultKey ne lui est
//! jamais exposée (ni au serveur, ni enrobée par une clé qu'il connaît).
//!
//! # Protocole en **deux tours**
//!
//! 1. le **nouvel appareil** génère une paire éphémère X25519 et affiche
//!    `{pairing_id, pk_new, device_pk}` en QR ([`pairing_start`]) — `device_pk` est sa
//!    **clé d'identité d'appareil** (Ed25519, opaque ici), destinée au registre du
//!    compte ;
//! 2. **tour 1** — la source scanne et publie sa **seule clé publique éphémère**
//!    ([`pairing_source_begin`] → `hello`). Les deux côtés dérivent alors le SAS
//!    ([`pairing_new_device_confirm`]) et l'affichent. **Aucun secret n'a circulé** ;
//! 3. **tour 2** — *uniquement après* que l'utilisateur a confirmé que les deux SAS
//!    correspondent, la source scelle `{account_id, vault_key}`
//!    ([`pairing_source_seal`]) ; le nouvel appareil ouvre ([`pairing_open`]).
//!
//! # Pourquoi deux tours
//!
//! Les deux côtés dérivent, du **même** secret partagé + transcript
//! (`pk_new ‖ pk_src ‖ device_pk`), la clé AEAD **et** le SAS. Toute substitution
//! (MITM) change le transcript → les SAS **divergent**. En un seul tour, la source
//! aurait déjà envoyé la VaultKey au moment où l'utilisateur s'en aperçoit : le SAS
//! ne ferait que **détecter**. En scindant, la clé ne part **qu'après** confirmation
//! → le SAS **empêche**.
//!
//! Aucune crypto maison : X25519 (dalek), HKDF-SHA256, AEAD partagé du cœur.

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
/// transcript et acheminée jusqu'à l'inscription au registre.
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

/// État conservé par le nouvel appareil entre l'affichage du QR et le tour 1.
/// **Contient le secret éphémère** ; sensible et éphémère.
#[derive(Serialize, Deserialize)]
struct PairingState {
    secret: [u8; X25519_LEN],
    pairing_id: [u8; PAIRING_ID_LEN],
    device_public_key: [u8; DEVICE_PK_LEN],
}

/// **Tour 1** relayé : la source publie sa clé publique éphémère. Aucun secret.
#[derive(Serialize, Deserialize)]
struct PairingHello {
    source_public: [u8; X25519_LEN],
}

/// État conservé **entre les deux tours**, des deux côtés. **Contient la clé AEAD
/// dérivée** : sensible, éphémère, jamais persisté.
#[derive(Serialize, Deserialize)]
struct PairingSessionState {
    aead_key: [u8; KEY_LEN],
}

/// Contenu chiffré transféré au tour 2.
#[derive(Serialize, Deserialize)]
struct PairingPayload {
    account_id: [u8; ACCOUNT_ID_LEN],
    vault_key: Vec<u8>,
}

/// Résultat du démarrage côté **nouvel appareil**.
pub struct PairingStart {
    /// État à conserver (contient le secret éphémère) jusqu'au tour 1.
    pub state: Vec<u8>,
    /// Payload QR à afficher (`{pairing_id, pk, device_pk}`, sérialisé).
    pub qr: Vec<u8>,
}

/// Résultat du **tour 1** côté source.
pub struct PairingSourceBegin {
    /// État à conserver jusqu'au scellage (contient la clé AEAD dérivée).
    pub state: Vec<u8>,
    /// Tour 1 à relayer au nouvel appareil (clé publique éphémère seule).
    pub hello: Vec<u8>,
    /// SAS à afficher. **Ne sceller qu'après** confirmation par l'utilisateur.
    pub sas: String,
    /// Clé d'identité du nouvel appareil, **extraite du QR** (donc liée au
    /// transcript). À inscrire au registre du compte, elle aussi **uniquement après**
    /// confirmation du SAS : sur un QR substitué, ce serait la clé de l'attaquant.
    pub device_public_key: Vec<u8>,
}

/// Résultat du **tour 1** côté nouvel appareil.
pub struct PairingConfirm {
    /// État à conserver jusqu'à l'ouverture (contient la clé AEAD dérivée).
    pub state: Vec<u8>,
    /// SAS à afficher (doit correspondre à celui de la source).
    pub sas: String,
}

/// Résultat de l'ouverture (**tour 2**) côté nouvel appareil.
pub struct PairingOpenResult {
    /// VaultKey reçue (octets).
    pub vault_key: Vec<u8>,
    /// Identifiant (UUID) du compte que le nouvel appareil rejoint.
    pub account_id: Vec<u8>,
}

/// **Nouvel appareil** — démarre le pairing : génère une paire éphémère X25519 + un
/// `pairing_id` aléatoire, et incorpore sa clé d'identité `device_public_key`
/// (Ed25519) au QR et à l'état.
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

/// **Appareil source, tour 1** — scanne le QR, fait l'ECDH et dérive le SAS. Publie
/// sa **seule clé publique** : aucun secret ne circule à ce stade. La VaultKey n'est
/// scellée qu'ensuite, par [`pairing_source_seal`], **après confirmation du SAS**.
///
/// # Errors
/// QR invalide, échec du CSPRNG ou de la dérivation.
pub fn pairing_source_begin(qr: &[u8]) -> Result<PairingSourceBegin> {
    let request: PairingRequest = codec::decode(qr)?;
    let their_public = PublicKey::from(request.public_key);

    let mut secret_bytes = [0u8; X25519_LEN];
    getrandom::getrandom(&mut secret_bytes).map_err(|e| Error::Crypto(format!("CSPRNG : {e}")))?;
    let secret = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();
    let source_public = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&their_public);

    let (aead_key, sas) = derive(
        shared.as_bytes(),
        &request.public_key,
        &source_public,
        &request.device_public_key,
    )?;

    let mut state = PairingSessionState { aead_key };
    let encoded_state = codec::encode(&state)?;
    state.aead_key.zeroize();

    let hello = codec::encode(&PairingHello { source_public })?;
    Ok(PairingSourceBegin {
        state: encoded_state,
        hello,
        sas,
        device_public_key: request.device_public_key.to_vec(),
    })
}

/// **Nouvel appareil, tour 1** — reçoit la clé publique de la source, dérive le SAS
/// et l'état de session. Le SAS doit être **comparé** avec celui de la source avant
/// que celle-ci n'envoie quoi que ce soit.
///
/// # Errors
/// État ou `hello` invalide, échec de la dérivation.
pub fn pairing_new_device_confirm(state: &[u8], hello: &[u8]) -> Result<PairingConfirm> {
    let mut state: PairingState = codec::decode(state)?;
    let hello: PairingHello = codec::decode(hello)?;

    let secret = StaticSecret::from(state.secret);
    let our_public = PublicKey::from(&secret).to_bytes();
    let their_public = PublicKey::from(hello.source_public);
    let shared = secret.diffie_hellman(&their_public);

    let derived = derive(
        shared.as_bytes(),
        &our_public,
        &hello.source_public,
        &state.device_public_key,
    );
    state.secret.zeroize();
    let (aead_key, sas) = derived?;

    let mut session = PairingSessionState { aead_key };
    let encoded = codec::encode(&session)?;
    session.aead_key.zeroize();
    Ok(PairingConfirm {
        state: encoded,
        sas,
    })
}

/// **Appareil source, tour 2** — scelle `{account_id, vault_key}` avec l'état issu du
/// tour 1.
///
/// # Errors
/// `account_id` de longueur invalide, état invalide, ou échec du chiffrement.
///
/// # Sécurité
/// **N'appeler qu'après** que l'utilisateur a confirmé que les deux SAS
/// correspondent : c'est précisément ce qui empêche un MITM d'obtenir la VaultKey.
pub fn pairing_source_seal(state: &[u8], account_id: &[u8], vault_key: &[u8]) -> Result<Vec<u8>> {
    let account = to_array::<ACCOUNT_ID_LEN>(account_id, "account_id")?;
    let mut session: PairingSessionState = codec::decode(state)?;

    let mut payload = PairingPayload {
        account_id: account,
        vault_key: vault_key.to_vec(),
    };
    let mut plaintext = codec::encode(&payload)?;
    let ciphertext = seal(&session.aead_key, &plaintext);
    session.aead_key.zeroize();
    plaintext.zeroize();
    payload.vault_key.zeroize();

    codec::encode(&ciphertext?)
}

/// **Nouvel appareil, tour 2** — ouvre le blob scellé avec l'état issu du tour 1.
/// **Échoue** si le blob ne s'ouvre pas (mauvais destinataire, ou altération).
///
/// # Errors
/// État ou blob invalide, mauvaise clé, ou texte chiffré altéré.
pub fn pairing_open(state: &[u8], sealed: &[u8]) -> Result<PairingOpenResult> {
    let mut session: PairingSessionState = codec::decode(state)?;
    let ciphertext: Ciphertext = codec::decode(sealed)?;

    let result = open(&session.aead_key, &ciphertext);
    session.aead_key.zeroize();

    let mut plaintext = result?;
    let payload: PairingPayload = codec::decode(&plaintext)?;
    plaintext.zeroize();
    Ok(PairingOpenResult {
        vault_key: payload.vault_key,
        account_id: payload.account_id.to_vec(),
    })
}

/// Dérive la clé AEAD et le SAS depuis le secret partagé ECDH + le transcript
/// (`pk_new ‖ pk_src ‖ device_pk`, ordre fixe). Lier le transcript à la clé rend une
/// substitution de clé publique **ou** du `device_pk` (MITM) détectable : clé
/// différente → ouverture qui échoue, et SAS différent → l'utilisateur ne confirme
/// pas, donc rien n'est envoyé.
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
    fn two_round_roundtrip_matches_sas_and_transfers_vault_key() {
        let vault_key = [42u8; KEY_LEN];

        let start = pairing_start(&DEVICE_PK).unwrap();
        // Tour 1 : la source publie sa clé publique, les deux dérivent le SAS.
        let begin = pairing_source_begin(&start.qr).unwrap();
        let confirm = pairing_new_device_confirm(&start.state, &begin.hello).unwrap();

        assert_eq!(begin.sas, confirm.sas);
        assert_eq!(begin.sas.len(), 6);
        assert!(begin.sas.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(begin.device_public_key, DEVICE_PK);

        // Tour 2 : après confirmation seulement.
        let sealed = pairing_source_seal(&begin.state, &ACCOUNT_ID, &vault_key).unwrap();
        let opened = pairing_open(&confirm.state, &sealed).unwrap();

        assert_eq!(opened.vault_key, vault_key);
        assert_eq!(opened.account_id, ACCOUNT_ID);
    }

    #[test]
    fn hello_carries_no_secret() {
        let vault_key = [42u8; KEY_LEN];
        let start = pairing_start(&DEVICE_PK).unwrap();
        let begin = pairing_source_begin(&start.qr).unwrap();

        // Le tour 1 ne contient que la clé publique : ni VaultKey, ni account_id, ni
        // clé AEAD. C'est **la** propriété qui rend le SAS préventif.
        let hello: PairingHello = codec::decode(&begin.hello).unwrap();
        assert_eq!(begin.hello.len(), X25519_LEN);
        assert!(!begin.hello.windows(4).any(|w| w == &vault_key[..4]));
        assert_ne!(hello.source_public, [0u8; X25519_LEN]);
    }

    #[test]
    fn swapped_device_key_diverges_sas_before_anything_is_sent() {
        let start = pairing_start(&DEVICE_PK).unwrap();

        // MITM réécrit le device_pk du QR (conserve pairing_id + pk X25519).
        let mut request: PairingRequest = codec::decode(&start.qr).unwrap();
        request.device_public_key = [0xAAu8; DEVICE_PK_LEN];
        let tampered_qr = codec::encode(&request).unwrap();

        let begin = pairing_source_begin(&tampered_qr).unwrap();
        let confirm = pairing_new_device_confirm(&start.state, &begin.hello).unwrap();

        // Les SAS divergent → l'utilisateur ne confirme pas → la source n'appelle
        // jamais `pairing_source_seal` : la VaultKey n'a **jamais** circulé.
        assert_ne!(begin.sas, confirm.sas);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let vault_key = [7u8; KEY_LEN];
        let target = pairing_start(&DEVICE_PK).unwrap();
        let other = pairing_start(&DEVICE_PK).unwrap();

        let begin = pairing_source_begin(&target.qr).unwrap();
        let other_confirm = pairing_new_device_confirm(&other.state, &begin.hello).unwrap();
        let sealed = pairing_source_seal(&begin.state, &ACCOUNT_ID, &vault_key).unwrap();

        // Autre secret éphémère → autre clé AEAD → ouverture impossible.
        assert!(pairing_open(&other_confirm.state, &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let vault_key = [9u8; KEY_LEN];
        let start = pairing_start(&DEVICE_PK).unwrap();
        let begin = pairing_source_begin(&start.qr).unwrap();
        let confirm = pairing_new_device_confirm(&start.state, &begin.hello).unwrap();

        let mut sealed = pairing_source_seal(&begin.state, &ACCOUNT_ID, &vault_key).unwrap();
        *sealed.last_mut().unwrap() ^= 0xFF;

        assert!(pairing_open(&confirm.state, &sealed).is_err());
    }

    #[test]
    fn rejects_invalid_lengths() {
        assert!(pairing_start(&[0u8; 31]).is_err());
        let start = pairing_start(&DEVICE_PK).unwrap();
        let begin = pairing_source_begin(&start.qr).unwrap();
        assert!(pairing_source_seal(&begin.state, &[0u8; 15], &[1u8; KEY_LEN]).is_err());
    }
}
