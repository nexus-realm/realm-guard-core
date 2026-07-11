//! Authentification **OPAQUE** (aPAKE zero-knowledge) — le serveur authentifie le
//! client par mot de passe **sans jamais l'apprendre**, ni le stocker sous une
//! forme réversible.
//!
//! Rôle dans l'architecture : OPAQUE gère **l'authentification serveur uniquement**.
//! Le déchiffrement du coffre reste **local** (Argon2id → KEK → VaultKey, hors-ligne,
//! cf. [`crate::crypto`]) — même mot de passe, deux dérivations indépendantes.
//!
//! Primitives (via `opaque-ke`, implémentation auditée de Meta ; aucune crypto
//! maison) : OPRF/KE sur **Ristretto255**, échange **3DH**, hash **SHA-512**, KSF
//! **Argon2id**. Les fonctions opèrent sur des **octets sérialisés** (format wire
//! canonique d'opaque-ke) pour le serveur et le pont FFI.
//!
//! Chaque connexion réussie produit une `session_key` **mutuelle** (client = serveur)
//! et une `export_key` **côté client** stable (dérivée du mot de passe ; servira à
//! protéger la VaultKey enrobée côté serveur en P1.4).

use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Choix de primitives OPAQUE (constant client ↔ serveur).
///
/// KSF = `Argon2` (feature `argon2`) — **params par défaut** de la crate argon2
/// (m = 19 MiB, t = 2). Le renforcement (m = 64 MiB, t = 3, via un KSF newtype)
/// est un point de la revue sécurité P1.
struct RealmCipherSuite;

impl CipherSuite for RealmCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

/// Clé exportée par OPAQUE côté client (stable pour un mot de passe donné). Secrète.
pub struct ExportKey(Zeroizing<Vec<u8>>);

/// Clé de session mutuelle établie à la connexion. Secrète.
pub struct SessionKey(Zeroizing<Vec<u8>>);

impl ExportKey {
    /// Les octets de la clé.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SessionKey {
    /// Les octets de la clé.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Résultat du démarrage d'enregistrement côté client.
pub struct ClientRegistrationStart {
    /// État à conserver côté client jusqu'au `finish`.
    pub state: Vec<u8>,
    /// `RegistrationRequest` à envoyer au serveur.
    pub request: Vec<u8>,
}

/// Résultat de la finalisation d'enregistrement côté client.
pub struct ClientRegistrationFinish {
    /// `RegistrationUpload` à envoyer au serveur (≈ sensibilité d'un hash de mdp).
    pub upload: Vec<u8>,
    /// Clé exportée (côté client).
    pub export_key: ExportKey,
}

/// Résultat du démarrage de connexion côté client.
pub struct ClientLoginStart {
    /// État à conserver côté client jusqu'au `finish`.
    pub state: Vec<u8>,
    /// `CredentialRequest` à envoyer au serveur.
    pub request: Vec<u8>,
}

/// Résultat du démarrage de connexion côté serveur.
pub struct ServerLoginStart {
    /// État à conserver côté serveur jusqu'au `finish`.
    pub state: Vec<u8>,
    /// `CredentialResponse` à renvoyer au client.
    pub response: Vec<u8>,
}

/// Résultat de la finalisation de connexion côté client.
pub struct ClientLoginFinish {
    /// `CredentialFinalization` à envoyer au serveur.
    pub finalization: Vec<u8>,
    /// Clé de session mutuelle.
    pub session_key: SessionKey,
    /// Clé exportée (côté client, stable).
    pub export_key: ExportKey,
}

/// Génère un `ServerSetup` (secret serveur : graine OPRF + clé). À **persister**
/// côté serveur ; renvoyé sérialisé.
#[must_use]
pub fn generate_server_setup() -> Vec<u8> {
    let mut rng = OsRng;
    ServerSetup::<RealmCipherSuite>::new(&mut rng)
        .serialize()
        .to_vec()
}

fn load_server_setup(bytes: &[u8]) -> Result<ServerSetup<RealmCipherSuite>> {
    ServerSetup::deserialize(bytes).map_err(|_| Error::Auth("server setup invalide".into()))
}

/// **Client** — démarre l'enregistrement à partir du mot de passe.
///
/// # Errors
/// Échec interne d'OPAQUE.
pub fn client_register_start(password: &[u8]) -> Result<ClientRegistrationStart> {
    let mut rng = OsRng;
    let result = ClientRegistration::<RealmCipherSuite>::start(&mut rng, password)
        .map_err(|_| Error::Auth("register start (client)".into()))?;
    Ok(ClientRegistrationStart {
        state: result.state.serialize().to_vec(),
        request: result.message.serialize().to_vec(),
    })
}

/// **Serveur** — répond au `RegistrationRequest` pour l'identifiant `username`.
///
/// # Errors
/// `server_setup` ou `request` invalide.
pub fn server_register_start(
    server_setup: &[u8],
    request: &[u8],
    username: &[u8],
) -> Result<Vec<u8>> {
    let setup = load_server_setup(server_setup)?;
    let request = RegistrationRequest::deserialize(request)
        .map_err(|_| Error::Auth("registration request invalide".into()))?;
    let result = ServerRegistration::<RealmCipherSuite>::start(&setup, request, username)
        .map_err(|_| Error::Auth("register start (serveur)".into()))?;
    Ok(result.message.serialize().to_vec())
}

/// **Client** — finalise l'enregistrement ; renvoie l'upload et l'`export_key`.
///
/// # Errors
/// État ou `response` invalide.
pub fn client_register_finish(
    state: &[u8],
    password: &[u8],
    response: &[u8],
) -> Result<ClientRegistrationFinish> {
    let mut rng = OsRng;
    let state = ClientRegistration::<RealmCipherSuite>::deserialize(state)
        .map_err(|_| Error::Auth("état d'enregistrement invalide".into()))?;
    let response = RegistrationResponse::deserialize(response)
        .map_err(|_| Error::Auth("registration response invalide".into()))?;
    let result = state
        .finish(
            &mut rng,
            password,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| Error::Auth("register finish (client)".into()))?;
    Ok(ClientRegistrationFinish {
        upload: result.message.serialize().to_vec(),
        export_key: ExportKey(Zeroizing::new(result.export_key.to_vec())),
    })
}

/// **Serveur** — transforme l'upload en **password file** (à stocker par compte).
///
/// # Errors
/// `upload` invalide.
pub fn server_register_finish(upload: &[u8]) -> Result<Vec<u8>> {
    let upload = RegistrationUpload::<RealmCipherSuite>::deserialize(upload)
        .map_err(|_| Error::Auth("registration upload invalide".into()))?;
    Ok(ServerRegistration::<RealmCipherSuite>::finish(upload)
        .serialize()
        .to_vec())
}

/// **Client** — démarre la connexion à partir du mot de passe.
///
/// # Errors
/// Échec interne d'OPAQUE.
pub fn client_login_start(password: &[u8]) -> Result<ClientLoginStart> {
    let mut rng = OsRng;
    let result = ClientLogin::<RealmCipherSuite>::start(&mut rng, password)
        .map_err(|_| Error::Auth("login start (client)".into()))?;
    Ok(ClientLoginStart {
        state: result.state.serialize().to_vec(),
        request: result.message.serialize().to_vec(),
    })
}

/// **Serveur** — répond au `CredentialRequest`. `password_file` = `None` pour un
/// utilisateur **inconnu** → opaque-ke fabrique une réponse indistinguable d'un
/// vrai compte (**résistance à l'énumération** : le client échouera au `finish`).
///
/// # Errors
/// `server_setup`, `password_file` ou `request` invalide.
pub fn server_login_start(
    server_setup: &[u8],
    password_file: Option<&[u8]>,
    request: &[u8],
    username: &[u8],
) -> Result<ServerLoginStart> {
    let mut rng = OsRng;
    let setup = load_server_setup(server_setup)?;
    let password_file = match password_file {
        Some(bytes) => Some(
            ServerRegistration::<RealmCipherSuite>::deserialize(bytes)
                .map_err(|_| Error::Auth("password file invalide".into()))?,
        ),
        None => None,
    };
    let request = CredentialRequest::deserialize(request)
        .map_err(|_| Error::Auth("credential request invalide".into()))?;
    let result = ServerLogin::start(
        &mut rng,
        &setup,
        password_file,
        request,
        username,
        ServerLoginParameters::default(),
    )
    .map_err(|_| Error::Auth("login start (serveur)".into()))?;
    Ok(ServerLoginStart {
        state: result.state.serialize().to_vec(),
        response: result.message.serialize().to_vec(),
    })
}

/// **Client** — finalise la connexion. **Échoue si le mot de passe est faux**
/// (l'enveloppe ne se déchiffre pas). Renvoie `session_key` + `export_key`.
///
/// # Errors
/// Mot de passe invalide, ou état/`response` invalide.
pub fn client_login_finish(
    state: &[u8],
    password: &[u8],
    response: &[u8],
) -> Result<ClientLoginFinish> {
    let mut rng = OsRng;
    let state = ClientLogin::<RealmCipherSuite>::deserialize(state)
        .map_err(|_| Error::Auth("état de connexion invalide".into()))?;
    let response = CredentialResponse::deserialize(response)
        .map_err(|_| Error::Auth("credential response invalide".into()))?;
    let result = state
        .finish(
            &mut rng,
            password,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| Error::Auth("mot de passe invalide".into()))?;
    Ok(ClientLoginFinish {
        finalization: result.message.serialize().to_vec(),
        session_key: SessionKey(Zeroizing::new(result.session_key.to_vec())),
        export_key: ExportKey(Zeroizing::new(result.export_key.to_vec())),
    })
}

/// **Serveur** — finalise la connexion et renvoie la `session_key` (doit égaler
/// celle du client si l'authentification a réussi).
///
/// # Errors
/// État ou `finalization` invalide.
pub fn server_login_finish(state: &[u8], finalization: &[u8]) -> Result<SessionKey> {
    let state = ServerLogin::<RealmCipherSuite>::deserialize(state)
        .map_err(|_| Error::Auth("état de connexion serveur invalide".into()))?;
    let finalization = CredentialFinalization::deserialize(finalization)
        .map_err(|_| Error::Auth("credential finalization invalide".into()))?;
    let result = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|_| Error::Auth("login finish (serveur)".into()))?;
    Ok(SessionKey(Zeroizing::new(result.session_key.to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &[u8] = b"alice@example.test";
    const PASSWORD: &[u8] = b"correct horse battery staple";

    // Déroule l'enregistrement complet, renvoie (password_file, export_key client).
    fn register(server_setup: &[u8], username: &[u8], password: &[u8]) -> (Vec<u8>, ExportKey) {
        let c_start = client_register_start(password).unwrap();
        let response = server_register_start(server_setup, &c_start.request, username).unwrap();
        let c_finish = client_register_finish(&c_start.state, password, &response).unwrap();
        let password_file = server_register_finish(&c_finish.upload).unwrap();
        (password_file, c_finish.export_key)
    }

    #[test]
    fn register_then_login_yields_matching_session_keys() {
        let server_setup = generate_server_setup();
        let (password_file, reg_export) = register(&server_setup, USER, PASSWORD);

        let cl_start = client_login_start(PASSWORD).unwrap();
        let sl_start =
            server_login_start(&server_setup, Some(&password_file), &cl_start.request, USER)
                .unwrap();
        let cl_finish = client_login_finish(&cl_start.state, PASSWORD, &sl_start.response).unwrap();
        let server_session = server_login_finish(&sl_start.state, &cl_finish.finalization).unwrap();

        // Authentification mutuelle : mêmes clés de session des deux côtés.
        assert_eq!(cl_finish.session_key.as_bytes(), server_session.as_bytes());
        assert!(!cl_finish.session_key.as_bytes().is_empty());
        // L'export_key est stable entre enregistrement et connexion.
        assert_eq!(reg_export.as_bytes(), cl_finish.export_key.as_bytes());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let server_setup = generate_server_setup();
        let (password_file, _) = register(&server_setup, USER, b"le-bon-mot-de-passe");

        let cl_start = client_login_start(b"mauvais-mot-de-passe").unwrap();
        let sl_start =
            server_login_start(&server_setup, Some(&password_file), &cl_start.request, USER)
                .unwrap();
        // Le client détecte l'échec : l'enveloppe ne se déchiffre pas.
        let result =
            client_login_finish(&cl_start.state, b"mauvais-mot-de-passe", &sl_start.response);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_user_login_is_indistinguishable() {
        let server_setup = generate_server_setup();
        // Aucun compte enregistré : le serveur répond quand même (password_file = None).
        let cl_start = client_login_start(PASSWORD).unwrap();
        let sl_start =
            server_login_start(&server_setup, None, &cl_start.request, b"inconnu").unwrap();
        // Le client ne peut pas finaliser (enveloppe fabriquée) → échec côté client.
        let result = client_login_finish(&cl_start.state, PASSWORD, &sl_start.response);
        assert!(result.is_err());
    }

    #[test]
    fn password_never_appears_in_wire_messages() {
        let server_setup = generate_server_setup();
        let password = b"un-secret-tres-reconnaissable-12345";
        let c_start = client_register_start(password).unwrap();
        let response = server_register_start(&server_setup, &c_start.request, USER).unwrap();

        // Le mot de passe en clair ne transite jamais (zero-knowledge).
        let contains = |haystack: &[u8]| {
            haystack
                .windows(password.len())
                .any(|window| window == password)
        };
        assert!(!contains(&c_start.request));
        assert!(!contains(&response));
    }
}
