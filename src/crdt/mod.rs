//! CRDT delta-state custom (lot P0.3) : convergence sans coordination.
//!
//! Primitives : [`Hlc`] (horloge logique hybride) + [`DeviceId`] → [`Timestamp`]
//! total-ordonné (P0.3a) ; `LwwRegister<T>` (P0.3b) ; `AddWinsSet` (P0.3c) ;
//! document coffre + deltas + version vectors (P0.3d).
//!
//! Correctness validée par tests property-based (commutativité, associativité,
//! idempotence, convergence quel que soit l'ordre des deltas).

mod hlc;
mod lww;

pub use hlc::{Hlc, HlcClock};
pub use lww::LwwRegister;

use crate::error::{Error, Result};

/// Identifiant stable d'un appareil (16 octets). Sert de **tiebreak déterministe**
/// dans l'ordre total des [`Timestamp`]. Non secret.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
    /// Construit un identifiant depuis 16 octets.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Les 16 octets de l'identifiant.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Génère un identifiant aléatoire via le CSPRNG de l'OS.
    ///
    /// # Errors
    /// Échec du générateur aléatoire de l'OS.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|e| Error::Crdt(format!("CSPRNG : {e}")))?;
        Ok(Self(bytes))
    }
}

/// Horodatage total-ordonné d'une écriture : [`Hlc`] puis [`DeviceId`] (tiebreak).
/// L'ordre lexicographique `(hlc, device)` départage **déterministement** deux
/// écritures concurrentes portant le même HLC.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Timestamp {
    /// Horloge logique hybride de l'écriture.
    pub hlc: Hlc,
    /// Appareil auteur (départage les HLC égaux).
    pub device: DeviceId,
}

impl Timestamp {
    /// Assemble un horodatage.
    #[must_use]
    pub fn new(hlc: Hlc, device: DeviceId) -> Self {
        Self { hlc, device }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    #[test]
    fn device_id_roundtrip() {
        let bytes = [3u8; 16];
        assert_eq!(DeviceId::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn generate_is_random() {
        let a = DeviceId::generate().unwrap();
        let b = DeviceId::generate().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn timestamp_orders_by_hlc_first() {
        // HLC domine même quand le device est plus petit.
        let lo = Timestamp::new(
            Hlc {
                wall_ms: 10,
                counter: 0,
            },
            dev(9),
        );
        let hi = Timestamp::new(
            Hlc {
                wall_ms: 20,
                counter: 0,
            },
            dev(1),
        );
        assert!(hi > lo);
    }

    #[test]
    fn timestamp_device_breaks_hlc_tie() {
        let hlc = Hlc {
            wall_ms: 10,
            counter: 2,
        };
        let a = Timestamp::new(hlc, dev(1));
        let b = Timestamp::new(hlc, dev(2));
        assert!(b > a);
        assert_ne!(a, b);
    }
}
