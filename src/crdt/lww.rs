//! Registre Last-Writer-Wins : une valeur estampillée d'un [`Timestamp`].
//!
//! Le `merge` est le **join** de deux registres : on garde le plus grand couple
//! `(timestamp, valeur)`. Le [`Timestamp`] étant totalement ordonné (HLC puis
//! device), l'écriture la plus récente gagne ; à horodatage **strictement égal**
//! (même appareil + même HLC = même écriture logique), les valeurs sont égales
//! par construction. Départager malgré tout par la valeur rend le join
//! **total et déterministe sur tout l'espace d'états** : la convergence tient
//! même si un client hostile forge deux écritures au même horodatage — le serveur
//! n'est pas fiable (E2EE). Ce join est idempotent, commutatif et associatif.

use super::Timestamp;

/// Registre LWW : dernière valeur écrite, ordonnée par [`Timestamp`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LwwRegister<T> {
    value: T,
    ts: Timestamp,
}

impl<T> LwwRegister<T> {
    /// Crée un registre à partir d'une écriture (valeur + horodatage).
    pub fn new(value: T, ts: Timestamp) -> Self {
        Self { value, ts }
    }

    /// Valeur courante.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Horodatage de l'écriture courante.
    #[must_use]
    pub fn timestamp(&self) -> Timestamp {
        self.ts
    }

    /// Consomme le registre et renvoie la valeur.
    pub fn into_value(self) -> T {
        self.value
    }
}

impl<T: Ord + Clone> LwwRegister<T> {
    /// Écriture locale : applique `(value, ts)` s'il l'emporte sur l'actuel
    /// (règle LWW : `ts` plus grand gagne ; à `ts` égal, la plus grande valeur).
    /// Un `ts` issu d'un `tick` frais domine toujours l'actuel.
    pub fn set(&mut self, value: T, ts: Timestamp) {
        if (ts, &value) > (self.ts, &self.value) {
            self.value = value;
            self.ts = ts;
        }
    }

    /// Fusionne `other` dans `self` (join LWW). Idempotent / commutatif /
    /// associatif : l'état final ne dépend pas de l'ordre des merges.
    pub fn merge(&mut self, other: &Self) {
        if (other.ts, &other.value) > (self.ts, &self.value) {
            self.value = other.value.clone();
            self.ts = other.ts;
        }
    }

    /// Variante consommante de [`Self::merge`], pratique pour les folds.
    #[must_use]
    pub fn merged(mut self, other: &Self) -> Self {
        self.merge(other);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{DeviceId, Hlc};
    use proptest::prelude::*;

    fn ts(wall: u64, dev: u8) -> Timestamp {
        Timestamp::new(
            Hlc {
                wall_ms: wall,
                counter: 0,
            },
            DeviceId::from_bytes([dev; 16]),
        )
    }

    #[test]
    fn newer_timestamp_wins() {
        let mut r = LwwRegister::new(1, ts(10, 0));
        r.merge(&LwwRegister::new(2, ts(20, 0)));
        assert_eq!(*r.value(), 2);
        assert_eq!(r.timestamp(), ts(20, 0));
    }

    #[test]
    fn older_timestamp_ignored() {
        let mut r = LwwRegister::new(2, ts(20, 0));
        r.merge(&LwwRegister::new(1, ts(10, 0)));
        assert_eq!(*r.value(), 2);
    }

    #[test]
    fn equal_timestamp_breaks_by_value_deterministically() {
        let t = ts(10, 0);
        let mut a = LwwRegister::new(1, t);
        a.merge(&LwwRegister::new(2, t));
        let mut b = LwwRegister::new(2, t);
        b.merge(&LwwRegister::new(1, t));
        // Convergence malgré un horodatage forgé identique (robustesse byzantine).
        assert_eq!(a, b);
        assert_eq!(*a.value(), 2);
    }

    #[test]
    fn set_respects_lww() {
        let mut r = LwwRegister::new(1, ts(10, 0));
        r.set(9, ts(5, 0)); // plus ancien → ignoré
        assert_eq!(*r.value(), 1);
        r.set(3, ts(20, 0)); // plus récent → appliqué
        assert_eq!(*r.value(), 3);
    }

    // Petits domaines → collisions d'horodatage fréquentes → exerce le tiebreak.
    fn ts_strategy() -> impl Strategy<Value = Timestamp> {
        (0u64..8, 0u32..4, 0u8..3).prop_map(|(wall, counter, dev)| {
            Timestamp::new(
                Hlc {
                    wall_ms: wall,
                    counter,
                },
                DeviceId::from_bytes([dev; 16]),
            )
        })
    }

    fn reg_strategy() -> impl Strategy<Value = LwwRegister<i32>> {
        (any::<i32>(), ts_strategy()).prop_map(|(v, ts)| LwwRegister::new(v, ts))
    }

    proptest! {
        #[test]
        fn idempotent(r in reg_strategy()) {
            let mut m = r.clone();
            m.merge(&r);
            prop_assert_eq!(m, r);
        }

        #[test]
        fn commutative(a in reg_strategy(), b in reg_strategy()) {
            let mut ab = a.clone();
            ab.merge(&b);
            let mut ba = b.clone();
            ba.merge(&a);
            prop_assert_eq!(ab, ba);
        }

        #[test]
        fn associative(a in reg_strategy(), b in reg_strategy(), c in reg_strategy()) {
            let mut abc = a.clone();
            abc.merge(&b);
            abc.merge(&c);
            let mut bc = b.clone();
            bc.merge(&c);
            let mut a_bc = a.clone();
            a_bc.merge(&bc);
            prop_assert_eq!(abc, a_bc);
        }

        /// Convergence quel que soit l'ordre + recoupement avec la spec
        /// (gagnant = max par `(timestamp, valeur)`).
        #[test]
        fn converges_regardless_of_order(regs in prop::collection::vec(reg_strategy(), 1..12)) {
            let fold = |order: &[LwwRegister<i32>]| {
                let mut acc = order[0].clone();
                for r in &order[1..] {
                    acc.merge(r);
                }
                acc
            };
            let forward = fold(&regs);
            let mut reversed = regs.clone();
            reversed.reverse();
            let backward = fold(&reversed);
            prop_assert_eq!(&forward, &backward);

            let winner = regs
                .iter()
                .max_by(|x, y| (x.timestamp(), x.value()).cmp(&(y.timestamp(), y.value())))
                .unwrap();
            prop_assert_eq!(forward.value(), winner.value());
            prop_assert_eq!(forward.timestamp(), winner.timestamp());
        }
    }
}
