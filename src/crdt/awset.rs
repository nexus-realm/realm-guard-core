//! OR-Set optimisé **add-wins** (delta-state) : gère l'appartenance d'éléments
//! (p. ex. quelles entrées existent dans le coffre).
//!
//! Chaque ajout crée un [`Dot`] frais associé à l'élément ; une suppression retire
//! les dots observés de l'élément (mais ils restent dans le contexte causal, pour
//! ne pas « ressusciter » l'élément à la re-livraison de l'ajout). Le join
//! (DotKernel) garde un dot `d` de l'élément `e` ssi :
//! `(d ∈ dots_self(e) ∨ d ∉ ctx_self) ∧ (d ∈ dots_other(e) ∨ d ∉ ctx_other)`.
//! Conséquence : un **ajout concurrent l'emporte** sur une suppression (add-wins),
//! et le join est idempotent / commutatif / associatif.

use std::collections::{BTreeMap, BTreeSet};

use super::DeviceId;
use super::dot::{Dot, DotContext};

/// Ensemble add-wins d'éléments `E`, répliquable sans coordination.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddWinsSet<E: Ord + Clone> {
    /// Éléments présents → dots des ajouts encore actifs (jamais vide).
    entries: BTreeMap<E, BTreeSet<Dot>>,
    /// Contexte causal (tous les dots observés).
    ctx: DotContext,
}

impl<E: Ord + Clone> Default for AddWinsSet<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Ord + Clone> AddWinsSet<E> {
    /// Ensemble vide.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            ctx: DotContext::new(),
        }
    }

    /// L'élément est-il présent ?
    pub fn contains(&self, e: &E) -> bool {
        self.entries.contains_key(e)
    }

    /// Itère les éléments présents.
    pub fn elements(&self) -> impl Iterator<Item = &E> {
        self.entries.keys()
    }

    /// Nombre d'éléments présents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// L'ensemble est-il vide ?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Contexte causal (pour les version vectors / la synchro).
    #[must_use]
    pub fn context(&self) -> &DotContext {
        &self.ctx
    }

    /// Ajoute (ou re-marque présent) `e` via un dot frais de `device`. Renvoie le
    /// **delta** à propager. Le delta porte, dans son contexte, les dots supersédés
    /// pour que sa fusion reproduise fidèlement le nouvel état.
    pub fn add(&mut self, e: E, device: DeviceId) -> Self {
        let dot = self.ctx.next_dot(device);
        let superseded = self.entries.get(&e).cloned().unwrap_or_default();

        let mut dots = BTreeSet::new();
        dots.insert(dot);
        self.entries.insert(e.clone(), dots.clone());

        let mut delta_ctx = DotContext::new();
        delta_ctx.insert(dot);
        for d in superseded {
            delta_ctx.insert(d);
        }
        let mut delta_entries = BTreeMap::new();
        delta_entries.insert(e, dots);
        Self {
            entries: delta_entries,
            ctx: delta_ctx,
        }
    }

    /// Retire `e`. Renvoie le **delta** (aucune entrée pour `e`, contexte = dots
    /// retirés → la fusion supprime `e` ailleurs sauf ré-ajout concurrent).
    pub fn remove(&mut self, e: &E) -> Self {
        let mut delta_ctx = DotContext::new();
        if let Some(dots) = self.entries.remove(e) {
            for dot in dots {
                delta_ctx.insert(dot);
            }
        }
        Self {
            entries: BTreeMap::new(),
            ctx: delta_ctx,
        }
    }

    /// Fusionne (join) un autre état — ou un delta. Idempotent / commutatif /
    /// associatif.
    pub fn merge(&mut self, other: &Self) {
        let keys: BTreeSet<E> = self
            .entries
            .keys()
            .chain(other.entries.keys())
            .cloned()
            .collect();
        let empty = BTreeSet::new();
        let mut merged = BTreeMap::new();
        for e in keys {
            let sd = self.entries.get(&e).unwrap_or(&empty);
            let od = other.entries.get(&e).unwrap_or(&empty);
            let mut kept = BTreeSet::new();
            for &d in sd.union(od) {
                let keep_self = sd.contains(&d) || !self.ctx.contains(&d);
                let keep_other = od.contains(&d) || !other.ctx.contains(&d);
                if keep_self && keep_other {
                    kept.insert(d);
                }
            }
            if !kept.is_empty() {
                merged.insert(e, kept);
            }
        }
        self.entries = merged;
        self.ctx.merge(&other.ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn dev(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    #[test]
    fn add_then_contains() {
        let mut s = AddWinsSet::new();
        assert!(!s.contains(&1u8));
        s.add(1u8, dev(1));
        assert!(s.contains(&1));
    }

    #[test]
    fn remove_makes_absent() {
        let mut s = AddWinsSet::new();
        s.add(1u8, dev(1));
        s.remove(&1);
        assert!(!s.contains(&1));
    }

    #[test]
    fn sequential_remove_wins() {
        // A ajoute ; B a observé l'ajout puis supprime → absent après fusion
        // (aucun ré-ajout concurrent).
        let mut a = AddWinsSet::new();
        a.add(1u8, dev(1));
        let mut b = a.clone();
        b.remove(&1);
        let mut merged = a.clone();
        merged.merge(&b);
        assert!(!merged.contains(&1));
    }

    #[test]
    fn readd_after_remove_is_present() {
        let mut s = AddWinsSet::new();
        s.add(1u8, dev(1));
        s.remove(&1);
        s.add(1u8, dev(1));
        assert!(s.contains(&1));
    }

    #[derive(Clone, Debug)]
    enum Op {
        Add(u8),
        Remove(u8),
    }

    fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(
            prop_oneof![(0u8..5).prop_map(Op::Add), (0u8..5).prop_map(Op::Remove)],
            0..12,
        )
    }

    fn apply_ops(device: DeviceId, ops: &[Op]) -> AddWinsSet<u8> {
        let mut s = AddWinsSet::new();
        for op in ops {
            match op {
                Op::Add(e) => {
                    s.add(*e, device);
                }
                Op::Remove(e) => {
                    s.remove(e);
                }
            }
        }
        s
    }

    proptest! {
        #[test]
        fn merge_idempotent(ops in ops_strategy()) {
            let s = apply_ops(dev(1), &ops);
            let mut m = s.clone();
            m.merge(&s);
            prop_assert_eq!(m, s);
        }

        #[test]
        fn merge_commutative(oa in ops_strategy(), ob in ops_strategy()) {
            // Appareils distincts : les dots ne se télescopent pas.
            let a = apply_ops(dev(1), &oa);
            let b = apply_ops(dev(2), &ob);
            let mut ab = a.clone();
            ab.merge(&b);
            let mut ba = b.clone();
            ba.merge(&a);
            prop_assert_eq!(ab, ba);
        }

        #[test]
        fn merge_associative(
            oa in ops_strategy(),
            ob in ops_strategy(),
            oc in ops_strategy(),
        ) {
            let a = apply_ops(dev(1), &oa);
            let b = apply_ops(dev(2), &ob);
            let c = apply_ops(dev(3), &oc);
            let mut left = a.clone();
            left.merge(&b);
            left.merge(&c);
            let mut bc = b.clone();
            bc.merge(&c);
            let mut right = a.clone();
            right.merge(&bc);
            prop_assert_eq!(left, right);
        }

        /// Trois répliques convergent quel que soit l'ordre des fusions.
        #[test]
        fn three_replicas_converge(
            oa in ops_strategy(),
            ob in ops_strategy(),
            oc in ops_strategy(),
        ) {
            let a = apply_ops(dev(1), &oa);
            let b = apply_ops(dev(2), &ob);
            let c = apply_ops(dev(3), &oc);
            let order1 = {
                let mut x = a.clone();
                x.merge(&b);
                x.merge(&c);
                x
            };
            let order2 = {
                let mut x = c.clone();
                x.merge(&a);
                x.merge(&b);
                x
            };
            let order3 = {
                let mut x = b.clone();
                x.merge(&c);
                x.merge(&a);
                x
            };
            prop_assert_eq!(&order1, &order2);
            prop_assert_eq!(&order2, &order3);
        }

        /// Un ajout concurrent l'emporte sur une suppression concurrente.
        #[test]
        fn concurrent_add_wins_over_remove(prefix in ops_strategy(), e in 0u8..5) {
            let base = apply_ops(dev(1), &prefix);
            let mut a = base.clone();
            a.add(e, dev(1)); // ré-ajout
            let mut b = base.clone();
            b.remove(&e); // suppression concurrente
            let mut merged = a.clone();
            merged.merge(&b);
            prop_assert!(merged.contains(&e));
        }

        /// Le delta d'un `add` reproduit fidèlement le nouvel état.
        #[test]
        fn add_delta_reproduces_state(ops in ops_strategy(), e in 0u8..5) {
            let mut s = apply_ops(dev(1), &ops);
            let before = s.clone();
            let delta = s.add(e, dev(1));
            let mut recon = before;
            recon.merge(&delta);
            prop_assert_eq!(recon, s);
        }

        /// Le delta d'un `remove` reproduit fidèlement le nouvel état.
        #[test]
        fn remove_delta_reproduces_state(ops in ops_strategy(), e in 0u8..5) {
            let mut s = apply_ops(dev(1), &ops);
            let before = s.clone();
            let delta = s.remove(&e);
            let mut recon = before;
            recon.merge(&delta);
            prop_assert_eq!(recon, s);
        }
    }
}
