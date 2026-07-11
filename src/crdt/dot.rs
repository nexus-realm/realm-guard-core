//! Dots et contexte causal — briques de l'OR-Set ([`super::awset`]).
//!
//! Un [`Dot`] `(device, counter)` étiquette **chaque** ajout de façon globalement
//! unique (un appareil n'incrémente que son propre compteur). Le [`DotContext`]
//! mémorise l'ensemble des dots observés, sous forme **compacte** : un préfixe
//! contigu par appareil (version vector `cc`) plus un « nuage » `dc` des dots vus
//! hors de ce préfixe (à cause de trous). La compaction absorbe le nuage dès que
//! le préfixe redevient contigu, gardant le contexte en O(appareils) et non en
//! O(opérations).

use std::collections::{BTreeMap, BTreeSet};

use super::DeviceId;

/// Étiquette unique d'un ajout : appareil + compteur monotone propre à l'appareil.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Dot {
    /// Appareil auteur de l'ajout.
    pub device: DeviceId,
    /// Compteur monotone (≥ 1) propre à `device`.
    pub counter: u64,
}

impl Dot {
    /// Construit un dot.
    #[must_use]
    pub fn new(device: DeviceId, counter: u64) -> Self {
        Self { device, counter }
    }
}

/// Contexte causal compact : ensemble des dots observés.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct DotContext {
    /// Version vector : plus grand compteur **contigu** observé par appareil.
    cc: BTreeMap<DeviceId, u64>,
    /// Nuage : dots observés hors du préfixe contigu (trous en dessous).
    dc: BTreeSet<Dot>,
}

impl DotContext {
    /// Contexte vide.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Le contexte a-t-il observé ce dot ?
    #[must_use]
    pub fn contains(&self, dot: &Dot) -> bool {
        self.cc.get(&dot.device).is_some_and(|&n| dot.counter <= n) || self.dc.contains(dot)
    }

    /// Génère le prochain dot frais pour `device` (compteur = max observé + 1) et
    /// l'enregistre dans le contexte.
    pub fn next_dot(&mut self, device: DeviceId) -> Dot {
        let base = self.cc.get(&device).copied().unwrap_or(0);
        let max_cloud = self
            .dc
            .iter()
            .filter(|d| d.device == device)
            .map(|d| d.counter)
            .max()
            .unwrap_or(0);
        let dot = Dot::new(device, base.max(max_cloud) + 1);
        self.insert(dot);
        dot
    }

    /// Enregistre un dot déjà connu ou reçu, puis compacte.
    pub fn insert(&mut self, dot: Dot) {
        if self.contains(&dot) {
            return;
        }
        self.dc.insert(dot);
        self.compact_device(dot.device);
    }

    /// Absorbe dans `cc` le plus long préfixe contigu de `dc` pour `device`.
    fn compact_device(&mut self, device: DeviceId) {
        let mut n = self.cc.get(&device).copied().unwrap_or(0);
        while self.dc.remove(&Dot::new(device, n + 1)) {
            n += 1;
        }
        if n > 0 {
            self.cc.insert(device, n);
        }
    }

    /// Fusionne (union) un autre contexte causal.
    pub fn merge(&mut self, other: &DotContext) {
        for (&device, &n) in &other.cc {
            let entry = self.cc.entry(device).or_insert(0);
            *entry = (*entry).max(n);
        }
        for &dot in &other.dc {
            self.dc.insert(dot);
        }
        // Purge les dots du nuage désormais couverts par le préfixe compact…
        let cc = &self.cc;
        self.dc
            .retain(|d| !cc.get(&d.device).is_some_and(|&n| d.counter <= n));
        // …puis compacte les runs devenus contigus.
        let devices: BTreeSet<DeviceId> = self.dc.iter().map(|d| d.device).collect();
        for device in devices {
            self.compact_device(device);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    #[test]
    fn next_dot_is_sequential() {
        let mut ctx = DotContext::new();
        assert_eq!(ctx.next_dot(dev(1)), Dot::new(dev(1), 1));
        assert_eq!(ctx.next_dot(dev(1)), Dot::new(dev(1), 2));
        // Compteurs indépendants par appareil.
        assert_eq!(ctx.next_dot(dev(2)), Dot::new(dev(2), 1));
    }

    #[test]
    fn contains_only_seen_dots() {
        let mut ctx = DotContext::new();
        let d = ctx.next_dot(dev(1));
        assert!(ctx.contains(&d));
        assert!(!ctx.contains(&Dot::new(dev(1), 2)));
        assert!(!ctx.contains(&Dot::new(dev(2), 1)));
    }

    #[test]
    fn compaction_absorbs_contiguous_run() {
        let mut ctx = DotContext::new();
        ctx.insert(Dot::new(dev(1), 1));
        ctx.insert(Dot::new(dev(1), 3)); // trou en 2
        assert_eq!(ctx.cc.get(&dev(1)), Some(&1));
        assert_eq!(ctx.dc.len(), 1); // (3) reste au nuage
        ctx.insert(Dot::new(dev(1), 2)); // comble → absorbe 2 puis 3
        assert!(ctx.dc.is_empty());
        assert_eq!(ctx.cc.get(&dev(1)), Some(&3));
    }

    #[test]
    fn merge_unions_and_compacts() {
        let mut a = DotContext::new();
        a.insert(Dot::new(dev(1), 1));
        a.insert(Dot::new(dev(1), 3)); // nuage : trou en 2
        let mut b = DotContext::new();
        b.insert(Dot::new(dev(1), 2));
        a.merge(&b); // b apporte le 2 → 1,2,3 contigus
        assert!(a.dc.is_empty());
        assert_eq!(a.cc.get(&dev(1)), Some(&3));
        assert!(a.contains(&Dot::new(dev(1), 3)));
    }
}
