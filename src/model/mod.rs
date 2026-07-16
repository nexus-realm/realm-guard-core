//! Modèle de données du coffre, projeté sur le CRDT (lot P0.3d).
//!
//! Un coffre = un ensemble **add-wins** d'entrées ([`EntryId`]) + par entrée une
//! map de champs ([`FieldId`] → [`LwwRegister`]). La **présence** d'une entrée est
//! régie par l'`AddWinsSet` (un ajout concurrent l'emporte sur une suppression) ;
//! la **valeur** de chaque champ par un registre LWW indépendant — deux appareils
//! éditant des champs *différents* de la même entrée convergent sans s'écraser.
//!
//! Présence et valeurs sont **orthogonales** (mécanisme, pas politique) : `set_field`
//! ne touche pas à la présence. Une app voulant « l'édition l'emporte sur la
//! suppression » ré-appelle simplement [`VaultDoc::add_entry`] à chaque édition.
//!
//! Tout est **E2EE** : le type de valeur `V` est un chiffré opaque (en production
//! `crypto::Ciphertext`, une clé par champ dérivée par HKDF), jamais déchiffré côté
//! serveur. Le cœur ignore le schéma en clair — la correspondance `FieldId` →
//! sémantique (titre, secret, TOTP…) et la nature d'une entrée vivent côté client.
//!
//! Mapping v1 (indicatif, côté client) : un *credential* = une entrée {titre,
//! secret, réf. profil} ; un *profil* = une entrée {nom, emails}. Les PK
//! auto-incrément de v1 deviennent des [`EntryId`] UUID à la migration.
//!
//! # Synchronisation par **deltas** (P3)
//!
//! Chaque mutation renvoie un **delta** : un `VaultDoc` partiel, join-compatible avec
//! l'état complet. Le modèle est **delta-interval** : on *expédie* les deltas
//! produits (vers le log serveur), on ne les *recalcule* pas depuis un version
//! vector. Un pair converge en fusionnant le flux de deltas — c'est l'invariant
//! testé par `delta_stream_converges_to_full_state`.
//!
//! Le join étant idempotent / commutatif / associatif, la livraison peut être
//! **désordonnée et dupliquée** (« at-least-once ») sans casser la convergence : le
//! log serveur n'a donc pas à garantir l'ordre ni l'unicité.
//!
//! Un pair trop en retard (log compacté) se resynchronise par **snapshot** : un join
//! de l'état complet, correct par la même propriété.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crdt::{AddWinsSet, DeviceId, DotContext, LwwRegister, Timestamp};
use crate::error::{Error, Result};

/// Identifiant global d'une entrée (UUID 16 octets) — unique entre appareils.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct EntryId([u8; 16]);

impl EntryId {
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

/// Étiquette compacte d'un champ. Sa sémantique (titre, secret…) est définie côté
/// client ; le serveur ne voit qu'un tag opaque (métadonnées minimisées).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct FieldId(pub u16);

/// Document coffre répliqué : présence des entrées (add-wins) + champs (LWW).
/// `V` = valeur chiffrée opaque (en prod `crypto::Ciphertext`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct VaultDoc<V: Ord + Clone> {
    entries: AddWinsSet<EntryId>,
    fields: BTreeMap<EntryId, BTreeMap<FieldId, LwwRegister<V>>>,
}

impl<V: Ord + Clone> Default for VaultDoc<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Ord + Clone> VaultDoc<V> {
    /// Document vide.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: AddWinsSet::new(),
            fields: BTreeMap::new(),
        }
    }

    /// Marque une entrée présente (sémantique add-wins). Renvoie le **delta** à
    /// propager (cf. doc du module).
    pub fn add_entry(&mut self, id: EntryId, device: DeviceId) -> Self {
        Self {
            entries: self.entries.add(id, device),
            fields: BTreeMap::new(),
        }
    }

    /// Retire une entrée. Les registres de champs sont **conservés** (pour ne pas
    /// perdre d'écritures concurrentes en cas de ré-ajout) ; leur GC est différée.
    /// Renvoie le **delta** à propager.
    ///
    /// Le delta ne porte **aucune** entrée : c'est son contexte causal (les dots
    /// retirés) qui véhicule la suppression chez le pair.
    pub fn remove_entry(&mut self, id: &EntryId) -> Self {
        Self {
            entries: self.entries.remove(id),
            fields: BTreeMap::new(),
        }
    }

    /// L'entrée est-elle présente ?
    pub fn contains_entry(&self, id: &EntryId) -> bool {
        self.entries.contains(id)
    }

    /// Itère les identifiants d'entrées présentes.
    pub fn entry_ids(&self) -> impl Iterator<Item = &EntryId> {
        self.entries.elements()
    }

    /// Nombre d'entrées présentes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Le coffre est-il sans entrée présente ?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Écrit (LWW) la valeur d'un champ. N'affecte pas la présence de l'entrée.
    /// Renvoie le **delta** à propager.
    ///
    /// Le delta porte le registre **résultant**, pas l'écriture tentée : `set` étant
    /// conditionnel (LWW), une écriture perdante laisse l'état inchangé — propager le
    /// registre résultant reste correct (le join est idempotent) et reproduit
    /// fidèlement l'issue chez le pair.
    pub fn set_field(&mut self, id: EntryId, field: FieldId, value: V, ts: Timestamp) -> Self {
        let entry_fields = self.fields.entry(id).or_default();
        let register = match entry_fields.get_mut(&field) {
            Some(reg) => {
                reg.set(value, ts);
                reg.clone()
            }
            None => {
                let reg = LwwRegister::new(value, ts);
                entry_fields.insert(field, reg.clone());
                reg
            }
        };

        let mut delta = Self::new();
        delta.fields.insert(id, BTreeMap::from([(field, register)]));
        delta
    }

    /// Valeur d'un champ, si (et seulement si) l'entrée est présente.
    #[must_use]
    pub fn field(&self, id: &EntryId, field: FieldId) -> Option<&V> {
        if !self.entries.contains(id) {
            return None;
        }
        self.fields.get(id)?.get(&field).map(LwwRegister::value)
    }

    /// Contexte causal de la présence (version vector) — pour la synchro (P3).
    #[must_use]
    pub fn presence_context(&self) -> &DotContext {
        self.entries.context()
    }

    /// Fusionne (join) un autre document — ou un delta partiel. Idempotent /
    /// commutatif / associatif (produit de CRDT : `AddWinsSet` ⊗ registres LWW).
    pub fn merge(&mut self, other: &Self) {
        self.entries.merge(&other.entries);
        for (id, other_fields) in &other.fields {
            let self_fields = self.fields.entry(*id).or_default();
            for (fid, other_reg) in other_fields {
                match self_fields.get_mut(fid) {
                    Some(self_reg) => self_reg.merge(other_reg),
                    None => {
                        self_fields.insert(*fid, other_reg.clone());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{Hlc, HlcClock};
    use proptest::prelude::*;

    fn dev(n: u8) -> DeviceId {
        DeviceId::from_bytes([n; 16])
    }

    fn eid(n: u8) -> EntryId {
        EntryId::from_bytes([n; 16])
    }

    fn ts(wall: u64, device: u8) -> Timestamp {
        Timestamp::new(
            Hlc {
                wall_ms: wall,
                counter: 0,
            },
            dev(device),
        )
    }

    #[test]
    fn add_and_read_field() {
        let mut d = VaultDoc::new();
        let x = eid(1);
        d.add_entry(x, dev(1));
        d.set_field(x, FieldId(0), 42u8, ts(10, 1));
        assert!(d.contains_entry(&x));
        assert_eq!(d.field(&x, FieldId(0)), Some(&42));
        assert_eq!(d.field(&x, FieldId(9)), None);
    }

    #[test]
    fn removed_entry_hides_fields() {
        let mut d = VaultDoc::new();
        let x = eid(1);
        d.add_entry(x, dev(1));
        d.set_field(x, FieldId(0), 42u8, ts(10, 1));
        d.remove_entry(&x);
        assert!(!d.contains_entry(&x));
        assert_eq!(d.field(&x, FieldId(0)), None);
    }

    #[test]
    fn concurrent_edits_of_different_fields_merge() {
        let x = eid(1);
        let mut base = VaultDoc::new();
        base.add_entry(x, dev(1));
        // Appareils distincts éditant des champs distincts, concurremment.
        let mut a = base.clone();
        a.set_field(x, FieldId(0), 1u8, ts(10, 1));
        let mut b = base.clone();
        b.set_field(x, FieldId(1), 2u8, ts(10, 2));
        let mut merged = a.clone();
        merged.merge(&b);
        assert_eq!(merged.field(&x, FieldId(0)), Some(&1));
        assert_eq!(merged.field(&x, FieldId(1)), Some(&2));
    }

    #[test]
    fn concurrent_edits_of_same_field_are_lww() {
        let x = eid(1);
        let mut base = VaultDoc::new();
        base.add_entry(x, dev(1));
        let mut a = base.clone();
        a.set_field(x, FieldId(0), 1u8, ts(20, 1)); // plus récent
        let mut b = base.clone();
        b.set_field(x, FieldId(0), 2u8, ts(10, 2)); // plus ancien
        let mut merged = a.clone();
        merged.merge(&b);
        assert_eq!(merged.field(&x, FieldId(0)), Some(&1));
    }

    #[test]
    fn add_wins_over_remove_entry() {
        let x = eid(1);
        let mut a: VaultDoc<u8> = VaultDoc::new();
        a.add_entry(x, dev(1));
        let mut b = a.clone(); // B a observé l'ajout
        b.remove_entry(&x);
        a.add_entry(x, dev(1)); // ré-ajout concurrent (dot frais)
        let mut merged = a.clone();
        merged.merge(&b);
        assert!(merged.contains_entry(&x));
    }

    #[test]
    fn serialization_roundtrip_u8() {
        let mut d: VaultDoc<u8> = VaultDoc::new();
        let x = eid(1);
        d.add_entry(x, dev(1));
        d.set_field(x, FieldId(0), 7u8, ts(5, 1));
        let bytes = crate::codec::encode(&d).unwrap();
        let decoded: VaultDoc<u8> = crate::codec::decode(&bytes).unwrap();
        assert_eq!(d, decoded);
    }

    #[test]
    fn serialization_roundtrip_ciphertext_value() {
        use crate::crypto::Ciphertext;
        let mut d: VaultDoc<Ciphertext> = VaultDoc::new();
        let x = eid(1);
        d.add_entry(x, dev(1));
        let ct = Ciphertext {
            version: 1,
            nonce: [3u8; 24],
            ciphertext: vec![9, 8, 7],
        };
        d.set_field(x, FieldId(0), ct.clone(), ts(5, 1));
        let bytes = crate::codec::encode(&d).unwrap();
        let decoded: VaultDoc<Ciphertext> = crate::codec::decode(&bytes).unwrap();
        assert_eq!(d, decoded);
        assert_eq!(decoded.field(&x, FieldId(0)), Some(&ct));
    }

    #[derive(Clone, Debug)]
    enum Op {
        Add(u8),
        Remove(u8),
        Set(u8, u16, u8),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..3).prop_map(Op::Add),
            (0u8..3).prop_map(Op::Remove),
            (0u8..3, 0u16..3, any::<u8>()).prop_map(|(e, f, v)| Op::Set(e, f, v)),
        ]
    }

    fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(op_strategy(), 0..15)
    }

    // Construit un document en appliquant `ops` sur un appareil donné (horloge
    // propre : chaque `set` avance le HLC).
    fn build(device: u8, ops: &[Op]) -> VaultDoc<u8> {
        build_with_deltas(device, ops).0
    }

    /// Construit un document **et** collecte les deltas produits, dans l'ordre.
    fn build_with_deltas(device: u8, ops: &[Op]) -> (VaultDoc<u8>, Vec<VaultDoc<u8>>) {
        let d = dev(device);
        let mut clock = HlcClock::new();
        let mut doc = VaultDoc::new();
        let mut deltas = Vec::new();
        let mut now = 0u64;
        for op in ops {
            now += 1;
            let delta = match op {
                Op::Add(n) => doc.add_entry(eid(*n), d),
                Op::Remove(n) => doc.remove_entry(&eid(*n)),
                Op::Set(n, f, v) => {
                    let stamp = Timestamp::new(clock.tick(now), d);
                    doc.set_field(eid(*n), FieldId(*f), *v, stamp)
                }
            };
            deltas.push(delta);
        }
        (doc, deltas)
    }

    proptest! {
        #[test]
        fn merge_idempotent(ops in ops_strategy()) {
            let d = build(1, &ops);
            let mut m = d.clone();
            m.merge(&d);
            prop_assert_eq!(m, d);
        }

        #[test]
        fn merge_commutative(oa in ops_strategy(), ob in ops_strategy()) {
            let a = build(1, &oa);
            let b = build(2, &ob);
            let mut ab = a.clone();
            ab.merge(&b);
            let mut ba = b.clone();
            ba.merge(&a);
            prop_assert_eq!(ab, ba);
        }

        #[test]
        fn merge_associative(oa in ops_strategy(), ob in ops_strategy(), oc in ops_strategy()) {
            let a = build(1, &oa);
            let b = build(2, &ob);
            let c = build(3, &oc);
            let mut left = a.clone();
            left.merge(&b);
            left.merge(&c);
            let mut bc = b.clone();
            bc.merge(&c);
            let mut right = a.clone();
            right.merge(&bc);
            prop_assert_eq!(left, right);
        }

        /// **L'invariant qui autorise le log de deltas (P3.2)** : un pair qui ne voit
        /// que le *flux de deltas* converge vers le même état que la source. Sans
        /// lui, la synchro par deltas serait fausse et il faudrait tout renvoyer.
        #[test]
        fn delta_stream_converges_to_full_state(ops in ops_strategy()) {
            let (source, deltas) = build_with_deltas(1, &ops);

            let mut peer = VaultDoc::new();
            for delta in &deltas {
                peer.merge(delta);
            }

            prop_assert_eq!(peer, source);
        }

        /// Livraison **désordonnée et dupliquée** : la convergence n'en dépend pas.
        /// C'est ce qui permet au log serveur de se contenter d'« at-least-once »,
        /// sans garantie d'ordre ni de dédoublonnage.
        #[test]
        fn delta_stream_tolerates_reorder_and_duplicates(ops in ops_strategy()) {
            let (source, deltas) = build_with_deltas(1, &ops);

            let mut peer = VaultDoc::new();
            for delta in deltas.iter().rev() {
                peer.merge(delta);
            }
            for delta in &deltas {
                peer.merge(delta); // redélivrance
            }

            prop_assert_eq!(peer, source);
        }

        /// Deux appareils qui échangent leurs deltas convergent — et vers le même
        /// état qu'un échange d'états complets.
        #[test]
        fn delta_exchange_matches_full_state_exchange(oa in ops_strategy(), ob in ops_strategy()) {
            let (a, da) = build_with_deltas(1, &oa);
            let (b, db) = build_with_deltas(2, &ob);

            // Par deltas : chacun applique le flux de l'autre.
            let mut a_delta = a.clone();
            for delta in &db {
                a_delta.merge(delta);
            }
            let mut b_delta = b.clone();
            for delta in &da {
                b_delta.merge(delta);
            }
            prop_assert_eq!(&a_delta, &b_delta);

            // Par états complets : même résultat.
            let mut a_full = a.clone();
            a_full.merge(&b);
            prop_assert_eq!(&a_delta, &a_full);
        }

        /// Trois répliques convergent quel que soit l'ordre des fusions.
        #[test]
        fn replicas_converge(oa in ops_strategy(), ob in ops_strategy(), oc in ops_strategy()) {
            let a = build(1, &oa);
            let b = build(2, &ob);
            let c = build(3, &oc);
            let order1 = {
                let mut x = a.clone();
                x.merge(&b);
                x.merge(&c);
                x
            };
            let order2 = {
                let mut x = c.clone();
                x.merge(&b);
                x.merge(&a);
                x
            };
            prop_assert_eq!(order1, order2);
        }
    }
}
