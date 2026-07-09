//! CRDT delta-state custom (implémenté au lot P0.3).
//!
//! - `LwwRegister<T>` : valeur + horloge logique hybride (HLC) + tiebreak par
//!   identifiant d'appareil ;
//! - `AddWinsSet` (OR-Set + tombstones) pour la collection d'entrées ;
//! - génération / application de deltas + version vectors.
//!
//! Correctness validée par tests property-based (commutativité, associativité,
//! idempotence, convergence quel que soit l'ordre des deltas).

// TODO(P0.3): HLC, LwwRegister, AddWinsSet, delta gen/apply, version vectors.
