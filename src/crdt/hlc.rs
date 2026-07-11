//! Horloge logique hybride (HLC) : ordonne causalement les écritures sans dépendre
//! d'une horloge physique fiable. Le temps physique (`now_ms`, millisecondes depuis
//! l'epoch) est **injecté par l'appelant** — le cœur reste pur et déterministe.
//!
//! Réf. Kulkarni et al., « Logical Physical Clocks » (2014).

/// Horloge logique hybride : temps physique borné par un compteur logique.
/// Ordre total lexicographique (`wall_ms` puis `counter`).
///
/// La monotonie stricte est garantie dans le **domaine physique** : `wall_ms` en
/// millisecondes epoch (aucun débordement `u64` avant ~l'an 584 millions) et
/// `counter` très en deçà de `u32::MAX` (il faudrait 2³² écritures dans la même
/// milliseconde). Hors de ce domaine (valeurs saturées), la monotonie ne peut
/// être préservée — cas physiquement impossible.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Hlc {
    /// Temps physique en millisecondes (epoch).
    pub wall_ms: u64,
    /// Compteur logique départageant les événements de même `wall_ms`.
    pub counter: u32,
}

impl Hlc {
    /// Incrément logique **sûr** : déborde sur `wall_ms` plutôt que de paniquer
    /// (un débordement de `counter` supposerait 2³² événements dans une même ms).
    fn inc(self) -> Self {
        match self.counter.checked_add(1) {
            Some(counter) => Self { counter, ..self },
            None => Self {
                wall_ms: self.wall_ms.saturating_add(1),
                counter: 0,
            },
        }
    }
}

/// Générateur d'HLC d'un appareil : conserve le dernier HLC émis pour garantir la
/// stricte croissance locale.
#[derive(Clone, Debug, Default)]
pub struct HlcClock {
    last: Hlc,
}

impl HlcClock {
    /// Nouvelle horloge à zéro.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Dernier HLC émis.
    #[must_use]
    pub fn last(&self) -> Hlc {
        self.last
    }

    /// Événement **local** : renvoie un HLC strictement supérieur au précédent.
    /// `now_ms` = temps physique courant ; peut régresser sans casser l'ordre.
    pub fn tick(&mut self, now_ms: u64) -> Hlc {
        self.last = if now_ms > self.last.wall_ms {
            Hlc {
                wall_ms: now_ms,
                counter: 0,
            }
        } else {
            self.last.inc()
        };
        self.last
    }

    /// **Réception** d'un HLC distant : avance l'horloge au-delà de l'événement
    /// reçu ET du dernier local. Renvoie le nouvel HLC local.
    pub fn update(&mut self, now_ms: u64, remote: Hlc) -> Hlc {
        let max_wall = self.last.wall_ms.max(remote.wall_ms).max(now_ms);
        self.last = if max_wall == self.last.wall_ms && max_wall == remote.wall_ms {
            Hlc {
                wall_ms: max_wall,
                counter: self.last.counter.max(remote.counter),
            }
            .inc()
        } else if max_wall == self.last.wall_ms {
            self.last.inc()
        } else if max_wall == remote.wall_ms {
            Hlc {
                wall_ms: max_wall,
                counter: remote.counter,
            }
            .inc()
        } else {
            Hlc {
                wall_ms: max_wall,
                counter: 0,
            }
        };
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn tick_resets_counter_when_wall_advances() {
        let mut c = HlcClock::new();
        assert_eq!(
            c.tick(100),
            Hlc {
                wall_ms: 100,
                counter: 0
            }
        );
        assert_eq!(
            c.tick(200),
            Hlc {
                wall_ms: 200,
                counter: 0
            }
        );
    }

    #[test]
    fn tick_increments_counter_when_wall_stalls() {
        let mut c = HlcClock::new();
        c.tick(100);
        assert_eq!(
            c.tick(100),
            Hlc {
                wall_ms: 100,
                counter: 1
            }
        );
        assert_eq!(
            c.tick(100),
            Hlc {
                wall_ms: 100,
                counter: 2
            }
        );
    }

    #[test]
    fn tick_survives_regressing_wall() {
        let mut c = HlcClock::new();
        c.tick(200);
        // L'horloge physique recule : le HLC reste monotone via le compteur.
        assert_eq!(
            c.tick(100),
            Hlc {
                wall_ms: 200,
                counter: 1
            }
        );
    }

    #[test]
    fn counter_overflow_bumps_wall() {
        let mut c = HlcClock {
            last: Hlc {
                wall_ms: 5,
                counter: u32::MAX,
            },
        };
        assert_eq!(
            c.tick(5),
            Hlc {
                wall_ms: 6,
                counter: 0
            }
        );
    }

    #[test]
    fn update_advances_past_remote_wall() {
        let mut c = HlcClock::new();
        c.tick(100);
        let next = c.update(
            100,
            Hlc {
                wall_ms: 150,
                counter: 5,
            },
        );
        assert_eq!(
            next,
            Hlc {
                wall_ms: 150,
                counter: 6
            }
        );
    }

    #[test]
    fn update_merges_equal_walls() {
        let mut c = HlcClock {
            last: Hlc {
                wall_ms: 100,
                counter: 3,
            },
        };
        let next = c.update(
            50,
            Hlc {
                wall_ms: 100,
                counter: 7,
            },
        );
        assert_eq!(
            next,
            Hlc {
                wall_ms: 100,
                counter: 8
            }
        );
    }

    #[test]
    fn update_uses_physical_time_when_ahead() {
        let mut c = HlcClock {
            last: Hlc {
                wall_ms: 100,
                counter: 0,
            },
        };
        let next = c.update(
            300,
            Hlc {
                wall_ms: 120,
                counter: 2,
            },
        );
        assert_eq!(
            next,
            Hlc {
                wall_ms: 300,
                counter: 0
            }
        );
    }

    proptest! {
        /// Quelle que soit la suite (même chaotique) de temps physiques, les HLC
        /// émis localement croissent strictement.
        #[test]
        fn tick_is_strictly_monotonic(times in prop::collection::vec(any::<u64>(), 1..300)) {
            let mut c = HlcClock::new();
            let mut prev = c.tick(times[0]);
            for &t in &times[1..] {
                let cur = c.tick(t);
                prop_assert!(cur > prev, "{cur:?} doit être > {prev:?}");
                prev = cur;
            }
        }

        /// Une réception fait dominer l'horloge locale sur l'événement distant ET
        /// sur son état précédent. Bornes = domaine physique réaliste (ms epoch,
        /// compteur sain) — loin de la saturation u64/u32.
        #[test]
        fn update_dominates_both(
            ticks in prop::collection::vec(0u64..1_000_000_000_000, 0..40),
            now in 0u64..1_000_000_000_000,
            r_wall in 0u64..1_000_000_000_000,
            r_counter in 0u32..1_000_000,
        ) {
            let mut c = HlcClock::new();
            for t in ticks {
                c.tick(t);
            }
            let before = c.last();
            let remote = Hlc { wall_ms: r_wall, counter: r_counter };
            let after = c.update(now, remote);
            prop_assert!(after > before, "après {after:?} doit dominer avant {before:?}");
            prop_assert!(after > remote, "après {after:?} doit dominer distant {remote:?}");
        }
    }
}
