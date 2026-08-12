//! Historique d'une valeur dans le temps — ce qui alimente `constat history`
//! (§10.1 de la spécification).
//!
//! À partir d'observations datées d'une même grandeur (un attribut d'une
//! entité), on produit :
//!
//! - les **plages de stabilité** : intervalles pendant lesquels la valeur
//!   observée n'a pas changé, chacun portant sa propre couverture — car « la
//!   valeur n'a pas changé entre deux collectes espacées de 26 h » n'a pas le
//!   même poids que la même affirmation avec une collecte horaire ;
//! - les **instants de changement** : jamais un instant exact, toujours un
//!   encadrement honnête — la dernière observation de l'ancienne valeur et la
//!   première de la nouvelle. Le changement a eu lieu quelque part entre les
//!   deux, et prétendre mieux serait mentir.

use constat_model::{DurationMs, Timestamp};
use serde::{Deserialize, Serialize};

use crate::coverage::build_coverage;
use crate::error::TimeError;
use crate::{Coverage, Gap, Period};

/// Observation datée d'une valeur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueObservation<T> {
    /// Instant de la collecte.
    pub at: Timestamp,
    /// Valeur observée à cet instant.
    pub value: T,
}

/// Plage de stabilité : la valeur est restée identique sur toutes les
/// observations de `[first_seen, last_seen]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabilityInterval<T> {
    /// La valeur observée sur toute la plage.
    pub value: T,
    /// Première observation de cette valeur dans la plage.
    pub first_seen: Timestamp,
    /// Dernière observation de cette valeur avant changement (ou fin des données).
    pub last_seen: Timestamp,
    /// Couverture de la plage `[first_seen, last_seen]` : ce que « stable »
    /// veut vraiment dire ici — inférences, écarts réels, interruptions.
    pub coverage: Vec<Coverage>,
}

/// Changement de valeur, encadré honnêtement.
///
/// Le changement s'est produit dans l'intervalle **ouvert**
/// `(last_seen_before, first_seen_after)` : on ne sait pas mieux.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueChange<T> {
    /// Dernière observation de l'ancienne valeur.
    pub last_seen_before: Timestamp,
    /// Première observation de la nouvelle valeur.
    pub first_seen_after: Timestamp,
    /// Valeur avant le changement.
    pub before: T,
    /// Valeur après le changement.
    pub after: T,
}

/// Historique d'une valeur sur une période : plages de stabilité et
/// changements, en ordre chronologique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueHistory<T> {
    /// La période interrogée.
    pub period: Period,
    /// Plages de stabilité successives, chacune avec sa couverture.
    pub intervals: Vec<StabilityInterval<T>>,
    /// Changements entre plages consécutives (`intervals.len() - 1` éléments
    /// quand il y a au moins une plage).
    pub changes: Vec<ValueChange<T>>,
}

/// Construit l'historique d'une valeur sur une période.
///
/// # Entrées
///
/// - `observations` : observations datées de la valeur, **triées ou non** ;
///   celles hors de `period` sont ignorées ; deux observations identiques au
///   même instant sont dédupliquées ;
/// - `declared_gaps` : interruptions déclarées, transmises à la couverture de
///   chaque plage de stabilité ;
/// - `max_expected_gap` : même seuil d'inférence que pour
///   [`build_coverage`](crate::build_coverage).
///
/// # Erreurs
///
/// - [`TimeError::InvalidPeriod`] si `period.from > period.to` ;
/// - [`TimeError::ConflictingObservations`] si deux valeurs **différentes**
///   sont observées au même instant ;
/// - [`TimeError::InvalidGap`] / [`TimeError::ObservationInDeclaredGap`]
///   propagées par le calcul de couverture — une observation à l'intérieur
///   strict d'une interruption déclarée reste une contradiction.
pub fn value_history<T: Eq + Clone>(
    period: Period,
    observations: &[ValueObservation<T>],
    declared_gaps: &[Gap],
    max_expected_gap: DurationMs,
) -> Result<ValueHistory<T>, TimeError> {
    if period.from > period.to {
        return Err(TimeError::InvalidPeriod {
            from: period.from,
            to: period.to,
        });
    }

    let mut in_period: Vec<&ValueObservation<T>> = observations
        .iter()
        .filter(|o| period.contains(o.at))
        .collect();
    // tri stable : à instant égal, l'ordre d'entrée est conservé, puis la
    // contradiction éventuelle est détectée explicitement ci-dessous.
    in_period.sort_by_key(|o| o.at);

    let mut clean: Vec<&ValueObservation<T>> = Vec::with_capacity(in_period.len());
    for o in in_period {
        if let Some(prev) = clean.last() {
            if prev.at == o.at {
                if prev.value == o.value {
                    continue; // doublon exact, sans information nouvelle
                }
                return Err(TimeError::ConflictingObservations { at: o.at });
            }
        }
        clean.push(o);
    }

    let mut intervals: Vec<StabilityInterval<T>> = Vec::new();
    let mut changes: Vec<ValueChange<T>> = Vec::new();
    let mut run: Vec<&ValueObservation<T>> = Vec::new();

    for o in clean {
        if let Some(prev) = run.last() {
            if prev.value != o.value {
                changes.push(ValueChange {
                    last_seen_before: prev.at,
                    first_seen_after: o.at,
                    before: prev.value.clone(),
                    after: o.value.clone(),
                });
                flush_run(&run, declared_gaps, max_expected_gap, &mut intervals)?;
                run.clear();
            }
        }
        run.push(o);
    }
    flush_run(&run, declared_gaps, max_expected_gap, &mut intervals)?;

    Ok(ValueHistory {
        period,
        intervals,
        changes,
    })
}

/// Transforme une suite d'observations de même valeur en plage de stabilité,
/// avec sa couverture propre.
fn flush_run<T: Clone>(
    run: &[&ValueObservation<T>],
    declared_gaps: &[Gap],
    max_expected_gap: DurationMs,
    intervals: &mut Vec<StabilityInterval<T>>,
) -> Result<(), TimeError> {
    let (Some(first), Some(last)) = (run.first(), run.last()) else {
        return Ok(());
    };
    let span = Period {
        from: first.at,
        to: last.at,
    };
    let times: Vec<Timestamp> = run.iter().map(|o| o.at).collect();
    let coverage = build_coverage(span, &times, declared_gaps, max_expected_gap)?;
    intervals.push(StabilityInterval {
        value: first.value.clone(),
        first_seen: first.at,
        last_seen: last.at,
        coverage,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GapReason;

    fn obs(at: i64, value: bool) -> ValueObservation<bool> {
        ValueObservation {
            at: Timestamp(at),
            value,
        }
    }

    fn p(from: i64, to: i64) -> Period {
        Period {
            from: Timestamp(from),
            to: Timestamp(to),
        }
    }

    #[test]
    fn historique_du_cas_jdupont() {
        // §10.1 : user.privileged — false, puis true, puis false.
        let observations = [
            obs(0, false),
            obs(10, false),
            obs(20, true), // ajouté au groupe d'administration
            obs(30, true),
            obs(40, false), // retiré
            obs(50, false),
        ];
        let h = value_history(p(0, 60), &observations, &[], DurationMs(15));
        let h = match h {
            Ok(h) => h,
            Err(e) => panic!("historique inattendu : {e}"),
        };
        assert_eq!(h.intervals.len(), 3);
        assert_eq!(h.changes.len(), 2);

        assert!(!h.changes[0].before);
        assert!(h.changes[0].after);
        assert_eq!(h.changes[0].last_seen_before, Timestamp(10));
        assert_eq!(h.changes[0].first_seen_after, Timestamp(20));

        assert!(h.changes[1].before);
        assert!(!h.changes[1].after);
        assert_eq!(h.changes[1].last_seen_before, Timestamp(30));
        assert_eq!(h.changes[1].first_seen_after, Timestamp(40));

        assert_eq!(h.intervals[0].first_seen, Timestamp(0));
        assert_eq!(h.intervals[0].last_seen, Timestamp(10));
        assert!(!h.intervals[0].coverage.is_empty());
    }

    #[test]
    fn observations_non_triees_et_doublons() {
        let observations = [obs(30, true), obs(0, false), obs(0, false), obs(10, false)];
        let h = value_history(p(0, 40), &observations, &[], DurationMs(100));
        match h {
            Ok(h) => {
                assert_eq!(h.intervals.len(), 2);
                assert_eq!(h.changes.len(), 1);
            }
            Err(e) => panic!("historique inattendu : {e}"),
        }
    }

    #[test]
    fn valeurs_contradictoires_au_meme_instant() {
        let observations = [obs(10, true), obs(10, false)];
        let err = value_history(p(0, 40), &observations, &[], DurationMs(100));
        assert_eq!(
            err,
            Err(TimeError::ConflictingObservations { at: Timestamp(10) })
        );
    }

    #[test]
    fn la_couverture_de_plage_porte_les_interruptions() {
        let gap = Gap {
            from: Timestamp(10),
            to: Timestamp(20),
            reason: GapReason::AgentDown,
        };
        let observations = [obs(0, true), obs(10, true), obs(20, true), obs(30, true)];
        let h = value_history(
            p(0, 30),
            &observations,
            std::slice::from_ref(&gap),
            DurationMs(100),
        );
        match h {
            Ok(h) => {
                assert_eq!(h.intervals.len(), 1);
                let has_gap = h.intervals[0].coverage.iter().any(|c| {
                    matches!(
                        c,
                        Coverage::Gap {
                            reason: GapReason::AgentDown,
                            ..
                        }
                    )
                });
                assert!(has_gap, "l'interruption déclarée doit rester visible");
            }
            Err(e) => panic!("historique inattendu : {e}"),
        }
    }
}
