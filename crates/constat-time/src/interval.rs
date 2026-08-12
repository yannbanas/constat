//! Algèbre d'intervalles — les briques réutilisables du modèle temporel.
//!
//! Sémantique : une [`Period`] est un intervalle **fermé** `[from, to]` sur la
//! droite des instants (millisecondes UTC). Sa mesure (durée) est `to - from` :
//! un point isolé `[t, t]` est valide et de durée nulle. Deux intervalles qui
//! ne partagent qu'une borne se touchent sans se recouvrir en mesure.
//!
//! Tous les calculs de durée passent par des entiers larges (`i128`/`u128`) :
//! l'amplitude maximale entre deux `Timestamp` (`i64::MIN` → `i64::MAX`) vaut
//! exactement `u64::MAX`, donc une durée tient toujours dans [`DurationMs`],
//! mais la soustraction naïve en `i64` déborderait.

use constat_model::{DurationMs, Timestamp};

use crate::error::TimeError;
use crate::Period;

/// Durée en millisecondes entre deux instants, sans débordement.
///
/// Renvoie `0` si `to` précède `from`. Le calcul passe par `i128` car
/// `to - from` peut dépasser `i64::MAX` ; le résultat tient toujours dans un
/// `u64` (l'amplitude maximale d'un `i64` vaut `u64::MAX`).
pub(crate) fn span_ms(from: Timestamp, to: Timestamp) -> u64 {
    let d = i128::from(to.0) - i128::from(from.0);
    if d <= 0 {
        0
    } else {
        // d ≤ i64::MAX − i64::MIN = u64::MAX : la conversion ne peut pas échouer.
        u64::try_from(d).unwrap_or(u64::MAX)
    }
}

impl Period {
    /// Construit une période validée : `from` doit précéder ou égaler `to`.
    ///
    /// # Erreurs
    ///
    /// [`TimeError::InvalidPeriod`] si `from > to`.
    pub fn new(from: Timestamp, to: Timestamp) -> Result<Self, TimeError> {
        if from > to {
            Err(TimeError::InvalidPeriod { from, to })
        } else {
            Ok(Self { from, to })
        }
    }

    /// Durée de la période, en millisecondes. Nulle pour un point `[t, t]`.
    #[must_use]
    pub fn duration(&self) -> DurationMs {
        DurationMs(span_ms(self.from, self.to))
    }

    /// L'instant `at` appartient-il à la période (bornes incluses) ?
    #[must_use]
    pub fn contains(&self, at: Timestamp) -> bool {
        self.from <= at && at <= self.to
    }

    /// Intersection de deux périodes.
    ///
    /// Renvoie `None` si elles sont disjointes ou si l'une des deux est mal
    /// formée (`from > to`). Deux périodes qui ne partagent qu'une borne ont
    /// pour intersection le point commun `[t, t]`, de durée nulle.
    #[must_use]
    pub fn intersect(&self, other: Period) -> Option<Period> {
        if self.from > self.to || other.from > other.to {
            return None;
        }
        let from = self.from.max(other.from);
        let to = self.to.min(other.to);
        (from <= to).then_some(Period { from, to })
    }
}

/// Fusionne une liste de périodes en une union triée, sans chevauchement.
///
/// - Les périodes mal formées (`from > to`) sont ignorées.
/// - Deux périodes qui se recouvrent **ou se touchent** (`[a, b]` et `[b, c]`)
///   sont fusionnées en une seule (`[a, c]`).
/// - Le résultat est trié par début croissant et strictement disjoint.
#[must_use]
pub fn merge_periods(periods: &[Period]) -> Vec<Period> {
    let mut sorted: Vec<Period> = periods.iter().copied().filter(|p| p.from <= p.to).collect();
    sorted.sort();

    let mut out: Vec<Period> = Vec::with_capacity(sorted.len());
    for p in sorted {
        match out.last_mut() {
            Some(last) if p.from <= last.to => {
                if p.to > last.to {
                    last.to = p.to;
                }
            }
            _ => out.push(p),
        }
    }
    out
}

/// Découpe une liste de périodes à l'intérieur d'une période englobante.
///
/// Chaque période est intersectée avec `within`, puis l'ensemble est fusionné
/// (voir [`merge_periods`]). Les morceaux hors de `within` disparaissent.
#[must_use]
pub fn clip_periods(periods: &[Period], within: Period) -> Vec<Period> {
    let clipped: Vec<Period> = periods.iter().filter_map(|p| p.intersect(within)).collect();
    merge_periods(&clipped)
}

/// Durée totale couverte par une liste de périodes, chevauchements dédupliqués.
///
/// Les périodes sont d'abord fusionnées : un même sous-intervalle couvert par
/// plusieurs périodes n'est compté qu'une fois. La somme d'intervalles
/// disjoints sur la droite des `i64` tient toujours dans un `u64` ; le calcul
/// intermédiaire passe néanmoins par `u128` par prudence.
#[must_use]
pub fn total_duration(periods: &[Period]) -> DurationMs {
    let merged = merge_periods(periods);
    let sum: u128 = merged
        .iter()
        .map(|p| u128::from(span_ms(p.from, p.to)))
        .sum();
    DurationMs(u64::try_from(sum).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(from: i64, to: i64) -> Period {
        Period {
            from: Timestamp(from),
            to: Timestamp(to),
        }
    }

    #[test]
    fn period_new_valide_les_bornes() {
        assert!(Period::new(Timestamp(2), Timestamp(1)).is_err());
        assert!(Period::new(Timestamp(1), Timestamp(1)).is_ok());
    }

    #[test]
    fn duration_sans_debordement() {
        let extreme = p(i64::MIN, i64::MAX);
        assert_eq!(extreme.duration(), DurationMs(u64::MAX));
        assert_eq!(p(5, 5).duration(), DurationMs(0));
    }

    #[test]
    fn intersection() {
        assert_eq!(p(0, 10).intersect(p(5, 20)), Some(p(5, 10)));
        assert_eq!(p(0, 10).intersect(p(10, 20)), Some(p(10, 10)));
        assert_eq!(p(0, 10).intersect(p(11, 20)), None);
        // une période mal formée n'intersecte rien
        assert_eq!(p(10, 0).intersect(p(0, 10)), None);
    }

    #[test]
    fn fusion_trie_et_recouvre() {
        let merged = merge_periods(&[p(10, 20), p(0, 5), p(4, 12), p(30, 40), p(20, 25)]);
        assert_eq!(merged, vec![p(0, 25), p(30, 40)]);
    }

    #[test]
    fn fusion_ignore_les_mal_formees() {
        assert_eq!(merge_periods(&[p(5, 1), p(0, 2)]), vec![p(0, 2)]);
    }

    #[test]
    fn decoupe_a_une_periode() {
        let clipped = clip_periods(&[p(-10, 2), p(5, 8), p(9, 30)], p(0, 10));
        assert_eq!(clipped, vec![p(0, 2), p(5, 8), p(9, 10)]);
    }

    #[test]
    fn duree_totale_dedupliquee() {
        let d = total_duration(&[p(0, 10), p(5, 15), p(20, 21)]);
        assert_eq!(d, DurationMs(16));
    }
}
