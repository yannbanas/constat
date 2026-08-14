//! Couverture d'une période : mince façade sur le moteur de `constat-time`.
//!
//! La CLI ne calcule rien elle-même : le modèle §4.2 (observé / inféré /
//! trou déclaré) vit dans `constat-time`, seul endroit où cette logique
//! subtile est testée par propriétés.
//!
//! Les seules interruptions déclarées que la CLI connaît aujourd'hui sont les
//! **purges de rétention journalisées** (§16) : [`crate::queries::purge_gaps`]
//! les relit du magasin et [`coverage_report_declared`] les transmet au
//! moteur — un trou `RetentionPurge` n'est jamais masqué en `Unknown`.
//!
//! TODO(integration) : les interruptions déclarées par l'*agent* (arrêt pour
//! maintenance, etc.) ne sont pas encore journalisées — dès qu'elles le
//! seront, les transmettre par le même chemin.

use constat_model::{DurationMs, Timestamp};
use constat_time::{CoverageReport, Gap, Period, TimeError};

/// Écart maximal attendu entre deux collectes avant de refuser d'inférer
/// « pas de changement » : 26 h, soit une collecte quotidienne plus une
/// marge honnête.
pub const DEFAULT_MAX_EXPECTED_GAP: DurationMs = DurationMs(26 * 3_600_000);

/// Rapport de couverture d'une période à partir des dates d'observation
/// (dates de snapshot). Délègue à [`constat_time::coverage_report`].
pub fn coverage_report(
    times: &[Timestamp],
    period: Period,
    threshold: DurationMs,
) -> Result<CoverageReport, TimeError> {
    constat_time::coverage_report(period, times, &[], threshold)
}

/// Comme [`coverage_report`], avec des interruptions déclarées (aujourd'hui :
/// les purges de rétention, §16).
///
/// Les interruptions sont d'abord **découpées aux instants observés** : une
/// purge déclare la période `[from, to]` de ce qu'elle a supprimé, mais un
/// objet conservé (enregistrement de purge antérieur, snapshot encore
/// référencé par un journal nommé…) peut avoir une observation à l'intérieur
/// de cette période. Pour le moteur de `constat-time`, une observation dans
/// une interruption est une contradiction ([`TimeError::ObservationInDeclaredGap`]) ;
/// la découpe transforme la déclaration en « trou déclaré partout où rien n'a
/// survécu » — l'observation survivante reste un fait, le trou reste déclaré
/// de part et d'autre.
pub fn coverage_report_declared(
    times: &[Timestamp],
    declared: &[Gap],
    period: Period,
    threshold: DurationMs,
) -> Result<CoverageReport, TimeError> {
    let split = split_gaps_at_observations(declared, times);
    constat_time::coverage_report(period, times, &split, threshold)
}

/// Découpe chaque interruption déclarée aux instants d'observation qui
/// tombent à l'intérieur **strict** de sa plage (voir
/// [`coverage_report_declared`]). La milliseconde observée est laissée HORS
/// des morceaux (`[from, at]` puis `[at + 1, to]`) : deux morceaux qui se
/// toucheraient à l'instant observé seraient re-fusionnés par la
/// normalisation du moteur, et la contradiction reviendrait. Les bornes sont
/// conservées : une observation sur `from` ou `to` est déjà admise.
fn split_gaps_at_observations(declared: &[Gap], times: &[Timestamp]) -> Vec<Gap> {
    let mut sorted: Vec<Timestamp> = times.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut out = Vec::with_capacity(declared.len());
    for gap in declared {
        let mut from = gap.from;
        for &at in sorted.iter().filter(|t| gap.from < **t && **t < gap.to) {
            if from < at {
                out.push(Gap {
                    from,
                    to: at,
                    reason: gap.reason.clone(),
                });
            }
            from = Timestamp(at.0 + 1);
        }
        if from <= gap.to {
            out.push(Gap {
                from,
                to: gap.to,
                reason: gap.reason.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use constat_time::GapReason;

    /// Une observation survivante à l'intérieur d'une période purgée ne fait
    /// pas échouer la couverture : le trou est découpé autour d'elle.
    #[test]
    fn purge_avec_observation_survivante() {
        let period = Period {
            from: Timestamp(0),
            to: Timestamp(100),
        };
        let times = [Timestamp(0), Timestamp(50), Timestamp(100)];
        let declared = [Gap {
            from: Timestamp(20),
            to: Timestamp(80),
            reason: GapReason::RetentionPurge,
        }];
        let report = coverage_report_declared(&times, &declared, period, DurationMs(1_000));
        match report {
            Ok(r) => {
                assert_eq!(r.gaps.len(), 2);
                assert!(r.gaps.iter().all(|g| g.reason == GapReason::RetentionPurge));
            }
            Err(e) => panic!("couverture incalculable : {e}"),
        }
    }
}
