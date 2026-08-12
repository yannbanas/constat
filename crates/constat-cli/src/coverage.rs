//! Couverture d'une période : mince façade sur le moteur de `constat-time`.
//!
//! La CLI ne calcule rien elle-même : le modèle §4.2 (observé / inféré /
//! trou déclaré) vit dans `constat-time`, seul endroit où cette logique
//! subtile est testée par propriétés.
//!
//! TODO(integration) : les interruptions *déclarées* (agent arrêté pour
//! maintenance, etc.) ne sont pas encore journalisées par l'agent — le
//! paramètre `declared_gaps` est donc vide pour l'instant. Dès que l'agent
//! journalise ses interruptions, les transmettre ici : les trous porteront
//! alors leur vraie raison au lieu de `Unknown`.

use constat_model::{DurationMs, Timestamp};
use constat_time::{CoverageReport, Period, TimeError};

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
