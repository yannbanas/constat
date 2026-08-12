//! # constat-time — cœur pur
//!
//! Le modèle temporel : des intervalles avec couverture, pas des points (§4).
//! Aucune entrée-sortie. Aucun flottant : les ratios sont en parties par million.
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.

use constat_model::{DurationMs, Timestamp};
use serde::{Deserialize, Serialize};

/// Période fermée `[from, to]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Period {
    pub from: Timestamp,
    pub to: Timestamp,
}

/// Pourquoi une interruption de collecte.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GapReason {
    AgentDown,
    MachineOff,
    CollectFailed,
    /// Purge de rétention journalisée (§16) — un trou déclaré, jamais masqué.
    RetentionPurge,
    Unknown,
}

/// Couverture d'un intervalle (§4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Coverage {
    /// On a observé, à cette date précise.
    Observed { at: Timestamp },
    /// Deux observations encadrantes, sans changement constaté,
    /// avec l'écart maximal entre deux collectes sur l'intervalle.
    Inferred {
        from: Timestamp,
        to: Timestamp,
        max_gap: DurationMs,
    },
    /// Aucune donnée : agent arrêté, machine éteinte, collecte en échec.
    Gap {
        from: Timestamp,
        to: Timestamp,
        reason: GapReason,
    },
}

/// Une interruption déclarée.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    pub from: Timestamp,
    pub to: Timestamp,
    pub reason: GapReason,
}

/// Rapport de couverture d'une période.
///
/// `observed_ppm` : part de la période réellement couverte, en parties par
/// million (0..=1_000_000). Entier, jamais de flottant dans ce qui peut être
/// haché (§15) — l'affichage en pourcentage est l'affaire du rendu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub period: Period,
    pub observed_ppm: u32,
    pub max_gap: DurationMs,
    /// Déclarées explicitement, jamais masquées.
    pub gaps: Vec<Gap>,
}
