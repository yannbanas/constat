//! Erreurs du modèle temporel.
//!
//! Toutes les erreurs sont des données pures, comparables et clonables :
//! deux évaluations sur les mêmes entrées produisent la même erreur.

use constat_model::Timestamp;
use thiserror::Error;

/// Erreur du modèle temporel.
///
/// Le variant [`TimeError::ObservationInDeclaredGap`] est central : une
/// observation datée à l'intérieur strict d'une interruption déclarée est une
/// **contradiction** — soit la déclaration ment, soit la donnée est corrompue.
/// Un outil de preuve ne tranche pas silencieusement : il refuse et le dit.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TimeError {
    /// Période mal formée : `from` strictement postérieur à `to`.
    #[error("période invalide : from ({}) postérieur à to ({})", from.0, to.0)]
    InvalidPeriod {
        /// Début déclaré de la période.
        from: Timestamp,
        /// Fin déclarée de la période.
        to: Timestamp,
    },

    /// Interruption déclarée mal formée : `from` strictement postérieur à `to`.
    #[error("interruption déclarée invalide : from ({}) postérieur à to ({})", from.0, to.0)]
    InvalidGap {
        /// Début déclaré de l'interruption.
        from: Timestamp,
        /// Fin déclarée de l'interruption.
        to: Timestamp,
    },

    /// Contradiction : une observation existe à l'intérieur **strict** d'une
    /// interruption déclarée. Une observation exactement sur une borne de
    /// l'interruption n'est pas contradictoire (l'agent a pu s'arrêter ou
    /// redémarrer à cet instant précis).
    #[error(
        "contradiction : observation à {} à l'intérieur de l'interruption déclarée [{} ; {}]",
        at.0, gap_from.0, gap_to.0
    )]
    ObservationInDeclaredGap {
        /// Instant de l'observation contradictoire.
        at: Timestamp,
        /// Début de l'interruption déclarée.
        gap_from: Timestamp,
        /// Fin de l'interruption déclarée.
        gap_to: Timestamp,
    },

    /// Contradiction : deux valeurs différentes observées au même instant
    /// pour la même entité et le même attribut.
    #[error("contradiction : deux valeurs différentes observées au même instant {}", at.0)]
    ConflictingObservations {
        /// Instant des observations contradictoires.
        at: Timestamp,
    },
}
