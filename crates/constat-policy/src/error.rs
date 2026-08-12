//! Erreurs du crate `constat-policy`.
//!
//! Toutes les erreurs sont **lisibles** : elles portent la position dans le
//! document YAML quand elle est connue, et un extrait de la ligne fautive.

use thiserror::Error;

/// Erreur de politique : parsing YAML, durées, dates, validation d'assertion.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// Le document YAML est invalide (syntaxe ou structure).
    ///
    /// `message` contient déjà la position et un extrait de la ligne fautive ;
    /// `line`/`column` (base 1) restent accessibles pour un rendu enrichi.
    #[error("{message}")]
    Yaml {
        /// Message complet, prêt à afficher.
        message: String,
        /// Ligne fautive (base 1), si connue.
        line: Option<usize>,
        /// Colonne fautive (base 1), si connue.
        column: Option<usize>,
    },

    /// Une durée lisible (« 24h », « 30m », « 7d », « 90s ») n'a pas pu être lue.
    #[error("durée illisible « {input} » : {reason}")]
    InvalidDuration {
        /// Texte fourni.
        input: String,
        /// Explication de l'échec.
        reason: String,
    },

    /// Une date (« 2027-01-01 », éventuellement suivie de `THH:MM[:SS][Z]`)
    /// n'a pas pu être lue.
    #[error("date illisible « {input} » : {reason}")]
    InvalidDate {
        /// Texte fourni.
        input: String,
        /// Explication de l'échec.
        reason: String,
    },

    /// Une assertion parsée est invalide (exception sans expiration,
    /// durée illisible, prédicat vide…).
    #[error("assertion « {assertion} » invalide : {reason}")]
    InvalidAssertion {
        /// Identifiant de l'assertion fautive.
        assertion: String,
        /// Explication de l'échec.
        reason: String,
    },

    /// Deux assertions portent le même identifiant.
    #[error("identifiant d'assertion en double : « {id} »")]
    DuplicateAssertionId {
        /// Identifiant dupliqué.
        id: String,
    },

    /// Le prédicat dépasse la profondeur maximale autorisée.
    ///
    /// La limite garantit que l'évaluation termine avec une pile bornée,
    /// même face à un document hostile.
    #[error("prédicat trop profond (plus de {max} niveaux d'imbrication) — refusé")]
    PredicateTooDeep {
        /// Profondeur maximale autorisée.
        max: usize,
    },
}
