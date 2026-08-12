//! # constat-collect
//!
//! Les collecteurs (§7). Lecture seule, toujours. Compilés dans le binaire,
//! jamais téléchargés. **Aucun secret ne quitte la machine** : l'expurgation
//! se fait ici, avant émission (§7.2).
//!
//! Les extracteurs (parsing → faits) sont purs et testables sur tout OS ;
//! seule la collecte effective est spécifique à la plateforme (`cfg`).
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.

use constat_model::{CollectorId, Fact};

/// Capture brute, telle que lue sur la machine. Peut contenir des secrets :
/// ne doit JAMAIS être émise telle quelle.
#[derive(Debug, Clone)]
pub struct RawCapture(pub Vec<u8>);

/// Capture expurgée : plus aucun secret. Seule forme autorisée à sortir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedCapture(pub Vec<u8>);

#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("collecte impossible : {0}")]
    Unavailable(String),
    #[error("erreur de lecture : {0}")]
    Io(String),
    #[error("extraction impossible : {0}")]
    Extract(String),
}

/// Un collecteur (§7.2). `redact` s'applique AVANT toute émission.
pub trait Collector {
    fn id(&self) -> CollectorId;
    fn collect(&self) -> Result<RawCapture, CollectError>;
    fn redact(&self, raw: RawCapture) -> RedactedCapture;
    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError>;
}
