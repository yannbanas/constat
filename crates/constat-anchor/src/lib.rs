//! # constat-anchor
//!
//! Ancrage externe de la racine du journal (§6.3) : export de racine,
//! horodatage qualifié RFC 3161.
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.

use constat_model::{BlobHash, Timestamp};
use serde::{Deserialize, Serialize};

/// Niveau d'ancrage, par ordre de force (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnchorLevel {
    LocalSignature = 0,
    MerkleChain = 1,
    RootExport = 2,
    Rfc3161 = 3,
    CoSignature = 4,
}

/// Preuve d'ancrage d'une racine à une date.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub root: BlobHash,
    pub at: Timestamp,
    pub level: AnchorLevel,
    /// Jeton d'horodatage RFC 3161 (DER), ou export signé selon le niveau.
    pub token: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("échec d'ancrage : {0}")]
    Failed(String),
    #[error("jeton invalide : {0}")]
    InvalidToken(String),
}
