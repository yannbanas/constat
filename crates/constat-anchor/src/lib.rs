//! # constat-anchor — l'ancrage externe (§6.3)
//!
//! Le journal Merkle protège contre la modification et l'insertion d'entrées
//! au milieu de la chaîne. Il ne protège **pas** contre la troncature : celui
//! qui contrôle le magasin et la clé de signature peut supprimer la fin du
//! journal, ou tout effacer et repartir de zéro.
//!
//! > **Noir sur blanc (§6.2) : sans ancrage externe, le journal prouve la
//! > cohérence interne, pas la non-répudiation.** Cette phrase doit figurer
//! > dans la documentation et dans chaque dossier généré.
//!
//! Ce crate fournit donc les deux ancrages qui rendent la troncature
//! détectable, par ordre de force (§6.3) :
//!
//! - **niveau 2** — [`root`] : un document signé `{ racine, date,
//!   organisation }`, sérialisé canoniquement, prêt à être envoyé hors du
//!   système (courriel au RSSI, dépôt tiers) ;
//! - **niveau 3** — [`rfc3161`] : l'encodage d'une `TimeStampReq` DER et le
//!   décodage minimal de la `TimeStampResp` du protocole RFC 3161
//!   (horodatage qualifié, reconnu eIDAS — c'est ce qui rend le dossier
//!   opposable).
//!
//! **Pureté** : ce crate encode et décode, il ne transporte rien. Aucun
//! client HTTP ici — l'envoi de la requête au prestataire d'horodatage est
//! l'affaire des binaires.

use constat_model::{BlobHash, Timestamp};
use serde::{Deserialize, Serialize};

mod der;
pub mod rfc3161;
pub mod root;

/// Niveau d'ancrage, par ordre de force (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnchorLevel {
    /// Niveau 0 — signature locale : protège d'une modification accidentelle.
    LocalSignature = 0,
    /// Niveau 1 — chaînage Merkle : protège d'une réécriture de l'historique.
    MerkleChain = 1,
    /// Niveau 2 — racine envoyée hors du système : protège d'une troncature simple.
    RootExport = 2,
    /// Niveau 3 — horodatage qualifié RFC 3161 : troncature + opposabilité juridique.
    Rfc3161 = 3,
    /// Niveau 4 — co-signature par un tiers : protège de la collusion d'un seul acteur.
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

/// Erreurs d'ancrage.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("échec d'ancrage : {0}")]
    Failed(String),
    #[error("jeton invalide : {0}")]
    InvalidToken(String),
    #[error("échec d'encodage canonique : {0}")]
    Encoding(String),
    #[error("signature invalide")]
    BadSignature,
}
