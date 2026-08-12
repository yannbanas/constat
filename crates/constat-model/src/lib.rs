//! # constat-model — cœur pur
//!
//! Faits, entités, snapshots et sérialisation canonique.
//!
//! **Règles non négociables** (voir CONSTAT-ARCHITECTURE.md §1, §15) :
//! - aucune entrée-sortie dans ce crate ;
//! - `BTreeMap`/`BTreeSet` partout, jamais `HashMap` ;
//! - aucun flottant dans une valeur hachée ;
//! - dates en UTC, entier de millisecondes depuis l'époque Unix ;
//! - encodage canonique déterministe : mêmes données → mêmes octets → même empreinte.
//!
//! **CONTRAT PUBLIC** : les types ci-dessous sont le contrat partagé par tous les
//! crates du workspace. On peut les étendre (nouvelles méthodes, nouveaux modules),
//! jamais les casser.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Temps
// ---------------------------------------------------------------------------

/// Instant UTC, en millisecondes depuis l'époque Unix. Précision fixe (§15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

/// Durée en millisecondes. Aucun flottant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DurationMs(pub u64);

// ---------------------------------------------------------------------------
// Identifiants
// ---------------------------------------------------------------------------

/// Identifiant d'entité, ex. `"user:root"`, `"service:sshd"`, `"pkg:openssh-server"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntityId(pub String);

/// Attribut, ex. `"sshd.PermitRootLogin"`, `"user.privileged"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Attribute(pub String);

/// Machine du parc, ex. `"srv-fic-01"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssetId(pub String);

/// Identifiant de collecteur, ex. `"linux.sshd"`, `"linux.accounts"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CollectorId(pub String);

// ---------------------------------------------------------------------------
// Faits
// ---------------------------------------------------------------------------

/// Valeur d'un fait. Volontairement sans flottant (§15).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<Value>),
    /// Empreinte d'un secret, jamais le secret lui-même.
    Fingerprint([u8; 32]),
    /// L'absence est un fait, et souvent LE fait important (§3.2).
    Absent,
}

/// Triplet entité-attribut-valeur.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fact {
    pub entity: EntityId,
    pub attribute: Attribute,
    pub value: Value,
}

// ---------------------------------------------------------------------------
// Magasin : blobs, snapshots (calqués sur Git, §3.3)
// ---------------------------------------------------------------------------

/// Empreinte BLAKE3 (32 octets) d'un objet encodé canoniquement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlobHash(pub [u8; 32]);

/// Les faits + le brut d'UN collecteur sur UNE machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    pub collector: CollectorId,
    /// Artefact brut, tel que collecté, APRÈS expurgation.
    pub raw: Vec<u8>,
    /// Faits extraits, triés (ordre canonique).
    pub facts: Vec<Fact>,
}

/// Manifeste : machine + date + { collecteur → empreinte de blob }.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub asset: AssetId,
    pub at: Timestamp,
    pub blobs: BTreeMap<CollectorId, BlobHash>,
}

// ---------------------------------------------------------------------------
// Sérialisation canonique + empreintes
// ---------------------------------------------------------------------------

/// Erreurs du cœur.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("échec d'encodage canonique : {0}")]
    Encode(String),
    #[error("échec de décodage : {0}")]
    Decode(String),
}

/// Encode en CBOR canonique (déterministe). Jamais de JSON pour ce qui est haché.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ModelError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| ModelError::Encode(e.to_string()))?;
    Ok(out)
}

/// Décode depuis l'encodage canonique.
pub fn from_canonical_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ModelError> {
    ciborium::from_reader(bytes).map_err(|e| ModelError::Decode(e.to_string()))
}

/// Empreinte BLAKE3 de l'encodage canonique d'une valeur.
pub fn hash_canonical<T: Serialize>(value: &T) -> Result<BlobHash, ModelError> {
    let bytes = to_canonical_bytes(value)?;
    Ok(BlobHash(*blake3::hash(&bytes).as_bytes()))
}

impl BlobHash {
    /// Représentation hexadécimale (pour affichage et preuve).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}
