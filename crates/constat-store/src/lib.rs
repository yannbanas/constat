//! # constat-store
//!
//! Magasin adressé par contenu + journal Merkle (§3.3, §6).
//! Le backend est derrière un trait → testable en mémoire.
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.

use constat_model::{Blob, BlobHash, Snapshot, Timestamp};
use serde::{Deserialize, Serialize};

/// Entrée du journal : empreinte de l'entrée précédente + empreintes de
/// snapshots + date + signature (§3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// `None` pour la première entrée (genèse).
    pub prev: Option<BlobHash>,
    pub snapshots: Vec<BlobHash>,
    pub at: Timestamp,
    /// Signature Ed25519 de l'encodage canonique de l'entrée sans ce champ.
    pub signature: Vec<u8>,
}

/// Erreurs du magasin.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("objet introuvable : {0}")]
    NotFound(String),
    #[error("chaîne rompue : {0}")]
    ChainBroken(String),
    #[error("erreur d'encodage : {0}")]
    Encoding(String),
    #[error("erreur de backend : {0}")]
    Backend(String),
}

/// Magasin adressé par contenu. Deux implémentations attendues :
/// `MemoryStore` (tests) et `RedbStore` (fichier unique, transactionnel).
pub trait Store {
    fn put_blob(&mut self, blob: &Blob) -> Result<BlobHash, StoreError>;
    fn get_blob(&self, hash: &BlobHash) -> Result<Blob, StoreError>;
    fn has_blob(&self, hash: &BlobHash) -> Result<bool, StoreError>;

    fn put_snapshot(&mut self, snapshot: &Snapshot) -> Result<BlobHash, StoreError>;
    fn get_snapshot(&self, hash: &BlobHash) -> Result<Snapshot, StoreError>;

    fn append_entry(&mut self, entry: &JournalEntry) -> Result<BlobHash, StoreError>;
    fn last_entry(&self) -> Result<Option<(BlobHash, JournalEntry)>, StoreError>;
    fn entries(&self) -> Result<Vec<(BlobHash, JournalEntry)>, StoreError>;
}
