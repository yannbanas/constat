//! # constat-store
//!
//! Magasin adressé par contenu + journal Merkle (§3.3, §6).
//! Le backend est derrière un trait → testable en mémoire.
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.
//!
//! Deux implémentations du trait [`Store`] :
//! - [`MemoryStore`] : en mémoire (`BTreeMap`), pour les tests de tout le workspace ;
//! - [`RedbStore`] : fichier unique transactionnel (redb), contenu des blobs
//!   compressé en zstd, déduplication par empreinte.
//!
//! Autour du magasin :
//! - [`Signer`] : clé Ed25519 qui signe les entrées du journal ;
//! - [`journal`] : construction, signature et vérification de la chaîne
//!   ([`append_signed`], [`verify_chain`]) — lire son rustdoc pour ce que la
//!   chaîne ne protège **pas** (§6.2) ;
//! - [`export_store`] : export vers un répertoire au format consommé par
//!   `constat-verify` en autonome (layout documenté dans [`export`]).

use constat_model::{Blob, BlobHash, ModelError, Snapshot, Timestamp};
use serde::{Deserialize, Serialize};

pub mod export;
pub mod journal;
pub mod memory;
pub mod redb_store;
pub mod signer;

pub use export::export_store;
pub use journal::{append_signed, entry_hash, signable_bytes, verify_chain, ChainError};
pub use memory::MemoryStore;
pub use redb_store::RedbStore;
pub use signer::Signer;

// Ré-exports pour que les crates aval (constat-verify, constat-agent, constat-cli)
// n'aient pas à dépendre directement de ed25519-dalek.
pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

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

impl From<ModelError> for StoreError {
    fn from(e: ModelError) -> Self {
        StoreError::Encoding(e.to_string())
    }
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

    /// Racine du journal : empreinte de la **dernière** entrée — c'est elle
    /// qu'on ancre à l'extérieur (§6.3). `None` si le journal est vide.
    fn root(&self) -> Result<Option<BlobHash>, StoreError> {
        Ok(self.last_entry()?.map(|(hash, _)| hash))
    }
}
