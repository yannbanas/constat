//! Implémentation en mémoire du [`Store`] — pour les tests de tout le workspace.
//!
//! Non persistant, non compressé : le but est d'avoir un double de test fidèle
//! au contrat (mêmes empreintes, même chaînage, mêmes erreurs) sans toucher au
//! disque. Toutes les structures internes sont des `BTreeMap` (§15 : ordre
//! déterministe, jamais de `HashMap`).

use std::collections::BTreeMap;

use constat_model::{hash_canonical, Blob, BlobHash, Snapshot};

use crate::{JournalEntry, Store, StoreError};

/// Magasin en mémoire, adressé par contenu.
///
/// ```
/// use constat_model::{Blob, CollectorId};
/// use constat_store::{MemoryStore, Store};
///
/// let mut store = MemoryStore::new();
/// let blob = Blob {
///     collector: CollectorId("linux.sshd".into()),
///     raw: b"PermitRootLogin no\n".to_vec(),
///     facts: vec![],
/// };
/// let hash = store.put_blob(&blob)?;
/// assert_eq!(store.get_blob(&hash)?, blob);
/// // Déduplication : re-poser le même objet retourne la même empreinte.
/// assert_eq!(store.put_blob(&blob)?, hash);
/// assert_eq!(store.blob_count(), 1);
/// # Ok::<(), constat_store::StoreError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    blobs: BTreeMap<BlobHash, Blob>,
    snapshots: BTreeMap<BlobHash, Snapshot>,
    journal: Vec<(BlobHash, JournalEntry)>,
}

impl MemoryStore {
    /// Crée un magasin vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// Nombre de blobs distincts stockés (utile pour tester la déduplication).
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    /// Nombre de snapshots distincts stockés.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Nombre d'entrées du journal.
    pub fn entry_count(&self) -> usize {
        self.journal.len()
    }
}

impl Store for MemoryStore {
    fn put_blob(&mut self, blob: &Blob) -> Result<BlobHash, StoreError> {
        let hash = hash_canonical(blob)?;
        // Déduplication : si l'objet est déjà présent, on ne réécrit rien.
        self.blobs.entry(hash).or_insert_with(|| blob.clone());
        Ok(hash)
    }

    fn get_blob(&self, hash: &BlobHash) -> Result<Blob, StoreError> {
        self.blobs
            .get(hash)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("blob {}", hash.to_hex())))
    }

    fn has_blob(&self, hash: &BlobHash) -> Result<bool, StoreError> {
        Ok(self.blobs.contains_key(hash))
    }

    fn put_snapshot(&mut self, snapshot: &Snapshot) -> Result<BlobHash, StoreError> {
        let hash = hash_canonical(snapshot)?;
        self.snapshots
            .entry(hash)
            .or_insert_with(|| snapshot.clone());
        Ok(hash)
    }

    fn get_snapshot(&self, hash: &BlobHash) -> Result<Snapshot, StoreError> {
        self.snapshots
            .get(hash)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("snapshot {}", hash.to_hex())))
    }

    fn append_entry(&mut self, entry: &JournalEntry) -> Result<BlobHash, StoreError> {
        let last = self.journal.last().map(|(hash, _)| *hash);
        if entry.prev != last {
            return Err(StoreError::ChainBroken(format!(
                "append refusé : `prev` = {:?} mais la dernière entrée est {:?}",
                entry.prev.map(|h| h.to_hex()),
                last.map(|h| h.to_hex()),
            )));
        }
        // Empreinte de l'entrée COMPLÈTE (signature incluse) — c'est elle qui
        // sert de maillon `prev` à l'entrée suivante.
        let hash = hash_canonical(entry)?;
        self.journal.push((hash, entry.clone()));
        Ok(hash)
    }

    fn last_entry(&self) -> Result<Option<(BlobHash, JournalEntry)>, StoreError> {
        Ok(self.journal.last().cloned())
    }

    fn entries(&self) -> Result<Vec<(BlobHash, JournalEntry)>, StoreError> {
        Ok(self.journal.clone())
    }
}
