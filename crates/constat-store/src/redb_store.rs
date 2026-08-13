//! Implémentation persistante du [`Store`] : fichier unique transactionnel (redb).
//!
//! ## Tables
//!
//! | Table              | Clé                                    | Valeur                                        |
//! |--------------------|----------------------------------------|-----------------------------------------------|
//! | `blobs`            | empreinte BLAKE3 (32 o)                | CBOR canonique du [`Blob`], **compressé zstd** |
//! | `snapshots`        | empreinte BLAKE3 (32 o)                | CBOR canonique du [`Snapshot`]                |
//! | `journal`          | index séquentiel (`u64`)               | empreinte de l'entrée (32 o)                  |
//! | `entries`          | empreinte de l'entrée                  | CBOR canonique de la [`JournalEntry`]         |
//! | `journaux_nommes`  | (clé du signataire 32 o, index `u64`)  | empreinte de l'entrée (32 o)                  |
//!
//! ## Journaux nommés et migration (§13 S8)
//!
//! `journaux_nommes` porte les index des journaux nommés par la clé publique
//! du signataire ([`crate::MultiJournalStore`]) ; le contenu des entrées reste
//! dans `entries`, partagé et adressé par contenu. Un magasin v0.1.0 s'ouvre
//! tel quel : la table manquante est simplement créée vide à l'ouverture, et
//! le journal historique (`journal`) devient le journal par défaut — aucune
//! donnée n'est déplacée ni réécrite.
//!
//! ## Compression
//!
//! Le contenu des blobs (artefacts bruts + faits) est compressé en zstd avant
//! écriture : les configurations texte compressent d'un facteur dix (§9).
//! L'empreinte est toujours celle des octets canoniques **non compressés** —
//! la compression est un détail de stockage, invisible pour la preuve.
//!
//! ## Déduplication
//!
//! `put_blob`/`put_snapshot` d'un objet déjà présent n'ouvrent **aucune
//! transaction d'écriture** : le fichier n'est pas modifié d'un octet, et
//! l'empreinte existante est retournée. C'est ce qui rend viable une rétention
//! de trois ans sur un parc stable (§3.3) : une collecte quotidienne sans
//! changement n'écrit que des références.
//!
//! ## Intégrité en lecture
//!
//! `get_blob` et `get_snapshot` recalculent l'empreinte de l'objet décodé et
//! la comparent à celle demandée : un octet altéré dans le fichier produit une
//! erreur [`StoreError::ChainBroken`] (ou une erreur de décodage si la
//! compression elle-même est corrompue). La vérification du journal, elle,
//! passe par [`crate::journal::verify_chain`].

use std::path::Path;

use constat_model::{
    from_canonical_bytes, hash_canonical, to_canonical_bytes, Blob, BlobHash, Snapshot,
};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::journal::check_journal_signature;
use crate::{JournalEntry, JournalId, MultiJournalStore, Store, StoreError};

/// Table des blobs : empreinte → CBOR canonique compressé zstd.
const BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");
/// Table des snapshots : empreinte → CBOR canonique.
const SNAPSHOTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("snapshots");
/// Journal : index séquentiel → empreinte d'entrée.
const JOURNAL: TableDefinition<u64, &[u8]> = TableDefinition::new("journal");
/// Entrées du journal : empreinte d'entrée → CBOR canonique de l'entrée.
const ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entries");
/// Journaux nommés : (clé publique du signataire, index séquentiel dans ce
/// journal) → empreinte d'entrée. Le contenu des entrées reste dans `entries`.
const NAMED_JOURNALS: TableDefinition<(&[u8; 32], u64), &[u8; 32]> =
    TableDefinition::new("journaux_nommes");

/// Niveau de compression zstd (3 = défaut : bon compromis débit/ratio).
const ZSTD_LEVEL: i32 = 3;

/// Magasin persistant : un seul fichier, transactionnel, pur Rust (§9).
pub struct RedbStore {
    db: Database,
}

impl std::fmt::Debug for RedbStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbStore").finish_non_exhaustive()
    }
}

fn backend(e: impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn hash32(bytes: &[u8], what: &str) -> Result<BlobHash, StoreError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::Encoding(format!("empreinte {what} de taille invalide")))?;
    Ok(BlobHash(arr))
}

impl RedbStore {
    /// Ouvre (ou crée) le magasin au chemin donné. Les tables sont créées si
    /// elles n'existent pas encore.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(backend)?;
        // Créer les tables si nécessaire : les transactions de lecture ne
        // peuvent pas ouvrir une table inexistante. On ne lance la
        // transaction d'écriture que si une table manque, pour que la simple
        // réouverture d'un magasin existant ne modifie pas le fichier.
        // `journaux_nommes` est apparue après la v0.1.0 : sur un magasin
        // existant elle est simplement créée vide — migration transparente,
        // le journal historique devient le journal par défaut, aucune donnée
        // n'est déplacée.
        let needs_init = {
            let tx = db.begin_read().map_err(backend)?;
            tx.open_table(BLOBS).is_err()
                || tx.open_table(SNAPSHOTS).is_err()
                || tx.open_table(JOURNAL).is_err()
                || tx.open_table(ENTRIES).is_err()
                || tx.open_table(NAMED_JOURNALS).is_err()
        };
        if needs_init {
            let tx = db.begin_write().map_err(backend)?;
            {
                tx.open_table(BLOBS).map_err(backend)?;
                tx.open_table(SNAPSHOTS).map_err(backend)?;
                tx.open_table(JOURNAL).map_err(backend)?;
                tx.open_table(ENTRIES).map_err(backend)?;
                tx.open_table(NAMED_JOURNALS).map_err(backend)?;
            }
            tx.commit().map_err(backend)?;
        }
        Ok(Self { db })
    }

    /// Nombre de blobs distincts stockés (utile pour tester la déduplication).
    pub fn blob_count(&self) -> Result<u64, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let table = tx.open_table(BLOBS).map_err(backend)?;
        table.len().map_err(backend)
    }

    /// Nombre de snapshots distincts stockés.
    pub fn snapshot_count(&self) -> Result<u64, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let table = tx.open_table(SNAPSHOTS).map_err(backend)?;
        table.len().map_err(backend)
    }

    /// Nombre d'entrées du journal.
    pub fn entry_count(&self) -> Result<u64, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let table = tx.open_table(JOURNAL).map_err(backend)?;
        table.len().map_err(backend)
    }

    /// Lit une valeur brute dans une table adressée par empreinte.
    fn get_raw(
        &self,
        def: TableDefinition<'_, &[u8], &[u8]>,
        hash: &BlobHash,
        what: &str,
    ) -> Result<Vec<u8>, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let table = tx.open_table(def).map_err(backend)?;
        let guard = table
            .get(hash.0.as_slice())
            .map_err(backend)?
            .ok_or_else(|| StoreError::NotFound(format!("{what} {}", hash.to_hex())))?;
        Ok(guard.value().to_vec())
    }

    /// Teste la présence d'une clé sans lire la valeur.
    fn contains(
        &self,
        def: TableDefinition<'_, &[u8], &[u8]>,
        hash: &BlobHash,
    ) -> Result<bool, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let table = tx.open_table(def).map_err(backend)?;
        Ok(table.get(hash.0.as_slice()).map_err(backend)?.is_some())
    }

    /// Insère une valeur dans une table adressée par empreinte.
    fn insert_raw(
        &self,
        def: TableDefinition<'_, &[u8], &[u8]>,
        hash: &BlobHash,
        value: &[u8],
    ) -> Result<(), StoreError> {
        let tx = self.db.begin_write().map_err(backend)?;
        {
            let mut table = tx.open_table(def).map_err(backend)?;
            table.insert(hash.0.as_slice(), value).map_err(backend)?;
        }
        tx.commit().map_err(backend)
    }

    /// Décode une entrée du journal depuis ses octets canoniques stockés.
    fn decode_entry(bytes: &[u8]) -> Result<JournalEntry, StoreError> {
        from_canonical_bytes(bytes).map_err(StoreError::from)
    }
}

impl Store for RedbStore {
    fn put_blob(&mut self, blob: &Blob) -> Result<BlobHash, StoreError> {
        let hash = hash_canonical(blob)?;
        // Déduplication : objet déjà présent → aucune écriture, on retourne
        // l'empreinte existante.
        if self.contains(BLOBS, &hash)? {
            return Ok(hash);
        }
        let bytes = to_canonical_bytes(blob)?;
        let compressed = zstd::stream::encode_all(bytes.as_slice(), ZSTD_LEVEL)
            .map_err(|e| StoreError::Backend(format!("compression zstd : {e}")))?;
        self.insert_raw(BLOBS, &hash, &compressed)?;
        Ok(hash)
    }

    fn get_blob(&self, hash: &BlobHash) -> Result<Blob, StoreError> {
        let compressed = self.get_raw(BLOBS, hash, "blob")?;
        let bytes = zstd::stream::decode_all(compressed.as_slice()).map_err(|e| {
            StoreError::ChainBroken(format!(
                "blob {} : décompression impossible (contenu altéré ?) : {e}",
                hash.to_hex()
            ))
        })?;
        let blob: Blob = from_canonical_bytes(&bytes).map_err(|e| {
            StoreError::ChainBroken(format!(
                "blob {} : décodage impossible (contenu altéré ?) : {e}",
                hash.to_hex()
            ))
        })?;
        // Contrôle d'intégrité : l'empreinte recalculée doit être celle demandée.
        let actual = hash_canonical(&blob)?;
        if actual != *hash {
            return Err(StoreError::ChainBroken(format!(
                "blob altéré : empreinte demandée {}, recalculée {}",
                hash.to_hex(),
                actual.to_hex()
            )));
        }
        Ok(blob)
    }

    fn has_blob(&self, hash: &BlobHash) -> Result<bool, StoreError> {
        self.contains(BLOBS, hash)
    }

    fn put_snapshot(&mut self, snapshot: &Snapshot) -> Result<BlobHash, StoreError> {
        let hash = hash_canonical(snapshot)?;
        if self.contains(SNAPSHOTS, &hash)? {
            return Ok(hash);
        }
        let bytes = to_canonical_bytes(snapshot)?;
        self.insert_raw(SNAPSHOTS, &hash, &bytes)?;
        Ok(hash)
    }

    fn get_snapshot(&self, hash: &BlobHash) -> Result<Snapshot, StoreError> {
        let bytes = self.get_raw(SNAPSHOTS, hash, "snapshot")?;
        let snapshot: Snapshot = from_canonical_bytes(&bytes).map_err(|e| {
            StoreError::ChainBroken(format!(
                "snapshot {} : décodage impossible (contenu altéré ?) : {e}",
                hash.to_hex()
            ))
        })?;
        let actual = hash_canonical(&snapshot)?;
        if actual != *hash {
            return Err(StoreError::ChainBroken(format!(
                "snapshot altéré : empreinte demandée {}, recalculée {}",
                hash.to_hex(),
                actual.to_hex()
            )));
        }
        Ok(snapshot)
    }

    fn append_entry(&mut self, entry: &JournalEntry) -> Result<BlobHash, StoreError> {
        let last = self.last_entry()?.map(|(hash, _)| hash);
        if entry.prev != last {
            return Err(StoreError::ChainBroken(format!(
                "append refusé : `prev` = {:?} mais la dernière entrée est {:?}",
                entry.prev.map(|h| h.to_hex()),
                last.map(|h| h.to_hex()),
            )));
        }
        // Empreinte de l'entrée COMPLÈTE (signature incluse).
        let hash = hash_canonical(entry)?;
        let bytes = to_canonical_bytes(entry)?;

        let tx = self.db.begin_write().map_err(backend)?;
        {
            let mut entries = tx.open_table(ENTRIES).map_err(backend)?;
            entries
                .insert(hash.0.as_slice(), bytes.as_slice())
                .map_err(backend)?;
            let mut journal = tx.open_table(JOURNAL).map_err(backend)?;
            let index = journal.len().map_err(backend)?;
            journal.insert(index, hash.0.as_slice()).map_err(backend)?;
        }
        tx.commit().map_err(backend)?;
        Ok(hash)
    }

    fn last_entry(&self) -> Result<Option<(BlobHash, JournalEntry)>, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let journal = tx.open_table(JOURNAL).map_err(backend)?;
        let Some((_, hash_guard)) = journal.last().map_err(backend)? else {
            return Ok(None);
        };
        let hash = hash32(hash_guard.value(), "d'entrée")?;
        drop(hash_guard);
        let entries = tx.open_table(ENTRIES).map_err(backend)?;
        let guard = entries
            .get(hash.0.as_slice())
            .map_err(backend)?
            .ok_or_else(|| {
                StoreError::ChainBroken(format!(
                    "le journal référence l'entrée {} qui n'existe pas",
                    hash.to_hex()
                ))
            })?;
        let entry = Self::decode_entry(guard.value())?;
        Ok(Some((hash, entry)))
    }

    fn entries(&self) -> Result<Vec<(BlobHash, JournalEntry)>, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let journal = tx.open_table(JOURNAL).map_err(backend)?;
        let entries = tx.open_table(ENTRIES).map_err(backend)?;
        let mut out = Vec::new();
        for item in journal.iter().map_err(backend)? {
            let (_, hash_guard) = item.map_err(backend)?;
            let hash = hash32(hash_guard.value(), "d'entrée")?;
            let guard = entries
                .get(hash.0.as_slice())
                .map_err(backend)?
                .ok_or_else(|| {
                    StoreError::ChainBroken(format!(
                        "le journal référence l'entrée {} qui n'existe pas",
                        hash.to_hex()
                    ))
                })?;
            let entry = Self::decode_entry(guard.value())?;
            out.push((hash, entry));
        }
        Ok(out)
    }
}

impl MultiJournalStore for RedbStore {
    fn append_entry_in(
        &mut self,
        journal: &JournalId,
        entry: &JournalEntry,
    ) -> Result<BlobHash, StoreError> {
        // Propriété structurelle : l'entrée doit être signée par la clé de
        // CE journal — une clé ne peut jamais écrire dans celui d'une autre.
        check_journal_signature(journal, entry)?;

        // Empreinte de l'entrée COMPLÈTE (signature incluse).
        let hash = hash_canonical(entry)?;
        let bytes = to_canonical_bytes(entry)?;

        // Une seule transaction d'écriture : la lecture du dernier maillon,
        // la vérification du chaînage et l'insertion sont atomiques.
        let tx = self.db.begin_write().map_err(backend)?;
        {
            let mut named = tx.open_table(NAMED_JOURNALS).map_err(backend)?;
            let (next_index, last) = {
                let mut range = named
                    .range((journal, 0u64)..=(journal, u64::MAX))
                    .map_err(backend)?;
                match range.next_back() {
                    Some(item) => {
                        let (key_guard, value_guard) = item.map_err(backend)?;
                        let (_, index) = key_guard.value();
                        (index + 1, Some(BlobHash(*value_guard.value())))
                    }
                    None => (0, None),
                }
            };
            if entry.prev != last {
                // La transaction est abandonnée à la sortie (drop = abort).
                return Err(StoreError::ChainBroken(format!(
                    "append refusé : `prev` = {:?} mais la dernière entrée du journal est {:?}",
                    entry.prev.map(|h| h.to_hex()),
                    last.map(|h| h.to_hex()),
                )));
            }
            let mut entries = tx.open_table(ENTRIES).map_err(backend)?;
            entries
                .insert(hash.0.as_slice(), bytes.as_slice())
                .map_err(backend)?;
            named
                .insert((journal, next_index), &hash.0)
                .map_err(backend)?;
        }
        tx.commit().map_err(backend)?;
        Ok(hash)
    }

    fn entries_of(&self, journal: &JournalId) -> Result<Vec<(BlobHash, JournalEntry)>, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let named = tx.open_table(NAMED_JOURNALS).map_err(backend)?;
        let entries = tx.open_table(ENTRIES).map_err(backend)?;
        let mut out = Vec::new();
        for item in named
            .range((journal, 0u64)..=(journal, u64::MAX))
            .map_err(backend)?
        {
            let (_, value_guard) = item.map_err(backend)?;
            let hash = BlobHash(*value_guard.value());
            let guard = entries
                .get(hash.0.as_slice())
                .map_err(backend)?
                .ok_or_else(|| {
                    StoreError::ChainBroken(format!(
                        "le journal référence l'entrée {} qui n'existe pas",
                        hash.to_hex()
                    ))
                })?;
            let entry = Self::decode_entry(guard.value())?;
            out.push((hash, entry));
        }
        Ok(out)
    }

    fn last_entry_of(
        &self,
        journal: &JournalId,
    ) -> Result<Option<(BlobHash, JournalEntry)>, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let named = tx.open_table(NAMED_JOURNALS).map_err(backend)?;
        let hash = {
            let mut range = named
                .range((journal, 0u64)..=(journal, u64::MAX))
                .map_err(backend)?;
            match range.next_back() {
                Some(item) => BlobHash(*item.map_err(backend)?.1.value()),
                None => return Ok(None),
            }
        };
        let entries = tx.open_table(ENTRIES).map_err(backend)?;
        let guard = entries
            .get(hash.0.as_slice())
            .map_err(backend)?
            .ok_or_else(|| {
                StoreError::ChainBroken(format!(
                    "le journal référence l'entrée {} qui n'existe pas",
                    hash.to_hex()
                ))
            })?;
        let entry = Self::decode_entry(guard.value())?;
        Ok(Some((hash, entry)))
    }

    fn journals(&self) -> Result<Vec<JournalId>, StoreError> {
        let tx = self.db.begin_read().map_err(backend)?;
        let named = tx.open_table(NAMED_JOURNALS).map_err(backend)?;
        let mut out: Vec<JournalId> = Vec::new();
        // Les clés sont triées (journal, index) : il suffit de relever chaque
        // premier composant distinct — l'ordre de sortie est déterministe.
        for item in named.iter().map_err(backend)? {
            let (key_guard, _) = item.map_err(backend)?;
            let (journal, _) = key_guard.value();
            if out.last() != Some(journal) {
                out.push(*journal);
            }
        }
        Ok(out)
    }
}
