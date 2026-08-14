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
//! - [`rotation`] : rotation **journalisée** de la clé de signature
//!   ([`rotate_key`], [`current_key`], [`verify_chain_rotated`]) — la clé
//!   courante suit la chaîne, l'identité du journal reste la clé de genèse ;
//! - [`export_store`] : export vers un répertoire au format consommé par
//!   `constat-verify` en autonome (layout documenté dans [`export`]).
//!
//! ## Journaux nommés (multi-agents, §13 S8) — extension ADDITIVE
//!
//! Le trait [`Store`] porte *un* journal chaîné : celui de l'agent local (le
//! « journal par défaut »). Quand plusieurs agents — chacun sa clé Ed25519,
//! chacun sa chaîne `prev` — poussent vers le même magasin central, leurs
//! entrées ne peuvent pas se raccorder à une chaîne unique. D'où le trait
//! [`MultiJournalStore`] : des journaux **nommés par la clé publique du
//! signataire** ([`JournalId`]), un par agent, chacun avec sa propre chaîne
//! et sa propre racine. Les méthodes historiques de [`Store`] restent le
//! journal par défaut, sémantique strictement inchangée.

use constat_model::{Blob, BlobHash, ModelError, Snapshot, Timestamp};
use serde::{Deserialize, Serialize};

pub mod export;
pub mod journal;
pub mod memory;
pub mod purge;
pub mod redb_store;
pub mod rotation;
pub mod signer;

pub use export::{export_journal, export_store};
pub use journal::{append_signed, entry_hash, signable_bytes, verify_chain, ChainError};
pub use memory::MemoryStore;
pub use purge::{
    build_purge_blob, declared_purged, execute_plan, manifest_hash, parse_purge_blob, plan_purge,
    purge_older_than, PurgeDeclaration, PurgeError, PurgePlan, PurgeReport, PURGE_ASSET,
    PURGE_COLLECTOR,
};
pub use redb_store::RedbStore;
pub use rotation::{
    build_rotation_blob, current_key, genesis_key, parse_rotation_blob, rotate_key,
    verify_chain_rotated, RotationDeclaration, RotationError, RotationTrace, ROTATION_ASSET,
    ROTATION_COLLECTOR,
};
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

    /// Le snapshot est-il présent ? Méthode ADDITIVE (défaut fourni pour ne
    /// casser aucune implémentation existante) : les backends peuvent la
    /// spécialiser pour éviter un décodage complet. Introduite pour la purge
    /// de rétention (§16), qui doit distinguer « absent » d'« altéré ».
    fn has_snapshot(&self, hash: &BlobHash) -> Result<bool, StoreError> {
        match self.get_snapshot(hash) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn append_entry(&mut self, entry: &JournalEntry) -> Result<BlobHash, StoreError>;
    fn last_entry(&self) -> Result<Option<(BlobHash, JournalEntry)>, StoreError>;
    fn entries(&self) -> Result<Vec<(BlobHash, JournalEntry)>, StoreError>;

    /// Racine du journal : empreinte de la **dernière** entrée — c'est elle
    /// qu'on ancre à l'extérieur (§6.3). `None` si le journal est vide.
    fn root(&self) -> Result<Option<BlobHash>, StoreError> {
        Ok(self.last_entry()?.map(|(hash, _)| hash))
    }
}

/// Identifiant d'un journal nommé : la clé publique Ed25519 (32 octets) du
/// signataire de ce journal — la même valeur, au bit près, que
/// [`VerifyingKey::to_bytes`] et que le champ `agent_public_key` des poussées.
///
/// Le journal *est* la clé : il n'existe pas de journal nommé sans signataire,
/// et une clé désigne toujours exactement un journal.
pub type JournalId = [u8; 32];

/// Journaux nommés par la clé publique du signataire — l'extension
/// multi-agents de [`Store`] (§13 S8).
///
/// # Design retenu
///
/// Un sous-trait `MultiJournalStore: Store`, plutôt qu'une évolution de
/// [`Store`] : les crates existants (CLI, agent, vérificateur) compilent tels
/// quels contre `dyn Store`, et seuls les consommateurs multi-agents (le
/// serveur central) exigent le sous-trait. Tout est additif :
///
/// - les méthodes historiques de [`Store`] ([`Store::append_entry`],
///   [`Store::entries`], [`Store::last_entry`], [`Store::root`]) restent le
///   **journal par défaut** — celui de l'agent local, ou le journal historique
///   d'un magasin v0.1.0 rouvert — sémantique strictement inchangée ;
/// - les journaux nommés sont des chaînes indépendantes : chaque journal a sa
///   genèse, son chaînage `prev` et sa racine ([`MultiJournalStore::root_of`]),
///   vérifiables séparément par [`verify_chain`] avec la clé du journal ;
/// - les blobs et snapshots restent partagés (adressés par contenu) : seuls
///   les index de journal sont séparés.
///
/// # Propriété structurelle : une clé n'écrit que dans son propre journal
///
/// [`MultiJournalStore::append_entry_in`] **vérifie la signature Ed25519 de
/// l'entrée contre la clé du journal** avant toute écriture : une entrée
/// signée par la clé B ne peut pas entrer dans le journal de la clé A, même
/// avec un chaînage `prev` correct. Ce n'est pas une politique du serveur,
/// c'est une propriété du magasin. (Le journal par défaut, lui, garde son
/// contrat historique : le chaînage seul, la signature étant vérifiée par
/// [`verify_chain`] a posteriori.)
///
/// ```
/// use constat_model::Timestamp;
/// use constat_store::{MemoryStore, MultiJournalStore, Signer, Store};
///
/// let mut store = MemoryStore::new();
/// let signer = Signer::generate();
/// let journal = signer.verifying_key().to_bytes();
///
/// let entry = signer.sign_entry(None, vec![], Timestamp(1))?;
/// let root = store.append_entry_in(&journal, &entry)?;
/// assert_eq!(store.root_of(&journal)?, Some(root));
/// assert_eq!(store.journals()?, vec![journal]);
/// // Le journal par défaut, lui, reste vide : sémantique inchangée.
/// assert_eq!(store.root()?, None);
/// # Ok::<(), constat_store::StoreError>(())
/// ```
pub trait MultiJournalStore: Store {
    /// Ajoute une entrée au journal `journal`, après avoir vérifié :
    /// 1. que la **signature** de l'entrée vérifie avec la clé du journal
    ///    (propriété structurelle : une clé n'écrit que chez elle) ;
    /// 2. que `prev` référence la dernière entrée de **ce** journal
    ///    (`None` pour sa genèse).
    ///
    /// Retourne l'empreinte de l'entrée — la nouvelle racine de ce journal.
    ///
    /// # Erreurs
    /// [`StoreError::ChainBroken`] si la signature ne vérifie pas avec la clé
    /// du journal ou si `prev` ne se raccorde pas ; [`StoreError::Encoding`]
    /// si `journal` n'est pas une clé publique Ed25519 valide.
    fn append_entry_in(
        &mut self,
        journal: &JournalId,
        entry: &JournalEntry,
    ) -> Result<BlobHash, StoreError>;

    /// Toutes les entrées du journal `journal`, dans l'ordre d'append.
    /// Vide (et non une erreur) si ce journal n'existe pas.
    fn entries_of(&self, journal: &JournalId) -> Result<Vec<(BlobHash, JournalEntry)>, StoreError>;

    /// La dernière entrée du journal `journal`, `None` s'il est vide.
    fn last_entry_of(
        &self,
        journal: &JournalId,
    ) -> Result<Option<(BlobHash, JournalEntry)>, StoreError>;

    /// Les journaux nommés existants (au moins une entrée), triés par
    /// identifiant. Le journal par défaut n'y figure pas : il n'a pas de
    /// [`JournalId`] — il s'interroge par les méthodes historiques de
    /// [`Store`].
    fn journals(&self) -> Result<Vec<JournalId>, StoreError>;

    /// Racine du journal `journal` : empreinte de sa **dernière** entrée —
    /// c'est elle qu'on ancre à l'extérieur (§6.3). `None` s'il est vide.
    fn root_of(&self, journal: &JournalId) -> Result<Option<BlobHash>, StoreError> {
        Ok(self.last_entry_of(journal)?.map(|(hash, _)| hash))
    }
}

/// Suppression d'objets pour la purge de rétention journalisée (§16) —
/// extension ADDITIVE de [`Store`], sur le modèle de [`MultiJournalStore`].
///
/// # Design retenu
///
/// Un sous-trait plutôt qu'une évolution de [`Store`] : la suppression est un
/// pouvoir que la quasi-totalité des consommateurs (CLI en lecture, agent,
/// vérificateur) ne doit **jamais** détenir — le type dit qui peut supprimer.
/// Seule la purge ([`purge::purge_older_than`]) l'exige, et elle exige aussi
/// [`MultiJournalStore`] : pour décider qu'un objet n'est plus référencé, il
/// faut voir **tous** les journaux, nommés compris — un magasin qui ne sait
/// pas les énumérer ne peut pas purger sans risquer de trouer la chaîne d'un
/// autre signataire.
///
/// # Ce que ces méthodes ne touchent JAMAIS
///
/// Les **entrées de journal**. La chaîne est la preuve : elle ne rétrécit
/// jamais, quelle que soit la rétention. Seuls blobs et snapshots — le
/// contenu — sont supprimables, et uniquement après que la purge a été
/// **déclarée** dans une nouvelle entrée signée (voir [`purge`]).
pub trait PurgeableStore: MultiJournalStore {
    /// Supprime le blob `hash` s'il existe. `Ok(true)` s'il existait,
    /// `Ok(false)` sinon (idempotent). Le journal n'est pas modifié.
    fn delete_blob(&mut self, hash: &BlobHash) -> Result<bool, StoreError>;

    /// Supprime le snapshot `hash` s'il existe. `Ok(true)` s'il existait,
    /// `Ok(false)` sinon (idempotent). Le journal n'est pas modifié.
    fn delete_snapshot(&mut self, hash: &BlobHash) -> Result<bool, StoreError>;
}
