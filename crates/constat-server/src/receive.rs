//! Réception des poussées d'agents — le contrat, et son implémentation
//! sur le magasin ([`StoreReceiver`]).
//!
//! # Propriété d'architecture (§17) : aucun chemin de retour
//!
//! Compromettre ce serveur ne donne **aucun** moyen d'agir sur les machines
//! auditées, parce qu'il n'en a aucun : ce n'est pas un réglage, c'est une
//! propriété d'architecture, tenue par construction dans ce module.
//!
//! - Le serveur n'initie **jamais** de connexion vers un agent : les agents
//!   poussent en sortant, le serveur ne fait qu'accepter.
//! - La réponse à une poussée est un [`Receipt`] — des compteurs et une
//!   empreinte. Elle ne contient ni commande, ni configuration, ni code :
//!   il n'existe aucun type dans cette interface qui puisse transporter une
//!   instruction vers l'agent, et il doit le rester.
//! - Le serveur ne connaît des agents que leur certificat client et leur
//!   clé publique de signature.
//!
//! # Protocole (miroir de `constat-agent/src/push.rs`)
//!
//! `POST /v1/pousse` sur liaison mTLS (certificat client obligatoire,
//! vérifié contre l'autorité `--client-ca` ; pas de repli en clair).
//! Corps : encodage canonique CBOR d'un [`PushBatch`]. La réception est
//! idempotente : les objets sont adressés par contenu, un blob déjà connu
//! est simplement ignoré.
//!
//! À la réception, [`StoreReceiver`] :
//! 1. vérifie que la clé de l'agent est **autorisée** ([`AgentPolicy`]) —
//!    clé absente d'une allowlist = refus avant toute écriture ;
//! 2. recalcule l'empreinte de chaque objet du lot — une empreinte annoncée
//!    (snapshot → blob, entrée → snapshot) qui ne se recalcule pas à
//!    l'identique est refusée : un objet altéré en vol ne rentre pas ;
//! 3. exige un **graphe fermé** : chaque blob du lot est référencé par un
//!    snapshot du lot, chaque snapshot par une entrée — un objet que rien
//!    n'annonce (l'autre visage de l'altération en vol) est refusé aussi ;
//! 4. vérifie que chaque entrée de journal est signée par la clé publique
//!    annoncée, et que la chaîne `prev` se raccorde au **journal de cette
//!    clé** déjà stocké ;
//! 5. valide **tout** le lot avant d'écrire quoi que ce soit : un lot refusé
//!    ne laisse aucune écriture partielle, et l'agent peut le repousser tel
//!    quel une fois la cause corrigée (idempotence).
//!
//! # Multi-agents : un journal par clé (§13 S8)
//!
//! Chaque agent a sa clé Ed25519 et sa propre chaîne `prev`. Le lot est donc
//! rangé dans le **journal nommé de sa clé** (`agent_public_key`, voir
//! [`constat_store::MultiJournalStore`]) : deux agents peuvent pousser en
//! entrelacé sans se marcher dessus, chaque chaîne restant vérifiable
//! indépendamment. Une clé ne peut jamais écrire dans le journal d'une autre :
//! chaque entrée est vérifiée contre la clé annoncée ici, et le magasin
//! lui-même revérifie la signature à l'append — propriété structurelle,
//! pas une politique.
//!
//! La couche transport (mTLS + HTTP) est dans [`crate::serve`] ; elle remet
//! le lot décodé à cette interface, qui reste ainsi testable sans réseau.

use std::collections::BTreeSet;
use std::path::Path;

use constat_model::{blob_hash, snapshot_hash, Blob, BlobHash, Snapshot};
use constat_store::{
    entry_hash, signable_bytes, JournalEntry, JournalId, MultiJournalStore, Signature, StoreError,
    VerifyingKey,
};
use serde::{Deserialize, Serialize};

/// Lot poussé par un agent. Miroir exact de la structure émise par
/// `constat-agent` (voir `crates/constat-agent/src/push.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushBatch {
    /// Clé publique Ed25519 de l'agent émetteur (32 octets).
    pub agent_public_key: [u8; 32],
    /// Machine concernée.
    pub asset: String,
    /// Blobs nouveaux, déjà expurgés à la source (§7.2).
    pub blobs: Vec<Blob>,
    /// Snapshots nouveaux.
    pub snapshots: Vec<Snapshot>,
    /// Entrées de journal signées, dans l'ordre de la chaîne.
    pub entries: Vec<JournalEntry>,
}

/// Accusé de réception. Des compteurs et des empreintes, rien d'autre :
/// aucune instruction ne peut transiter vers l'agent par ce type (§17).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Objets acceptés (les doublons idempotents comptent comme acceptés).
    pub accepted_blobs: usize,
    pub accepted_snapshots: usize,
    pub accepted_entries: usize,
    /// Empreinte de la dernière entrée connue côté serveur pour cet agent —
    /// permet à l'agent de savoir où reprendre après une coupure.
    pub last_entry: Option<BlobHash>,
    /// Racine du **journal de cette clé** après réception (empreinte de sa
    /// dernière entrée, celle qu'on ancre §6.3). Identique à `last_entry` —
    /// champ explicite pour l'inventaire multi-agents. Toujours rien
    /// d'exécutable.
    pub journal_root: Option<BlobHash>,
}

/// Erreurs de réception.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
    /// La clé publique de l'agent n'est pas dans la liste des agents
    /// autorisés ([`AgentPolicy::Allowlist`]) : refus **avant toute
    /// écriture** — la couche transport répond `403`.
    #[error("agent non autorisé : clé {0} absente de la liste des agents autorisés")]
    Forbidden(String),
    /// Une signature d'entrée ne correspond pas à la clé annoncée.
    #[error("signature d'entrée invalide : {0}")]
    BadSignature(String),
    /// La chaîne `prev` ne se raccorde pas à l'existant : troncature ou
    /// réécriture — à consigner, jamais à réparer silencieusement (§6).
    #[error("chaîne de journal incohérente : {0}")]
    ChainMismatch(String),
    /// Une empreinte référencée est introuvable dans le lot et le magasin.
    #[error("référence non résoluble : {0}")]
    DanglingReference(String),
    /// Un blob du lot n'est pas en forme canonique (faits non triés ou
    /// dupliqués) : son empreinte serait ambiguë, il est refusé.
    #[error("blob non canonique : {0}")]
    NotCanonical(String),
    /// Erreur du magasin serveur.
    #[error("erreur du magasin : {0}")]
    Store(#[from] constat_store::StoreError),
}

/// Erreurs de lecture de la liste des agents autorisés.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum PolicyError {
    /// Le fichier n'a pas pu être lu.
    #[error("liste d'agents autorisés illisible ({path}) : {detail}")]
    #[diagnostic(help(
        "--allowed-agents attend un fichier texte : une clé publique Ed25519 \
         en hexadécimal (64 caractères) par ligne, commentaires avec #"
    ))]
    Unreadable { path: String, detail: String },
    /// Une ligne n'est pas une clé publique hexadécimale de 64 caractères.
    #[error(
        "liste d'agents autorisés ({path}), ligne {line} : « {text} » n'est pas \
         une clé publique hexadécimale de 64 caractères"
    )]
    BadKey {
        path: String,
        line: usize,
        text: String,
    },
}

/// Qui a le droit de pousser — décidé **avant toute écriture**.
///
/// - [`AgentPolicy::Tofu`] (défaut, sans `--allowed-agents`) :
///   premier-arrivé-enregistré — toute clé peut créer *son* journal. La
///   confiance est posée à la première poussée, mais chaque clé reste
///   ensuite verrouillée sur son propre journal : une clé ne peut jamais
///   écrire dans le journal d'une autre (propriété structurelle du magasin,
///   voir [`constat_store::MultiJournalStore::append_entry_in`]).
/// - [`AgentPolicy::Allowlist`] (avec `--allowed-agents <fichier>`) : seules
///   les clés listées peuvent pousser ; clé absente = `403`, refusé avant
///   toute écriture.
#[derive(Debug, Clone, Default)]
pub enum AgentPolicy {
    /// Premier-arrivé-enregistré : toute clé peut créer son journal.
    #[default]
    Tofu,
    /// Seules les clés listées peuvent pousser.
    Allowlist(BTreeSet<JournalId>),
}

impl AgentPolicy {
    /// La clé `key` a-t-elle le droit de pousser ?
    pub fn allows(&self, key: &JournalId) -> bool {
        match self {
            AgentPolicy::Tofu => true,
            AgentPolicy::Allowlist(keys) => keys.contains(key),
        }
    }

    /// Charge une allowlist depuis un fichier texte : une clé publique
    /// Ed25519 en hexadécimal (64 caractères) par ligne ; lignes vides et
    /// commentaires `#` (pleine ligne ou fin de ligne) ignorés.
    ///
    /// Un fichier vide produit une allowlist vide : **tout** agent est
    /// refusé — c'est voulu, une liste explicite ne s'improvise pas.
    pub fn from_allowlist_file(path: &Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|e| PolicyError::Unreadable {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        let mut keys = BTreeSet::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let bad = || PolicyError::BadKey {
                path: path.display().to_string(),
                line: index + 1,
                text: line.to_string(),
            };
            let bytes = hex::decode(line).map_err(|_| bad())?;
            let key: JournalId = bytes.try_into().map_err(|_| bad())?;
            keys.insert(key);
        }
        Ok(AgentPolicy::Allowlist(keys))
    }
}

/// Ce que fait le serveur d'un lot accepté par la couche mTLS.
///
/// La couche transport (rustls) authentifie l'agent par son certificat
/// client puis remet le lot décodé à cette interface — qui reste ainsi
/// testable sans réseau.
pub trait Receiver {
    /// Vérifie et range un lot. Idempotent.
    fn receive(&mut self, batch: PushBatch) -> Result<Receipt, ReceiveError>;
}

/// Implémentation de [`Receiver`] sur un magasin `constat-store`.
///
/// Valide tout le lot (autorisation, empreintes recalculées, signatures,
/// chaînage) avant la moindre écriture : un lot refusé ne modifie pas le
/// magasin.
///
/// Multi-agents : le lot est rangé dans le **journal nommé de la clé**
/// `agent_public_key` ([`MultiJournalStore`]) — un journal par agent, le
/// journal par défaut du magasin restant intact.
pub struct StoreReceiver<'a> {
    store: &'a mut dyn MultiJournalStore,
    policy: AgentPolicy,
}

impl<'a> StoreReceiver<'a> {
    /// Enveloppe un magasin ouvert en écriture, en mode
    /// premier-arrivé-enregistré ([`AgentPolicy::Tofu`]).
    pub fn new(store: &'a mut dyn MultiJournalStore) -> Self {
        Self {
            store,
            policy: AgentPolicy::Tofu,
        }
    }

    /// Enveloppe un magasin ouvert en écriture, avec la politique
    /// d'autorisation donnée.
    pub fn with_policy(store: &'a mut dyn MultiJournalStore, policy: AgentPolicy) -> Self {
        Self { store, policy }
    }

    /// L'empreinte `hash` désigne-t-elle un snapshot déjà stocké ?
    /// (`NotFound` = non ; toute autre erreur du magasin est remontée.)
    fn has_snapshot(&self, hash: &BlobHash) -> Result<bool, ReceiveError> {
        match self.store.get_snapshot(hash) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

impl Receiver for StoreReceiver<'_> {
    fn receive(&mut self, batch: PushBatch) -> Result<Receipt, ReceiveError> {
        // ------------------------------------------------------------------
        // Phase 0 — autorisation, avant toute écriture (et avant tout
        // travail) : clé absente d'une allowlist = 403.
        // ------------------------------------------------------------------
        let journal: JournalId = batch.agent_public_key;
        if !self.policy.allows(&journal) {
            return Err(ReceiveError::Forbidden(hex::encode(journal)));
        }
        let key = VerifyingKey::from_bytes(&batch.agent_public_key).map_err(|e| {
            ReceiveError::BadSignature(format!("clé publique d'agent invalide : {e}"))
        })?;

        // ------------------------------------------------------------------
        // Phase 1 — validation, aucune écriture.
        // ------------------------------------------------------------------

        // Blobs : l'empreinte est RECALCULÉE sur les octets reçus. C'est elle
        // qui fait foi — un blob altéré en vol produit une empreinte que
        // rien ne référence, et le lot est refusé plus bas.
        let mut batch_blobs: BTreeSet<BlobHash> = BTreeSet::new();
        let mut blob_hashes: Vec<BlobHash> = Vec::with_capacity(batch.blobs.len());
        for blob in &batch.blobs {
            if !blob.is_canonical() {
                return Err(ReceiveError::NotCanonical(format!(
                    "collecteur {} : faits non triés ou dupliqués",
                    blob.collector.0
                )));
            }
            let hash = blob_hash(blob).map_err(StoreError::from)?;
            batch_blobs.insert(hash);
            blob_hashes.push(hash);
        }

        // Le lot doit être un graphe fermé : un blob que rien n'annonce est
        // le symptôme d'un objet altéré en vol (son empreinte recalculée ne
        // correspond plus à aucune référence de snapshot). Refus.
        let referenced_blobs: BTreeSet<BlobHash> = batch
            .snapshots
            .iter()
            .flat_map(|snapshot| snapshot.blobs.values().copied())
            .collect();
        for (blob, hash) in batch.blobs.iter().zip(&blob_hashes) {
            if !referenced_blobs.contains(hash) {
                return Err(ReceiveError::DanglingReference(format!(
                    "blob {} (collecteur {}) : aucun snapshot du lot ne porte cette \
                     empreinte — objet altéré en vol ou lot incohérent",
                    hash.to_hex(),
                    blob.collector.0
                )));
            }
        }

        // Snapshots : chaque référence de blob doit être résoluble dans le
        // lot (empreintes recalculées ci-dessus) ou dans le magasin.
        let mut batch_snapshots: BTreeSet<BlobHash> = BTreeSet::new();
        let mut snapshot_hashes: Vec<BlobHash> = Vec::with_capacity(batch.snapshots.len());
        for snapshot in &batch.snapshots {
            for (collector, hash) in &snapshot.blobs {
                if !batch_blobs.contains(hash) && !self.store.has_blob(hash)? {
                    return Err(ReceiveError::DanglingReference(format!(
                        "snapshot de {} : blob {} ({}) absent du lot et du magasin — \
                         objet altéré en vol ou lot incomplet",
                        snapshot.asset.0,
                        hash.to_hex(),
                        collector.0
                    )));
                }
            }
            let hash = snapshot_hash(snapshot).map_err(StoreError::from)?;
            batch_snapshots.insert(hash);
            snapshot_hashes.push(hash);
        }

        // Même fermeture pour les snapshots : chacun doit être annoncé par
        // une entrée de journal du lot.
        let referenced_snapshots: BTreeSet<BlobHash> = batch
            .entries
            .iter()
            .flat_map(|entry| entry.snapshots.iter().copied())
            .collect();
        for (snapshot, hash) in batch.snapshots.iter().zip(&snapshot_hashes) {
            if !referenced_snapshots.contains(hash) {
                return Err(ReceiveError::DanglingReference(format!(
                    "snapshot de {} ({}) : aucune entrée du lot ne porte cette \
                     empreinte — objet altéré en vol ou lot incohérent",
                    snapshot.asset.0,
                    hash.to_hex()
                )));
            }
        }

        // Entrées : signature vérifiée avec la clé annoncée, références de
        // snapshots résolubles, chaîne `prev` raccordée au journal de CETTE
        // clé (les autres journaux ne sont ni lus ni touchés). Les entrées
        // déjà stockées dans ce journal (rejeu idempotent) sont admises.
        let existing: BTreeSet<BlobHash> = self
            .store
            .entries_of(&journal)?
            .iter()
            .map(|(hash, _)| *hash)
            .collect();
        let mut last = self.store.last_entry_of(&journal)?.map(|(hash, _)| hash);
        let mut new_entries: Vec<&JournalEntry> = Vec::new();
        for (index, entry) in batch.entries.iter().enumerate() {
            let hash = entry_hash(entry).map_err(StoreError::from)?;
            if existing.contains(&hash) {
                continue; // déjà connue : le rejeu est un non-événement
            }
            for snapshot in &entry.snapshots {
                if !batch_snapshots.contains(snapshot) && !self.has_snapshot(snapshot)? {
                    return Err(ReceiveError::DanglingReference(format!(
                        "entrée {index} : snapshot {} absent du lot et du magasin",
                        snapshot.to_hex()
                    )));
                }
            }
            let bytes = signable_bytes(entry).map_err(StoreError::from)?;
            let signature = Signature::try_from(entry.signature.as_slice()).map_err(|_| {
                ReceiveError::BadSignature(format!(
                    "entrée {index} : signature malformée ({} octets, 64 attendus)",
                    entry.signature.len()
                ))
            })?;
            key.verify_strict(&bytes, &signature).map_err(|_| {
                ReceiveError::BadSignature(format!(
                    "entrée {index} : la signature ne vérifie pas avec la clé annoncée"
                ))
            })?;
            if entry.prev != last {
                return Err(ReceiveError::ChainMismatch(format!(
                    "entrée {index} : `prev` = {} mais la dernière entrée connue du journal \
                     de cette clé est {} — troncature ou réécriture, à consigner",
                    entry
                        .prev
                        .map(|h| h.to_hex())
                        .unwrap_or_else(|| "absent".into()),
                    last.map(|h| h.to_hex()).unwrap_or_else(|| "absent".into()),
                )));
            }
            last = Some(hash);
            new_entries.push(entry);
        }

        // ------------------------------------------------------------------
        // Phase 2 — écriture, dans le journal de CETTE clé. Le lot entier
        // est valide ; l'adressage par contenu rend chaque écriture
        // idempotente, et `append_entry_in` revérifie structurellement que
        // chaque entrée est signée par la clé du journal.
        // ------------------------------------------------------------------
        for blob in &batch.blobs {
            self.store.put_blob(blob)?;
        }
        for snapshot in &batch.snapshots {
            self.store.put_snapshot(snapshot)?;
        }
        for entry in new_entries {
            self.store.append_entry_in(&journal, entry)?;
        }

        let root = self.store.root_of(&journal)?;
        Ok(Receipt {
            accepted_blobs: batch.blobs.len(),
            accepted_snapshots: batch.snapshots.len(),
            accepted_entries: batch.entries.len(),
            last_entry: root,
            journal_root: root,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use constat_model::{Fact, Snapshot, Timestamp};
    use constat_store::{append_signed, verify_chain, MemoryStore, Signer, Store};
    use std::collections::BTreeMap;

    /// Construit un magasin d'agent avec `n` collectes journalisées par
    /// `signer` (le contenu varie avec `asset`), et le lot correspondant.
    fn batch_of(signer: &Signer, asset: &str, n: usize) -> PushBatch {
        let mut store = MemoryStore::new();
        let mut all_blobs = Vec::new();
        let mut all_snapshots = Vec::new();
        for i in 0..n {
            let blob = Blob::new(
                "linux.sshd",
                format!("PermitRootLogin no # {asset} v{i}\n").into_bytes(),
                vec![Fact::new("service:sshd", "sshd.PermitRootLogin", "no")],
            );
            let hash = store.put_blob(&blob).unwrap();
            let mut blobs = BTreeMap::new();
            blobs.insert("linux.sshd".into(), hash);
            let snapshot = Snapshot::new(asset, Timestamp(1_000 + i as i64), blobs);
            let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
            append_signed(
                &mut store,
                signer,
                vec![snapshot_hash],
                Timestamp(1_000 + i as i64),
            )
            .unwrap();
            all_blobs.push(blob);
            all_snapshots.push(snapshot);
        }
        let entries = store
            .entries()
            .unwrap()
            .into_iter()
            .map(|(_, e)| e)
            .collect();
        PushBatch {
            agent_public_key: signer.verifying_key().to_bytes(),
            asset: asset.into(),
            blobs: all_blobs,
            snapshots: all_snapshots,
            entries,
        }
    }

    fn agent_batch(n: usize) -> (Signer, PushBatch) {
        let signer = Signer::generate();
        let batch = batch_of(&signer, "srv-01", n);
        (signer, batch)
    }

    #[test]
    fn reception_puis_verification_de_chaine() {
        let (signer, batch) = agent_batch(2);
        let journal = signer.verifying_key().to_bytes();
        let mut store = MemoryStore::new();
        let receipt = StoreReceiver::new(&mut store).receive(batch).unwrap();
        assert_eq!(receipt.accepted_entries, 2);
        // Le lot est rangé dans le journal de la clé de l'agent…
        let entries = store.entries_of(&journal).unwrap();
        assert_eq!(entries.len(), 2);
        verify_chain(&entries, &signer.verifying_key()).unwrap();
        assert_eq!(receipt.last_entry, store.root_of(&journal).unwrap());
        assert_eq!(receipt.journal_root, receipt.last_entry);
        // …et le journal par défaut du magasin n'est pas touché.
        assert_eq!(store.entry_count(), 0);
        assert_eq!(store.root().unwrap(), None);
    }

    /// Re-pousser exactement le même lot est un non-événement.
    #[test]
    fn double_poussee_idempotente() {
        let (signer, batch) = agent_batch(2);
        let journal = signer.verifying_key().to_bytes();
        let mut store = MemoryStore::new();
        StoreReceiver::new(&mut store)
            .receive(batch.clone())
            .unwrap();
        let root = store.root_of(&journal).unwrap();
        let receipt = StoreReceiver::new(&mut store).receive(batch).unwrap();
        assert_eq!(store.entries_of(&journal).unwrap().len(), 2);
        assert_eq!(store.blob_count(), 2);
        assert_eq!(store.root_of(&journal).unwrap(), root);
        // Les doublons idempotents comptent comme acceptés.
        assert_eq!(receipt.accepted_entries, 2);
    }

    /// Deux agents qui poussent en entrelacé : deux journaux, deux chaînes
    /// intactes, vérifiables indépendamment — personne ne se marche dessus.
    #[test]
    fn deux_agents_entrelaces() {
        let a = Signer::generate();
        let b = Signer::generate();
        let journal_a = a.verifying_key().to_bytes();
        let journal_b = b.verifying_key().to_bytes();
        let mut store = MemoryStore::new();

        // Entrelacement : A pousse 1 collecte, B pousse 1, A repousse tout
        // (2 collectes, la première en rejeu idempotent), B aussi.
        StoreReceiver::new(&mut store)
            .receive(batch_of(&a, "srv-a", 1))
            .unwrap();
        StoreReceiver::new(&mut store)
            .receive(batch_of(&b, "srv-b", 1))
            .unwrap();
        let receipt_a = StoreReceiver::new(&mut store)
            .receive(batch_of(&a, "srv-a", 2))
            .unwrap();
        let receipt_b = StoreReceiver::new(&mut store)
            .receive(batch_of(&b, "srv-b", 3))
            .unwrap();

        let entries_a = store.entries_of(&journal_a).unwrap();
        let entries_b = store.entries_of(&journal_b).unwrap();
        assert_eq!(entries_a.len(), 2);
        assert_eq!(entries_b.len(), 3);
        verify_chain(&entries_a, &a.verifying_key()).unwrap();
        verify_chain(&entries_b, &b.verifying_key()).unwrap();
        assert_eq!(receipt_a.journal_root, store.root_of(&journal_a).unwrap());
        assert_eq!(receipt_b.journal_root, store.root_of(&journal_b).unwrap());
        assert_ne!(receipt_a.journal_root, receipt_b.journal_root);
        assert_eq!(store.journals().unwrap().len(), 2);
    }

    /// Une clé qui rejoue une entrée du journal d'une autre : refusée —
    /// l'entrée est signée par l'autre clé, elle ne peut pas entrer dans ce
    /// journal. Une clé ne peut jamais écrire dans le journal d'une autre.
    #[test]
    fn rejeu_d_une_entree_d_un_autre_agent_refuse() {
        let a = Signer::generate();
        let b = Signer::generate();
        let journal_b = b.verifying_key().to_bytes();
        let mut store = MemoryStore::new();
        let batch_b = batch_of(&b, "srv-b", 1);
        StoreReceiver::new(&mut store)
            .receive(batch_b.clone())
            .unwrap();
        let root_b = store.root_of(&journal_b).unwrap();

        // A annonce SA clé mais rejoue les objets de B (snapshots et blobs
        // déjà connus du magasin, entrée signée par B).
        let vol = PushBatch {
            agent_public_key: a.verifying_key().to_bytes(),
            asset: "srv-b".into(),
            blobs: vec![],
            snapshots: vec![],
            entries: batch_b.entries.clone(),
        };
        let err = StoreReceiver::new(&mut store).receive(vol).unwrap_err();
        assert!(matches!(err, ReceiveError::BadSignature(_)), "{err}");
        // Rien n'a bougé : ni journal pour A, ni écriture chez B.
        assert_eq!(store.journals().unwrap().len(), 1);
        assert_eq!(store.root_of(&journal_b).unwrap(), root_b);
    }

    /// Allowlist : une clé absente de la liste est refusée AVANT toute
    /// écriture ; une clé listée passe.
    #[test]
    fn allowlist_refuse_avant_toute_ecriture() {
        let a = Signer::generate();
        let b = Signer::generate();
        let policy = AgentPolicy::Allowlist(BTreeSet::from([a.verifying_key().to_bytes()]));
        let mut store = MemoryStore::new();

        let err = StoreReceiver::with_policy(&mut store, policy.clone())
            .receive(batch_of(&b, "srv-b", 1))
            .unwrap_err();
        assert!(matches!(err, ReceiveError::Forbidden(_)), "{err}");
        assert_eq!(store.blob_count(), 0);
        assert!(store.journals().unwrap().is_empty());

        StoreReceiver::with_policy(&mut store, policy)
            .receive(batch_of(&a, "srv-a", 1))
            .unwrap();
        assert_eq!(store.journals().unwrap().len(), 1);
    }

    /// L'allowlist se charge depuis un fichier : hex, une clé par ligne,
    /// commentaires `#`, lignes vides ignorées, ligne invalide = erreur.
    #[test]
    fn allowlist_depuis_fichier() {
        let a = Signer::generate();
        let dir = std::env::temp_dir().join(format!("constat-allow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agents.txt");
        std::fs::write(
            &path,
            format!(
                "# agents autorisés\n\n{} # agent A\n",
                hex::encode(a.verifying_key().to_bytes())
            ),
        )
        .unwrap();
        let policy = AgentPolicy::from_allowlist_file(&path).unwrap();
        assert!(policy.allows(&a.verifying_key().to_bytes()));
        assert!(!policy.allows(&[0u8; 32]));

        std::fs::write(&path, "pas-une-clé\n").unwrap();
        assert!(matches!(
            AgentPolicy::from_allowlist_file(&path),
            Err(PolicyError::BadKey { line: 1, .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Un blob altéré en vol : son empreinte recalculée ne correspond plus à
    /// celle que le snapshot annonce → référence non résoluble, lot refusé,
    /// et aucune écriture partielle.
    #[test]
    fn blob_altere_refuse_sans_ecriture() {
        let (signer, mut batch) = agent_batch(1);
        batch.blobs[0].raw.push(b'!');
        let mut store = MemoryStore::new();
        let err = StoreReceiver::new(&mut store).receive(batch).unwrap_err();
        assert!(matches!(err, ReceiveError::DanglingReference(_)), "{err}");
        assert_eq!(store.blob_count(), 0);
        assert!(store
            .entries_of(&signer.verifying_key().to_bytes())
            .unwrap()
            .is_empty());
    }

    /// Une entrée dont la signature ne vérifie pas avec la clé annoncée est
    /// refusée.
    #[test]
    fn signature_invalide_refusee() {
        let (_, mut batch) = agent_batch(1);
        batch.entries[0].signature[0] ^= 0xff;
        let mut store = MemoryStore::new();
        let err = StoreReceiver::new(&mut store).receive(batch).unwrap_err();
        assert!(matches!(err, ReceiveError::BadSignature(_)), "{err}");
    }

    /// Une clé publique annoncée différente de celle qui a signé : refus —
    /// les entrées iraient dans le journal d'une clé qui ne les a pas signées.
    #[test]
    fn cle_annoncee_differente_refusee() {
        let (_, mut batch) = agent_batch(1);
        batch.agent_public_key = Signer::generate().verifying_key().to_bytes();
        let mut store = MemoryStore::new();
        let err = StoreReceiver::new(&mut store).receive(batch).unwrap_err();
        assert!(matches!(err, ReceiveError::BadSignature(_)), "{err}");
    }

    /// Une chaîne qui ne se raccorde pas à l'existant du journal de cette clé
    /// (genèse concurrente du même signataire) : refus explicite, jamais de
    /// réparation silencieuse.
    #[test]
    fn chaine_incoherente_refusee() {
        let signer = Signer::generate();
        let first = batch_of(&signer, "srv-01", 1);
        // Même clé, autre magasin local : autre genèse — une réécriture.
        let second = batch_of(&signer, "srv-fork", 1);
        let mut store = MemoryStore::new();
        StoreReceiver::new(&mut store).receive(first).unwrap();
        let err = StoreReceiver::new(&mut store).receive(second).unwrap_err();
        assert!(matches!(err, ReceiveError::ChainMismatch(_)), "{err}");
        assert_eq!(
            store
                .entries_of(&signer.verifying_key().to_bytes())
                .unwrap()
                .len(),
            1
        );
    }

    /// Un blob que rien ne référence dans le lot — l'autre visage de
    /// l'altération en vol — est refusé : le lot doit être un graphe fermé.
    #[test]
    fn blob_orphelin_refuse() {
        let (_, mut batch) = agent_batch(1);
        batch
            .blobs
            .push(Blob::new("linux.autre", b"orphelin".to_vec(), Vec::new()));
        let mut store = MemoryStore::new();
        let err = StoreReceiver::new(&mut store).receive(batch).unwrap_err();
        assert!(matches!(err, ReceiveError::DanglingReference(_)), "{err}");
        assert_eq!(store.blob_count(), 0);
    }

    /// Un blob non canonique (faits non triés) serait ambigu : refusé.
    #[test]
    fn blob_non_canonique_refuse() {
        let (_, mut batch) = agent_batch(1);
        let fact_a = Fact::new("service:sshd", "sshd.a", "1");
        let fact_b = Fact::new("service:sshd", "sshd.b", "2");
        batch.blobs[0].facts = vec![fact_b, fact_a]; // désordre volontaire
        let mut store = MemoryStore::new();
        let err = StoreReceiver::new(&mut store).receive(batch).unwrap_err();
        assert!(matches!(err, ReceiveError::NotCanonical(_)), "{err}");
    }
}
