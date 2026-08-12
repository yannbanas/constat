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
//! 1. recalcule l'empreinte de chaque objet du lot — une empreinte annoncée
//!    (snapshot → blob, entrée → snapshot) qui ne se recalcule pas à
//!    l'identique est refusée : un objet altéré en vol ne rentre pas ;
//! 2. exige un **graphe fermé** : chaque blob du lot est référencé par un
//!    snapshot du lot, chaque snapshot par une entrée — un objet que rien
//!    n'annonce (l'autre visage de l'altération en vol) est refusé aussi ;
//! 3. vérifie que chaque entrée de journal est signée par la clé publique
//!    annoncée, et que la chaîne `prev` se raccorde à ce qui est déjà stocké ;
//! 4. valide **tout** le lot avant d'écrire quoi que ce soit : un lot refusé
//!    ne laisse aucune écriture partielle, et l'agent peut le repousser tel
//!    quel une fois la cause corrigée (idempotence).
//!
//! La couche transport (mTLS + HTTP) est dans [`crate::serve`] ; elle remet
//! le lot décodé à cette interface, qui reste ainsi testable sans réseau.

use std::collections::BTreeSet;

use constat_model::{blob_hash, snapshot_hash, Blob, BlobHash, Snapshot};
use constat_store::{
    entry_hash, signable_bytes, JournalEntry, Signature, Store, StoreError, VerifyingKey,
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

/// Accusé de réception. Des compteurs et une empreinte, rien d'autre :
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
}

/// Erreurs de réception.
#[derive(Debug, thiserror::Error)]
pub enum ReceiveError {
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
/// Valide tout le lot (empreintes recalculées, signatures, chaînage) avant
/// la moindre écriture : un lot refusé ne modifie pas le magasin.
///
/// **Limite assumée** : le magasin sous-jacent porte *un* journal — le
/// serveur actuel range donc les poussées d'*un* agent par magasin. Le
/// multi-agents (un journal par clé publique) viendra avec l'évolution du
/// trait `Store`, sans changer ce contrat de validation.
pub struct StoreReceiver<'a> {
    store: &'a mut dyn Store,
}

impl<'a> StoreReceiver<'a> {
    /// Enveloppe un magasin ouvert en écriture.
    pub fn new(store: &'a mut dyn Store) -> Self {
        Self { store }
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
        // snapshots résolubles, chaîne `prev` raccordée à l'existant. Les
        // entrées déjà stockées (rejeu idempotent) sont simplement admises.
        let existing: BTreeSet<BlobHash> = self
            .store
            .entries()?
            .iter()
            .map(|(hash, _)| *hash)
            .collect();
        let mut last = self.store.last_entry()?.map(|(hash, _)| hash);
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
                    "entrée {index} : `prev` = {} mais la dernière entrée connue est {} — \
                     troncature ou réécriture, à consigner",
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
        // Phase 2 — écriture. Le lot entier est valide ; l'adressage par
        // contenu rend chaque écriture idempotente.
        // ------------------------------------------------------------------
        for blob in &batch.blobs {
            self.store.put_blob(blob)?;
        }
        for snapshot in &batch.snapshots {
            self.store.put_snapshot(snapshot)?;
        }
        for entry in new_entries {
            self.store.append_entry(entry)?;
        }

        Ok(Receipt {
            accepted_blobs: batch.blobs.len(),
            accepted_snapshots: batch.snapshots.len(),
            accepted_entries: batch.entries.len(),
            last_entry: self.store.root()?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use constat_model::{Fact, Snapshot, Timestamp};
    use constat_store::{append_signed, verify_chain, MemoryStore, Signer};
    use std::collections::BTreeMap;

    /// Construit un magasin d'agent avec `n` collectes journalisées, et le
    /// lot correspondant.
    fn agent_batch(n: usize) -> (Signer, PushBatch) {
        let mut store = MemoryStore::new();
        let signer = Signer::generate();
        let mut all_blobs = Vec::new();
        let mut all_snapshots = Vec::new();
        for i in 0..n {
            let blob = Blob::new(
                "linux.sshd",
                format!("PermitRootLogin no # v{i}\n").into_bytes(),
                vec![Fact::new("service:sshd", "sshd.PermitRootLogin", "no")],
            );
            let hash = store.put_blob(&blob).unwrap();
            let mut blobs = BTreeMap::new();
            blobs.insert("linux.sshd".into(), hash);
            let snapshot = Snapshot::new("srv-01", Timestamp(1_000 + i as i64), blobs);
            let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
            append_signed(
                &mut store,
                &signer,
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
        let batch = PushBatch {
            agent_public_key: signer.verifying_key().to_bytes(),
            asset: "srv-01".into(),
            blobs: all_blobs,
            snapshots: all_snapshots,
            entries,
        };
        (signer, batch)
    }

    #[test]
    fn reception_puis_verification_de_chaine() {
        let (signer, batch) = agent_batch(2);
        let mut store = MemoryStore::new();
        let receipt = StoreReceiver::new(&mut store).receive(batch).unwrap();
        assert_eq!(receipt.accepted_entries, 2);
        assert_eq!(store.entry_count(), 2);
        // La chaîne reçue se vérifie avec la clé publique de l'agent.
        verify_chain(&store.entries().unwrap(), &signer.verifying_key()).unwrap();
        assert_eq!(receipt.last_entry, store.root().unwrap());
    }

    /// Re-pousser exactement le même lot est un non-événement.
    #[test]
    fn double_poussee_idempotente() {
        let (_, batch) = agent_batch(2);
        let mut store = MemoryStore::new();
        StoreReceiver::new(&mut store)
            .receive(batch.clone())
            .unwrap();
        let root = store.root().unwrap();
        let receipt = StoreReceiver::new(&mut store).receive(batch).unwrap();
        assert_eq!(store.entry_count(), 2);
        assert_eq!(store.blob_count(), 2);
        assert_eq!(store.root().unwrap(), root);
        // Les doublons idempotents comptent comme acceptés.
        assert_eq!(receipt.accepted_entries, 2);
    }

    /// Un blob altéré en vol : son empreinte recalculée ne correspond plus à
    /// celle que le snapshot annonce → référence non résoluble, lot refusé,
    /// et aucune écriture partielle.
    #[test]
    fn blob_altere_refuse_sans_ecriture() {
        let (_, mut batch) = agent_batch(1);
        batch.blobs[0].raw.push(b'!');
        let mut store = MemoryStore::new();
        let err = StoreReceiver::new(&mut store).receive(batch).unwrap_err();
        assert!(matches!(err, ReceiveError::DanglingReference(_)), "{err}");
        assert_eq!(store.blob_count(), 0);
        assert_eq!(store.entry_count(), 0);
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

    /// Une clé publique annoncée différente de celle qui a signé : refus.
    #[test]
    fn cle_annoncee_differente_refusee() {
        let (_, mut batch) = agent_batch(1);
        batch.agent_public_key = Signer::generate().verifying_key().to_bytes();
        let mut store = MemoryStore::new();
        let err = StoreReceiver::new(&mut store).receive(batch).unwrap_err();
        assert!(matches!(err, ReceiveError::BadSignature(_)), "{err}");
    }

    /// Une chaîne qui ne se raccorde pas à l'existant (genèse concurrente) :
    /// refus explicite, jamais de réparation silencieuse.
    #[test]
    fn chaine_incoherente_refusee() {
        let (_, first) = agent_batch(1);
        let (_, second) = agent_batch(1); // autre signer → autre genèse
        let mut store = MemoryStore::new();
        StoreReceiver::new(&mut store).receive(first).unwrap();
        let err = StoreReceiver::new(&mut store).receive(second).unwrap_err();
        assert!(matches!(err, ReceiveError::ChainMismatch(_)), "{err}");
        assert_eq!(store.entry_count(), 1);
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
