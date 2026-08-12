//! Réception des poussées d'agents — l'interface, et son contrat.
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
//! À la réception, l'implémentation doit :
//! 1. vérifier que chaque entrée de journal est signée par la clé publique
//!    annoncée, et que la chaîne `prev` est cohérente avec ce qui est déjà
//!    stocké pour cet agent ;
//! 2. vérifier que chaque empreinte référencée (snapshot → blob,
//!    entrée → snapshot) est résoluble dans le lot ou dans le magasin ;
//! 3. écrire blobs, snapshots et entrées dans le magasin serveur.
//!
//! TODO(integration) : l'implémentation (rustls côté serveur + magasin
//! concret) sera branchée derrière [`Receiver`] — aucun serveur factice
//! n'est démarré en attendant.

use constat_model::{Blob, BlobHash, Snapshot};
use constat_store::JournalEntry;
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
