//! Poussée sortante vers `constat-server` — l'interface, et son contrat.
//!
//! # Contraintes §7.1, non négociables
//!
//! - **Aucun port en écoute.** L'agent est exclusivement client : il initie
//!   la connexion, pousse, et raccroche. Compromettre le serveur ne donne
//!   aucun moyen d'atteindre l'agent.
//! - **mTLS obligatoire.** L'agent présente son certificat client ; il
//!   vérifie le certificat du serveur contre l'autorité fournie à
//!   l'installation. Pas de repli en clair, jamais.
//! - **Aucune exécution de code envoyé.** La réponse du serveur est un
//!   accusé de réception, rien d'autre : elle n'est jamais interprétée
//!   comme une instruction.
//!
//! # Protocole
//!
//! `POST /v1/pousse` sur la liaison mTLS, corps : l'encodage canonique CBOR
//! (celui de `constat-model`, §15) d'un [`PushBatch`]. Le serveur répond
//! `200` avec un accusé — nombre d'objets acceptés — ou un code d'erreur.
//! La poussée est **idempotente** : les objets sont adressés par contenu,
//! re-pousser un blob déjà connu est un non-événement. L'agent peut donc
//! rejouer sans risque après une coupure.
//!
//! Le miroir côté serveur est `constat-server/src/receive.rs`.
//!
//! TODO(integration) : le transport (rustls + certificats client) n'est pas
//! encore câblé — [`push`] renvoie une erreur explicite. Le mode
//! local-d'abord (magasin local + CLI) est complet sans lui.

use std::path::PathBuf;

use constat_model::{Blob, Snapshot};
use constat_store::JournalEntry;
use serde::{Deserialize, Serialize};

/// Ce que l'agent pousse : les objets nouveaux depuis la dernière poussée.
///
/// L'ordre importe : blobs, puis snapshots, puis entrées — le serveur peut
/// ainsi vérifier chaque référence au moment où il la rencontre.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushBatch {
    /// Clé publique Ed25519 de l'agent (32 octets) : identifie la source et
    /// permet au serveur de vérifier les signatures des entrées.
    pub agent_public_key: [u8; 32],
    /// Machine concernée (redondant avec les snapshots, mais permet le
    /// contrôle d'inventaire attendu/observé côté serveur).
    pub asset: String,
    /// Blobs nouveaux, déjà expurgés (§7.2) — le serveur ne reçoit jamais
    /// autre chose que la forme expurgée.
    pub blobs: Vec<Blob>,
    /// Snapshots nouveaux.
    pub snapshots: Vec<Snapshot>,
    /// Entrées de journal nouvelles, signées, dans l'ordre de la chaîne.
    pub entries: Vec<JournalEntry>,
}

/// Configuration de la poussée, fournie à l'installation
/// (`constat agent install --server … --token …`).
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// URL du serveur, ex. `https://constat.interne`.
    pub server_url: String,
    /// Certificat client de l'agent (PEM).
    pub client_cert: PathBuf,
    /// Clé privée du certificat client (PEM) — distincte de la clé de
    /// signature du journal.
    pub client_key: PathBuf,
    /// Autorité de certification du serveur (PEM) : la seule acceptée.
    pub server_ca: PathBuf,
}

/// Erreurs de poussée.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum PushError {
    #[error("la poussée mTLS n'est pas encore câblée")]
    #[diagnostic(help(
        "TODO(integration) : transport rustls à brancher dans \
         crates/constat-agent/src/push.rs ; le mode local (magasin + CLI) \
         est complet sans lui"
    ))]
    NotWired,
}

/// Pousse un lot vers le serveur, en mTLS sortant uniquement.
///
/// TODO(integration) : transport rustls à brancher — l'interface et le
/// protocole ci-dessus sont le contrat, l'implémentation réseau viendra
/// sans changer les appelants.
pub fn push(_config: &PushConfig, _batch: &PushBatch) -> Result<(), PushError> {
    Err(PushError::NotWired)
}
