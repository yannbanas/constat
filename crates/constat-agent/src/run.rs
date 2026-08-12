//! La collecte : `constat-agent run --once`.
//!
//! Contraintes §7.1, non négociables :
//! - **lecture seule** — les collecteurs lisent, rien d'autre ;
//! - **expurgation avant émission** — `redact` s'applique avant toute écriture ;
//! - **aucune exécution de code envoyé** — les collecteurs sont compilés ici
//!   ([`constat_collect::all_collectors`]) ;
//! - **jamais de données simulées présentées comme réelles** — si aucun
//!   collecteur n'est applicable à la plateforme, l'agent le dit et n'écrit
//!   rien.

use std::collections::BTreeMap;

use constat_collect::{CollectError, Collector};
use constat_model::{AssetId, Blob, BlobHash, CollectorId, Snapshot, Timestamp};
use constat_store::{append_signed, Signer, Store, StoreError};

/// Erreurs d'une collecte.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum RunError {
    #[error("erreur du magasin : {0}")]
    Store(#[from] StoreError),
    #[error("tous les collecteurs ont échoué : {0}")]
    #[diagnostic(help(
        "aucune donnée partielle n'a été journalisée ; corrigez la cause et relancez"
    ))]
    AllFailed(String),
}

/// Compte rendu d'une collecte.
#[derive(Debug)]
pub enum RunOutcome {
    /// Aucun collecteur applicable à cette plateforme : rien n'a été
    /// collecté, rien n'a été écrit — sortie honnête, jamais simulée.
    NothingAvailable {
        /// (collecteur, raison d'indisponibilité), pour transparence.
        unavailable: Vec<(CollectorId, String)>,
    },
    /// Collecte effectuée et journalisée.
    Collected(RunReport),
}

/// Détail d'une collecte journalisée.
#[derive(Debug)]
pub struct RunReport {
    pub asset: AssetId,
    /// Date de la collecte — portée pour les appelants (poussée, tests).
    #[allow(dead_code)]
    pub at: Timestamp,
    /// Collecteurs réussis : (identifiant, empreinte du blob, nombre de faits).
    pub collected: Vec<(CollectorId, BlobHash, usize)>,
    /// Collecteurs indisponibles sur cette plateforme (déclarés).
    pub unavailable: Vec<(CollectorId, String)>,
    /// Collecteurs en échec réel : (identifiant, cause). Déclarés, jamais masqués.
    pub failed: Vec<(CollectorId, String)>,
    /// Empreinte du snapshot écrit.
    pub snapshot: BlobHash,
    /// Empreinte de l'entrée de journal signée (la nouvelle racine).
    pub entry: BlobHash,
}

/// Exécute tous les collecteurs, construit les blobs et le snapshot, écrit
/// dans le magasin local, puis ajoute l'entrée de journal signée
/// ([`constat_store::append_signed`] : chaînage `prev` automatique).
pub fn run_once(
    store: &mut dyn Store,
    signer: &Signer,
    collectors: &[Box<dyn Collector>],
    asset: AssetId,
    now: Timestamp,
) -> Result<RunOutcome, RunError> {
    let mut blobs: BTreeMap<CollectorId, BlobHash> = BTreeMap::new();
    let mut collected = Vec::new();
    let mut unavailable = Vec::new();
    let mut failed = Vec::new();

    for collector in collectors {
        let id = collector.id();
        match collector.collect() {
            Err(CollectError::Unavailable(reason)) => unavailable.push((id, reason)),
            Err(e) => failed.push((id, e.to_string())),
            Ok(raw) => {
                // Expurgation AVANT émission (§7.2) : le brut ne sort jamais tel quel.
                let redacted = collector.redact(raw);
                match collector.extract(&redacted) {
                    Err(e) => failed.push((id, e.to_string())),
                    Ok(mut facts) => {
                        facts.sort(); // ordre canonique : empreinte stable (§15)
                        let fact_count = facts.len();
                        let blob = Blob {
                            collector: id.clone(),
                            raw: redacted.0,
                            facts,
                        };
                        let hash = store.put_blob(&blob)?;
                        blobs.insert(id.clone(), hash);
                        collected.push((id, hash, fact_count));
                    }
                }
            }
        }
    }

    if blobs.is_empty() {
        if failed.is_empty() {
            // Plateforme sans collecteur applicable : sortie honnête.
            return Ok(RunOutcome::NothingAvailable { unavailable });
        }
        let causes: Vec<String> = failed
            .iter()
            .map(|(id, e)| format!("{} : {e}", id.0))
            .collect();
        return Err(RunError::AllFailed(causes.join(" ; ")));
    }

    let snapshot = Snapshot {
        asset: asset.clone(),
        at: now,
        blobs,
    };
    let snapshot_hash = store.put_snapshot(&snapshot)?;
    let (entry_hash, _) = append_signed(store, signer, vec![snapshot_hash], now)?;

    Ok(RunOutcome::Collected(RunReport {
        asset,
        at: now,
        collected,
        unavailable,
        failed,
        snapshot: snapshot_hash,
        entry: entry_hash,
    }))
}

/// L'instant présent, en millisecondes UTC depuis l'époque Unix.
pub fn now_ms() -> Timestamp {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp(d.as_millis() as i64)
}

/// Nom de machine, sans dépendance : variables d'environnement usuelles.
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "hote-inconnu".to_string())
}
