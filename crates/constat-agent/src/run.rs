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
//!
//! La collecte est scindée en deux phases : [`collect_all`] (lecture seule,
//! aucune clé ni magasin requis) puis [`persist`] (écriture + signature).
//! Cette séparation permet au binaire de constater qu'il n'y a rien à
//! collecter **avant** d'exiger les clés de signature.

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

/// Résultat de la phase de lecture ([`collect_all`]) : rien n'a encore été
/// écrit, aucune clé n'a été chargée.
#[derive(Debug)]
pub struct Collection {
    /// Blobs prêts à écrire : (collecteur, blob expurgé, nombre de faits).
    pub blobs: Vec<(CollectorId, Blob, usize)>,
    /// Collecteurs indisponibles sur cette plateforme (déclarés).
    pub unavailable: Vec<(CollectorId, String)>,
    /// Collecteurs en échec réel : (identifiant, cause). Déclarés, jamais masqués.
    pub failed: Vec<(CollectorId, String)>,
}

impl Collection {
    /// Rien à écrire : aucun collecteur n'a produit de blob.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
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

/// Phase 1 — exécute tous les collecteurs, expurge, extrait les faits.
///
/// Lecture seule : aucun magasin ouvert, aucune clé chargée, rien d'écrit.
pub fn collect_all(collectors: &[Box<dyn Collector>]) -> Collection {
    let mut blobs = Vec::new();
    let mut unavailable = Vec::new();
    let mut failed = Vec::new();

    for collector in collectors {
        let id = collector.id();
        // Défense en profondeur (§7.1) : l'espace de noms réservé
        // (`constat.purge`, `constat.rotation`, préfixe `constat.`) est
        // exclusivement celui des chemins SIGNÉS de purge et de rotation
        // ([`constat_store::purge`]/[`rotation`]). Une collecte ordinaire ne
        // doit jamais y écrire — un collecteur (bug interne) qui porterait un
        // identifiant réservé est refusé, jamais persisté, et déclaré comme
        // tout autre échec (jamais masqué).
        if constat_store::is_reserved_collector(&id) {
            failed.push((
                id,
                format!(
                    "identifiant dans l'espace de noms réservé « {} » : \
                     ces blobs ne sont créés que par les chemins signés de \
                     purge/rotation, jamais par une collecte ordinaire",
                    constat_store::RESERVED_COLLECTOR_PREFIX
                ),
            ));
            continue;
        }
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
                        blobs.push((id, blob, fact_count));
                    }
                }
            }
        }
    }

    Collection {
        blobs,
        unavailable,
        failed,
    }
}

/// Phase 2 — écrit les blobs et le snapshot dans le magasin, puis ajoute
/// l'entrée de journal signée ([`constat_store::append_signed`] : chaînage
/// `prev` automatique).
///
/// À n'appeler que si [`Collection::is_empty`] est faux : la phase d'écriture
/// suppose qu'il y a quelque chose à journaliser.
pub fn persist(
    store: &mut dyn Store,
    signer: &Signer,
    collection: Collection,
    asset: AssetId,
    now: Timestamp,
) -> Result<RunReport, RunError> {
    let Collection {
        blobs,
        unavailable,
        failed,
    } = collection;

    let mut hashes: BTreeMap<CollectorId, BlobHash> = BTreeMap::new();
    let mut collected = Vec::new();
    for (id, blob, fact_count) in blobs {
        let hash = store.put_blob(&blob)?;
        hashes.insert(id.clone(), hash);
        collected.push((id, hash, fact_count));
    }

    let snapshot = Snapshot {
        asset: asset.clone(),
        at: now,
        blobs: hashes,
    };
    let snapshot_hash = store.put_snapshot(&snapshot)?;
    let (entry_hash, _) = append_signed(store, signer, vec![snapshot_hash], now)?;

    Ok(RunReport {
        asset,
        at: now,
        collected,
        unavailable,
        failed,
        snapshot: snapshot_hash,
        entry: entry_hash,
    })
}

/// Les deux phases enchaînées — pour les appelants qui disposent déjà du
/// magasin et des clés. Le binaire, lui, appelle [`collect_all`] d'abord
/// pour ne pas exiger de clés quand il n'y a rien à collecter.
pub fn run_once(
    store: &mut dyn Store,
    signer: &Signer,
    collectors: &[Box<dyn Collector>],
    asset: AssetId,
    now: Timestamp,
) -> Result<RunOutcome, RunError> {
    let collection = collect_all(collectors);
    if collection.is_empty() {
        if collection.failed.is_empty() {
            // Plateforme sans collecteur applicable : sortie honnête.
            return Ok(RunOutcome::NothingAvailable {
                unavailable: collection.unavailable,
            });
        }
        return Err(RunError::AllFailed(all_failed_causes(&collection.failed)));
    }
    persist(store, signer, collection, asset, now).map(RunOutcome::Collected)
}

/// Concatène les causes d'échec pour [`RunError::AllFailed`].
pub fn all_failed_causes(failed: &[(CollectorId, String)]) -> String {
    failed
        .iter()
        .map(|(id, e)| format!("{} : {e}", id.0))
        .collect::<Vec<_>>()
        .join(" ; ")
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use constat_collect::{CollectError, Collector, RawCapture, RedactedCapture};
    use constat_model::Fact;

    /// Collecteur de test dont l'identifiant usurpe l'espace de noms réservé :
    /// il collecte et extrait normalement, mais son `id` est `constat.purge`.
    struct ReservedCollector;

    impl Collector for ReservedCollector {
        fn id(&self) -> CollectorId {
            CollectorId(constat_store::purge::PURGE_COLLECTOR.to_string())
        }
        fn collect(&self) -> Result<RawCapture, CollectError> {
            Ok(RawCapture(b"peu importe".to_vec()))
        }
        fn redact(&self, raw: RawCapture) -> RedactedCapture {
            RedactedCapture(raw.0)
        }
        fn extract(&self, _redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
            Ok(vec![Fact::new("service:x", "x.y", "z")])
        }
    }

    /// Un collecteur portant un identifiant réservé (`constat.purge`) hors du
    /// protocole de purge/rotation est refusé à la construction du blob :
    /// aucun blob n'est produit, l'échec est déclaré (jamais masqué).
    #[test]
    fn collecteur_reserve_refuse_a_la_collecte() {
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(ReservedCollector)];
        let collection = collect_all(&collectors);
        assert!(collection.is_empty(), "aucun blob ne doit être produit");
        assert_eq!(collection.failed.len(), 1);
        assert_eq!(
            collection.failed[0].0 .0,
            constat_store::purge::PURGE_COLLECTOR
        );
    }
}
