//! # constat-collect
//!
//! Les collecteurs (§7). Lecture seule, toujours. Compilés dans le binaire,
//! jamais téléchargés. **Aucun secret ne quitte la machine** : l'expurgation
//! se fait ici, avant émission (§7.2).
//!
//! Les extracteurs (parsing → faits) sont purs et testables sur tout OS ;
//! seule la collecte effective est spécifique à la plateforme (`cfg`).
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.

use constat_model::{CollectorId, Fact};

pub mod backup;
pub mod capture;
pub mod linux;
pub mod redact;

/// Capture brute, telle que lue sur la machine. Peut contenir des secrets :
/// ne doit JAMAIS être émise telle quelle.
#[derive(Debug, Clone)]
pub struct RawCapture(pub Vec<u8>);

/// Capture expurgée : plus aucun secret. Seule forme autorisée à sortir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedCapture(pub Vec<u8>);

#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("collecte impossible : {0}")]
    Unavailable(String),
    #[error("erreur de lecture : {0}")]
    Io(String),
    #[error("extraction impossible : {0}")]
    Extract(String),
}

/// Un collecteur (§7.2). `redact` s'applique AVANT toute émission.
pub trait Collector {
    fn id(&self) -> CollectorId;
    fn collect(&self) -> Result<RawCapture, CollectError>;
    fn redact(&self, raw: RawCapture) -> RedactedCapture;
    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError>;
}

/// Le registre des collecteurs : **compilés dans le binaire, jamais
/// téléchargés** (§7.1). L'ordre suit la valeur (§7.3) : comptes privilégiés
/// et preuve de sauvegarde d'abord — le coin d'entrée du produit.
///
/// Sur une plateforme non-Unix, chaque `collect()` retourne proprement
/// [`CollectError::Unavailable`] ; l'expurgation et l'extraction, elles,
/// restent pures et fonctionnent partout.
pub fn all_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(linux::accounts::AccountsCollector::default()),
        Box::new(backup::BackupProofCollector::default()),
        Box::new(linux::sshd::SshdCollector::default()),
        Box::new(linux::sudoers::SudoersCollector::default()),
        // priorité haute (§7.3) : correctifs (délai réel d'application)…
        Box::new(linux::packages::PackagesCollector::default()),
        // …puis segmentation (qu'est-ce qui écoute), services, durcissement
        Box::new(linux::ports::PortsCollector::default()),
        Box::new(linux::systemd::SystemdCollector::default()),
        Box::new(linux::kernel_params::KernelParamsCollector::default()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_registre_est_complet_et_ordonne_par_valeur() {
        let ids: Vec<String> = all_collectors().iter().map(|c| c.id().0).collect();
        assert_eq!(
            ids,
            vec![
                "linux.accounts",
                "backup.proof",
                "linux.sshd",
                "linux.sudoers",
                "linux.packages",
                "linux.ports",
                "linux.systemd",
                "linux.kernel_params"
            ]
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn sur_non_unix_collect_retourne_unavailable() {
        for collector in all_collectors() {
            match collector.collect() {
                Err(CollectError::Unavailable(_)) => {}
                autre => panic!(
                    "{} : attendu Unavailable sur non-unix, obtenu {autre:?}",
                    collector.id().0
                ),
            }
        }
    }
}
