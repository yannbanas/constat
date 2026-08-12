//! Binaire `constat-agent` — l'agent de collecte.
//!
//! # Contraintes §7.1, non négociables
//!
//! - **Aucun port en écoute.** Ce binaire n'appelle jamais `bind`/`listen` :
//!   la seule communication réseau prévue est la poussée sortante mTLS
//!   (module [`push`]).
//! - **Aucune exécution de code envoyé.** Les collecteurs sont compilés dans
//!   le binaire (`constat-collect`) ; rien n'est téléchargé, rien n'est
//!   interprété.
//! - **Lecture seule** sur la machine auditée : les seules écritures sont le
//!   magasin local et les fichiers de clés.
//! - **Binaire unique, sans dépendance** d'exécution.

mod keys;
// Interface d'attente : structures du protocole de poussée, consommées par le
// câblage mTLS à venir (TODO(integration) dans push.rs).
#[allow(dead_code)]
mod push;
mod run;
mod storeopen;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use constat_model::AssetId;
use miette::miette;

#[derive(Parser)]
#[command(
    name = "constat-agent",
    version,
    about = "Agent de collecte Constat : lecture seule, aucun port en écoute.",
    long_about = "L'agent lit l'état de configuration de la machine (collecteurs compilés, \
                  jamais téléchargés), expurge les secrets à la source, écrit blobs et \
                  snapshots dans le magasin local et signe l'entrée de journal. \
                  Il n'ouvre aucun port et n'exécute jamais de code envoyé."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Exécute une collecte
    Run {
        /// Une seule collecte, puis terminer (seul mode disponible pour l'instant)
        #[arg(long)]
        once: bool,
        /// Chemin du magasin local (sinon CONSTAT_STORE, sinon ./constat.redb)
        #[arg(long, value_name = "CHEMIN")]
        store: Option<PathBuf>,
        /// Répertoire des clés de signature
        #[arg(long, value_name = "DOSSIER")]
        keys: Option<PathBuf>,
        /// Identifiant de la machine (défaut : le nom d'hôte)
        #[arg(long)]
        asset: Option<String>,
    },
    /// Génère la paire de clés de signature de l'agent
    Keygen {
        /// Répertoire de destination des clés
        #[arg(long, value_name = "DOSSIER")]
        keys: Option<PathBuf>,
        /// Écrase une clé existante (l'ancienne ne vérifiera plus rien)
        #[arg(long)]
        force: bool,
    },
}

fn main() -> miette::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            once,
            store,
            keys: keys_dir,
            asset,
        } => {
            if !once {
                return Err(miette!(
                    help = "utilisez `constat-agent run --once` ; le mode continu \
                            (planification interne) viendra dans une version ultérieure",
                    "seul le mode --once est disponible"
                ));
            }
            cmd_run_once(store, keys_dir, asset)
        }
        Command::Keygen {
            keys: keys_dir,
            force,
        } => {
            let dir = keys::resolve_keys_dir(keys_dir);
            let (key_path, public_hex) = keys::generate(&dir, force)?;
            println!(
                "Paire de clés générée.\n  clé privée   : {}\n  clé publique : {} ({})\n\
                 La clé privée ne quitte jamais cette machine ; la clé publique est \
                 à distribuer aux vérificateurs.",
                key_path.display(),
                dir.join(keys::PUB_FILE).display(),
                public_hex
            );
            Ok(())
        }
    }
}

fn cmd_run_once(
    store_flag: Option<PathBuf>,
    keys_dir: Option<PathBuf>,
    asset: Option<String>,
) -> miette::Result<()> {
    // Les collecteurs sont compilés dans le binaire, jamais téléchargés (§7.1).
    let collectors = constat_collect::all_collectors();

    let asset = AssetId(asset.unwrap_or_else(run::hostname));
    let signer = keys::load(&keys::resolve_keys_dir(keys_dir))?;
    let store_path = storeopen::resolve_store_path(store_flag);
    let mut store = storeopen::open_store(&store_path)?;

    match run::run_once(store.as_mut(), &signer, &collectors, asset, run::now_ms())? {
        run::RunOutcome::NothingAvailable { unavailable } => {
            // Sortie honnête (§7) : jamais de données simulées présentées
            // comme réelles. Rien n'a été collecté, rien n'a été écrit.
            println!(
                "Aucun collecteur disponible sur cette plateforme — rien n'a été \
                 collecté, rien n'a été écrit."
            );
            for (id, reason) in &unavailable {
                println!("  {}  indisponible : {}", id.0, reason);
            }
        }
        run::RunOutcome::Collected(report) => {
            println!(
                "Collecte de {} terminée : {} collecteur(s) réussi(s), {} indisponible(s), {} en échec.",
                report.asset.0,
                report.collected.len(),
                report.unavailable.len(),
                report.failed.len()
            );
            for (id, hash, count) in &report.collected {
                println!(
                    "  {}  blob {}…  {} fait(s)",
                    id.0,
                    &hash.to_hex()[..8],
                    count
                );
            }
            for (id, reason) in &report.unavailable {
                println!("  {}  indisponible : {}", id.0, reason);
            }
            for (id, cause) in &report.failed {
                // Les échecs sont déclarés, jamais masqués (§4.2).
                println!("  {}  ÉCHEC : {}", id.0, cause);
            }
            println!(
                "  snapshot {}…  entrée de journal signée {}… (nouvelle racine)",
                &report.snapshot.to_hex()[..8],
                &report.entry.to_hex()[..8]
            );
        }
    }
    Ok(())
}
