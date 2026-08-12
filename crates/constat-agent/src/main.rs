//! Binaire `constat-agent` — l'agent de collecte.
//!
//! # Contraintes §7.1, non négociables
//!
//! - **Aucun port en écoute.** Ce binaire n'appelle jamais `bind`/`listen` :
//!   la seule communication réseau est la poussée sortante mTLS
//!   (`constat-agent push`, module [`constat_agent::push`]).
//! - **Aucune exécution de code envoyé.** Les collecteurs sont compilés dans
//!   le binaire (`constat-collect`) ; rien n'est téléchargé, rien n'est
//!   interprété — y compris la réponse du serveur, dont seul le statut HTTP
//!   est lu.
//! - **Lecture seule** sur la machine auditée : les seules écritures sont le
//!   magasin local et les fichiers de clés.
//! - **Binaire unique, sans dépendance** d'exécution.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use constat_agent::{keys, push, run, storeopen};
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
                  Il n'ouvre aucun port et n'exécute jamais de code envoyé ; \
                  la poussée vers le serveur est exclusivement sortante, en mTLS."
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
    /// Pousse le magasin local vers le serveur (mTLS sortant, idempotent)
    Push {
        /// URL du serveur, ex. https://constat.interne:8443 (https obligatoire)
        #[arg(long, value_name = "URL")]
        server: String,
        /// Certificat client de l'agent (PEM)
        #[arg(long, value_name = "FICHIER")]
        cert: PathBuf,
        /// Clé privée du certificat client (PEM)
        #[arg(long, value_name = "FICHIER")]
        key: PathBuf,
        /// Autorité de certification du serveur (PEM) : la seule acceptée
        #[arg(long, value_name = "FICHIER")]
        ca: PathBuf,
        /// Chemin du magasin local (sinon CONSTAT_STORE, sinon ./constat.redb)
        #[arg(long, value_name = "CHEMIN")]
        store: Option<PathBuf>,
        /// Répertoire des clés de signature (pour annoncer la clé publique)
        #[arg(long, value_name = "DOSSIER")]
        keys: Option<PathBuf>,
        /// Identifiant de la machine (défaut : le nom d'hôte)
        #[arg(long)]
        asset: Option<String>,
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
        Command::Push {
            server,
            cert,
            key,
            ca,
            store,
            keys: keys_dir,
            asset,
        } => cmd_push(server, cert, key, ca, store, keys_dir, asset),
    }
}

fn cmd_run_once(
    store_flag: Option<PathBuf>,
    keys_dir: Option<PathBuf>,
    asset: Option<String>,
) -> miette::Result<()> {
    // Les collecteurs sont compilés dans le binaire, jamais téléchargés (§7.1).
    let collectors = constat_collect::all_collectors();

    // Phase 1 : lecture seule. Ni clés ni magasin ne sont exigés tant qu'on
    // ne sait pas s'il y a quelque chose à écrire — sur une plateforme sans
    // collecteur applicable, l'agent le dit et s'arrête là.
    let collection = run::collect_all(&collectors);
    if collection.is_empty() {
        if collection.failed.is_empty() {
            // Sortie honnête (§7) : jamais de données simulées présentées
            // comme réelles. Rien n'a été collecté, rien n'a été écrit.
            println!(
                "Aucun collecteur disponible sur cette plateforme — rien n'a été \
                 collecté, rien n'a été écrit."
            );
            for (id, reason) in &collection.unavailable {
                println!("  {}  indisponible : {}", id.0, reason);
            }
            return Ok(());
        }
        return Err(run::RunError::AllFailed(run::all_failed_causes(&collection.failed)).into());
    }

    // Phase 2 : il y a de la matière — les clés et le magasin deviennent
    // nécessaires pour écrire et signer.
    let asset = AssetId(asset.unwrap_or_else(run::hostname));
    let signer = keys::load(&keys::resolve_keys_dir(keys_dir))?;
    let store_path = storeopen::resolve_store_path(store_flag);
    let mut store = storeopen::open_store(&store_path)?;

    let report = run::persist(store.as_mut(), &signer, collection, asset, run::now_ms())?;
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
    Ok(())
}

fn cmd_push(
    server: String,
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
    store_flag: Option<PathBuf>,
    keys_dir: Option<PathBuf>,
    asset: Option<String>,
) -> miette::Result<()> {
    let signer = keys::load(&keys::resolve_keys_dir(keys_dir))?;
    let store_path = storeopen::resolve_store_path(store_flag);
    let store = storeopen::open_store(&store_path)?;
    let asset = asset.unwrap_or_else(run::hostname);

    let batch = push::build_batch(
        store.as_ref(),
        signer.verifying_key().to_bytes(),
        asset.clone(),
    )?;
    if batch.is_empty() {
        println!(
            "Magasin {} vide : rien à pousser. Lancez d'abord `constat-agent run --once`.",
            store_path.display()
        );
        return Ok(());
    }

    let config = push::PushConfig {
        server_url: server,
        client_cert: cert,
        client_key: key,
        server_ca: ca,
    };
    push::push(&config, &batch)?;
    // La poussée est idempotente : ces compteurs décrivent le lot émis, le
    // serveur a pu en dédoublonner tout ou partie — c'est un non-événement.
    println!(
        "Poussée de {} acceptée par {} : {} blob(s), {} snapshot(s), {} entrée(s) de journal.",
        asset,
        config.server_url,
        batch.blobs.len(),
        batch.snapshots.len(),
        batch.entries.len()
    );
    Ok(())
}
