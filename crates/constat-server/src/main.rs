//! Binaire `constat-server` — le dépôt central des collectes.
//!
//! # Propriété d'architecture (§17) : aucun chemin de retour
//!
//! Ce serveur reçoit ; il n'agit jamais sur le parc. Il n'initie aucune
//! connexion vers les machines auditées et ses réponses aux agents sont des
//! accusés de réception sans contenu exécutable ni configuration (voir
//! [`constat_server::receive`]). Compromettre le serveur ne donne pas le
//! contrôle du parc, parce que le serveur n'a aucun moyen d'agir sur lui —
//! c'est une propriété de construction, pas un réglage.
//!
//! # mTLS obligatoire
//!
//! Le serveur refuse de démarrer sans son certificat, sa clé, et l'autorité
//! qui authentifie les certificats clients des agents. Pas de mode « sans
//! TLS pour essayer » : un dépôt de données sensibles ne s'essaie pas en
//! clair.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};
use constat_server::receive::AgentPolicy;
use constat_server::{inventory, serve};
use constat_store::RedbStore;
use miette::miette;

#[derive(Parser)]
#[command(
    name = "constat-server",
    version,
    about = "Serveur collecteur Constat : réception mTLS, aucun chemin de retour vers le parc.",
    long_about = "Reçoit les poussées des agents en mTLS et les range dans le magasin \
                  central. Le serveur n'initie jamais de connexion vers les machines \
                  auditées : le compromettre ne donne aucun moyen d'agir sur le parc (§17)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Démarre le serveur de réception
    Run {
        /// Adresse d'écoute, ex. 0.0.0.0:8443
        #[arg(long, default_value = "0.0.0.0:8443", value_name = "ADRESSE")]
        listen: String,
        /// Certificat du serveur (PEM) — obligatoire
        #[arg(long, value_name = "FICHIER")]
        cert: PathBuf,
        /// Clé privée du certificat serveur (PEM) — obligatoire
        #[arg(long, value_name = "FICHIER")]
        key: PathBuf,
        /// Autorité de certification des agents (PEM) — obligatoire :
        /// tout client sans certificat signé par cette autorité est refusé
        #[arg(long, value_name = "FICHIER")]
        client_ca: PathBuf,
        /// Chemin du magasin central (sinon CONSTAT_STORE, sinon ./constat.redb)
        #[arg(long, value_name = "CHEMIN")]
        store: Option<PathBuf>,
        /// Liste des clés publiques d'agents autorisées : un fichier texte,
        /// une clé Ed25519 en hexadécimal (64 caractères) par ligne,
        /// commentaires avec #. Clé absente = poussée refusée (403) avant
        /// toute écriture. Sans ce fichier : premier-arrivé-enregistré
        /// (TOFU), chaque clé restant verrouillée sur son propre journal.
        #[arg(long, value_name = "FICHIER")]
        allowed_agents: Option<PathBuf>,
    },
    /// Liste les journaux du magasin : clé d'agent abrégée, nombre
    /// d'entrées, date de la dernière entrée, racine — l'inventaire
    /// attendu/observé (§10.2) commence ici. Lecture seule.
    Journals {
        /// Chemin du magasin central (sinon CONSTAT_STORE, sinon ./constat.redb)
        #[arg(long, value_name = "CHEMIN")]
        store: Option<PathBuf>,
    },
}

/// Résout le chemin du magasin : `--store`, sinon `CONSTAT_STORE`, sinon
/// `./constat.redb`.
fn resolve_store_path(store: Option<PathBuf>) -> PathBuf {
    store
        .or_else(|| std::env::var_os("CONSTAT_STORE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("./constat.redb"))
}

/// Configuration validée du serveur.
#[derive(Debug)]
struct ServerConfig {
    listen: String,
    cert: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
    store: PathBuf,
}

/// Valide la configuration : les trois éléments mTLS doivent exister.
/// Sans eux, le serveur refuse de démarrer — pas de mode dégradé.
fn validate(
    listen: String,
    cert: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
    store: Option<PathBuf>,
) -> miette::Result<ServerConfig> {
    let must_exist = |path: &Path, role: &str| -> miette::Result<()> {
        if path.is_file() {
            Ok(())
        } else {
            Err(miette!(
                help = "le serveur refuse de démarrer sans mTLS complet : \
                        certificat serveur, clé privée et autorité des agents \
                        (générables avec rcgen ou votre PKI interne)",
                "{role} introuvable : {}",
                path.display()
            ))
        }
    };
    must_exist(&cert, "certificat serveur (--cert)")?;
    must_exist(&key, "clé privée du serveur (--key)")?;
    must_exist(&client_ca, "autorité des agents (--client-ca)")?;
    if listen.parse::<std::net::SocketAddr>().is_err() {
        return Err(miette!(
            "adresse d'écoute invalide : « {listen} » (attendu : IP:port, ex. 0.0.0.0:8443)"
        ));
    }
    let store = resolve_store_path(store);
    Ok(ServerConfig {
        listen,
        cert,
        key,
        client_ca,
        store,
    })
}

fn main() -> miette::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            listen,
            cert,
            key,
            client_ca,
            store,
            allowed_agents,
        } => {
            let config = validate(listen, cert, key, client_ca, store)?;

            // mTLS d'abord : sans les trois fichiers valides, rien ne démarre.
            let tls = serve::load_tls(&config.cert, &config.key, &config.client_ca)?;

            // Politique d'autorisation des clés d'agents : allowlist si le
            // fichier est fourni (et lisible), TOFU sinon.
            let policy = match &allowed_agents {
                Some(path) => AgentPolicy::from_allowlist_file(path)?,
                None => AgentPolicy::Tofu,
            };

            let store = RedbStore::open(&config.store).map_err(|e| {
                miette!(
                    "impossible d'ouvrir le magasin {} : {e}",
                    config.store.display()
                )
            })?;
            let shared: serve::SharedStore = Arc::new(Mutex::new(store));

            let server = serve::Server::bind(&config.listen, tls, shared)?.with_policy(policy);
            let addr = server
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| config.listen.clone());
            let regime = match &allowed_agents {
                Some(path) => format!("agents autorisés : {}", path.display()),
                None => "TOFU (premier-arrivé-enregistré, une clé = un journal)".to_string(),
            };
            eprintln!(
                "constat-server en écoute sur {addr} — magasin {} — mTLS exigé \
                 (autorité des agents : {}) — {regime}. Réception uniquement : \
                 ce serveur n'initie jamais de connexion vers le parc (§17).",
                config.store.display(),
                config.client_ca.display()
            );
            server.run()
        }
        Command::Journals { store } => {
            let path = resolve_store_path(store);
            let store = RedbStore::open(&path)
                .map_err(|e| miette!("impossible d'ouvrir le magasin {} : {e}", path.display()))?;
            let rows = inventory::inventory(&store)
                .map_err(|e| miette!("lecture des journaux de {} : {e}", path.display()))?;
            print!("{}", inventory::render(&rows));
            Ok(())
        }
    }
}
