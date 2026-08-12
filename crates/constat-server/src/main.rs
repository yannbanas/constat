//! Binaire `constat-server` — le dépôt central des collectes.
//!
//! # Propriété d'architecture (§17) : aucun chemin de retour
//!
//! Ce serveur reçoit ; il n'agit jamais sur le parc. Il n'initie aucune
//! connexion vers les machines auditées et ses réponses aux agents sont des
//! accusés de réception sans contenu exécutable ni configuration (voir
//! [`receive`]). Compromettre le serveur ne donne pas le contrôle du parc,
//! parce que le serveur n'a aucun moyen d'agir sur lui — c'est une propriété
//! de construction, pas un réglage.
//!
//! # mTLS obligatoire
//!
//! Le serveur refuse de démarrer sans son certificat, sa clé, et l'autorité
//! qui authentifie les certificats clients des agents. Pas de mode « sans
//! TLS pour essayer » : un dépôt de données sensibles ne s'essaie pas en
//! clair.

// Interface d'attente : contrat de réception documenté, consommé par le
// câblage rustls à venir (TODO(integration) dans receive.rs).
#[allow(dead_code)]
mod receive;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
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
    },
}

/// Configuration validée du serveur. Les champs mTLS seront consommés par
/// l'écouteur rustls (TODO(integration)) ; ils sont validés dès maintenant
/// pour que le refus de démarrer sans mTLS soit effectif au premier jour.
#[derive(Debug)]
#[allow(dead_code)]
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
    let store = store
        .or_else(|| std::env::var_os("CONSTAT_STORE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("./constat.redb"));
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
        } => {
            let config = validate(listen, cert, key, client_ca, store)?;
            eprintln!(
                "Configuration valide : écoute prévue sur {}, magasin {}.",
                config.listen,
                config.store.display()
            );
            // Pas de serveur factice : tant que la réception n'est pas
            // implémentée, on refuse de démarrer plutôt que de faire
            // semblant d'accepter des poussées.
            Err(miette!(
                help = "TODO(integration) : brancher l'écouteur rustls (mTLS, \
                        certificat client obligatoire) et une implémentation de \
                        `receive::Receiver` sur le magasin concret de constat-store ; \
                        l'interface et le protocole sont documentés dans \
                        crates/constat-server/src/receive.rs",
                "la réception n'est pas encore implémentée : le serveur ne démarre pas \
                 (aucun serveur factice ne sera lancé)"
            ))
        }
    }
}
