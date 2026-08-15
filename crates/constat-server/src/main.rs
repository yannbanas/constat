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

use clap::{Parser, Subcommand, ValueEnum};
use constat_server::receive::AgentPolicy;
use constat_server::{agents, inventory, monitor, serve};
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
        /// Nombre de connexions traitées SIMULTANÉMENT (défaut : 64). Ce
        /// n'est pas un serveur haute charge (un thread par connexion) mais
        /// cette borne évite qu'un flot de connexions n'épuise threads et
        /// mémoire : au-delà, l'acceptation attend qu'un créneau se libère
        /// (chaque connexion est coupée après 30 s). À augmenter si un parc
        /// nombreux pousse en rafales.
        #[arg(long, value_name = "N", default_value_t = serve::DEFAULT_MAX_CONNECTIONS)]
        max_connections: usize,
    },
    /// Liste les journaux du magasin : clé d'agent abrégée, nombre
    /// d'entrées, date de la dernière entrée, racine — l'inventaire
    /// attendu/observé (§10.2) commence ici. Lecture seule.
    Journals {
        /// Chemin du magasin central (sinon CONSTAT_STORE, sinon ./constat.redb)
        #[arg(long, value_name = "CHEMIN")]
        store: Option<PathBuf>,
    },
    /// Gère le fichier d'agents autorisés (--allowed-agents) : liste,
    /// ajout, retrait, révocation tracée. Les clés sont des clés de
    /// GENÈSE — des identités : une rotation de clé d'agent ne demande
    /// aucune modification ici, une révocation retire l'identité entière.
    /// Le fichier est préservé (commentaires, ordre) ; relancez le serveur
    /// pour prendre en compte la modification.
    Agents {
        /// Le fichier d'agents autorisés à éditer (celui de
        /// --allowed-agents)
        #[arg(long, value_name = "FICHIER")]
        file: PathBuf,
        #[command(subcommand)]
        action: AgentsAction,
    },
    /// Supervision : par journal/agent, dernière entrée, âge, entrées,
    /// racine. Code de sortie 1 si un journal dépasse --max-age ou si
    /// l'inventaire s'écarte de --expected — utilisable tel quel en check
    /// cron/Nagios. Aucun port, aucun endpoint : la supervision est un
    /// binaire qu'on lance, pas une surface d'attaque (§17). Lecture seule.
    Status {
        /// Chemin du magasin central (sinon CONSTAT_STORE, sinon ./constat.redb)
        #[arg(long, value_name = "CHEMIN")]
        store: Option<PathBuf>,
        /// Âge maximal toléré de la dernière entrée de chaque journal
        /// (ex. 90s, 30min, 6h, 7j). Dépassé : code de sortie 1.
        #[arg(long, value_name = "DURÉE")]
        max_age: Option<String>,
        /// Format de sortie : `text` (lisible) ou `prometheus` (métriques
        /// textfile pour le textfile collector de node_exporter).
        #[arg(long, value_enum, default_value_t = StatusFormat::Text)]
        format: StatusFormat,
        /// Inventaire attendu : un fichier texte, une entrée par ligne —
        /// `<clé publique hex 64 caractères> [nom]` ou `default [nom]`,
        /// commentaires avec #. Les journaux attendus absents et les
        /// journaux inattendus sont signalés : l'écart est un constat
        /// (§10.2) — code de sortie 1.
        #[arg(long, value_name = "FICHIER")]
        expected: Option<PathBuf>,
    },
}

/// Actions de `constat-server agents`.
#[derive(Subcommand)]
enum AgentsAction {
    /// Liste les agents autorisés (clé de genèse, nom éventuel)
    List,
    /// Ajoute une clé de genèse (le nom devient un commentaire de fin de
    /// ligne). Crée le fichier s'il n'existe pas.
    Add {
        /// Clé publique Ed25519 de genèse, 64 caractères hexadécimaux
        /// (le contenu d'agent.pub d'origine)
        key: String,
        /// Nom lisible de l'agent (optionnel)
        name: Option<String>,
    },
    /// Retire une clé de genèse (l'identité entière, rotations comprises)
    Remove {
        /// Clé publique Ed25519 de genèse, 64 caractères hexadécimaux
        key: String,
    },
    /// Révoque une clé de genèse : retrait + note datée en commentaire —
    /// la révocation est tracée dans le fichier. Procédure complète de
    /// compromission : docs/cles.md
    Revoke {
        /// Clé publique Ed25519 de genèse, 64 caractères hexadécimaux
        key: String,
    },
}

/// Format de sortie de `constat-server status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StatusFormat {
    /// Texte lisible, une ligne par journal.
    Text,
    /// Métriques textfile Prometheus (node_exporter textfile collector).
    Prometheus,
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
            max_connections,
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

            let server = serve::Server::bind(&config.listen, tls, shared)?
                .with_policy(policy)
                .with_max_connections(max_connections);
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
                 (autorité des agents : {}) — {regime} — {max_connections} connexions \
                 simultanées au plus. Réception uniquement : ce serveur n'initie \
                 jamais de connexion vers le parc (§17).",
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
        Command::Agents { file, action } => cmd_agents(&file, action),
        Command::Status {
            store,
            max_age,
            format,
            expected,
        } => cmd_status(store, max_age, format, expected),
    }
}

/// `constat-server agents` : édite le fichier d'agents autorisés en le
/// préservant (commentaires, ordre). Les transformations sont pures
/// ([`agents`]) ; cette fonction ne fait que lire et réécrire le fichier.
fn cmd_agents(file: &Path, action: AgentsAction) -> miette::Result<()> {
    let read = |must_exist: bool| -> miette::Result<String> {
        match std::fs::read_to_string(file) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !must_exist => Ok(String::new()),
            Err(e) => Err(miette!(
                help = "indiquez avec --file le fichier passé au serveur via --allowed-agents",
                "fichier d'agents autorisés illisible ({}) : {e}",
                file.display()
            )),
        }
    };
    let write = |text: String| -> miette::Result<()> {
        std::fs::write(file, text)
            .map_err(|e| miette!("impossible d'écrire {} : {e}", file.display()))?;
        println!(
            "{} mis à jour. Relancez le serveur (ou attendez son prochain démarrage) \
             pour prendre en compte la modification.",
            file.display()
        );
        Ok(())
    };
    match action {
        AgentsAction::List => {
            let rows = agents::list(&read(true)?)?;
            if rows.is_empty() {
                println!(
                    "Aucun agent autorisé dans {} : TOUTE poussée est refusée tant que \
                     ce fichier est passé via --allowed-agents.",
                    file.display()
                );
                return Ok(());
            }
            println!("Agents autorisés ({}) — clés de GENÈSE :", file.display());
            for row in rows {
                match row.name {
                    Some(name) => println!("  {}  {name}", row.key_hex),
                    None => println!("  {}", row.key_hex),
                }
            }
            Ok(())
        }
        AgentsAction::Add { key, name } => {
            let text = agents::add(&read(false)?, &key, name.as_deref())?;
            write(text)
        }
        AgentsAction::Remove { key } => {
            let text = agents::remove(&read(true)?, &key)?;
            write(text)
        }
        AgentsAction::Revoke { key } => {
            // L'horloge n'entre qu'ici : la note de révocation est datée du
            // jour, le module reste pur et testable.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| constat_model::Timestamp(d.as_millis() as i64))
                .unwrap_or(constat_model::Timestamp::UNIX_EPOCH);
            let date = now.to_rfc3339().unwrap_or_else(|_| format!("{} ms", now.0));
            let text = agents::revoke(&read(true)?, &key, &date)?;
            write(text)?;
            println!(
                "Révocation tracée dans le fichier. Rappel (docs/cles.md) : révoquer \
                 côté serveur n'est que la première étape d'une compromission — ancrez \
                 la racine du journal concerné et investiguez depuis la dernière racine \
                 ancrée."
            );
            Ok(())
        }
    }
}

/// `constat-server status` : calcule le rapport de supervision et sort avec
/// le code 1 si quelque chose alerte (retard ou écart d'inventaire) — le
/// texte explique, le code de sortie décide.
fn cmd_status(
    store: Option<PathBuf>,
    max_age: Option<String>,
    format: StatusFormat,
    expected: Option<PathBuf>,
) -> miette::Result<()> {
    let max_age = max_age.as_deref().map(monitor::parse_max_age).transpose()?;
    let expected = expected
        .map(|path| -> miette::Result<Vec<monitor::ExpectedEntry>> {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| miette!("fichier --expected illisible : {} : {e}", path.display()))?;
            Ok(monitor::parse_expected(&content)?)
        })
        .transpose()?;

    let path = resolve_store_path(store);
    // Taille du fichier du magasin — pour `constat_store_size_bytes`.
    // `None` (et non une erreur) si le fichier n'est pas mesurable.
    let store_size = std::fs::metadata(&path).ok().map(|m| m.len());
    let store = RedbStore::open(&path)
        .map_err(|e| miette!("impossible d'ouvrir le magasin {} : {e}", path.display()))?;

    // L'horloge n'entre qu'ici : tout le calcul en aval est testable à date fixe.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| constat_model::Timestamp(d.as_millis() as i64))
        .unwrap_or(constat_model::Timestamp::UNIX_EPOCH);

    let report = monitor::compute(&store, now, max_age, expected.as_deref(), store_size)
        .map_err(|e| miette!("lecture des journaux de {} : {e}", path.display()))?;

    match format {
        StatusFormat::Text => print!(
            "{}",
            monitor::render_text(&report, &path.display().to_string())
        ),
        StatusFormat::Prometheus => print!("{}", monitor::render_prometheus(&report)),
    }

    if report.alert() {
        // Convention des checks (cron, Nagios) : 1 = alerte. La sortie est
        // déjà écrite et expliquée ; le code de sortie porte le verdict.
        std::process::exit(1);
    }
    Ok(())
}
