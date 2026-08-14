//! Binaire `constat-agent` — l'agent de collecte.
//!
//! # Contraintes §7.1, non négociables
//!
//! - **Aucun port en écoute.** Ce binaire n'appelle jamais `bind`/`listen` :
//!   la seule communication réseau est la poussée sortante mTLS
//!   (`constat-agent push` ou `run --push`, module [`constat_agent::push`]).
//! - **Aucune exécution de code envoyé.** Les collecteurs sont compilés dans
//!   le binaire (`constat-collect`) ; rien n'est téléchargé, rien n'est
//!   interprété — y compris la réponse du serveur, dont seul le statut HTTP
//!   est lu.
//! - **Lecture seule** sur la machine auditée : les seules écritures sont le
//!   magasin local, les fichiers de clés — et, sur demande explicite de
//!   l'opérateur, les fichiers de planification de `install`.
//! - **Privilèges minimaux.** Sur Unix, en mode `--once` démarré root,
//!   l'agent abandonne définitivement ses privilèges après la collecte et
//!   **avant** toute connexion réseau ; sans abandon réussi, la poussée est
//!   refusée (échappatoire explicite : `--allow-root-push`). Modèle de
//!   menace et compromis du mode continu : [`constat_agent::privileges`].
//! - **Binaire unique, sans dépendance** d'exécution. Même le mode continu
//!   (`run --every`) et l'installation (`install`) n'en ajoutent aucune :
//!   la boucle dort avec `std::thread::sleep`, la planification système est
//!   du texte généré (voir [`constat_agent::schedule`] et
//!   [`constat_agent::install`]).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use constat_agent::{install, keys, privileges, push, run, schedule, status, storeopen};
use constat_model::AssetId;
use constat_store::{Signer, Store};
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
    /// Exécute la collecte : une fois (--once) ou en boucle planifiée (--every)
    Run {
        /// Une seule collecte, puis terminer
        #[arg(long)]
        once: bool,
        /// Boucle planifiée : intervalle entre deux collectes, ex. 6h, 30m
        /// (gigue aléatoire ±10 % ; un échec de cycle n'arrête pas la boucle)
        #[arg(long, value_name = "DURÉE")]
        every: Option<String>,
        /// Chemin du magasin local (sinon CONSTAT_STORE, sinon ./constat.redb)
        #[arg(long, value_name = "CHEMIN")]
        store: Option<PathBuf>,
        /// Répertoire des clés de signature
        #[arg(long, value_name = "DOSSIER")]
        keys: Option<PathBuf>,
        /// Identifiant de la machine (défaut : le nom d'hôte)
        #[arg(long)]
        asset: Option<String>,
        /// Pousse vers le serveur après chaque collecte réussie (exige
        /// --server, --cert, --key et --ca) ; un échec de poussée est
        /// déclaré mais ne bloque jamais la collecte locale
        #[arg(long)]
        push: bool,
        #[command(flatten)]
        push_opts: PushOpts,
        /// Unix, mode --once démarré root : utilisateur vers lequel les
        /// privilèges sont définitivement abandonnés après la collecte et
        /// AVANT la poussée (défaut : constat s'il existe, sinon nobody)
        #[arg(long, value_name = "UTILISATEUR")]
        run_as: Option<String>,
        /// Échappatoire explicite et DÉCONSEILLÉE : pousser sans abandonner
        /// les privilèges root (à réserver aux environnements où l'abandon
        /// casse la poussée — sans elle, l'abandon est obligatoire, §7.1)
        #[arg(long)]
        allow_root_push: bool,
        /// Réservée aux tests : borne le nombre de cycles du mode --every
        /// puis rend la main (la boucle est sinon infinie)
        #[arg(long, hide = true, value_name = "N")]
        max_cycles: Option<u64>,
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
    /// Prépare la collecte planifiée via le planificateur du système
    /// (systemd ou Planificateur de tâches) — n'exécute rien, écrit les
    /// fichiers et affiche les commandes à lancer
    Install(InstallArgs),
    /// État du magasin local : dernière collecte par machine, racine
    /// courante, avertissement si la collecte semble arrêtée
    Status {
        /// Chemin du magasin local (sinon CONSTAT_STORE, sinon ./constat.redb)
        #[arg(long, value_name = "CHEMIN")]
        store: Option<PathBuf>,
        /// Intervalle attendu entre deux collectes ; l'avertissement se
        /// déclenche au-delà de deux fois cette durée
        #[arg(long, value_name = "DURÉE", default_value = "6h")]
        every: String,
    },
}

/// Options de poussée partagées par `run` et `install` (optionnelles ici ;
/// la sous-commande `push`, elle, les exige toutes).
#[derive(Args)]
struct PushOpts {
    /// URL du serveur, ex. https://constat.interne:8443 (https obligatoire)
    #[arg(long, value_name = "URL")]
    server: Option<String>,
    /// Certificat client de l'agent (PEM)
    #[arg(long, value_name = "FICHIER")]
    cert: Option<PathBuf>,
    /// Clé privée du certificat client (PEM)
    #[arg(long, value_name = "FICHIER")]
    key: Option<PathBuf>,
    /// Autorité de certification du serveur (PEM) : la seule acceptée
    #[arg(long, value_name = "FICHIER")]
    ca: Option<PathBuf>,
}

impl PushOpts {
    fn any_given(&self) -> bool {
        self.server.is_some() || self.cert.is_some() || self.key.is_some() || self.ca.is_some()
    }

    /// Toutes les options sont là → configuration ; sinon erreur honnête.
    fn to_config(&self) -> miette::Result<push::PushConfig> {
        match (&self.server, &self.cert, &self.key, &self.ca) {
            (Some(server), Some(cert), Some(key), Some(ca)) => Ok(push::PushConfig {
                server_url: server.clone(),
                client_cert: cert.clone(),
                client_key: key.clone(),
                server_ca: ca.clone(),
            }),
            _ => Err(miette!(
                help = "la poussée mTLS exige les quatre options : --server, --cert, --key, --ca",
                "configuration de poussée incomplète"
            )),
        }
    }

    /// Pour `run` : `--push` active la poussée et exige les quatre options ;
    /// sans `--push`, les options de poussée sont refusées (pas d'option
    /// silencieusement ignorée).
    fn for_run(&self, push_flag: bool) -> miette::Result<Option<push::PushConfig>> {
        if !push_flag {
            if self.any_given() {
                return Err(miette!(
                    help = "ajoutez --push pour activer la poussée après collecte",
                    "--server/--cert/--key/--ca fournis sans --push"
                ));
            }
            return Ok(None);
        }
        self.to_config().map(Some)
    }

    /// Pour `install` : la présence de --server active la poussée ; une
    /// configuration partielle est refusée.
    fn for_install(&self) -> miette::Result<Option<push::PushConfig>> {
        if !self.any_given() {
            return Ok(None);
        }
        self.to_config().map(Some)
    }
}

#[derive(Args)]
struct InstallArgs {
    /// Intervalle entre deux collectes, ex. 6h, 30m
    #[arg(long, value_name = "DURÉE", default_value = "6h")]
    every: String,
    /// Chemin du magasin sur la machine cible (défaut selon le système :
    /// /var/lib/constat/constat.redb ou C:\ProgramData\Constat\constat.redb)
    #[arg(long, value_name = "CHEMIN")]
    store: Option<PathBuf>,
    /// Répertoire des clés sur la machine cible (défaut à côté du magasin)
    #[arg(long, value_name = "DOSSIER")]
    keys: Option<PathBuf>,
    #[command(flatten)]
    push_opts: PushOpts,
    /// Affiche les fichiers et les commandes sans rien écrire
    #[arg(long)]
    print: bool,
    /// Linux : répertoire des unités systemd (défaut /etc/systemd/system)
    #[arg(long, value_name = "DOSSIER")]
    unit_dir: Option<PathBuf>,
    /// Windows : fichier XML de la tâche (défaut ./constat-agent-tache.xml)
    #[arg(long, value_name = "FICHIER")]
    out: Option<PathBuf>,
    /// Chemin du binaire tel que le planificateur l'invoquera
    /// (défaut : l'exécutable courant)
    #[arg(long, value_name = "FICHIER")]
    exe: Option<PathBuf>,
    /// Système cible (défaut : celui-ci) — permet de préparer depuis un
    /// poste d'administration les fichiers d'un parc hétérogène
    #[arg(long, value_enum)]
    target: Option<install::InstallTarget>,
}

fn main() -> miette::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            once,
            every,
            store,
            keys: keys_dir,
            asset,
            push: push_flag,
            push_opts,
            run_as,
            allow_root_push,
            max_cycles,
        } => {
            let privilege_opts = run_as.is_some() || allow_root_push;
            if privilege_opts && !cfg!(unix) {
                return Err(miette!(
                    help = "l'abandon de privilèges est un mécanisme Unix (setresuid) ; \
                            sous Windows la tâche planifiée tourne en SYSTEM, borné \
                            autrement — voir `constat-agent install`",
                    "--run-as/--allow-root-push : options Unix uniquement"
                ));
            }
            let config = RunConfig {
                store,
                keys: keys_dir,
                asset,
                push: push_opts.for_run(push_flag)?,
                drop_after_collect: once,
                run_as,
                allow_root_push,
            };
            if privilege_opts && config.push.is_none() {
                return Err(miette!(
                    help = "l'abandon de privilèges borne la phase réseau ; sans poussée, \
                            le processus se termine juste après la collecte et il n'y a \
                            rien à borner",
                    "--run-as/--allow-root-push exigent --push"
                ));
            }
            match (once, every) {
                (true, Some(_)) => Err(miette!(
                    help = "--once fait une collecte puis termine ; --every boucle",
                    "--once et --every s'excluent mutuellement"
                )),
                (false, None) => Err(miette!(
                    help = "utilisez `run --once` (une collecte, puis terminer) ou \
                            `run --every 6h` (boucle planifiée, gigue ±10 %)",
                    "précisez le mode : --once ou --every <durée>"
                )),
                (true, None) => {
                    if max_cycles.is_some() {
                        return Err(miette!(
                            help = "--max-cycles borne la boucle du mode --every (option de test)",
                            "--max-cycles n'a pas de sens avec --once"
                        ));
                    }
                    if privilege_opts && !privileges::running_as_root() {
                        return Err(miette!(
                            help = "--run-as/--allow-root-push gouvernent l'abandon de \
                                    privilèges d'un agent démarré root ; sans euid 0, il \
                                    n'y a rien à abandonner",
                            "--run-as/--allow-root-push fournis mais l'agent ne démarre \
                             pas en root"
                        ));
                    }
                    cycle_once(&config)
                }
                (false, Some(every)) => {
                    if privilege_opts {
                        return Err(miette!(
                            help = "en mode continu, l'agent n'abandonne PAS ses privilèges \
                                    in-process : la collecte suivante devrait relire les \
                                    fichiers protégés. La réduction vient du durcissement \
                                    systemd — préférez `constat-agent install` (timer + \
                                    `run --once`, abandon systématique avant la poussée)",
                            "--run-as/--allow-root-push n'existent qu'en mode --once"
                        ));
                    }
                    cmd_run_every(&every, max_cycles, &config)
                }
            }
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
        Command::Install(args) => cmd_install(args),
        Command::Status { store, every } => cmd_status(store, &every),
    }
}

/// Ce qu'un cycle de collecte doit savoir — commun à `--once` et `--every`.
struct RunConfig {
    store: Option<PathBuf>,
    keys: Option<PathBuf>,
    asset: Option<String>,
    /// Poussée après collecte réussie (`--push`) ; l'échec de poussée est
    /// déclaré mais jamais bloquant.
    push: Option<push::PushConfig>,
    /// Mode `--once` : sur Unix démarré root, les privilèges sont
    /// définitivement abandonnés après la collecte et avant la poussée
    /// (§7.1, voir [`constat_agent::privileges`]). Faux en mode `--every` :
    /// le cycle suivant doit relire les fichiers protégés — compromis
    /// documenté, la réduction vient alors du durcissement systemd.
    drop_after_collect: bool,
    /// Utilisateur cible de l'abandon (`--run-as`) ; défaut : `constat`
    /// s'il existe, sinon `nobody`.
    run_as: Option<String>,
    /// Échappatoire explicite et déconseillée (`--allow-root-push`) :
    /// pousser sans abandonner. Sans elle, l'abandon est obligatoire.
    allow_root_push: bool,
}

/// Un cycle complet : collecter, journaliser, et pousser si demandé.
///
/// Le magasin est ouvert puis refermé à chaque cycle : en mode `--every`,
/// cela coûte quelques millisecondes toutes les six heures et rend chaque
/// cycle indépendant du précédent — un cycle en échec ne laisse rien
/// d'ouvert derrière lui.
fn cycle_once(config: &RunConfig) -> miette::Result<()> {
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
    let asset = AssetId(config.asset.clone().unwrap_or_else(run::hostname));
    let signer = keys::load(&keys::resolve_keys_dir(config.keys.clone()))?;
    let store_path = storeopen::resolve_store_path(config.store.clone());
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

    push_phase(config, store, &signer, &report.asset.0)
}

/// La phase réseau d'un cycle — et l'endroit où §7.1 (« abandon après
/// collecte ») se joue.
///
/// Sur Unix, en mode `--once` démarré root, l'ordre est strict : le lot et
/// le matériel TLS sont préparés **en mémoire**, le magasin est fermé, les
/// privilèges sont définitivement abandonnés
/// ([`constat_agent::privileges::drop_now`]), et alors seulement la
/// connexion sort. Un échec d'abandon **refuse la poussée** (erreur fatale)
/// — sauf `--allow-root-push`, échappatoire explicite et déconseillée. Un
/// échec de la poussée elle-même reste déclaré et non bloquant, comme
/// toujours.
///
/// Le lot est construit avant l'abandon parce que le magasin redb ne
/// s'ouvre qu'en lecture-écriture : le rouvrir en tant qu'utilisateur cible
/// exigerait de rendre le magasin inscriptible par lui — pire que garder en
/// mémoire un lot déjà expurgé, qui est exactement ce qui part sur le
/// réseau. Même logique pour le matériel TLS : chargé avant l'abandon, la
/// clé cliente peut rester lisible par root seul (0600).
fn push_phase(
    config: &RunConfig,
    store: Box<dyn Store>,
    signer: &Signer,
    asset: &str,
) -> miette::Result<()> {
    let Some(push_config) = &config.push else {
        return Ok(());
    };
    if !(config.drop_after_collect && privileges::running_as_root()) {
        // Sans privilèges à abandonner (agent non root, Windows) ou en mode
        // continu (compromis documenté : l'abandon rendrait la collecte
        // suivante impossible), la poussée part telle quelle.
        push_after_collect(push_config, store.as_ref(), signer, asset);
        return Ok(());
    }
    if config.allow_root_push {
        println!(
            "  AVERTISSEMENT : --allow-root-push — poussée SANS abandon de privilèges \
             (déconseillé, §7.1)."
        );
        push_after_collect(push_config, store.as_ref(), signer, asset);
        return Ok(());
    }

    // Tout ce que la poussée relira est préparé AVANT l'abandon…
    let prepared = push::build_batch(
        store.as_ref(),
        signer.verifying_key().to_bytes(),
        asset.to_string(),
    )
    .and_then(|batch| push::load_tls_config(push_config).map(|tls| (batch, tls)));
    // …le magasin est fermé (plus aucun descripteur ouvert)…
    drop(store);
    // …et les privilèges abandonnés, définitivement, avant toute connexion.
    // Un échec ici est FATAL : jamais de poussée root par accident.
    let target = privileges::drop_now(config.run_as.as_deref())?;
    println!(
        "  privilèges abandonnés avant la poussée : {} (uid {}, gid {}) — \
         réacquisition vérifiée impossible.",
        target.name, target.uid, target.gid
    );

    let result = prepared
        .and_then(|(batch, tls)| push::push_with_tls(push_config, tls, &batch).map(|()| batch));
    report_push_result(&push_config.server_url, result);
    Ok(())
}

/// Poussée post-collecte sans abandon préalable (agent non root, Windows,
/// mode continu, ou `--allow-root-push`).
fn push_after_collect(config: &push::PushConfig, store: &dyn Store, signer: &Signer, asset: &str) {
    let result = push::build_batch(store, signer.verifying_key().to_bytes(), asset.to_string())
        .and_then(|batch| push::push(config, &batch).map(|()| batch));
    report_push_result(&config.server_url, result);
}

/// Compte rendu d'une poussée. L'échec est **déclaré, jamais bloquant** : la
/// collecte locale est déjà journalisée — c'est elle, la preuve — et la
/// poussée suivante rattrape tout, puisqu'elle est idempotente (le lot
/// émet l'intégralité du magasin, le serveur dédoublonne).
fn report_push_result(server_url: &str, result: Result<push::PushBatch, push::PushError>) {
    match result {
        Ok(batch) => println!(
            "  poussée acceptée par {} : {} blob(s), {} snapshot(s), {} entrée(s) de journal.",
            server_url,
            batch.blobs.len(),
            batch.snapshots.len(),
            batch.entries.len()
        ),
        Err(e) => println!(
            "  poussée vers {} ÉCHOUÉE : {e}\n  (déclarée, non bloquante : la collecte \
             locale est journalisée, la prochaine poussée rattrapera — idempotente)",
            server_url
        ),
    }
}

/// Le mode continu : `run --every <durée>`. Voir [`constat_agent::schedule`]
/// pour les choix documentés (gigue ±10 %, arrêt par Ctrl-C non intercepté).
fn cmd_run_every(every: &str, max_cycles: Option<u64>, config: &RunConfig) -> miette::Result<()> {
    let interval = schedule::parse_every(every)?;
    println!(
        "Collecte planifiée toutes les {every}, gigue ±10 %. Arrêt : Ctrl-C — brutal \
         mais sans danger, le magasin est transactionnel et la poussée idempotente."
    );
    if privileges::running_as_root() && config.push.is_some() {
        // Compromis documenté (§7.1, module `privileges`) : en mode continu,
        // pas d'abandon in-process — dit à l'opérateur, pas seulement dans
        // la documentation.
        println!(
            "Mode continu démarré root : PAS d'abandon de privilèges in-process (la \
             collecte suivante doit relire les fichiers protégés) ; les poussées \
             s'exécutent donc en root. La réduction vient du durcissement du service \
             (voir `constat-agent install`). Mode recommandé : timer système + \
             `run --once`, qui abandonne systématiquement avant chaque poussée."
        );
    }
    let options = schedule::EveryOptions {
        interval,
        max_cycles,
    };
    schedule::run_every(&options, |n| {
        println!("\n[{}] cycle {n}", status::ts_display(run::now_ms()));
        if let Err(e) = cycle_once(config) {
            // Échec déclaré, boucle poursuivie : la continuité de la preuve
            // prime (§4.2) — l'interruption restera visible dans la
            // couverture, elle n'est ni masquée ni fatale.
            println!("cycle {n} en ÉCHEC : {e:?}");
            println!("la boucle continue — le trou de collecte restera déclaré, pas masqué.");
        }
    });
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

/// `constat-agent install` : écrit les fichiers de planification demandés
/// et affiche les commandes d'activation — **sans jamais les exécuter**.
fn cmd_install(args: InstallArgs) -> miette::Result<()> {
    let every = schedule::parse_every(&args.every)?;
    let target = args.target.unwrap_or_else(install::InstallTarget::current);
    let options = install::InstallOptions {
        every,
        exe: match args.exe {
            Some(p) => p.display().to_string(),
            // Sur le système courant : l'exécutable qui tourne. Pour une
            // autre cible, son chemin n'aurait aucun sens là-bas — on prend
            // le chemin conventionnel, remplaçable par --exe.
            None if target == install::InstallTarget::current() => std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| target.default_exe().to_string()),
            None => target.default_exe().to_string(),
        },
        store: args
            .store
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| target.default_store().to_string()),
        keys: args
            .keys
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| target.default_keys().to_string()),
        push: args.push_opts.for_install()?,
    };

    match target {
        install::InstallTarget::Linux => {
            let service = install::systemd_service(&options);
            let timer = install::systemd_timer(&options);
            let unit_dir = args
                .unit_dir
                .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"));
            let service_path = unit_dir.join(install::SERVICE_UNIT);
            let timer_path = unit_dir.join(install::TIMER_UNIT);

            if args.print {
                println!("--- {} ---\n{service}", service_path.display());
                println!("--- {} ---\n{timer}", timer_path.display());
                println!("(--print : rien n'a été écrit)\n");
            } else {
                std::fs::create_dir_all(&unit_dir)
                    .map_err(|e| miette!("impossible de créer {} : {e}", unit_dir.display()))?;
                write_file(&service_path, &service)?;
                write_file(&timer_path, &timer)?;
                println!(
                    "Fichiers écrits (et rien d'autre : aucune commande exécutée) :\n  {}\n  {}\n",
                    service_path.display(),
                    timer_path.display()
                );
            }

            println!("Modèle de privilèges (§7.1) :");
            println!(
                "  Le service démarre root (lire /etc/shadow l'exige), borné par les\n\
                 \x20 directives commentées dans l'unité. En mode --once — celui du timer —\n\
                 \x20 l'agent abandonne définitivement ses privilèges après la collecte et\n\
                 \x20 AVANT toute connexion réseau (--run-as ; défaut : constat, sinon\n\
                 \x20 nobody). Le mode continu `run --every` ne peut pas abandonner\n\
                 \x20 in-process (la collecte suivante relirait les fichiers protégés) : sa\n\
                 \x20 réduction viendrait du seul durcissement systemd — préférez le timer.\n"
            );
            println!("Avant la première collecte (une fois) :");
            if let Some(dir) = install::parent_unix(&options.store) {
                println!("  mkdir -p {dir}");
            }
            println!("  {} keygen --keys {}\n", options.exe, options.keys);
            println!("Pour activer (la décision reste à l'opérateur) :");
            println!("  systemctl daemon-reload");
            println!("  systemctl enable --now {}\n", install::TIMER_UNIT);
            println!("Pour vérifier :");
            println!("  systemctl list-timers {}", install::TIMER_UNIT);
            println!(
                "  {} status --store {} --every {}",
                options.exe, options.store, args.every
            );
        }
        install::InstallTarget::Windows => {
            let xml = install::windows_task_xml(&options);
            let out = args
                .out
                .unwrap_or_else(|| PathBuf::from("constat-agent-tache.xml"));

            if args.print {
                println!("--- {} ---\n{xml}", out.display());
                println!("(--print : rien n'a été écrit)\n");
            } else {
                write_file(&out, &xml)?;
                println!(
                    "Fichier écrit (et rien d'autre : aucune commande exécutée) :\n  {}\n",
                    out.display()
                );
            }

            println!("Modèle de privilèges (§7.1) :");
            println!(
                "  La tâche tourne en SYSTEM : les lectures qu'exige la collecte (SAM,\n\
                 \x20 GPO appliquées, registre protégé) sont refusées à un compte à faible\n\
                 \x20 privilège, et Windows n'a pas d'équivalent de CAP_DAC_READ_SEARCH —\n\
                 \x20 l'abandon in-process du monde Unix n'a pas de traduction ici. SYSTEM\n\
                 \x20 reste borné : aucun port en écoute, aucune exécution de code envoyé,\n\
                 \x20 lecture seule hors magasin/clés, une heure d'exécution au plus,\n\
                 \x20 jamais deux instances (détail dans le XML généré).\n"
            );
            println!("Avant la première collecte (une fois, en console administrateur) :");
            println!("  \"{}\" keygen --keys \"{}\"\n", options.exe, options.keys);
            println!("Pour enregistrer la tâche (la décision reste à l'opérateur) :");
            println!(
                "  schtasks /create /tn \"{}\" /xml \"{}\"\n",
                install::TASK_NAME,
                out.display()
            );
            println!("Pour vérifier :");
            println!("  schtasks /query /tn \"{}\"", install::TASK_NAME);
            println!(
                "  \"{}\" status --store \"{}\" --every {}",
                options.exe, options.store, args.every
            );
        }
    }
    Ok(())
}

/// `constat-agent status` : lit le magasin et rend l'état, avec un
/// avertissement si la dernière entrée a plus de deux fois `--every`.
fn cmd_status(store_flag: Option<PathBuf>, every: &str) -> miette::Result<()> {
    let expected = schedule::parse_every(every)?;
    let store_path = storeopen::resolve_store_path(store_flag);
    // Ne pas créer un magasin vide juste pour le regarder : un chemin sans
    // fichier signifie qu'aucune collecte n'a eu lieu — on le dit.
    if !store_path.exists() {
        return Err(miette!(
            help = "aucune collecte n'a encore eu lieu ici — lancez \
                    `constat-agent run --once`, ou désignez le magasin avec \
                    --store ou CONSTAT_STORE",
            "aucun magasin à {}",
            store_path.display()
        ));
    }
    let store = storeopen::open_store(&store_path)?;
    let data = status::compute(store.as_ref()).map_err(run::RunError::Store)?;
    print!(
        "{}",
        status::render(
            &data,
            &store_path.display().to_string(),
            run::now_ms(),
            expected
        )
    );
    Ok(())
}

/// Écrit un fichier avec une erreur miette lisible.
fn write_file(path: &std::path::Path, content: &str) -> miette::Result<()> {
    std::fs::write(path, content)
        .map_err(|e| miette!("impossible d'écrire {} : {e}", path.display()))
}
