//! Binaire `constat` — l'interface en ligne de commande du §10.
//!
//! ```text
//! constat state    --asset srv-fic-01 --at 2026-03-03T14:00
//! constat diff     --asset srv-fic-01 --from 2026-03-01 --to 2026-03-31
//! constat history  --entity "user:jdupont" --attr "user.privileged"
//! constat timeline --assertion SSH-ROOT --period 2026-Q1
//! constat check    --period 2026-Q1 --explain
//! constat pack     --period 2026-Q1 --referential exemple --out dossier-Q1.html
//! constat segmentation --flows flows.yaml --at 2026-03-03T14:00
//! constat anchor   --send https://tsa.exemple.fr/tsr
//! constat export   --out ./export
//! constat verify   ./export
//! ```

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use constat_cli::{commands, segmentation, storeopen};

#[derive(Parser)]
#[command(
    name = "constat",
    version,
    about = "Constat — l'état de votre infrastructure dans la durée, avec preuve.",
    long_about = "Constat enregistre l'état de configuration d'une infrastructure dans la \
                  durée, de façon non falsifiable, et produit la preuve qu'un auditeur \
                  accepte. Cette CLI interroge le magasin local : elle ne modifie rien, \
                  jamais — à l'exception de `segmentation --record`, qui ajoute des faits \
                  signés au journal (le verdict d'accessibilité est un constat comme un \
                  autre, §14)."
)]
struct Cli {
    /// Chemin du magasin (sinon variable CONSTAT_STORE, sinon ./constat.redb)
    #[arg(long, global = true, value_name = "CHEMIN")]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// État d'une machine à une date : dernier snapshot antérieur + faits
    State {
        /// Machine interrogée, ex. srv-fic-01
        #[arg(long)]
        asset: String,
        /// Date, ex. 2026-03-03 ou 2026-03-03T14:00
        #[arg(long)]
        at: String,
    },
    /// Différence d'état d'une machine entre deux dates
    Diff {
        /// Machine interrogée
        #[arg(long)]
        asset: String,
        /// Date de départ
        #[arg(long)]
        from: String,
        /// Date d'arrivée
        #[arg(long)]
        to: String,
    },
    /// Historique daté d'un attribut d'une entité, avec preuve et couverture
    History {
        /// Entité, ex. "user:jdupont"
        #[arg(long)]
        entity: String,
        /// Attribut, ex. "user.privileged"
        #[arg(long)]
        attr: String,
        /// Restreindre à une période, ex. 2026-Q1
        #[arg(long)]
        period: Option<String>,
    },
    /// Chronologie du verdict d'une assertion sur une période
    Timeline {
        /// Identifiant de l'assertion, ex. SSH-ROOT
        #[arg(long)]
        assertion: String,
        /// Période, ex. 2026-Q1 ou 2026-03
        #[arg(long)]
        period: String,
        /// Fichier d'assertions
        #[arg(long, default_value = "assertions.yaml", value_name = "FICHIER")]
        assertions: PathBuf,
    },
    /// Évalue les assertions : verdicts, couverture, violations
    Check {
        /// Période d'évaluation, ex. 2026-Q1 (défaut : l'empan des collectes)
        #[arg(long)]
        period: Option<String>,
        /// Explique chaque violation : machine, entité, valeurs, dates, preuve
        #[arg(long)]
        explain: bool,
        /// Fichier d'assertions
        #[arg(long, default_value = "assertions.yaml", value_name = "FICHIER")]
        assertions: PathBuf,
    },
    /// Génère le dossier de preuve d'une période (HTML autonome, imprimable)
    Pack {
        /// Période couverte, ex. 2026-Q1
        #[arg(long)]
        period: String,
        /// Fichier de sortie, ex. dossier-Q1.html
        #[arg(long, value_name = "FICHIER")]
        out: PathBuf,
        /// Référentiel de correspondance : chemin d'un fichier YAML, ou nom
        /// court résolu en referentials/<nom>.yaml (voir referentials/exemple.yaml)
        #[arg(long, value_name = "FICHIER-OU-NOM")]
        referential: Option<String>,
        /// Fichier d'assertions
        #[arg(long, default_value = "assertions.yaml", value_name = "FICHIER")]
        assertions: PathBuf,
        /// Organisation auditée (page de couverture)
        #[arg(long)]
        organization: Option<String>,
        /// Inventaire des machines attendues (une par ligne, # commente) —
        /// sans lui, l'écart attendu/observé ne peut pas être constaté
        #[arg(long, value_name = "FICHIER")]
        inventory: Option<PathBuf>,
        /// Fichier de clé publique du journal (hexadécimal ou 32 octets bruts)
        #[arg(long, value_name = "FICHIER")]
        pubkey: Option<PathBuf>,
        /// Répertoire des clés de l'agent (agent.pub / agent.key)
        #[arg(long, value_name = "DOSSIER")]
        keys: Option<PathBuf>,
    },
    /// Ancre la racine courante du journal hors du système (§6.3)
    Anchor {
        /// Écrit la requête d'horodatage RFC 3161 (DER) dans ce fichier
        #[arg(long, value_name = "FICHIER")]
        out: Option<PathBuf>,
        /// Écrit un export de racine signé (niveau 2) dans ce fichier
        #[arg(long, value_name = "FICHIER")]
        export: Option<PathBuf>,
        /// Envoie la requête RFC 3161 à ce prestataire (http:// ou https://)
        /// et archive le jeton dans <magasin>.anchors/<racine>.tsr
        #[arg(long, value_name = "URL")]
        send: Option<String>,
        /// Répertoire des clés de l'agent (pour signer l'export)
        #[arg(long, value_name = "DOSSIER")]
        keys: Option<PathBuf>,
        /// Organisation, inscrite dans le document d'export
        #[arg(long)]
        organization: Option<String>,
    },
    /// Preuve de segmentation : évalue les configurations réseau historiques
    /// avec le moteur de Calque (jonction §14) — codes de sortie 0 conforme,
    /// 1 violation, 3 non concluant
    Segmentation {
        /// Fichier de flux, au format flows.yaml natif de Calque (le même
        /// fichier que `calque test`)
        #[arg(long, value_name = "FICHIER")]
        flows: PathBuf,
        /// Date d'évaluation : dernier blob network.configs antérieur
        #[arg(long, conflicts_with = "period", required_unless_present = "period")]
        at: Option<String>,
        /// Période, ex. 2026-Q1 : chronologie des verdicts à chaque
        /// changement de configuration, avec couverture et trous déclarés
        #[arg(long)]
        period: Option<String>,
        /// Enregistre le verdict comme entrée signée du journal (§14) —
        /// la seule commande de la CLI qui écrit dans le magasin
        #[arg(long, conflicts_with = "period")]
        record: bool,
        /// Répertoire des clés de l'agent (agent.key) pour signer
        /// l'enregistrement
        #[arg(long, value_name = "DOSSIER", requires = "record")]
        keys: Option<PathBuf>,
        /// Machine du snapshot enregistré par --record
        #[arg(long, default_value = constat_cli::segmentation::DEFAULT_ASSET)]
        asset: String,
    },
    /// Rappelle comment vérifier un dossier SANS Constat (binaire séparé, §10.3)
    Verify {
        /// Répertoire d'export à vérifier (produit par `constat export --out`)
        #[arg(value_name = "DOSSIER")]
        export: Option<PathBuf>,
    },
    /// Exporte la clôture de preuve du journal, vérifiable par constat-verify
    Export {
        /// Répertoire de sortie (créé si nécessaire)
        #[arg(long, value_name = "DOSSIER")]
        out: PathBuf,
        /// Fichier de clé publique du journal (hexadécimal ou 32 octets bruts)
        #[arg(long, value_name = "FICHIER")]
        pubkey: Option<PathBuf>,
        /// Répertoire des clés de l'agent (agent.pub / agent.key)
        #[arg(long, value_name = "DOSSIER")]
        keys: Option<PathBuf>,
    },
}

fn main() -> miette::Result<()> {
    let cli = Cli::parse();
    let store_path = storeopen::resolve_store_path(cli.store);

    match cli.command {
        Command::State { asset, at } => {
            let store = storeopen::open_store(&store_path)?;
            println!("{}", commands::cmd_state(store.as_ref(), &asset, &at)?);
        }
        Command::Diff { asset, from, to } => {
            let store = storeopen::open_store(&store_path)?;
            println!(
                "{}",
                commands::cmd_diff(store.as_ref(), &asset, &from, &to)?
            );
        }
        Command::History {
            entity,
            attr,
            period,
        } => {
            let store = storeopen::open_store(&store_path)?;
            println!(
                "{}",
                commands::cmd_history(store.as_ref(), &entity, &attr, period.as_deref())?
            );
        }
        Command::Timeline {
            assertion,
            period,
            assertions,
        } => {
            let store = storeopen::open_store(&store_path)?;
            println!(
                "{}",
                commands::cmd_timeline(store.as_ref(), &assertions, &assertion, &period)?
            );
        }
        Command::Check {
            period,
            explain,
            assertions,
        } => {
            let store = storeopen::open_store(&store_path)?;
            let (out, any_fail) =
                commands::cmd_check(store.as_ref(), &assertions, period.as_deref(), explain)?;
            println!("{out}");
            if any_fail {
                // Code retour 1 : au moins une assertion non conforme.
                std::process::exit(1);
            }
        }
        Command::Pack {
            period,
            out,
            referential,
            assertions,
            organization,
            inventory,
            pubkey,
            keys,
        } => {
            let store = storeopen::open_store(&store_path)?;
            let args = commands::PackArgs {
                assertions_path: &assertions,
                period: &period,
                out: &out,
                referential: referential.as_deref(),
                organization: organization.as_deref(),
                inventory: inventory.as_deref(),
                pubkey: pubkey.as_deref(),
                keys: keys.as_deref(),
                store_path: Some(&store_path),
            };
            println!("{}", commands::cmd_pack(store.as_ref(), &args)?);
        }
        Command::Anchor {
            out,
            export,
            send,
            keys,
            organization,
        } => {
            let store = storeopen::open_store(&store_path)?;
            let args = commands::AnchorArgs {
                request_out: out.as_deref(),
                export_out: export.as_deref(),
                keys: keys.as_deref(),
                organization: organization.as_deref(),
                send: send.as_deref(),
                store_path: Some(&store_path),
            };
            println!("{}", commands::cmd_anchor(store.as_ref(), &args)?);
        }
        Command::Segmentation {
            flows,
            at,
            period,
            record,
            keys,
            asset,
        } => {
            // Ouverture en écriture UNIQUEMENT parce que `--record` peut
            // ajouter une entrée signée (§14) ; sans lui, rien n'est modifié.
            let mut store = storeopen::open_store(&store_path)?;
            let args = segmentation::SegmentationArgs {
                flows_path: &flows,
                at: at.as_deref(),
                period: period.as_deref(),
                record,
                keys: keys.as_deref(),
                asset: &asset,
            };
            let (out, code) = segmentation::cmd_segmentation(store.as_mut(), &args)?;
            println!("{out}");
            if code != 0 {
                // Conventions de Calque : 1 violation, 3 non concluant.
                std::process::exit(i32::from(code));
            }
        }
        Command::Verify { export } => {
            // Pas d'ouverture du magasin : cette commande n'est qu'un rappel,
            // la vérification elle-même est le binaire autonome (§10.3).
            println!("{}", commands::cmd_verify(export.as_deref()));
        }
        Command::Export { out, pubkey, keys } => {
            let store = storeopen::open_store(&store_path)?;
            let args = commands::ExportArgs {
                out: &out,
                pubkey: pubkey.as_deref(),
                keys: keys.as_deref(),
            };
            println!("{}", commands::cmd_export(store.as_ref(), &args)?);
        }
    }
    Ok(())
}
