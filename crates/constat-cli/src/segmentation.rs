//! `constat segmentation` — la jonction avec `Calque` (§14).
//!
//! > « Prouvez-moi que votre réseau industriel était isolé du bureautique
//! > pendant tout le trimestre. »
//!
//! - `Constat` prouve **quel était l'état** des configurations réseau, à
//!   chaque date, sans falsification possible (collecteur `network.configs`) ;
//! - `Calque` calcule **ce que cet état impliquait** en accessibilité réelle
//!   (import constructeur, topologie, moteur de traçage, tests de flux) ;
//! - et avec `--record`, le verdict d'accessibilité **redevient un fait
//!   horodaté** dans le journal signé — un constat comme un autre.
//!
//! ## Le chemin des données
//!
//! Le dernier blob `network.configs` antérieur à la date demandée est relu
//! depuis le magasin, re-découpé en sections `netdev:<nom>` par le MÊME
//! découpeur que la collecte ([`constat_collect::capture::split_sections`]),
//! et chaque équipement passe par [`calque_vendors::detect_and_import`] avec
//! le libellé `<équipement>@<date RFC 3339>` : chaque règle décisive citée
//! par un verdict remonte ainsi à l'équipement, à la date de collecte et à
//! la ligne exacte (« fw-01@2026-03-03T14:00Z ligne 42 »), et l'empreinte du
//! blob de configurations renvoie à la preuve brute du magasin signé.
//!
//! ## Le fichier de flux : le format natif de Calque
//!
//! `--flows` lit un fichier au format `flows.yaml` de Calque, **tel quel**
//! (voir `flows.example.yaml` du dépôt Calque) : le même fichier sert à
//! `calque test` sur le réseau vivant et à `constat segmentation` sur les
//! configurations historiques. Un seul format, pas de dialecte local.
//!
//! ## L'honnêteté du verdict (§6.3 de Calque, §4 de Constat)
//!
//! Trois verdicts par flux, jamais deux :
//!
//! - ✔ **conforme** : le flux se comporte comme déclaré ;
//! - ✘ **violé** : le comportement observé contredit l'attente, règle
//!   décisive citée avec sa source ;
//! - ? **non concluant** : impossible de trancher sans deviner — chemin
//!   traversant un modèle partiel, extrémité non résolue, moteur sans
//!   verdict ferme.
//!
//! Un équipement que Calque ne reconnaît pas ([`DetectImportError`]) est
//! **déclaré** et l'évaluation continue sur les autres, mais **tout verdict
//! devient non concluant** : un équipement illisible est un pan entier du
//! réseau hors modèle — affirmer « isolé » sans lui serait deviner, et
//! l'outil ne devine jamais.
//!
//! Codes de sortie, conventions de Calque : `0` conforme, `1` au moins une
//! violation, `3` non concluant (sans violation ferme).
//!
//! ## `--record` : la SEULE écriture de toute la CLI
//!
//! La CLI est en lecture seule (§1) — à une exception près, celle-ci,
//! documentée dans l'aide (`constat --help`) : `segmentation --record`
//! ajoute une entrée **signée** au journal (collecteur `calque.segmentation`).
//! Pourquoi cette exception : le §14 fait du verdict d'accessibilité un fait
//! horodaté de plein droit — « le réseau industriel était isolé au 3 mars »
//! est un constat au même titre que « root n'avait pas de mot de passe » ;
//! il entre donc dans le magasin par le même chemin que toute collecte
//! (blob → snapshot → entrée signée), avec le compte rendu texte complet en
//! artefact brut (preuve autonome) et les faits `flow.*` requêtables par
//! `constat history`. Faits enregistrés :
//!
//! | Entité | Attribut | Valeur |
//! |---|---|---|
//! | `flow:<nom>` | `flow.expected` | `Text` — attente déclarée (`allow`/`deny`) |
//! | `flow:<nom>` | `flow.verdict` | `Text` — comportement observé (`allow`/`deny`/`unknown`), `Absent` si aucun |
//! | `flow:<nom>` | `flow.status` | `Text` — `ok`, `broken` ou `inconclusive` |
//! | `flow:<nom>` | `flow.rule` | `Text` — règle décisive et sa source, `Absent` si non concluant |
//! | `segmentation:run` | `segmentation.flows_file` | `Text` — empreinte BLAKE3 (hex) du YAML de flux |
//! | `segmentation:run` | `segmentation.configs_blob` | `Text` — empreinte (hex) du blob de configurations évalué |

use std::collections::BTreeMap;
use std::path::Path;

use calque_engine::{infer_links_from_subnets, prepare_for_engine};
use calque_model::{DeviceId, Fidelity, Network};
use calque_policy::{evaluate_flows, FlowResult, FlowSpec, FlowStatus, FlowsFile};
use calque_vendors::{detect_and_import, DetectImportError};
use constat_collect::capture::split_sections;
use constat_collect::network_configs::SECTION_NETDEV_PREFIX;
use constat_model::{AssetId, Blob, BlobHash, CollectorId, Fact, Snapshot, Timestamp, Value};
use constat_store::{append_signed, Signer, Store};
use constat_time::Period;
use miette::{miette, IntoDiagnostic};

use crate::coverage::DEFAULT_MAX_EXPECTED_GAP;
use crate::datetime::{self, format_timestamp, parse_period, parse_timestamp};
use crate::{keyres, queries, render};

/// Identifiant du collecteur dont les blobs sont évalués (celui de
/// `constat-collect`).
pub const NETWORK_CONFIGS_COLLECTOR: &str = constat_collect::network_configs::COLLECTOR_ID;

/// Identifiant du collecteur sous lequel `--record` archive le verdict.
pub const SEGMENTATION_COLLECTOR: &str = "calque.segmentation";

/// Machine par défaut du snapshot de `--record` : le verdict porte sur le
/// réseau, pas sur une machine physique précise.
pub const DEFAULT_ASSET: &str = "reseau";

/// Code de sortie : tous les flux conformes.
pub const EXIT_CONFORME: u8 = 0;
/// Code de sortie : au moins une violation ferme.
pub const EXIT_VIOLATION: u8 = 1;
/// Code de sortie : au moins un verdict non concluant, aucune violation ferme.
pub const EXIT_NON_CONCLUANT: u8 = 3;

/// Paramètres de `constat segmentation`.
pub struct SegmentationArgs<'a> {
    /// Fichier de flux, au format `flows.yaml` natif de Calque.
    pub flows_path: &'a Path,
    /// Date d'évaluation ponctuelle (exclusif avec `period`).
    pub at: Option<&'a str>,
    /// Période : chronologie des verdicts à chaque changement de
    /// configuration (exclusif avec `at` et avec `record`).
    pub period: Option<&'a str>,
    /// Enregistre le verdict comme fait signé dans le journal (§14).
    pub record: bool,
    /// Répertoire des clés de l'agent (`agent.key`) pour signer
    /// l'enregistrement ; défaut : celui de l'agent.
    pub keys: Option<&'a Path>,
    /// Machine du snapshot enregistré (défaut : [`DEFAULT_ASSET`]).
    pub asset: &'a str,
}

// ---------------------------------------------------------------------------
// Verdict trois états
// ---------------------------------------------------------------------------

/// Le verdict d'un flux, côté Constat : trois états, jamais deux (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FluxVerdict {
    /// Le flux se comporte comme déclaré.
    Conforme,
    /// Le comportement observé contredit l'attente, avec preuve.
    Viole,
    /// Impossible de trancher sans deviner : déclaré, jamais masqué.
    NonConcluant,
}

impl FluxVerdict {
    /// Symbole + libellé français, alignés pour la sortie texte.
    fn label(self) -> &'static str {
        match self {
            FluxVerdict::Conforme => "✔ conforme     ",
            FluxVerdict::Viole => "✘ violé        ",
            FluxVerdict::NonConcluant => "? non concluant",
        }
    }

    /// La valeur de `flow.status` enregistrée par `--record`.
    fn status_text(self, calque: FlowStatus) -> &'static str {
        match self {
            FluxVerdict::NonConcluant => "inconclusive",
            _ => match calque {
                FlowStatus::Ok => "ok",
                FlowStatus::Broken => "broken",
                FlowStatus::Fixed => "fixed",
                FlowStatus::New => "new",
            },
        }
    }
}

/// Classe un [`FlowResult`] de Calque en verdict trois états.
///
/// Calque compte « en échec » (`Broken`) aussi bien une vraie violation
/// qu'un verdict non ferme (chemin traversant un modèle partiel, extrémité
/// non résolue, moteur `unknown`) : la distinction se lit sur `actual` —
/// un comportement observé `allow`/`deny` est ferme, tout le reste ne
/// l'est pas. Et si un équipement du parc est illisible
/// (`has_unreadable`), AUCUN verdict n'est ferme : le modèle est partiel
/// par construction.
fn classify(result: &FlowResult, has_unreadable: bool) -> FluxVerdict {
    if has_unreadable {
        return FluxVerdict::NonConcluant;
    }
    match result.status {
        FlowStatus::Ok | FlowStatus::Fixed => FluxVerdict::Conforme,
        FlowStatus::Broken | FlowStatus::New => match result.actual.as_deref() {
            Some("allow") | Some("deny") => FluxVerdict::Viole,
            _ => FluxVerdict::NonConcluant,
        },
    }
}

/// Code de sortie d'un lot de verdicts : la violation ferme prime, puis le
/// non concluant, puis la conformité (conventions de Calque).
fn exit_code(verdicts: &[FluxVerdict]) -> u8 {
    if verdicts.contains(&FluxVerdict::Viole) {
        EXIT_VIOLATION
    } else if verdicts.contains(&FluxVerdict::NonConcluant) {
        EXIT_NON_CONCLUANT
    } else {
        EXIT_CONFORME
    }
}

// ---------------------------------------------------------------------------
// Lecture du magasin : les blobs network.configs datés
// ---------------------------------------------------------------------------

/// Une observation datée d'un blob `network.configs` dans le magasin.
#[derive(Debug, Clone)]
struct ConfigsObservation {
    at: Timestamp,
    asset: AssetId,
    blob: BlobHash,
}

/// Toutes les observations `network.configs` du magasin, triées par date.
fn configs_observations(store: &dyn Store) -> miette::Result<Vec<ConfigsObservation>> {
    let collector = CollectorId(NETWORK_CONFIGS_COLLECTOR.to_string());
    let mut out = Vec::new();
    for (_, snap) in queries::snapshots(store).into_diagnostic()? {
        if let Some(blob) = snap.blobs.get(&collector) {
            out.push(ConfigsObservation {
                at: snap.at,
                asset: snap.asset.clone(),
                blob: *blob,
            });
        }
    }
    // `queries::snapshots` trie déjà par date ; le tri est réaffirmé ici
    // pour que la chronologie ne dépende jamais d'un détail d'implémentation.
    out.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.asset.cmp(&b.asset)));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Évaluation d'un blob de configurations
// ---------------------------------------------------------------------------

/// Ce qu'est devenu un équipement de la capture à l'import Calque.
#[derive(Debug, Clone)]
struct DeviceReport {
    /// Nom de la section `netdev:<nom>`.
    name: String,
    /// Libellé de l'adaptateur retenu (« FortiGate (CLI) »…), si import réussi.
    adapter: Option<&'static str>,
    /// Nombre de directives non comprises (`Fidelity::Partial`), 0 si complète.
    unsupported: usize,
    /// Motif d'échec si l'équipement est illisible.
    error: Option<String>,
}

/// Le résultat de l'évaluation d'UN blob de configurations.
struct BlobEvaluation {
    devices: Vec<DeviceReport>,
    /// Les résultats de Calque, un par flux, dans l'ordre du fichier.
    results: Vec<FlowResult>,
    /// Le verdict trois états correspondant, même ordre.
    verdicts: Vec<FluxVerdict>,
    /// Au moins un équipement illisible : tout verdict est non concluant.
    has_unreadable: bool,
}

/// Date au format RFC 3339 court (`2026-03-03T14:00Z`) pour les libellés de
/// source : c'est elle que citent les règles décisives.
fn format_rfc3339(t: Timestamp) -> String {
    format!("{}Z", format_timestamp(t).replacen(' ', "T", 1))
}

/// Re-découpe une capture `network.configs`, importe chaque équipement dans
/// Calque (libellé `<nom>@<date RFC 3339>`), assemble le réseau (liens
/// inférés par sous-réseaux, préparation moteur) et évalue les flux avec la
/// table de fidélité réelle des imports.
fn evaluate_configs(
    capture: &str,
    at: Timestamp,
    flows: &[FlowSpec],
) -> miette::Result<BlobEvaluation> {
    let stamp = format_rfc3339(at);
    let mut devices = Vec::new();
    let mut network = Network::default();
    let mut fidelity: BTreeMap<DeviceId, Fidelity> = BTreeMap::new();
    let mut has_unreadable = false;

    let mut seen_sections = 0usize;
    for (section, content) in split_sections(capture) {
        let Some(name) = section.strip_prefix(SECTION_NETDEV_PREFIX) else {
            continue; // section étrangère au collecteur : ignorée, comme à l'extraction
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        seen_sections += 1;
        let label = format!("{name}@{stamp}");
        match detect_and_import(&content, &label) {
            Ok(imported) => {
                let device = imported.output.device;
                if network.devices.contains_key(&device.id) {
                    // Deux sections qui modélisent le même équipement : on ne
                    // peut pas choisir sans deviner — déclaré, non concluant.
                    has_unreadable = true;
                    devices.push(DeviceReport {
                        name: name.to_string(),
                        adapter: Some(imported.adapter),
                        unsupported: 0,
                        error: Some(format!(
                            "identifiant d'équipement « {} » déjà importé depuis une autre \
                             section : impossible de choisir sans deviner",
                            device.id
                        )),
                    });
                    continue;
                }
                let unsupported = match &imported.output.fidelity {
                    Fidelity::Complete => 0,
                    Fidelity::Partial { unsupported } => unsupported.len(),
                };
                fidelity.insert(device.id.clone(), imported.output.fidelity);
                network.devices.insert(device.id.clone(), device);
                devices.push(DeviceReport {
                    name: name.to_string(),
                    adapter: Some(imported.adapter),
                    unsupported,
                    error: None,
                });
            }
            Err(e) => {
                // Équipement illisible : déclaré, l'évaluation continue sur
                // les autres, mais plus aucun verdict n'est ferme (§6.3).
                has_unreadable = true;
                devices.push(DeviceReport {
                    name: name.to_string(),
                    adapter: match &e {
                        DetectImportError::Import { adapter, .. } => Some(adapter),
                        _ => None,
                    },
                    unsupported: 0,
                    error: Some(e.to_string()),
                });
            }
        }
    }
    if seen_sections == 0 {
        return Err(miette!(
            "le blob network.configs ne contient aucune section « {SECTION_NETDEV_PREFIX}<nom> » \
             : capture malformée ou collecteur étranger"
        ));
    }

    let inferred = infer_links_from_subnets(&network);
    network.links.extend(inferred);
    let network = prepare_for_engine(&network);

    // `allow_partial = false` : Constat produit des PREUVES, il exige des
    // verdicts fermes. Depuis calque v0.6.0, la fidélité est évaluée PAR
    // CHEMIN — un verdict n'est « non ferme » que si une lacune de
    // modélisation (objet externe non résolu, règle sur-approximée par
    // identité/internet-service/négation) touche le chemin décisif du
    // flux. Une lacune sans rapport (multicast, objet dynamique…) ne
    // déclasse plus le verdict. C'est exactement la sémantique voulue pour
    // une preuve : ferme quand c'est démontrable, non ferme (jamais un
    // faux « autorisé ») quand le chemin dépend d'une approximation.
    let results = evaluate_flows(&network, flows, false);
    let verdicts = results
        .iter()
        .map(|r| classify(r, has_unreadable))
        .collect();
    Ok(BlobEvaluation {
        devices,
        results,
        verdicts,
        has_unreadable,
    })
}

/// Relit le blob depuis le magasin et l'évalue.
fn evaluate_blob(
    store: &dyn Store,
    obs: &ConfigsObservation,
    flows: &[FlowSpec],
) -> miette::Result<BlobEvaluation> {
    let blob = store.get_blob(&obs.blob).into_diagnostic()?;
    let capture = String::from_utf8_lossy(&blob.raw);
    evaluate_configs(&capture, obs.at, flows)
}

// ---------------------------------------------------------------------------
// Fichier de flux
// ---------------------------------------------------------------------------

/// Charge le fichier de flux (format `flows.yaml` natif de Calque) et rend
/// son empreinte BLAKE3 (hex) — celle qu'enregistre `--record`.
fn load_flows(path: &Path) -> miette::Result<(FlowsFile, String)> {
    let bytes = std::fs::read(path).map_err(|e| {
        miette!(
            help = "indiquez le fichier avec --flows <chemin> ; c'est le même flows.yaml \
                    que `calque test` (voir flows.example.yaml du dépôt Calque)",
            "impossible de lire le fichier de flux {} : {e}",
            path.display()
        )
    })?;
    let text = String::from_utf8_lossy(&bytes);
    let file: FlowsFile = serde_yaml::from_str(&text)
        .map_err(|e| miette!("fichier de flux invalide dans {} : {e}", path.display()))?;
    if file.flows.is_empty() {
        return Err(miette!(
            "aucun flux déclaré dans {} — rien à évaluer",
            path.display()
        ));
    }
    Ok((file, blake3::hash(&bytes).to_hex().to_string()))
}

// ---------------------------------------------------------------------------
// Rendu
// ---------------------------------------------------------------------------

/// Bloc « équipements » d'un compte rendu : imports réussis, fidélités,
/// équipements illisibles déclarés.
fn render_devices(eval: &BlobEvaluation) -> String {
    let mut out = String::from("Équipements de la capture :\n");
    for d in &eval.devices {
        match (&d.error, d.adapter) {
            (None, Some(adapter)) => {
                let fid = if d.unsupported == 0 {
                    "fidélité complète".to_string()
                } else {
                    format!(
                        "fidélité PARTIELLE : {} directive(s) non comprise(s)",
                        d.unsupported
                    )
                };
                out.push_str(&format!("  - {} — {adapter}, {fid}\n", d.name));
            }
            (Some(err), _) => {
                out.push_str(&format!("  - {} — ILLISIBLE : {err}\n", d.name));
            }
            (None, None) => {} // impossible par construction
        }
    }
    if eval.has_unreadable {
        out.push_str(
            "Au moins un équipement est illisible : le modèle est partiel, tout verdict \
             ci-dessous est non concluant (l'outil ne devine jamais).\n",
        );
    }
    out
}

/// Bloc « flux » d'un compte rendu : verdict, attendu/observé, règle décisive.
fn render_flows(eval: &BlobEvaluation) -> String {
    let mut out = String::new();
    for (result, verdict) in eval.results.iter().zip(eval.verdicts.iter()) {
        let observed = result.actual.as_deref().unwrap_or("—");
        out.push_str(&format!(
            "  {}  « {} »\n      flux : {} — attendu {}, observé {}\n",
            verdict.label(),
            result.name,
            result.flow,
            result.expected,
            observed
        ));
        if let Some(detail) = &result.detail {
            let prefix = match verdict {
                FluxVerdict::NonConcluant => "motif",
                _ => "règle décisive",
            };
            for (i, line) in detail.lines().enumerate() {
                if i == 0 {
                    out.push_str(&format!("      {prefix} : {}\n", line.trim()));
                } else {
                    out.push_str(&format!("        {}\n", line.trim()));
                }
            }
        }
    }
    out
}

/// Bilan chiffré d'un lot de verdicts.
fn render_summary(verdicts: &[FluxVerdict]) -> String {
    let conformes = verdicts
        .iter()
        .filter(|v| **v == FluxVerdict::Conforme)
        .count();
    let violes = verdicts
        .iter()
        .filter(|v| **v == FluxVerdict::Viole)
        .count();
    let nc = verdicts
        .iter()
        .filter(|v| **v == FluxVerdict::NonConcluant)
        .count();
    format!(
        "Bilan : {} flux — {conformes} conforme(s), {violes} violé(s), {nc} non concluant(s).",
        verdicts.len()
    )
}

/// Compte rendu complet d'une évaluation ponctuelle (`--at`). C'est ce
/// texte, intégralement, que `--record` archive comme artefact brut.
fn render_at_report(
    asked_at: Timestamp,
    obs: &ConfigsObservation,
    eval: &BlobEvaluation,
    flows_path: &Path,
    flows_hash: &str,
) -> String {
    let mut out = format!(
        "Segmentation au {} — configurations du {} (machine {}, blob {})\n",
        format_timestamp(asked_at),
        format_timestamp(obs.at),
        obs.asset.0,
        render::short_hash(&obs.blob)
    );
    out.push_str(&format!(
        "Fichier de flux : {} — empreinte BLAKE3 {} (format flows.yaml natif de Calque)\n\n",
        flows_path.display(),
        flows_hash
    ));
    out.push_str(&render_devices(eval));
    out.push('\n');
    out.push_str(&render_flows(eval));
    out.push('\n');
    out.push_str(&format!(
        "Traçabilité Constat : blob de configurations {} — la preuve brute est dans le \
         magasin signé.\n",
        obs.blob.to_hex()
    ));
    out.push_str(&render_summary(&eval.verdicts));
    out.push('\n');
    out
}

// ---------------------------------------------------------------------------
// --record : le verdict redevient un fait horodaté (§14)
// ---------------------------------------------------------------------------

/// Construit les faits du blob `calque.segmentation` (format documenté en
/// tête de module) : un quadruplet `flow.*` par flux, plus l'entité
/// `segmentation:run` qui relie le verdict à ses deux entrées — le fichier
/// de flux (empreinte BLAKE3) et le blob de configurations évalué.
fn record_facts(eval: &BlobEvaluation, configs_blob: &BlobHash, flows_hash: &str) -> Vec<Fact> {
    let mut facts = Vec::new();
    for (result, verdict) in eval.results.iter().zip(eval.verdicts.iter()) {
        let entity = format!("flow:{}", result.name);
        facts.push(Fact::new(
            entity.as_str(),
            "flow.expected",
            result.expected.as_str(),
        ));
        let verdict_value = match (*verdict, result.actual.as_deref()) {
            // Non concluant : aucun comportement observé fiable à archiver.
            (FluxVerdict::NonConcluant, _) | (_, None) => Value::Absent,
            (_, Some(actual)) => Value::Text(actual.to_string()),
        };
        facts.push(Fact::new(entity.as_str(), "flow.verdict", verdict_value));
        facts.push(Fact::new(
            entity.as_str(),
            "flow.status",
            verdict.status_text(result.status),
        ));
        let rule_value = match (*verdict, result.detail.as_deref()) {
            (FluxVerdict::NonConcluant, _) | (_, None) => Value::Absent,
            (_, Some(detail)) => Value::Text(detail.to_string()),
        };
        facts.push(Fact::new(entity.as_str(), "flow.rule", rule_value));
    }
    facts.push(Fact::new(
        "segmentation:run",
        "segmentation.flows_file",
        flows_hash,
    ));
    facts.push(Fact::new(
        "segmentation:run",
        "segmentation.configs_blob",
        configs_blob.to_hex(),
    ));
    facts
}

/// Archive le verdict dans le journal : blob `calque.segmentation` (compte
/// rendu complet en brut + faits `flow.*`), snapshot sur la machine
/// `asset`, entrée **signée** par la clé de l'agent ([`crate::keyres`]).
fn record_run(
    store: &mut dyn Store,
    keys: Option<&Path>,
    asset: &str,
    report: &str,
    eval: &BlobEvaluation,
    configs_blob: &BlobHash,
    flows_hash: &str,
) -> miette::Result<String> {
    let keys_dir = keys
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from(keyres::DEFAULT_KEYS_DIR));
    let signing_key = keyres::load_signing_key(&keys_dir)?;
    let signer = Signer::from_bytes(&signing_key.to_bytes());

    let blob = Blob::new(
        SEGMENTATION_COLLECTOR,
        report.as_bytes().to_vec(),
        record_facts(eval, configs_blob, flows_hash),
    );
    let blob_hash = store.put_blob(&blob).into_diagnostic()?;
    let now = datetime::now();
    let snapshot = Snapshot::new(
        asset,
        now,
        BTreeMap::from([(CollectorId(SEGMENTATION_COLLECTOR.to_string()), blob_hash)]),
    );
    let snap_hash = store.put_snapshot(&snapshot).into_diagnostic()?;
    let (root, _) = append_signed(store, &signer, vec![snap_hash], now).into_diagnostic()?;
    Ok(format!(
        "\nVerdict enregistré au journal (§14) : entrée signée du {}, machine {}, blob {} \
         — nouvelle racine {}.\nLes faits flow.* sont requêtables : \
         constat history --entity \"flow:<nom>\" --attr flow.verdict",
        format_timestamp(now),
        asset,
        render::short_hash(&blob_hash),
        render::short_hash(&root)
    ))
}

// ---------------------------------------------------------------------------
// Chronologie (--period)
// ---------------------------------------------------------------------------

/// Un intervalle de verdict stable pour un flux.
struct FluxInterval {
    from: Timestamp,
    to: Timestamp,
    verdict: FluxVerdict,
    observed: Option<String>,
    detail: Option<String>,
}

/// Compte rendu d'une période : un point d'évaluation par blob
/// `network.configs` distinct observé, la chronologie des verdicts par flux
/// (intervalles stables datés), et la couverture honnête de la période.
fn render_period_report(
    store: &dyn Store,
    period: Period,
    flows: &[FlowSpec],
    flows_path: &Path,
    flows_hash: &str,
) -> miette::Result<(String, Vec<FluxVerdict>)> {
    let all = configs_observations(store)?;
    let in_period: Vec<&ConfigsObservation> = all
        .iter()
        .filter(|o| o.at >= period.from && o.at <= period.to)
        .collect();
    if in_period.is_empty() {
        return Ok((
            format!(
                "{}\n\nAucune collecte network.configs dans la période : verdict non \
                 concluant partout (rien n'a été observé, rien n'est inféré).",
                render::period_header(period)
            ),
            vec![FluxVerdict::NonConcluant; flows.len()],
        ));
    }

    // Un point d'évaluation par CHANGEMENT de blob : les observations
    // successives du même blob confirment l'état, elles ne le changent pas.
    // Un même blob revenu plus tard (A → B → A) est bien réévalué.
    let mut points: Vec<(&ConfigsObservation, BlobEvaluation)> = Vec::new();
    let mut cache: BTreeMap<BlobHash, usize> = BTreeMap::new();
    let mut last_blob: Option<BlobHash> = None;
    for obs in in_period.iter().copied() {
        if last_blob == Some(obs.blob) {
            continue;
        }
        last_blob = Some(obs.blob);
        // Les blobs déjà évalués (retour à une configuration antérieure) ne
        // sont pas réimportés : le résultat est recopié depuis le cache.
        let eval = match cache.get(&obs.blob) {
            Some(&i) => reevaluate_cached(&points[i].1),
            None => {
                let e = evaluate_blob(store, obs, flows)?;
                cache.insert(obs.blob, points.len());
                e
            }
        };
        points.push((obs, eval));
    }

    // Chronologie par flux : intervalles de verdict stable, datés du
    // changement de configuration au changement suivant (ou à la fin de
    // période).
    let mut out = format!("{}\n\n", render::period_header(period));
    out.push_str(&format!(
        "Fichier de flux : {} — empreinte BLAKE3 {} (format flows.yaml natif de Calque)\n",
        flows_path.display(),
        flows_hash
    ));
    out.push_str(&format!(
        "{} changement(s) de configuration réseau observé(s) dans la période :\n",
        points.len()
    ));
    for (obs, eval) in &points {
        let note = if eval.has_unreadable {
            " — équipement(s) illisible(s), verdicts non concluants"
        } else {
            ""
        };
        out.push_str(&format!(
            "  - {} : blob {} (machine {}){note}\n",
            format_timestamp(obs.at),
            render::short_hash(&obs.blob),
            obs.asset.0
        ));
    }
    out.push('\n');

    let mut worst: Vec<FluxVerdict> = Vec::with_capacity(flows.len());
    for (i, flow) in flows.iter().enumerate() {
        let mut intervals: Vec<FluxInterval> = Vec::new();
        for (k, (obs, eval)) in points.iter().enumerate() {
            let to = points
                .get(k + 1)
                .map(|(next, _)| next.at)
                .unwrap_or(period.to);
            let verdict = eval.verdicts[i];
            let result = &eval.results[i];
            match intervals.last_mut() {
                Some(last) if last.verdict == verdict => last.to = to,
                _ => intervals.push(FluxInterval {
                    from: obs.at,
                    to,
                    verdict,
                    observed: result.actual.clone(),
                    detail: result.detail.clone(),
                }),
            }
        }
        out.push_str(&format!(
            "Flux « {} » ({}, attendu {})\n",
            flow.name,
            flow.flow_label(),
            flow.expect
        ));
        for itv in &intervals {
            out.push_str(&format!(
                "  {} → {}   {}",
                format_timestamp(itv.from),
                format_timestamp(itv.to),
                itv.verdict.label().trim_end()
            ));
            if let Some(observed) = &itv.observed {
                out.push_str(&format!("  (observé {observed})"));
            }
            out.push('\n');
            if itv.verdict != FluxVerdict::Conforme {
                if let Some(detail) = &itv.detail {
                    for line in detail.lines() {
                        out.push_str(&format!("      {}\n", line.trim()));
                    }
                }
            }
        }
        // Le verdict agrégé du flux sur la période : le pire intervalle.
        let flux_verdicts: Vec<FluxVerdict> = intervals.iter().map(|itv| itv.verdict).collect();
        worst.push(match exit_code(&flux_verdicts) {
            EXIT_VIOLATION => FluxVerdict::Viole,
            EXIT_NON_CONCLUANT => FluxVerdict::NonConcluant,
            _ => FluxVerdict::Conforme,
        });
        out.push('\n');
    }

    // Couverture honnête : les dates d'observation network.configs de la
    // période, comme `constat history` le fait pour les machines (§4.2).
    // Le premier intervalle ne commence qu'à la première collecte : ce qui
    // précède est un trou, déclaré ci-dessous, jamais masqué.
    let times: Vec<Timestamp> = in_period.iter().map(|o| o.at).collect();
    let coverage = crate::coverage::coverage_report(&times, period, DEFAULT_MAX_EXPECTED_GAP)
        .into_diagnostic()?;
    out.push_str(&render::render_coverage(&coverage));
    out.push('\n');
    out.push_str(&render_summary(&worst));
    Ok((out, worst))
}

/// Recopie une évaluation depuis le cache (mêmes verdicts : même blob,
/// mêmes flux). Seule la liste des équipements est clonée telle quelle —
/// l'import de Calque est déterministe sur un même texte.
fn reevaluate_cached(eval: &BlobEvaluation) -> BlobEvaluation {
    BlobEvaluation {
        devices: eval.devices.clone(),
        results: eval.results.clone(),
        verdicts: eval.verdicts.clone(),
        has_unreadable: eval.has_unreadable,
    }
}

// ---------------------------------------------------------------------------
// La commande
// ---------------------------------------------------------------------------

/// `constat segmentation --flows <fichier> (--at <date> | --period <p>)
/// [--record [--keys <dossier>] [--asset <machine>]]`.
///
/// Renvoie le compte rendu et le code de sortie (`0` conforme, `1`
/// violation, `3` non concluant — conventions de Calque). Voir la
/// documentation du module pour le fond ; en résumé :
///
/// - `--at` : évalue le dernier blob `network.configs` antérieur à la date ;
/// - `--period` : évalue chaque blob distinct observé dans la période et
///   restitue la chronologie des verdicts avec la couverture — la réponse à
///   « pendant tout le trimestre » ;
/// - `--record` (avec `--at` uniquement) : archive le verdict en entrée
///   signée du journal — la seule écriture de toute la CLI, assumée et
///   documentée.
pub fn cmd_segmentation(
    store: &mut dyn Store,
    args: &SegmentationArgs<'_>,
) -> miette::Result<(String, u8)> {
    let (flows_file, flows_hash) = load_flows(args.flows_path)?;

    match (args.at, args.period) {
        (Some(at), None) => {
            let at_ts = parse_timestamp(at)?;
            let all = configs_observations(&*store)?;
            let Some(obs) = all.into_iter().rev().find(|o| o.at <= at_ts) else {
                return Err(miette!(
                    help = "les configurations d'équipements arrivent par le collecteur \
                            network.configs (répertoire de dépôt, voir constat-collect)",
                    "aucune collecte network.configs antérieure au {} dans le magasin",
                    format_timestamp(at_ts)
                ));
            };
            let eval = evaluate_blob(&*store, &obs, &flows_file.flows)?;
            let mut report = render_at_report(at_ts, &obs, &eval, args.flows_path, &flows_hash);
            let code = exit_code(&eval.verdicts);
            if args.record {
                let note = record_run(
                    store,
                    args.keys,
                    args.asset,
                    &report,
                    &eval,
                    &obs.blob,
                    &flows_hash,
                )?;
                report.push_str(&note);
            }
            Ok((report, code))
        }
        (None, Some(period)) => {
            if args.record {
                return Err(miette!(
                    help = "enregistrez un verdict ponctuel : --at <date> --record",
                    "--record enregistre UN verdict daté ; avec --period, la chronologie \
                     en contiendrait plusieurs — combinaison refusée"
                ));
            }
            let period = parse_period(period)?;
            let (report, verdicts) = render_period_report(
                &*store,
                period,
                &flows_file.flows,
                args.flows_path,
                &flows_hash,
            )?;
            Ok((report, exit_code(&verdicts)))
        }
        (Some(_), Some(_)) => Err(miette!(
            "--at et --period sont exclusifs : une date OU une chronologie"
        )),
        (None, None) => Err(miette!(
            help = "--at 2026-03-03T14:00 pour un instant, --period 2026-Q1 pour une chronologie",
            "indiquez --at <date> ou --period <période>"
        )),
    }
}
