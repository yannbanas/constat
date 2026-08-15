//! Les commandes du §10, écrites contre `&dyn Store`.
//!
//! Chaque commande renvoie le texte à afficher : la logique est ainsi
//! exerçable par le test de fumée sur un magasin en mémoire, sans processus.
//! Aucune commande de ce module ne modifie le magasin — lecture seule,
//! comme tout le produit (§1). Les seules écritures sont **à côté** du
//! magasin : le répertoire d'export (`constat export`), les fichiers
//! d'ancrage (`constat anchor`) et le dossier de preuve (`constat pack`).
//! L'unique exception de toute la CLI vit dans [`crate::segmentation`] :
//! `segmentation --record`, qui ajoute une entrée signée au journal (§14).

use std::path::Path;

use constat_anchor::rfc3161::{parse_response, TimeStampRequest};
use constat_anchor::root::{sign_root_export, RootExportDocument};
use constat_model::{AssetId, Attribute, BlobHash, EntityId, Snapshot, Timestamp};
use constat_policy::{Assertion, Evaluation, EvaluationOptions, Verdict};
use constat_store::Store;
use constat_time::{CoverageReport, Gap, Period};
use miette::{miette, IntoDiagnostic};

use crate::coverage::DEFAULT_MAX_EXPECTED_GAP;
use crate::datetime::{self, format_timestamp, parse_period, parse_timestamp};
use crate::{anchors, eval, http, keyres, queries, referential, render};

/// `constat state --asset <id> --at <date>` : dernier snapshot antérieur + faits.
pub fn cmd_state(store: &dyn Store, asset: &str, at: &str) -> miette::Result<String> {
    let at_ts = parse_timestamp(at)?;
    let asset_id = AssetId(asset.to_string());
    match queries::state_at(store, &asset_id, at_ts).into_diagnostic()? {
        Some(view) => Ok(render::render_state(&view, &format_timestamp(at_ts))),
        None => Ok(format!(
            "Aucun snapshot de {asset} antérieur au {} dans le magasin.",
            format_timestamp(at_ts)
        )),
    }
}

/// `constat diff --asset <id> --from <date> --to <date>`.
pub fn cmd_diff(store: &dyn Store, asset: &str, from: &str, to: &str) -> miette::Result<String> {
    let from_ts = parse_timestamp(from)?;
    let to_ts = parse_timestamp(to)?;
    if to_ts < from_ts {
        return Err(miette!("la date --to précède la date --from"));
    }
    let asset_id = AssetId(asset.to_string());
    match queries::diff_asset(store, &asset_id, from_ts, to_ts).into_diagnostic()? {
        Some(view) => Ok(render::render_diff(
            &asset_id,
            &view,
            &format_timestamp(from_ts),
            &format_timestamp(to_ts),
        )),
        None => Ok(format!(
            "Impossible de comparer : aucun snapshot de {asset} antérieur à l'une des deux dates."
        )),
    }
}

/// `constat history --entity <e> --attr <a>` — la commande qui vend (§10.1).
pub fn cmd_history(
    store: &dyn Store,
    entity: &str,
    attr: &str,
    period: Option<&str>,
) -> miette::Result<String> {
    let period = period.map(parse_period).transpose()?;
    let h = queries::history(
        store,
        &EntityId(entity.to_string()),
        &Attribute(attr.to_string()),
        period,
    )
    .into_diagnostic()?;
    Ok(render::render_history(entity, attr, &h))
}

/// Charge et valide `assertions.yaml` via `constat-policy` (§5.2) :
/// exceptions datées obligatoires, prédicats bornés, durées lisibles.
pub fn load_assertions(path: &Path) -> miette::Result<Vec<Assertion>> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        miette!(
            help = "indiquez le fichier avec --assertions <chemin>",
            "impossible de lire le fichier d'assertions {} : {e}",
            path.display()
        )
    })?;
    constat_policy::parse_assertions(&text)
        .map_err(|e| miette!("assertions invalides dans {} : {e}", path.display()))
}

/// Période d'évaluation : celle demandée, sinon l'empan des collectes.
fn resolve_period(store: &dyn Store, period: Option<&str>) -> miette::Result<Option<Period>> {
    if let Some(p) = period {
        return Ok(Some(parse_period(p)?));
    }
    let snaps = queries::snapshots(store).into_diagnostic()?;
    Ok(match (snaps.first(), snaps.last()) {
        (Some((_, first)), Some((_, last))) => Some(Period {
            from: first.at,
            to: last.at,
        }),
        _ => None,
    })
}

/// Les données de parc communes à `check` et `pack`, lues une seule fois : la
/// liste des snapshots (manifestes légers), les interruptions déclarées et la
/// couverture de parc. C'est volontairement *tout* ce qui reste matérialisé à
/// l'échelle du parc — les observations, elles, sont lues par tranches (voir
/// [`stream_evaluations`]).
struct ParkFrame {
    snaps: Vec<(BlobHash, Snapshot)>,
    /// Interruptions déclarées (§16) : purges de rétention journalisées.
    purge_gaps: Vec<Gap>,
    /// Couverture de parc — même valeur pour toutes les assertions.
    park_coverage: CoverageReport,
}

/// Lit une fois les manifestes de snapshots, les purges déclarées et en dérive
/// la couverture de parc. Ne touche à aucun blob : empreinte à l'échelle du
/// magasin (les manifestes), pas des observations.
fn park_frame(store: &dyn Store, period: Period) -> miette::Result<ParkFrame> {
    let snaps = queries::snapshots(store).into_diagnostic()?;
    // Les purges de rétention journalisées (§16) sont des interruptions
    // déclarées : une période purgée apparaît comme un trou `RetentionPurge`
    // dans chaque couverture, jamais comme un trou inexpliqué.
    let purge_gaps = queries::purge_gaps_from(store, &snaps).into_diagnostic()?;
    let times: Vec<Timestamp> = snaps.iter().map(|(_, s)| s.at).collect();
    let park_coverage = crate::coverage::coverage_report_declared(
        &times,
        &purge_gaps,
        period,
        DEFAULT_MAX_EXPECTED_GAP,
    )
    .into_diagnostic()?;
    Ok(ParkFrame {
        snaps,
        purge_gaps,
        park_coverage,
    })
}

/// Évalue toutes les assertions sur une période, chemin « tout en mémoire ».
///
/// Socle de `constat pack`, qui a besoin, en plus des verdicts, des entrées par
/// machine ([`constat_policy::EvaluationInput`]) pour restituer les
/// interruptions par machine du dossier. `constat check`, lui, passe par
/// [`stream_evaluations`] pour ne jamais matérialiser tout le parc.
fn evaluate_all(
    store: &dyn Store,
    assertions: &[Assertion],
    period: Period,
) -> miette::Result<(Vec<Evaluation>, Vec<constat_policy::EvaluationInput>)> {
    let frame = park_frame(store, period)?;
    let refs: Vec<&Snapshot> = frame.snaps.iter().map(|(_, s)| s).collect();
    let obs = queries::observations_of(store, &refs).into_diagnostic()?;
    let snap_times: Vec<(AssetId, Timestamp)> = frame
        .snaps
        .iter()
        .map(|(_, s)| (s.asset.clone(), s.at))
        .collect();
    let inputs = eval::build_inputs_with_gaps(
        &obs,
        &snap_times,
        &frame.purge_gaps,
        period,
        DEFAULT_MAX_EXPECTED_GAP,
    )
    .into_diagnostic()?;
    let mut results = Vec::with_capacity(assertions.len());
    for a in assertions {
        results
            .push(eval::evaluate_park(a, &inputs, frame.park_coverage.clone()).into_diagnostic()?);
    }
    Ok((results, inputs))
}

/// Évalue toutes les assertions **par machine, à empreinte mémoire bornée** :
/// le socle de `constat check`.
///
/// Le verdict de parc est une agrégation par machine (`merge_verdicts`, via
/// [`eval::ParkAccumulator`]) ; on peut donc traiter les machines une à une.
/// Pour chaque machine, on charge ses seules observations, on construit son
/// unique entrée d'évaluation, on l'intègre à chaque accumulateur d'assertion,
/// puis on **libère** avant de passer à la suivante. Le pic mémoire devient
/// « une machine » au lieu de « tout le parc ».
///
/// Résultat **strictement identique** à [`evaluate_all`] (mêmes verdicts,
/// mêmes violations dans le même ordre, même couverture) : les machines sont
/// parcourues dans l'ordre trié de leur identifiant — l'ordre exact qu'aurait
/// produit `build_inputs_with_gaps` sur tout le parc (sa `BTreeMap` par actif) —
/// et chaque machine reçoit ses snapshots dans l'ordre global (date, actif).
fn stream_evaluations(
    store: &dyn Store,
    assertions: &[Assertion],
    period: Period,
) -> miette::Result<Vec<Evaluation>> {
    let frame = park_frame(store, period)?;
    let options = EvaluationOptions::default();

    // Regroupe les indices de snapshots par machine, en préservant l'ordre
    // global (les snapshots sont déjà triés par date puis actif) : le sous-
    // ensemble d'une machine est donc dans l'ordre attendu par la construction
    // des plages de stabilité.
    let mut by_asset: std::collections::BTreeMap<AssetId, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (i, (_, s)) in frame.snaps.iter().enumerate() {
        by_asset.entry(s.asset.clone()).or_default().push(i);
    }

    let mut accs: Vec<eval::ParkAccumulator> = (0..assertions.len())
        .map(|_| eval::ParkAccumulator::default())
        .collect();

    for (asset, idxs) in &by_asset {
        let snaps_of_asset: Vec<&Snapshot> = idxs.iter().map(|&i| &frame.snaps[i].1).collect();
        let obs = queries::observations_of(store, &snaps_of_asset).into_diagnostic()?;
        let asset_times: Vec<(AssetId, Timestamp)> = idxs
            .iter()
            .map(|&i| (asset.clone(), frame.snaps[i].1.at))
            .collect();
        // Une seule machine en entrée : `build_inputs_with_gaps` renvoie son
        // unique `EvaluationInput` (identique à celui du chemin global, dont la
        // construction est indépendante d'un actif à l'autre).
        let inputs = eval::build_inputs_with_gaps(
            &obs,
            &asset_times,
            &frame.purge_gaps,
            period,
            DEFAULT_MAX_EXPECTED_GAP,
        )
        .into_diagnostic()?;
        for input in &inputs {
            for (acc, a) in accs.iter_mut().zip(assertions) {
                acc.observe(a, input, &options).into_diagnostic()?;
            }
        }
        // `obs` et `inputs` sont libérés ici : le pic reste borné à une machine.
    }

    Ok(accs
        .into_iter()
        .zip(assertions)
        .map(|(acc, a)| acc.finish(a, frame.park_coverage.clone()))
        .collect())
}

/// `constat check [--period <p>] [--explain]`. Renvoie la sortie et un
/// indicateur « au moins une assertion non conforme » (pour le code retour).
pub fn cmd_check(
    store: &dyn Store,
    assertions_path: &Path,
    period: Option<&str>,
    explain: bool,
) -> miette::Result<(String, bool)> {
    let assertions = load_assertions(assertions_path)?;
    if assertions.is_empty() {
        return Ok((
            format!("Aucune assertion dans {}.", assertions_path.display()),
            false,
        ));
    }
    let Some(period) = resolve_period(store, period)? else {
        return Ok((
            "Le magasin ne contient aucune collecte — rien à évaluer (verdict indéterminé partout)."
                .to_string(),
            false,
        ));
    };
    let results = stream_evaluations(store, &assertions, period)?;
    let any_fail = results.iter().any(|e| e.verdict == Verdict::Fail);
    let mut out = format!("{}\n\n", render::period_header(period));
    out.push_str(&render::render_check(&results, explain));
    Ok((out, any_fail))
}

/// `constat timeline --assertion <id> --period <p>`.
pub fn cmd_timeline(
    store: &dyn Store,
    assertions_path: &Path,
    assertion_id: &str,
    period: &str,
) -> miette::Result<String> {
    let assertions = load_assertions(assertions_path)?;
    let assertion = assertions
        .iter()
        .find(|a| a.id.0 == assertion_id)
        .ok_or_else(|| {
            let known: Vec<&str> = assertions.iter().map(|a| a.id.0.as_str()).collect();
            miette!(
                help = format!("assertions connues : {}", known.join(", ")),
                "assertion « {assertion_id} » introuvable dans {}",
                assertions_path.display()
            )
        })?;
    let period = parse_period(period)?;
    let obs = queries::observations(store).into_diagnostic()?;
    let snap_times: Vec<(AssetId, Timestamp)> = queries::snapshots(store)
        .into_diagnostic()?
        .iter()
        .map(|(_, s)| (s.asset.clone(), s.at))
        .collect();
    let segments = eval::timeline(assertion, &obs, &snap_times, period).into_diagnostic()?;
    let mut out = format!("{}\n\n", render::period_header(period));
    out.push_str(&render::render_timeline(assertion, &segments));
    Ok(out)
}

/// Paramètres du dossier de preuve (`constat pack`).
pub struct PackArgs<'a> {
    pub assertions_path: &'a Path,
    pub period: &'a str,
    pub out: &'a Path,
    pub referential: Option<&'a str>,
    /// Organisation auditée, affichée en couverture du dossier.
    pub organization: Option<&'a str>,
    /// Fichier d'inventaire des machines **attendues** (une par ligne,
    /// `#` pour les commentaires). Sans lui, l'écart attendu/observé ne
    /// peut pas être constaté et le dossier le déclare.
    pub inventory: Option<&'a Path>,
    /// Fichier de clé publique du journal (voir [`crate::keyres`]).
    pub pubkey: Option<&'a Path>,
    /// Répertoire des clés de l'agent (`agent.pub`/`agent.key`).
    pub keys: Option<&'a Path>,
    /// Chemin du magasin — sert à retrouver le jeton d'horodatage archivé
    /// pour la racine courante (`<magasin>.anchors/`, voir [`crate::anchors`]).
    pub store_path: Option<&'a Path>,
}

/// `constat pack --period <p> --out <fichier>` : dossier de preuve (§10.2),
/// rendu HTML autonome et imprimable via `constat-report`.
pub fn cmd_pack(store: &dyn Store, args: &PackArgs<'_>) -> miette::Result<String> {
    use constat_report as report;

    let period = parse_period(args.period)?;
    let assertions = load_assertions(args.assertions_path)?;
    let (evaluations, inputs) = evaluate_all(store, &assertions, period)?;

    // Référentiel de correspondance (§10.2.3) : chargé d'abord — un
    // référentiel introuvable ou invalide doit échouer avant d'écrire quoi
    // que ce soit.
    let referential_file = args.referential.map(referential::load).transpose()?;

    let snaps = queries::snapshots(store).into_diagnostic()?;
    let mut observed: Vec<AssetId> = snaps
        .iter()
        .filter(|(_, s)| s.at >= period.from && s.at <= period.to)
        .map(|(_, s)| s.asset.clone())
        .collect();
    observed.sort();
    observed.dedup();

    // Inventaire attendu : fichier fourni, sinon l'observé (écart nul par
    // construction — le dossier reste honnête : la source est indiquée).
    let (expected, inventory_note) = match args.inventory {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| miette!("impossible de lire l'inventaire {} : {e}", path.display()))?;
            let list: Vec<AssetId> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| AssetId(l.to_string()))
                .collect();
            (list, String::new())
        }
        None => (
            observed.clone(),
            "\nAttention : aucun inventaire attendu fourni (--inventory) — l'écart \
             attendu/observé n'a pas pu être constaté."
                .to_string(),
        ),
    };

    // Exigences : verdicts, couverture, exceptions datées — et, en parallèle,
    // les mêmes verdicts sous la forme reprise par la table de correspondance.
    let mut requirements = Vec::with_capacity(evaluations.len());
    let mut outcomes = Vec::with_capacity(evaluations.len());
    for (e, a) in evaluations.iter().zip(assertions.iter()) {
        let mut exceptions = Vec::with_capacity(a.exceptions.len());
        for exc in &a.exceptions {
            exceptions.push(report::ExceptionNote {
                entity: exc.entity.clone(),
                reason: exc.reason.clone(),
                approved_by: exc.approved_by.clone(),
                expires: exc.expires_at().into_diagnostic()?,
            });
        }
        let verdict = match e.verdict {
            Verdict::Pass => report::Verdict::Pass,
            Verdict::Fail => report::Verdict::Fail,
            Verdict::Undetermined => report::Verdict::Undetermined,
        };
        let coverage = report::CoverageSummary {
            observed_permille: (e.coverage.observed_ppm / 1_000) as u16,
            max_gap: e.coverage.max_gap,
            gap_count: e.coverage.gaps.len() as u32,
        };
        outcomes.push(report::AssertionOutcome {
            assertion_id: e.assertion.0.clone(),
            title: e.title.clone(),
            verdict,
            coverage,
        });
        requirements.push(report::RequirementReport {
            assertion_id: e.assertion.0.clone(),
            title: e.title.clone(),
            requirement_ref: None,
            verdict,
            coverage,
            exceptions,
        });
    }

    // Table de correspondance : verdicts issus de l'évaluation ci-dessus,
    // assertions inconnues du référentiel en avertissements listés.
    let correspondence = referential_file
        .as_ref()
        .map(|f| referential::build_table(f, &outcomes));

    // Interruptions par machine, déclarées explicitement (§10.2.4).
    let mut outages = Vec::new();
    for input in &inputs {
        for g in &input.coverage.gaps {
            outages.push(report::Outage {
                asset: input.asset.clone(),
                from: g.from,
                to: g.to,
                reason: render::gap_reason_label(&g.reason).to_string(),
            });
        }
    }

    // Annexe : les artefacts bruts de la période, avec leurs empreintes.
    let mut artifacts = Vec::new();
    for (_, snap) in snaps
        .iter()
        .filter(|(_, s)| s.at >= period.from && s.at <= period.to)
    {
        for (cid, bh) in &snap.blobs {
            artifacts.push(report::ArtifactRef {
                asset: snap.asset.clone(),
                collector: cid.0.clone(),
                blob: *bh,
                collected_at: snap.at,
            });
        }
    }

    // Bloc de preuve : racine, signature, procédure.
    let Some((root, last)) = store.last_entry().into_diagnostic()? else {
        return Err(miette!(
            "le journal est vide : aucun dossier de preuve à générer"
        ));
    };
    let entry_count = store.entries().into_diagnostic()?.len() as u64;
    // Clé publique du journal : résolue comme pour `constat export`
    // (--pubkey, sinon le répertoire de clés de l'agent). Sans clé, le
    // dossier déclare l'absence — l'auditeur la reçoit de toute façon par
    // un canal séparé.
    let public_key = keyres::try_resolve_public_key(args.pubkey, args.keys)?
        .map(|k| k.to_bytes().to_vec())
        .unwrap_or_default();
    // Jeton RFC 3161 : celui archivé par `constat anchor --send` pour la
    // racine courante, s'il existe. Son absence reste déclarée, jamais
    // masquée — et un jeton d'une autre racine n'est jamais recyclé.
    let timestamp_token = match args.store_path {
        Some(store_path) => anchors::read_token(store_path, &root)?,
        None => None,
    };
    let anchored = timestamp_token.is_some();
    let proof = report::ProofBlock {
        merkle_root: root,
        root_signature: last.signature.clone(),
        public_key,
        timestamp_token,
        entry_count,
    };

    let dossier = report::EvidenceDossier {
        cover: report::Cover {
            organization: args
                .organization
                .unwrap_or("(organisation non renseignée)")
                .to_string(),
            period_start: period.from,
            period_end: period.to,
            scope: format!("{} machine(s) observée(s)", observed.len()),
            generated_at: datetime::now(),
            // En couverture : l'identité du référentiel chargé, pas
            // l'argument brut de la ligne de commande.
            referential: referential_file.as_ref().map(|f| {
                format!(
                    "{} {} ({})",
                    f.referential.title, f.referential.version, f.referential.id
                )
            }),
        },
        inventory: report::Inventory { expected, observed },
        requirements,
        correspondence,
        outages,
        artifacts,
        proof,
    };

    let html = report::render_html(&dossier);
    std::fs::write(args.out, html)
        .map_err(|e| miette!("impossible d'écrire {} : {e}", args.out.display()))?;
    let anchor_note = if anchored {
        "\nJeton d'horodatage RFC 3161 joint au dossier (niveau 3, §6.3)."
    } else {
        "\nAucun jeton d'horodatage pour la racine courante — absence déclarée dans le \
         dossier (`constat anchor --send <url>` pour ancrer)."
    };
    // La table de correspondance résume son contenu sur la sortie, et ses
    // avertissements (assertions inconnues référencées) sont listés — dans
    // le dossier ET ici, jamais tus.
    let referential_note = match &dossier.correspondence {
        Some(table) => {
            let uncovered = table
                .requirements
                .iter()
                .filter(|r| r.verdict() == report::RequirementVerdict::NotCovered)
                .count();
            let mut note = format!(
                "\nTable de correspondance « {} {} » : {} exigence(s), dont {} non couverte(s) ; \
                 {} assertion(s) hors référentiel en annexe.",
                table.referential_title,
                table.referential_version,
                table.requirements.len(),
                uncovered,
                table.unmapped_assertions.len()
            );
            for warning in &table.warnings {
                note.push_str(&format!("\nAvertissement : {warning}."));
            }
            note
        }
        None => String::new(),
    };
    Ok(format!(
        "Dossier de preuve écrit : {} (HTML autonome, imprimable en PDF).{}{}{}",
        args.out.display(),
        anchor_note,
        referential_note,
        inventory_note
    ))
}

/// `constat verify [DOSSIER]` : rappelle où est le vérificateur **autonome**
/// et comment le lancer. Volontairement PAS une réimplémentation de la
/// vérification dans la CLI : si contrôler un dossier exigeait de faire
/// confiance à l'outil qui l'a produit, ce ne serait pas une preuve (§10.3).
pub fn cmd_verify(export: Option<&Path>) -> String {
    let name = format!("constat-verify{}", std::env::consts::EXE_SUFFIX);
    // Le binaire est distribué à côté de `constat` : on le cherche là.
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(&name)))
        .filter(|p| p.is_file());
    let binary = match &sibling {
        Some(path) => path.display().to_string(),
        None => name.clone(),
    };
    let target = match export {
        Some(path) => path.display().to_string(),
        None => "<répertoire-export>".to_string(),
    };
    let location_note = match &sibling {
        Some(path) => format!("Binaire autonome : {}", path.display()),
        None => format!(
            "Binaire autonome : {name} (introuvable à côté de `constat` — il est \
             distribué séparément, précisément pour être remis à l'auditeur)"
        ),
    };
    format!(
        "La vérification est un binaire séparé, volontairement : si contrôler un dossier \
         exigeait de faire confiance à l'outil qui l'a produit, ce ne serait pas une \
         preuve (§10.3).\n\
         {location_note}\n\
         Commande : {binary} {target}\n\
         (répertoire produit par `constat export --out <répertoire-export>` ; algorithme \
         documenté dans crates/constat-verify/FORMAT.md)"
    )
}

/// Paramètres de `constat export`.
pub struct ExportArgs<'a> {
    /// Répertoire de sortie (créé si nécessaire).
    pub out: &'a Path,
    /// Fichier de clé publique du journal (voir [`crate::keyres`]).
    pub pubkey: Option<&'a Path>,
    /// Répertoire des clés de l'agent (`agent.pub`/`agent.key`).
    pub keys: Option<&'a Path>,
}

/// `constat export --out <dir>` : produit le répertoire d'export vérifiable
/// par `constat-verify`, au format normatif de
/// `crates/constat-verify/FORMAT.md` (§10.3), via
/// [`constat_store::export_store`].
///
/// La clé publique est résolue comme documenté dans [`crate::keyres`]
/// (`--pubkey`, sinon le répertoire de clés de l'agent) — c'est la clé
/// **courante**. L'export, lui, écrit dans `pubkey.bin` la clé de **GENÈSE**
/// du journal (l'identité, stable à travers les rotations de clé,
/// [`constat_store::genesis_key`]) : c'est elle que le vérificateur attend,
/// et il suit ensuite les rotations journalisées le long de la chaîne
/// (FORMAT.md § 4 ter). Avant d'écrire, la chaîne est vérifiée en suivant la
/// clé courante ([`constat_store::verify_chain_rotated`]) : exporter un
/// journal qui ne se vérifie pas produirait un export qui échoue chez
/// l'auditeur.
pub fn cmd_export(store: &dyn Store, args: &ExportArgs<'_>) -> miette::Result<String> {
    let key = keyres::resolve_public_key(args.pubkey, args.keys)?;
    let entries = store.entries().into_diagnostic()?;
    let Some((root, _)) = entries.last() else {
        return Err(miette!(
            "le journal est vide : aucun export de preuve à produire"
        ));
    };
    let genesis_bytes = constat_store::genesis_key(store, &entries, &key.to_bytes())
        .map_err(|e| miette!("lecture des rotations du journal impossible : {e}"))?;
    let genesis = constat_store::VerifyingKey::from_bytes(&genesis_bytes)
        .map_err(|e| miette!("clé de genèse du journal invalide : {e}"))?;
    let trace = constat_store::verify_chain_rotated(store, &entries, &genesis).map_err(|e| {
        miette!(
            help = "vérifiez que la clé fournie (--pubkey/--keys) est bien la clé \
                    courante de ce journal (après rotation, agent.pub est la nouvelle \
                    clé ; la genèse est retrouvée par le journal lui-même)",
            "le journal ne se vérifie pas : {e}"
        )
    })?;
    if trace.final_key != key.to_bytes() {
        return Err(miette!(
            help = "après `constat-agent rotate-key`, la clé courante est le nouvel \
                    agent.pub ; fournissez-la (--pubkey/--keys) — la clé de genèse, \
                    elle, est retrouvée automatiquement dans le journal",
            "la clé fournie n'est pas la clé courante de ce journal"
        ));
    }
    constat_store::export_store(store, args.out, &genesis)
        .map_err(|e| miette!("export vers {} impossible : {e}", args.out.display()))?;
    let rotation_note = if trace.rotations == 0 {
        String::new()
    } else {
        format!(
            "{} rotation(s) de clé suivie(s) — pubkey.bin est la clé de GENÈSE \
             (l'identité du journal), le vérificateur suit les rotations.\n",
            trace.rotations
        )
    };
    Ok(format!(
        "Export vérifiable écrit : {} ({} entrée(s), clôture complète de la preuve).\n\
         {rotation_note}\
         Racine du journal : {}\n\
         Vérification par un tiers, sans Constat : constat-verify {}",
        args.out.display(),
        entries.len(),
        root.to_hex(),
        args.out.display()
    ))
}

/// Paramètres de `constat anchor`.
pub struct AnchorArgs<'a> {
    /// Écrire la requête d'horodatage RFC 3161 (DER) dans ce fichier.
    pub request_out: Option<&'a Path>,
    /// Écrire un export de racine signé (niveau 2, §6.3) dans ce fichier.
    pub export_out: Option<&'a Path>,
    /// Répertoire des clés de l'agent (pour signer l'export de racine).
    pub keys: Option<&'a Path>,
    /// Organisation, inscrite dans le document d'export.
    pub organization: Option<&'a str>,
    /// Envoyer la requête RFC 3161 à ce prestataire (URL `http://…` ou
    /// `https://…`) et archiver le jeton délivré à côté du magasin.
    pub send: Option<&'a str>,
    /// Chemin du magasin — sert à situer le répertoire d'ancrage
    /// (`<magasin>.anchors/`, voir [`crate::anchors`]). Requis avec `send`.
    pub store_path: Option<&'a Path>,
}

/// `constat anchor` : ancre la racine courante du journal (§6.3).
///
/// - `--export <fichier>` : export de racine **signé** (niveau 2) — un
///   document canonique à envoyer hors du système (courriel au RSSI, dépôt
///   tiers).
/// - `--out <fichier>` : requête d'horodatage RFC 3161 (DER), prête à être
///   envoyée au prestataire (`Content-Type: application/timestamp-query`).
/// - `--send <url>` : envoie la requête RFC 3161 au prestataire (niveau 3)
///   et archive la réponse délivrée dans `<magasin>.anchors/<racine>.tsr`
///   (voir [`crate::anchors`]) ; `constat pack` la joindra au dossier.
///   Un refus du prestataire est une **erreur** (code de sortie 1), avec le
///   motif renvoyé.
pub fn cmd_anchor(store: &dyn Store, args: &AnchorArgs<'_>) -> miette::Result<String> {
    let Some((root, entry)) = store.last_entry().into_diagnostic()? else {
        return Ok("Le journal est vide — rien à ancrer.".to_string());
    };
    let mut out = format!(
        "Racine courante du journal : {}\nDernière entrée : {}\n",
        root.to_hex(),
        format_timestamp(entry.at)
    );
    let mut did_something = false;

    if let Some(path) = args.export_out {
        let keys_dir = args
            .keys
            .map(Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from(keyres::DEFAULT_KEYS_DIR));
        let key = keyres::load_signing_key(&keys_dir)?;
        let export = sign_root_export(
            RootExportDocument {
                root,
                at: datetime::now(),
                organization: args
                    .organization
                    .unwrap_or("(organisation non renseignée)")
                    .to_string(),
            },
            &key,
        )
        .into_diagnostic()?;
        let bytes = export.to_transport_bytes().into_diagnostic()?;
        std::fs::write(path, bytes)
            .map_err(|e| miette!("impossible d'écrire {} : {e}", path.display()))?;
        out.push_str(&format!(
            "Export de racine signé écrit : {} (niveau 2 : à envoyer hors du système — \
             courriel au RSSI, dépôt tiers).\n",
            path.display()
        ));
        did_something = true;
    }

    if let Some(path) = args.request_out {
        let request = TimeStampRequest::for_root(&root);
        std::fs::write(path, request.to_der())
            .map_err(|e| miette!("impossible d'écrire {} : {e}", path.display()))?;
        out.push_str(&format!(
            "Requête d'horodatage RFC 3161 écrite : {} — à envoyer au prestataire :\n  \
             curl -s -H 'Content-Type: application/timestamp-query' \
             --data-binary @{} https://<prestataire>/tsa > jeton.tsr\n",
            path.display(),
            path.display()
        ));
        did_something = true;
    }

    if let Some(url) = args.send {
        let store_path = args.store_path.ok_or_else(|| {
            miette!("chemin du magasin inconnu : impossible de situer le répertoire d'ancrage")
        })?;
        let request = TimeStampRequest::for_root(&root);
        let response = http::post(
            url,
            "application/timestamp-query",
            "application/timestamp-reply",
            &request.to_der(),
        )?;
        if response.status != 200 {
            return Err(miette!(
                "le prestataire d'horodatage a répondu HTTP {} {}",
                response.status,
                response.reason
            ));
        }
        let parsed = parse_response(&response.body)
            .map_err(|e| miette!("réponse d'horodatage illisible depuis {url} : {e}"))?;
        if !parsed.status.is_granted() {
            let motif = if parsed.status_text.is_empty() {
                "aucun motif fourni".to_string()
            } else {
                parsed.status_text.join(" ; ")
            };
            return Err(miette!(
                help = "le journal n'est pas ancré : réessayez, ou changez de prestataire",
                "horodatage refusé par {url} ({:?}) : {motif}",
                parsed.status
            ));
        }
        let path = anchors::write_response(store_path, &root, &response.body)?;
        out.push_str(&format!(
            "Jeton d'horodatage RFC 3161 délivré (niveau 3) et archivé : {}\n\
             `constat pack` le joindra au dossier de preuve de cette racine.\n\
             Vérification indépendante : openssl ts -reply -in {} -text\n",
            path.display(),
            path.display()
        ));
        did_something = true;
    }

    if !did_something {
        out.push_str(
            "Rappel (§6.2) : sans ancrage externe, le journal prouve la cohérence \
             interne, pas la non-répudiation.\n\
             - `constat anchor --export racine.export` : export de racine signé (niveau 2)\n\
             - `constat anchor --out requete.tsq`     : requête d'horodatage RFC 3161 (niveau 3)\n\
             - `constat anchor --send https://…`      : envoi direct au prestataire (niveau 3)\n",
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Non-régression du verdict après le fenêtrage de `check` : le chemin
    //! fenêtré ([`stream_evaluations`], machine par machine, à empreinte
    //! bornée) doit rendre EXACTEMENT le même résultat que le chemin « tout en
    //! mémoire » ([`evaluate_all`]) — mêmes verdicts, mêmes violations dans le
    //! même ordre, mêmes exceptions appliquées, même couverture.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{evaluate_all, stream_evaluations};
    use std::collections::BTreeMap;

    use constat_model::{
        AssetId, Attribute, Blob, CollectorId, EntityId, Fact, Snapshot, Timestamp, Value,
    };
    use constat_policy::{
        Assertion, AssertionId, AssetSelector, EntityPattern, Exception, Predicate, Verdict,
    };
    use constat_store::{append_signed, MemoryStore, Signer, Store};
    use constat_time::Period;

    fn fact(entity: &str, attr: &str, value: Value) -> Fact {
        Fact {
            entity: EntityId(entity.to_string()),
            attribute: Attribute(attr.to_string()),
            value,
        }
    }

    /// Une collecte : un blob, un snapshot, une entrée de journal signée.
    fn inject(store: &mut MemoryStore, signer: &Signer, asset: &str, at: i64, facts: Vec<Fact>) {
        let blob = Blob {
            collector: CollectorId("inventaire".to_string()),
            raw: format!("{asset}@{at}").into_bytes(),
            facts,
        };
        let bh = store.put_blob(&blob).unwrap();
        let mut blobs = BTreeMap::new();
        blobs.insert(CollectorId("inventaire".to_string()), bh);
        let snap = Snapshot {
            asset: AssetId(asset.to_string()),
            at: Timestamp(at),
            blobs,
        };
        let sh = store.put_snapshot(&snap).unwrap();
        append_signed(store, signer, vec![sh], Timestamp(at)).unwrap();
    }

    /// Parc de trois machines : `srv-a` (linux, un admin privilégié → viole),
    /// `srv-b` (linux, propre), `srv-win` (windows, un root privilégié). Les
    /// collectes sont entrelacées dans le temps pour que l'ordre global
    /// (date, actif) ne coïncide pas avec l'ordre par machine — c'est
    /// précisément ce que le regroupement fenêtré doit reconstituer.
    fn parc() -> MemoryStore {
        let mut store = MemoryStore::new();
        let signer = Signer::generate();
        let os = |m: &str, v: &str| fact(&format!("asset:{m}"), "asset.os", Value::Text(v.into()));

        inject(
            &mut store,
            &signer,
            "srv-a",
            1_000,
            vec![
                os("srv-a", "linux"),
                fact("user:jdupont", "user.privileged", Value::Bool(false)),
            ],
        );
        inject(
            &mut store,
            &signer,
            "srv-b",
            1_100,
            vec![
                os("srv-b", "linux"),
                fact("user:alice", "user.privileged", Value::Bool(false)),
            ],
        );
        inject(
            &mut store,
            &signer,
            "srv-win",
            1_200,
            vec![
                os("srv-win", "windows"),
                fact("user:root", "user.privileged", Value::Bool(true)),
            ],
        );
        inject(
            &mut store,
            &signer,
            "srv-a",
            2_000,
            vec![
                os("srv-a", "linux"),
                fact("user:jdupont", "user.privileged", Value::Bool(true)),
            ],
        );
        inject(
            &mut store,
            &signer,
            "srv-b",
            2_100,
            vec![
                os("srv-b", "linux"),
                fact("user:alice", "user.privileged", Value::Bool(false)),
            ],
        );
        inject(
            &mut store,
            &signer,
            "srv-win",
            2_200,
            vec![
                os("srv-win", "windows"),
                fact("user:root", "user.privileged", Value::Bool(true)),
            ],
        );
        store
    }

    fn never_privileged(id: &str, scope: AssetSelector, exceptions: Vec<Exception>) -> Assertion {
        Assertion {
            id: AssertionId(id.to_string()),
            title: format!("aucun compte privilégié ({id})"),
            scope,
            predicate: Predicate::Never {
                entity: EntityPattern::Glob("user:*".to_string()),
                attr: Attribute("user.privileged".to_string()),
                equals: Value::Bool(true),
            },
            exceptions,
        }
    }

    fn linux() -> AssetSelector {
        AssetSelector {
            os: Some("linux".to_string()),
            tag: None,
            domain: None,
        }
    }

    fn solaris() -> AssetSelector {
        AssetSelector {
            os: Some("solaris".to_string()),
            tag: None,
            domain: None,
        }
    }

    fn exception(entity: &str) -> Exception {
        Exception {
            entity: entity.to_string(),
            reason: "dérogation de test".to_string(),
            approved_by: "rssi".to_string(),
            expires: "2099-01-01".to_string(),
        }
    }

    /// Le cœur de la preuve : sur un parc multi-machines et un jeu d'assertions
    /// couvrant portée large / restreinte / vide et exceptions, le chemin
    /// fenêtré et le chemin global rendent des `Evaluation` identiques.
    #[test]
    fn fenetre_et_global_rendent_le_meme_verdict() {
        let store = parc();
        let period = Period {
            from: Timestamp(0),
            to: Timestamp(10_000),
        };
        let assertions = vec![
            // Portée linux : srv-a viole, srv-win exclue → Fail, 1 violation.
            never_privileged("LNX", linux(), vec![]),
            // Portée large + exception jdupont : la violation de srv-a est
            // neutralisée (exception appliquée), celle de srv-win (root) reste.
            never_privileged(
                "ALL-EXC",
                AssetSelector::default(),
                vec![exception("user:jdupont")],
            ),
            // Portée vide (aucune machine solaris) → Undetermined, périmètre nul.
            never_privileged("SOL", solaris(), vec![]),
        ];

        let (global, _) = evaluate_all(&store, &assertions, period).expect("chemin global");
        let windowed = stream_evaluations(&store, &assertions, period).expect("chemin fenêtré");

        assert_eq!(
            windowed, global,
            "le fenêtrage par machine ne doit RIEN changer au verdict de parc"
        );

        // Et les verdicts attendus sont bien ceux du modèle (ancrage explicite).
        assert_eq!(windowed[0].verdict, Verdict::Fail);
        assert_eq!(windowed[0].violations.len(), 1);
        assert_eq!(windowed[0].violations[0].asset.0, "srv-a");

        assert_eq!(windowed[1].verdict, Verdict::Fail);
        assert_eq!(windowed[1].violations.len(), 1);
        assert_eq!(windowed[1].violations[0].asset.0, "srv-win");
        assert_eq!(windowed[1].applied_exceptions.len(), 1);
        assert_eq!(
            windowed[1].applied_exceptions[0].neutralized.asset.0,
            "srv-a"
        );

        assert_eq!(windowed[2].verdict, Verdict::Undetermined);
        assert!(windowed[2].violations.is_empty());
    }
}
