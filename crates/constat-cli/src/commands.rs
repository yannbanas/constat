//! Les commandes du §10, écrites contre `&dyn Store`.
//!
//! Chaque commande renvoie le texte à afficher : la logique est ainsi
//! exerçable par le test de fumée sur un magasin en mémoire, sans processus.
//! La CLI ne modifie jamais le magasin — lecture seule, comme tout le
//! produit (§1).

use std::path::Path;

use constat_anchor::rfc3161::TimeStampRequest;
use constat_anchor::root::{sign_root_export, RootExportDocument};
use constat_model::{AssetId, Attribute, EntityId, Timestamp};
use constat_policy::{Assertion, Evaluation, Verdict};
use constat_store::{SigningKey, Store};
use constat_time::Period;
use miette::{miette, IntoDiagnostic};

use crate::coverage::DEFAULT_MAX_EXPECTED_GAP;
use crate::datetime::{self, format_timestamp, parse_period, parse_timestamp};
use crate::{eval, queries, render};

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

/// Évalue toutes les assertions sur une période : le socle de `check` et `pack`.
fn evaluate_all(
    store: &dyn Store,
    assertions: &[Assertion],
    period: Period,
) -> miette::Result<(Vec<Evaluation>, Vec<constat_policy::EvaluationInput>)> {
    let obs = queries::observations(store).into_diagnostic()?;
    let snap_times: Vec<(AssetId, Timestamp)> = queries::snapshots(store)
        .into_diagnostic()?
        .iter()
        .map(|(_, s)| (s.asset.clone(), s.at))
        .collect();
    let inputs = eval::build_inputs(&obs, &snap_times, period, DEFAULT_MAX_EXPECTED_GAP)
        .into_diagnostic()?;
    let times: Vec<Timestamp> = snap_times.iter().map(|(_, t)| *t).collect();
    let park_coverage = crate::coverage::coverage_report(&times, period, DEFAULT_MAX_EXPECTED_GAP)
        .into_diagnostic()?;
    let mut results = Vec::with_capacity(assertions.len());
    for a in assertions {
        results.push(eval::evaluate_park(a, &inputs, park_coverage.clone()).into_diagnostic()?);
    }
    Ok((results, inputs))
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
    let (results, _) = evaluate_all(store, &assertions, period)?;
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
}

/// `constat pack --period <p> --out <fichier>` : dossier de preuve (§10.2),
/// rendu HTML autonome et imprimable via `constat-report`.
pub fn cmd_pack(store: &dyn Store, args: &PackArgs<'_>) -> miette::Result<String> {
    use constat_report as report;

    let period = parse_period(args.period)?;
    let assertions = load_assertions(args.assertions_path)?;
    let (evaluations, inputs) = evaluate_all(store, &assertions, period)?;

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

    // Exigences : verdicts, couverture, exceptions datées.
    let mut requirements = Vec::with_capacity(evaluations.len());
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
        requirements.push(report::RequirementReport {
            assertion_id: e.assertion.0.clone(),
            title: e.title.clone(),
            // TODO(integration) : table de correspondance par référentiel
            // (exigence RECYF/ISO ↔ assertion), à venir dans constat-report.
            requirement_ref: None,
            verdict: match e.verdict {
                Verdict::Pass => report::Verdict::Pass,
                Verdict::Fail => report::Verdict::Fail,
                Verdict::Undetermined => report::Verdict::Undetermined,
            },
            coverage: report::CoverageSummary {
                observed_permille: (e.coverage.observed_ppm / 1_000) as u16,
                max_gap: e.coverage.max_gap,
                gap_count: e.coverage.gaps.len() as u32,
            },
            exceptions,
        });
    }

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
    let proof = report::ProofBlock {
        merkle_root: root,
        root_signature: last.signature.clone(),
        // TODO(integration) : distribution de la clé publique du journal à
        // la CLI (aujourd'hui elle vit dans le répertoire de clés de
        // l'agent) — l'auditeur la reçoit par un canal séparé de toute façon.
        public_key: Vec::new(),
        // TODO(integration) : joindre le jeton RFC 3161 une fois le
        // transport d'ancrage câblé (`constat anchor`).
        timestamp_token: None,
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
            referential: args.referential.map(str::to_string),
        },
        inventory: report::Inventory { expected, observed },
        requirements,
        outages,
        artifacts,
        proof,
    };

    let html = report::render_html(&dossier);
    std::fs::write(args.out, html)
        .map_err(|e| miette!("impossible d'écrire {} : {e}", args.out.display()))?;
    Ok(format!(
        "Dossier de preuve écrit : {} (HTML autonome, imprimable en PDF).{}",
        args.out.display(),
        inventory_note
    ))
}

/// Charge la clé de signature du journal depuis le répertoire de clés de
/// l'agent (fichier `agent.key`, 32 octets hexadécimaux).
fn load_signing_key(dir: &Path) -> miette::Result<SigningKey> {
    let path = dir.join("agent.key");
    let text = std::fs::read_to_string(&path).map_err(|e| {
        miette!(
            help = "générez la paire de clés avec `constat-agent keygen`",
            "impossible de lire la clé {} : {e}",
            path.display()
        )
    })?;
    let bytes = hex_decode(text.trim()).ok_or_else(|| {
        miette!(
            "clé illisible dans {} (hexadécimal attendu)",
            path.display()
        )
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        miette!(
            "clé de taille invalide dans {} (32 octets attendus)",
            path.display()
        )
    })?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Décodage hexadécimal sans dépendance.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
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
}

/// `constat anchor` : ancre la racine courante du journal (§6.3).
///
/// - `--export <fichier>` : export de racine **signé** (niveau 2) — un
///   document canonique à envoyer hors du système (courriel au RSSI, dépôt
///   tiers). Fonctionnel.
/// - `--out <fichier>` : requête d'horodatage RFC 3161 (DER), prête à être
///   envoyée au prestataire (`Content-Type: application/timestamp-query`).
///   Fonctionnel ; l'envoi HTTP automatique reste un TODO(integration).
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
            .unwrap_or_else(|| std::path::PathBuf::from("./constat-agent.keys"));
        let key = load_signing_key(&keys_dir)?;
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
             --data-binary @{} https://<prestataire>/tsa > jeton.tsr\n\
             (TODO(integration) : l'envoi HTTP automatique et la vérification du \
             jeton seront câblés dans constat-anchor.)\n",
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
             - `constat anchor --out requete.tsq`     : requête d'horodatage RFC 3161 (niveau 3)\n",
        );
    }
    Ok(out)
}
