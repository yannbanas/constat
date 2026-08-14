//! `constat purge` et `constat retention` — la purge de rétention
//! journalisée (§16) côté CLI.
//!
//! > Une suppression liée à la rétention crée un trou dans les données, et un
//! > trou non déclaré est indistinguable d'un effacement malveillant.
//!
//! - `constat retention --show` / `--check <durée>` : lecture seule — l'âge
//!   des données et ce qu'une politique de rétention purgerait ;
//! - `constat purge --older-than <durée> --reason <motif>` : la **deuxième**
//!   commande d'écriture de la CLI (après `segmentation --record`), assumée
//!   et documentée. Elle supprime blobs et snapshots trop vieux et **déclare
//!   la purge dans une nouvelle entrée signée** du journal — les entrées de
//!   journal, elles, ne sont jamais supprimées ([`constat_store::purge`]).
//!
//! Une purge est irréversible : sans `--yes`, un récapitulatif est affiché et
//! une confirmation interactive est exigée ; `--dry-run` montre le plan sans
//! rien modifier.

use std::path::Path;

use constat_model::Timestamp;
use constat_store::{plan_purge, MultiJournalStore, PurgePlan, PurgeableStore, Signer, Store};
use miette::{miette, IntoDiagnostic};

use crate::datetime::{self, format_duration, format_timestamp, parse_duration};
use crate::{keyres, queries};

/// Paramètres de `constat purge`.
pub struct PurgeArgs<'a> {
    /// Durée de rétention : tout objet plus vieux est purgé (ex. `1095j`).
    pub older_than: &'a str,
    /// Motif de la purge, inscrit dans la déclaration signée.
    pub reason: &'a str,
    /// Répertoire des clés de l'agent (`agent.key`) pour signer la
    /// déclaration ; défaut : celui de l'agent.
    pub keys: Option<&'a Path>,
    /// Simulation : affiche le plan, ne modifie rien.
    pub dry_run: bool,
    /// Saute la confirmation interactive (purge irréversible).
    pub assume_yes: bool,
}

/// Récapitulatif lisible d'un plan de purge.
fn render_plan(plan: &PurgePlan) -> String {
    format!(
        "Purge planifiée (seuil : objets antérieurs au {}) :\n\
         - période purgée : {} → {}\n\
         - {} snapshot(s), {} blob(s) — {} objet(s) au total\n\
         - volume des blobs : {} octet(s) (décompressés)\n\
         Les entrées de journal ne sont JAMAIS supprimées : la purge sera \
         déclarée dans une nouvelle entrée signée (§16).",
        format_timestamp(plan.cutoff),
        format_timestamp(plan.from),
        format_timestamp(plan.to),
        plan.snapshots.len(),
        plan.blobs.len(),
        plan.object_count(),
        plan.blob_bytes
    )
}

/// `constat purge --older-than <durée> --reason <motif> [--keys <dossier>]
/// [--dry-run] [--yes]`.
///
/// `confirm` reçoit le récapitulatif et rend la décision de l'utilisateur —
/// il n'est appelé que si la purge est réelle (`!dry_run`) et non déjà
/// consentie (`!assume_yes`). Le binaire y branche la question interactive ;
/// les tests, une constante.
///
/// La commande est générique sur [`PurgeableStore`] : le pouvoir de
/// suppression est porté par le type, pas par une option.
pub fn cmd_purge<S: PurgeableStore>(
    store: &mut S,
    args: &PurgeArgs<'_>,
    confirm: impl FnOnce(&str) -> bool,
) -> miette::Result<String> {
    let retention = parse_duration(args.older_than)?;
    if args.reason.trim().is_empty() {
        return Err(miette!(
            "le motif (--reason) est obligatoire : une purge sans motif déclaré \
             ne vaut pas mieux qu'un trou inexpliqué (§16)"
        ));
    }
    let now = datetime::now();
    let cutoff = Timestamp(now.0.saturating_sub_unsigned(retention.0));

    let Some(plan) = plan_purge(&*store, cutoff).into_diagnostic()? else {
        return Ok(format!(
            "Rien à purger : aucun objet antérieur au {} (rétention {}).",
            format_timestamp(cutoff),
            format_duration(retention)
        ));
    };
    let recap = render_plan(&plan);

    if args.dry_run {
        return Ok(format!(
            "{recap}\n\nMode simulation (--dry-run) : le magasin n'a pas été modifié."
        ));
    }

    // La clé est résolue AVANT la confirmation : inutile de faire confirmer
    // une purge que l'on ne pourra pas signer.
    let keys_dir = args
        .keys
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from(keyres::DEFAULT_KEYS_DIR));
    let signing_key = keyres::load_signing_key(&keys_dir)?;
    let signer = Signer::from_bytes(&signing_key.to_bytes());

    let confirmed = args.assume_yes || confirm(&recap);
    if !confirmed {
        return Ok("Purge annulée — le magasin n'a pas été modifié.".to_string());
    }

    let report =
        constat_store::execute_plan(store, &signer, &plan, args.reason, now).into_diagnostic()?;

    let mut out = String::new();
    if args.assume_yes {
        // En mode non interactif, le récapitulatif n'a pas encore été montré.
        out.push_str(&recap);
        out.push_str("\n\n");
    }
    out.push_str(&format!(
        "Purge exécutée et déclarée au journal (§16) :\n\
         - période purgée : {} → {}\n\
         - motif : {}\n\
         - {} snapshot(s) et {} blob(s) supprimé(s)\n\
         - manifeste BLAKE3 : {}\n\
         - blob de déclaration : {}\n\
         - nouvelle racine du journal : {}\n\
         La chaîne n'a pas été réécrite : l'entrée de purge s'ajoute à la fin, \
         signée. `constat-verify` acceptera les absences déclarées, et \
         l'évaluation montrera un trou « purge de rétention journalisée ».",
        format_timestamp(report.from),
        format_timestamp(report.to),
        report.reason,
        report.snapshots_purged,
        report.blobs_purged,
        report.manifest.to_hex(),
        report.declaration_blob.to_hex(),
        report.root.to_hex()
    ));
    Ok(out)
}

/// Paramètres de `constat retention`.
pub struct RetentionArgs<'a> {
    /// `--check <durée>` : simule une purge à cette rétention.
    pub check: Option<&'a str>,
}

/// `constat retention [--show | --check <durée>]` — lecture seule.
///
/// - sans `--check` : l'âge des données du magasin (plus vieil et plus récent
///   snapshot, comptes d'objets, purges déjà déclarées) ;
/// - avec `--check <durée>` : ce qu'une purge à cette rétention supprimerait,
///   sans rien modifier.
pub fn cmd_retention<S: MultiJournalStore>(
    store: &S,
    args: &RetentionArgs<'_>,
) -> miette::Result<String> {
    let dyn_store: &dyn Store = store;
    let snaps = queries::snapshots(dyn_store).into_diagnostic()?;
    let now = datetime::now();

    let mut out = String::new();
    match (snaps.first(), snaps.last()) {
        (Some((_, oldest)), Some((_, newest))) => {
            let age = constat_model::DurationMs(now.0.abs_diff(oldest.at.0));
            out.push_str(&format!(
                "Magasin : {} snapshot(s) référencé(s) par le journal.\n\
                 Plus vieil objet : {} (âge : {})\n\
                 Plus récent      : {}\n",
                snaps.len(),
                format_timestamp(oldest.at),
                format_duration(age),
                format_timestamp(newest.at)
            ));
        }
        _ => out.push_str("Magasin : aucune collecte référencée par le journal.\n"),
    }

    // Purges déjà déclarées : elles font partie de l'état de rétention.
    let declared = queries::purge_gaps(dyn_store).into_diagnostic()?;
    if declared.is_empty() {
        out.push_str("Aucune purge déclarée dans le journal.\n");
    } else {
        out.push_str(&format!("{} purge(s) déjà déclarée(s) :\n", declared.len()));
        for gap in &declared {
            out.push_str(&format!(
                "  - {} → {}\n",
                format_timestamp(gap.from),
                format_timestamp(gap.to)
            ));
        }
    }

    if let Some(duration) = args.check {
        let retention = parse_duration(duration)?;
        let cutoff = Timestamp(now.0.saturating_sub_unsigned(retention.0));
        out.push('\n');
        match plan_purge(store, cutoff).into_diagnostic()? {
            Some(plan) => {
                out.push_str(&format!(
                    "Une rétention de {} purgerait :\n\
                     - période : {} → {}\n\
                     - {} snapshot(s), {} blob(s) — {} objet(s)\n\
                     - volume des blobs : {} octet(s) (décompressés)\n",
                    format_duration(retention),
                    format_timestamp(plan.from),
                    format_timestamp(plan.to),
                    plan.snapshots.len(),
                    plan.blobs.len(),
                    plan.object_count(),
                    plan.blob_bytes
                ));
            }
            None => out.push_str(&format!(
                "Une rétention de {} ne purgerait rien (aucun objet antérieur au {}).\n",
                format_duration(retention),
                format_timestamp(cutoff)
            )),
        }
        out.push_str("Aucune suppression effectuée : `constat purge` pour purger réellement.");
    }
    Ok(out)
}
