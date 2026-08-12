//! L'évaluation explique (§5.3) : rendu humain, en français, d'un
//! [`Evaluation`] — **pourquoi** ça échoue, pas seulement que ça échoue.
//!
//! Le format suit les exemples de la spécification (§4.2) : verdict et
//! période, couverture et écart maximal, interruptions déclarées (jamais
//! masquées), puis chaque violation avec l'entité, l'observé, l'attendu, les
//! dates et l'empreinte de la preuve, et enfin les exceptions appliquées avec
//! leur justification et leur expiration.

use crate::dates::{format_date, format_datetime};
use crate::duration::format_duration;
use crate::eval::NO_EVIDENCE;
use crate::value_repr::fingerprint_hex;
use crate::{Evaluation, Verdict};
use constat_model::Value;
use constat_time::GapReason;
use std::fmt::Write as _;

/// Rendu français d'une valeur de fait : « vrai », « faux », `« texte »`,
/// « absent »…
#[must_use]
pub fn format_value(v: &Value) -> String {
    match v {
        Value::Bool(true) => "vrai".to_owned(),
        Value::Bool(false) => "faux".to_owned(),
        Value::Int(i) => i.to_string(),
        Value::Text(t) => format!("« {t} »"),
        Value::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(format_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Fingerprint(fp) => {
            let hexa = fingerprint_hex(fp);
            format!("empreinte {}…", hexa.get(..8).unwrap_or(&hexa))
        }
        Value::Absent => "absent".to_owned(),
    }
}

/// Pourcentage français depuis des parties par million : « 99,2 % ».
fn format_ppm(ppm: u32) -> String {
    let tenths = ppm / 1_000; // dixièmes de pour cent
    let whole = tenths / 10;
    let frac = tenths % 10;
    if frac == 0 {
        format!("{whole} %")
    } else {
        format!("{whole},{frac} %")
    }
}

/// Libellé français d'une raison d'interruption.
fn gap_reason_fr(reason: &GapReason) -> &'static str {
    match reason {
        GapReason::AgentDown => "agent indisponible",
        GapReason::MachineOff => "machine arrêtée",
        GapReason::CollectFailed => "collecte en échec",
        GapReason::RetentionPurge => "purge de rétention journalisée",
        GapReason::Unknown => "raison inconnue",
    }
}

/// Huit premiers caractères hexadécimaux d'une empreinte.
fn short_hash(h: &constat_model::BlobHash) -> String {
    let hexa = h.to_hex();
    hexa.get(..8).unwrap_or(&hexa).to_owned()
}

/// Accord singulier/pluriel paresseux : « 1 violation », « 3 violations ».
fn plural(n: usize, singulier: &str, pluriel: &str) -> String {
    if n <= 1 {
        format!("{n} {singulier}")
    } else {
        format!("{n} {pluriel}")
    }
}

/// Produit l'explication humaine d'une évaluation, en français.
///
/// Chaque violation est expliquée : machine, entité, valeur observée contre
/// valeur attendue, le **pourquoi** (champ [`crate::Violation::detail`]),
/// l'intervalle de constat et l'empreinte de l'artefact de preuve. Les
/// interruptions de collecte sont toujours déclarées, et les exceptions
/// appliquées sont tracées avec justification, approbateur et expiration.
#[must_use]
pub fn explain(e: &Evaluation) -> String {
    let mut out = String::new();

    // En-tête : identifiant, titre, machine.
    if e.title.is_empty() {
        let _ = writeln!(out, "{}", e.assertion.0);
    } else {
        let _ = writeln!(out, "{} — {}", e.assertion.0, e.title);
    }
    if let Some(asset) = &e.asset {
        let _ = writeln!(out, "Machine : {}", asset.0);
    }

    // Verdict et période.
    let period = format!(
        "sur la période du {} au {}",
        format_date(e.coverage.period.from),
        format_date(e.coverage.period.to)
    );
    match e.verdict {
        Verdict::Pass => {
            let _ = writeln!(out, "CONFORME {period}.");
        }
        Verdict::Fail => {
            let _ = writeln!(out, "NON CONFORME {period}.");
        }
        Verdict::Undetermined => {
            let _ = writeln!(
                out,
                "INDÉTERMINÉ {period} — couverture insuffisante pour se prononcer."
            );
        }
    }

    // Couverture, toujours affichée : c'est ce qui distingue une preuve d'un
    // joli tableau de bord (§4.2).
    let _ = writeln!(
        out,
        "  Couverture : {} — écart maximal entre deux collectes : {}",
        format_ppm(e.coverage.observed_ppm),
        format_duration(e.coverage.max_gap)
    );
    if e.coverage.gaps.is_empty() {
        let _ = writeln!(out, "  Aucune interruption de collecte déclarée.");
    } else {
        let _ = writeln!(
            out,
            "  {} :",
            plural(
                e.coverage.gaps.len(),
                "interruption déclarée",
                "interruptions déclarées"
            )
        );
        for g in &e.coverage.gaps {
            let _ = writeln!(
                out,
                "    - {} → {}  ({})",
                format_datetime(g.from),
                format_datetime(g.to),
                gap_reason_fr(&g.reason)
            );
        }
    }

    // Violations : le cœur de l'explication.
    if !e.violations.is_empty() {
        let _ = writeln!(
            out,
            "  {} :",
            plural(e.violations.len(), "violation", "violations")
        );
        for v in &e.violations {
            let _ = writeln!(out, "    - {} · {}", v.asset.0, v.entity.0);
            // Pour « never », `expected` porte la valeur interdite : l'observé
            // est alors égal à l'attendu et on affiche « ≠ ».
            let expected = if v.observed == v.expected {
                format!("≠ {}", format_value(&v.expected))
            } else {
                format_value(&v.expected)
            };
            let _ = writeln!(
                out,
                "      observé : {} — attendu : {}",
                format_value(&v.observed),
                expected
            );
            if !v.detail.is_empty() {
                let _ = writeln!(out, "      pourquoi : {}", v.detail);
            }
            let _ = writeln!(
                out,
                "      constaté du {} au {}",
                format_datetime(v.first_seen),
                format_datetime(v.last_seen)
            );
            if v.evidence == NO_EVIDENCE {
                let _ = writeln!(
                    out,
                    "      preuve : aucune — le constat porte sur une absence"
                );
            } else {
                let _ = writeln!(out, "      preuve : blob {}…", short_hash(&v.evidence));
            }
        }
    }

    // Exceptions appliquées : neutralisées mais jamais passées sous silence.
    if !e.applied_exceptions.is_empty() {
        let _ = writeln!(
            out,
            "  {} :",
            plural(
                e.applied_exceptions.len(),
                "exception appliquée",
                "exceptions appliquées"
            )
        );
        for a in &e.applied_exceptions {
            let _ = writeln!(out, "    - {} — {}", a.exception.entity, a.exception.reason);
            let expires = crate::dates::parse_date(&a.exception.expires)
                .map_or_else(|_| a.exception.expires.clone(), format_date);
            let _ = writeln!(
                out,
                "      approuvée par {}, expire le {} — neutralise : {}",
                a.exception.approved_by, expires, a.neutralized.detail
            );
        }
    }

    if e.verdict == Verdict::Pass && e.violations.is_empty() && e.applied_exceptions.is_empty() {
        let _ = writeln!(out, "  Aucune violation constatée.");
    }

    out
}
