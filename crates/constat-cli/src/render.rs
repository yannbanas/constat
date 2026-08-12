//! Mise en forme des sorties de la CLI, en français.
//!
//! Le format de `constat history` suit l'exemple du §10.1 : des changements
//! datés, l'empreinte du blob de preuve, la machine, puis la couverture avec
//! les interruptions déclarées — jamais masquées.

use constat_model::{AssetId, BlobHash, Value};
use constat_policy::{Assertion, Evaluation, Verdict, NO_EVIDENCE};
use constat_time::{CoverageReport, GapReason};

use crate::datetime::{format_duration, format_period, format_ppm, format_timestamp};
use crate::eval::TimelineSegment;
use crate::queries::{DiffView, History, StateView};

/// Représentation courte d'une empreinte : huit hexadécimaux et une ellipse.
pub fn short_hash(h: &BlobHash) -> String {
    let hex = h.to_hex();
    format!("{}…", &hex[..8])
}

/// Représentation lisible d'une valeur de fait.
pub fn format_value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Text(t) => t.clone(),
        Value::List(items) => {
            let inner: Vec<String> = items.iter().map(format_value).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Fingerprint(fp) => format!("empreinte:{}…", hex_prefix(fp)),
        Value::Absent => "(absent)".to_string(),
    }
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Libellé français d'une raison d'interruption.
pub fn gap_reason_label(r: &GapReason) -> &'static str {
    match r {
        GapReason::AgentDown => "agent indisponible",
        GapReason::MachineOff => "machine arrêtée",
        GapReason::CollectFailed => "collecte en échec",
        GapReason::RetentionPurge => "purge de rétention journalisée",
        GapReason::Unknown => "cause inconnue",
    }
}

/// Bloc de couverture : ratio, écart maximal, interruptions déclarées.
pub fn render_coverage(c: &CoverageReport) -> String {
    let mut s = format!(
        "Couverture sur la période : {} — écart maximal entre deux collectes : {}",
        format_ppm(c.observed_ppm),
        format_duration(c.max_gap)
    );
    if c.gaps.is_empty() {
        s.push_str("\nAucune interruption déclarée.");
    } else {
        let n = c.gaps.len();
        s.push_str(&format!(
            "\n{n} interruption{s1} déclarée{s1} :",
            s1 = if n > 1 { "s" } else { "" }
        ));
        for g in &c.gaps {
            s.push_str(&format!(
                "\n  - {} → {}  ({})",
                format_timestamp(g.from),
                format_timestamp(g.to),
                gap_reason_label(&g.reason)
            ));
        }
    }
    s
}

/// Sortie de `constat state`.
pub fn render_state(view: &StateView, asked_at: &str) -> String {
    let mut out = format!(
        "État de {} au {} — snapshot du {} (empreinte {})\n",
        view.snapshot.asset.0,
        asked_at,
        format_timestamp(view.snapshot.at),
        short_hash(&view.snapshot_hash)
    );
    if view.facts.is_empty() {
        out.push_str("\n  (aucun fait dans ce snapshot)\n");
        return out;
    }
    let mut current_entity: Option<&str> = None;
    for (collector, blob, fact) in &view.facts {
        if current_entity != Some(fact.entity.0.as_str()) {
            out.push_str(&format!("\n  {}\n", fact.entity.0));
            current_entity = Some(fact.entity.0.as_str());
        }
        out.push_str(&format!(
            "    {} = {}    [{}, blob {}]\n",
            fact.attribute.0,
            format_value(&fact.value),
            collector.0,
            short_hash(blob)
        ));
    }
    out
}

/// Sortie de `constat diff`.
pub fn render_diff(asset: &AssetId, view: &DiffView, from: &str, to: &str) -> String {
    let mut out = format!(
        "Différence sur {} entre {} (snapshot du {}) et {} (snapshot du {})\n",
        asset.0,
        from,
        format_timestamp(view.before_at),
        to,
        format_timestamp(view.after_at)
    );
    if view.diff.is_empty() {
        out.push_str("\nAucune différence constatée.\n");
        return out;
    }
    for f in &view.diff.added {
        out.push_str(&format!(
            "  + ajouté    {} {} = {}\n",
            f.entity.0,
            f.attribute.0,
            format_value(&f.value)
        ));
    }
    for f in &view.diff.removed {
        out.push_str(&format!(
            "  - retiré    {} {} (valait {})\n",
            f.entity.0,
            f.attribute.0,
            format_value(&f.value)
        ));
    }
    for c in &view.diff.changed {
        out.push_str(&format!(
            "  ~ modifié   {} {} : {} → {}\n",
            c.entity.0,
            c.attribute.0,
            format_value(&c.before),
            format_value(&c.after)
        ));
    }
    out.push_str(&format!(
        "\n{} ajout(s), {} retrait(s), {} modification(s).\n",
        view.diff.added.len(),
        view.diff.removed.len(),
        view.diff.changed.len()
    ));
    out
}

/// Sortie de `constat history`, dans l'esprit exact du §10.1.
pub fn render_history(entity: &str, attr: &str, h: &History) -> String {
    if h.changes.is_empty() {
        return format!("Aucune observation de {attr} sur {entity} dans le magasin.");
    }
    let mut out = String::new();
    for c in &h.changes {
        match &c.before {
            None => out.push_str(&format!(
                "{}   première observation : {}\n",
                format_timestamp(c.at),
                format_value(&c.after)
            )),
            Some(b) => out.push_str(&format!(
                "{}   {:<5} → {}\n",
                format_timestamp(c.at),
                format_value(b),
                format_value(&c.after)
            )),
        }
        out.push_str(&format!(
            "                   preuve : blob {}  {}\n",
            short_hash(&c.evidence),
            c.asset.0
        ));
    }
    if let Some(cov) = &h.coverage {
        out.push('\n');
        out.push_str(&render_coverage(cov));
    }
    out
}

/// Empreinte de preuve, en tenant compte du constat d'absence
/// ([`NO_EVIDENCE`] : il n'existe aucun blob à citer).
pub fn evidence_label(h: &BlobHash) -> String {
    if *h == NO_EVIDENCE {
        "(constat d'absence — aucun blob)".to_string()
    } else {
        format!("blob {}", short_hash(h))
    }
}

/// Sortie de `constat check`.
pub fn render_check(results: &[Evaluation], explain: bool) -> String {
    let mut out = String::new();
    let (mut pass, mut fail, mut undet) = (0usize, 0usize, 0usize);
    for eval in results {
        match eval.verdict {
            Verdict::Pass => pass += 1,
            Verdict::Fail => fail += 1,
            Verdict::Undetermined => undet += 1,
        }
        out.push_str(&format!(
            "[{:<12}] {} — {}\n",
            eval.verdict.label_fr(),
            eval.assertion.0,
            eval.title
        ));
        out.push_str(&format!(
            "               couverture {} — écart max {} — {} interruption(s)\n",
            format_ppm(eval.coverage.observed_ppm),
            format_duration(eval.coverage.max_gap),
            eval.coverage.gaps.len()
        ));
        if !eval.violations.is_empty() {
            out.push_str(&format!(
                "               {} violation(s)\n",
                eval.violations.len()
            ));
            if explain {
                for v in &eval.violations {
                    out.push_str(&format!(
                        "                 ✗ {}  {}\n",
                        v.asset.0, v.entity.0
                    ));
                    if !v.detail.is_empty() {
                        out.push_str(&format!("                   {}\n", v.detail));
                    }
                    out.push_str(&format!(
                        "                   observé : {} — attendu : {}\n",
                        format_value(&v.observed),
                        format_value(&v.expected)
                    ));
                    out.push_str(&format!(
                        "                   première constatation : {} — dernière : {}\n",
                        format_timestamp(v.first_seen),
                        format_timestamp(v.last_seen)
                    ));
                    out.push_str(&format!(
                        "                   preuve : {}\n",
                        evidence_label(&v.evidence)
                    ));
                }
            }
        }
        if !eval.applied_exceptions.is_empty() {
            // Une exception neutralise, mais reste tracée — jamais passée
            // sous silence (§5.2).
            out.push_str(&format!(
                "               {} exception(s) appliquée(s)\n",
                eval.applied_exceptions.len()
            ));
            if explain {
                for ae in &eval.applied_exceptions {
                    out.push_str(&format!(
                        "                 ⚠ {} — {} (approuvée par {}, expire le {})\n",
                        ae.neutralized.entity.0,
                        ae.exception.reason,
                        ae.exception.approved_by,
                        ae.exception.expires
                    ));
                }
            }
        }
        if explain && eval.verdict == Verdict::Undetermined {
            out.push_str("               couverture insuffisante pour se prononcer (§5.3)\n");
        }
    }
    let total = results.len();
    out.push_str(&format!(
        "\n{total} assertion(s) : {pass} conforme(s), {fail} non conforme(s), {undet} indéterminée(s).\n"
    ));
    out
}

/// Sortie de `constat timeline`.
pub fn render_timeline(assertion: &Assertion, segments: &[TimelineSegment]) -> String {
    let mut out = format!(
        "Chronologie de {} — {}\n\n",
        assertion.id.0, assertion.title
    );
    if segments.is_empty() {
        out.push_str("Aucune observation sur la période : verdict indéterminé partout.\n");
        return out;
    }
    for s in segments {
        let mut line = format!(
            "  {} → {}   {}",
            format_timestamp(s.from),
            format_timestamp(s.to),
            s.verdict.label_fr()
        );
        if s.violations > 0 {
            line.push_str(&format!("  ({} violation(s))", s.violations));
        }
        line.push('\n');
        out.push_str(&line);
    }
    out
}

/// En-tête d'une période pour les sorties qui en affichent une.
pub fn period_header(p: constat_time::Period) -> String {
    format!("Période : {}", format_period(p))
}
