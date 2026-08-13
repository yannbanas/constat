//! Rendu HTML autonome du dossier de preuve (§9 : HTML puis impression —
//! pas de bibliothèque PDF). Un seul fichier, aucun script, aucune ressource
//! externe : le dossier doit s'ouvrir dans dix ans sur n'importe quel poste.
//!
//! Le rendu inclut **toujours** :
//! - la section « Ce que ce dossier ne prouve pas » (§6.4), y compris la
//!   phrase de §6.2 sur la cohérence interne face à la non-répudiation ;
//! - la procédure de vérification par `constat-verify` (§10.3).

use crate::time_format::{format_duration, format_timestamp};
use crate::{CorrespondenceTable, EvidenceDossier, ExceptionNote, RequirementVerdict, Verdict};

/// Rend le dossier en HTML autonome et imprimable. Déterministe : le même
/// dossier produit exactement le même document.
pub fn render_html(dossier: &EvidenceDossier) -> String {
    let mut html = String::with_capacity(16 * 1024);
    let e = escape;

    let cover = &dossier.cover;
    html.push_str("<!DOCTYPE html>\n<html lang=\"fr\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str(&format!(
        "<title>Dossier de preuve — {} — {} → {}</title>\n",
        e(&cover.organization),
        format_timestamp(cover.period_start),
        format_timestamp(cover.period_end)
    ));
    html.push_str(STYLE);
    html.push_str("</head>\n<body>\n");

    // 1. Couverture --------------------------------------------------------
    html.push_str("<header>\n<h1>Dossier de preuve de conformité</h1>\n<table class=\"meta\">\n");
    push_row(&mut html, "Organisation", &e(&cover.organization));
    push_row(
        &mut html,
        "Période couverte",
        &format!(
            "du {} au {}",
            format_timestamp(cover.period_start),
            format_timestamp(cover.period_end)
        ),
    );
    push_row(&mut html, "Périmètre", &e(&cover.scope));
    if let Some(referential) = &cover.referential {
        push_row(&mut html, "Référentiel", &e(referential));
    }
    push_row(
        &mut html,
        "Généré le",
        &format_timestamp(cover.generated_at),
    );
    html.push_str("</table>\n</header>\n");

    // 2. Inventaire attendu / observé --------------------------------------
    html.push_str("<section>\n<h2>1. Inventaire : machines attendues et machines observées</h2>\n");
    html.push_str(&format!(
        "<p>{} machine(s) attendue(s), {} machine(s) observée(s). \
         <strong>L'écart entre les deux est un constat en soi</strong> : rien ne peut \
         être prouvé sur une machine jamais observée.</p>\n",
        dossier.inventory.expected.len(),
        dossier.inventory.observed.len()
    ));
    let missing = dossier.inventory.missing();
    let unexpected = dossier.inventory.unexpected();
    if missing.is_empty() && unexpected.is_empty() {
        html.push_str("<p class=\"ok\">Aucun écart : toutes les machines attendues ont été observées, et aucune machine hors inventaire n'est apparue.</p>\n");
    } else {
        if !missing.is_empty() {
            html.push_str("<p class=\"alert\">Machines attendues jamais observées (trou de preuve) :</p>\n<ul>\n");
            for asset in &missing {
                html.push_str(&format!("<li><code>{}</code></li>\n", e(&asset.0)));
            }
            html.push_str("</ul>\n");
        }
        if !unexpected.is_empty() {
            html.push_str(
                "<p class=\"alert\">Machines observées hors inventaire déclaré :</p>\n<ul>\n",
            );
            for asset in &unexpected {
                html.push_str(&format!("<li><code>{}</code></li>\n", e(&asset.0)));
            }
            html.push_str("</ul>\n");
        }
    }
    html.push_str("</section>\n");

    // 3. Exigences ----------------------------------------------------------
    html.push_str("<section>\n<h2>2. Exigences : verdicts et couverture</h2>\n");
    if dossier.requirements.is_empty() {
        html.push_str("<p>Aucune exigence évaluée.</p>\n");
    }
    for req in &dossier.requirements {
        let class = match req.verdict {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Undetermined => "undet",
        };
        html.push_str(&format!(
            "<article class=\"req\">\n<h3><code>{}</code> — {}</h3>\n",
            e(&req.assertion_id),
            e(&req.title)
        ));
        if let Some(reference) = &req.requirement_ref {
            html.push_str(&format!(
                "<p class=\"ref\">Exigence du référentiel : {}</p>\n",
                e(reference)
            ));
        }
        html.push_str(&format!(
            "<p>Verdict : <strong class=\"{class}\">{}</strong> — couverture {}, \
             écart maximal entre deux collectes : {}, {} interruption(s) déclarée(s).</p>\n",
            req.verdict.label(),
            permille(req.coverage.observed_permille),
            format_duration(req.coverage.max_gap),
            req.coverage.gap_count
        ));
        if !req.exceptions.is_empty() {
            html.push_str("<p>Exceptions documentées :</p>\n<ul>\n");
            for exception in &req.exceptions {
                html.push_str(&render_exception(exception, dossier.cover.generated_at));
            }
            html.push_str("</ul>\n");
        }
        html.push_str("</article>\n");
    }
    html.push_str("</section>\n");

    // 3 bis. Table de correspondance par référentiel (optionnelle) ----------
    // Les sections suivantes sont renumérotées quand elle est présente : un
    // dossier sans référentiel rend exactement le même document qu'avant.
    let shift = usize::from(dossier.correspondence.is_some());
    if let Some(table) = &dossier.correspondence {
        render_correspondence(&mut html, table);
    }

    // 4. Interruptions -------------------------------------------------------
    html.push_str(&format!(
        "<section>\n<h2>{}. Interruptions de collecte, déclarées</h2>\n",
        3 + shift
    ));
    if dossier.outages.is_empty() {
        html.push_str("<p>Aucune interruption de collecte sur la période.</p>\n");
    } else {
        html.push_str(
            "<p>Les interruptions ci-dessous sont déclarées explicitement : un trou \
             non déclaré serait indistinguable d'un effacement.</p>\n\
             <table>\n<tr><th>Machine</th><th>Du</th><th>Au</th><th>Motif</th></tr>\n",
        );
        for outage in &dossier.outages {
            html.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                e(&outage.asset.0),
                format_timestamp(outage.from),
                format_timestamp(outage.to),
                e(&outage.reason)
            ));
        }
        html.push_str("</table>\n");
    }
    html.push_str("</section>\n");

    // 5. Annexe : artefacts ---------------------------------------------------
    html.push_str(&format!(
        "<section>\n<h2>{}. Annexe : artefacts bruts et empreintes</h2>\n",
        4 + shift
    ));
    if dossier.artifacts.is_empty() {
        html.push_str("<p>Aucun artefact référencé.</p>\n");
    } else {
        html.push_str(
            "<table>\n<tr><th>Machine</th><th>Collecteur</th><th>Collecté le</th>\
             <th>Empreinte BLAKE3 du blob</th></tr>\n",
        );
        for artifact in &dossier.artifacts {
            html.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td>\
                 <td><code class=\"hash\">{}</code></td></tr>\n",
                e(&artifact.asset.0),
                e(&artifact.collector),
                format_timestamp(artifact.collected_at),
                artifact.blob.to_hex()
            ));
        }
        html.push_str("</table>\n");
    }
    html.push_str("</section>\n");

    // 6. Bloc de preuve --------------------------------------------------------
    let proof = &dossier.proof;
    html.push_str(&format!(
        "<section>\n<h2>{}. Preuve et procédure de vérification</h2>\n<table class=\"meta\">\n",
        5 + shift
    ));
    push_row(
        &mut html,
        "Racine de Merkle",
        &format!("<code class=\"hash\">{}</code>", proof.merkle_root.to_hex()),
    );
    push_row(
        &mut html,
        "Signature de la racine (Ed25519)",
        &format!("<code class=\"hash\">{}</code>", hex(&proof.root_signature)),
    );
    push_row(
        &mut html,
        "Clé publique du journal",
        &format!("<code class=\"hash\">{}</code>", hex(&proof.public_key)),
    );
    push_row(
        &mut html,
        "Entrées du journal",
        &proof.entry_count.to_string(),
    );
    match &proof.timestamp_token {
        Some(token) => push_row(
            &mut html,
            "Horodatage qualifié RFC 3161",
            &format!("jeton présent ({} octets, joint à l'export)", token.len()),
        ),
        None => push_row(
            &mut html,
            "Horodatage qualifié RFC 3161",
            "<strong>absent</strong> — voir la section « Ce que ce dossier ne prouve pas »",
        ),
    }
    html.push_str("</table>\n");

    html.push_str(
        "<h3>Vérifier ce dossier sans Constat</h3>\n\
         <p>La vérification ne demande aucune confiance envers l'outil qui a produit \
         ce dossier (§10.3). Procédure :</p>\n<ol>\n\
         <li>Obtenez l'export du journal : un répertoire contenant <code>pubkey.bin</code>, \
         les entrées <code>0.cbor</code>…<code>N.cbor</code>, <code>snapshots/</code> et \
         <code>blobs/</code>.</li>\n\
         <li>Exécutez <code>constat-verify &lt;répertoire-export&gt;</code>. Le binaire \
         recalcule chaque empreinte BLAKE3, vérifie le chaînage de la genèse à la racine, \
         chaque signature Ed25519 et la correspondance de chaque artefact avec son \
         empreinte.</li>\n\
         <li>Comparez la racine affichée avec celle de ce dossier (ci-dessus), et la clé \
         publique avec celle communiquée par un canal indépendant.</li>\n\
         <li>Si un jeton RFC 3161 est joint, vérifiez-le auprès du prestataire ou avec \
         <code>openssl ts -verify</code> : il prouve que la racine existait à la date \
         d'horodatage.</li>\n</ol>\n\
         <p>L'algorithme complet est documenté publiquement dans \
         <code>crates/constat-verify/FORMAT.md</code>, assez simplement pour être \
         réimplémenté en une centaine de lignes par un auditeur méfiant.</p>\n</section>\n",
    );

    // 7. Ce que ce dossier ne prouve pas — TOUJOURS présent (§6.4) -------------
    html.push_str(&format!(
        "<section class=\"limits\">\n<h2>{}. Ce que ce dossier ne prouve pas</h2>\n",
        6 + shift
    ));
    html.push_str(
        "\
         <p>Un outil de preuve qui surestime ses garanties est pire qu'inutile. \
         Les limites suivantes font partie du dossier :</p>\n<ul>\n\
         <li><strong>Sans ancrage externe, le journal prouve la cohérence interne, pas \
         la non-répudiation</strong> : celui qui contrôle le magasin et la clé de \
         signature peut tronquer la fin du journal ou repartir de zéro. La parade est \
         la comparaison de la racine avec un ancrage hors du système : racine envoyée \
         au RSSI, jeton d'horodatage RFC 3161 (§6.2, §6.3).</li>\n\
         <li>Un <strong>agent compromis</strong> peut mentir sur l'état de sa machine : \
         un agent est une source, pas un oracle. Le journal prouve ce qui a été \
         enregistré, pas ce qui était vrai.</li>\n\
         <li>Rien n'est prouvé sur une machine où l'agent n'a <strong>jamais été \
         installé</strong> — d'où l'inventaire de la section 1 : l'écart entre attendu \
         et observé est lui-même un constat.</li>\n\
         <li>Ce dossier ne remplace pas une <strong>supervision temps réel</strong> : \
         la granularité est celle de la collecte, et les intervalles entre deux \
         observations sont des inférences déclarées comme telles, jamais des \
         certitudes.</li>\n</ul>\n</section>\n",
    );

    html.push_str("<footer><p>Dossier généré par Constat. La preuve est vérifiable sans Constat.</p></footer>\n");
    html.push_str("</body>\n</html>\n");
    html
}

/// Rend la table de correspondance (§10.2.3) : par exigence du référentiel,
/// les assertions qui la couvrent avec leur verdict et leur couverture, et le
/// verdict agrégé. Une exigence sans assertion mappée est déclarée **non
/// couverte** — jamais passée sous silence. Les assertions évaluées
/// qu'aucune exigence ne référence sont listées en annexe.
fn render_correspondence(html: &mut String, table: &CorrespondenceTable) {
    let e = escape;
    html.push_str(&format!(
        "<section>\n<h2>3. Table de correspondance — {} {} (<code>{}</code>)</h2>\n",
        e(&table.referential_title),
        e(&table.referential_version),
        e(&table.referential_id)
    ));
    html.push_str(
        "<p>Par exigence du référentiel : les assertions qui la couvrent, leur verdict, \
         et le verdict agrégé de l'exigence. <strong>Une exigence qu'aucune assertion \
         ne couvre est déclarée non couverte</strong> : rien ne peut être affirmé à \
         son sujet.</p>\n",
    );

    if !table.warnings.is_empty() {
        html.push_str(
            "<p class=\"alert\">Avertissements à la construction de la table :</p>\n<ul>\n",
        );
        for warning in &table.warnings {
            html.push_str(&format!("<li class=\"alert\">{}</li>\n", e(warning)));
        }
        html.push_str("</ul>\n");
    }

    for req in &table.requirements {
        let verdict = req.verdict();
        let class = match verdict {
            RequirementVerdict::Pass => "pass",
            RequirementVerdict::Fail => "fail",
            RequirementVerdict::Undetermined | RequirementVerdict::NotCovered => "undet",
        };
        html.push_str(&format!(
            "<article class=\"req\">\n<h3><code>{}</code> — {}</h3>\n\
             <p>Verdict agrégé : <strong class=\"{class}\">{}</strong></p>\n",
            e(&req.id),
            e(&req.title),
            verdict.label()
        ));
        if req.assertions.is_empty() {
            html.push_str(
                "<p class=\"alert\">Exigence non couverte : aucune assertion ne lui est \
                 rattachée — ce dossier ne prouve rien à son sujet.</p>\n",
            );
        } else {
            html.push_str("<ul>\n");
            for a in &req.assertions {
                html.push_str(&render_outcome(a));
            }
            html.push_str("</ul>\n");
        }
        html.push_str("</article>\n");
    }

    html.push_str("<h3>Annexe : assertions évaluées non rattachées au référentiel</h3>\n");
    if table.unmapped_assertions.is_empty() {
        html.push_str("<p>Aucune : toutes les assertions évaluées couvrent une exigence.</p>\n");
    } else {
        html.push_str("<ul>\n");
        for a in &table.unmapped_assertions {
            html.push_str(&render_outcome(a));
        }
        html.push_str("</ul>\n");
    }
    html.push_str("</section>\n");
}

/// Une assertion dans la table : identifiant, titre, verdict, couverture.
fn render_outcome(outcome: &crate::AssertionOutcome) -> String {
    let class = match outcome.verdict {
        Verdict::Pass => "pass",
        Verdict::Fail => "fail",
        Verdict::Undetermined => "undet",
    };
    format!(
        "<li><code>{}</code> — {} : <strong class=\"{class}\">{}</strong>, couverture {}</li>\n",
        escape(&outcome.assertion_id),
        escape(&outcome.title),
        outcome.verdict.label(),
        permille(outcome.coverage.observed_permille)
    )
}

/// Rend une exception, en signalant celles qui ont expiré à la date de
/// génération : une exception expirée n'excuse plus rien.
fn render_exception(exception: &ExceptionNote, generated_at: constat_model::Timestamp) -> String {
    let expired = if exception.is_expired(generated_at) {
        " <strong class=\"fail\">[EXPIRÉE — n'excuse plus la non-conformité]</strong>"
    } else {
        ""
    };
    format!(
        "<li><code>{}</code> — {} (approuvée par : {}, expire le {}){}</li>\n",
        escape(&exception.entity),
        escape(&exception.reason),
        escape(&exception.approved_by),
        format_timestamp(exception.expires),
        expired
    )
}

fn push_row(html: &mut String, label: &str, value: &str) {
    html.push_str(&format!("<tr><th>{label}</th><td>{value}</td></tr>\n"));
}

/// Pour-mille → pourcentage français : 992 → « 99,2 % ».
fn permille(p: u16) -> String {
    format!("{},{} %", p / 10, p % 10)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Échappement HTML minimal.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Feuille de style embarquée : sobre, lisible, imprimable en A4.
const STYLE: &str = "<style>\n\
:root { color-scheme: light; }\n\
body { font-family: Georgia, 'Times New Roman', serif; color: #1a1a1a; background: #fff;\n\
  max-width: 21cm; margin: 1.5cm auto; padding: 0 1cm; line-height: 1.45; }\n\
h1 { font-size: 1.6em; border-bottom: 3px double #1a1a1a; padding-bottom: .3em; }\n\
h2 { font-size: 1.2em; margin-top: 1.6em; border-bottom: 1px solid #999; padding-bottom: .2em; }\n\
h3 { font-size: 1em; margin-bottom: .2em; }\n\
table { border-collapse: collapse; width: 100%; margin: .6em 0; }\n\
th, td { border: 1px solid #bbb; padding: .3em .5em; text-align: left;\n\
  vertical-align: top; font-size: .92em; }\n\
table.meta th { width: 30%; background: #f4f4f4; font-weight: normal; }\n\
code { font-family: 'Courier New', monospace; font-size: .92em; }\n\
code.hash { word-break: break-all; }\n\
article.req { margin: 1em 0; padding: .5em .8em; border: 1px solid #ccc;\n\
  page-break-inside: avoid; }\n\
p.ref { color: #555; font-size: .9em; margin: .1em 0; }\n\
.pass { color: #1d6b2f; }\n\
.fail { color: #9c1a1a; }\n\
.undet { color: #8a6d00; }\n\
.ok { color: #1d6b2f; }\n\
.alert { color: #9c1a1a; }\n\
section.limits { border: 2px solid #1a1a1a; padding: .2em 1em .6em; margin-top: 2em;\n\
  page-break-inside: avoid; }\n\
footer { margin-top: 2em; font-size: .85em; color: #555; text-align: center; }\n\
@media print { body { margin: 0; max-width: none; } }\n\
</style>\n";
