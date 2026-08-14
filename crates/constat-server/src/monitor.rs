//! `constat-server status` — la supervision du serveur, en lecture seule.
//!
//! Répond à la question de l'exploitant : « les agents poussent-ils
//! encore ? ». Par journal (donc par agent, voir [`crate::inventory`]) :
//! dernière entrée, âge, nombre d'entrées, racine. Deux seuils d'alerte :
//!
//! - `--max-age <durée>` : un journal dont la dernière entrée est plus
//!   vieille que le seuil est **en retard** — code de sortie 1, utilisable
//!   tel quel en check Nagios ou en cron ;
//! - `--expected <fichier>` : l'inventaire attendu (une clé publique hex
//!   par ligne, nom optionnel). Un journal attendu absent, ou un journal
//!   présent non attendu, est un **écart d'inventaire** — et l'écart est un
//!   constat (§10.2), pas un détail : code de sortie 1 aussi.
//!
//! # Pourquoi un binaire, pas un endpoint (§17)
//!
//! La supervision est une commande qu'on lance, **pas** un port qu'on
//! expose. Le serveur n'ouvre aucun port supplémentaire, n'ajoute aucun
//! endpoint HTTP : sa surface d'attaque reste la seule réception mTLS.
//! Le format `--format prometheus` écrit des métriques *textfile* sur la
//! sortie standard, à rediriger vers le répertoire du *textfile collector*
//! de node_exporter — c'est node_exporter qui expose, avec sa propre
//! politique, et le serveur Constat n'y gagne aucune surface.
//!
//! Comme dans `constat-agent status`, le calcul ([`compute`]) est séparé du
//! rendu ([`render_text`], [`render_prometheus`]) : le premier ne touche
//! que le magasin, l'horloge est un paramètre — tout se teste à date fixe.

use constat_model::{DurationMs, Timestamp};
use constat_store::{JournalId, MultiJournalStore, StoreError};

use crate::inventory::{self, JournalSummary};

/// Erreurs de la supervision (hors magasin) : analyse du seuil et du
/// fichier d'inventaire attendu.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum MonitorError {
    /// La durée fournie à `--max-age` ne correspond à aucune forme acceptée.
    #[error("durée invalide : « {0} »")]
    #[diagnostic(help("formes acceptées : 500ms, 90s, 30m (ou 30min), 6h, 7j (ou 7d)"))]
    Duration(String),
    /// Une durée nulle ne peut servir de seuil : tout serait en retard.
    #[error("seuil nul : « {0} »")]
    #[diagnostic(help("--max-age doit être strictement positif"))]
    Zero(String),
    /// Une ligne du fichier `--expected` n'est ni une clé hex, ni `default`.
    #[error("fichier --expected, ligne {line} : « {content} » n'est ni une clé publique Ed25519 en hexadécimal (64 caractères), ni le mot-clé « default »")]
    #[diagnostic(help(
        "format : une entrée par ligne — `<clé hex> [nom]` ou `default [nom]`, commentaires avec #"
    ))]
    Expected {
        /// Numéro de ligne (à partir de 1).
        line: usize,
        /// Début de la ligne fautive.
        content: String,
    },
}

/// Analyse le seuil `--max-age` : `500ms`, `90s`, `30m` (ou `30min`), `6h`,
/// `7j` (ou `7d`).
///
/// La grammaire est volontairement identique à celle de l'agent
/// (`constat-agent`, `schedule::parse_every`) et de la CLI — copie locale
/// assumée : le serveur est un binaire autonome, et la grammaire tient en
/// dix lignes.
pub fn parse_max_age(s: &str) -> Result<DurationMs, MonitorError> {
    let raw = s;
    let s = s.trim();
    let err = || MonitorError::Duration(raw.to_string());
    let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(err)?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| err())?;
    let ms = match unit.trim() {
        "ms" => n,
        "s" | "sec" => n.saturating_mul(1_000),
        "m" | "min" => n.saturating_mul(60_000),
        "h" => n.saturating_mul(3_600_000),
        "d" | "j" => n.saturating_mul(86_400_000),
        _ => return Err(err()),
    };
    if ms == 0 {
        return Err(MonitorError::Zero(raw.to_string()));
    }
    Ok(DurationMs(ms))
}

/// Ce qu'une ligne du fichier `--expected` désigne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedTarget {
    /// Le journal par défaut (agent local, ou magasin v0.1.0 migré) :
    /// mot-clé `default`.
    Default,
    /// Un journal nommé, désigné par la clé publique Ed25519 de son agent.
    Key(JournalId),
}

/// Une entrée de l'inventaire attendu : la cible, et un nom optionnel —
/// libre, purement humain — qui accompagne la clé dans les rendus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedEntry {
    /// Le journal attendu.
    pub target: ExpectedTarget,
    /// Nom lisible optionnel (le reste de la ligne après la clé).
    pub label: Option<String>,
}

/// Analyse le contenu du fichier `--expected` : une entrée par ligne —
/// `<clé hex 64 caractères> [nom]` ou `default [nom]` — lignes vides et
/// commentaires `#` ignorés.
pub fn parse_expected(content: &str) -> Result<Vec<ExpectedEntry>, MonitorError> {
    let mut entries = Vec::new();
    for (index, raw) in content.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (head, rest) = match line.split_once(char::is_whitespace) {
            Some((head, rest)) => (head, rest.trim()),
            None => (line, ""),
        };
        let label = if rest.is_empty() {
            None
        } else {
            Some(rest.to_string())
        };
        let target = if head.eq_ignore_ascii_case("default") {
            ExpectedTarget::Default
        } else {
            let mut key = [0u8; 32];
            match hex::decode_to_slice(head, &mut key) {
                Ok(()) => ExpectedTarget::Key(key),
                Err(_) => {
                    return Err(MonitorError::Expected {
                        line: index + 1,
                        content: head.chars().take(40).collect(),
                    })
                }
            }
        };
        entries.push(ExpectedEntry { target, label });
    }
    Ok(entries)
}

/// L'état supervisé d'un journal : son résumé d'inventaire, plus ce que la
/// supervision en déduit (âge, retard, attendu ou non).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalStatus {
    /// Le résumé calculé par [`inventory::inventory`].
    pub summary: JournalSummary,
    /// Âge de la dernière entrée à l'instant `now` — zéro si l'horloge a
    /// été recalée en arrière (pas d'« âge négatif »), `None` si vide.
    pub age: Option<DurationMs>,
    /// `--max-age` fourni et dépassé (ou journal sans entrée datée).
    pub stale: bool,
    /// `--expected` fourni et ce journal n'y figure pas : inattendu.
    pub unexpected: bool,
    /// Nom lisible venu du fichier `--expected`, s'il y en a un.
    pub label: Option<String>,
}

/// Le rapport de supervision complet — tout ce que les rendus affichent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorReport {
    /// L'instant du calcul (paramètre, jamais lu ici : testable à date fixe).
    pub now: Timestamp,
    /// Le seuil `--max-age`, s'il a été fourni.
    pub max_age: Option<DurationMs>,
    /// Un statut par journal du magasin, dans l'ordre de l'inventaire.
    pub journals: Vec<JournalStatus>,
    /// Entrées de `--expected` sans journal correspondant : les absents.
    pub missing: Vec<ExpectedEntry>,
    /// Taille du fichier du magasin, si l'appelant la connaît (un
    /// `MemoryStore` de test n'a pas de fichier).
    pub store_size: Option<u64>,
}

impl MonitorReport {
    /// Vrai si quelque chose mérite d'alerter : un journal en retard, un
    /// journal attendu absent, ou un journal inattendu. C'est ce qui décide
    /// du code de sortie 1 de `constat-server status`.
    pub fn alert(&self) -> bool {
        !self.missing.is_empty() || self.journals.iter().any(|j| j.stale || j.unexpected)
    }
}

/// Calcule le rapport : inventaire du magasin, âges à l'instant `now`,
/// confrontation à l'inventaire attendu. Lecture seule, aucune horloge lue.
pub fn compute(
    store: &dyn MultiJournalStore,
    now: Timestamp,
    max_age: Option<DurationMs>,
    expected: Option<&[ExpectedEntry]>,
    store_size: Option<u64>,
) -> Result<MonitorReport, StoreError> {
    let rows = inventory::inventory(store)?;

    let journals: Vec<JournalStatus> = rows
        .into_iter()
        .map(|summary| {
            let age = summary
                .last_at
                .map(|last| now.duration_since(last).unwrap_or(DurationMs::ZERO));
            let stale = match (max_age, age) {
                (Some(max), Some(age)) => age > max,
                (Some(_), None) => true, // un journal sans entrée datée est en retard par définition
                (None, _) => false,
            };
            let matched = expected.map(|entries| {
                entries
                    .iter()
                    .find(|e| match (&e.target, &summary.id) {
                        (ExpectedTarget::Default, None) => true,
                        (ExpectedTarget::Key(key), Some(id)) => key == id,
                        _ => false,
                    })
                    .cloned()
            });
            let (unexpected, label) = match matched {
                None => (false, None),      // pas de fichier : rien à confronter
                Some(None) => (true, None), // fichier fourni, journal absent du fichier
                Some(Some(entry)) => (false, entry.label), // attendu, avec son nom éventuel
            };
            JournalStatus {
                summary,
                age,
                stale,
                unexpected,
                label,
            }
        })
        .collect();

    let missing = match expected {
        None => Vec::new(),
        Some(entries) => entries
            .iter()
            .filter(|e| {
                !journals.iter().any(|j| match (&e.target, &j.summary.id) {
                    (ExpectedTarget::Default, None) => true,
                    (ExpectedTarget::Key(key), Some(id)) => key == id,
                    _ => false,
                })
            })
            .cloned()
            .collect(),
    };

    Ok(MonitorReport {
        now,
        max_age,
        journals,
        missing,
        store_size,
    })
}

/// Identité d'un journal pour l'affichage : clé hex abrégée, ou
/// `(journal par défaut)`.
fn journal_display(status: &JournalStatus) -> String {
    let base = match status.summary.id {
        Some(id) => {
            let hex = hex::encode(id);
            match hex.get(..16) {
                Some(head) => format!("{head}…"),
                None => hex,
            }
        }
        None => "(journal par défaut)".to_string(),
    };
    match &status.label {
        Some(label) => format!("{base} [{label}]"),
        None => base,
    }
}

/// Identité d'un journal pour les métriques : la clé hex **complète**
/// (une étiquette Prometheus doit être stable et non ambiguë), ou `default`.
fn journal_metric_id(summary: &JournalSummary) -> String {
    match summary.id {
        Some(id) => hex::encode(id),
        None => "default".to_string(),
    }
}

/// Durée lisible et approximative — c'est un âge, pas une preuve.
fn format_age(ms: u64) -> String {
    let secs = ms / 1_000;
    if secs < 60 {
        format!("{secs} s")
    } else if secs < 3_600 {
        format!("{} min", secs / 60)
    } else if secs < 48 * 3_600 {
        let h = secs / 3_600;
        let min = (secs % 3_600) / 60;
        if min == 0 {
            format!("{h} h")
        } else {
            format!("{h} h {min:02} min")
        }
    } else {
        let days = secs / 86_400;
        let h = (secs % 86_400) / 3_600;
        if h == 0 {
            format!("{days} j")
        } else {
            format!("{days} j {h} h")
        }
    }
}

/// Rend le rapport en texte : une ligne par journal, puis les écarts
/// d'inventaire, puis le verdict — lisible par un humain et par la sortie
/// d'un check cron (le code de sortie porte l'alerte, le texte l'explique).
pub fn render_text(report: &MonitorReport, store_path: &str) -> String {
    let mut out = match report.store_size {
        Some(size) => format!("Magasin : {store_path} ({size} octets)\n"),
        None => format!("Magasin : {store_path}\n"),
    };

    if report.journals.is_empty() {
        out.push_str("Aucun journal : le magasin est vide — aucun agent n'a encore poussé.\n");
    } else {
        out.push_str(&format!(
            "{:<40}  {:>8}  {:<24}  {:<12}  {}\n",
            "JOURNAL", "ENTRÉES", "DERNIÈRE ENTRÉE", "ÂGE", "ÉTAT"
        ));
        for status in &report.journals {
            let last = match status.summary.last_at {
                Some(at) => at
                    .to_rfc3339()
                    .unwrap_or_else(|_| format!("{} ms", at.as_unix_millis())),
                None => "—".to_string(),
            };
            let age = match status.age {
                Some(age) => format_age(age.0),
                None => "—".to_string(),
            };
            let mut etat = Vec::new();
            if status.stale {
                etat.push("RETARD");
            }
            if status.unexpected {
                etat.push("INATTENDU");
            }
            let etat = if etat.is_empty() {
                "ok".to_string()
            } else {
                etat.join(", ")
            };
            out.push_str(&format!(
                "{:<40}  {:>8}  {:<24}  {:<12}  {}\n",
                journal_display(status),
                status.summary.entry_count,
                last,
                age,
                etat
            ));
        }
    }

    for entry in &report.missing {
        let target = match &entry.target {
            ExpectedTarget::Default => "(journal par défaut)".to_string(),
            ExpectedTarget::Key(key) => {
                let hex = hex::encode(key);
                match hex.get(..16) {
                    Some(head) => format!("{head}…"),
                    None => hex,
                }
            }
        };
        let name = match &entry.label {
            Some(label) => format!(" [{label}]"),
            None => String::new(),
        };
        out.push_str(&format!("ATTENDU, ABSENT : {target}{name}\n"));
    }

    if report.alert() {
        let retards = report.journals.iter().filter(|j| j.stale).count();
        let inattendus = report.journals.iter().filter(|j| j.unexpected).count();
        out.push_str(&format!(
            "ALERTE : {retards} journal/journaux en retard, {} attendu(s) absent(s), \
             {inattendus} inattendu(s). L'écart d'inventaire est un constat (§10.2).\n",
            report.missing.len()
        ));
    } else if let Some(max) = report.max_age {
        out.push_str(&format!(
            "OK : aucun journal au-delà du seuil ({}).\n",
            format_age(max.0)
        ));
    }
    out
}

/// Rend le rapport au format d'exposition Prometheus (métriques
/// *textfile*), prêt pour le *textfile collector* de node_exporter :
///
/// ```text
/// constat-server status --format prometheus > /var/lib/node_exporter/textfile/constat.prom.tmp \
///   && mv /var/lib/node_exporter/textfile/constat.prom.tmp /var/lib/node_exporter/textfile/constat.prom
/// ```
///
/// Aucun port, aucun endpoint : c'est node_exporter qui expose (§17).
pub fn render_prometheus(report: &MonitorReport) -> String {
    let mut out = String::new();

    out.push_str("# HELP constat_agent_last_entry_timestamp_seconds Date de la dernière entrée du journal, en secondes depuis l'époque Unix.\n");
    out.push_str("# TYPE constat_agent_last_entry_timestamp_seconds gauge\n");
    for status in &report.journals {
        if let Some(last) = status.summary.last_at {
            out.push_str(&format!(
                "constat_agent_last_entry_timestamp_seconds{{journal=\"{}\"}} {:.3}\n",
                journal_metric_id(&status.summary),
                last.as_unix_millis() as f64 / 1_000.0
            ));
        }
    }

    out.push_str("# HELP constat_agent_entries_total Nombre d'entrées du journal.\n");
    out.push_str("# TYPE constat_agent_entries_total gauge\n");
    for status in &report.journals {
        out.push_str(&format!(
            "constat_agent_entries_total{{journal=\"{}\"}} {}\n",
            journal_metric_id(&status.summary),
            status.summary.entry_count
        ));
    }

    if report.max_age.is_some() {
        out.push_str("# HELP constat_agent_stale Journal en retard : 1 si la dernière entrée dépasse le seuil --max-age, 0 sinon.\n");
        out.push_str("# TYPE constat_agent_stale gauge\n");
        for status in &report.journals {
            out.push_str(&format!(
                "constat_agent_stale{{journal=\"{}\"}} {}\n",
                journal_metric_id(&status.summary),
                u8::from(status.stale)
            ));
        }
    }

    out.push_str("# HELP constat_expected_missing_total Journaux attendus (--expected) absents du magasin.\n");
    out.push_str("# TYPE constat_expected_missing_total gauge\n");
    out.push_str(&format!(
        "constat_expected_missing_total {}\n",
        report.missing.len()
    ));

    out.push_str("# HELP constat_unexpected_journals_total Journaux présents dans le magasin mais absents de --expected.\n");
    out.push_str("# TYPE constat_unexpected_journals_total gauge\n");
    out.push_str(&format!(
        "constat_unexpected_journals_total {}\n",
        report.journals.iter().filter(|j| j.unexpected).count()
    ));

    if let Some(size) = report.store_size {
        out.push_str(
            "# HELP constat_store_size_bytes Taille du fichier du magasin central, en octets.\n",
        );
        out.push_str("# TYPE constat_store_size_bytes gauge\n");
        out.push_str(&format!("constat_store_size_bytes {size}\n"));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use constat_store::{append_signed, MemoryStore, MultiJournalStore, Signer};

    /// Un magasin de test : le journal par défaut (1 entrée à t=1 000 ms)
    /// et deux journaux nommés (a : 2 entrées, dernière à t=2 001 ;
    /// b : 3 entrées, dernière à t=2 002). Retourne (magasin, clé a, clé b).
    fn magasin() -> (MemoryStore, JournalId, JournalId) {
        let mut store = MemoryStore::new();
        let historique = Signer::generate();
        append_signed(&mut store, &historique, vec![], Timestamp(1_000)).unwrap();

        let a = Signer::generate();
        let b = Signer::generate();
        for (signer, n) in [(&a, 2i64), (&b, 3i64)] {
            let journal = signer.verifying_key().to_bytes();
            for i in 0..n {
                let prev = store.last_entry_of(&journal).unwrap().map(|(h, _)| h);
                let entry = signer
                    .sign_entry(prev, vec![], Timestamp(2_000 + i))
                    .unwrap();
                store.append_entry_in(&journal, &entry).unwrap();
            }
        }
        (
            store,
            a.verifying_key().to_bytes(),
            b.verifying_key().to_bytes(),
        )
    }

    /// La clé du premier journal nommé de l'inventaire (ordre trié).
    fn premiere_cle(store: &MemoryStore) -> JournalId {
        store.journals().unwrap()[0]
    }

    #[test]
    fn seuil_analyse() {
        assert_eq!(parse_max_age("90s").unwrap().0, 90_000);
        assert_eq!(parse_max_age("30min").unwrap().0, 30 * 60_000);
        assert_eq!(parse_max_age("6h").unwrap().0, 6 * 3_600_000);
        assert_eq!(parse_max_age("7j").unwrap().0, 7 * 86_400_000);
        assert!(matches!(
            parse_max_age("six heures").unwrap_err(),
            MonitorError::Duration(_)
        ));
        assert!(matches!(
            parse_max_age("0h").unwrap_err(),
            MonitorError::Zero(_)
        ));
    }

    #[test]
    fn fichier_expected_analyse() {
        let cle = "aa".repeat(32);
        let contenu = format!(
            "# inventaire attendu\n\
             \n\
             {cle} srv-web-01  # le serveur web\n\
             default\n"
        );
        let entries = parse_expected(&contenu).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].target, ExpectedTarget::Key([0xaa; 32]));
        assert_eq!(entries[0].label.as_deref(), Some("srv-web-01"));
        assert_eq!(entries[1].target, ExpectedTarget::Default);
        assert_eq!(entries[1].label, None);
    }

    #[test]
    fn fichier_expected_ligne_invalide() {
        let err = parse_expected("pas-une-cle\n").unwrap_err();
        match err {
            MonitorError::Expected { line, content } => {
                assert_eq!(line, 1);
                assert_eq!(content, "pas-une-cle");
            }
            other => panic!("erreur inattendue : {other:?}"),
        }
    }

    #[test]
    fn sans_seuil_ni_attendus_rien_n_alerte() {
        let (store, _, _) = magasin();
        // 10 ans plus tard, sans --max-age : aucun retard possible.
        let report = compute(&store, Timestamp(315_360_000_000), None, None, None).unwrap();
        assert_eq!(report.journals.len(), 3);
        assert!(!report.alert());
        let texte = render_text(&report, "./test.redb");
        assert!(texte.contains("(journal par défaut)"));
        assert!(!texte.contains("ALERTE"));
        assert!(!texte.contains("RETARD"));
    }

    #[test]
    fn seuil_depasse_alerte_et_code_de_sortie() {
        let (store, _, _) = magasin();
        // Dernières entrées vers t=2s ; à t=1h, seuil 30 min : tout est en retard.
        let now = Timestamp(3_600_000);
        let max = parse_max_age("30min").unwrap();
        let report = compute(&store, now, Some(max), None, None).unwrap();
        assert!(report.alert());
        assert!(report.journals.iter().all(|j| j.stale));
        let texte = render_text(&report, "./test.redb");
        assert!(texte.contains("RETARD"));
        assert!(texte.contains("ALERTE"));

        // Seuil 2 h : personne n'est en retard, le rendu dit OK.
        let large = parse_max_age("2h").unwrap();
        let report = compute(&store, now, Some(large), None, None).unwrap();
        assert!(!report.alert());
        let texte = render_text(&report, "./test.redb");
        assert!(texte.contains("OK : aucun journal au-delà du seuil (2 h)"));
    }

    /// Un âge exactement égal au seuil n'est pas un retard (strictement
    /// supérieur), et une horloge recalée en arrière donne un âge nul.
    #[test]
    fn seuil_strict_et_age_jamais_negatif() {
        let (store, _, _) = magasin();
        // Dernière entrée la plus vieille : t=1 000 ms (journal par défaut).
        // now = 1 000 + seuil exactement : pas de retard.
        let max = DurationMs(60_000);
        let report = compute(&store, Timestamp(61_000), Some(max), None, None).unwrap();
        assert!(!report.journals[0].stale);

        // Horloge recalée avant les entrées : âges nuls, pas de panique.
        let report = compute(&store, Timestamp(0), Some(max), None, None).unwrap();
        assert!(report
            .journals
            .iter()
            .all(|j| j.age == Some(DurationMs::ZERO)));
        assert!(!report.alert());
    }

    #[test]
    fn ecarts_d_inventaire_absents_et_inattendus() {
        let (store, _, _) = magasin();
        let presente = premiere_cle(&store);
        let absente: JournalId = [0x42; 32];

        // Attendus : le journal par défaut, un journal présent (nommé), un absent.
        let expected = vec![
            ExpectedEntry {
                target: ExpectedTarget::Default,
                label: None,
            },
            ExpectedEntry {
                target: ExpectedTarget::Key(presente),
                label: Some("srv-01".to_string()),
            },
            ExpectedEntry {
                target: ExpectedTarget::Key(absente),
                label: Some("srv-fantome".to_string()),
            },
        ];
        let report = compute(&store, Timestamp(10_000), None, Some(&expected), None).unwrap();

        // L'absent est signalé, le second journal nommé est inattendu.
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.missing[0].target, ExpectedTarget::Key(absente));
        assert_eq!(
            report.journals.iter().filter(|j| j.unexpected).count(),
            1,
            "le journal nommé hors liste doit être inattendu"
        );
        assert!(report.alert());

        let texte = render_text(&report, "./test.redb");
        assert!(texte.contains("ATTENDU, ABSENT"));
        assert!(texte.contains("[srv-fantome]"));
        assert!(texte.contains("[srv-01]"));
        assert!(texte.contains("INATTENDU"));
        assert!(texte.contains("§10.2"));
    }

    #[test]
    fn inventaire_conforme_n_alerte_pas() {
        let (store, a, b) = magasin();
        let expected = vec![
            ExpectedEntry {
                target: ExpectedTarget::Default,
                label: None,
            },
            ExpectedEntry {
                target: ExpectedTarget::Key(a),
                label: None,
            },
            ExpectedEntry {
                target: ExpectedTarget::Key(b),
                label: None,
            },
        ];
        let report = compute(&store, Timestamp(10_000), None, Some(&expected), None).unwrap();
        assert!(report.missing.is_empty());
        assert!(report.journals.iter().all(|j| !j.unexpected));
        assert!(!report.alert());
    }

    #[test]
    fn format_prometheus() {
        let (store, _, _) = magasin();
        let cle = hex::encode(premiere_cle(&store));
        let max = parse_max_age("30min").unwrap();
        let report = compute(&store, Timestamp(3_600_000), Some(max), None, Some(4_096)).unwrap();
        let prom = render_prometheus(&report);

        // Dates en secondes, précision milliseconde, clé complète en étiquette.
        assert!(
            prom.contains("constat_agent_last_entry_timestamp_seconds{journal=\"default\"} 1.000")
        );
        assert!(prom.contains(&format!(
            "constat_agent_last_entry_timestamp_seconds{{journal=\"{cle}\"}} 2.00"
        )));
        assert!(prom.contains("constat_agent_entries_total{journal=\"default\"} 1"));
        assert!(prom.contains(&format!("constat_agent_entries_total{{journal=\"{cle}\"}}")));
        // Tout le monde est en retard à t=1 h avec un seuil de 30 min.
        assert!(prom.contains("constat_agent_stale{journal=\"default\"} 1"));
        assert!(prom.contains("constat_store_size_bytes 4096\n"));
        assert!(prom.contains("constat_expected_missing_total 0\n"));
        assert!(prom.contains("constat_unexpected_journals_total 0\n"));
        // Chaque métrique est annoncée (HELP + TYPE) : node_exporter est strict.
        for nom in [
            "constat_agent_last_entry_timestamp_seconds",
            "constat_agent_entries_total",
            "constat_agent_stale",
            "constat_expected_missing_total",
            "constat_unexpected_journals_total",
            "constat_store_size_bytes",
        ] {
            assert!(
                prom.contains(&format!("# HELP {nom} ")),
                "HELP manquant : {nom}"
            );
            assert!(
                prom.contains(&format!("# TYPE {nom} gauge")),
                "TYPE manquant : {nom}"
            );
        }
    }

    #[test]
    fn magasin_vide_dit_la_verite() {
        let store = MemoryStore::new();
        let report = compute(&store, Timestamp(0), None, None, None).unwrap();
        assert!(report.journals.is_empty());
        assert!(!report.alert());
        let texte = render_text(&report, "./vide.redb");
        assert!(texte.contains("le magasin est vide"));

        // Vide mais avec un inventaire attendu : les absents alertent.
        let expected = vec![ExpectedEntry {
            target: ExpectedTarget::Default,
            label: Some("agent-local".to_string()),
        }];
        let report = compute(&store, Timestamp(0), None, Some(&expected), None).unwrap();
        assert!(report.alert());
        assert_eq!(report.missing.len(), 1);
    }

    #[test]
    fn ages_lisibles() {
        assert_eq!(format_age(45_000), "45 s");
        assert_eq!(format_age(12 * 60_000), "12 min");
        assert_eq!(format_age(3 * 3_600_000 + 5 * 60_000), "3 h 05 min");
        assert_eq!(format_age(52 * 3_600_000), "2 j 4 h");
    }
}
