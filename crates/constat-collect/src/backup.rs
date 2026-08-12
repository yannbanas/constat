//! Collecteur `backup.proof` : preuve de sauvegarde — **priorité maximale
//! (§7.3)**. « Dernière sauvegarde réussie par périmètre, et date du dernier
//! test de restauration » : ce qu'on demande toujours et que personne ne sait
//! produire.
//!
//! ## Le format de statut, simple et documenté
//!
//! L'outil de sauvegarde (ou un crochet post-sauvegarde) écrit un fichier
//! texte, par défaut `/var/lib/constat/backup-status`, au format suivant :
//!
//! ```text
//! # statut de sauvegarde constat, v1
//! # une section par périmètre ; les clefs hors section vont dans "default"
//! [srv-fichiers]
//! last_success = 2026-08-11T02:14:00Z
//! last_restore_test = 2026-06-30T09:00:00Z
//! retention_days = 90
//!
//! [base-de-donnees]
//! last_success = 2026-08-11T03:00:00Z
//! ```
//!
//! - `last_success` : horodatage UTC (`AAAA-MM-JJTHH:MM:SSZ`, secondes
//!   optionnelles) de la dernière sauvegarde réussie du périmètre ;
//! - `last_restore_test` : horodatage UTC du dernier test de restauration ;
//! - `retention_days` : rétention effective, en jours.
//!
//! ## Faits produits (entité `backup:<périmètre>`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `backup.last_success` | `Int` — millisecondes UTC depuis l'époque, ou `Absent` |
//! | `backup.last_restore_test` | `Int` (ms UTC) ou `Absent` |
//! | `backup.retention_days` | `Int` ou `Absent` |
//!
//! **L'absence est LE fait important (§3.2)** : une section sans
//! `last_restore_test` produit `Value::Absent` — c'est exactement ce que
//! l'assertion `Fresher` doit voir échouer. Un horodatage illisible est
//! remonté tel quel en `Text` : l'évaluation le traitera comme non conforme
//! plutôt que de l'inventer.

use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::BTreeMap;

/// Chemin par défaut du fichier de statut.
pub const BACKUP_STATUS_PATH: &str = "/var/lib/constat/backup-status";

/// Périmètre implicite pour les clefs hors section.
pub const DEFAULT_SCOPE: &str = "default";

/// Clefs suivies : un fait est TOUJOURS produit par périmètre, `Absent` compris.
const TRACKED_KEYS: &[&str] = &["last_success", "last_restore_test", "retention_days"];

// ---------------------------------------------------------------------------
// Horodatage : parse maison (aucune dépendance), UTC uniquement
// ---------------------------------------------------------------------------

/// Jours écoulés depuis l'époque Unix pour une date civile (algorithme de
/// Howard Hinnant, valide sur tout le calendrier grégorien proleptique).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Analyse un horodatage `AAAA-MM-JJTHH:MM[:SS][Z]` (UTC ; l'espace est
/// accepté à la place du `T` ; les fractions de seconde sont ignorées).
/// Retourne les millisecondes UTC depuis l'époque Unix, ou `None` si la
/// forme ou les bornes sont invalides. Ne panique jamais.
pub fn parse_utc_timestamp_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (date, time) = match s.split_once(['T', 't', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    let mut date_parts = date.split('-');
    let y: i64 = date_parts.next()?.parse().ok()?;
    let m: i64 = date_parts.next()?.parse().ok()?;
    let d: i64 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    if !(1..=9999).contains(&y) || !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
        return None;
    }
    let (hh, mm, ss) = match time {
        None => (0, 0, 0),
        Some(t) => {
            let mut it = t.split(':');
            let hh: i64 = it.next()?.parse().ok()?;
            let mm: i64 = it.next()?.parse().ok()?;
            let ss: i64 = match it.next() {
                None => 0,
                // fraction de seconde ignorée (précision milliseconde du modèle : §15)
                Some(sec) => sec.split(['.', ',']).next()?.parse().ok()?,
            };
            if it.next().is_some() {
                return None;
            }
            (hh, mm, ss)
        }
    };
    if !(0..24).contains(&hh) || !(0..60).contains(&mm) || !(0..60).contains(&ss) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    Some((days * 86_400 + hh * 3_600 + mm * 60 + ss) * 1_000)
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/// Extracteur pur : texte du fichier de statut (déjà expurgé) → faits.
/// Lignes malformées ignorées, jamais de panique.
pub fn extract_backup_facts(text: &str) -> Vec<Fact> {
    // périmètre → (clef → valeur brute) ; BTreeMap : ordre canonique (§15)
    let mut scopes: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = DEFAULT_SCOPE.to_string();
    let mut current_seen = false;

    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            if let Some(name) = rest.strip_suffix(']') {
                let name = name.trim();
                current = if name.is_empty() {
                    DEFAULT_SCOPE.to_string()
                } else {
                    name.to_string()
                };
                scopes.entry(current.clone()).or_default();
                current_seen = true;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if !current_seen {
            scopes.entry(current.clone()).or_default();
            current_seen = true;
        }
        scopes
            .entry(current.clone())
            .or_default()
            .entry(key)
            .or_insert(value); // première occurrence gagnante
    }

    let mut facts: Vec<Fact> = Vec::new();
    for (scope, keys) in &scopes {
        let entity = EntityId(format!("backup:{scope}"));
        for tracked in TRACKED_KEYS {
            let value = match keys.get(*tracked) {
                None => Value::Absent,
                Some(raw) if raw.is_empty() => Value::Absent,
                Some(raw) => {
                    if *tracked == "retention_days" {
                        match raw.parse::<i64>() {
                            Ok(n) => Value::Int(n),
                            Err(_) => Value::Text(raw.clone()),
                        }
                    } else {
                        match parse_utc_timestamp_ms(raw) {
                            Some(ms) => Value::Int(ms),
                            // illisible : remonté tel quel, jamais inventé
                            None => Value::Text(raw.clone()),
                        }
                    }
                }
            };
            facts.push(Fact {
                entity: entity.clone(),
                attribute: Attribute(format!("backup.{tracked}")),
                value,
            });
        }
    }
    facts.sort();
    facts
}

/// Collecteur `backup.proof`.
#[derive(Debug, Clone)]
pub struct BackupProofCollector {
    /// Chemin du fichier de statut (paramétrable pour les tests).
    pub path: std::path::PathBuf,
}

impl Default for BackupProofCollector {
    fn default() -> Self {
        Self {
            path: std::path::PathBuf::from(BACKUP_STATUS_PATH),
        }
    }
}

impl Collector for BackupProofCollector {
    fn id(&self) -> CollectorId {
        CollectorId("backup.proof".to_string())
    }

    #[cfg(unix)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let bytes = std::fs::read(&self.path)
            .map_err(|e| CollectError::Io(format!("{} : {e}", self.path.display())))?;
        Ok(RawCapture(bytes))
    }

    #[cfg(not(unix))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "backup.proof : collecteur Unix, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_backup_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(facts: &'a [Fact], entity: &str, attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.entity.0 == entity && f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {entity} {attr}"))
            .value
    }

    #[test]
    fn horodatages_utc() {
        assert_eq!(parse_utc_timestamp_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc_timestamp_ms("1970-01-02"), Some(86_400_000));
        assert_eq!(
            parse_utc_timestamp_ms("2026-08-11T02:14:00Z"),
            Some(1_786_414_440_000)
        );
        assert_eq!(parse_utc_timestamp_ms("2026-02-30"), None);
        assert_eq!(
            parse_utc_timestamp_ms("2024-02-29"),
            Some(1_709_164_800_000)
        );
        assert_eq!(parse_utc_timestamp_ms("n'importe quoi"), None);
        assert_eq!(parse_utc_timestamp_ms("2026-13-01"), None);
        assert_eq!(parse_utc_timestamp_ms("2026-01-01T25:00"), None);
    }

    #[test]
    fn absence_de_test_de_restauration_est_un_fait() {
        let texte = "[donnees]\nlast_success = 2026-08-11T02:14:00Z\n";
        let facts = extract_backup_facts(texte);
        assert_eq!(
            value(&facts, "backup:donnees", "backup.last_restore_test"),
            &Value::Absent
        );
        assert_eq!(
            value(&facts, "backup:donnees", "backup.last_success"),
            &Value::Int(1_786_414_440_000)
        );
    }

    #[test]
    fn perimetre_par_defaut() {
        let facts = extract_backup_facts("last_success = 2026-08-11T02:14:00Z\n");
        assert_eq!(
            value(&facts, "backup:default", "backup.last_success"),
            &Value::Int(1_786_414_440_000)
        );
    }

    #[test]
    fn horodatage_illisible_remonte_en_texte() {
        let facts = extract_backup_facts("last_success = hier soir\n");
        assert_eq!(
            value(&facts, "backup:default", "backup.last_success"),
            &Value::Text("hier soir".to_string())
        );
    }

    #[test]
    fn plusieurs_perimetres() {
        let texte = "[a]\nretention_days = 90\n[b]\nretention_days = 30\n";
        let facts = extract_backup_facts(texte);
        assert_eq!(
            value(&facts, "backup:a", "backup.retention_days"),
            &Value::Int(90)
        );
        assert_eq!(
            value(&facts, "backup:b", "backup.retention_days"),
            &Value::Int(30)
        );
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_backup_facts("[\n]]]\n=\n= =\n[x]\nlast_success==\u{0}=");
    }
}
