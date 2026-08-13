//! Collecteur `windows.password_policy` : la politique de mots de passe locale
//! (§7.3, comptes et durcissement).
//!
//! Source (LECTURE SEULE) : l'API Win32 `NetUserModalsGet`, niveaux 0
//! (longueur/âges/historique) et 3 (verrouillage). Aucune commande, aucun
//! secret : uniquement des seuils numériques.
//!
//! ## La capture, en secondes brutes (la sémantique est portée par le parseur)
//!
//! ```text
//! [password_policy]
//! min_password_length = 8
//! min_password_age_seconds = 0
//! max_password_age_seconds = 3628800
//! password_history_length = 24
//! lockout_threshold = 5
//! lockout_duration_seconds = 1800
//! lockout_observation_seconds = 1800
//! ```
//!
//! Les durées sont émises **en secondes** telles que rendues par l'API ; c'est
//! l'extracteur pur qui convertit en jours/minutes, ce qui le rend testable.
//! La sentinelle `TIMEQ_FOREVER` (`4294967295`) signifie « n'expire jamais » :
//! `max_password_age_days` vaut alors `Absent`.
//!
//! ## Faits produits (entité `host:windows`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `policy.min_password_length` | `Int` |
//! | `policy.min_password_age_days` | `Int` |
//! | `policy.max_password_age_days` | `Int` ou `Absent` (n'expire jamais) |
//! | `policy.password_history_length` | `Int` |
//! | `policy.lockout_threshold` | `Int` (0 = pas de verrouillage) |
//! | `policy.lockout_duration_minutes` | `Int` |
//! | `policy.lockout_observation_minutes` | `Int` |

use crate::windows::{self, int_or_absent};
use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};

/// Identifiant du collecteur.
pub const COLLECTOR_ID: &str = "windows.password_policy";

/// Entité unique décrite par ce collecteur.
pub const ENTITY: &str = "host:windows";

/// Sentinelle Win32 `TIMEQ_FOREVER` : l'âge maximal « n'expire jamais ».
pub const TIMEQ_FOREVER: i64 = 4_294_967_295;

/// Extracteur **pur** : capture INI (déjà expurgée) → faits.
/// Jamais de panique.
pub fn extract_password_policy_facts(capture_text: &str) -> Vec<Fact> {
    let sections = windows::parse_ini(capture_text);
    let entity = EntityId(ENTITY.to_string());
    let mut facts: Vec<Fact> = Vec::new();

    let section = sections.iter().find(|s| s.header == "password_policy");
    let get = |k: &str| section.and_then(|s| s.get(k));
    let secs = |k: &str| get(k).and_then(|v| v.trim().parse::<i64>().ok());

    // longueur minimale et historique : valeurs directes
    facts.push(int_or_absent(
        &entity,
        "policy.min_password_length",
        get("min_password_length"),
    ));
    facts.push(int_or_absent(
        &entity,
        "policy.password_history_length",
        get("password_history_length"),
    ));
    facts.push(int_or_absent(
        &entity,
        "policy.lockout_threshold",
        get("lockout_threshold"),
    ));

    // âge minimal : secondes → jours
    facts.push(Fact {
        entity: entity.clone(),
        attribute: Attribute("policy.min_password_age_days".to_string()),
        value: match secs("min_password_age_seconds") {
            Some(s) => Value::Int(s / 86_400),
            None => Value::Absent,
        },
    });

    // âge maximal : secondes → jours, avec la sentinelle « n'expire jamais »
    facts.push(Fact {
        entity: entity.clone(),
        attribute: Attribute("policy.max_password_age_days".to_string()),
        value: match secs("max_password_age_seconds") {
            Some(s) if s == TIMEQ_FOREVER => Value::Absent,
            Some(s) => Value::Int(s / 86_400),
            None => Value::Absent,
        },
    });

    // durées de verrouillage : secondes → minutes
    facts.push(Fact {
        entity: entity.clone(),
        attribute: Attribute("policy.lockout_duration_minutes".to_string()),
        value: match secs("lockout_duration_seconds") {
            Some(s) => Value::Int(s / 60),
            None => Value::Absent,
        },
    });
    facts.push(Fact {
        entity,
        attribute: Attribute("policy.lockout_observation_minutes".to_string()),
        value: match secs("lockout_observation_seconds") {
            Some(s) => Value::Int(s / 60),
            None => Value::Absent,
        },
    });

    facts.sort();
    facts
}

/// Collecteur `windows.password_policy`.
#[derive(Debug, Clone, Default)]
pub struct PasswordPolicyCollector;

impl Collector for PasswordPolicyCollector {
    fn id(&self) -> CollectorId {
        CollectorId(COLLECTOR_ID.to_string())
    }

    #[cfg(windows)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let text = windows::ffi::collect_password_policy_capture().map_err(CollectError::Io)?;
        Ok(RawCapture(text.into_bytes()))
    }

    #[cfg(not(windows))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "windows.password_policy : collecteur Windows, plateforme non prise en charge"
                .to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_password_policy_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(facts: &'a [Fact], attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {attr}"))
            .value
    }

    #[test]
    fn conversions_jours_et_minutes() {
        let capture = "\
[password_policy]
min_password_length = 8
min_password_age_seconds = 86400
max_password_age_seconds = 3628800
password_history_length = 24
lockout_threshold = 5
lockout_duration_seconds = 1800
lockout_observation_seconds = 900
";
        let facts = extract_password_policy_facts(capture);
        assert_eq!(value(&facts, "policy.min_password_length"), &Value::Int(8));
        assert_eq!(
            value(&facts, "policy.min_password_age_days"),
            &Value::Int(1)
        );
        assert_eq!(
            value(&facts, "policy.max_password_age_days"),
            &Value::Int(42)
        );
        assert_eq!(
            value(&facts, "policy.password_history_length"),
            &Value::Int(24)
        );
        assert_eq!(value(&facts, "policy.lockout_threshold"), &Value::Int(5));
        assert_eq!(
            value(&facts, "policy.lockout_duration_minutes"),
            &Value::Int(30)
        );
        assert_eq!(
            value(&facts, "policy.lockout_observation_minutes"),
            &Value::Int(15)
        );
    }

    #[test]
    fn mot_de_passe_qui_nexpire_jamais_est_absent() {
        let capture =
            "[password_policy]\nmin_password_length = 0\nmax_password_age_seconds = 4294967295\n";
        let facts = extract_password_policy_facts(capture);
        assert_eq!(
            value(&facts, "policy.max_password_age_days"),
            &Value::Absent
        );
    }

    #[test]
    fn valeurs_manquantes_sont_absent() {
        let facts = extract_password_policy_facts("[password_policy]\n");
        assert_eq!(value(&facts, "policy.min_password_length"), &Value::Absent);
        assert_eq!(value(&facts, "policy.lockout_threshold"), &Value::Absent);
        assert_eq!(
            value(&facts, "policy.lockout_duration_minutes"),
            &Value::Absent
        );
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_password_policy_facts("");
        let _ =
            extract_password_policy_facts("[password_policy]\nmax_password_age_seconds = xxx\n");
        let _ = extract_password_policy_facts("\u{0}[password_policy\n=\n");
    }
}
