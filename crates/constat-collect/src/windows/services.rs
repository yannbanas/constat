//! Collecteur `windows.services` : les services système — mode de démarrage,
//! compte de service, chemin de l'exécutable (§7.3, comptes de service).
//!
//! Source (LECTURE SEULE) : le registre
//! `HKLM\SYSTEM\CurrentControlSet\Services`, lu via `advapi32` (`RegOpenKeyEx`,
//! `RegEnumKeyEx`, `RegQueryValueEx`, accès `KEY_READ`). Aucune commande, aucun
//! SCM démarré. Seules les sous-clefs portant une valeur `Start` (les vrais
//! services et pilotes) sont retenues.
//!
//! **Expurgation (§7.2)** : `image_path` peut contenir des arguments avec un
//! `--password=…` ou un jeton ; il passe par la liste de refus de
//! [`crate::redact`] AVANT émission, dans la capture comme dans les faits.
//!
//! ## La capture, format INI normalisé et trié
//!
//! ```text
//! [Dhcp]
//! start = 2
//! object_name = NT Authority\LocalService
//! image_path = C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted
//! ```
//!
//! ## Faits produits (entité `service:<nom>`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `service.start_mode` | `Text` — `boot`/`system`/`auto`/`manual`/`disabled` (ou `inconnu(N)`) |
//! | `service.account` | `Text` (compte `ObjectName`) ou `Absent` (défaut `LocalSystem`) |
//! | `service.image_path` | `Text` **expurgé** ou `Absent` |

use crate::windows;
use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::BTreeSet;

/// Identifiant du collecteur.
pub const COLLECTOR_ID: &str = "windows.services";

/// Traduit la valeur `Start` du registre en mode de démarrage lisible.
/// (0 = démarrage noyau, …, 4 = désactivé — table stable de Windows.)
fn start_mode(raw: &str) -> String {
    match raw.trim() {
        "0" => "boot".to_string(),
        "1" => "system".to_string(),
        "2" => "auto".to_string(),
        "3" => "manual".to_string(),
        "4" => "disabled".to_string(),
        other => format!("inconnu({other})"),
    }
}

/// Extracteur **pur** : capture INI (déjà expurgée) → faits.
/// Jamais de panique.
pub fn extract_services_facts(capture_text: &str) -> Vec<Fact> {
    let sections = windows::parse_ini(capture_text);
    let mut facts: Vec<Fact> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for section in &sections {
        let name = section.header.trim();
        // en-tête réservé à d'éventuelles métadonnées : on ne prend que les
        // sections dont l'en-tête est un nom simple de service
        if name.is_empty() || name.contains(' ') {
            continue;
        }
        if !seen.insert(name.to_string()) {
            continue;
        }
        let entity = EntityId(format!("service:{name}"));

        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("service.start_mode".to_string()),
            value: match section.get("start") {
                Some(s) => Value::Text(start_mode(s)),
                None => Value::Absent,
            },
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("service.account".to_string()),
            value: match section.get("object_name") {
                Some(a) if !a.is_empty() => Value::Text(a.to_string()),
                _ => Value::Absent,
            },
        });
        facts.push(Fact {
            entity,
            attribute: Attribute("service.image_path".to_string()),
            value: match section.get("image_path") {
                Some(p) if !p.is_empty() => Value::Text(p.to_string()),
                _ => Value::Absent,
            },
        });
    }

    facts.sort();
    facts
}

/// Collecteur `windows.services`.
#[derive(Debug, Clone, Default)]
pub struct ServicesCollector;

impl Collector for ServicesCollector {
    fn id(&self) -> CollectorId {
        CollectorId(COLLECTOR_ID.to_string())
    }

    #[cfg(windows)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let text = windows::ffi::collect_services_capture().map_err(CollectError::Io)?;
        Ok(RawCapture(text.into_bytes()))
    }

    #[cfg(not(windows))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "windows.services : collecteur Windows, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_services_facts(&text))
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

    const CAPTURE: &str = "\
[Dhcp]
start = 2
object_name = NT Authority\\LocalService
image_path = C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted

[Fax]
start = 4
object_name = NT AUTHORITY\\NetworkService

[Ntfs]
start = 0
image_path = System32\\drivers\\Ntfs.sys
";

    #[test]
    fn modes_de_demarrage_traduits() {
        let facts = extract_services_facts(CAPTURE);
        assert_eq!(
            value(&facts, "service:Dhcp", "service.start_mode"),
            &Value::Text("auto".to_string())
        );
        assert_eq!(
            value(&facts, "service:Fax", "service.start_mode"),
            &Value::Text("disabled".to_string())
        );
        assert_eq!(
            value(&facts, "service:Ntfs", "service.start_mode"),
            &Value::Text("boot".to_string())
        );
    }

    #[test]
    fn compte_et_chemin() {
        let facts = extract_services_facts(CAPTURE);
        assert_eq!(
            value(&facts, "service:Dhcp", "service.account"),
            &Value::Text("NT Authority\\LocalService".to_string())
        );
        assert_eq!(
            value(&facts, "service:Dhcp", "service.image_path"),
            &Value::Text(
                "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted".to_string()
            )
        );
        // sans ObjectName : compte Absent (défaut LocalSystem)
        assert_eq!(
            value(&facts, "service:Ntfs", "service.account"),
            &Value::Absent
        );
    }

    #[test]
    fn image_path_expurgee_de_bout_en_bout() {
        // un argument sensible dans l'ImagePath ne doit pas fuir dans les faits
        let hostile = "[Louche]\nstart = 2\nimage_path = C:\\svc.exe --password=Sup3rSecret\n";
        let collector = ServicesCollector;
        let redacted = collector.redact(RawCapture(hostile.as_bytes().to_vec()));
        let facts = collector
            .extract(&redacted)
            .unwrap_or_else(|e| panic!("extraction en échec : {e}"));
        let debug = format!("{facts:?}");
        assert!(!debug.contains("Sup3rSecret"), "secret fuité : {debug}");
        assert!(debug.contains("C:\\\\svc.exe") || debug.contains("C:\\svc.exe"));
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_services_facts("");
        let _ = extract_services_facts("[a b]\nstart=2\n"); // en-tête avec espace ignoré
        let _ = extract_services_facts("[svc]\nstart=\u{0}\n");
    }
}
