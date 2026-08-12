//! Collecteur `linux.systemd` : unités de service — quel service est activé,
//! sous quel compte il tourne, avec quelle ligne de commande (§7.3).
//!
//! ## La capture, deux sortes de sections
//!
//! - Une section `systemd:unit-files` au **format texte stable** de
//!   `systemctl list-unit-files --type=service` : un nom d'unité
//!   (`*.service`) puis son état d'activation, séparés par des espaces.
//!   L'en-tête (`UNIT FILE STATE …`) et le pied (`N unit files listed.`)
//!   sont ignorés — seules comptent les lignes dont le premier mot se
//!   termine par `.service`.
//! - Une section par fichier unit `.service`, nommée par son chemin
//!   (`/etc/systemd/system/sauvegarde.service`), contenant le fichier brut.
//!   Seules les directives de la section `[Service]` sont extraites :
//!   `User=` et `ExecStart=` (dernière occurrence non vide gagnante,
//!   sémantique systemd).
//!
//! **Expurgation (§7.2)** : les arguments d'`ExecStart=` (et tout le reste de
//! la capture) passent par la liste de refus de [`crate::redact`] — un
//! `--password=…`, `token=…` ou une clé collée dans un `Environment=` est
//! remplacé par un marqueur AVANT émission, dans la capture comme dans les
//! faits (les faits sont extraits de la capture déjà expurgée).
//!
//! ## Faits produits (entité `service:<nom>`, sans le suffixe `.service`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `service.enabled` | `Bool` — `true` pour `enabled`/`enabled-runtime`, `false` pour `disabled` ; `Text` pour les autres états (`static`, `masked`, `alias`, …) ; `Absent` si l'unité n'apparaît pas dans la liste |
//! | `service.user` | `Text` — directive `User=` du fichier unit ; `Absent` si le fichier est capturé sans `User=` (le service tourne alors sous root). Pas de fait sans fichier unit capturé |
//! | `service.exec_start` | `Text` — commande `ExecStart=` **déjà expurgée** ; `Absent` si le fichier est capturé sans `ExecStart=`. Pas de fait sans fichier unit capturé |
//!
//! ## Collecte réelle (`#[cfg(unix)]`)
//!
//! Aucune commande n'est exécutée. La collecte lit directement :
//!
//! - les fichiers `*.service` de `/usr/lib/systemd/system`,
//!   `/lib/systemd/system` et `/etc/systemd/system` (ce dernier prioritaire) ;
//! - l'état d'activation par le système de fichiers :
//!   `masked` = lien symbolique vers `/dev/null` dans `/etc/systemd/system`,
//!   `enabled` = lien dans un répertoire `/etc/systemd/system/*.wants/` ou
//!   `*.requires/`, `static` = fichier sans section `[Install]`,
//!   `disabled` sinon.

use crate::{capture, redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::BTreeMap;

/// Nom de la section « liste des unités » dans la capture combinée.
pub const SECTION_UNIT_FILES: &str = "systemd:unit-files";

/// Suffixe des unités de service.
pub const SERVICE_SUFFIX: &str = ".service";

/// Directives extraites d'un fichier unit (section `[Service]` uniquement).
#[derive(Debug, Default)]
struct UnitDirectives {
    user: Option<String>,
    exec_start: Option<String>,
}

/// Parse un fichier unit : ne retient que `User=` et `ExecStart=` de la
/// section `[Service]`. Sémantique systemd : dernière occurrence gagnante,
/// une valeur vide réinitialise la directive. Jamais de panique.
fn parse_unit_file(content: &str) -> UnitDirectives {
    let mut directives = UnitDirectives::default();
    let mut in_service = false;
    for line in content.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_service = line.eq_ignore_ascii_case("[Service]");
            continue;
        }
        if !in_service {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let slot = if key == "User" {
            &mut directives.user
        } else if key == "ExecStart" {
            &mut directives.exec_start
        } else {
            continue;
        };
        *slot = if value.is_empty() {
            None // `Directive=` vide : réinitialisation, sémantique systemd
        } else {
            Some(value.to_string())
        };
    }
    directives
}

/// Extrait le nom d'unité (`sauvegarde.service`) d'un nom de section
/// (`/etc/systemd/system/sauvegarde.service`).
fn unit_name_from_section(section_name: &str) -> Option<&str> {
    let base = section_name.rsplit('/').next()?;
    if base.ends_with(SERVICE_SUFFIX) && base.len() > SERVICE_SUFFIX.len() {
        Some(base)
    } else {
        None
    }
}

/// Traduit un état d'activation systemd en valeur : `Bool` quand la réponse
/// est binaire, `Text` sinon (`static`, `masked`, `alias`, `indirect`, …) —
/// on n'invente pas de booléen pour un état qui n'en est pas un.
fn enablement_value(state: &str) -> Value {
    match state {
        "enabled" | "enabled-runtime" => Value::Bool(true),
        "disabled" => Value::Bool(false),
        other => Value::Text(other.to_string()),
    }
}

/// Extracteur pur : capture combinée (déjà expurgée) → faits.
/// Lignes malformées ignorées, jamais de panique.
pub fn extract_systemd_facts(text: &str) -> Vec<Fact> {
    let sections = capture::split_sections(text);

    // 1. la liste des unités : nom → état d'activation
    let mut states: BTreeMap<String, String> = BTreeMap::new();
    if let Some(list) = capture::find_section(&sections, SECTION_UNIT_FILES) {
        for line in list.split('\n') {
            let mut words = line.split_whitespace();
            let (Some(unit), Some(state)) = (words.next(), words.next()) else {
                continue;
            };
            if unit.ends_with(SERVICE_SUFFIX) && unit.len() > SERVICE_SUFFIX.len() {
                states
                    .entry(unit.to_string())
                    .or_insert_with(|| state.to_string());
            }
        }
    }

    // 2. les fichiers unit capturés : nom → directives
    let mut units: BTreeMap<String, UnitDirectives> = BTreeMap::new();
    for (name, content) in &sections {
        let Some(unit) = unit_name_from_section(name) else {
            continue;
        };
        units
            .entry(unit.to_string())
            .or_insert_with(|| parse_unit_file(content));
    }

    // 3. les faits, sur l'union des deux sources
    let mut facts: Vec<Fact> = Vec::new();
    let mut all_units: Vec<&String> = states.keys().chain(units.keys()).collect();
    all_units.sort();
    all_units.dedup();
    for unit in all_units {
        let short = unit.strip_suffix(SERVICE_SUFFIX).unwrap_or(unit);
        let entity = EntityId(format!("service:{short}"));
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("service.enabled".to_string()),
            value: match states.get(unit) {
                Some(state) => enablement_value(state),
                None => Value::Absent,
            },
        });
        if let Some(directives) = units.get(unit) {
            facts.push(Fact {
                entity: entity.clone(),
                attribute: Attribute("service.user".to_string()),
                value: match &directives.user {
                    Some(user) => Value::Text(user.clone()),
                    None => Value::Absent,
                },
            });
            facts.push(Fact {
                entity,
                attribute: Attribute("service.exec_start".to_string()),
                value: match &directives.exec_start {
                    Some(exec) => Value::Text(exec.clone()),
                    None => Value::Absent,
                },
            });
        }
    }
    facts.sort();
    facts
}

/// Collecteur `linux.systemd`.
#[derive(Debug, Clone)]
pub struct SystemdCollector {
    /// Racine des fichiers systèmes (paramétrable pour les tests ; `/` en production).
    pub root: std::path::PathBuf,
}

impl Default for SystemdCollector {
    fn default() -> Self {
        Self {
            root: std::path::PathBuf::from("/"),
        }
    }
}

/// Répertoires d'unités lus, dans l'ordre ; le dernier (l'administrateur,
/// `/etc`) est prioritaire sur les fichiers livrés par les paquets.
#[cfg(unix)]
const UNIT_DIRS: &[&str] = &[
    "usr/lib/systemd/system",
    "lib/systemd/system",
    "etc/systemd/system",
];

#[cfg(unix)]
impl SystemdCollector {
    /// Inventorie les fichiers `*.service` : nom d'unité → chemin retenu.
    fn discover_units(&self) -> BTreeMap<String, std::path::PathBuf> {
        let mut units: BTreeMap<String, std::path::PathBuf> = BTreeMap::new();
        for dir in UNIT_DIRS {
            let Ok(entries) = std::fs::read_dir(self.root.join(dir)) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if name.ends_with(SERVICE_SUFFIX) && name.len() > SERVICE_SUFFIX.len() {
                    units.insert(name.to_string(), entry.path());
                }
            }
        }
        units
    }

    /// L'unité est-elle référencée par un lien dans un répertoire
    /// `*.wants/` ou `*.requires/` de `/etc/systemd/system` ?
    fn is_wanted(&self, unit: &str) -> bool {
        let Ok(entries) = std::fs::read_dir(self.root.join("etc/systemd/system")) else {
            return false;
        };
        for entry in entries.flatten() {
            let dir_name = entry.file_name();
            let Some(dir_name) = dir_name.to_str() else {
                continue;
            };
            if !(dir_name.ends_with(".wants") || dir_name.ends_with(".requires")) {
                continue;
            }
            if entry.path().join(unit).symlink_metadata().is_ok() {
                return true;
            }
        }
        false
    }

    /// État d'activation d'une unité, déduit du système de fichiers
    /// (voir la documentation du module).
    fn enablement_state(&self, unit: &str, content: &str) -> &'static str {
        let etc_path = self.root.join("etc/systemd/system").join(unit);
        if let Ok(target) = std::fs::read_link(&etc_path) {
            if target.as_os_str() == "/dev/null" {
                return "masked";
            }
        }
        if self.is_wanted(unit) {
            return "enabled";
        }
        let has_install = content
            .split('\n')
            .any(|l| l.trim().eq_ignore_ascii_case("[Install]"));
        if has_install {
            "disabled"
        } else {
            "static"
        }
    }
}

impl Collector for SystemdCollector {
    fn id(&self) -> CollectorId {
        CollectorId("linux.systemd".to_string())
    }

    /// Lit les répertoires d'unités et `/etc/systemd/system` (liens `*.wants/`,
    /// `*.requires/`, masquages vers `/dev/null`) — jamais de commande.
    #[cfg(unix)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let units = self.discover_units();
        if units.is_empty() {
            return Err(CollectError::Unavailable(
                "linux.systemd : aucun répertoire d'unités lisible".to_string(),
            ));
        }
        let mut list = String::new();
        let mut unit_sections: Vec<(String, String)> = Vec::new();
        for (unit, path) in &units {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            let state = self.enablement_state(unit, &content);
            list.push_str(&format!("{unit} {state}\n"));
            if !content.is_empty() {
                unit_sections.push((path.display().to_string(), content));
            }
        }
        let mut sections: Vec<(&str, &str)> = vec![(SECTION_UNIT_FILES, list.as_str())];
        sections.extend(unit_sections.iter().map(|(n, c)| (n.as_str(), c.as_str())));
        Ok(RawCapture(capture::join_sections(&sections).into_bytes()))
    }

    #[cfg(not(unix))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "linux.systemd : collecteur Linux, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_systemd_facts(&text))
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
    fn etats_d_activation_traduits() {
        let raw = capture::join_sections(&[(
            SECTION_UNIT_FILES,
            "UNIT FILE STATE PRESET\n\
             ssh.service enabled enabled\n\
             telemetrie.service disabled enabled\n\
             dbus.service static -\n\
             vieux.service masked enabled\n\
             4 unit files listed.\n",
        )]);
        let facts = extract_systemd_facts(&raw);
        assert_eq!(
            value(&facts, "service:ssh", "service.enabled"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "service:telemetrie", "service.enabled"),
            &Value::Bool(false)
        );
        assert_eq!(
            value(&facts, "service:dbus", "service.enabled"),
            &Value::Text("static".to_string())
        );
        assert_eq!(
            value(&facts, "service:vieux", "service.enabled"),
            &Value::Text("masked".to_string())
        );
        // l'en-tête et le pied de page ne créent pas d'entités fantômes
        assert!(!facts.iter().any(|f| f.entity.0 == "service:UNIT"));
        assert!(!facts.iter().any(|f| f.entity.0 == "service:4"));
    }

    #[test]
    fn directives_user_et_execstart() {
        let unit = "[Unit]\nDescription=App\n\n[Service]\nUser=svc-app\nExecStart=/usr/bin/app --port 8080\n\n[Install]\nWantedBy=multi-user.target\n";
        let raw = capture::join_sections(&[
            (SECTION_UNIT_FILES, "app.service enabled\n"),
            ("/etc/systemd/system/app.service", unit),
        ]);
        let facts = extract_systemd_facts(&raw);
        assert_eq!(
            value(&facts, "service:app", "service.user"),
            &Value::Text("svc-app".to_string())
        );
        assert_eq!(
            value(&facts, "service:app", "service.exec_start"),
            &Value::Text("/usr/bin/app --port 8080".to_string())
        );
    }

    #[test]
    fn user_absent_signifie_root_pas_defaut_invente() {
        let unit = "[Service]\nExecStart=/usr/bin/simple\n";
        let raw = capture::join_sections(&[("/usr/lib/systemd/system/simple.service", unit)]);
        let facts = extract_systemd_facts(&raw);
        assert_eq!(
            value(&facts, "service:simple", "service.user"),
            &Value::Absent
        );
        // pas dans la liste : l'état d'activation est Absent, pas « disabled »
        assert_eq!(
            value(&facts, "service:simple", "service.enabled"),
            &Value::Absent
        );
    }

    #[test]
    fn user_hors_section_service_ignore() {
        let unit = "[Unit]\nUser=pas-la-bonne-section\n[Service]\nExecStart=/bin/x\n";
        let raw = capture::join_sections(&[("/etc/systemd/system/u.service", unit)]);
        let facts = extract_systemd_facts(&raw);
        assert_eq!(value(&facts, "service:u", "service.user"), &Value::Absent);
    }

    #[test]
    fn derniere_occurrence_gagnante_et_reinitialisation() {
        let unit = "[Service]\nExecStart=/bin/premier\nExecStart=\nExecStart=/bin/dernier\nUser=a\nUser=b\n";
        let raw = capture::join_sections(&[("/etc/systemd/system/w.service", unit)]);
        let facts = extract_systemd_facts(&raw);
        assert_eq!(
            value(&facts, "service:w", "service.exec_start"),
            &Value::Text("/bin/dernier".to_string())
        );
        assert_eq!(
            value(&facts, "service:w", "service.user"),
            &Value::Text("b".to_string())
        );
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_systemd_facts("");
        let _ = extract_systemd_facts("### constat:fichier .service\n[Service\nUser");
        let _ = extract_systemd_facts(&capture::join_sections(&[(
            SECTION_UNIT_FILES,
            ".service enabled\n\u{0}\n= = =\n",
        )]));
    }
}
