//! Collecteur `linux.accounts` : comptes et groupes — **priorité maximale
//! (§7.3)**. C'est le collecteur qui répond à « qui était admin en mars ? ».
//!
//! Sources : `/etc/passwd`, `/etc/group` et, si lisible, `/etc/shadow`.
//! Les trois fichiers sont regroupés en une capture unique par sections
//! (voir [`crate::capture`]).
//!
//! **`/etc/shadow` (§7.2)** : on n'extrait QUE l'algorithme de hachage, l'âge
//! du mot de passe et l'état verrouillé. L'empreinte elle-même est expurgée
//! structurellement AVANT émission ([`redact::redact_shadow_hash_field`]) —
//! elle n'apparaît ni dans la capture expurgée ni dans les faits, jamais.
//!
//! ## Faits produits (entité `user:<nom>`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `user.uid` | `Int` |
//! | `user.shell` | `Text` |
//! | `user.groups` | `List` de `Text` (groupe primaire + secondaires, triés, dédupliqués) |
//! | `user.privileged` | `Bool` — uid 0 ou membre de `root`/`sudo`/`wheel`/`adm` |
//! | `user.password.locked` | `Bool` (si `/etc/shadow` lisible) |
//! | `user.password.set` | `Bool` — un hachage existe (si shadow lisible) |
//! | `user.password.algorithm` | `Text` (`sha512`, `yescrypt`, …) ou `Absent` |
//! | `user.password.last_change_days` | `Int` — jours depuis l'époque Unix, ou `Absent` |
//! | `user.password.max_days` | `Int` ou `Absent` |

use crate::{capture, redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Groupes dont l'appartenance rend un compte privilégié.
pub const PRIVILEGED_GROUPS: &[&str] = &["root", "sudo", "wheel", "adm"];

/// Noms de sections dans la capture combinée.
pub const SECTION_PASSWD: &str = "/etc/passwd";
/// Voir [`SECTION_PASSWD`].
pub const SECTION_GROUP: &str = "/etc/group";
/// Voir [`SECTION_PASSWD`].
pub const SECTION_SHADOW: &str = "/etc/shadow";

/// Traduit l'identifiant modulaire `crypt(3)` en nom d'algorithme.
fn algorithm_name(id: &str) -> String {
    match id {
        "1" => "md5".to_string(),
        "2a" | "2b" | "2y" => "bcrypt".to_string(),
        "5" => "sha256".to_string(),
        "6" => "sha512".to_string(),
        "7" => "scrypt".to_string(),
        "y" => "yescrypt".to_string(),
        "gy" => "gost-yescrypt".to_string(),
        autre => format!("inconnu(${autre}$)"),
    }
}

/// Informations extraites d'un champ hachage de shadow **déjà expurgé**
/// (forme `[!*]*($id$)?[EXPURGÉ:hachage]` ou marqueur de verrouillage seul).
struct ShadowHashInfo {
    locked: bool,
    set: bool,
    algorithm: Option<String>,
}

fn parse_shadow_hash_field(field: &str) -> ShadowHashInfo {
    let lock_len = field
        .bytes()
        .take_while(|b| *b == b'!' || *b == b'*')
        .count();
    let rest = field.get(lock_len..).unwrap_or("");
    let algorithm = rest
        .strip_prefix('$')
        .and_then(|r| r.split_once('$').map(|(id, _)| algorithm_name(id)));
    ShadowHashInfo {
        locked: lock_len > 0,
        set: !rest.is_empty(),
        algorithm,
    }
}

/// Extracteur pur : contenus (déjà expurgés) de passwd, group et shadow
/// (optionnel) → faits. Lignes malformées ignorées, jamais de panique.
pub fn extract_accounts_facts(passwd: &str, group: &str, shadow: Option<&str>) -> Vec<Fact> {
    // /etc/group : gid → nom, et membre → groupes secondaires
    let mut gid_to_name: BTreeMap<i64, String> = BTreeMap::new();
    let mut member_groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in group.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = redact::split_colon_fields(line);
        if fields.len() < 4 || fields[0].is_empty() {
            continue;
        }
        let group_name = fields[0];
        if let Ok(gid) = fields[2].trim().parse::<i64>() {
            gid_to_name
                .entry(gid)
                .or_insert_with(|| group_name.to_string());
        }
        for member in fields[3].split(',') {
            let member = member.trim();
            if !member.is_empty() {
                member_groups
                    .entry(member.to_string())
                    .or_default()
                    .insert(group_name.to_string());
            }
        }
    }

    // /etc/shadow (déjà expurgé) : nom → (hachage expurgé, lastchg, max)
    let mut shadow_info: BTreeMap<String, (String, Option<i64>, Option<i64>)> = BTreeMap::new();
    if let Some(shadow) = shadow {
        for line in shadow.split('\n') {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // découpage conscient des marqueurs : le « : » de [EXPURGÉ:hachage]
            // ne doit pas décaler les champs
            let fields = redact::split_colon_fields(line);
            if fields.len() < 2 || fields[0].is_empty() {
                continue;
            }
            let last_change = fields.get(2).and_then(|f| f.trim().parse::<i64>().ok());
            let max_days = fields.get(4).and_then(|f| f.trim().parse::<i64>().ok());
            shadow_info.entry(fields[0].to_string()).or_insert((
                fields[1].to_string(),
                last_change,
                max_days,
            ));
        }
    }

    // /etc/passwd : les entités
    let mut facts: Vec<Fact> = Vec::new();
    let mut seen_users: BTreeSet<String> = BTreeSet::new();
    for line in passwd.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = redact::split_colon_fields(line);
        if fields.len() < 7 || fields[0].is_empty() {
            continue;
        }
        let name = fields[0];
        if !seen_users.insert(name.to_string()) {
            continue; // doublon hostile : première occurrence gagnante
        }
        let Ok(uid) = fields[2].trim().parse::<i64>() else {
            continue;
        };
        let shell = fields[6];
        let entity = EntityId(format!("user:{name}"));

        // groupes : primaire (via gid) + secondaires (via /etc/group)
        let mut groups: BTreeSet<String> = member_groups.get(name).cloned().unwrap_or_default();
        if let Ok(gid) = fields[3].trim().parse::<i64>() {
            if let Some(primary) = gid_to_name.get(&gid) {
                groups.insert(primary.clone());
            }
        }
        let privileged = uid == 0
            || groups
                .iter()
                .any(|g| PRIVILEGED_GROUPS.contains(&g.as_str()));

        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.uid".to_string()),
            value: Value::Int(uid),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.shell".to_string()),
            value: Value::Text(shell.to_string()),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.groups".to_string()),
            value: Value::List(groups.into_iter().map(Value::Text).collect()),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.privileged".to_string()),
            value: Value::Bool(privileged),
        });

        if let Some((hash_field, last_change, max_days)) = shadow_info.get(name) {
            let info = parse_shadow_hash_field(hash_field);
            facts.push(Fact {
                entity: entity.clone(),
                attribute: Attribute("user.password.locked".to_string()),
                value: Value::Bool(info.locked),
            });
            facts.push(Fact {
                entity: entity.clone(),
                attribute: Attribute("user.password.set".to_string()),
                value: Value::Bool(info.set),
            });
            facts.push(Fact {
                entity: entity.clone(),
                attribute: Attribute("user.password.algorithm".to_string()),
                value: match info.algorithm {
                    Some(a) => Value::Text(a),
                    None => Value::Absent,
                },
            });
            facts.push(Fact {
                entity: entity.clone(),
                attribute: Attribute("user.password.last_change_days".to_string()),
                value: match last_change {
                    Some(d) => Value::Int(*d),
                    None => Value::Absent,
                },
            });
            facts.push(Fact {
                entity,
                attribute: Attribute("user.password.max_days".to_string()),
                value: match max_days {
                    Some(d) => Value::Int(*d),
                    None => Value::Absent,
                },
            });
        }
    }

    facts.sort();
    facts
}

/// Expurge une capture combinée passwd/group/shadow : expurgation
/// **structurelle** du champ 2 de chaque ligne de la section shadow, puis
/// liste de refus générique sur l'ensemble.
pub fn redact_accounts_capture(raw_text: &str) -> String {
    let sections = capture::split_sections(raw_text);
    let rebuilt: Vec<(String, String)> = sections
        .into_iter()
        .map(|(name, content)| {
            if name == SECTION_SHADOW {
                (name, redact_shadow_content(&content))
            } else {
                (name, content)
            }
        })
        .collect();
    let joined = capture::join_sections(
        &rebuilt
            .iter()
            .map(|(n, c)| (n.as_str(), c.as_str()))
            .collect::<Vec<_>>(),
    );
    redact::redact_text(&joined)
}

/// Expurge chaque ligne d'un contenu shadow : le champ 2 (hachage) est
/// toujours remplacé, quelle que soit sa forme (voir
/// [`redact::redact_shadow_hash_field`]).
fn redact_shadow_content(shadow: &str) -> String {
    shadow
        .split('\n')
        .map(|line| {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                return line.to_string();
            }
            let mut fields: Vec<String> = line.split(':').map(str::to_string).collect();
            if fields.len() >= 2 {
                fields[1] = redact::redact_shadow_hash_field(&fields[1]);
            } else {
                // ligne sans structure : on ne sait pas ce que c'est → tout expurger
                return redact::MARKER_HASH.to_string();
            }
            // défense en profondeur : dans shadow, tous les champs après le
            // hachage sont numériques ou vides par construction. Un champ 2
            // hostile contenant « : » ferait déborder du secret dans les
            // champs suivants — tout champ non numérique est donc expurgé.
            for field in fields.iter_mut().skip(2) {
                if !field.chars().all(|c| c.is_ascii_digit()) {
                    *field = redact::MARKER_HASH.to_string();
                }
            }
            fields.join(":")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Collecteur `linux.accounts`.
#[derive(Debug, Clone)]
pub struct AccountsCollector {
    /// Racine des fichiers systèmes (paramétrable pour les tests ; `/` en production).
    pub root: std::path::PathBuf,
}

impl Default for AccountsCollector {
    fn default() -> Self {
        Self {
            root: std::path::PathBuf::from("/"),
        }
    }
}

impl Collector for AccountsCollector {
    fn id(&self) -> CollectorId {
        CollectorId("linux.accounts".to_string())
    }

    #[cfg(unix)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let read = |rel: &str| -> Result<String, CollectError> {
            let path = self.root.join(rel.trim_start_matches('/'));
            std::fs::read_to_string(&path)
                .map_err(|e| CollectError::Io(format!("{} : {e}", path.display())))
        };
        let passwd = read(SECTION_PASSWD)?;
        let group = read(SECTION_GROUP)?;
        // /etc/shadow exige des privilèges : son absence n'invalide pas la collecte
        let mut sections: Vec<(&str, &str)> = vec![
            (SECTION_PASSWD, passwd.as_str()),
            (SECTION_GROUP, group.as_str()),
        ];
        let shadow = read(SECTION_SHADOW).ok();
        if let Some(shadow) = shadow.as_deref() {
            sections.push((SECTION_SHADOW, shadow));
        }
        Ok(RawCapture(capture::join_sections(&sections).into_bytes()))
    }

    #[cfg(not(unix))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "linux.accounts : collecteur Linux, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        let text = String::from_utf8_lossy(&raw.0);
        RedactedCapture(redact_accounts_capture(&text).into_bytes())
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        let sections = capture::split_sections(&text);
        let passwd = capture::find_section(&sections, SECTION_PASSWD).unwrap_or("");
        let group = capture::find_section(&sections, SECTION_GROUP).unwrap_or("");
        let shadow = capture::find_section(&sections, SECTION_SHADOW);
        Ok(extract_accounts_facts(passwd, group, shadow))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                          alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
                          bob:x:1001:1001:Bob:/home/bob:/usr/sbin/nologin\n";
    const GROUP: &str = "root:x:0:\n\
                         sudo:x:27:alice\n\
                         alice:x:1000:\n\
                         bob:x:1001:\n";

    fn value<'a>(facts: &'a [Fact], entity: &str, attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.entity.0 == entity && f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {entity} {attr}"))
            .value
    }

    #[test]
    fn privileges_par_uid_et_par_groupe() {
        let facts = extract_accounts_facts(PASSWD, GROUP, None);
        assert_eq!(
            value(&facts, "user:root", "user.privileged"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:alice", "user.privileged"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:bob", "user.privileged"),
            &Value::Bool(false)
        );
    }

    #[test]
    fn groupes_primaire_et_secondaires() {
        let facts = extract_accounts_facts(PASSWD, GROUP, None);
        assert_eq!(
            value(&facts, "user:alice", "user.groups"),
            &Value::List(vec![
                Value::Text("alice".to_string()),
                Value::Text("sudo".to_string())
            ])
        );
    }

    #[test]
    fn shadow_expurge_puis_extrait() {
        let shadow_brut = "alice:$6$sel$empreintesecrete123456789:19700:0:99999:7:::\n\
                           bob:!$y$j9T$sel$empreinte:19000:0:60:7:::\n\
                           root:*:18000::::::\n";
        let expurge = redact_shadow_content(shadow_brut);
        assert!(!expurge.contains("empreintesecrete"));
        assert!(!expurge.contains("sel$"));
        let facts = extract_accounts_facts(PASSWD, GROUP, Some(&expurge));
        assert_eq!(
            value(&facts, "user:alice", "user.password.algorithm"),
            &Value::Text("sha512".to_string())
        );
        assert_eq!(
            value(&facts, "user:alice", "user.password.locked"),
            &Value::Bool(false)
        );
        assert_eq!(
            value(&facts, "user:alice", "user.password.last_change_days"),
            &Value::Int(19700)
        );
        assert_eq!(
            value(&facts, "user:bob", "user.password.locked"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:bob", "user.password.algorithm"),
            &Value::Text("yescrypt".to_string())
        );
        assert_eq!(
            value(&facts, "user:bob", "user.password.max_days"),
            &Value::Int(60)
        );
        assert_eq!(
            value(&facts, "user:root", "user.password.set"),
            &Value::Bool(false)
        );
        assert_eq!(
            value(&facts, "user:root", "user.password.locked"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:root", "user.password.algorithm"),
            &Value::Absent
        );
    }

    #[test]
    fn sans_shadow_pas_de_faits_mot_de_passe() {
        let facts = extract_accounts_facts(PASSWD, GROUP, None);
        assert!(!facts
            .iter()
            .any(|f| f.attribute.0.starts_with("user.password")));
    }

    #[test]
    fn lignes_malformees_ignorees() {
        let facts = extract_accounts_facts("pas:assez:de:champs\n::::::\nx\n", "###\n", None);
        assert!(facts.is_empty());
    }
}
