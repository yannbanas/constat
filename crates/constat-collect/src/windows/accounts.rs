//! Collecteur `windows.accounts` : comptes locaux et appartenances aux groupes
//! locaux — **priorité maximale (§7.3)**. C'est le collecteur qui répond, côté
//! Windows, à « qui était administrateur en mars ? ».
//!
//! Sources (LECTURE SEULE, aucune commande exécutée) : les API Win32
//! `NetUserEnum` (niveau 3), `NetLocalGroupEnum` et `NetLocalGroupGetMembers`,
//! plus `LookupAccountName` pour résoudre les SID. **Jamais de hachage, jamais
//! de secret** : seuls le SID, des drapeaux et l'appartenance aux groupes sont
//! lus.
//!
//! ## La capture, format INI normalisé et trié
//!
//! ```text
//! [localgroup S-1-5-32-544]
//! name = Administrateurs
//!
//! [user S-1-5-21-…-500]
//! name = Administrateur
//! enabled = false
//! password_never_expires = true
//! last_logon = 1723200000000
//! groups = S-1-5-32-544,S-1-5-32-545
//! ```
//!
//! Les groupes d'un utilisateur sont stockés par **SID** ; c'est le SID
//! `S-1-5-32-544` (et non le nom localisé) qui décide du privilège. Les
//! sections `localgroup` fournissent la table SID → nom pour restituer des
//! noms lisibles.
//!
//! ## Faits produits (entité `user:<nom>`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `user.sid` | `Text` |
//! | `user.enabled` | `Bool` |
//! | `user.groups` | `List` de `Text` (noms de groupes locaux, triés) |
//! | `user.privileged` | `Bool` — membre de `BUILTIN\Administrateurs` (SID `S-1-5-32-544`) |
//! | `user.password.never_expires` | `Bool` |
//! | `user.last_logon` | `Int` (ms UTC depuis l'époque) ou `Absent` — aucune connexion observée par la SAM locale (`NetUserEnum` rend 0 dans ce cas ; on ne l'invente pas en date) |

use crate::windows::{self, BUILTIN_ADMINISTRATORS_SID};
use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::BTreeSet;

/// Identifiant du collecteur.
pub const COLLECTOR_ID: &str = "windows.accounts";

/// Extracteur **pur** : capture INI (déjà expurgée) → faits.
/// Lignes malformées ignorées, jamais de panique.
pub fn extract_accounts_facts(capture_text: &str) -> Vec<Fact> {
    let sections = windows::parse_ini(capture_text);

    // 1. table SID de groupe → nom (première occurrence gagnante)
    let mut group_names: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for section in &sections {
        let Some(("localgroup", sid)) = section.header.split_once(' ') else {
            continue;
        };
        let sid = sid.trim();
        if let Some(name) = section.get("name") {
            group_names
                .entry(sid.to_string())
                .or_insert_with(|| name.to_string());
        }
    }

    // 2. un jeu de faits par section `user`
    let mut facts: Vec<Fact> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for section in &sections {
        let Some(("user", sid)) = section.header.split_once(' ') else {
            continue;
        };
        let sid = sid.trim().to_string();
        let name = match section.get("name") {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };
        if !seen.insert(name.clone()) {
            continue; // doublon hostile : première occurrence gagnante
        }
        let entity = EntityId(format!("user:{name}"));

        // SID des groupes de l'utilisateur (liste séparée par des virgules)
        let group_sids: Vec<&str> = section
            .get("groups")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|g| !g.is_empty())
            .collect();
        let privileged = group_sids.contains(&BUILTIN_ADMINISTRATORS_SID);
        // noms lisibles, triés et dédupliqués (repli sur le SID si inconnu)
        let group_display: BTreeSet<String> = group_sids
            .iter()
            .map(|g| {
                group_names
                    .get(*g)
                    .cloned()
                    .unwrap_or_else(|| (*g).to_string())
            })
            .collect();

        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.sid".to_string()),
            value: Value::Text(sid),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.enabled".to_string()),
            value: Value::Bool(windows::parse_bool(section.get("enabled"))),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.password.never_expires".to_string()),
            value: Value::Bool(windows::parse_bool(section.get("password_never_expires"))),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.last_logon".to_string()),
            value: match section
                .get("last_logon")
                .and_then(|v| v.trim().parse::<i64>().ok())
            {
                Some(ms) => Value::Int(ms),
                None => Value::Absent,
            },
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("user.groups".to_string()),
            value: Value::List(group_display.into_iter().map(Value::Text).collect()),
        });
        facts.push(Fact {
            entity,
            attribute: Attribute("user.privileged".to_string()),
            value: Value::Bool(privileged),
        });
    }

    facts.sort();
    facts
}

/// Collecteur `windows.accounts`.
#[derive(Debug, Clone, Default)]
pub struct AccountsCollector;

impl Collector for AccountsCollector {
    fn id(&self) -> CollectorId {
        CollectorId(COLLECTOR_ID.to_string())
    }

    #[cfg(windows)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let text = windows::ffi::collect_accounts_capture().map_err(CollectError::Io)?;
        Ok(RawCapture(text.into_bytes()))
    }

    #[cfg(not(windows))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "windows.accounts : collecteur Windows, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_accounts_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPTURE: &str = "\
[localgroup S-1-5-32-544]
name = Administrateurs

[localgroup S-1-5-32-545]
name = Utilisateurs

[user S-1-5-21-111-500]
name = Administrateur
enabled = false
password_never_expires = true
last_logon = 1723200000000
groups = S-1-5-32-544,S-1-5-32-545

[user S-1-5-21-111-1001]
name = alice
enabled = true
password_never_expires = false
groups = S-1-5-32-545
";

    fn value<'a>(facts: &'a [Fact], entity: &str, attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.entity.0 == entity && f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {entity} {attr}"))
            .value
    }

    #[test]
    fn privilege_decide_par_le_sid_pas_par_le_nom() {
        let facts = extract_accounts_facts(CAPTURE);
        assert_eq!(
            value(&facts, "user:Administrateur", "user.privileged"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:alice", "user.privileged"),
            &Value::Bool(false)
        );
    }

    #[test]
    fn sid_enabled_never_expires() {
        let facts = extract_accounts_facts(CAPTURE);
        assert_eq!(
            value(&facts, "user:Administrateur", "user.sid"),
            &Value::Text("S-1-5-21-111-500".to_string())
        );
        assert_eq!(
            value(&facts, "user:Administrateur", "user.enabled"),
            &Value::Bool(false)
        );
        assert_eq!(
            value(&facts, "user:Administrateur", "user.password.never_expires"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:alice", "user.enabled"),
            &Value::Bool(true)
        );
    }

    #[test]
    fn groupes_resolus_en_noms_lisibles_et_tries() {
        let facts = extract_accounts_facts(CAPTURE);
        assert_eq!(
            value(&facts, "user:Administrateur", "user.groups"),
            &Value::List(vec![
                Value::Text("Administrateurs".to_string()),
                Value::Text("Utilisateurs".to_string()),
            ])
        );
    }

    #[test]
    fn last_logon_absent_si_jamais_connecte() {
        let facts = extract_accounts_facts(CAPTURE);
        assert_eq!(
            value(&facts, "user:Administrateur", "user.last_logon"),
            &Value::Int(1723200000000)
        );
        // alice n'a pas de ligne last_logon → Absent, pas 0
        assert_eq!(
            value(&facts, "user:alice", "user.last_logon"),
            &Value::Absent
        );
    }

    #[test]
    fn groupe_inconnu_repli_sur_le_sid() {
        let capture = "[user S-1-5-21-1-1005]\nname = bob\ngroups = S-1-5-21-1-9999\n";
        let facts = extract_accounts_facts(capture);
        assert_eq!(
            value(&facts, "user:bob", "user.groups"),
            &Value::List(vec![Value::Text("S-1-5-21-1-9999".to_string())])
        );
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_accounts_facts("");
        let _ = extract_accounts_facts("[user ]\nname =\n");
        let _ = extract_accounts_facts("[user S-1]\n\u{0}\ngroups=,,,\n");
    }
}
