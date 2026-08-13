//! Collecteur `ad.groups` : les groupes du domaine, **sans client LDAP** — via
//! les API Win32 `NetGroupEnum`/`NetGroupGetUsers` en pointant le contrôleur de
//! domaine découvert par `DsGetDcName` (§7.3, comptes privilégiés du domaine).
//!
//! Si la machine **n'est pas jointe à un domaine**, `collect` retourne
//! proprement [`CollectError::Unavailable`] avec le motif — c'est le cas d'un
//! poste de travail autonome.
//!
//! ## La capture, format INI normalisé et trié
//!
//! ```text
//! [domain]
//! name = EXEMPLE
//!
//! [group S-1-5-21-…-512]
//! name = Admins du domaine
//! member = alice
//! member = bob
//! ```
//!
//! Les groupes à **SID privilégié connu** (RID 512 « Admins du domaine », 519
//! « Administrateurs de l'entreprise ») sont reconnus par leur SID, pas par
//! leur nom localisé, et rendent leurs membres privilégiés.
//!
//! ## Faits produits
//!
//! | Entité | Attribut | Valeur |
//! |---|---|---|
//! | `group:<domaine>\<nom>` | `group.members` | `List` de `Text` (membres, triés) |
//! | `user:<domaine>\<membre>` | `user.privileged` | `Bool` `true` (membres d'un groupe à SID privilégié) |

use crate::windows::{self, sid_rid, RID_DOMAIN_ADMINS, RID_ENTERPRISE_ADMINS};
use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::BTreeSet;

/// Identifiant du collecteur.
pub const COLLECTOR_ID: &str = "ad.groups";

/// Un RID est-il celui d'un groupe d'administration privilégié connu ?
fn is_privileged_group_sid(sid: &str) -> bool {
    matches!(
        sid_rid(sid),
        Some(RID_DOMAIN_ADMINS) | Some(RID_ENTERPRISE_ADMINS)
    )
}

/// Extracteur **pur** : capture INI (déjà expurgée) → faits.
/// Jamais de panique.
pub fn extract_ad_groups_facts(capture_text: &str) -> Vec<Fact> {
    let sections = windows::parse_ini(capture_text);

    let domain = sections
        .iter()
        .find(|s| s.header == "domain")
        .and_then(|s| s.get("name"))
        .unwrap_or("")
        .to_string();

    let mut facts: Vec<Fact> = Vec::new();
    let mut privileged_users: BTreeSet<String> = BTreeSet::new();

    for section in &sections {
        let Some(("group", sid)) = section.header.split_once(' ') else {
            continue;
        };
        let sid = sid.trim();
        let Some(name) = section.get("name").filter(|n| !n.is_empty()) else {
            continue;
        };
        // membres, triés et dédupliqués
        let members: BTreeSet<String> = section
            .all("member")
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(String::from)
            .collect();

        let group_entity = EntityId(format!("group:{domain}\\{name}"));
        facts.push(Fact {
            entity: group_entity,
            attribute: Attribute("group.members".to_string()),
            value: Value::List(members.iter().cloned().map(Value::Text).collect()),
        });

        if is_privileged_group_sid(sid) {
            for member in &members {
                privileged_users.insert(member.clone());
            }
        }
    }

    for member in privileged_users {
        facts.push(Fact {
            entity: EntityId(format!("user:{domain}\\{member}")),
            attribute: Attribute("user.privileged".to_string()),
            value: Value::Bool(true),
        });
    }

    facts.sort();
    facts
}

/// Collecteur `ad.groups`.
#[derive(Debug, Clone, Default)]
pub struct AdGroupsCollector;

impl Collector for AdGroupsCollector {
    fn id(&self) -> CollectorId {
        CollectorId(COLLECTOR_ID.to_string())
    }

    #[cfg(windows)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        // `DsGetDcName` échoue proprement hors domaine → Unavailable déclaré.
        let text = windows::ffi::collect_ad_groups_capture()
            .map_err(|e| CollectError::Unavailable(format!("ad.groups : {e}")))?;
        Ok(RawCapture(text.into_bytes()))
    }

    #[cfg(not(windows))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "ad.groups : collecteur Windows/Active Directory, plateforme non prise en charge"
                .to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_ad_groups_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPTURE: &str = "\
[domain]
name = EXEMPLE

[group S-1-5-21-1-2-3-512]
name = Admins du domaine
member = Administrateur
member = alice

[group S-1-5-21-1-2-3-1108]
name = Support
member = bob
";

    fn value<'a>(facts: &'a [Fact], entity: &str, attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.entity.0 == entity && f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {entity} {attr}"))
            .value
    }

    #[test]
    fn membres_du_groupe_tries() {
        let facts = extract_ad_groups_facts(CAPTURE);
        assert_eq!(
            value(&facts, "group:EXEMPLE\\Admins du domaine", "group.members"),
            &Value::List(vec![
                Value::Text("Administrateur".to_string()),
                Value::Text("alice".to_string()),
            ])
        );
    }

    #[test]
    fn membres_des_admins_du_domaine_sont_privilegies() {
        let facts = extract_ad_groups_facts(CAPTURE);
        assert_eq!(
            value(&facts, "user:EXEMPLE\\alice", "user.privileged"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:EXEMPLE\\Administrateur", "user.privileged"),
            &Value::Bool(true)
        );
        // bob n'est que dans Support (RID 1108) : pas de fait de privilège
        assert!(!facts
            .iter()
            .any(|f| f.entity.0 == "user:EXEMPLE\\bob" && f.attribute.0 == "user.privileged"));
    }

    #[test]
    fn enterprise_admins_reconnus_par_sid() {
        let capture =
            "[domain]\nname = D\n[group S-1-5-21-9-9-9-519]\nname = Entreprise\nmember = carol\n";
        let facts = extract_ad_groups_facts(capture);
        assert_eq!(
            value(&facts, "user:D\\carol", "user.privileged"),
            &Value::Bool(true)
        );
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_ad_groups_facts("");
        let _ = extract_ad_groups_facts("[group ]\nname=\n");
        let _ = extract_ad_groups_facts("[group S-1]\nmember=\u{0}\n");
    }
}
