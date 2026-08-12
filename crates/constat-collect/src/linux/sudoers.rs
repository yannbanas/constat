//! Collecteur `linux.sudoers` : qui a quels privilèges via `sudo`.
//!
//! Parse **basique et honnête** de `/etc/sudoers` : le format complet est
//! notoirement complexe ; on extrait les règles utilisateur/groupe simples,
//! on résout les `User_Alias`, et on ignore explicitement le reste
//! (`Defaults`, alias de commandes, inclusions). Ce qui n'est pas compris
//! n'est pas inventé — l'artefact brut expurgé reste la preuve complète.
//!
//! ## Faits produits
//!
//! Entité `user:<nom>` ou `group:<nom>` (pour `%groupe`) :
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `sudo.rules` | `List` de `Text` — les règles normalisées `hôtes = (runas) commandes` |
//! | `sudo.all_commands` | `Bool` — au moins une règle donne `ALL` |
//! | `sudo.nopasswd` | `Bool` — au moins une règle porte `NOPASSWD:` |

use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Chemin par défaut. Les fragments de `/etc/sudoers.d/` ne sont pas lus en
/// v1 (limite documentée : une règle peut donc échapper à ce collecteur).
pub const SUDOERS_PATH: &str = "/etc/sudoers";

/// Règles agrégées pour une entité.
#[derive(Debug, Default)]
struct EntityRules {
    rules: Vec<String>,
    all_commands: bool,
    nopasswd: bool,
}

/// Recolle les continuations de ligne (`\` en fin de ligne).
fn join_continuations(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut pending = String::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(stripped) = line.strip_suffix('\\') {
            pending.push_str(stripped);
            pending.push(' ');
        } else {
            pending.push_str(line);
            lines.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        lines.push(pending);
    }
    lines
}

/// Une spécification sudo analysée : côté droit d'une règle.
struct ParsedSpec {
    normalized: String,
    grants_all: bool,
    nopasswd: bool,
}

/// Analyse le côté droit d'une règle (`(runas) NOPASSWD: cmd1, cmd2`).
fn parse_spec(hosts: &str, rhs: &str) -> ParsedSpec {
    let rhs = rhs.trim();
    let (runas, commands_part) = if let Some(rest) = rhs.strip_prefix('(') {
        match rest.split_once(')') {
            Some((inside, after)) => (inside.trim().to_string(), after.trim().to_string()),
            None => (String::new(), rhs.to_string()),
        }
    } else {
        (String::new(), rhs.to_string())
    };
    let mut commands = commands_part.as_str();
    let mut nopasswd = false;
    // étiquettes éventuelles, répétables : NOPASSWD:, PASSWD:, SETENV:, NOEXEC:, …
    loop {
        let upper = commands.trim_start();
        let Some((head, tail)) = upper.split_once(':') else {
            break;
        };
        let tag = head.trim();
        if tag.chars().all(|c| c.is_ascii_uppercase()) && !tag.is_empty() && tag != "ALL" {
            if tag == "NOPASSWD" {
                nopasswd = true;
            }
            commands = tail;
        } else {
            break;
        }
    }
    let commands = commands.trim();
    let grants_all = commands
        .split(',')
        .any(|c| c.trim().eq_ignore_ascii_case("ALL"));
    let runas_display = if runas.is_empty() {
        "-".to_string()
    } else {
        runas
    };
    let normalized = format!(
        "{} = ({}) {}{}",
        hosts.trim(),
        runas_display,
        if nopasswd { "NOPASSWD: " } else { "" },
        commands
    );
    ParsedSpec {
        normalized,
        grants_all,
        nopasswd,
    }
}

/// Extracteur pur : texte de `sudoers` (déjà expurgé) → faits.
/// Ne panique jamais ; ce qui n'est pas analysable est ignoré.
pub fn extract_sudoers_facts(text: &str) -> Vec<Fact> {
    let mut user_aliases: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut entities: BTreeMap<String, EntityRules> = BTreeMap::new();

    let lines = join_continuations(text);

    // première passe : les User_Alias
    for line in &lines {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("User_Alias") {
            if let Some((name, members)) = rest.split_once('=') {
                let name = name.trim().to_string();
                if !name.is_empty() {
                    user_aliases.insert(
                        name,
                        members
                            .split(',')
                            .map(|m| m.trim().to_string())
                            .filter(|m| !m.is_empty())
                            .collect(),
                    );
                }
            }
        }
    }

    // deuxième passe : les règles
    for line in &lines {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("Defaults")
            || line.starts_with("User_Alias")
            || line.starts_with("Cmnd_Alias")
            || line.starts_with("Host_Alias")
            || line.starts_with("Runas_Alias")
            || line.starts_with('@')
        {
            continue;
        }
        // forme : <utilisateurs> <hôtes> = <spec>
        let Some(eq_pos) = line.find('=') else {
            continue;
        };
        let left = line[..eq_pos].trim();
        let rhs = line.get(eq_pos + 1..).unwrap_or("");
        let mut left_tokens: Vec<&str> = left.split_whitespace().collect();
        if left_tokens.len() < 2 {
            continue; // pas de liste d'hôtes identifiable : règle inexploitable
        }
        let hosts = match left_tokens.pop() {
            Some(h) => h,
            None => continue,
        };
        let users_part = left_tokens.join(" ");
        let spec = parse_spec(hosts, rhs);

        // liste d'utilisateurs, séparés par des virgules
        let mut targets: BTreeSet<String> = BTreeSet::new();
        for user in users_part.split(',') {
            let user = user.trim();
            if user.is_empty() {
                continue;
            }
            if let Some(group) = user.strip_prefix('%') {
                if !group.is_empty() {
                    targets.insert(format!("group:{group}"));
                }
            } else if user.starts_with('+') || user.starts_with('#') {
                // netgroups et uid numériques : hors périmètre v1
                continue;
            } else if let Some(members) = user_aliases.get(user) {
                for member in members {
                    if let Some(group) = member.strip_prefix('%') {
                        targets.insert(format!("group:{group}"));
                    } else if !member.starts_with('+') && !member.starts_with('#') {
                        targets.insert(format!("user:{member}"));
                    }
                }
            } else {
                targets.insert(format!("user:{user}"));
            }
        }

        for target in targets {
            let entry = entities.entry(target).or_default();
            entry.rules.push(spec.normalized.clone());
            entry.all_commands |= spec.grants_all;
            entry.nopasswd |= spec.nopasswd;
        }
    }

    let mut facts: Vec<Fact> = Vec::new();
    for (entity_id, rules) in entities {
        let entity = EntityId(entity_id);
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("sudo.rules".to_string()),
            value: Value::List(rules.rules.into_iter().map(Value::Text).collect()),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("sudo.all_commands".to_string()),
            value: Value::Bool(rules.all_commands),
        });
        facts.push(Fact {
            entity,
            attribute: Attribute("sudo.nopasswd".to_string()),
            value: Value::Bool(rules.nopasswd),
        });
    }
    facts.sort();
    facts
}

/// Collecteur `linux.sudoers`.
#[derive(Debug, Clone)]
pub struct SudoersCollector {
    /// Chemin du fichier sudoers (paramétrable pour les tests).
    pub path: std::path::PathBuf,
}

impl Default for SudoersCollector {
    fn default() -> Self {
        Self {
            path: std::path::PathBuf::from(SUDOERS_PATH),
        }
    }
}

impl Collector for SudoersCollector {
    fn id(&self) -> CollectorId {
        CollectorId("linux.sudoers".to_string())
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
            "linux.sudoers : collecteur Linux, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_sudoers_facts(&text))
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
    fn regle_simple() {
        let facts = extract_sudoers_facts("root ALL=(ALL:ALL) ALL\n");
        assert_eq!(
            value(&facts, "user:root", "sudo.all_commands"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:root", "sudo.nopasswd"),
            &Value::Bool(false)
        );
    }

    #[test]
    fn groupe_et_nopasswd() {
        let facts = extract_sudoers_facts(
            "%sudo ALL=(ALL) ALL\nalice ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx\n",
        );
        assert_eq!(
            value(&facts, "group:sudo", "sudo.all_commands"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:alice", "sudo.nopasswd"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:alice", "sudo.all_commands"),
            &Value::Bool(false)
        );
    }

    #[test]
    fn alias_utilisateur_resolu() {
        let texte = "User_Alias ADMINS = alice, bob\nADMINS ALL=(ALL) ALL\n";
        let facts = extract_sudoers_facts(texte);
        assert_eq!(
            value(&facts, "user:alice", "sudo.all_commands"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "user:bob", "sudo.all_commands"),
            &Value::Bool(true)
        );
    }

    #[test]
    fn continuation_de_ligne() {
        let texte = "carol ALL=(ALL) \\\n    NOPASSWD: ALL\n";
        let facts = extract_sudoers_facts(texte);
        assert_eq!(
            value(&facts, "user:carol", "sudo.nopasswd"),
            &Value::Bool(true)
        );
    }

    #[test]
    fn defaults_et_inclusions_ignores() {
        let texte = "Defaults env_reset\n@includedir /etc/sudoers.d\n#include /etc/autre\n";
        assert!(extract_sudoers_facts(texte).is_empty());
    }

    #[test]
    fn entree_malformee_sans_panique() {
        let _ = extract_sudoers_facts("=\n= = =\n((((\nx =\n%\n");
    }
}
