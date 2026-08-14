//! Collecteur `linux.sshd` : configuration du démon OpenSSH.
//!
//! L'extracteur est **pur** (texte → faits) et testable sur tout OS ; seule
//! la lecture de `/etc/ssh/sshd_config` est derrière `#[cfg(unix)]`.
//!
//! **Point crucial (§3.2)** : une directive absente produit [`Value::Absent`],
//! jamais une valeur par défaut. Un `sshd_config` sans `PermitRootLogin`
//! applique le défaut du système, qui varie — confondre « absent » et « no »
//! produirait des verdicts faux.
//!
//! Sémantique reproduite d'OpenSSH :
//! - mots-clefs insensibles à la casse, séparateur espace ou `=` ;
//! - **première occurrence gagnante** pour chaque directive (sauf `Port`,
//!   qui est cumulative) ;
//! - les directives situées dans un bloc `Match` sont conditionnelles : elles
//!   ne sont PAS remontées comme faits globaux (les remonter serait mentir
//!   sur l'état effectif hors condition).

use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};

/// Chemin par défaut de la configuration sshd.
pub const SSHD_CONFIG_PATH: &str = "/etc/ssh/sshd_config";

/// Entité porteuse des faits sshd.
const ENTITY: &str = "service:sshd";

/// Directives suivies. Pour chacune, un fait est TOUJOURS produit :
/// la valeur observée si elle est présente, [`Value::Absent`] sinon.
/// (`Port` est traité à part car cumulatif.)
///
/// **Critère d'inclusion** : une directive entre dans cette liste si un
/// référentiel de durcissement (CIS, ANSSI) la contrôle — c'est le corpus
/// (`corpus/sshd/`) qui a fixé la couverture. Par famille :
///
/// - accès : `PermitRootLogin`, `PasswordAuthentication`,
///   `PubkeyAuthentication`, `PermitEmptyPasswords`,
///   `ChallengeResponseAuthentication`, `KbdInteractiveAuthentication`,
///   `UsePAM`, `AllowGroups`, `Protocol` ;
/// - robustesse d'authentification : `MaxAuthTries`, `LoginGraceTime`,
///   `MaxSessions` ;
/// - sessions inactives : `ClientAliveInterval`, `ClientAliveCountMax` ;
/// - transferts : `X11Forwarding`, `AllowTcpForwarding` ;
/// - intégrité et traçabilité : `StrictModes`, `LogLevel`.
///
/// La REPRÉSENTATION reste celle du fichier : les valeurs « booléennes »
/// d'OpenSSH sont des [`Value::Text`] (`"yes"`, `"no"`) car certaines
/// directives admettent d'autres mots (`prohibit-password`,
/// `forced-commands-only`…) — normaliser en [`Value::Bool`] perdrait cette
/// nuance et produirait des verdicts faux.
pub const TRACKED_DIRECTIVES: &[&str] = &[
    "PermitRootLogin",
    "PasswordAuthentication",
    "PubkeyAuthentication",
    "PermitEmptyPasswords",
    "ChallengeResponseAuthentication",
    "KbdInteractiveAuthentication",
    "X11Forwarding",
    "AllowTcpForwarding",
    "MaxAuthTries",
    "LoginGraceTime",
    "UsePAM",
    "Protocol",
    "MaxSessions",
    "StrictModes",
    "LogLevel",
    "ClientAliveInterval",
    "ClientAliveCountMax",
    "AllowGroups",
];

/// Directives à valeur numérique (stockées en [`Value::Int`] si possible).
const NUMERIC_DIRECTIVES: &[&str] = &[
    "MaxAuthTries",
    "LoginGraceTime",
    "MaxSessions",
    "ClientAliveInterval",
    "ClientAliveCountMax",
];

/// Directives dont l'argument est une liste de motifs séparés par des
/// espaces : stockées en [`Value::List`] de [`Value::Text`], même pour un
/// seul élément (une liste reste une liste — prévisible pour les assertions).
const LIST_DIRECTIVES: &[&str] = &["AllowGroups"];

/// Sépare une ligne de sshd_config en (mot-clef, argument).
/// OpenSSH accepte `Cle valeur`, `Cle=valeur` et `Cle = valeur`.
fn split_directive(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let sep = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let keyword = &line[..sep];
    let rest = line[sep..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
    if keyword.is_empty() {
        return None;
    }
    Some((keyword, rest.trim()))
}

/// Extracteur pur : texte de `sshd_config` (déjà expurgé) → faits.
///
/// Ne panique jamais : les lignes malformées sont ignorées, les faits
/// sont partiels plutôt qu'absents en bloc.
pub fn extract_sshd_facts(text: &str) -> Vec<Fact> {
    let entity = EntityId(ENTITY.to_string());
    // première occurrence gagnante : (directive canonique → valeur brute)
    let mut seen: Vec<(usize, String)> = Vec::new();
    let mut ports: Vec<Value> = Vec::new();
    let mut in_match_block = false;

    for line in text.split('\n') {
        let Some((keyword, value)) = split_directive(line) else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("Match") {
            in_match_block = true;
            continue;
        }
        if in_match_block {
            continue; // directives conditionnelles : jamais des faits globaux
        }
        if keyword.eq_ignore_ascii_case("Port") {
            if !value.is_empty() {
                ports.push(match value.parse::<i64>() {
                    Ok(n) => Value::Int(n),
                    Err(_) => Value::Text(value.to_string()),
                });
            }
            continue;
        }
        if let Some(idx) = TRACKED_DIRECTIVES
            .iter()
            .position(|d| d.eq_ignore_ascii_case(keyword))
        {
            if !seen.iter().any(|(i, _)| *i == idx) {
                seen.push((idx, value.to_string()));
            }
        }
    }

    let mut facts: Vec<Fact> = TRACKED_DIRECTIVES
        .iter()
        .enumerate()
        .map(|(idx, canonical)| {
            let value = match seen.iter().find(|(i, _)| *i == idx) {
                None => Value::Absent,
                Some((_, raw)) => {
                    if NUMERIC_DIRECTIVES.contains(canonical) {
                        match raw.parse::<i64>() {
                            Ok(n) => Value::Int(n),
                            Err(_) => Value::Text(raw.clone()),
                        }
                    } else if LIST_DIRECTIVES.contains(canonical) {
                        Value::List(
                            raw.split_whitespace()
                                .map(|t| Value::Text(t.to_string()))
                                .collect(),
                        )
                    } else {
                        Value::Text(raw.clone())
                    }
                }
            };
            Fact {
                entity: entity.clone(),
                attribute: Attribute(format!("sshd.{canonical}")),
                value,
            }
        })
        .collect();

    facts.push(Fact {
        entity,
        attribute: Attribute("sshd.Port".to_string()),
        value: match ports.len() {
            0 => Value::Absent,
            1 => ports.remove(0),
            _ => Value::List(ports),
        },
    });

    facts.sort();
    facts
}

/// Collecteur `linux.sshd`.
#[derive(Debug, Clone)]
pub struct SshdCollector {
    /// Chemin du fichier de configuration (paramétrable pour les tests).
    pub path: std::path::PathBuf,
}

impl Default for SshdCollector {
    fn default() -> Self {
        Self {
            path: std::path::PathBuf::from(SSHD_CONFIG_PATH),
        }
    }
}

impl Collector for SshdCollector {
    fn id(&self) -> CollectorId {
        CollectorId("linux.sshd".to_string())
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
            "linux.sshd : collecteur Linux, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_sshd_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact<'a>(facts: &'a [Fact], attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {attr}"))
            .value
    }

    #[test]
    fn directive_absente_donne_absent_jamais_no() {
        let facts = extract_sshd_facts("Port 22\nPasswordAuthentication no\n");
        assert_eq!(fact(&facts, "sshd.PermitRootLogin"), &Value::Absent);
        assert_eq!(
            fact(&facts, "sshd.PasswordAuthentication"),
            &Value::Text("no".to_string())
        );
        // et « no » explicite n'est pas Absent : les deux sont distincts
        assert_ne!(fact(&facts, "sshd.PasswordAuthentication"), &Value::Absent);
    }

    #[test]
    fn premiere_occurrence_gagnante() {
        let facts = extract_sshd_facts("PermitRootLogin no\nPermitRootLogin yes\n");
        assert_eq!(
            fact(&facts, "sshd.PermitRootLogin"),
            &Value::Text("no".to_string())
        );
    }

    #[test]
    fn casse_et_egal_acceptes() {
        let facts = extract_sshd_facts("permitrootlogin=prohibit-password\n");
        assert_eq!(
            fact(&facts, "sshd.PermitRootLogin"),
            &Value::Text("prohibit-password".to_string())
        );
    }

    #[test]
    fn ports_multiples_en_liste() {
        let facts = extract_sshd_facts("Port 22\nPort 2222\n");
        assert_eq!(
            fact(&facts, "sshd.Port"),
            &Value::List(vec![Value::Int(22), Value::Int(2222)])
        );
    }

    #[test]
    fn bloc_match_ignore() {
        let facts = extract_sshd_facts("Match User sauvegarde\n    PermitRootLogin yes\n");
        assert_eq!(fact(&facts, "sshd.PermitRootLogin"), &Value::Absent);
    }

    #[test]
    fn numerique_parse_en_int() {
        let facts = extract_sshd_facts("MaxAuthTries 3\n");
        assert_eq!(fact(&facts, "sshd.MaxAuthTries"), &Value::Int(3));
    }

    /// Chaque directive suivie — les extensions venues du corpus comprises
    /// (`MaxSessions`, `StrictModes`, `LogLevel`, `ClientAliveInterval`,
    /// `ClientAliveCountMax`, `AllowGroups`) — produit `Absent` quand elle
    /// ne figure pas dans le fichier : le cas Absent est couvert pour toutes.
    #[test]
    fn toute_directive_suivie_absente_donne_absent() {
        let facts = extract_sshd_facts("");
        assert_eq!(facts.len(), TRACKED_DIRECTIVES.len() + 1); // + Port
        for f in &facts {
            assert_eq!(
                f.value,
                Value::Absent,
                "{} devrait être Absent",
                f.attribute.0
            );
        }
    }

    #[test]
    fn directives_du_corpus_extraites() {
        let facts = extract_sshd_facts(
            "MaxSessions 4\nStrictModes yes\nLogLevel VERBOSE\n\
             ClientAliveInterval 300\nClientAliveCountMax 2\n",
        );
        assert_eq!(fact(&facts, "sshd.MaxSessions"), &Value::Int(4));
        // « yes » reste du texte : la représentation suit le fichier,
        // jamais une normalisation en Bool (prohibit-password le prouve)
        assert_eq!(
            fact(&facts, "sshd.StrictModes"),
            &Value::Text("yes".to_string())
        );
        assert_eq!(
            fact(&facts, "sshd.LogLevel"),
            &Value::Text("VERBOSE".to_string())
        );
        assert_eq!(fact(&facts, "sshd.ClientAliveInterval"), &Value::Int(300));
        assert_eq!(fact(&facts, "sshd.ClientAliveCountMax"), &Value::Int(2));
    }

    #[test]
    fn allow_groups_toujours_en_liste() {
        let facts = extract_sshd_facts("AllowGroups ssh-users admins\n");
        assert_eq!(
            fact(&facts, "sshd.AllowGroups"),
            &Value::List(vec![
                Value::Text("ssh-users".to_string()),
                Value::Text("admins".to_string())
            ])
        );
        // un seul élément : liste quand même (représentation prévisible)
        let facts = extract_sshd_facts("AllowGroups ssh-users\n");
        assert_eq!(
            fact(&facts, "sshd.AllowGroups"),
            &Value::List(vec![Value::Text("ssh-users".to_string())])
        );
    }

    #[test]
    fn ligne_malformee_ignoree_sans_panique() {
        let facts = extract_sshd_facts("=====\n\u{0}\u{0}\nPort\n#comment\nPermitRootLogin\n");
        // « PermitRootLogin » sans argument n'est pas une directive exploitable :
        // la ligne est ignorée, le fait reste Absent
        assert_eq!(fact(&facts, "sshd.PermitRootLogin"), &Value::Absent);
    }
}
