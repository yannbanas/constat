//! Collecteur `ad.gpo_security` : les paramètres de sécurité des GPO — le
//! fichier SecEdit `GptTmpl.inf` de chaque stratégie (§7.3, GPO et politique
//! de mots de passe du domaine).
//!
//! ## Le format `GptTmpl.inf`
//!
//! Un fichier INI encodé **UTF-16LE avec BOM** (parfois UTF-8), déposé par
//! l'éditeur de GPO sous
//! `\\<domaine>\SYSVOL\<domaine>\Policies\{<guid>}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`.
//! Sections utiles :
//!
//! - `[System Access]` — `MinimumPasswordLength = 8`, `LockoutBadCount = 5`,
//!   `MaximumPasswordAge = 42`… (valeurs numériques ou chaînes) ;
//! - `[Privilege Rights]` — `SeDebugPrivilege = *S-1-5-32-544,EXEMPLE\ops`
//!   (listes de SID préfixés `*` ou de noms).
//!
//! ## Architecture
//!
//! Le décodage UTF-16LE ([`decode_inf_text`]) et l'extraction
//! ([`extract_gpo_security_facts`]) sont **purs** et testables par fixtures
//! sur toute plateforme. La collecte réelle lit SYSVOL **en lecture seule**
//! (partage fichier classique, aucun client LDAP) : si la machine n'est pas
//! jointe à un domaine ou si SYSVOL est injoignable, `collect` retourne
//! [`CollectError::Unavailable`] avec le motif.
//!
//! La capture regroupe un fichier par GPO, en sections
//! [`crate::capture`] nommées par le GUID :
//!
//! ```text
//! ### constat:fichier gpo:{31B2F340-016D-11D2-945F-00C04FB984F9}
//! [System Access]
//! MinimumPasswordLength = 8
//! ```
//!
//! (le contenu y est **déjà décodé** en UTF-8 : le BOM et l'UTF-16 restent un
//! détail de la collecte).
//!
//! ## Faits produits (entité `gpo:<guid>`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `gpo.<clé de [System Access]>` | `Int` si numérique, sinon `Text` |
//! | `gpo.privilege.<privilège>` | `List` des bénéficiaires (`*SID` ou noms), triés |

use crate::{capture, redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::BTreeSet;

/// Identifiant du collecteur.
pub const COLLECTOR_ID: &str = "ad.gpo_security";

/// Préfixe des noms de section de la capture (suivi du GUID de la GPO).
pub const SECTION_GPO_PREFIX: &str = "gpo:";

// ---------------------------------------------------------------------------
// Décodage : UTF-16LE (BOM), UTF-16BE (BOM), UTF-8 (BOM optionnel)
// ---------------------------------------------------------------------------

/// Décode le contenu d'un `GptTmpl.inf` en texte. Les fichiers SecEdit sont
/// en UTF-16LE avec BOM ; on accepte aussi UTF-16BE et UTF-8 (avec ou sans
/// BOM) — décodage **avec perte** sur entrée hostile, jamais de panique.
pub fn decode_inf_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&bytes[2..], u16::from_le_bytes);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&bytes[2..], u16::from_be_bytes);
    }
    let without_bom = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(bytes);
    String::from_utf8_lossy(without_bom).into_owned()
}

/// Décode une suite d'unités UTF-16 (un octet final orphelin est ignoré ;
/// les substituts invalides deviennent U+FFFD).
fn decode_utf16(bytes: &[u8], from_bytes: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| from_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

// ---------------------------------------------------------------------------
// Extraction pure
// ---------------------------------------------------------------------------

/// Parse le texte d'UN `GptTmpl.inf` (déjà décodé) et produit les faits de
/// l'entité `gpo:<guid>`. Jamais de panique.
pub fn extract_gpt_tmpl_facts(guid: &str, text: &str) -> Vec<Fact> {
    let entity = EntityId(format!("gpo:{guid}"));
    let mut facts: Vec<Fact> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    #[derive(PartialEq)]
    enum Section {
        SystemAccess,
        PrivilegeRights,
        Other,
    }
    let mut section = Section::Other;

    for raw in text.split('\n') {
        let line = raw.trim().trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            let name = line[1..line.len() - 1].trim();
            section = if name.eq_ignore_ascii_case("System Access") {
                Section::SystemAccess
            } else if name.eq_ignore_ascii_case("Privilege Rights") {
                Section::PrivilegeRights
            } else {
                Section::Other
            };
            continue;
        }
        if section == Section::Other {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        if key.is_empty() {
            continue;
        }
        match section {
            Section::SystemAccess => {
                let attr = format!("gpo.{key}");
                if !seen.insert(attr.clone()) {
                    continue; // clef répétée hostile : première occurrence gagnante
                }
                facts.push(Fact {
                    entity: entity.clone(),
                    attribute: Attribute(attr),
                    value: match value.parse::<i64>() {
                        Ok(n) => Value::Int(n),
                        Err(_) if value.is_empty() => Value::Absent,
                        Err(_) => Value::Text(value.to_string()),
                    },
                });
            }
            Section::PrivilegeRights => {
                let attr = format!("gpo.privilege.{key}");
                if !seen.insert(attr.clone()) {
                    continue;
                }
                let holders: BTreeSet<String> = value
                    .split(',')
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(String::from)
                    .collect();
                facts.push(Fact {
                    entity: entity.clone(),
                    attribute: Attribute(attr),
                    value: Value::List(holders.into_iter().map(Value::Text).collect()),
                });
            }
            Section::Other => {}
        }
    }

    facts.sort();
    facts
}

/// Extracteur **pur** : capture combinée (une section [`crate::capture`] par
/// GPO, contenu déjà décodé et expurgé) → faits. Jamais de panique.
pub fn extract_gpo_security_facts(capture_text: &str) -> Vec<Fact> {
    let sections = capture::split_sections(capture_text);
    let mut facts: Vec<Fact> = Vec::new();
    let mut seen_guids: BTreeSet<String> = BTreeSet::new();
    for (name, content) in &sections {
        let Some(guid) = name.strip_prefix(SECTION_GPO_PREFIX) else {
            continue;
        };
        let guid = guid.trim();
        if guid.is_empty() || !seen_guids.insert(guid.to_string()) {
            continue;
        }
        facts.extend(extract_gpt_tmpl_facts(guid, content));
    }
    facts.sort();
    facts
}

// ---------------------------------------------------------------------------
// Expurgation structurelle
// ---------------------------------------------------------------------------

/// Clefs de `[System Access]` qui se terminent par un mot sensible
/// (`…Password`) mais dont la valeur est un **drapeau de politique** (0/1),
/// pas un secret. Sans cette liste, la liste de refus générique les
/// expurgerait — et détruirait un fait de conformité.
const NUMERIC_POLICY_KEYS: &[&str] = &["ClearTextPassword", "RequireLogonToChangePassword"];

/// Une ligne est-elle `<clef de politique connue> = <entier>` —
/// structurellement sans secret (clef dans [`NUMERIC_POLICY_KEYS`], valeur
/// strictement numérique) ?
fn is_numeric_policy_line(line: &str) -> bool {
    let Some((key, value)) = line.split_once('=') else {
        return false;
    };
    let key = key.trim();
    let value = value.trim();
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && NUMERIC_POLICY_KEYS
            .iter()
            .any(|k| key.eq_ignore_ascii_case(k))
}

/// Expurge une capture GPO : la liste de refus générique s'applique au texte
/// ENTIER (les blocs PEM multi-lignes restent traités globalement), SAUF pour
/// les lignes de politique numériques ([`is_numeric_policy_line`]), mises à
/// l'abri par un jalon puis restaurées. Une ligne protégée avalée par un bloc
/// PEM jamais refermé disparaît avec lui — dans le doute, sur-expurger (§7.2).
pub fn redact_gpo_capture(text: &str) -> String {
    let mut protected: Vec<&str> = Vec::new();
    let prepared: Vec<String> = text
        .split('\n')
        .map(|line| {
            if is_numeric_policy_line(line) {
                let marker = format!("\u{1}gpo-politique-{}\u{1}", protected.len());
                protected.push(line);
                marker
            } else {
                line.to_string()
            }
        })
        .collect();
    let mut out = redact::redact_text(&prepared.join("\n"));
    for (n, original) in protected.iter().enumerate() {
        // si le jalon a été avalé (bloc PEM), il n'y a rien à restaurer ; si
        // une entrée hostile a fabriqué le même jalon, elle ne récupère
        // qu'une ligne numérique déjà jugée sans secret
        out = out.replace(&format!("\u{1}gpo-politique-{n}\u{1}"), original);
    }
    out
}

/// Collecteur `ad.gpo_security`.
#[derive(Debug, Clone, Default)]
pub struct GpoSecurityCollector;

impl Collector for GpoSecurityCollector {
    fn id(&self) -> CollectorId {
        CollectorId(COLLECTOR_ID.to_string())
    }

    /// Lit `\\<domaine>\SYSVOL\<domaine>\Policies\*\MACHINE\…\SecEdit\GptTmpl.inf`
    /// (lecture seule, partage fichier). Hors domaine ou SYSVOL injoignable :
    /// [`CollectError::Unavailable`] avec le motif.
    #[cfg(windows)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let domain = crate::windows::ffi::joined_domain_name()
            .map_err(|e| CollectError::Unavailable(format!("ad.gpo_security : {e}")))?;
        let policies_dir = format!("\\\\{domain}\\SYSVOL\\{domain}\\Policies");
        let entries = std::fs::read_dir(&policies_dir).map_err(|e| {
            CollectError::Unavailable(format!(
                "ad.gpo_security : SYSVOL injoignable ({policies_dir} : {e})"
            ))
        })?;
        let mut sections: Vec<(String, String)> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(guid) = name.to_str() else { continue };
            if !(guid.starts_with('{') && guid.ends_with('}')) {
                continue;
            }
            let inf = entry
                .path()
                .join("MACHINE")
                .join("Microsoft")
                .join("Windows NT")
                .join("SecEdit")
                .join("GptTmpl.inf");
            let Ok(bytes) = std::fs::read(&inf) else {
                continue; // GPO sans modèle de sécurité : rien à collecter ici
            };
            sections.push((
                format!("{SECTION_GPO_PREFIX}{guid}"),
                decode_inf_text(&bytes),
            ));
        }
        sections.sort();
        let refs: Vec<(&str, &str)> = sections
            .iter()
            .map(|(n, c)| (n.as_str(), c.as_str()))
            .collect();
        Ok(RawCapture(capture::join_sections(&refs).into_bytes()))
    }

    #[cfg(not(windows))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "ad.gpo_security : collecteur Windows/Active Directory, plateforme non prise en charge"
                .to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        let text = String::from_utf8_lossy(&raw.0);
        RedactedCapture(redact_gpo_capture(&text).into_bytes())
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_gpo_security_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "{31B2F340-016D-11D2-945F-00C04FB984F9}";

    const INF: &str = "\
[Unicode]\r
Unicode=yes\r
[System Access]\r
MinimumPasswordLength = 8\r
MaximumPasswordAge = 42\r
LockoutBadCount = 5\r
NewadministratorName = \"AdminRenomme\"\r
[Privilege Rights]\r
SeDebugPrivilege = *S-1-5-32-544\r
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555\r
[Version]\r
signature=\"$CHICAGO$\"\r
";

    /// Encode un texte en UTF-16LE avec BOM, comme un vrai `GptTmpl.inf`.
    fn to_utf16le_bom(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn value<'a>(facts: &'a [Fact], entity: &str, attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.entity.0 == entity && f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {entity} {attr}"))
            .value
    }

    #[test]
    fn decode_utf16le_avec_bom() {
        let bytes = to_utf16le_bom("[System Access]\r\nMinimumPasswordLength = 8\r\n");
        let text = decode_inf_text(&bytes);
        assert!(text.contains("MinimumPasswordLength = 8"));
        assert!(!text.contains('\u{FEFF}'));
    }

    #[test]
    fn decode_utf8_avec_et_sans_bom() {
        assert_eq!(decode_inf_text(b"abc"), "abc");
        assert_eq!(decode_inf_text(&[0xEF, 0xBB, 0xBF, b'a']), "a");
    }

    #[test]
    fn system_access_et_privilege_rights() {
        let entity = format!("gpo:{GUID}");
        let facts = extract_gpt_tmpl_facts(GUID, INF);
        assert_eq!(
            value(&facts, &entity, "gpo.MinimumPasswordLength"),
            &Value::Int(8)
        );
        assert_eq!(
            value(&facts, &entity, "gpo.MaximumPasswordAge"),
            &Value::Int(42)
        );
        assert_eq!(
            value(&facts, &entity, "gpo.LockoutBadCount"),
            &Value::Int(5)
        );
        // valeur non numérique : Text, guillemets rognés
        assert_eq!(
            value(&facts, &entity, "gpo.NewadministratorName"),
            &Value::Text("AdminRenomme".to_string())
        );
        assert_eq!(
            value(&facts, &entity, "gpo.privilege.SeDebugPrivilege"),
            &Value::List(vec![Value::Text("*S-1-5-32-544".to_string())])
        );
        assert_eq!(
            value(
                &facts,
                &entity,
                "gpo.privilege.SeRemoteInteractiveLogonRight"
            ),
            &Value::List(vec![
                Value::Text("*S-1-5-32-544".to_string()),
                Value::Text("*S-1-5-32-555".to_string()),
            ])
        );
        // les sections [Unicode] et [Version] ne produisent rien
        assert!(!facts.iter().any(|f| f.attribute.0 == "gpo.Unicode"));
        assert!(!facts.iter().any(|f| f.attribute.0 == "gpo.signature"));
    }

    #[test]
    fn pipeline_complet_depuis_utf16() {
        // le chemin réel : octets UTF-16LE → décodage → capture → extraction
        let text = decode_inf_text(&to_utf16le_bom(INF));
        let raw =
            capture::join_sections(&[(&format!("{SECTION_GPO_PREFIX}{GUID}"), text.as_str())]);
        let facts = extract_gpo_security_facts(&raw);
        assert_eq!(
            value(&facts, &format!("gpo:{GUID}"), "gpo.MinimumPasswordLength"),
            &Value::Int(8)
        );
    }

    #[test]
    fn plusieurs_gpo_dans_une_capture() {
        let raw = capture::join_sections(&[
            ("gpo:{AAAA}", "[System Access]\nLockoutBadCount = 3\n"),
            ("gpo:{BBBB}", "[System Access]\nLockoutBadCount = 10\n"),
        ]);
        let facts = extract_gpo_security_facts(&raw);
        assert_eq!(
            value(&facts, "gpo:{AAAA}", "gpo.LockoutBadCount"),
            &Value::Int(3)
        );
        assert_eq!(
            value(&facts, "gpo:{BBBB}", "gpo.LockoutBadCount"),
            &Value::Int(10)
        );
    }

    #[test]
    fn les_drapeaux_de_politique_survivent_a_l_expurgation() {
        // ClearTextPassword se termine par « password » : sans l'expurgation
        // structurelle, la liste de refus générique détruirait ce fait.
        let texte = "[System Access]\nClearTextPassword = 0\nRequireLogonToChangePassword = 1\n";
        let expurge = redact_gpo_capture(texte);
        assert!(expurge.contains("ClearTextPassword = 0"));
        assert!(expurge.contains("RequireLogonToChangePassword = 1"));
        // mais une valeur NON numérique pour la même clef reste expurgée
        let hostile = "ClearTextPassword = MotDePasseEnClair!";
        assert!(!redact_gpo_capture(hostile).contains("MotDePasseEnClair"));
        // et un vrai secret d'une autre clef aussi
        let secret = "AutoLogonPassword = Sup3rSecret";
        assert!(!redact_gpo_capture(secret).contains("Sup3rSecret"));
    }

    #[test]
    fn bloc_pem_multiligne_expurge_malgre_la_protection() {
        let texte = "avant\n-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n-----END RSA PRIVATE KEY-----\nClearTextPassword = 0\n";
        let expurge = redact_gpo_capture(texte);
        assert!(!expurge.contains("MIIEvQIBADAN"));
        assert!(expurge.contains("ClearTextPassword = 0"));
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = decode_inf_text(&[0xFF]);
        let _ = decode_inf_text(&[0xFF, 0xFE, 0x41]); // octet orphelin
        let _ = decode_inf_text(&[0xFE, 0xFF, 0x00]);
        let _ = extract_gpt_tmpl_facts("{X}", "[System Access\n=\n[Privilege Rights]\n=x\n");
        let _ = extract_gpo_security_facts("### constat:fichier gpo:\n[System Access]\na=1\n");
        let _ = redact_gpo_capture("\u{1}gpo-politique-0\u{1}\nClearTextPassword = 0\n");
    }
}
