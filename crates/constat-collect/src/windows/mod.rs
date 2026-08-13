//! Collecteurs Windows et Active Directory (§7.3, §13 S5). **Priorité maximale
//! (§7.3) : les comptes privilégiés.**
//!
//! ## Architecture, calquée sur les collecteurs Linux
//!
//! Comme partout dans le crate, chaque collecteur se décompose en trois temps
//! nettement séparés (§7.2) :
//!
//! 1. `collect` — **spécifique à Windows** (`#[cfg(windows)]`), en LECTURE
//!    SEULE via les API Win32 (`netapi32`, `advapi32`). **Aucune commande n'est
//!    exécutée.** La collecte produit une **capture texte normalisée**, au
//!    format INI documenté, triée et déterministe.
//! 2. `redact` — l'expurgation générique de [`crate::redact`] s'applique à la
//!    capture texte AVANT toute émission.
//! 3. `extract` — un **parseur PUR** (texte → faits), testable par fixtures sur
//!    n'importe quel OS. C'est lui qui porte toute la sémantique.
//!
//! Sur une plateforme non-Windows, chaque `collect()` retourne proprement
//! [`crate::CollectError::Unavailable`] — miroir exact des collecteurs
//! `linux.*` sur Windows. L'expurgation et l'extraction, elles, restent pures
//! et fonctionnent partout.
//!
//! **Jamais de hash, jamais de secret** : aucune API manipulant des empreintes
//! de mots de passe n'est appelée ; seuls des drapeaux et des métadonnées de
//! politique sont lus.

use constat_model::{Attribute, EntityId, Fact, Value};

pub mod accounts;
pub mod ad_groups;
pub mod gpo_security;
pub mod password_policy;
pub mod services;

/// Rassemble la logique FFI Win32 en un seul module auditable
/// (`#[cfg(windows)]`). Tout le code `unsafe` du crate y est confiné.
#[cfg(windows)]
pub(crate) mod ffi;

/// SID du groupe local `BUILTIN\Administrateurs`. **Constant sur toutes les
/// installations, indépendant de la langue** — on l'utilise plutôt que le nom
/// localisé (« Administrateurs », « Administrators », …) pour décider du
/// privilège (§7.3).
pub const BUILTIN_ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// RID (dernier composant du SID) du groupe « Admins du domaine »
/// (`S-1-5-21-<domaine>-512`).
pub const RID_DOMAIN_ADMINS: u64 = 512;

/// RID du groupe « Administrateurs de l'entreprise » (`…-519`).
pub const RID_ENTERPRISE_ADMINS: u64 = 519;

// ---------------------------------------------------------------------------
// Aides PURES, partagées et testables sur tout OS
// ---------------------------------------------------------------------------

/// Formate une structure SID **binaire** en sa forme textuelle canonique
/// `S-<révision>-<autorité>-<sous-autorité>-…` (telle que produite par
/// `ConvertSidToStringSid`). Fonction pure : aucune FFI, donc testable partout.
///
/// Disposition d'un `SID` (documentée et stable) :
/// - octet 0 : révision ;
/// - octet 1 : nombre de sous-autorités *n* ;
/// - octets 2..8 : autorité d'identifiant, 48 bits **gros-boutiste** ;
/// - puis *n* sous-autorités, chacune un `u32` **petit-boutiste**.
///
/// Retourne `None` si le tampon est trop court pour le nombre annoncé de
/// sous-autorités — entrée hostile, jamais de panique.
pub fn format_sid_bytes(sid: &[u8]) -> Option<String> {
    if sid.len() < 8 {
        return None;
    }
    let revision = sid[0];
    let sub_count = sid[1] as usize;
    let needed = 8 + sub_count * 4;
    if sid.len() < needed {
        return None;
    }
    // autorité : 6 octets gros-boutistes
    let mut authority: u64 = 0;
    for &b in &sid[2..8] {
        authority = (authority << 8) | b as u64;
    }
    let mut out = format!("S-{revision}-{authority}");
    for i in 0..sub_count {
        let off = 8 + i * 4;
        let sub = u32::from_le_bytes([sid[off], sid[off + 1], sid[off + 2], sid[off + 3]]);
        out.push('-');
        out.push_str(&sub.to_string());
    }
    Some(out)
}

/// Extrait le RID — la dernière sous-autorité — d'un SID textuel.
/// `None` si le SID est mal formé ou si la dernière composante n'est pas un
/// entier.
pub fn sid_rid(sid: &str) -> Option<u64> {
    sid.rsplit('-').next()?.parse().ok()
}

/// Une section d'une capture au format INI : l'en-tête (le contenu entre
/// crochets) et ses entrées `clef = valeur`, **dans l'ordre, doublons
/// conservés** (indispensable pour les clefs répétées comme `member =`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IniSection {
    /// Contenu entre crochets, ex. `user S-1-5-32-544` ou `password_policy`.
    pub header: String,
    /// Couples `(clef, valeur)`, dans l'ordre d'apparition.
    pub entries: Vec<(String, String)>,
}

impl IniSection {
    /// Première valeur associée à `key`, si présente.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Toutes les valeurs associées à `key`, dans l'ordre (clefs répétées).
    pub fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parseur INI **pur** partagé par les extracteurs Windows. Robuste aux
/// entrées hostiles : lignes malformées ignorées, jamais de panique.
///
/// - les lignes vides et les commentaires (`#`, `;`) sont ignorés ;
/// - une ligne `[…]` ouvre une section (son en-tête est le contenu entre
///   crochets, rogné) ;
/// - une ligne `clef = valeur` hors de toute section est ignorée.
pub fn parse_ini(text: &str) -> Vec<IniSection> {
    let mut sections: Vec<IniSection> = Vec::new();
    let mut current: Option<IniSection> = None;
    for raw in text.split('\n') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.len() >= 2 && line.starts_with('[') && line.ends_with(']') {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            // '[' et ']' sont ASCII : ces bornes sont des frontières de caractère.
            let header = line[1..line.len() - 1].trim().to_string();
            current = Some(IniSection {
                header,
                entries: Vec::new(),
            });
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if let Some(section) = current.as_mut() {
                section
                    .entries
                    .push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    if let Some(section) = current.take() {
        sections.push(section);
    }
    sections
}

/// Interprète une valeur booléenne de capture (`true`/`false`, insensible à la
/// casse). Toute autre valeur est considérée `false` — l'absence d'un drapeau
/// est un « non » honnête.
pub(crate) fn parse_bool(value: Option<&str>) -> bool {
    matches!(value, Some(v) if v.eq_ignore_ascii_case("true"))
}

/// Construit un fait, avec `Value::Int` si `raw` est un entier lisible, sinon
/// `Value::Absent`. Utilisé par les politiques (Int/Absent, jamais inventé).
pub(crate) fn int_or_absent(entity: &EntityId, attr: &str, raw: Option<&str>) -> Fact {
    let value = match raw.and_then(|r| r.trim().parse::<i64>().ok()) {
        Some(n) => Value::Int(n),
        None => Value::Absent,
    };
    Fact {
        entity: entity.clone(),
        attribute: Attribute(attr.to_string()),
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_administrateurs_local_formate_correctement() {
        // S-1-5-32-544 : révision 1, 2 sous-autorités, autorité 5 (NT),
        // sous-autorités 32 et 544.
        let bytes = [
            1, // révision
            2, // nombre de sous-autorités
            0, 0, 0, 0, 0, 5, // autorité NT (gros-boutiste)
            32, 0, 0, 0, // 32 (petit-boutiste)
            0x20, 0x02, 0, 0, // 544
        ];
        assert_eq!(format_sid_bytes(&bytes).as_deref(), Some("S-1-5-32-544"));
    }

    #[test]
    fn sid_tampon_tronque_ne_panique_pas() {
        assert_eq!(format_sid_bytes(&[1, 5, 0, 0, 0, 0, 0, 5]), None);
        assert_eq!(format_sid_bytes(&[]), None);
        assert_eq!(format_sid_bytes(&[1]), None);
    }

    #[test]
    fn rid_extrait() {
        assert_eq!(sid_rid("S-1-5-21-1-2-3-512"), Some(512));
        assert_eq!(sid_rid("S-1-5-32-544"), Some(544));
        assert_eq!(sid_rid("pas-un-sid-xyz"), None);
        assert_eq!(sid_rid(""), None);
    }

    #[test]
    fn ini_sections_et_doublons() {
        let text = "# commentaire\n[a]\nname = x\nmember = u1\nmember = u2\n\n[b une clef]\nk=v\n";
        let sections = parse_ini(text);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].header, "a");
        assert_eq!(sections[0].get("name"), Some("x"));
        assert_eq!(
            sections[0].all("member").collect::<Vec<_>>(),
            vec!["u1", "u2"]
        );
        assert_eq!(sections[1].header, "b une clef");
    }

    #[test]
    fn ini_entree_hostile_sans_panique() {
        let _ = parse_ini("[\n]]]\n=\n= =\n[x]\n\u{0}=\u{0}\n[");
        let _ = parse_ini("");
        let _ = parse_ini("pas de section\nclef = valeur");
    }
}
