//! Faits : triplets entité-attribut-valeur (§3.2).
//!
//! # Sémantique de `Value::Absent`
//!
//! **« L'attribut n'existe pas » et « l'attribut vaut faux » sont deux choses
//! différentes.** Un `sshd_config` sans directive `PermitRootLogin` applique
//! le défaut du système, qui varie selon les versions : le collecteur émet
//! alors `Absent`, jamais `Bool(false)`. Confondre les deux produit des
//! verdicts faux (§3.2).
//!
//! `Absent` est donc un fait de plein droit : il est stocké, haché et comparé
//! comme n'importe quelle valeur, et `Absent != Bool(false)` — leurs
//! empreintes canoniques diffèrent (testé).

use crate::ids::{Attribute, EntityId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Valeur d'un fait. Volontairement sans flottant (§15).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<Value>),
    /// Empreinte d'un secret, jamais le secret lui-même.
    Fingerprint([u8; 32]),
    /// L'absence est un fait, et souvent LE fait important (§3.2).
    /// Distinct de `Bool(false)` : voir la documentation du module.
    Absent,
}

impl Value {
    /// Construit une empreinte de secret (le secret lui-même ne doit
    /// jamais entrer dans le modèle).
    pub const fn fingerprint(bytes: [u8; 32]) -> Self {
        Value::Fingerprint(bytes)
    }

    /// La valeur est-elle [`Value::Absent`] ?
    pub const fn is_absent(&self) -> bool {
        matches!(self, Value::Absent)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}

impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::List(v)
    }
}

/// Affichage lisible, destiné aux rapports et à la CLI — **pas** une
/// sérialisation : l'encodage canonique passe par
/// [`to_canonical_bytes`](crate::to_canonical_bytes).
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Text(t) => f.write_str(t),
            Value::List(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            Value::Fingerprint(bytes) => {
                write!(f, "fingerprint:{}…", hex::encode(&bytes[..4]))
            }
            Value::Absent => f.write_str("absent"),
        }
    }
}

/// Triplet entité-attribut-valeur.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fact {
    pub entity: EntityId,
    pub attribute: Attribute,
    pub value: Value,
}

impl Fact {
    /// Constructeur ergonomique.
    ///
    /// ```
    /// use constat_model::{Fact, Value};
    /// let f = Fact::new("service:sshd", "sshd.PermitRootLogin", "no");
    /// assert_eq!(f.value, Value::Text("no".into()));
    /// let g = Fact::new("user:root", "user.privileged", true);
    /// assert_eq!(g.value, Value::Bool(true));
    /// ```
    pub fn new(
        entity: impl Into<EntityId>,
        attribute: impl Into<Attribute>,
        value: impl Into<Value>,
    ) -> Self {
        Fact {
            entity: entity.into(),
            attribute: attribute.into(),
            value: value.into(),
        }
    }

    /// Fait d'absence : l'attribut n'existe pas sur cette entité.
    /// Voir la sémantique de [`Value::Absent`] dans la doc du module.
    pub fn absent(entity: impl Into<EntityId>, attribute: impl Into<Attribute>) -> Self {
        Fact::new(entity, attribute, Value::Absent)
    }
}

/// Affichage lisible : `entité attribut = valeur`.
impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} = {}", self.entity, self.attribute, self.value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::canonical::hash_canonical;

    /// La sémantique centrale de `Absent` (§3.2) : l'absence n'est PAS
    /// l'équivalent de « faux », ni en égalité, ni en empreinte, ni en tri.
    #[test]
    fn absent_est_distinct_de_bool_false() {
        assert_ne!(Value::Absent, Value::Bool(false));
        assert_ne!(
            hash_canonical(&Value::Absent).unwrap(),
            hash_canonical(&Value::Bool(false)).unwrap()
        );
        // Deux faits identiques hormis Absent/false ont des empreintes distinctes.
        let f1 = Fact::absent("service:sshd", "sshd.PermitRootLogin");
        let f2 = Fact::new("service:sshd", "sshd.PermitRootLogin", false);
        assert_ne!(hash_canonical(&f1).unwrap(), hash_canonical(&f2).unwrap());
    }

    #[test]
    fn absent_est_distinct_du_texte_vide_et_de_la_liste_vide() {
        assert_ne!(Value::Absent, Value::Text(String::new()));
        assert_ne!(Value::Absent, Value::List(Vec::new()));
        assert_ne!(
            hash_canonical(&Value::Absent).unwrap(),
            hash_canonical(&Value::Text(String::new())).unwrap()
        );
        assert_ne!(
            hash_canonical(&Value::Absent).unwrap(),
            hash_canonical(&Value::List(Vec::new())).unwrap()
        );
    }

    #[test]
    fn conversions_from() {
        assert_eq!(Value::from(true), Value::Bool(true));
        assert_eq!(Value::from(42), Value::Int(42));
        assert_eq!(Value::from("yes"), Value::Text("yes".into()));
        assert_eq!(Value::from(String::from("yes")), Value::Text("yes".into()));
        assert_eq!(
            Value::from(vec![Value::from(1), Value::from(2)]),
            Value::List(vec![Value::Int(1), Value::Int(2)])
        );
        assert!(Value::Absent.is_absent());
        assert!(!Value::Bool(false).is_absent());
    }

    #[test]
    fn affichage() {
        assert_eq!(Value::Bool(true).to_string(), "true");
        assert_eq!(Value::Int(-7).to_string(), "-7");
        assert_eq!(Value::Text("no".into()).to_string(), "no");
        assert_eq!(
            Value::List(vec![Value::Int(1), Value::Text("a".into())]).to_string(),
            "[1, a]"
        );
        assert_eq!(Value::Absent.to_string(), "absent");
        assert_eq!(
            Value::Fingerprint([0xab; 32]).to_string(),
            "fingerprint:abababab…"
        );
        let f = Fact::new("user:root", "user.privileged", true);
        assert_eq!(f.to_string(), "user:root user.privileged = true");
    }

    /// Le tri des faits est total et stable : c'est lui qui fonde l'ordre
    /// canonique d'un Blob.
    #[test]
    fn ordre_total_des_faits() {
        let a = Fact::new("a:x", "attr", 1);
        let b = Fact::new("a:x", "attr", 2);
        let c = Fact::new("b:y", "attr", 0);
        assert!(a < b);
        assert!(b < c);
    }
}
