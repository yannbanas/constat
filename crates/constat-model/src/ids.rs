//! Identifiants du modèle : entités, attributs, machines, collecteurs.
//!
//! Un [`EntityId`] suit la convention `"type:nom"` (`"user:root"`,
//! `"service:sshd"`, `"pkg:openssh-server"`). Le constructeur [`EntityId::parse`]
//! valide ce format ; le champ interne reste public (contrat partagé), donc une
//! construction directe non validée reste possible — les collecteurs doivent
//! passer par `parse` ou [`EntityId::new`].

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Identifiant d'entité, ex. `"user:root"`, `"service:sshd"`, `"pkg:openssh-server"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntityId(pub String);

/// Attribut, ex. `"sshd.PermitRootLogin"`, `"user.privileged"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Attribute(pub String);

/// Machine du parc, ex. `"srv-fic-01"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssetId(pub String);

/// Identifiant de collecteur, ex. `"linux.sshd"`, `"linux.accounts"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CollectorId(pub String);

/// Erreur de validation d'un [`EntityId`] au format `"type:nom"`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntityIdError {
    /// Aucun séparateur `:` — impossible de distinguer le type du nom.
    #[error(
        "identifiant d'entité « {0} » : séparateur « : » manquant (format attendu « type:nom »)"
    )]
    MissingSeparator(String),
    /// La partie type (avant le premier `:`) est vide.
    #[error("identifiant d'entité « {0} » : type vide (format attendu « type:nom »)")]
    EmptyType(String),
    /// La partie nom (après le premier `:`) est vide.
    #[error("identifiant d'entité « {0} » : nom vide (format attendu « type:nom »)")]
    EmptyName(String),
    /// Le type passé à [`EntityId::new`] contient lui-même un `:`.
    #[error("type d'entité « {0} » : ne doit pas contenir « : »")]
    TypeContainsSeparator(String),
}

impl EntityId {
    /// Construit et valide un identifiant depuis ses deux parties.
    ///
    /// Le type ne doit être ni vide ni contenir `:` ; le nom ne doit pas
    /// être vide (il peut contenir `:`, ex. `"file:/etc/ssh:config"`).
    ///
    /// ```
    /// use constat_model::EntityId;
    /// let id = EntityId::new("user", "root")?;
    /// assert_eq!(id.0, "user:root");
    /// # Ok::<(), constat_model::EntityIdError>(())
    /// ```
    pub fn new(entity_type: &str, name: &str) -> Result<Self, EntityIdError> {
        if entity_type.is_empty() {
            return Err(EntityIdError::EmptyType(format!("{entity_type}:{name}")));
        }
        if entity_type.contains(':') {
            return Err(EntityIdError::TypeContainsSeparator(entity_type.to_owned()));
        }
        if name.is_empty() {
            return Err(EntityIdError::EmptyName(format!("{entity_type}:{name}")));
        }
        Ok(EntityId(format!("{entity_type}:{name}")))
    }

    /// Analyse et valide une chaîne au format `"type:nom"`.
    ///
    /// Le premier `:` sépare le type du nom ; les deux parties doivent être
    /// non vides. Le nom peut contenir d'autres `:`.
    pub fn parse(s: &str) -> Result<Self, EntityIdError> {
        let Some((t, n)) = s.split_once(':') else {
            return Err(EntityIdError::MissingSeparator(s.to_owned()));
        };
        if t.is_empty() {
            return Err(EntityIdError::EmptyType(s.to_owned()));
        }
        if n.is_empty() {
            return Err(EntityIdError::EmptyName(s.to_owned()));
        }
        Ok(EntityId(s.to_owned()))
    }

    /// Le type de l'entité (avant le premier `:`), s'il est bien formé.
    ///
    /// `None` si l'identifiant ne respecte pas le format `"type:nom"`
    /// (possible car le champ interne est public).
    pub fn entity_type(&self) -> Option<&str> {
        match self.0.split_once(':') {
            Some((t, n)) if !t.is_empty() && !n.is_empty() => Some(t),
            _ => None,
        }
    }

    /// Le nom de l'entité (après le premier `:`), s'il est bien formé.
    pub fn name(&self) -> Option<&str> {
        match self.0.split_once(':') {
            Some((t, n)) if !t.is_empty() && !n.is_empty() => Some(n),
            _ => None,
        }
    }

    /// L'identifiant respecte-t-il le format `"type:nom"` ?
    pub fn is_well_formed(&self) -> bool {
        self.entity_type().is_some()
    }
}

impl FromStr for EntityId {
    type Err = EntityIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EntityId::parse(s)
    }
}

/// Conversion **non validée** (commodité pour les littéraux connus).
/// Pour valider une entrée externe, utiliser [`EntityId::parse`].
impl From<&str> for EntityId {
    fn from(s: &str) -> Self {
        EntityId(s.to_owned())
    }
}

/// Conversion **non validée**. Pour valider, utiliser [`EntityId::parse`].
impl From<String> for EntityId {
    fn from(s: String) -> Self {
        EntityId(s)
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Attribute {
    fn from(s: &str) -> Self {
        Attribute(s.to_owned())
    }
}

impl From<String> for Attribute {
    fn from(s: String) -> Self {
        Attribute(s)
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for AssetId {
    fn from(s: &str) -> Self {
        AssetId(s.to_owned())
    }
}

impl From<String> for AssetId {
    fn from(s: String) -> Self {
        AssetId(s)
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for CollectorId {
    fn from(s: &str) -> Self {
        CollectorId(s.to_owned())
    }
}

impl From<String> for CollectorId {
    fn from(s: String) -> Self {
        CollectorId(s)
    }
}

impl fmt::Display for CollectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_valide() {
        let id = EntityId::parse("user:root").unwrap();
        assert_eq!(id.entity_type(), Some("user"));
        assert_eq!(id.name(), Some("root"));
        assert!(id.is_well_formed());
        assert_eq!(id.to_string(), "user:root");
    }

    #[test]
    fn le_nom_peut_contenir_des_deux_points() {
        let id = EntityId::parse("file:/etc/ssh:sshd_config").unwrap();
        assert_eq!(id.entity_type(), Some("file"));
        assert_eq!(id.name(), Some("/etc/ssh:sshd_config"));
    }

    #[test]
    fn parse_rejette_les_formats_invalides() {
        assert_eq!(
            EntityId::parse("root"),
            Err(EntityIdError::MissingSeparator("root".into()))
        );
        assert_eq!(
            EntityId::parse(":root"),
            Err(EntityIdError::EmptyType(":root".into()))
        );
        assert_eq!(
            EntityId::parse("user:"),
            Err(EntityIdError::EmptyName("user:".into()))
        );
    }

    #[test]
    fn new_valide_les_parties() {
        assert_eq!(EntityId::new("user", "root").unwrap().0, "user:root");
        assert!(matches!(
            EntityId::new("", "root"),
            Err(EntityIdError::EmptyType(_))
        ));
        assert!(matches!(
            EntityId::new("user", ""),
            Err(EntityIdError::EmptyName(_))
        ));
        assert!(matches!(
            EntityId::new("a:b", "c"),
            Err(EntityIdError::TypeContainsSeparator(_))
        ));
    }

    #[test]
    fn accesseurs_sur_identifiant_mal_forme() {
        // Construction directe non validée : les accesseurs répondent None.
        let id = EntityId("pasdeformat".into());
        assert_eq!(id.entity_type(), None);
        assert_eq!(id.name(), None);
        assert!(!id.is_well_formed());
    }

    #[test]
    fn fromstr_delegue_a_parse() {
        let id: EntityId = "service:sshd".parse().unwrap();
        assert_eq!(id.name(), Some("sshd"));
        assert!("invalide".parse::<EntityId>().is_err());
    }
}
