//! # constat-policy — cœur pur
//!
//! Langage d'assertions volontairement faible (§5) : total, terminant,
//! analysable. Ni Rhai, ni Lua, ni Starlark — jamais.
//! Aucune entrée-sortie (le YAML est parsé depuis une chaîne fournie).
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.

use constat_model::{AssetId, Attribute, BlobHash, EntityId, Timestamp, Value};
use constat_time::CoverageReport;
use serde::{Deserialize, Serialize};

/// Identifiant d'assertion, ex. `"SSH-ROOT"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssertionId(pub String);

/// Sélecteur de machines (portée d'une assertion).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Motif d'entités, ex. `"service:sshd"`, ou sélection typée avec filtre.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EntityPattern {
    /// Motif littéral avec jokers `*`, ex. `"user:*"`.
    Glob(String),
    /// Sélection typée : `{ type: user, where: { privileged: true } }`.
    Typed {
        #[serde(rename = "type")]
        entity_type: String,
        #[serde(default, rename = "where")]
        filter: std::collections::BTreeMap<String, Value>,
    },
}

/// Prédicat total et terminant (§5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Predicate {
    Never {
        entity: EntityPattern,
        attr: Attribute,
        equals: Value,
    },
    Always {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entity: Option<EntityPattern>,
        attr: Attribute,
        equals: Value,
    },
    ForAll {
        over: EntityPattern,
        satisfies: Box<Predicate>,
    },
    Exists {
        matching: EntityPattern,
    },
    Fresher {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entity: Option<EntityPattern>,
        attr: Attribute,
        /// Durée lisible, ex. `"24h"`.
        than: String,
    },
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
}

/// Exception documentée, justifiée, datée. `expires` obligatoire par conception.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exception {
    pub entity: String,
    pub reason: String,
    pub approved_by: String,
    /// Une exception sans date d'expiration est un mensonge (§5.2).
    pub expires: String,
}

/// Une assertion de conformité.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    pub id: AssertionId,
    pub title: String,
    #[serde(default)]
    pub scope: AssetSelector,
    pub predicate: Predicate,
    #[serde(default)]
    pub exceptions: Vec<Exception>,
}

/// Verdict : `Undetermined` est un verdict à part entière (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Fail,
    Undetermined,
}

/// Violation constatée, avec renvoi vers la preuve brute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub asset: AssetId,
    pub entity: EntityId,
    pub observed: Value,
    pub expected: Value,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    /// Vers l'artefact brut.
    pub evidence: BlobHash,
}

/// Résultat d'évaluation : un verdict accompagné de sa couverture, jamais un
/// simple booléen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    pub assertion: AssertionId,
    pub verdict: Verdict,
    pub coverage: CoverageReport,
    pub violations: Vec<Violation>,
}
