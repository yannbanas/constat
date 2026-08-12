//! # constat-diff — cœur pur
//!
//! Une différence, c'est une soustraction d'ensembles de triplets (§3.2).
//! Aucune entrée-sortie.
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.

use constat_model::{Attribute, EntityId, Fact, Value};
use serde::{Deserialize, Serialize};

/// Un changement de valeur sur un couple (entité, attribut).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Changed {
    pub entity: EntityId,
    pub attribute: Attribute,
    pub before: Value,
    pub after: Value,
}

/// Différence entre deux ensembles de faits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactDiff {
    pub added: Vec<Fact>,
    pub removed: Vec<Fact>,
    pub changed: Vec<Changed>,
}

impl FactDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Calcule la différence entre deux états. Générique : aucun code par collecteur.
pub fn diff(before: &[Fact], after: &[Fact]) -> FactDiff {
    use std::collections::BTreeMap;
    let index = |facts: &[Fact]| -> BTreeMap<(EntityId, Attribute), Value> {
        facts
            .iter()
            .map(|f| ((f.entity.clone(), f.attribute.clone()), f.value.clone()))
            .collect()
    };
    let b = index(before);
    let a = index(after);

    let mut out = FactDiff::default();
    for (key, val) in &a {
        match b.get(key) {
            None => out.added.push(Fact {
                entity: key.0.clone(),
                attribute: key.1.clone(),
                value: val.clone(),
            }),
            Some(prev) if prev != val => out.changed.push(Changed {
                entity: key.0.clone(),
                attribute: key.1.clone(),
                before: prev.clone(),
                after: val.clone(),
            }),
            Some(_) => {}
        }
    }
    for (key, val) in &b {
        if !a.contains_key(key) {
            out.removed.push(Fact {
                entity: key.0.clone(),
                attribute: key.1.clone(),
                value: val.clone(),
            });
        }
    }
    out
}
