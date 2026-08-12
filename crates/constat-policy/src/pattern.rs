//! Correspondance de motifs d'entités (§5.1).
//!
//! Deux formes de [`EntityPattern`] :
//!
//! - **Glob** : motif littéral avec jokers `*` (zéro ou plusieurs caractères)
//!   et `?` (exactement un caractère), ex. `"user:*"` ou `"service:sshd"`
//!   (sans joker, c'est une égalité stricte) ;
//! - **Typed** : sélection par type d'entité (le préfixe avant `:` de
//!   l'identifiant) et filtre `where` sur les **faits** de l'entité.
//!
//! Pour le filtre `where`, une clé `k` correspond à un fait dont l'attribut
//! vaut `k` **ou** `"{type}.{k}"` — le YAML de la spec écrit
//! `where: { privileged: true }` pour l'attribut `user.privileged`.
//! Une valeur [`Value::Absent`] dans le filtre correspond aussi à l'absence
//! totale du fait (l'absence est un fait, §3.2).

use crate::eval::TimedFact;
use crate::explain::format_value;
use crate::EntityPattern;
use constat_model::{EntityId, Value};

/// Correspondance d'un motif glob (`*` : zéro ou plus, `?` : exactement un).
///
/// Totale et terminante : parcours itératif avec retour arrière borné,
/// aucune récursion.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

impl EntityPattern {
    /// L'entité `entity`, décrite par ses faits datés `facts`, correspond-elle
    /// au motif ?
    ///
    /// - [`EntityPattern::Glob`] : correspondance glob sur l'identifiant ;
    /// - [`EntityPattern::Typed`] : le type (préfixe avant `:`) doit être égal,
    ///   et chaque clause du filtre `where` doit être satisfaite par un fait
    ///   de l'entité (clé nue ou préfixée par le type).
    #[must_use]
    pub fn matches(&self, entity: &EntityId, facts: &[&TimedFact]) -> bool {
        match self {
            EntityPattern::Glob(g) => glob_match(g, &entity.0),
            EntityPattern::Typed {
                entity_type,
                filter,
            } => {
                let Some((etype, _)) = entity.0.split_once(':') else {
                    return false;
                };
                if etype != entity_type {
                    return false;
                }
                filter.iter().all(|(key, wanted)| {
                    let qualified = format!("{entity_type}.{key}");
                    let found = facts
                        .iter()
                        .find(|f| f.fact.attribute.0 == *key || f.fact.attribute.0 == qualified);
                    match found {
                        Some(f) => f.fact.value == *wanted,
                        // Le fait n'existe pas : seul « Absent » y correspond.
                        None => *wanted == Value::Absent,
                    }
                })
            }
        }
    }

    /// Rendu lisible du motif, pour les explications.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            EntityPattern::Glob(g) => format!("« {g} »"),
            EntityPattern::Typed {
                entity_type,
                filter,
            } => {
                if filter.is_empty() {
                    format!("type = {entity_type}")
                } else {
                    let clauses: Vec<String> = filter
                        .iter()
                        .map(|(k, v)| format!("{k} = {}", format_value(v)))
                        .collect();
                    format!("type = {entity_type} où {}", clauses.join(" et "))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use constat_model::{Attribute, BlobHash, Fact, Timestamp};
    use std::collections::BTreeMap;

    #[test]
    fn glob_exact() {
        assert!(glob_match("service:sshd", "service:sshd"));
        assert!(!glob_match("service:sshd", "service:sshd2"));
        assert!(!glob_match("service:sshd", "service:ssh"));
    }

    #[test]
    fn glob_jokers() {
        assert!(glob_match("user:*", "user:root"));
        assert!(glob_match("user:*", "user:"));
        assert!(!glob_match("user:*", "service:sshd"));
        assert!(glob_match("*", "n'importe quoi"));
        assert!(glob_match("user:?dupont", "user:jdupont"));
        assert!(!glob_match("user:?dupont", "user:dupont"));
        assert!(glob_match("*:sshd", "service:sshd"));
        assert!(glob_match("srv-*-0?", "srv-fic-01"));
        assert!(!glob_match("srv-*-0?", "srv-fic-12"));
        // plusieurs étoiles, retour arrière
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXcYYb"));
    }

    fn tfact(entity: &str, attr: &str, value: Value) -> TimedFact {
        TimedFact {
            fact: Fact {
                entity: EntityId(entity.to_owned()),
                attribute: Attribute(attr.to_owned()),
                value,
            },
            first_seen: Timestamp(0),
            last_seen: Timestamp(1000),
            evidence: BlobHash([7u8; 32]),
        }
    }

    #[test]
    fn motif_type_avec_filtre() {
        let f1 = tfact("user:root", "user.privileged", Value::Bool(true));
        let f2 = tfact("user:root", "user.mfa_enabled", Value::Bool(false));
        let facts: Vec<&TimedFact> = vec![&f1, &f2];

        let mut filter = BTreeMap::new();
        filter.insert("privileged".to_owned(), Value::Bool(true));
        let motif = EntityPattern::Typed {
            entity_type: "user".to_owned(),
            filter,
        };
        assert!(motif.matches(&EntityId("user:root".to_owned()), &facts));
        // mauvais type
        assert!(!motif.matches(&EntityId("service:root".to_owned()), &facts));
        // identifiant sans type
        assert!(!motif.matches(&EntityId("root".to_owned()), &facts));
    }

    #[test]
    fn motif_type_filtre_non_satisfait() {
        let f1 = tfact("user:bob", "user.privileged", Value::Bool(false));
        let facts: Vec<&TimedFact> = vec![&f1];
        let mut filter = BTreeMap::new();
        filter.insert("privileged".to_owned(), Value::Bool(true));
        let motif = EntityPattern::Typed {
            entity_type: "user".to_owned(),
            filter,
        };
        assert!(!motif.matches(&EntityId("user:bob".to_owned()), &facts));
    }

    #[test]
    fn motif_type_absent_correspond_a_l_absence() {
        let f1 = tfact("user:bob", "user.shell", Value::Text("/bin/sh".to_owned()));
        let facts: Vec<&TimedFact> = vec![&f1];
        let mut filter = BTreeMap::new();
        filter.insert("privileged".to_owned(), Value::Absent);
        let motif = EntityPattern::Typed {
            entity_type: "user".to_owned(),
            filter,
        };
        // le fait « privileged » n'existe pas : Absent correspond
        assert!(motif.matches(&EntityId("user:bob".to_owned()), &facts));
        // mais une valeur explicite ne correspond pas à l'absence
        let mut filter2 = BTreeMap::new();
        filter2.insert("privileged".to_owned(), Value::Bool(false));
        let motif2 = EntityPattern::Typed {
            entity_type: "user".to_owned(),
            filter: filter2,
        };
        assert!(
            !motif2.matches(&EntityId("user:bob".to_owned()), &facts),
            "absence ≠ false (§3.2)"
        );
    }

    #[test]
    fn motif_type_cle_nue() {
        // la clé du filtre peut être l'attribut complet, sans préfixe de type
        let f1 = tfact("user:bob", "custom_flag", Value::Bool(true));
        let facts: Vec<&TimedFact> = vec![&f1];
        let mut filter = BTreeMap::new();
        filter.insert("custom_flag".to_owned(), Value::Bool(true));
        let motif = EntityPattern::Typed {
            entity_type: "user".to_owned(),
            filter,
        };
        assert!(motif.matches(&EntityId("user:bob".to_owned()), &facts));
    }
}
