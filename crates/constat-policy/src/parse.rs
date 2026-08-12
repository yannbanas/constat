//! Parsing du YAML d'assertions (§5.2) — pur : le YAML arrive en `&str`,
//! aucune entrée-sortie.
//!
//! Le fichier d'assertions de la spécification parse tel quel. Les erreurs
//! sont lisibles : position (ligne, colonne) et extrait de la ligne fautive.
//! La validation a lieu **à la construction** : une exception sans date
//! d'expiration, une durée illisible ou un prédicat vide sont refusés ici,
//! pas au moment de l'évaluation.

use crate::dates::parse_date;
use crate::duration::parse_duration;
use crate::error::PolicyError;
use crate::{Assertion, Predicate, MAX_PREDICATE_DEPTH};
use serde::Deserialize;
use std::collections::BTreeSet;

/// Document racine : `assertions:` suivi d'une liste.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionsFile {
    assertions: Vec<Assertion>,
}

/// Erreur YAML enrichie : position et extrait de la ligne fautive.
fn yaml_error(source: &str, err: &serde_yaml::Error) -> PolicyError {
    let location = err.location();
    let line = location.as_ref().map(serde_yaml::Location::line);
    let column = location.as_ref().map(serde_yaml::Location::column);
    let mut message = match (line, column) {
        (Some(l), Some(c)) => format!("YAML invalide (ligne {l}, colonne {c}) : {err}"),
        _ => format!("YAML invalide : {err}"),
    };
    if let (Some(l), Some(c)) = (line, column) {
        if let Some(text) = source.lines().nth(l.saturating_sub(1)) {
            let caret_pad = " ".repeat(c.saturating_sub(1));
            let _ = std::fmt::Write::write_fmt(
                &mut message,
                format_args!("\n  {l:>4} | {text}\n       | {caret_pad}^"),
            );
        }
    }
    PolicyError::Yaml {
        message,
        line,
        column,
    }
}

/// Parse un document YAML d'assertions et **valide** chaque assertion.
///
/// Le YAML attendu est celui de la spécification (§5.2) :
///
/// ```yaml
/// assertions:
///   - id: SSH-ROOT
///     title: la connexion root en SSH est désactivée
///     scope: { os: linux }
///     predicate:
///       never: { entity: "service:sshd", attr: "sshd.PermitRootLogin", equals: "yes" }
/// ```
///
/// # Erreurs
///
/// - [`PolicyError::Yaml`] : syntaxe ou structure invalide, avec ligne,
///   colonne et extrait de la ligne fautive ;
/// - [`PolicyError::InvalidAssertion`] : exception sans date d'expiration
///   (une exception permanente n'est pas une exception, §5.2), justification
///   ou approbateur vides, durée `than` illisible, `and`/`or` vides ;
/// - [`PolicyError::DuplicateAssertionId`] : deux assertions de même `id` ;
/// - [`PolicyError::PredicateTooDeep`] : imbrication au-delà de
///   [`MAX_PREDICATE_DEPTH`].
pub fn parse_assertions(yaml: &str) -> Result<Vec<Assertion>, PolicyError> {
    let file: AssertionsFile = serde_yaml::from_str(yaml).map_err(|e| yaml_error(yaml, &e))?;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for a in &file.assertions {
        if !seen.insert(a.id.0.as_str()) {
            return Err(PolicyError::DuplicateAssertionId { id: a.id.0.clone() });
        }
        validate_assertion(a)?;
    }
    Ok(file.assertions)
}

/// Valide une assertion : identifiant, prédicat, exceptions.
///
/// Appelée par [`parse_assertions`] ; utile aussi pour des assertions
/// construites programmatiquement.
///
/// # Erreurs
///
/// Voir [`parse_assertions`].
pub fn validate_assertion(a: &Assertion) -> Result<(), PolicyError> {
    let invalid = |reason: String| PolicyError::InvalidAssertion {
        assertion: if a.id.0.trim().is_empty() {
            "(sans id)".to_owned()
        } else {
            a.id.0.clone()
        },
        reason,
    };
    if a.id.0.trim().is_empty() {
        return Err(invalid("identifiant vide".to_owned()));
    }
    if a.title.trim().is_empty() {
        return Err(invalid("titre vide".to_owned()));
    }
    validate_predicate(&a.predicate, 0).map_err(|e| match e {
        PolicyError::PredicateTooDeep { .. } => e,
        PolicyError::InvalidAssertion { reason, .. } => invalid(reason),
        other => invalid(other.to_string()),
    })?;
    for (i, exc) in a.exceptions.iter().enumerate() {
        let place = format!("exception n°{}", i + 1);
        if exc.entity.trim().is_empty() {
            return Err(invalid(format!("{place} : entité vide")));
        }
        if exc.reason.trim().is_empty() {
            return Err(invalid(format!(
                "{place} : une exception doit être justifiée (« reason » vide)"
            )));
        }
        if exc.approved_by.trim().is_empty() {
            return Err(invalid(format!(
                "{place} : approbateur manquant (« approved_by » vide)"
            )));
        }
        if exc.expires.trim().is_empty() {
            return Err(invalid(format!(
                "{place} : une exception sans date d'expiration est refusée — \
                 une exception permanente est un changement de politique non assumé (§5.2)"
            )));
        }
        parse_date(&exc.expires).map_err(|e| invalid(format!("{place} : {e}")))?;
    }
    Ok(())
}

/// Valide récursivement un prédicat : profondeur bornée, durées lisibles,
/// conjonctions/disjonctions non vides.
fn validate_predicate(p: &Predicate, depth: usize) -> Result<(), PolicyError> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(PolicyError::PredicateTooDeep {
            max: MAX_PREDICATE_DEPTH,
        });
    }
    match p {
        Predicate::Fresher { than, .. } => {
            parse_duration(than)?;
        }
        Predicate::ForAll { satisfies, .. } => validate_predicate(satisfies, depth + 1)?,
        Predicate::Not(inner) => validate_predicate(inner, depth + 1)?,
        Predicate::And(children) => {
            if children.is_empty() {
                return Err(PolicyError::InvalidAssertion {
                    assertion: String::new(),
                    reason: "« and » vide — un prédicat sans branche ne vérifie rien".to_owned(),
                });
            }
            for c in children {
                validate_predicate(c, depth + 1)?;
            }
        }
        Predicate::Or(children) => {
            if children.is_empty() {
                return Err(PolicyError::InvalidAssertion {
                    assertion: String::new(),
                    reason: "« or » vide — il serait toujours faux".to_owned(),
                });
            }
            for c in children {
                validate_predicate(c, depth + 1)?;
            }
        }
        Predicate::Never { .. } | Predicate::Always { .. } | Predicate::Exists { .. } => {}
    }
    Ok(())
}
