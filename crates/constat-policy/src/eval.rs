//! Moteur d'évaluation — pur, total, terminant (§5.1, §5.3).
//!
//! L'évaluation prend une assertion, les faits datés d'une machine et le
//! rapport de couverture de la période, et rend un [`Evaluation`] : un
//! verdict **accompagné de sa couverture**, jamais un simple booléen.
//!
//! # Sémantique de l'absence (§3.2)
//!
//! « L'attribut n'existe pas » et « l'attribut vaut faux » sont deux choses
//! différentes. Concrètement :
//!
//! - `never … equals: v` : une entité **sans** le fait ne viole jamais la
//!   règle — l'absence n'est pas égale à `v` ;
//! - `always … equals: v` sur une entité **explicitement sélectionnée**
//!   (motif `entity` ou liaison `forall`) : l'absence du fait est une
//!   violation, `observed = Absent` — on ne peut pas affirmer la conformité
//!   d'un fait qu'on n'a jamais vu ;
//! - `always … equals: v` **sans** motif ni liaison : la règle porte sur les
//!   entités qui possèdent l'attribut (« partout où il est observé, il vaut
//!   `v` ») ;
//! - `fresher` : l'absence de toute valeur est une violation — on ne peut pas
//!   attester la fraîcheur de ce qu'on n'a jamais observé.
//!
//! # Verdict `Undetermined`
//!
//! Si aucune violation ne subsiste mais que la couverture observée est
//! inférieure au seuil ([`EvaluationOptions::min_observed_ppm`], défaut
//! [`DEFAULT_MIN_OBSERVED_PPM`]), le verdict est `Undetermined` : la
//! couverture était insuffisante pour se prononcer. Une violation
//! **observée** reste en revanche une violation : une couverture faible ne
//! blanchit jamais un constat, le verdict est alors `Fail`.

use crate::dates::parse_date;
use crate::duration::{format_duration, parse_duration};
use crate::error::PolicyError;
use crate::explain::format_value;
use crate::{
    AppliedException, Assertion, EntityPattern, Evaluation, Predicate, Verdict, Violation,
    MAX_PREDICATE_DEPTH,
};
use constat_model::{AssetId, Attribute, BlobHash, EntityId, Fact, Timestamp, Value};
use constat_time::{CoverageReport, Period};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Seuil de couverture par défaut : 950 000 ppm, soit 95 %.
///
/// Pourquoi 95 % : avec une collecte quotidienne, une interruption d'agent
/// d'un jour et demi sur un mois laisse environ 95 % de couverture observée.
/// En dessous, affirmer « conforme sur la période » deviendrait trompeur —
/// l'outil rend alors `Undetermined` et déclare ses trous (§4.2).
/// Le seuil est paramétrable via [`EvaluationOptions`].
pub const DEFAULT_MIN_OBSERVED_PPM: u32 = 950_000;

/// Empreinte nulle : aucun artefact associé.
///
/// Utilisée quand la violation constate une **absence** (aucune entité ne
/// correspond, aucun fait ne porte l'attribut) : il n'existe alors, par
/// construction, aucun blob de preuve à citer.
pub const NO_EVIDENCE: BlobHash = BlobHash([0u8; 32]);

/// Un fait accompagné de son intervalle d'observation et de sa preuve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimedFact {
    /// Le triplet entité-attribut-valeur.
    pub fact: Fact,
    /// Première observation de cette valeur sur la période.
    pub first_seen: Timestamp,
    /// Dernière observation de cette valeur sur la période.
    pub last_seen: Timestamp,
    /// Empreinte du blob contenant l'artefact brut (la preuve).
    pub evidence: BlobHash,
}

/// Entrée d'évaluation : une machine, ses faits datés, la couverture de la
/// période, et la date d'évaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationInput {
    /// Machine évaluée. Le filtrage par [`crate::AssetSelector`] (portée de
    /// l'assertion) est à la charge de l'appelant.
    pub asset: AssetId,
    /// Faits observés sur la période, avec leurs intervalles et leurs preuves.
    pub facts: Vec<TimedFact>,
    /// Rapport de couverture de la période (produit par `constat-time`).
    pub coverage: CoverageReport,
    /// Date d'évaluation : sert aux prédicats `fresher` et à l'expiration des
    /// exceptions. Typiquement la borne haute de la période.
    pub at: Timestamp,
}

impl EvaluationInput {
    /// Construit une entrée dont la date d'évaluation est la fin de la
    /// période couverte — le cas usuel.
    #[must_use]
    pub fn new(asset: AssetId, facts: Vec<TimedFact>, coverage: CoverageReport) -> Self {
        let at = coverage.period.to;
        Self {
            asset,
            facts,
            coverage,
            at,
        }
    }
}

/// Paramètres d'évaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationOptions {
    /// Couverture observée minimale (en parties par million) pour accepter de
    /// prononcer `Pass`. En dessous, un résultat sans violation devient
    /// `Undetermined`. Défaut : [`DEFAULT_MIN_OBSERVED_PPM`] (95 %).
    pub min_observed_ppm: u32,
}

impl Default for EvaluationOptions {
    fn default() -> Self {
        Self {
            min_observed_ppm: DEFAULT_MIN_OBSERVED_PPM,
        }
    }
}

/// Témoin interne : un fait qui **soutient** un prédicat vrai. Sert à
/// construire des violations explicites quand un `not` renverse le verdict.
struct Witness {
    entity: EntityId,
    attr: Option<Attribute>,
    value: Value,
    first_seen: Timestamp,
    last_seen: Timestamp,
    evidence: BlobHash,
}

/// Résultat interne de l'évaluation d'un prédicat.
struct Outcome {
    holds: bool,
    violations: Vec<Violation>,
    witnesses: Vec<Witness>,
}

impl Outcome {
    fn holding() -> Self {
        Self {
            holds: true,
            violations: Vec::new(),
            witnesses: Vec::new(),
        }
    }
}

/// Contexte d'évaluation : faits indexés par entité (ordre déterministe).
struct Ctx<'a> {
    asset: &'a AssetId,
    entities: BTreeMap<&'a EntityId, Vec<&'a TimedFact>>,
    at: Timestamp,
    period: Period,
}

impl<'a> Ctx<'a> {
    fn facts_of(&self, e: &EntityId) -> &[&'a TimedFact] {
        self.entities.get(e).map_or(&[], Vec::as_slice)
    }

    /// Bornes d'observation et preuve « par défaut » d'une entité (utilisées
    /// quand la violation porte sur un fait manquant : la preuve citée est
    /// alors celle de l'existence de l'entité).
    fn entity_span(&self, e: &EntityId) -> (Timestamp, Timestamp, BlobHash) {
        let fs = self.facts_of(e);
        let mut first = Timestamp(i64::MAX);
        let mut last = Timestamp(i64::MIN);
        for f in fs {
            first = first.min(f.first_seen);
            last = last.max(f.last_seen);
        }
        let evidence = fs.first().map_or(NO_EVIDENCE, |f| f.evidence);
        if fs.is_empty() {
            (self.period.from, self.period.to, NO_EVIDENCE)
        } else {
            (first, last, evidence)
        }
    }
}

/// Entités candidates : la liaison `forall` restreint à l'entité liée, le
/// motif filtre ensuite.
fn candidates<'a>(
    ctx: &Ctx<'a>,
    pattern: Option<&EntityPattern>,
    bound: Option<&'a EntityId>,
) -> Vec<&'a EntityId> {
    let base: Vec<&'a EntityId> = match bound {
        Some(b) => match ctx.entities.get_key_value(b) {
            Some((k, _)) => vec![*k],
            None => vec![],
        },
        None => ctx.entities.keys().copied().collect(),
    };
    match pattern {
        None => base,
        Some(p) => base
            .into_iter()
            .filter(|e| p.matches(e, ctx.facts_of(e)))
            .collect(),
    }
}

/// Portée d'un prédicat attributaire (`always`, `fresher`) et exigence de
/// présence du fait — voir la sémantique de l'absence en tête de module.
fn attr_scope<'a>(
    ctx: &Ctx<'a>,
    entity: Option<&EntityPattern>,
    attr: &Attribute,
    bound: Option<&'a EntityId>,
) -> (Vec<&'a EntityId>, bool) {
    match (entity, bound) {
        (Some(p), _) => (candidates(ctx, Some(p), bound), true),
        (None, Some(_)) => (candidates(ctx, None, bound), true),
        (None, None) => (
            ctx.entities
                .iter()
                .filter(|(_, fs)| fs.iter().any(|f| f.fact.attribute == *attr))
                .map(|(e, _)| *e)
                .collect(),
            false,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn violation(
    ctx: &Ctx<'_>,
    entity: EntityId,
    observed: Value,
    expected: Value,
    first_seen: Timestamp,
    last_seen: Timestamp,
    evidence: BlobHash,
    detail: String,
) -> Violation {
    Violation {
        asset: ctx.asset.clone(),
        entity,
        observed,
        expected,
        first_seen,
        last_seen,
        evidence,
        detail,
    }
}

fn witness_of(f: &TimedFact) -> Witness {
    Witness {
        entity: f.fact.entity.clone(),
        attr: Some(f.fact.attribute.clone()),
        value: f.fact.value.clone(),
        first_seen: f.first_seen,
        last_seen: f.last_seen,
        evidence: f.evidence,
    }
}

/// Référence temporelle d'un fait pour `fresher` : si la valeur est un entier,
/// elle est interprétée comme une date (millisecondes d'époque, §15) — c'est
/// la convention des collecteurs (`backup.last_success`). Sinon, la fraîcheur
/// est celle de la dernière observation du fait.
fn freshness_ref(f: &TimedFact) -> i64 {
    match f.fact.value {
        Value::Int(ts) => ts,
        _ => f.last_seen.0,
    }
}

/// Évalue récursivement un prédicat. Total et terminant : la structure est
/// finie, la profondeur bornée par [`MAX_PREDICATE_DEPTH`], aucune boucle.
fn eval_predicate(
    pred: &Predicate,
    ctx: &Ctx<'_>,
    bound: Option<&EntityId>,
    depth: usize,
) -> Result<Outcome, PolicyError> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(PolicyError::PredicateTooDeep {
            max: MAX_PREDICATE_DEPTH,
        });
    }
    match pred {
        // -- never : aucune entité correspondante ne doit porter attr == equals
        Predicate::Never {
            entity,
            attr,
            equals,
        } => {
            let mut out = Outcome::holding();
            for e in candidates(ctx, Some(entity), bound) {
                for f in ctx.facts_of(e).iter().filter(|f| f.fact.attribute == *attr) {
                    if f.fact.value == *equals {
                        out.violations.push(violation(
                            ctx,
                            e.clone(),
                            f.fact.value.clone(),
                            // Convention : pour « never », `expected` porte la
                            // valeur interdite (l'attendu est « toute autre
                            // valeur ») ; `detail` l'explicite.
                            equals.clone(),
                            f.first_seen,
                            f.last_seen,
                            f.evidence,
                            format!(
                                "valeur interdite {} observée pour « {} » — la règle exige : jamais {}",
                                format_value(&f.fact.value),
                                attr.0,
                                format_value(equals)
                            ),
                        ));
                    } else {
                        out.witnesses.push(witness_of(f));
                    }
                }
            }
            out.holds = out.violations.is_empty();
            Ok(out)
        }

        // -- always : chaque entité de la portée doit porter attr == equals
        Predicate::Always {
            entity,
            attr,
            equals,
        } => {
            let (ents, require_presence) = attr_scope(ctx, entity.as_ref(), attr, bound);
            let mut out = Outcome::holding();
            for e in ents {
                let with_attr: Vec<&&TimedFact> = ctx
                    .facts_of(e)
                    .iter()
                    .filter(|f| f.fact.attribute == *attr)
                    .collect();
                if with_attr.is_empty() {
                    if require_presence {
                        let (first, last, evidence) = ctx.entity_span(e);
                        out.violations.push(violation(
                            ctx,
                            e.clone(),
                            Value::Absent,
                            equals.clone(),
                            first,
                            last,
                            evidence,
                            format!(
                                "« {} » n'a jamais été observé sur cette entité — \
                                 l'absence n'est pas la conformité (§3.2), {} était attendu",
                                attr.0,
                                format_value(equals)
                            ),
                        ));
                    }
                    continue;
                }
                for f in with_attr {
                    if f.fact.value == *equals {
                        out.witnesses.push(witness_of(f));
                    } else {
                        let detail = if f.fact.value == Value::Absent {
                            format!(
                                "« {} » est explicitement absent alors que {} était attendu \
                                 (absence ≠ {})",
                                attr.0,
                                format_value(equals),
                                format_value(equals)
                            )
                        } else {
                            format!(
                                "« {} » vaut {} au lieu de {} attendu",
                                attr.0,
                                format_value(&f.fact.value),
                                format_value(equals)
                            )
                        };
                        out.violations.push(violation(
                            ctx,
                            e.clone(),
                            f.fact.value.clone(),
                            equals.clone(),
                            f.first_seen,
                            f.last_seen,
                            f.evidence,
                            detail,
                        ));
                    }
                }
            }
            out.holds = out.violations.is_empty();
            Ok(out)
        }

        // -- forall : lie chaque entité du motif et évalue le sous-prédicat
        Predicate::ForAll { over, satisfies } => {
            let mut out = Outcome::holding();
            for e in candidates(ctx, Some(over), bound) {
                let child = eval_predicate(satisfies, ctx, Some(e), depth + 1)?;
                if !child.holds {
                    out.holds = false;
                }
                out.violations.extend(child.violations);
                out.witnesses.extend(child.witnesses);
            }
            // Zéro entité correspondante : vrai par vacuité. La question
            // « y en a-t-il au moins une ? » relève de `exists`, et la
            // question « en a-t-on assez vu ? » relève de la couverture.
            Ok(out)
        }

        // -- exists : au moins une entité correspond au motif
        Predicate::Exists { matching } => {
            let ents = candidates(ctx, Some(matching), bound);
            if ents.is_empty() {
                let detail = format!(
                    "aucune entité ne correspond au motif {} sur la période",
                    matching.display()
                );
                Ok(Outcome {
                    holds: false,
                    violations: vec![violation(
                        ctx,
                        EntityId(matching.display()),
                        Value::Absent,
                        Value::Text("au moins une entité correspondante".to_owned()),
                        ctx.period.from,
                        ctx.period.to,
                        NO_EVIDENCE,
                        detail,
                    )],
                    witnesses: Vec::new(),
                })
            } else {
                let mut out = Outcome::holding();
                for e in ents {
                    if let Some(f) = ctx.facts_of(e).first() {
                        out.witnesses.push(witness_of(f));
                    }
                }
                Ok(out)
            }
        }

        // -- fresher : la valeur la plus récente doit dater de moins de `than`
        Predicate::Fresher { entity, attr, than } => {
            let than_ms = parse_duration(than)?;
            let (ents, _) = attr_scope(ctx, entity.as_ref(), attr, bound);
            let mut out = Outcome::holding();
            if ents.is_empty() {
                // Personne ne porte l'attribut (ou le motif ne matche rien) :
                // on ne peut pas attester la fraîcheur → violation d'absence.
                let subject = entity
                    .as_ref()
                    .map_or_else(|| "*".to_owned(), |p| p.display());
                out.violations.push(violation(
                    ctx,
                    EntityId(subject),
                    Value::Absent,
                    Value::Text(format!(
                        "une valeur de « {} » datant de moins de {}",
                        attr.0,
                        format_duration(than_ms)
                    )),
                    ctx.period.from,
                    ctx.period.to,
                    NO_EVIDENCE,
                    format!(
                        "aucune valeur de « {} » observée sur la période — \
                         impossible d'attester une fraîcheur de moins de {}",
                        attr.0,
                        format_duration(than_ms)
                    ),
                ));
            }
            for e in ents {
                let best = ctx
                    .facts_of(e)
                    .iter()
                    .filter(|f| f.fact.attribute == *attr)
                    .max_by_key(|f| freshness_ref(f))
                    .copied();
                match best {
                    None => {
                        // entité explicitement sélectionnée mais sans le fait
                        let (first, last, evidence) = ctx.entity_span(e);
                        out.violations.push(violation(
                            ctx,
                            e.clone(),
                            Value::Absent,
                            Value::Text(format!(
                                "une valeur de « {} » datant de moins de {}",
                                attr.0,
                                format_duration(than_ms)
                            )),
                            first,
                            last,
                            evidence,
                            format!(
                                "« {} » n'a jamais été observé sur cette entité — \
                                 impossible d'attester une fraîcheur de moins de {}",
                                attr.0,
                                format_duration(than_ms)
                            ),
                        ));
                    }
                    Some(f) => {
                        let reference = freshness_ref(f);
                        let age = i128::from(ctx.at.0) - i128::from(reference);
                        if age <= i128::from(than_ms.0) {
                            out.witnesses.push(witness_of(f));
                        } else {
                            let age_ms = u64::try_from(age).unwrap_or(u64::MAX);
                            out.violations.push(violation(
                                ctx,
                                e.clone(),
                                f.fact.value.clone(),
                                Value::Text(format!(
                                    "une valeur de « {} » datant de moins de {}",
                                    attr.0,
                                    format_duration(than_ms)
                                )),
                                f.first_seen,
                                f.last_seen,
                                f.evidence,
                                format!(
                                    "la dernière valeur de « {} » date de {} \
                                     (seuil : {})",
                                    attr.0,
                                    format_duration(constat_model::DurationMs(age_ms)),
                                    format_duration(than_ms)
                                ),
                            ));
                        }
                    }
                }
            }
            out.holds = out.violations.is_empty();
            Ok(out)
        }

        // -- and : tous les enfants doivent tenir
        Predicate::And(children) => {
            let mut out = Outcome::holding();
            for c in children {
                let child = eval_predicate(c, ctx, bound, depth + 1)?;
                if !child.holds {
                    out.holds = false;
                }
                out.violations.extend(child.violations);
                out.witnesses.extend(child.witnesses);
            }
            Ok(out)
        }

        // -- or : au moins un enfant doit tenir
        Predicate::Or(children) => {
            let mut evaluated = Vec::with_capacity(children.len());
            for c in children {
                evaluated.push(eval_predicate(c, ctx, bound, depth + 1)?);
            }
            if evaluated.iter().any(|o| o.holds) {
                let witnesses = evaluated
                    .into_iter()
                    .filter(|o| o.holds)
                    .flat_map(|o| o.witnesses)
                    .collect();
                Ok(Outcome {
                    holds: true,
                    violations: Vec::new(),
                    witnesses,
                })
            } else {
                // toutes les branches échouent : on explique chacune
                let mut violations: Vec<Violation> =
                    evaluated.into_iter().flat_map(|o| o.violations).collect();
                if violations.is_empty() {
                    violations.push(violation(
                        ctx,
                        EntityId(format!("asset:{}", ctx.asset.0)),
                        Value::Absent,
                        Value::Text("au moins une branche du « or » satisfaite".to_owned()),
                        ctx.period.from,
                        ctx.period.to,
                        NO_EVIDENCE,
                        "aucune branche du « or » n'est satisfaite".to_owned(),
                    ));
                }
                Ok(Outcome {
                    holds: false,
                    violations,
                    witnesses: Vec::new(),
                })
            }
        }

        // -- not : renverse le verdict ; les témoins du prédicat interne
        //    deviennent les violations, pour que l'échec reste expliqué
        Predicate::Not(inner) => {
            let child = eval_predicate(inner, ctx, bound, depth + 1)?;
            if child.holds {
                let mut violations: Vec<Violation> = child
                    .witnesses
                    .iter()
                    .map(|w| {
                        let attr_txt = w
                            .attr
                            .as_ref()
                            .map_or_else(String::new, |a| format!(" pour « {} »", a.0));
                        violation(
                            ctx,
                            w.entity.clone(),
                            w.value.clone(),
                            Value::Text("la négation du prédicat interne".to_owned()),
                            w.first_seen,
                            w.last_seen,
                            w.evidence,
                            format!(
                                "le prédicat interne est vérifié ({}{} = {}) \
                                 alors que sa négation était attendue",
                                w.entity.0,
                                attr_txt,
                                format_value(&w.value)
                            ),
                        )
                    })
                    .collect();
                if violations.is_empty() {
                    violations.push(violation(
                        ctx,
                        EntityId(format!("asset:{}", ctx.asset.0)),
                        Value::Absent,
                        Value::Text("la négation du prédicat interne".to_owned()),
                        ctx.period.from,
                        ctx.period.to,
                        NO_EVIDENCE,
                        "le prédicat interne est vérifié alors que sa négation était attendue"
                            .to_owned(),
                    ));
                }
                Ok(Outcome {
                    holds: false,
                    violations,
                    witnesses: Vec::new(),
                })
            } else {
                Ok(Outcome::holding())
            }
        }
    }
}

/// Évalue une assertion avec les paramètres par défaut
/// ([`EvaluationOptions::default`]).
///
/// Voir [`evaluate_with`].
///
/// # Erreurs
///
/// [`PolicyError`] si l'assertion elle-même est mal formée (durée `than`
/// illisible, date d'expiration illisible, prédicat trop profond). Les
/// assertions issues de [`crate::parse_assertions`] sont déjà validées : ces
/// erreurs ne peuvent alors pas se produire.
pub fn evaluate(assertion: &Assertion, input: &EvaluationInput) -> Result<Evaluation, PolicyError> {
    evaluate_with(assertion, input, &EvaluationOptions::default())
}

/// Évalue une assertion sur une machine — fonction **pure** : deux appels sur
/// les mêmes données rendent exactement le même [`Evaluation`].
///
/// Déroulé :
///
/// 1. le prédicat est évalué sur les faits datés (sémantique de l'absence en
///    tête de module) ;
/// 2. chaque violation dont l'entité correspond à une exception **non
///    expirée** à la date `input.at` est neutralisée, mais reste tracée dans
///    [`Evaluation::applied_exceptions`] ; une exception expirée ne
///    neutralise plus rien ;
/// 3. verdict : `Fail` s'il reste une violation (une couverture faible ne
///    blanchit jamais un constat) ; sinon `Undetermined` si la couverture
///    observée est sous le seuil ; sinon `Pass`.
///
/// La portée (`scope`) de l'assertion n'est **pas** vérifiée ici : le choix
/// des machines à évaluer appartient à l'appelant.
///
/// # Erreurs
///
/// Voir [`evaluate`].
pub fn evaluate_with(
    assertion: &Assertion,
    input: &EvaluationInput,
    options: &EvaluationOptions,
) -> Result<Evaluation, PolicyError> {
    let mut entities: BTreeMap<&EntityId, Vec<&TimedFact>> = BTreeMap::new();
    for f in &input.facts {
        entities.entry(&f.fact.entity).or_default().push(f);
    }
    let ctx = Ctx {
        asset: &input.asset,
        entities,
        at: input.at,
        period: input.coverage.period,
    };

    let outcome = eval_predicate(&assertion.predicate, &ctx, None, 0)?;

    // Exceptions : pré-parse des dates d'expiration (erreur lisible si une
    // assertion construite à la main porte une date illisible).
    let mut active_exceptions = Vec::with_capacity(assertion.exceptions.len());
    for exc in &assertion.exceptions {
        let expires_at = parse_date(&exc.expires)?;
        active_exceptions.push((exc, expires_at));
    }

    let mut violations = Vec::new();
    let mut applied_exceptions = Vec::new();
    for v in outcome.violations {
        let neutralizing = active_exceptions
            .iter()
            .find(|(exc, expires_at)| input.at < *expires_at && exc.matches(&v.entity));
        match neutralizing {
            Some((exc, _)) => applied_exceptions.push(AppliedException {
                exception: (*exc).clone(),
                neutralized: v,
            }),
            None => violations.push(v),
        }
    }

    let verdict = if violations.is_empty() {
        if input.coverage.observed_ppm < options.min_observed_ppm {
            Verdict::Undetermined
        } else {
            Verdict::Pass
        }
    } else {
        Verdict::Fail
    };

    Ok(Evaluation {
        assertion: assertion.id.clone(),
        title: assertion.title.clone(),
        asset: Some(input.asset.clone()),
        verdict,
        coverage: input.coverage.clone(),
        violations,
        applied_exceptions,
    })
}
