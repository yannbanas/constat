//! Adaptateur entre le magasin et le moteur d'évaluation de `constat-policy`.
//!
//! Le moteur (`constat_policy::evaluate_with`) est **pur** et évalue une
//! machine à la fois. Ce module fait le travail d'assemblage :
//!
//! - transformer les observations du magasin en [`EvaluationInput`] par
//!   machine (faits datés par plages de stabilité, couverture par machine) ;
//! - agréger les évaluations par machine en un verdict de parc ;
//! - dérouler la chronologie d'un verdict (`constat timeline`).
//!
//! TODO(integration) : la portée (`Assertion::scope`) n'est pas encore
//! appliquée — le moteur la laisse à l'appelant, et le filtrage exige les
//! faits d'inventaire (`asset.os`, `asset.tag`, `asset.domain`) que les
//! collecteurs ne produisent pas encore. Toutes les machines observées sont
//! donc évaluées.

use std::collections::BTreeMap;

use constat_model::{AssetId, Attribute, BlobHash, DurationMs, EntityId, Fact, Timestamp, Value};
use constat_policy::{
    evaluate_with, Assertion, Evaluation, EvaluationInput, EvaluationOptions, PolicyError,
    TimedFact, Verdict,
};
use constat_time::{CoverageReport, Period, TimeError};

use crate::queries::Observation;

/// Construit une entrée d'évaluation par machine observée.
///
/// Les faits sont regroupés en **plages de stabilité** : une [`TimedFact`]
/// par valeur consécutive identique d'un couple (entité, attribut), avec ses
/// dates de première et dernière observation et l'empreinte du blob de
/// preuve de la dernière. La couverture de chaque machine est calculée sur
/// ses propres dates de collecte.
pub fn build_inputs(
    obs: &[Observation],
    snapshot_times: &[(AssetId, Timestamp)],
    period: Period,
    threshold: DurationMs,
) -> Result<Vec<EvaluationInput>, TimeError> {
    // Dates de collecte par machine (le rognage à la période est fait par
    // le moteur de couverture).
    let mut times_by_asset: BTreeMap<AssetId, Vec<Timestamp>> = BTreeMap::new();
    for (asset, at) in snapshot_times {
        times_by_asset.entry(asset.clone()).or_default().push(*at);
    }

    // Séries temporelles par (machine, entité, attribut) — les observations
    // arrivent déjà triées par date de snapshot.
    type Series = Vec<(Timestamp, Value, BlobHash)>;
    let mut series: BTreeMap<(AssetId, EntityId, Attribute), Series> = BTreeMap::new();
    for o in obs {
        if o.at < period.from || o.at > period.to {
            continue;
        }
        series
            .entry((
                o.asset.clone(),
                o.fact.entity.clone(),
                o.fact.attribute.clone(),
            ))
            .or_default()
            .push((o.at, o.fact.value.clone(), o.blob));
    }

    // Plages de stabilité → TimedFact.
    let mut facts_by_asset: BTreeMap<AssetId, Vec<TimedFact>> = BTreeMap::new();
    for ((asset, entity, attr), list) in series {
        let mut i = 0;
        while i < list.len() {
            let mut j = i;
            while j + 1 < list.len() && list[j + 1].1 == list[i].1 {
                j += 1;
            }
            facts_by_asset
                .entry(asset.clone())
                .or_default()
                .push(TimedFact {
                    fact: Fact {
                        entity: entity.clone(),
                        attribute: attr.clone(),
                        value: list[i].1.clone(),
                    },
                    first_seen: list[i].0,
                    last_seen: list[j].0,
                    evidence: list[j].2,
                });
            i = j + 1;
        }
    }

    let mut inputs = Vec::new();
    for (asset, times) in times_by_asset {
        let coverage = crate::coverage::coverage_report(&times, period, threshold)?;
        let facts = facts_by_asset.remove(&asset).unwrap_or_default();
        inputs.push(EvaluationInput::new(asset, facts, coverage));
    }
    Ok(inputs)
}

/// Agrégation de verdicts : un constat (`Fail`) n'est jamais blanchi par une
/// couverture faible ailleurs ; sans aucune machine, on ne se prononce pas.
fn merge_verdicts(verdicts: &[Verdict]) -> Verdict {
    if verdicts.contains(&Verdict::Fail) {
        Verdict::Fail
    } else if verdicts.is_empty() || verdicts.contains(&Verdict::Undetermined) {
        Verdict::Undetermined
    } else {
        Verdict::Pass
    }
}

/// Évalue une assertion sur tout le parc (toutes les entrées par machine),
/// et agrège en une évaluation unique portée par la couverture de parc.
pub fn evaluate_park_with(
    assertion: &Assertion,
    inputs: &[EvaluationInput],
    park_coverage: CoverageReport,
    options: &EvaluationOptions,
) -> Result<Evaluation, PolicyError> {
    let mut verdicts = Vec::with_capacity(inputs.len());
    let mut violations = Vec::new();
    let mut applied_exceptions = Vec::new();
    for input in inputs {
        let e = evaluate_with(assertion, input, options)?;
        verdicts.push(e.verdict);
        violations.extend(e.violations);
        applied_exceptions.extend(e.applied_exceptions);
    }
    Ok(Evaluation {
        assertion: assertion.id.clone(),
        title: assertion.title.clone(),
        asset: None,
        verdict: merge_verdicts(&verdicts),
        coverage: park_coverage,
        violations,
        applied_exceptions,
    })
}

/// [`evaluate_park_with`] avec les paramètres par défaut du moteur
/// (couverture minimale de 95 % pour prononcer `Pass`).
pub fn evaluate_park(
    assertion: &Assertion,
    inputs: &[EvaluationInput],
    park_coverage: CoverageReport,
) -> Result<Evaluation, PolicyError> {
    evaluate_park_with(
        assertion,
        inputs,
        park_coverage,
        &EvaluationOptions::default(),
    )
}

/// Un segment de la chronologie d'une assertion : le verdict était constant
/// de `from` à `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineSegment {
    pub from: Timestamp,
    pub to: Timestamp,
    pub verdict: Verdict,
    /// Nombre de violations au pire point du segment.
    pub violations: usize,
}

/// Chronologie du verdict d'une assertion sur une période
/// (`constat timeline`).
///
/// À chaque date de collecte de la période, l'assertion est évaluée sur
/// l'**état ponctuel** : la dernière valeur connue de chaque (machine,
/// entité, attribut), dates d'origine conservées (les prédicats `fresher`
/// gardent donc leur sens). La couverture n'intervient pas ici — elle est
/// l'affaire de `constat check` ; la chronologie répond à « qu'aurait dit le
/// verdict à cette date ? ». Les verdicts consécutifs identiques sont
/// fusionnés en segments.
pub fn timeline(
    assertion: &Assertion,
    obs: &[Observation],
    snapshot_times: &[(AssetId, Timestamp)],
    period: Period,
) -> Result<Vec<TimelineSegment>, PolicyError> {
    let mut times: Vec<Timestamp> = snapshot_times
        .iter()
        .map(|(_, t)| *t)
        .filter(|t| *t >= period.from && *t <= period.to)
        .collect();
    times.sort();
    times.dedup();

    // La couverture ne doit pas forcer Undetermined sur un état ponctuel.
    let options = EvaluationOptions {
        min_observed_ppm: 0,
    };

    let mut points: Vec<(Timestamp, Verdict, usize)> = Vec::new();
    for &t in &times {
        // Dernière observation de chaque triplet, antérieure ou égale à t.
        let mut latest: BTreeMap<(AssetId, EntityId, Attribute), (Timestamp, Value, BlobHash)> =
            BTreeMap::new();
        for o in obs.iter().filter(|o| o.at <= t) {
            latest.insert(
                (
                    o.asset.clone(),
                    o.fact.entity.clone(),
                    o.fact.attribute.clone(),
                ),
                (o.at, o.fact.value.clone(), o.blob),
            );
        }
        let mut facts_by_asset: BTreeMap<AssetId, Vec<TimedFact>> = BTreeMap::new();
        for ((asset, entity, attr), (at, value, blob)) in latest {
            facts_by_asset.entry(asset).or_default().push(TimedFact {
                fact: Fact {
                    entity,
                    attribute: attr,
                    value,
                },
                first_seen: at,
                last_seen: at,
                evidence: blob,
            });
        }

        let window = Period {
            from: period.from.min(t),
            to: t,
        };
        let mut verdicts = Vec::new();
        let mut nviol = 0usize;
        for (asset, facts) in facts_by_asset {
            let coverage = CoverageReport {
                period: window,
                observed_ppm: 1_000_000, // état ponctuel : voir la rustdoc
                max_gap: DurationMs(0),
                gaps: Vec::new(),
            };
            let e = evaluate_with(
                assertion,
                &EvaluationInput::new(asset, facts, coverage),
                &options,
            )?;
            verdicts.push(e.verdict);
            nviol += e.violations.len();
        }
        points.push((t, merge_verdicts(&verdicts), nviol));
    }

    let mut segments: Vec<TimelineSegment> = Vec::new();
    for (i, (t, verdict, nv)) in points.iter().enumerate() {
        let next_change = points[i + 1..]
            .iter()
            .find(|(_, v, _)| v != verdict)
            .map(|(nt, _, _)| *nt);
        match segments.last_mut() {
            Some(last) if last.verdict == *verdict => {
                last.to = next_change.unwrap_or(period.to);
                last.violations = last.violations.max(*nv);
            }
            _ => segments.push(TimelineSegment {
                from: *t,
                to: next_change.unwrap_or(period.to),
                verdict: *verdict,
                violations: *nv,
            }),
        }
    }
    Ok(segments)
}
