//! Adaptateur entre le magasin et le moteur d'évaluation de `constat-policy`.
//!
//! Le moteur (`constat_policy::evaluate_with`) est **pur** et évalue une
//! machine à la fois. Ce module fait le travail d'assemblage :
//!
//! - transformer les observations du magasin en [`EvaluationInput`] par
//!   machine (faits datés par plages de stabilité, couverture par machine) ;
//! - appliquer la portée de l'assertion ([`scope_selects`]) — le moteur pur
//!   la laisse à l'appelant ;
//! - agréger les évaluations par machine en un verdict de parc ;
//! - dérouler la chronologie d'un verdict (`constat timeline`).
//!
//! ## La portée (`Assertion::scope`) sélectionne, elle ne présume pas
//!
//! Le filtrage repose sur les **faits d'inventaire** : des attributs
//! `asset.os`, `asset.tag` et `asset.domain` portés par l'entité
//! `asset:<nom de la machine>`. Une machine qui ne porte pas le fait exigé
//! par un critère du scope est **exclue** de l'évaluation de l'assertion :
//! on ne devine pas l'OS d'une machine qui ne l'a pas déclaré — sans fait,
//! pas de sélection. C'est cohérent avec le reste du produit : l'absence est
//! un état, jamais une supposition (§3.2).

use std::collections::BTreeMap;

use constat_model::{AssetId, Attribute, BlobHash, DurationMs, EntityId, Fact, Timestamp, Value};
use constat_policy::{
    evaluate_with, Assertion, AssetSelector, Evaluation, EvaluationInput, EvaluationOptions,
    PolicyError, TimedFact, Verdict,
};
use constat_time::{CoverageReport, Gap, Period, TimeError};

use crate::queries::Observation;

/// Construit une entrée d'évaluation par machine observée.
///
/// Équivalent de [`build_inputs_with_gaps`] sans interruption déclarée —
/// conservé tel quel pour les appelants existants.
pub fn build_inputs(
    obs: &[Observation],
    snapshot_times: &[(AssetId, Timestamp)],
    period: Period,
    threshold: DurationMs,
) -> Result<Vec<EvaluationInput>, TimeError> {
    build_inputs_with_gaps(obs, snapshot_times, &[], period, threshold)
}

/// Construit une entrée d'évaluation par machine observée.
///
/// Les faits sont regroupés en **plages de stabilité** : une [`TimedFact`]
/// par valeur consécutive identique d'un couple (entité, attribut), avec ses
/// dates de première et dernière observation et l'empreinte du blob de
/// preuve de la dernière. La couverture de chaque machine est calculée sur
/// ses propres dates de collecte, avec les interruptions déclarées
/// (aujourd'hui : les purges de rétention, [`crate::queries::purge_gaps`]) —
/// une période purgée pèse comme un trou `RetentionPurge` sur chaque machine.
pub fn build_inputs_with_gaps(
    obs: &[Observation],
    snapshot_times: &[(AssetId, Timestamp)],
    declared_gaps: &[Gap],
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
        let coverage =
            crate::coverage::coverage_report_declared(&times, declared_gaps, period, threshold)?;
        let facts = facts_by_asset.remove(&asset).unwrap_or_default();
        inputs.push(EvaluationInput::new(asset, facts, coverage));
    }
    Ok(inputs)
}

/// Attributs d'inventaire reconnus par la portée, dans l'ordre des champs
/// de [`AssetSelector`] : os, tag, domain.
const SCOPE_ATTRS: [&str; 3] = ["asset.os", "asset.tag", "asset.domain"];

/// Une valeur d'inventaire satisfait-elle un critère de portée ?
///
/// - texte : égalité stricte, ou n'importe quelle valeur si le critère est
///   `"*"` (le fait doit tout de même exister — voir la doc du module) ;
/// - liste : au moins un élément satisfait le critère (une machine porte
///   souvent plusieurs étiquettes) ;
/// - les autres types de valeur ne satisfont jamais un critère de portée.
fn scope_value_matches(value: &Value, wanted: &str) -> bool {
    match value {
        Value::Text(text) => wanted == "*" || text == wanted,
        Value::List(items) => items.iter().any(|v| scope_value_matches(v, wanted)),
        _ => false,
    }
}

/// Un critère de portée est-il satisfait par les faits d'inventaire de la
/// machine ? (`None` = pas de critère = satisfait.)
fn scope_criterion_ok(
    wanted: Option<&str>,
    attr: &str,
    asset: &AssetId,
    facts: &[TimedFact],
) -> bool {
    let Some(wanted) = wanted else {
        return true;
    };
    let entity = format!("asset:{}", asset.0);
    facts.iter().any(|tf| {
        tf.fact.entity.0 == entity
            && tf.fact.attribute.0 == attr
            && scope_value_matches(&tf.fact.value, wanted)
    })
}

/// La portée d'une assertion sélectionne-t-elle cette machine ?
///
/// Convention d'inventaire : faits d'attributs `asset.os`, `asset.tag`,
/// `asset.domain` sur l'entité `asset:<nom>`. Tous les critères présents
/// doivent être satisfaits (conjonction). **Le scope sélectionne, il ne
/// présume pas** : une machine sans le fait requis est exclue de
/// l'évaluation de l'assertion (voir la doc du module).
pub fn scope_selects(scope: &AssetSelector, asset: &AssetId, facts: &[TimedFact]) -> bool {
    let criteria = [
        scope.os.as_deref(),
        scope.tag.as_deref(),
        scope.domain.as_deref(),
    ];
    criteria
        .iter()
        .zip(SCOPE_ATTRS)
        .all(|(wanted, attr)| scope_criterion_ok(*wanted, attr, asset, facts))
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

/// Accumulateur incrémental d'un verdict de parc — l'équivalent **fenêtré**
/// de [`evaluate_park_with`], machine par machine.
///
/// Au lieu de recevoir d'un coup toutes les entrées du parc (et donc de garder
/// en mémoire toutes leurs observations), on les intègre une à une avec
/// [`observe`](ParkAccumulator::observe) puis on clôt avec
/// [`finish`](ParkAccumulator::finish). Le pic mémoire de `constat check`
/// tombe ainsi de « tout le parc » à « une machine » : une fois une machine
/// intégrée, ses observations sont libérées, seul l'état agrégé (verdict,
/// violations restantes, exceptions appliquées) survit.
///
/// La sémantique est **strictement identique** à [`evaluate_park_with`] — qui
/// est d'ailleurs réécrite en fonction de ce type, pour que les deux chemins
/// ne puissent pas diverger : un `Fail` n'est jamais blanchi, `Undetermined`
/// dès qu'une couverture est insuffisante et qu'aucun `Fail` n'existe, et
/// `Undetermined` aussi sur un périmètre vide ([`merge_verdicts`]).
#[derive(Debug, Default)]
pub struct ParkAccumulator {
    saw_fail: bool,
    saw_undetermined: bool,
    /// Au moins une machine a été retenue par la portée : sans cela, le
    /// périmètre est vide et le verdict reste `Undetermined`.
    in_scope: bool,
    violations: Vec<constat_policy::Violation>,
    applied_exceptions: Vec<constat_policy::AppliedException>,
}

impl ParkAccumulator {
    /// Intègre une machine : applique la portée ([`scope_selects`]) puis, si
    /// la machine est retenue, l'évalue et accumule son verdict, ses
    /// violations et ses exceptions appliquées. Miroir exact du corps de
    /// boucle de [`evaluate_park_with`].
    pub fn observe(
        &mut self,
        assertion: &Assertion,
        input: &EvaluationInput,
        options: &EvaluationOptions,
    ) -> Result<(), PolicyError> {
        if !scope_selects(&assertion.scope, &input.asset, &input.facts) {
            return Ok(());
        }
        let e = evaluate_with(assertion, input, options)?;
        self.in_scope = true;
        match e.verdict {
            Verdict::Fail => self.saw_fail = true,
            Verdict::Undetermined => self.saw_undetermined = true,
            Verdict::Pass => {}
        }
        self.violations.extend(e.violations);
        self.applied_exceptions.extend(e.applied_exceptions);
        Ok(())
    }

    /// Le verdict agrégé — reproduit exactement [`merge_verdicts`] sur la
    /// suite des verdicts des machines retenues (un `Fail` domine ; sinon un
    /// périmètre vide ou un `Undetermined` donne `Undetermined` ; sinon `Pass`).
    fn verdict(&self) -> Verdict {
        if self.saw_fail {
            Verdict::Fail
        } else if !self.in_scope || self.saw_undetermined {
            Verdict::Undetermined
        } else {
            Verdict::Pass
        }
    }

    /// Clôt l'accumulation en une [`Evaluation`] de parc portée par la
    /// couverture de parc fournie.
    pub fn finish(self, assertion: &Assertion, park_coverage: CoverageReport) -> Evaluation {
        Evaluation {
            assertion: assertion.id.clone(),
            title: assertion.title.clone(),
            asset: None,
            verdict: self.verdict(),
            coverage: park_coverage,
            violations: self.violations,
            applied_exceptions: self.applied_exceptions,
        }
    }
}

/// Évalue une assertion sur tout le parc (toutes les entrées par machine),
/// et agrège en une évaluation unique portée par la couverture de parc.
///
/// La portée de l'assertion est appliquée ici ([`scope_selects`]) : les
/// machines hors portée — ou sans le fait d'inventaire requis — sont
/// exclues. Si aucune machine n'est sélectionnée, le verdict est
/// `Undetermined` : on ne se prononce pas sur un périmètre vide.
///
/// Chemin « tout en mémoire » : conservé pour les appelants qui disposent
/// déjà de toutes les entrées (`constat pack`, tests). `constat check`, lui,
/// passe par [`ParkAccumulator`] pour ne jamais matérialiser tout le parc —
/// mais les deux partagent le même corps, gage qu'ils ne divergent pas.
pub fn evaluate_park_with(
    assertion: &Assertion,
    inputs: &[EvaluationInput],
    park_coverage: CoverageReport,
    options: &EvaluationOptions,
) -> Result<Evaluation, PolicyError> {
    let mut acc = ParkAccumulator::default();
    for input in inputs {
        acc.observe(assertion, input, options)?;
    }
    Ok(acc.finish(assertion, park_coverage))
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
            // La portée s'applique aussi à l'état ponctuel : une machine
            // hors scope (ou sans fait d'inventaire) n'entre pas dans la
            // chronologie de l'assertion.
            if !scope_selects(&assertion.scope, &asset, &facts) {
                continue;
            }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use constat_policy::AssertionId;

    fn timed(asset_entity: &str, attr: &str, value: Value) -> TimedFact {
        TimedFact {
            fact: Fact {
                entity: EntityId(asset_entity.to_string()),
                attribute: Attribute(attr.to_string()),
                value,
            },
            first_seen: Timestamp(0),
            last_seen: Timestamp(1000),
            evidence: BlobHash([0; 32]),
        }
    }

    fn selector(os: Option<&str>, tag: Option<&str>, domain: Option<&str>) -> AssetSelector {
        AssetSelector {
            os: os.map(str::to_string),
            tag: tag.map(str::to_string),
            domain: domain.map(str::to_string),
        }
    }

    #[test]
    fn le_scope_selectionne_par_fait_d_inventaire() {
        let asset = AssetId("srv-01".to_string());
        let facts = vec![
            timed("asset:srv-01", "asset.os", Value::Text("linux".into())),
            timed(
                "asset:srv-01",
                "asset.domain",
                Value::Text("interne".into()),
            ),
        ];
        assert!(scope_selects(&selector(None, None, None), &asset, &facts));
        assert!(scope_selects(
            &selector(Some("linux"), None, None),
            &asset,
            &facts
        ));
        // Conjonction : os ET domaine.
        assert!(scope_selects(
            &selector(Some("linux"), None, Some("interne")),
            &asset,
            &facts
        ));
        // Mauvais OS : exclue.
        assert!(!scope_selects(
            &selector(Some("windows"), None, None),
            &asset,
            &facts
        ));
        // Le fait d'un AUTRE actif ne sélectionne pas celui-ci.
        assert!(!scope_selects(
            &selector(Some("linux"), None, None),
            &AssetId("srv-02".to_string()),
            &facts
        ));
    }

    #[test]
    fn une_machine_sans_le_fait_requis_est_exclue() {
        // Le scope sélectionne, il ne présume pas : pas de fait `asset.os`,
        // pas de sélection — même avec un joker.
        let asset = AssetId("srv-mystere".to_string());
        let facts = vec![timed("user:root", "user.privileged", Value::Bool(true))];
        assert!(!scope_selects(
            &selector(Some("linux"), None, None),
            &asset,
            &facts
        ));
        assert!(!scope_selects(
            &selector(None, None, Some("*")),
            &asset,
            &facts
        ));
        // Sans aucun critère, en revanche, toute machine est dans la portée.
        assert!(scope_selects(&selector(None, None, None), &asset, &facts));
    }

    #[test]
    fn le_joker_et_les_listes_d_etiquettes() {
        let asset = AssetId("srv-01".to_string());
        let facts = vec![
            timed(
                "asset:srv-01",
                "asset.domain",
                Value::Text("prod.local".into()),
            ),
            timed(
                "asset:srv-01",
                "asset.tag",
                Value::List(vec![
                    Value::Text("production".into()),
                    Value::Text("sauvegarde".into()),
                ]),
            ),
        ];
        // `"*"` exige la présence du fait, quelle que soit sa valeur.
        assert!(scope_selects(
            &selector(None, None, Some("*")),
            &asset,
            &facts
        ));
        // Une étiquette parmi la liste suffit.
        assert!(scope_selects(
            &selector(None, Some("production"), None),
            &asset,
            &facts
        ));
        assert!(!scope_selects(
            &selector(None, Some("test"), None),
            &asset,
            &facts
        ));
    }

    #[test]
    fn evaluate_park_exclut_les_machines_hors_scope() {
        let period = Period {
            from: Timestamp(0),
            to: Timestamp(1000),
        };
        let coverage = CoverageReport {
            period,
            observed_ppm: 1_000_000,
            max_gap: DurationMs(0),
            gaps: Vec::new(),
        };
        let violating = |asset: &str, with_os: Option<&str>| {
            let mut facts = vec![timed("user:root", "user.privileged", Value::Bool(true))];
            if let Some(os) = with_os {
                facts.push(timed(
                    &format!("asset:{asset}"),
                    "asset.os",
                    Value::Text(os.into()),
                ));
            }
            EvaluationInput::new(AssetId(asset.to_string()), facts, coverage.clone())
        };
        let assertion = Assertion {
            id: AssertionId("ADM-AUCUN".to_string()),
            title: "aucun compte privilégié".to_string(),
            scope: selector(Some("linux"), None, None),
            predicate: constat_policy::Predicate::Never {
                entity: constat_policy::EntityPattern::Glob("user:*".to_string()),
                attr: Attribute("user.privileged".to_string()),
                equals: Value::Bool(true),
            },
            exceptions: Vec::new(),
        };
        let inputs = vec![
            violating("srv-linux", Some("linux")), // dans la portée : violation comptée
            violating("srv-win", Some("windows")), // hors portée : exclue
            violating("srv-mystere", None),        // sans fait d'inventaire : exclue
        ];
        let e = evaluate_park(&assertion, &inputs, coverage.clone()).expect("évaluation");
        assert_eq!(e.verdict, Verdict::Fail);
        assert_eq!(e.violations.len(), 1);
        assert_eq!(e.violations[0].asset.0, "srv-linux");

        // Aucune machine dans la portée : on ne se prononce pas.
        let none = vec![violating("srv-win", Some("windows"))];
        let e = evaluate_park(&assertion, &none, coverage).expect("évaluation");
        assert_eq!(e.verdict, Verdict::Undetermined);
        assert!(e.violations.is_empty());
    }
}
