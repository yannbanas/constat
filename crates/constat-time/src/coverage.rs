//! Construction de la couverture temporelle (§4 de la spécification).
//!
//! Le principe : **des intervalles avec couverture, pas des points**. À partir
//! d'observations datées et d'interruptions déclarées, on produit une
//! séquence chronologique de [`Coverage`] qui partitionne exactement la
//! période — chaque milliseconde est soit inférée, soit déclarée manquante,
//! jamais passée sous silence.
//!
//! Règles de construction, dans l'ordre :
//!
//! 1. entre deux observations consécutives espacées d'au plus
//!    `max_expected_gap` : [`Coverage::Inferred`], porteur de l'écart réel ;
//! 2. entre deux observations trop espacées, avant la première ou après la
//!    dernière : [`Coverage::Gap`] avec [`GapReason::Unknown`] — un trou
//!    constaté mais non expliqué ;
//! 3. une interruption déclarée l'emporte sur l'inférence : même encadrée par
//!    deux observations, la plage déclarée devient [`Coverage::Gap`] avec la
//!    raison déclarée. Déclarer un arrêt d'agent, c'est renoncer à inférer ;
//! 4. une observation à l'intérieur **strict** d'une interruption déclarée
//!    est une contradiction : la construction échoue, elle ne tranche pas.

use constat_model::{DurationMs, Timestamp};

use crate::error::TimeError;
use crate::interval::span_ms;
use crate::{Coverage, CoverageReport, Gap, GapReason, Period};

/// Segment interne non ponctuel, avant assemblage en [`Coverage`].
#[derive(Clone)]
enum SegKind {
    Inferred(DurationMs),
    Gap(GapReason),
}

/// Normalise une liste d'interruptions déclarées : validées, triées par début
/// croissant, sans chevauchement.
///
/// - Deux interruptions qui se recouvrent ou se touchent avec la **même**
///   raison sont fusionnées.
/// - En cas de recouvrement entre raisons différentes, la première déclarée
///   (au sens du tri par bornes) l'emporte sur la zone commune ; la suivante
///   est tronquée à ce qui dépasse. Règle arbitraire mais **déterministe** :
///   mêmes entrées, même résultat, quelle que soit leur ordre d'arrivée.
/// - Les interruptions ponctuelles (`from == to`) sont conservées telles
///   quelles : de mesure nulle, elles n'affectent pas la couverture mais
///   restent des déclarations.
///
/// # Erreurs
///
/// [`TimeError::InvalidGap`] si une interruption a `from > to`.
pub fn normalize_gaps(declared: &[Gap]) -> Result<Vec<Gap>, TimeError> {
    for g in declared {
        if g.from > g.to {
            return Err(TimeError::InvalidGap {
                from: g.from,
                to: g.to,
            });
        }
    }
    let mut sorted: Vec<Gap> = declared.to_vec();
    sorted.sort_by_key(|g| (g.from, g.to, g.reason.clone()));

    let mut out: Vec<Gap> = Vec::with_capacity(sorted.len());
    for g in sorted {
        let Some(last) = out.last_mut() else {
            out.push(g);
            continue;
        };
        if g.from > last.to {
            out.push(g);
        } else if g.reason == last.reason {
            if g.to > last.to {
                last.to = g.to;
            }
        } else if g.to > last.to {
            // raisons différentes : la zone commune reste à la première,
            // la suivante ne garde que ce qui dépasse.
            let from = last.to;
            out.push(Gap {
                from,
                to: g.to,
                reason: g.reason,
            });
        }
        // sinon : g est entièrement recouverte par une déclaration antérieure.
    }
    Ok(out)
}

/// Vérifie qu'aucune observation ne tombe à l'intérieur strict d'une
/// interruption déclarée. `gaps` doit être normalisé (trié, sans
/// chevauchement) — voir [`normalize_gaps`].
fn check_observations_against_gaps(
    observations: &[Timestamp],
    gaps: &[Gap],
) -> Result<(), TimeError> {
    for &at in observations {
        // gaps triés par `from` et disjoints : l'unique candidate est la
        // dernière interruption dont le début précède strictement `at`.
        let idx = gaps.partition_point(|g| g.from < at);
        if idx > 0 {
            let g = &gaps[idx - 1];
            if at < g.to {
                return Err(TimeError::ObservationInDeclaredGap {
                    at,
                    gap_from: g.from,
                    gap_to: g.to,
                });
            }
        }
    }
    Ok(())
}

/// Construit la séquence de couverture d'une période.
///
/// # Entrées
///
/// - `period` : la période interrogée, bornes incluses ;
/// - `observations` : instants de collecte, **triés ou non**, doublons admis,
///   y compris hors période — une observation juste avant `period.from` et
///   une juste après `period.to` peuvent encadrer la période entière ;
/// - `declared_gaps` : interruptions déclarées (agent arrêté, machine
///   éteinte…), dans n'importe quel ordre, chevauchements admis ;
/// - `max_expected_gap` : écart maximal entre deux collectes au-delà duquel
///   on refuse d'inférer « pas de changement ».
///
/// # Sortie
///
/// Une séquence chronologique où :
///
/// - chaque observation dans la période apparaît comme
///   [`Coverage::Observed`] (point de mesure nulle), placée avant le segment
///   qui commence à cet instant ;
/// - les segments [`Coverage::Inferred`] et [`Coverage::Gap`] **partitionnent
///   exactement** `[period.from, period.to]` : la somme de leurs durées vaut
///   la durée de la période, ils sont contigus, ordonnés, jamais chevauchants ;
/// - chaque `Inferred` porte dans `max_gap` l'écart réel entre les deux
///   collectes qui l'encadrent — même si le segment a été rogné par la
///   période ou découpé par une interruption déclarée, l'écart affiché reste
///   celui des vraies collectes ;
/// - les trous non déclarés portent [`GapReason::Unknown`].
///
/// # Erreurs
///
/// - [`TimeError::InvalidPeriod`] si `period.from > period.to` ;
/// - [`TimeError::InvalidGap`] si une interruption déclarée est mal formée ;
/// - [`TimeError::ObservationInDeclaredGap`] si une observation (même hors
///   période) tombe à l'intérieur strict d'une interruption déclarée — une
///   contradiction n'est jamais résolue en silence.
pub fn build_coverage(
    period: Period,
    observations: &[Timestamp],
    declared_gaps: &[Gap],
    max_expected_gap: DurationMs,
) -> Result<Vec<Coverage>, TimeError> {
    if period.from > period.to {
        return Err(TimeError::InvalidPeriod {
            from: period.from,
            to: period.to,
        });
    }

    let mut obs: Vec<Timestamp> = observations.to_vec();
    obs.sort_unstable();
    obs.dedup();

    let gaps = normalize_gaps(declared_gaps)?;
    check_observations_against_gaps(&obs, &gaps)?;

    // Interruptions bornées à la période ; celles de mesure nulle disparaissent
    // de la couverture (elles ne retirent rien).
    let gaps: Vec<Gap> = gaps
        .into_iter()
        .filter_map(|g| {
            let from = g.from.max(period.from);
            let to = g.to.min(period.to);
            (from < to).then_some(Gap {
                from,
                to,
                reason: g.reason,
            })
        })
        .collect();

    // 1. Segments de base, issus des seules observations, rognés à la période.
    let mut base: Vec<(Timestamp, Timestamp, SegKind)> = Vec::new();
    if obs.is_empty() {
        if period.from < period.to {
            base.push((period.from, period.to, SegKind::Gap(GapReason::Unknown)));
        }
    } else {
        if let Some(&first) = obs.first() {
            let to = first.min(period.to);
            if period.from < to {
                base.push((period.from, to, SegKind::Gap(GapReason::Unknown)));
            }
        }
        for w in obs.windows(2) {
            let (a, b) = (w[0], w[1]);
            let from = a.max(period.from);
            let to = b.min(period.to);
            if from < to {
                let spacing = span_ms(a, b);
                let kind = if spacing <= max_expected_gap.0 {
                    SegKind::Inferred(DurationMs(spacing))
                } else {
                    SegKind::Gap(GapReason::Unknown)
                };
                base.push((from, to, kind));
            }
        }
        if let Some(&last) = obs.last() {
            let from = last.max(period.from);
            if from < period.to {
                base.push((from, period.to, SegKind::Gap(GapReason::Unknown)));
            }
        }
    }

    // 2. Soustraction des interruptions déclarées : sur la zone recouverte,
    //    la déclaration remplace l'inférence.
    let mut segs: Vec<(Timestamp, Timestamp, SegKind)> = Vec::new();
    let mut gi = 0usize;
    for (bf, bt, kind) in base {
        while gi < gaps.len() && gaps[gi].to <= bf {
            gi += 1;
        }
        let mut cursor = bf;
        let mut j = gi;
        while j < gaps.len() && gaps[j].from < bt {
            let gf = gaps[j].from.max(cursor);
            let gt = gaps[j].to.min(bt);
            if cursor < gf {
                segs.push((cursor, gf, kind.clone()));
            }
            if gf < gt {
                segs.push((gf, gt, SegKind::Gap(gaps[j].reason.clone())));
            }
            if gt > cursor {
                cursor = gt;
            }
            if gaps[j].to > bt {
                break;
            }
            j += 1;
        }
        if cursor < bt {
            segs.push((cursor, bt, kind));
        }
    }

    // 3. Fusion des trous adjacents de même raison — uniquement si aucune
    //    observation ne marque la jonction : une collecte réelle entre deux
    //    trous ne doit jamais être gommée.
    let obs_in: Vec<Timestamp> = obs
        .iter()
        .copied()
        .filter(|t| period.contains(*t))
        .collect();

    let mut merged: Vec<(Timestamp, Timestamp, SegKind)> = Vec::with_capacity(segs.len());
    for seg in segs {
        if let Some(last) = merged.last_mut() {
            let fusion = match (&last.2, &seg.2) {
                (SegKind::Gap(r1), SegKind::Gap(r2)) => {
                    r1 == r2 && last.1 == seg.0 && obs_in.binary_search(&seg.0).is_err()
                }
                _ => false,
            };
            if fusion {
                last.1 = seg.1;
                continue;
            }
        }
        merged.push(seg);
    }

    // 4. Entrelacement des points observés : chaque observation apparaît
    //    avant le segment qui commence à son instant.
    let mut out: Vec<Coverage> = Vec::with_capacity(merged.len() + obs_in.len());
    let mut oi = 0usize;
    for (from, to, kind) in merged {
        while oi < obs_in.len() && obs_in[oi] <= from {
            out.push(Coverage::Observed { at: obs_in[oi] });
            oi += 1;
        }
        out.push(match kind {
            SegKind::Inferred(max_gap) => Coverage::Inferred { from, to, max_gap },
            SegKind::Gap(reason) => Coverage::Gap { from, to, reason },
        });
    }
    while oi < obs_in.len() {
        out.push(Coverage::Observed { at: obs_in[oi] });
        oi += 1;
    }
    Ok(out)
}

/// Construit le [`CoverageReport`] d'une période à partir des données brutes.
///
/// Équivalent de [`build_coverage`] suivi de [`report_from_coverage`] :
/// mêmes entrées, mêmes erreurs. C'est la fonction que `constat-policy` et la
/// CLI appellent pour accompagner chaque verdict de sa couverture.
pub fn coverage_report(
    period: Period,
    observations: &[Timestamp],
    declared_gaps: &[Gap],
    max_expected_gap: DurationMs,
) -> Result<CoverageReport, TimeError> {
    let coverage = build_coverage(period, observations, declared_gaps, max_expected_gap)?;
    Ok(report_from_coverage(period, &coverage))
}

/// Agrège une séquence de couverture en [`CoverageReport`].
///
/// - `observed_ppm` : part de la période couverte par les segments
///   [`Coverage::Inferred`], en parties par million, **arithmétique entière
///   exclusivement** (`u128` intermédiaire, division entière tronquée —
///   jamais arrondie vers le haut : on ne surestime pas une couverture).
///   Cas limite : une période de durée nulle est couverte à `1_000_000` si un
///   point [`Coverage::Observed`] existe à cet instant, `0` sinon.
/// - `max_gap` : le plus grand écart entre deux collectes sur la période —
///   maximum des `max_gap` portés par les segments inférés et des durées des
///   trous (rognées à la période).
/// - `gaps` : tous les trous, déclarés ou non, **jamais masqués** — triés,
///   sans chevauchement, bornés à la période. Deux trous contigus de même
///   raison sont fusionnés — **sauf** si une observation réelle marque la
///   jonction : une collecte entre deux trous est un fait, on ne la gomme pas.
///
/// La séquence attendue est celle produite par [`build_coverage`] ; la
/// fonction reste néanmoins défensive (rognage à la période, tri) si on lui
/// donne une séquence quelconque.
#[must_use]
pub fn report_from_coverage(period: Period, coverage: &[Coverage]) -> CoverageReport {
    let total = u128::from(span_ms(period.from, period.to));
    let mut covered: u128 = 0;
    let mut max_gap_ms: u64 = 0;
    let mut any_point = false;
    let mut observed_points: Vec<Timestamp> = Vec::new();
    let mut raw_gaps: Vec<Gap> = Vec::new();

    for c in coverage {
        match c {
            Coverage::Observed { at } => {
                if period.contains(*at) {
                    any_point = true;
                    observed_points.push(*at);
                }
            }
            Coverage::Inferred { from, to, max_gap } => {
                let f = (*from).max(period.from);
                let t = (*to).min(period.to);
                if f <= t {
                    covered += u128::from(span_ms(f, t));
                    max_gap_ms = max_gap_ms.max(max_gap.0);
                }
            }
            Coverage::Gap { from, to, reason } => {
                let f = (*from).max(period.from);
                let t = (*to).min(period.to);
                if f < t {
                    max_gap_ms = max_gap_ms.max(span_ms(f, t));
                    raw_gaps.push(Gap {
                        from: f,
                        to: t,
                        reason: reason.clone(),
                    });
                }
            }
        }
    }

    observed_points.sort_unstable();
    observed_points.dedup();
    raw_gaps.sort_by_key(|g| (g.from, g.to, g.reason.clone()));

    // Fusion des trous : mêmes règles que la normalisation, à une exception
    // près — deux trous qui se touchent ne fusionnent pas si une observation
    // réelle marque la jonction.
    let mut gaps: Vec<Gap> = Vec::with_capacity(raw_gaps.len());
    for g in raw_gaps {
        let Some(last) = gaps.last_mut() else {
            gaps.push(g);
            continue;
        };
        if g.from > last.to {
            gaps.push(g);
            continue;
        }
        let junction_observed = g.from == last.to && observed_points.binary_search(&g.from).is_ok();
        if g.reason == last.reason && !junction_observed {
            if g.to > last.to {
                last.to = g.to;
            }
        } else if g.from == last.to {
            if g.to > g.from {
                gaps.push(g);
            }
        } else if g.to > last.to {
            // chevauchement défensif entre raisons différentes : la première
            // garde la zone commune, la suivante ce qui dépasse.
            let from = last.to;
            gaps.push(Gap {
                from,
                to: g.to,
                reason: g.reason,
            });
        }
        // sinon : trou entièrement recouvert, rien à ajouter.
    }

    let observed_ppm = if total == 0 {
        if any_point {
            1_000_000
        } else {
            0
        }
    } else {
        let capped = covered.min(total);
        // capped * 1_000_000 ≤ u64::MAX * 1_000_000 < u128::MAX : pas de débordement,
        // et le quotient est ≤ 1_000_000 donc tient dans un u32.
        u32::try_from(capped * 1_000_000 / total).unwrap_or(1_000_000)
    };

    CoverageReport {
        period,
        observed_ppm,
        max_gap: DurationMs(max_gap_ms),
        gaps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(t: i64) -> Timestamp {
        Timestamp(t)
    }

    fn p(from: i64, to: i64) -> Period {
        Period {
            from: ts(from),
            to: ts(to),
        }
    }

    #[test]
    fn periode_sans_observation_est_un_trou_inconnu() {
        let cov = build_coverage(p(0, 100), &[], &[], DurationMs(10));
        assert_eq!(
            cov,
            Ok(vec![Coverage::Gap {
                from: ts(0),
                to: ts(100),
                reason: GapReason::Unknown
            }])
        );
    }

    #[test]
    fn deux_observations_proches_inferent() {
        let cov = build_coverage(p(0, 100), &[ts(0), ts(100)], &[], DurationMs(200));
        assert_eq!(
            cov,
            Ok(vec![
                Coverage::Observed { at: ts(0) },
                Coverage::Inferred {
                    from: ts(0),
                    to: ts(100),
                    max_gap: DurationMs(100)
                },
                Coverage::Observed { at: ts(100) },
            ])
        );
    }

    #[test]
    fn ecart_trop_grand_devient_trou() {
        let cov = build_coverage(p(0, 100), &[ts(0), ts(100)], &[], DurationMs(50));
        assert_eq!(
            cov,
            Ok(vec![
                Coverage::Observed { at: ts(0) },
                Coverage::Gap {
                    from: ts(0),
                    to: ts(100),
                    reason: GapReason::Unknown
                },
                Coverage::Observed { at: ts(100) },
            ])
        );
    }

    #[test]
    fn observations_hors_periode_encadrent() {
        // observations juste avant et juste après : la période est inférée entière.
        let cov = build_coverage(p(10, 20), &[ts(0), ts(30)], &[], DurationMs(40));
        assert_eq!(
            cov,
            Ok(vec![Coverage::Inferred {
                from: ts(10),
                to: ts(20),
                max_gap: DurationMs(30)
            }])
        );
    }

    #[test]
    fn interruption_declaree_l_emporte_sur_l_inference() {
        let gap = Gap {
            from: ts(40),
            to: ts(60),
            reason: GapReason::AgentDown,
        };
        let cov = build_coverage(p(0, 100), &[ts(0), ts(100)], &[gap], DurationMs(1000));
        assert_eq!(
            cov,
            Ok(vec![
                Coverage::Observed { at: ts(0) },
                Coverage::Inferred {
                    from: ts(0),
                    to: ts(40),
                    max_gap: DurationMs(100)
                },
                Coverage::Gap {
                    from: ts(40),
                    to: ts(60),
                    reason: GapReason::AgentDown
                },
                Coverage::Inferred {
                    from: ts(60),
                    to: ts(100),
                    max_gap: DurationMs(100)
                },
                Coverage::Observed { at: ts(100) },
            ])
        );
    }

    #[test]
    fn observation_dans_interruption_est_une_contradiction() {
        let gap = Gap {
            from: ts(40),
            to: ts(60),
            reason: GapReason::AgentDown,
        };
        let err = build_coverage(p(0, 100), &[ts(50)], &[gap], DurationMs(1000));
        assert_eq!(
            err,
            Err(TimeError::ObservationInDeclaredGap {
                at: ts(50),
                gap_from: ts(40),
                gap_to: ts(60),
            })
        );
    }

    #[test]
    fn observation_sur_la_borne_d_une_interruption_est_admise() {
        let gap = Gap {
            from: ts(40),
            to: ts(60),
            reason: GapReason::AgentDown,
        };
        assert!(build_coverage(p(0, 100), &[ts(40), ts(60)], &[gap], DurationMs(1000)).is_ok());
    }

    #[test]
    fn normalisation_fusionne_et_tranche() {
        let gaps = [
            Gap {
                from: ts(10),
                to: ts(30),
                reason: GapReason::AgentDown,
            },
            Gap {
                from: ts(20),
                to: ts(50),
                reason: GapReason::AgentDown,
            },
            Gap {
                from: ts(40),
                to: ts(70),
                reason: GapReason::MachineOff,
            },
        ];
        let norm = normalize_gaps(&gaps).unwrap_or_default();
        assert_eq!(
            norm,
            vec![
                Gap {
                    from: ts(10),
                    to: ts(50),
                    reason: GapReason::AgentDown
                },
                Gap {
                    from: ts(50),
                    to: ts(70),
                    reason: GapReason::MachineOff
                },
            ]
        );
    }

    #[test]
    fn rapport_ppm_entier() {
        // 100 ms couvertes sur 400 → 250 000 ppm exactement.
        let report = coverage_report(p(0, 400), &[ts(0), ts(100)], &[], DurationMs(100));
        match report {
            Ok(r) => {
                assert_eq!(r.observed_ppm, 250_000);
                assert_eq!(r.max_gap, DurationMs(300));
                assert_eq!(r.gaps.len(), 1);
            }
            Err(e) => panic!("rapport inattendu : {e}"),
        }
    }

    #[test]
    fn rapport_periode_ponctuelle() {
        let full = coverage_report(p(5, 5), &[ts(5)], &[], DurationMs(1));
        let empty = coverage_report(p(5, 5), &[], &[], DurationMs(1));
        assert_eq!(full.map(|r| r.observed_ppm), Ok(1_000_000));
        assert_eq!(empty.map(|r| r.observed_ppm), Ok(0));
    }

    #[test]
    fn periode_invalide_refusee() {
        let err = build_coverage(p(10, 0), &[], &[], DurationMs(1));
        assert_eq!(
            err,
            Err(TimeError::InvalidPeriod {
                from: ts(10),
                to: ts(0)
            })
        );
    }
}
