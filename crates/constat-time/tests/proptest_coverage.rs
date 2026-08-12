//! Tests par propriétés sur le modèle temporel (§12) — « le point le plus
//! subtil du produit ».
//!
//! Invariants vérifiés sur entrées générées :
//!
//! 1. `observed_ppm ≤ 1_000_000` ;
//! 2. somme des durées (segments inférés + trous) = durée de la période ;
//! 3. trous du rapport jamais chevauchants, toujours dans la période ;
//! 4. une observation dans une interruption déclarée est une contradiction
//!    détectée ;
//! 5. monotonie : ajouter une observation ne diminue jamais la couverture.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use constat_model::{DurationMs, Timestamp};
use constat_time::{build_coverage, coverage_report, Coverage, Gap, GapReason, Period, TimeError};
use proptest::prelude::*;

/// Échelle des instants générés : assez large pour des configurations
/// variées, assez resserrée pour que observations et interruptions se
/// rencontrent souvent.
const SCALE: i64 = 1_000_000;

fn arb_period() -> impl Strategy<Value = Period> {
    (-SCALE..SCALE, 0i64..SCALE).prop_map(|(from, len)| Period {
        from: Timestamp(from),
        to: Timestamp(from + len),
    })
}

fn arb_observations() -> impl Strategy<Value = Vec<Timestamp>> {
    prop::collection::vec((-SCALE..SCALE).prop_map(Timestamp), 0..48)
}

fn arb_reason() -> impl Strategy<Value = GapReason> {
    prop_oneof![
        Just(GapReason::AgentDown),
        Just(GapReason::MachineOff),
        Just(GapReason::CollectFailed),
        Just(GapReason::RetentionPurge),
        Just(GapReason::Unknown),
    ]
}

fn arb_gaps() -> impl Strategy<Value = Vec<Gap>> {
    prop::collection::vec(
        (-SCALE..SCALE, 0i64..SCALE / 4, arb_reason()).prop_map(|(from, len, reason)| Gap {
            from: Timestamp(from),
            to: Timestamp(from + len),
            reason,
        }),
        0..8,
    )
}

/// Écarte les observations qui tomberaient à l'intérieur strict d'une
/// interruption déclarée — la contradiction est testée à part.
fn drop_contradictory(obs: Vec<Timestamp>, gaps: &[Gap]) -> Vec<Timestamp> {
    obs.into_iter()
        .filter(|t| !gaps.iter().any(|g| g.from < *t && *t < g.to))
        .collect()
}

proptest! {
    /// Invariant 1 : le ppm est borné — jamais plus que la période entière.
    #[test]
    fn ppm_borne_a_un_million(
        period in arb_period(),
        obs in arb_observations(),
        gaps in arb_gaps(),
        max_gap in 0u64..(SCALE as u64),
    ) {
        let obs = drop_contradictory(obs, &gaps);
        let report = coverage_report(period, &obs, &gaps, DurationMs(max_gap))
            .expect("entrées valides");
        prop_assert!(report.observed_ppm <= 1_000_000);
    }

    /// Invariant 2 : les segments partitionnent exactement la période —
    /// contigus, ordonnés, somme des durées égale à la durée de la période.
    #[test]
    fn partition_exacte_de_la_periode(
        period in arb_period(),
        obs in arb_observations(),
        gaps in arb_gaps(),
        max_gap in 0u64..(SCALE as u64),
    ) {
        let obs = drop_contradictory(obs, &gaps);
        let cov = build_coverage(period, &obs, &gaps, DurationMs(max_gap))
            .expect("entrées valides");

        let mut cursor = period.from;
        let mut sum: u128 = 0;
        for c in &cov {
            match c {
                Coverage::Observed { at } => {
                    prop_assert!(period.contains(*at));
                }
                Coverage::Inferred { from, to, .. } | Coverage::Gap { from, to, .. } => {
                    prop_assert_eq!(*from, cursor, "segments contigus");
                    prop_assert!(from < to, "segments de mesure non nulle");
                    sum += (i128::from(to.0) - i128::from(from.0)) as u128;
                    cursor = *to;
                }
            }
        }
        prop_assert_eq!(cursor, period.to, "la partition atteint la fin de la période");
        let total = (i128::from(period.to.0) - i128::from(period.from.0)) as u128;
        prop_assert_eq!(sum, total, "somme des durées = durée de la période");
    }

    /// Invariant 3 : les trous du rapport sont triés, non chevauchants,
    /// bornés à la période, de durée non nulle.
    #[test]
    fn trous_du_rapport_bien_formes(
        period in arb_period(),
        obs in arb_observations(),
        gaps in arb_gaps(),
        max_gap in 0u64..(SCALE as u64),
    ) {
        let obs = drop_contradictory(obs, &gaps);
        let report = coverage_report(period, &obs, &gaps, DurationMs(max_gap))
            .expect("entrées valides");

        for g in &report.gaps {
            prop_assert!(g.from < g.to);
            prop_assert!(g.from >= period.from);
            prop_assert!(g.to <= period.to);
        }
        for w in report.gaps.windows(2) {
            prop_assert!(w[0].to <= w[1].from, "trous non chevauchants et triés");
        }
    }

    /// Invariant 4 : une observation à l'intérieur strict d'une interruption
    /// déclarée est une contradiction détectée, jamais résolue en silence.
    #[test]
    fn contradiction_detectee(
        period in arb_period(),
        gap_from in -SCALE..SCALE,
        gap_len in 2i64..(SCALE / 4),
        reason in arb_reason(),
        offset in 1i64..(SCALE / 4),
    ) {
        let gap = Gap {
            from: Timestamp(gap_from),
            to: Timestamp(gap_from + gap_len),
            reason,
        };
        // un instant strictement intérieur, quel que soit l'offset généré
        let at = Timestamp(gap_from + 1 + offset % (gap_len - 1));
        let err = build_coverage(period, &[at], &[gap], DurationMs(10));
        let is_contradiction = matches!(
            err,
            Err(TimeError::ObservationInDeclaredGap { .. })
        );
        prop_assert!(is_contradiction, "attendu : contradiction détectée");
    }

    /// Invariant 5 : monotonie — ajouter une observation (hors interruption
    /// déclarée) ne diminue jamais la couverture.
    #[test]
    fn ajouter_une_observation_ne_diminue_jamais(
        period in arb_period(),
        obs in arb_observations(),
        gaps in arb_gaps(),
        max_gap in 0u64..(SCALE as u64),
        extra in -SCALE..SCALE,
    ) {
        let obs = drop_contradictory(obs, &gaps);
        let extra = Timestamp(extra);
        prop_assume!(!gaps.iter().any(|g| g.from < extra && extra < g.to));

        let before = coverage_report(period, &obs, &gaps, DurationMs(max_gap))
            .expect("entrées valides")
            .observed_ppm;

        let mut augmented = obs.clone();
        augmented.push(extra);
        let after = coverage_report(period, &augmented, &gaps, DurationMs(max_gap))
            .expect("entrées valides")
            .observed_ppm;

        prop_assert!(after >= before, "couverture avant={before} après={after}");
    }

    /// Robustesse : l'ordre des observations et des interruptions n'a aucune
    /// influence sur le résultat — déterminisme (§1).
    #[test]
    fn independant_de_l_ordre_des_entrees(
        period in arb_period(),
        obs in arb_observations(),
        gaps in arb_gaps(),
        max_gap in 0u64..(SCALE as u64),
    ) {
        let obs = drop_contradictory(obs, &gaps);
        let cov1 = build_coverage(period, &obs, &gaps, DurationMs(max_gap));

        let mut obs_rev = obs.clone();
        obs_rev.reverse();
        let mut gaps_rev = gaps.clone();
        gaps_rev.reverse();
        let cov2 = build_coverage(period, &obs_rev, &gaps_rev, DurationMs(max_gap));

        prop_assert_eq!(cov1, cov2);
    }
}
