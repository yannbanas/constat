//! Cas de la spécification, testés tels quels.
//!
//! Le plus important : §13 S2 — « arrêter un agent pendant six heures, et
//! vérifier que le rapport déclare honnêtement l'interruption au lieu de la
//! masquer ».

#![allow(clippy::unwrap_used, clippy::expect_used)]

use constat_model::{DurationMs, Timestamp};
use constat_time::{
    build_coverage, coverage_report, value_history, Coverage, Gap, GapReason, Period,
    ValueObservation,
};

const HOUR: i64 = 3_600_000;
const DAY: i64 = 24 * HOUR;

/// §13 S2 : agent arrêté six heures → le rapport déclare l'interruption.
#[test]
fn s2_agent_arrete_six_heures_interruption_declaree() {
    let period = Period {
        from: Timestamp(0),
        to: Timestamp(DAY),
    };
    // Collecte horaire, sauf entre 08:00 et 14:00 (agent arrêté).
    let observations: Vec<Timestamp> = (0..=24)
        .filter(|h| !(9..=13).contains(h))
        .map(|h| Timestamp(h * HOUR))
        .collect();
    let declared = [Gap {
        from: Timestamp(8 * HOUR),
        to: Timestamp(14 * HOUR),
        reason: GapReason::AgentDown,
    }];

    let report = coverage_report(
        period,
        &observations,
        &declared,
        DurationMs(2 * HOUR as u64),
    )
    .expect("le rapport doit se construire");

    // L'interruption est déclarée, avec sa vraie raison — jamais masquée.
    assert_eq!(
        report.gaps,
        vec![Gap {
            from: Timestamp(8 * HOUR),
            to: Timestamp(14 * HOUR),
            reason: GapReason::AgentDown,
        }]
    );
    // 18 h couvertes sur 24 : 750 000 ppm, en arithmétique entière exacte.
    assert_eq!(report.observed_ppm, 750_000);
    // Le plus grand écart entre deux collectes : les six heures d'arrêt.
    assert_eq!(report.max_gap, DurationMs(6 * HOUR as u64));
}

/// Le même arrêt, non déclaré : le trou apparaît quand même, en `Unknown`.
/// Un outil qui masque ses angles morts détruit sa valeur probante (§18.5).
#[test]
fn s2_arret_non_declare_reste_un_trou() {
    let period = Period {
        from: Timestamp(0),
        to: Timestamp(DAY),
    };
    let observations: Vec<Timestamp> = (0..=24)
        .filter(|h| !(9..=13).contains(h))
        .map(|h| Timestamp(h * HOUR))
        .collect();

    let report = coverage_report(period, &observations, &[], DurationMs(2 * HOUR as u64))
        .expect("le rapport doit se construire");

    assert_eq!(report.observed_ppm, 750_000);
    assert_eq!(
        report.gaps,
        vec![Gap {
            from: Timestamp(8 * HOUR),
            to: Timestamp(14 * HOUR),
            reason: GapReason::Unknown,
        }]
    );
}

/// §4.1 : le piège de l'instantané. Une collecte quotidienne avec un seuil
/// horaire ne doit PAS affirmer la couverture — tout l'intervalle est un trou.
#[test]
fn le_piege_de_l_instantane_est_evite() {
    let period = Period {
        from: Timestamp(0),
        to: Timestamp(2 * DAY),
    };
    let observations = [Timestamp(0), Timestamp(DAY), Timestamp(2 * DAY)];
    // Seuil d'inférence : 1 h. Les collectes sont à 24 h d'écart.
    let report = coverage_report(period, &observations, &[], DurationMs(HOUR as u64))
        .expect("le rapport doit se construire");
    assert_eq!(report.observed_ppm, 0);
    assert_eq!(report.max_gap, DurationMs(DAY as u64));
    // Deux trous distincts : la collecte de minuit au milieu reste visible.
    assert_eq!(report.gaps.len(), 2);
}

/// §10.1 : `constat history` sur `user.privileged` — deux changements
/// encadrés, avec la couverture de la période.
#[test]
fn history_jdupont_privilegie() {
    let period = Period {
        from: Timestamp(0),
        to: Timestamp(10 * DAY),
    };
    let mut observations: Vec<ValueObservation<bool>> = Vec::new();
    for d in 0..=10 {
        let at = Timestamp(d * DAY);
        // privilégié entre le jour 3 et le jour 7 inclus
        observations.push(ValueObservation {
            at,
            value: (3..=7).contains(&d),
        });
    }

    let h = value_history(period, &observations, &[], DurationMs(2 * DAY as u64))
        .expect("l'historique doit se construire");

    assert_eq!(h.changes.len(), 2);
    assert!(!h.changes[0].before);
    assert!(h.changes[0].after);
    assert_eq!(h.changes[0].last_seen_before, Timestamp(2 * DAY));
    assert_eq!(h.changes[0].first_seen_after, Timestamp(3 * DAY));
    assert!(h.changes[1].before);
    assert!(!h.changes[1].after);

    assert_eq!(h.intervals.len(), 3);
    // chaque plage porte sa couverture
    for interval in &h.intervals {
        assert!(!interval.coverage.is_empty() || interval.first_seen == interval.last_seen);
    }
}

/// La séquence de couverture partitionne exactement la période, dans l'ordre.
#[test]
fn la_couverture_partitionne_la_periode() {
    let period = Period {
        from: Timestamp(0),
        to: Timestamp(DAY),
    };
    let observations = [
        Timestamp(-HOUR),
        Timestamp(2 * HOUR),
        Timestamp(3 * HOUR),
        Timestamp(20 * HOUR),
        Timestamp(DAY + HOUR),
    ];
    let declared = [Gap {
        from: Timestamp(5 * HOUR),
        to: Timestamp(7 * HOUR),
        reason: GapReason::MachineOff,
    }];
    let cov = build_coverage(
        period,
        &observations,
        &declared,
        DurationMs(4 * HOUR as u64),
    )
    .expect("la couverture doit se construire");

    let mut cursor = period.from;
    let mut sum: u64 = 0;
    for c in &cov {
        match c {
            Coverage::Observed { at } => assert!(period.contains(*at)),
            Coverage::Inferred { from, to, .. } | Coverage::Gap { from, to, .. } => {
                assert_eq!(
                    *from, cursor,
                    "segments contigus, sans trou ni recouvrement"
                );
                assert!(from < to);
                sum += (to.0 - from.0) as u64;
                cursor = *to;
            }
        }
    }
    assert_eq!(cursor, period.to);
    assert_eq!(sum, DAY as u64);
}
