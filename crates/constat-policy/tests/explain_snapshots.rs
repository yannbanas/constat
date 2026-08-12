//! Snapshots insta des explications humaines (§5.3) : le format est un
//! livrable — toute régression silencieuse doit casser un test.

#![allow(clippy::unwrap_used)]

use constat_model::{AssetId, Attribute, BlobHash, DurationMs, EntityId, Fact, Timestamp, Value};
use constat_policy::{
    evaluate, explain, parse_assertions, parse_date, Assertion, EvaluationInput, TimedFact,
};
use constat_time::{CoverageReport, Gap, GapReason, Period};

const SPEC_YAML: &str = r#"assertions:
  - id: SSH-ROOT
    title: la connexion root en SSH est désactivée
    scope: { os: linux }
    predicate:
      never: { entity: "service:sshd", attr: "sshd.PermitRootLogin", equals: "yes" }

  - id: ADM-MFA
    title: tous les comptes privilégiés ont l'authentification forte
    scope: { domain: "*" }
    predicate:
      forall:
        over: { type: user, where: { privileged: true } }
        satisfies:
          always: { attr: "user.mfa_enabled", equals: true }
    exceptions:
      - entity: "user:svc-sauvegarde"
        reason: "compte de service, authentification par certificat"
        approved_by: "RSSI"
        expires: 2027-01-01

  - id: BKP-24H
    title: sauvegarde réussie dans les dernières 24 heures
    scope: { tag: production }
    predicate:
      fresher: { attr: "backup.last_success", than: 24h }
"#;

fn ts(s: &str) -> Timestamp {
    parse_date(s).unwrap()
}

fn assertion(id: &str) -> Assertion {
    parse_assertions(SPEC_YAML)
        .unwrap()
        .into_iter()
        .find(|a| a.id.0 == id)
        .unwrap()
}

fn tf(entity: &str, attr: &str, value: Value, from: &str, to: &str, tag: u8) -> TimedFact {
    TimedFact {
        fact: Fact {
            entity: EntityId(entity.to_owned()),
            attribute: Attribute(attr.to_owned()),
            value,
        },
        first_seen: ts(from),
        last_seen: ts(to),
        evidence: BlobHash([tag; 32]),
    }
}

/// Couverture réaliste : 99,2 %, trois interruptions déclarées (cf. §4.2).
fn coverage_q1() -> CoverageReport {
    CoverageReport {
        period: Period {
            from: ts("2026-01-01"),
            to: ts("2026-03-31"),
        },
        observed_ppm: 992_000,
        max_gap: DurationMs(26 * 3_600_000),
        gaps: vec![
            Gap {
                from: ts("2026-02-12T03:00"),
                to: ts("2026-02-12T07:12"),
                reason: GapReason::MachineOff,
            },
            Gap {
                from: ts("2026-02-28T14:00"),
                to: ts("2026-02-28T14:45"),
                reason: GapReason::AgentDown,
            },
            Gap {
                from: ts("2026-03-03T01:00"),
                to: ts("2026-03-03T09:30"),
                reason: GapReason::AgentDown,
            },
        ],
    }
}

#[test]
fn explication_echec_ssh_root() {
    let a = assertion("SSH-ROOT");
    let inp = EvaluationInput::new(
        AssetId("srv-app-01".to_owned()),
        vec![tf(
            "service:sshd",
            "sshd.PermitRootLogin",
            Value::Text("yes".to_owned()),
            "2026-03-03T01:00",
            "2026-03-05T09:30",
            0x7f,
        )],
        coverage_q1(),
    );
    let ev = evaluate(&a, &inp).unwrap();
    insta::assert_snapshot!("echec_ssh_root", explain(&ev));
}

#[test]
fn explication_echec_mfa_avec_exception_appliquee() {
    let a = assertion("ADM-MFA");
    let inp = EvaluationInput::new(
        AssetId("srv-ad-01".to_owned()),
        vec![
            tf(
                "user:root",
                "user.privileged",
                Value::Bool(true),
                "2026-01-01",
                "2026-03-31",
                1,
            ),
            tf(
                "user:root",
                "user.mfa_enabled",
                Value::Bool(true),
                "2026-01-01",
                "2026-03-31",
                1,
            ),
            // jdupont : privilégié, MFA jamais observée → violation
            tf(
                "user:jdupont",
                "user.privileged",
                Value::Bool(true),
                "2026-01-15",
                "2026-03-31",
                2,
            ),
            // compte de service : violation neutralisée par l'exception
            tf(
                "user:svc-sauvegarde",
                "user.privileged",
                Value::Bool(true),
                "2026-01-01",
                "2026-03-31",
                4,
            ),
        ],
        coverage_q1(),
    );
    let ev = evaluate(&a, &inp).unwrap();
    insta::assert_snapshot!("echec_mfa_avec_exception", explain(&ev));
}

#[test]
fn explication_echec_sauvegarde_trop_vieille() {
    let a = assertion("BKP-24H");
    let mut inp = EvaluationInput::new(
        AssetId("srv-fic-02".to_owned()),
        vec![tf(
            "backup:principal",
            "backup.last_success",
            Value::Int(ts("2026-03-29T12:00").0),
            "2026-03-01",
            "2026-03-31",
            0xb8,
        )],
        coverage_q1(),
    );
    inp.at = ts("2026-03-31");
    let ev = evaluate(&a, &inp).unwrap();
    insta::assert_snapshot!("echec_sauvegarde_trop_vieille", explain(&ev));
}

#[test]
fn explication_absence_de_sauvegarde() {
    let a = assertion("BKP-24H");
    let inp = EvaluationInput::new(AssetId("srv-fic-02".to_owned()), vec![], coverage_q1());
    let ev = evaluate(&a, &inp).unwrap();
    insta::assert_snapshot!("absence_de_sauvegarde", explain(&ev));
}

#[test]
fn explication_conforme() {
    let a = assertion("SSH-ROOT");
    let inp = EvaluationInput::new(
        AssetId("srv-app-01".to_owned()),
        vec![tf(
            "service:sshd",
            "sshd.PermitRootLogin",
            Value::Text("no".to_owned()),
            "2026-01-01",
            "2026-03-31",
            0x11,
        )],
        coverage_q1(),
    );
    let ev = evaluate(&a, &inp).unwrap();
    insta::assert_snapshot!("conforme_ssh_root", explain(&ev));
}

#[test]
fn explication_indeterminee() {
    let a = assertion("SSH-ROOT");
    let inp = EvaluationInput::new(
        AssetId("srv-app-01".to_owned()),
        vec![],
        CoverageReport {
            period: Period {
                from: ts("2026-01-01"),
                to: ts("2026-03-31"),
            },
            observed_ppm: 610_000,
            max_gap: DurationMs(21 * 86_400_000),
            gaps: vec![Gap {
                from: ts("2026-01-05"),
                to: ts("2026-01-26"),
                reason: GapReason::Unknown,
            }],
        },
    );
    let ev = evaluate(&a, &inp).unwrap();
    insta::assert_snapshot!("indetermine_ssh_root", explain(&ev));
}
