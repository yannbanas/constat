//! Tests du moteur d'évaluation : sémantique de l'absence (§3.2), verdicts,
//! exceptions, fraîcheur, combinateurs.

#![allow(clippy::unwrap_used)]

use constat_model::{AssetId, Attribute, BlobHash, DurationMs, EntityId, Fact, Timestamp, Value};
use constat_policy::{
    evaluate, evaluate_with, parse_assertions, parse_date, Assertion, EvaluationInput,
    EvaluationOptions, TimedFact, Verdict, NO_EVIDENCE,
};
use constat_time::{CoverageReport, Gap, GapReason, Period};

// ---------------------------------------------------------------------------
// Aides de construction
// ---------------------------------------------------------------------------

fn ts(s: &str) -> Timestamp {
    parse_date(s).unwrap()
}

fn full_coverage(from: &str, to: &str) -> CoverageReport {
    CoverageReport {
        period: Period {
            from: ts(from),
            to: ts(to),
        },
        observed_ppm: 1_000_000,
        max_gap: DurationMs(26 * 3_600_000),
        gaps: vec![],
    }
}

fn weak_coverage(from: &str, to: &str) -> CoverageReport {
    CoverageReport {
        period: Period {
            from: ts(from),
            to: ts(to),
        },
        observed_ppm: 600_000,
        max_gap: DurationMs(10 * 86_400_000),
        gaps: vec![Gap {
            from: ts(from),
            to: ts("2026-02-01"),
            reason: GapReason::AgentDown,
        }],
    }
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

fn input(facts: Vec<TimedFact>) -> EvaluationInput {
    EvaluationInput::new(
        AssetId("srv-app-01".to_owned()),
        facts,
        full_coverage("2026-01-01", "2026-03-31"),
    )
}

fn spec_assertion(id: &str) -> Assertion {
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
    parse_assertions(SPEC_YAML)
        .unwrap()
        .into_iter()
        .find(|a| a.id.0 == id)
        .unwrap()
}

fn from_yaml(predicate_yaml: &str) -> Assertion {
    let yaml = format!(
        "assertions:\n  - id: TEST\n    title: assertion de test\n    predicate:\n{predicate_yaml}"
    );
    parse_assertions(&yaml).unwrap().into_iter().next().unwrap()
}

// ---------------------------------------------------------------------------
// never — et la sémantique de l'absence (§3.2)
// ---------------------------------------------------------------------------

#[test]
fn never_conforme_quand_la_valeur_differe() {
    let a = spec_assertion("SSH-ROOT");
    let inp = input(vec![tf(
        "service:sshd",
        "sshd.PermitRootLogin",
        Value::Text("no".to_owned()),
        "2026-01-01",
        "2026-03-31",
        1,
    )]);
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Pass);
    assert!(ev.violations.is_empty());
}

#[test]
fn never_echoue_sur_la_valeur_interdite() {
    let a = spec_assertion("SSH-ROOT");
    let inp = input(vec![tf(
        "service:sshd",
        "sshd.PermitRootLogin",
        Value::Text("yes".to_owned()),
        "2026-03-03",
        "2026-03-05",
        7,
    )]);
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 1);
    let v = &ev.violations[0];
    assert_eq!(v.asset.0, "srv-app-01");
    assert_eq!(v.entity.0, "service:sshd");
    assert_eq!(v.observed, Value::Text("yes".to_owned()));
    assert_eq!(v.first_seen, ts("2026-03-03"));
    assert_eq!(v.last_seen, ts("2026-03-05"));
    assert_eq!(v.evidence, BlobHash([7u8; 32]));
    assert!(v.detail.contains("valeur interdite"), "{}", v.detail);
}

#[test]
fn never_absence_nest_pas_une_violation() {
    // sshd sans directive PermitRootLogin : l'absence n'est PAS égale à "yes"
    let a = spec_assertion("SSH-ROOT");
    let inp = input(vec![tf(
        "service:sshd",
        "sshd.Port",
        Value::Int(22),
        "2026-01-01",
        "2026-03-31",
        1,
    )]);
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Pass, "absence ≠ « yes » (§3.2)");
}

#[test]
fn never_fait_absent_explicite_nest_pas_la_valeur_interdite() {
    let a = spec_assertion("SSH-ROOT");
    let inp = input(vec![tf(
        "service:sshd",
        "sshd.PermitRootLogin",
        Value::Absent,
        "2026-01-01",
        "2026-03-31",
        1,
    )]);
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Pass);
}

// ---------------------------------------------------------------------------
// forall + always — ADM-MFA
// ---------------------------------------------------------------------------

fn mfa_facts() -> Vec<TimedFact> {
    vec![
        // root : privilégié, MFA active → conforme
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
        // jdupont : privilégié, MFA jamais observée → violation (observé absent)
        tf(
            "user:jdupont",
            "user.privileged",
            Value::Bool(true),
            "2026-01-15",
            "2026-03-31",
            2,
        ),
        // invite : non privilégié → hors portée
        tf(
            "user:invite",
            "user.privileged",
            Value::Bool(false),
            "2026-01-01",
            "2026-03-31",
            3,
        ),
        tf(
            "user:invite",
            "user.mfa_enabled",
            Value::Bool(false),
            "2026-01-01",
            "2026-03-31",
            3,
        ),
    ]
}

#[test]
fn forall_absence_du_fait_est_une_violation_sur_entite_liee() {
    let a = spec_assertion("ADM-MFA");
    let ev = evaluate(&a, &input(mfa_facts())).unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 1);
    let v = &ev.violations[0];
    assert_eq!(v.entity.0, "user:jdupont");
    assert_eq!(v.observed, Value::Absent);
    assert_eq!(v.expected, Value::Bool(true));
    // la preuve citée est celle de l'existence de l'entité
    assert_eq!(v.evidence, BlobHash([2u8; 32]));
    assert!(v.detail.contains("absence"), "{}", v.detail);
}

#[test]
fn forall_valeur_fausse_est_une_violation() {
    let a = spec_assertion("ADM-MFA");
    let mut facts = mfa_facts();
    facts.push(tf(
        "user:jdupont",
        "user.mfa_enabled",
        Value::Bool(false),
        "2026-01-15",
        "2026-03-31",
        2,
    ));
    let ev = evaluate(&a, &input(facts)).unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 1);
    assert_eq!(ev.violations[0].observed, Value::Bool(false));
}

#[test]
fn forall_sans_entite_correspondante_est_vrai_par_vacuite() {
    let a = spec_assertion("ADM-MFA");
    let ev = evaluate(
        &a,
        &input(vec![tf(
            "service:sshd",
            "sshd.Port",
            Value::Int(22),
            "2026-01-01",
            "2026-03-31",
            1,
        )]),
    )
    .unwrap();
    assert_eq!(ev.verdict, Verdict::Pass);
}

// ---------------------------------------------------------------------------
// exceptions
// ---------------------------------------------------------------------------

fn mfa_facts_avec_compte_de_service() -> Vec<TimedFact> {
    let mut facts = mfa_facts();
    // le compte de service est privilégié et sans MFA — couvert par exception
    facts.push(tf(
        "user:svc-sauvegarde",
        "user.privileged",
        Value::Bool(true),
        "2026-01-01",
        "2026-03-31",
        4,
    ));
    // jdupont a sa MFA ici, pour isoler l'effet de l'exception
    facts.push(tf(
        "user:jdupont",
        "user.mfa_enabled",
        Value::Bool(true),
        "2026-01-15",
        "2026-03-31",
        2,
    ));
    facts
}

#[test]
fn exception_active_neutralise_mais_reste_tracee() {
    let a = spec_assertion("ADM-MFA");
    // évaluation en 2026 : l'exception expire en 2027, elle est active
    let ev = evaluate(&a, &input(mfa_facts_avec_compte_de_service())).unwrap();
    assert_eq!(ev.verdict, Verdict::Pass);
    assert!(ev.violations.is_empty());
    assert_eq!(ev.applied_exceptions.len(), 1);
    let applied = &ev.applied_exceptions[0];
    assert_eq!(applied.exception.entity, "user:svc-sauvegarde");
    assert_eq!(applied.neutralized.entity.0, "user:svc-sauvegarde");
    assert_eq!(applied.neutralized.observed, Value::Absent);
}

#[test]
fn exception_expiree_ne_neutralise_plus_rien() {
    let a = spec_assertion("ADM-MFA");
    let mut inp = input(mfa_facts_avec_compte_de_service());
    // évaluation le 2027-06-01 : l'exception (expires: 2027-01-01) est morte
    inp.at = ts("2027-06-01");
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 1);
    assert_eq!(ev.violations[0].entity.0, "user:svc-sauvegarde");
    assert!(ev.applied_exceptions.is_empty());
}

#[test]
fn exception_expire_le_jour_meme_ne_neutralise_plus() {
    let a = spec_assertion("ADM-MFA");
    let mut inp = input(mfa_facts_avec_compte_de_service());
    inp.at = ts("2027-01-01"); // minuit UTC du jour d'expiration : expirée
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
}

#[test]
fn exception_glob_couvre_plusieurs_entites() {
    let yaml = r#"assertions:
  - id: GLOB-EXC
    title: exceptions par motif
    predicate:
      forall:
        over: { type: user, where: { privileged: true } }
        satisfies:
          always: { attr: "user.mfa_enabled", equals: true }
    exceptions:
      - entity: "user:svc-*"
        reason: "comptes de service"
        approved_by: "RSSI"
        expires: 2027-01-01
"#;
    let a = parse_assertions(yaml).unwrap().into_iter().next().unwrap();
    let facts = vec![
        tf(
            "user:svc-a",
            "user.privileged",
            Value::Bool(true),
            "2026-01-01",
            "2026-03-31",
            1,
        ),
        tf(
            "user:svc-b",
            "user.privileged",
            Value::Bool(true),
            "2026-01-01",
            "2026-03-31",
            2,
        ),
    ];
    let ev = evaluate(&a, &input(facts)).unwrap();
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.applied_exceptions.len(), 2);
}

// ---------------------------------------------------------------------------
// fresher — BKP-24H
// ---------------------------------------------------------------------------

#[test]
fn fresher_conforme_quand_la_valeur_est_recente() {
    let a = spec_assertion("BKP-24H");
    let mut inp = input(vec![tf(
        "backup:principal",
        "backup.last_success",
        Value::Int(ts("2026-03-30T22:00").0), // 2 h avant la date d'évaluation
        "2026-03-01",
        "2026-03-31",
        9,
    )]);
    inp.at = ts("2026-03-31"); // minuit UTC — la sauvegarde date de 2 h
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Pass);
}

#[test]
fn fresher_echoue_quand_la_valeur_est_trop_vieille() {
    let a = spec_assertion("BKP-24H");
    let mut inp = input(vec![tf(
        "backup:principal",
        "backup.last_success",
        Value::Int(ts("2026-03-29T12:00").0),
        "2026-03-01",
        "2026-03-31",
        9,
    )]);
    inp.at = ts("2026-03-31"); // la sauvegarde date de 36 h > 24 h
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 1);
    let v = &ev.violations[0];
    assert_eq!(v.entity.0, "backup:principal");
    assert!(v.detail.contains("36 h"), "{}", v.detail);
    assert!(v.detail.contains("24 h"), "{}", v.detail);
}

#[test]
fn fresher_absence_totale_est_une_violation() {
    // aucun fait backup.last_success : impossible d'attester la fraîcheur
    let a = spec_assertion("BKP-24H");
    let ev = evaluate(
        &a,
        &input(vec![tf(
            "service:sshd",
            "sshd.Port",
            Value::Int(22),
            "2026-01-01",
            "2026-03-31",
            1,
        )]),
    )
    .unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 1);
    let v = &ev.violations[0];
    assert_eq!(v.observed, Value::Absent);
    assert_eq!(v.evidence, NO_EVIDENCE);
    assert!(v.detail.contains("aucune valeur"), "{}", v.detail);
}

#[test]
fn fresher_utilise_la_valeur_la_plus_recente() {
    let a = spec_assertion("BKP-24H");
    let mut inp = input(vec![
        tf(
            "backup:principal",
            "backup.last_success",
            Value::Int(ts("2026-03-20").0),
            "2026-03-01",
            "2026-03-20",
            8,
        ),
        tf(
            "backup:principal",
            "backup.last_success",
            Value::Int(ts("2026-03-30T20:00").0),
            "2026-03-30",
            "2026-03-31",
            9,
        ),
    ]);
    inp.at = ts("2026-03-31");
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Pass, "la valeur la plus récente prime");
}

// ---------------------------------------------------------------------------
// couverture insuffisante → Undetermined
// ---------------------------------------------------------------------------

#[test]
fn couverture_insuffisante_sans_violation_rend_indetermine() {
    let a = spec_assertion("SSH-ROOT");
    let inp = EvaluationInput::new(
        AssetId("srv-app-01".to_owned()),
        vec![tf(
            "service:sshd",
            "sshd.PermitRootLogin",
            Value::Text("no".to_owned()),
            "2026-01-01",
            "2026-03-31",
            1,
        )],
        weak_coverage("2026-01-01", "2026-03-31"),
    );
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(ev.verdict, Verdict::Undetermined);
}

#[test]
fn une_violation_observee_reste_fail_meme_a_couverture_faible() {
    let a = spec_assertion("SSH-ROOT");
    let inp = EvaluationInput::new(
        AssetId("srv-app-01".to_owned()),
        vec![tf(
            "service:sshd",
            "sshd.PermitRootLogin",
            Value::Text("yes".to_owned()),
            "2026-02-10",
            "2026-02-12",
            5,
        )],
        weak_coverage("2026-01-01", "2026-03-31"),
    );
    let ev = evaluate(&a, &inp).unwrap();
    assert_eq!(
        ev.verdict,
        Verdict::Fail,
        "une couverture faible ne blanchit jamais un constat"
    );
}

#[test]
fn seuil_de_couverture_parametrable() {
    let a = spec_assertion("SSH-ROOT");
    let inp = EvaluationInput::new(
        AssetId("srv-app-01".to_owned()),
        vec![],
        weak_coverage("2026-01-01", "2026-03-31"), // 60 %
    );
    // seuil abaissé à 50 % : le même résultat devient Pass
    let ev = evaluate_with(
        &a,
        &inp,
        &EvaluationOptions {
            min_observed_ppm: 500_000,
        },
    )
    .unwrap();
    assert_eq!(ev.verdict, Verdict::Pass);
}

// ---------------------------------------------------------------------------
// exists, and, or, not
// ---------------------------------------------------------------------------

#[test]
fn exists_conforme_et_non_conforme() {
    let a = from_yaml("      exists: { matching: \"user:*\" }\n");
    let oui = evaluate(
        &a,
        &input(vec![tf(
            "user:root",
            "user.privileged",
            Value::Bool(true),
            "2026-01-01",
            "2026-03-31",
            1,
        )]),
    )
    .unwrap();
    assert_eq!(oui.verdict, Verdict::Pass);

    let non = evaluate(
        &a,
        &input(vec![tf(
            "service:sshd",
            "sshd.Port",
            Value::Int(22),
            "2026-01-01",
            "2026-03-31",
            1,
        )]),
    )
    .unwrap();
    assert_eq!(non.verdict, Verdict::Fail);
    assert_eq!(non.violations.len(), 1);
    assert_eq!(non.violations[0].evidence, NO_EVIDENCE);
    assert!(non.violations[0].detail.contains("aucune entité"));
}

#[test]
fn and_reunit_les_violations_de_chaque_branche() {
    let a = from_yaml(
        "      and:\n        - exists: { matching: \"user:*\" }\n        - never: { entity: \"service:sshd\", attr: \"sshd.PermitRootLogin\", equals: \"yes\" }\n",
    );
    let ev = evaluate(
        &a,
        &input(vec![tf(
            "service:sshd",
            "sshd.PermitRootLogin",
            Value::Text("yes".to_owned()),
            "2026-01-01",
            "2026-03-31",
            1,
        )]),
    )
    .unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 2, "les deux branches échouent");
}

#[test]
fn or_tient_si_une_branche_tient() {
    let a = from_yaml(
        "      or:\n        - exists: { matching: \"user:*\" }\n        - exists: { matching: \"service:*\" }\n",
    );
    let ev = evaluate(
        &a,
        &input(vec![tf(
            "service:sshd",
            "sshd.Port",
            Value::Int(22),
            "2026-01-01",
            "2026-03-31",
            1,
        )]),
    )
    .unwrap();
    assert_eq!(ev.verdict, Verdict::Pass);
}

#[test]
fn or_explique_chaque_branche_quand_tout_echoue() {
    let a = from_yaml(
        "      or:\n        - exists: { matching: \"user:*\" }\n        - exists: { matching: \"pkg:*\" }\n",
    );
    let ev = evaluate(
        &a,
        &input(vec![tf(
            "service:sshd",
            "sshd.Port",
            Value::Int(22),
            "2026-01-01",
            "2026-03-31",
            1,
        )]),
    )
    .unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 2);
}

#[test]
fn not_renverse_et_reste_explique() {
    let a = from_yaml("      not:\n        exists: { matching: \"user:ancien-admin\" }\n");
    // l'entité existe : not(exists) échoue, avec une violation étayée
    let ev = evaluate(
        &a,
        &input(vec![tf(
            "user:ancien-admin",
            "user.privileged",
            Value::Bool(true),
            "2026-02-01",
            "2026-02-20",
            6,
        )]),
    )
    .unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 1);
    assert_eq!(ev.violations[0].entity.0, "user:ancien-admin");
    assert!(ev.violations[0].detail.contains("négation"));

    // l'entité n'existe pas : not(exists) tient
    let ev = evaluate(&a, &input(vec![])).unwrap();
    // couverture pleine, aucune violation
    assert_eq!(ev.verdict, Verdict::Pass);
}

// ---------------------------------------------------------------------------
// motifs
// ---------------------------------------------------------------------------

#[test]
fn glob_sur_les_entites() {
    let a = from_yaml(
        "      never: { entity: \"user:*\", attr: \"user.shell\", equals: \"/bin/bash\" }\n",
    );
    let ev = evaluate(
        &a,
        &input(vec![
            tf(
                "user:root",
                "user.shell",
                Value::Text("/bin/bash".to_owned()),
                "2026-01-01",
                "2026-03-31",
                1,
            ),
            tf(
                "service:sshd",
                "user.shell",
                Value::Text("/bin/bash".to_owned()),
                "2026-01-01",
                "2026-03-31",
                2,
            ),
        ]),
    )
    .unwrap();
    assert_eq!(ev.verdict, Verdict::Fail);
    assert_eq!(ev.violations.len(), 1, "seul user:* est visé");
    assert_eq!(ev.violations[0].entity.0, "user:root");
}

#[test]
fn always_sans_motif_ni_liaison_porte_sur_les_porteurs_de_l_attribut() {
    let a = from_yaml("      always: { attr: \"disk.encrypted\", equals: true }\n");
    // une entité porte l'attribut à vrai, une autre ne le porte pas du tout
    let ev = evaluate(
        &a,
        &input(vec![
            tf(
                "disk:sda",
                "disk.encrypted",
                Value::Bool(true),
                "2026-01-01",
                "2026-03-31",
                1,
            ),
            tf(
                "disk:sdb",
                "disk.model",
                Value::Text("X".to_owned()),
                "2026-01-01",
                "2026-03-31",
                2,
            ),
        ]),
    )
    .unwrap();
    assert_eq!(
        ev.verdict,
        Verdict::Pass,
        "sans sélection explicite, la règle porte sur les porteurs de l'attribut"
    );
}

#[test]
fn evaluation_deterministe() {
    // deux évaluations sur les mêmes données rendent le même résultat, octet
    // pour octet — indispensable pour un outil dont la sortie sert de preuve
    let a = spec_assertion("ADM-MFA");
    let inp = input(mfa_facts_avec_compte_de_service());
    let e1 = evaluate(&a, &inp).unwrap();
    let e2 = evaluate(&a, &inp).unwrap();
    assert_eq!(e1, e2);
    assert_eq!(format!("{e1:?}"), format!("{e2:?}"));
}
