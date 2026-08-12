//! Le fichier d'assertions de la spécification (§5.2) parse tel quel,
//! et les documents invalides sont refusés avec des erreurs lisibles.

#![allow(clippy::unwrap_used)]

use constat_model::Value;
use constat_policy::{parse_assertions, EntityPattern, PolicyError, Predicate};

/// YAML exact de la spécification, §5.2 — ne pas retoucher.
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
        expires: 2027-01-01     # une exception sans date d'expiration est un mensonge

  - id: BKP-24H
    title: sauvegarde réussie dans les dernières 24 heures
    scope: { tag: production }
    predicate:
      fresher: { attr: "backup.last_success", than: 24h }
"#;

#[test]
fn le_yaml_de_la_spec_parse_tel_quel() {
    let assertions = parse_assertions(SPEC_YAML).unwrap();
    assert_eq!(assertions.len(), 3);

    // SSH-ROOT : never avec valeur textuelle "yes"
    assert_eq!(assertions[0].id.0, "SSH-ROOT");
    assert_eq!(assertions[0].scope.os.as_deref(), Some("linux"));
    match &assertions[0].predicate {
        Predicate::Never {
            entity,
            attr,
            equals,
        } => {
            assert_eq!(entity, &EntityPattern::Glob("service:sshd".to_owned()));
            assert_eq!(attr.0, "sshd.PermitRootLogin");
            assert_eq!(equals, &Value::Text("yes".to_owned()));
        }
        autre => panic!("prédicat inattendu : {autre:?}"),
    }

    // ADM-MFA : forall + always avec booléen, exception datée
    assert_eq!(assertions[1].id.0, "ADM-MFA");
    match &assertions[1].predicate {
        Predicate::ForAll { over, satisfies } => {
            match over {
                EntityPattern::Typed {
                    entity_type,
                    filter,
                } => {
                    assert_eq!(entity_type, "user");
                    assert_eq!(filter.get("privileged"), Some(&Value::Bool(true)));
                }
                autre => panic!("motif inattendu : {autre:?}"),
            }
            match satisfies.as_ref() {
                Predicate::Always {
                    entity,
                    attr,
                    equals,
                } => {
                    assert!(entity.is_none());
                    assert_eq!(attr.0, "user.mfa_enabled");
                    assert_eq!(equals, &Value::Bool(true));
                }
                autre => panic!("prédicat inattendu : {autre:?}"),
            }
        }
        autre => panic!("prédicat inattendu : {autre:?}"),
    }
    let exc = &assertions[1].exceptions[0];
    assert_eq!(exc.entity, "user:svc-sauvegarde");
    assert_eq!(exc.expires, "2027-01-01");
    assert!(exc.expires_at().is_ok());

    // BKP-24H : fresher sans entité, durée lisible
    assert_eq!(assertions[2].id.0, "BKP-24H");
    match &assertions[2].predicate {
        Predicate::Fresher { entity, attr, than } => {
            assert!(entity.is_none());
            assert_eq!(attr.0, "backup.last_success");
            assert_eq!(than, "24h");
        }
        autre => panic!("prédicat inattendu : {autre:?}"),
    }
}

#[test]
fn snapshot_du_resultat_parse() {
    let assertions = parse_assertions(SPEC_YAML).unwrap();
    insta::assert_debug_snapshot!("spec_5_2_parsee", assertions);
}

#[test]
fn exception_sans_expiration_refusee() {
    let yaml = r#"assertions:
  - id: ADM-MFA
    title: mfa partout
    predicate:
      exists: { matching: "user:*" }
    exceptions:
      - entity: "user:svc"
        reason: "compte de service"
        approved_by: "RSSI"
"#;
    let err = parse_assertions(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("expires"),
        "le message doit citer le champ manquant : {msg}"
    );
    match err {
        PolicyError::Yaml { line, .. } => assert!(line.is_some(), "position attendue"),
        autre => panic!("erreur inattendue : {autre:?}"),
    }
}

#[test]
fn exception_avec_expiration_vide_refusee() {
    let yaml = r#"assertions:
  - id: A
    title: t
    predicate:
      exists: { matching: "user:*" }
    exceptions:
      - entity: "user:svc"
        reason: "compte de service"
        approved_by: "RSSI"
        expires: "   "
"#;
    let err = parse_assertions(yaml).unwrap_err();
    assert!(matches!(err, PolicyError::InvalidAssertion { .. }));
    assert!(err.to_string().contains("expiration"), "{err}");
}

#[test]
fn exception_avec_date_illisible_refusee() {
    let yaml = r#"assertions:
  - id: A
    title: t
    predicate:
      exists: { matching: "user:*" }
    exceptions:
      - entity: "user:svc"
        reason: "compte de service"
        approved_by: "RSSI"
        expires: bientôt
"#;
    let err = parse_assertions(yaml).unwrap_err();
    assert!(err.to_string().contains("date illisible"), "{err}");
}

#[test]
fn exception_sans_justification_refusee() {
    let yaml = r#"assertions:
  - id: A
    title: t
    predicate:
      exists: { matching: "user:*" }
    exceptions:
      - entity: "user:svc"
        reason: ""
        approved_by: "RSSI"
        expires: 2027-01-01
"#;
    let err = parse_assertions(yaml).unwrap_err();
    assert!(err.to_string().contains("justifiée"), "{err}");
}

#[test]
fn duree_illisible_refusee_au_parsing() {
    let yaml = r#"assertions:
  - id: BKP
    title: sauvegarde fraîche
    predicate:
      fresher: { attr: "backup.last_success", than: bientôt }
"#;
    let err = parse_assertions(yaml).unwrap_err();
    assert!(matches!(err, PolicyError::InvalidAssertion { .. }));
    assert!(err.to_string().contains("durée illisible"), "{err}");
}

#[test]
fn identifiants_en_double_refuses() {
    let yaml = r#"assertions:
  - id: X
    title: a
    predicate:
      exists: { matching: "user:*" }
  - id: X
    title: b
    predicate:
      exists: { matching: "user:*" }
"#;
    let err = parse_assertions(yaml).unwrap_err();
    assert!(matches!(err, PolicyError::DuplicateAssertionId { ref id } if id == "X"));
}

#[test]
fn variante_de_predicat_inconnue_refusee_avec_position() {
    let yaml = r#"assertions:
  - id: A
    title: t
    predicate:
      nevr: { entity: "service:sshd", attr: "a", equals: "b" }
"#;
    let err = parse_assertions(yaml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("nevr"), "{msg}");
    // le message porte la position et l'extrait de la ligne fautive
    assert!(msg.contains("ligne"), "{msg}");
    assert!(msg.contains('|'), "{msg}");
}

#[test]
fn flottant_refuse_dans_equals() {
    let yaml = r#"assertions:
  - id: A
    title: t
    predicate:
      always: { attr: "a", equals: 1.5 }
"#;
    let err = parse_assertions(yaml).unwrap_err();
    assert!(err.to_string().contains("flottant"), "{err}");
}

#[test]
fn champ_inconnu_refuse() {
    let yaml = r#"assertions:
  - id: A
    title: t
    predicate:
      exists: { matching: "user:*" }
    exeptions: []
"#;
    let err = parse_assertions(yaml).unwrap_err();
    assert!(err.to_string().contains("exeptions"), "{err}");
}

#[test]
fn conjonctions_vides_refusees() {
    let yaml = r#"assertions:
  - id: A
    title: t
    predicate:
      and: []
"#;
    let err = parse_assertions(yaml).unwrap_err();
    assert!(err.to_string().contains("and"), "{err}");
}

#[test]
fn predicat_trop_profond_refuse() {
    let mut predicate = "      exists: { matching: \"user:*\" }\n".to_owned();
    for depth in 0..70 {
        let indent = " ".repeat(6);
        predicate = format!("{indent}not:\n{}", indent_block(&predicate, 2));
        let _ = depth;
    }
    let yaml =
        format!("assertions:\n  - id: DEEP\n    title: profond\n    predicate:\n{predicate}");
    let err = parse_assertions(&yaml).unwrap_err();
    assert!(matches!(err, PolicyError::PredicateTooDeep { .. }), "{err}");
}

fn indent_block(block: &str, by: usize) -> String {
    let pad = " ".repeat(by);
    block
        .lines()
        .map(|l| format!("{pad}{l}\n"))
        .collect::<String>()
}

#[test]
fn valeurs_naturelles_bool_entier_texte_liste_null() {
    let yaml = r#"assertions:
  - id: VAL
    title: valeurs naturelles
    predicate:
      and:
        - always: { attr: "a.bool", equals: true }
        - always: { attr: "a.int", equals: -3 }
        - always: { attr: "a.txt", equals: "texte" }
        - always: { attr: "a.liste", equals: [1, "deux", false] }
        - always: { attr: "a.absent", equals: null }
"#;
    let assertions = parse_assertions(yaml).unwrap();
    let Predicate::And(children) = &assertions[0].predicate else {
        panic!("and attendu");
    };
    let expected = [
        Value::Bool(true),
        Value::Int(-3),
        Value::Text("texte".to_owned()),
        Value::List(vec![
            Value::Int(1),
            Value::Text("deux".to_owned()),
            Value::Bool(false),
        ]),
        Value::Absent,
    ];
    for (child, want) in children.iter().zip(expected.iter()) {
        let Predicate::Always { equals, .. } = child else {
            panic!("always attendu");
        };
        assert_eq!(equals, want);
    }
}
