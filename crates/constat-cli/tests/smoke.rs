//! Test de fumée (§13 S1–S3) : magasin en mémoire → injection de faits →
//! `state`, `diff`, `history` et l'évaluation répondent correctement —
//! puis la même boucle sur le vrai backend redb, via le même chemin
//! d'ouverture que le binaire.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use constat_cli::commands;
use constat_cli::datetime::parse_timestamp;
use constat_cli::eval;
use constat_cli::queries;
use constat_model::{
    AssetId, Attribute, Blob, BlobHash, CollectorId, EntityId, Fact, Snapshot, Timestamp, Value,
};
use constat_policy::{
    Assertion, AssertionId, AssetSelector, EntityPattern, EvaluationOptions, Predicate, Verdict,
};
use constat_store::{append_signed, MemoryStore, Signer, Store};
use constat_time::Period;

fn ts(s: &str) -> Timestamp {
    parse_timestamp(s).expect("date de test valide")
}

fn fact(entity: &str, attr: &str, value: Value) -> Fact {
    Fact {
        entity: EntityId(entity.to_string()),
        attribute: Attribute(attr.to_string()),
        value,
    }
}

/// Injecte une collecte : un blob, un snapshot, une entrée de journal signée.
fn inject<S: Store + ?Sized>(
    store: &mut S,
    signer: &Signer,
    asset: &str,
    at: Timestamp,
    facts: Vec<Fact>,
) -> BlobHash {
    let blob = Blob {
        collector: CollectorId("ad.groupes".to_string()),
        raw: format!("capture expurgée du {}", at.0).into_bytes(),
        facts,
    };
    let blob_hash = store.put_blob(&blob).expect("put_blob");
    let mut blobs = BTreeMap::new();
    blobs.insert(CollectorId("ad.groupes".to_string()), blob_hash);
    let snap = Snapshot {
        asset: AssetId(asset.to_string()),
        at,
        blobs,
    };
    let snap_hash = store.put_snapshot(&snap).expect("put_snapshot");
    append_signed(store, signer, vec![snap_hash], at).expect("append_signed");
    blob_hash
}

/// Le scénario du §10.1 : jdupont devient admin, puis ne l'est plus.
fn scenario_into<S: Store + ?Sized>(store: &mut S) -> (BlobHash, BlobHash, BlobHash) {
    let signer = Signer::generate();
    let b1 = inject(
        store,
        &signer,
        "srv-ad-01",
        ts("2025-11-01T06:00Z"),
        vec![
            fact("user:jdupont", "user.privileged", Value::Bool(false)),
            fact("user:jdupont", "user.mfa_enabled", Value::Bool(true)),
        ],
    );
    let b2 = inject(
        store,
        &signer,
        "srv-ad-01",
        ts("2025-11-04T09:12Z"),
        vec![
            fact("user:jdupont", "user.privileged", Value::Bool(true)),
            fact("user:jdupont", "user.mfa_enabled", Value::Bool(true)),
        ],
    );
    let b3 = inject(
        store,
        &signer,
        "srv-ad-01",
        ts("2026-02-18T16:40Z"),
        vec![
            fact("user:jdupont", "user.privileged", Value::Bool(false)),
            fact("user:jdupont", "user.mfa_enabled", Value::Bool(true)),
        ],
    );
    (b1, b2, b3)
}

fn scenario() -> (MemoryStore, BlobHash, BlobHash, BlobHash) {
    let mut store = MemoryStore::new();
    let (b1, b2, b3) = scenario_into(&mut store);
    (store, b1, b2, b3)
}

#[test]
fn state_restitue_le_dernier_snapshot_anterieur() {
    let (store, _, _, _) = scenario();
    let view = queries::state_at(
        &store,
        &AssetId("srv-ad-01".to_string()),
        ts("2025-12-01T00:00Z"),
    )
    .expect("lecture")
    .expect("un snapshot existe");
    // Le dernier snapshot antérieur au 1er décembre est celui du 4 novembre.
    assert_eq!(view.snapshot.at, ts("2025-11-04T09:12Z"));
    let privileged = view
        .facts
        .iter()
        .find(|(_, _, f)| f.attribute.0 == "user.privileged")
        .expect("le fait existe");
    assert_eq!(privileged.2.value, Value::Bool(true));

    // Avant toute collecte : aucun état, et on le dit.
    let nothing = queries::state_at(
        &store,
        &AssetId("srv-ad-01".to_string()),
        ts("2025-10-01T00:00Z"),
    )
    .expect("lecture");
    assert!(nothing.is_none());
}

#[test]
fn diff_entre_deux_dates() {
    let (store, _, _, _) = scenario();
    let view = queries::diff_asset(
        &store,
        &AssetId("srv-ad-01".to_string()),
        ts("2025-11-02T00:00Z"), // état : privileged=false
        ts("2025-11-05T00:00Z"), // état : privileged=true
    )
    .expect("lecture")
    .expect("les deux dates ont un snapshot antérieur");
    assert_eq!(view.diff.changed.len(), 1);
    assert_eq!(view.diff.changed[0].attribute.0, "user.privileged");
    assert_eq!(view.diff.changed[0].before, Value::Bool(false));
    assert_eq!(view.diff.changed[0].after, Value::Bool(true));
    assert!(view.diff.added.is_empty());
    assert!(view.diff.removed.is_empty());

    // Entre deux dates encadrant tout l'aller-retour : aucune différence.
    let round = queries::diff_asset(
        &store,
        &AssetId("srv-ad-01".to_string()),
        ts("2025-11-02T00:00Z"),
        ts("2026-03-01T00:00Z"),
    )
    .expect("lecture")
    .expect("snapshots présents");
    assert!(round.diff.is_empty());
}

#[test]
fn history_restitue_les_changements_dates_avec_preuve() {
    let (store, b1, b2, b3) = scenario();
    let h = queries::history(
        &store,
        &EntityId("user:jdupont".to_string()),
        &Attribute("user.privileged".to_string()),
        None,
    )
    .expect("lecture");

    // Première observation + deux changements réels.
    assert_eq!(h.changes.len(), 3);

    assert_eq!(h.changes[0].before, None);
    assert_eq!(h.changes[0].after, Value::Bool(false));
    assert_eq!(h.changes[0].evidence, b1);

    assert_eq!(h.changes[1].at, ts("2025-11-04T09:12Z"));
    assert_eq!(h.changes[1].before, Some(Value::Bool(false)));
    assert_eq!(h.changes[1].after, Value::Bool(true));
    assert_eq!(
        h.changes[1].evidence, b2,
        "l'empreinte de preuve désigne le bon blob"
    );
    assert_eq!(h.changes[1].asset.0, "srv-ad-01");

    assert_eq!(h.changes[2].at, ts("2026-02-18T16:40Z"));
    assert_eq!(h.changes[2].before, Some(Value::Bool(true)));
    assert_eq!(h.changes[2].after, Value::Bool(false));
    assert_eq!(h.changes[2].evidence, b3);

    // La couverture déclare honnêtement le trou de trois mois entre les
    // collectes — jamais masqué (§4.2).
    let cov = h.coverage.expect("couverture présente");
    assert!(
        !cov.gaps.is_empty(),
        "le trou de collecte doit être déclaré"
    );
    assert!(cov.observed_ppm < 1_000_000);

    // Et le rendu suit l'esprit du §10.1.
    let text =
        commands::cmd_history(&store, "user:jdupont", "user.privileged", None).expect("rendu");
    assert!(text.contains("2025-11-04 09:12"));
    assert!(text.contains("false → true"));
    assert!(text.contains("true  → false"));
    assert!(text.contains("preuve : blob"));
    assert!(text.contains("srv-ad-01"));
    assert!(text.contains("Couverture sur la période"));
}

/// Prépare les entrées d'évaluation du scénario sur une période donnée.
fn inputs_for(
    store: &dyn Store,
    period: Period,
) -> (
    Vec<constat_policy::EvaluationInput>,
    constat_time::CoverageReport,
) {
    let obs = queries::observations(store).expect("lecture");
    let snaps = queries::snapshots(store).expect("lecture");
    let snap_times: Vec<(AssetId, Timestamp)> =
        snaps.iter().map(|(_, s)| (s.asset.clone(), s.at)).collect();
    let inputs = eval::build_inputs(
        &obs,
        &snap_times,
        period,
        constat_cli::coverage::DEFAULT_MAX_EXPECTED_GAP,
    )
    .expect("couverture calculable");
    let times: Vec<Timestamp> = snap_times.iter().map(|(_, t)| *t).collect();
    let park = constat_cli::coverage::coverage_report(
        &times,
        period,
        constat_cli::coverage::DEFAULT_MAX_EXPECTED_GAP,
    )
    .expect("couverture calculable");
    (inputs, park)
}

#[test]
fn evaluation_never_designe_la_violation_et_sa_preuve() {
    let (store, _, b2, _) = scenario();
    // « Aucun compte ne doit être privilégié » — volontairement violée par
    // le scénario, pour vérifier que la violation désigne machine, entité,
    // valeurs, dates et artefact de preuve (§13 S3).
    let assertion = Assertion {
        id: AssertionId("ADM-AUCUN".to_string()),
        title: "aucun compte privilégié".to_string(),
        scope: AssetSelector::default(),
        predicate: Predicate::Never {
            entity: EntityPattern::Glob("user:*".to_string()),
            attr: Attribute("user.privileged".to_string()),
            equals: Value::Bool(true),
        },
        exceptions: Vec::new(),
    };
    let period = Period {
        from: ts("2025-11-01T00:00Z"),
        to: ts("2026-03-01T00:00Z"),
    };
    let (inputs, park) = inputs_for(&store, period);
    let e = eval::evaluate_park(&assertion, &inputs, park).expect("évaluation");

    // Une couverture faible ne blanchit jamais un constat : Fail.
    assert_eq!(e.verdict, Verdict::Fail);
    assert_eq!(e.violations.len(), 1);
    let v = &e.violations[0];
    assert_eq!(v.asset.0, "srv-ad-01");
    assert_eq!(v.entity.0, "user:jdupont");
    assert_eq!(v.observed, Value::Bool(true));
    assert_eq!(v.first_seen, ts("2025-11-04T09:12Z"));
    assert_eq!(v.last_seen, ts("2025-11-04T09:12Z"));
    assert_eq!(
        v.evidence, b2,
        "la preuve désigne le blob où la violation est constatée"
    );
    // Le verdict déclare ses trous — jamais masqués.
    assert!(!e.coverage.gaps.is_empty());
}

#[test]
fn evaluation_always_conforme_mais_couverture_insuffisante() {
    let (store, _, _, _) = scenario();
    // « MFA activée partout » — vraie sur toutes les observations du
    // scénario, mais trois collectes en quatre mois : la couverture est
    // insuffisante pour affirmer « conforme sur la période ».
    let assertion = Assertion {
        id: AssertionId("ADM-MFA".to_string()),
        title: "authentification forte partout".to_string(),
        scope: AssetSelector::default(),
        predicate: Predicate::Always {
            entity: Some(EntityPattern::Glob("user:*".to_string())),
            attr: Attribute("user.mfa_enabled".to_string()),
            equals: Value::Bool(true),
        },
        exceptions: Vec::new(),
    };
    let period = Period {
        from: ts("2025-11-01T06:00Z"),
        to: ts("2026-02-18T16:40Z"),
    };
    let (inputs, park) = inputs_for(&store, period);

    // Avec le seuil honnête par défaut (95 %) : INDÉTERMINÉ, sans violation.
    let e = eval::evaluate_park(&assertion, &inputs, park.clone()).expect("évaluation");
    assert_eq!(e.verdict, Verdict::Undetermined);
    assert!(e.violations.is_empty());
    assert!(!e.coverage.gaps.is_empty(), "les trous restent déclarés");

    // Sans exigence de couverture : CONFORME — les faits eux-mêmes tiennent.
    let e0 = eval::evaluate_park_with(
        &assertion,
        &inputs,
        park,
        &EvaluationOptions {
            min_observed_ppm: 0,
        },
    )
    .expect("évaluation");
    assert_eq!(e0.verdict, Verdict::Pass);
}

#[test]
fn timeline_suit_le_verdict_dans_le_temps() {
    let (store, _, _, _) = scenario();
    let assertion = Assertion {
        id: AssertionId("ADM-AUCUN".to_string()),
        title: "aucun compte privilégié".to_string(),
        scope: AssetSelector::default(),
        predicate: Predicate::Never {
            entity: EntityPattern::Glob("user:*".to_string()),
            attr: Attribute("user.privileged".to_string()),
            equals: Value::Bool(true),
        },
        exceptions: Vec::new(),
    };
    let period = Period {
        from: ts("2025-11-01T00:00Z"),
        to: ts("2026-03-01T00:00Z"),
    };
    let obs = queries::observations(&store).expect("lecture");
    let snaps = queries::snapshots(&store).expect("lecture");
    let snap_times: Vec<(AssetId, Timestamp)> =
        snaps.iter().map(|(_, s)| (s.asset.clone(), s.at)).collect();
    let segments = eval::timeline(&assertion, &obs, &snap_times, period).expect("chronologie");

    // Conforme au départ, non conforme quand jdupont devient admin.
    // (L'état ponctuel garde la dernière valeur connue : le retour à
    // `false` le 18/02 rend le dernier segment de nouveau conforme —
    // mais l'historique du parcours `never` reste un constat pour `check`.)
    assert!(segments.len() >= 2, "au moins un basculement de verdict");
    assert_eq!(segments[0].verdict, Verdict::Pass);
    assert_eq!(segments[0].from, ts("2025-11-01T06:00Z"));
    assert_eq!(segments[1].verdict, Verdict::Fail);
    assert_eq!(segments[1].from, ts("2025-11-04T09:12Z"));
    assert!(segments[1].violations >= 1);
}

#[test]
fn check_pack_et_anchor_repondent_sur_le_scenario() {
    let (store, _, _, _) = scenario();
    let dir = std::env::temp_dir().join(format!(
        "constat-smoke-cmd-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("répertoire temporaire");

    // Le YAML du §5.2, tel quel.
    let assertions_path = dir.join("assertions.yaml");
    std::fs::write(
        &assertions_path,
        r#"assertions:
  - id: ADM-AUCUN
    title: aucun compte ne doit être privilégié
    predicate:
      never: { entity: "user:*", attr: "user.privileged", equals: true }
  - id: ADM-MFA
    title: authentification forte partout
    predicate:
      always: { entity: "user:*", attr: "user.mfa_enabled", equals: true }
"#,
    )
    .expect("écriture assertions");

    // check : verdicts + couverture + violations expliquées.
    let (out, any_fail) = commands::cmd_check(
        &store,
        &assertions_path,
        Some("2025-11-01..2026-03-01"),
        true,
    )
    .expect("check");
    assert!(any_fail, "ADM-AUCUN est violée par le scénario");
    assert!(out.contains("NON CONFORME"));
    assert!(out.contains("user:jdupont"));
    assert!(out.contains("preuve"));
    assert!(out.contains("couverture"));

    // pack : dossier HTML autonome.
    let dossier_path = dir.join("dossier.html");
    let msg = commands::cmd_pack(
        &store,
        &commands::PackArgs {
            assertions_path: &assertions_path,
            period: "2025-11-01..2026-03-01",
            out: &dossier_path,
            referential: None,
            organization: Some("Exemple SARL"),
            inventory: None,
            pubkey: None,
            keys: None,
            store_path: None,
        },
    )
    .expect("pack");
    assert!(msg.contains("Dossier de preuve écrit"));
    let html = std::fs::read_to_string(&dossier_path).expect("dossier lisible");
    assert!(html.contains("Exemple SARL"));
    assert!(html.contains("srv-ad-01"));

    // anchor : export de racine signé (niveau 2) + requête RFC 3161.
    let keys_dir = dir.join("cles");
    std::fs::create_dir_all(&keys_dir).expect("répertoire clés");
    let signer = Signer::generate();
    std::fs::write(
        keys_dir.join("agent.key"),
        signer
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
    .expect("écriture clé");
    let export_path = dir.join("racine.export");
    let tsq_path = dir.join("requete.tsq");
    let msg = commands::cmd_anchor(
        &store,
        &commands::AnchorArgs {
            request_out: Some(&tsq_path),
            export_out: Some(&export_path),
            keys: Some(&keys_dir),
            organization: Some("Exemple SARL"),
            send: None,
            store_path: None,
        },
    )
    .expect("anchor");
    assert!(msg.contains("Racine courante du journal"));
    assert!(export_path.metadata().map(|m| m.len() > 0).unwrap_or(false));
    assert!(tsq_path.metadata().map(|m| m.len() > 0).unwrap_or(false));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn le_backend_redb_fait_la_meme_boucle() {
    // Même scénario, mais sur le vrai fichier redb, ouvert par le même
    // chemin que le binaire (`storeopen::open_store`).
    let dir = std::env::temp_dir().join(format!(
        "constat-smoke-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("répertoire temporaire");
    let path = dir.join("constat.redb");

    let (b2, expected_root) = {
        let mut store = constat_store::RedbStore::open(&path).expect("création du magasin");
        let (_, b2, _) = scenario_into(&mut store);
        let root = store.root().expect("racine").expect("journal non vide");
        (b2, root)
    }; // fermeture du fichier

    let store = constat_cli::storeopen::open_store(&path).expect("réouverture CLI");

    // La racine survit à la réouverture : le journal est bien persistant.
    assert_eq!(store.root().expect("racine"), Some(expected_root));

    // `state` : même réponse que sur le magasin en mémoire.
    let view = queries::state_at(
        store.as_ref(),
        &AssetId("srv-ad-01".to_string()),
        ts("2025-12-01T00:00Z"),
    )
    .expect("lecture")
    .expect("un snapshot existe");
    assert_eq!(view.snapshot.at, ts("2025-11-04T09:12Z"));

    // `history` : les changements et leurs preuves.
    let h = queries::history(
        store.as_ref(),
        &EntityId("user:jdupont".to_string()),
        &Attribute("user.privileged".to_string()),
        None,
    )
    .expect("lecture");
    assert_eq!(h.changes.len(), 3);
    assert_eq!(h.changes[1].evidence, b2);

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
