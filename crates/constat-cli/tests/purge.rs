//! `constat purge` / `constat retention` et la couverture après purge (§16) :
//! le plan est sans effet, la confirmation refusée ne modifie rien, la purge
//! exécutée déclare — et la période purgée apparaît comme un trou
//! `RetentionPurge` dans `history`, jamais comme un trou inexpliqué.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use constat_cli::purge::{cmd_purge, cmd_retention, PurgeArgs, RetentionArgs};
use constat_cli::{datetime, queries};
use constat_model::{Blob, BlobHash, CollectorId, EntityId, Fact, Snapshot, Timestamp};
use constat_store::{append_signed, MemoryStore, Signer, Store};
use constat_time::{GapReason, Period};

/// Injecte une collecte : un blob, un snapshot, une entrée signée.
fn inject(store: &mut MemoryStore, signer: &Signer, at: Timestamp, raw: &str) -> BlobHash {
    let blob = Blob::new(
        "linux.accounts",
        raw.as_bytes().to_vec(),
        vec![Fact::new("user:jdupont", "user.privileged", true)],
    );
    let blob_hash = store.put_blob(&blob).unwrap();
    let snap = Snapshot::new(
        "srv-01",
        at,
        BTreeMap::from([(CollectorId("linux.accounts".to_string()), blob_hash)]),
    );
    let snap_hash = store.put_snapshot(&snap).unwrap();
    append_signed(store, signer, vec![snap_hash], at).unwrap();
    blob_hash
}

/// Écrit la paire de clés au format de l'agent et rend le répertoire.
fn keys_dir(signer: &Signer, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "constat-cli-purge-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let hex: String = signer
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(dir.join("agent.key"), hex).unwrap();
    dir
}

/// Deux collectes anciennes (au-delà de la rétention) et une récente,
/// datées par rapport à maintenant pour exercer la vraie CLI.
fn scenario() -> (MemoryStore, Signer, Timestamp, Timestamp) {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    let now = datetime::now();
    let day = 86_400_000i64;
    let old1 = Timestamp(now.0 - 100 * day);
    let old2 = Timestamp(now.0 - 90 * day);
    let recent = Timestamp(now.0 - day);
    inject(&mut store, &signer, old1, "ancienne 1");
    inject(&mut store, &signer, old2, "ancienne 2");
    inject(&mut store, &signer, recent, "récente");
    (store, signer, old1, old2)
}

#[test]
fn dry_run_et_refus_ne_modifient_rien() {
    let (mut store, signer, _, _) = scenario();
    let keys = keys_dir(&signer, "dry-run");
    let before = (
        store.blob_count(),
        store.snapshot_count(),
        store.entry_count(),
    );

    // --dry-run : le plan s'affiche, rien ne bouge, pas de confirmation.
    let args = PurgeArgs {
        older_than: "50j",
        reason: "rétention test",
        keys: Some(&keys),
        dry_run: true,
        assume_yes: false,
    };
    let out = cmd_purge(&mut store, &args, |_| {
        panic!("pas de confirmation en dry-run")
    })
    .unwrap();
    assert!(out.contains("--dry-run"), "sortie : {out}");
    assert_eq!(
        (
            store.blob_count(),
            store.snapshot_count(),
            store.entry_count()
        ),
        before
    );

    // Confirmation refusée : rien ne bouge non plus.
    let args = PurgeArgs {
        older_than: "50j",
        reason: "rétention test",
        keys: Some(&keys),
        dry_run: false,
        assume_yes: false,
    };
    let out = cmd_purge(&mut store, &args, |recap| {
        assert!(recap.contains("2 snapshot(s)"), "récapitulatif : {recap}");
        false
    })
    .unwrap();
    assert!(out.contains("annulée"), "sortie : {out}");
    assert_eq!(
        (
            store.blob_count(),
            store.snapshot_count(),
            store.entry_count()
        ),
        before
    );

    let _ = std::fs::remove_dir_all(&keys);
}

#[test]
fn purge_executee_puis_trou_retention_dans_history() {
    let (mut store, signer, old1, old2) = scenario();
    let keys = keys_dir(&signer, "exec");

    let args = PurgeArgs {
        older_than: "50j",
        reason: "rétention 50 jours",
        keys: Some(&keys),
        dry_run: false,
        assume_yes: true,
    };
    let out = cmd_purge(&mut store, &args, |_| unreachable!("--yes")).unwrap();
    assert!(out.contains("Purge exécutée"), "sortie : {out}");
    assert!(out.contains("2 snapshot(s)"), "sortie : {out}");

    // L'entrée de purge existe et la chaîne se vérifie toujours.
    let entries = store.entries().unwrap();
    assert_eq!(entries.len(), 4);
    constat_store::verify_chain(&entries, &signer.verifying_key()).unwrap();

    // La couverture de `history` déclare le trou : période purgée =
    // [old1, old2], raison RetentionPurge — jamais un trou inexpliqué.
    let now = datetime::now();
    let history = queries::history(
        &store,
        &EntityId("user:jdupont".to_string()),
        &constat_model::Attribute("user.privileged".to_string()),
        Some(Period {
            from: Timestamp(old1.0 - 1_000),
            to: now,
        }),
    )
    .unwrap();
    let coverage = history.coverage.expect("couverture calculée");
    let purge_gap = coverage
        .gaps
        .iter()
        .find(|g| g.reason == GapReason::RetentionPurge)
        .expect("un trou RetentionPurge doit être déclaré");
    assert_eq!(purge_gap.from, old1);
    assert_eq!(purge_gap.to, old2);

    // Rejeu : rien à purger, rien d'écrit.
    let args = PurgeArgs {
        older_than: "50j",
        reason: "rétention 50 jours",
        keys: Some(&keys),
        dry_run: false,
        assume_yes: true,
    };
    let out = cmd_purge(&mut store, &args, |_| unreachable!("--yes")).unwrap();
    assert!(out.contains("Rien à purger"), "sortie : {out}");
    assert_eq!(store.entry_count(), 4);

    let _ = std::fs::remove_dir_all(&keys);
}

#[test]
fn retention_show_et_check_en_lecture_seule() {
    let (store, _, _, _) = scenario();
    let before = (
        store.blob_count(),
        store.snapshot_count(),
        store.entry_count(),
    );

    let out = cmd_retention(&store, &RetentionArgs { check: None }).unwrap();
    assert!(out.contains("3 snapshot(s)"), "sortie : {out}");
    assert!(out.contains("Aucune purge déclarée"), "sortie : {out}");

    let out = cmd_retention(&store, &RetentionArgs { check: Some("50j") }).unwrap();
    assert!(out.contains("purgerait"), "sortie : {out}");
    assert!(out.contains("2 snapshot(s)"), "sortie : {out}");
    assert!(
        out.contains("Aucune suppression effectuée"),
        "sortie : {out}"
    );

    // Une rétention plus longue que l'historique ne purgerait rien.
    let out = cmd_retention(
        &store,
        &RetentionArgs {
            check: Some("200j"),
        },
    )
    .unwrap();
    assert!(out.contains("ne purgerait rien"), "sortie : {out}");

    assert_eq!(
        (
            store.blob_count(),
            store.snapshot_count(),
            store.entry_count()
        ),
        before
    );
}
