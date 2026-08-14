//! Purge de rétention journalisée (§16) — tests de bout en bout côté magasin.
//!
//! La promesse : la purge supprime le contenu au-delà de la rétention, mais
//! **déclare** d'abord ce qu'elle supprime dans une nouvelle entrée signée —
//! la chaîne n'est jamais réécrite, un blob dédupliqué encore référencé est
//! conservé, et rejouer une purge est sans effet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use constat_model::{Blob, BlobHash, CollectorId, Fact, Snapshot, Timestamp};
use constat_store::{
    export_store, journal::append_signed, manifest_hash, parse_purge_blob, plan_purge,
    purge_older_than, verify_chain, MemoryStore, PurgeableStore, RedbStore, Signer, Store,
    StoreError, PURGE_ASSET, PURGE_COLLECTOR,
};

fn blob(collector: &str, raw: &str) -> Blob {
    Blob::new(
        collector,
        raw.as_bytes().to_vec(),
        vec![Fact::new("user:jdupont", "user.privileged", true)],
    )
}

/// Un magasin avec deux collectes anciennes et une récente :
///
/// - `snap1` (at 1 000)   → `blob_old` + `blob_shared`
/// - `snap2` (at 2 000)   → `blob_old`
/// - `snap3` (at 100 000) → `blob_shared` + `blob_new`
///
/// Après purge au seuil 50 000 : `snap1`, `snap2` et `blob_old` disparaissent ;
/// `blob_shared` (dédupliqué, encore référencé par `snap3`) est conservé.
struct Fixture {
    store: MemoryStore,
    signer: Signer,
    snap1: BlobHash,
    snap2: BlobHash,
    snap3: BlobHash,
    blob_old: BlobHash,
    blob_shared: BlobHash,
    blob_new: BlobHash,
}

fn fixture() -> Fixture {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();

    let blob_old = store.put_blob(&blob("linux.sshd", "ancien")).unwrap();
    let blob_shared = store.put_blob(&blob("linux.accounts", "partagé")).unwrap();
    let blob_new = store.put_blob(&blob("linux.packages", "récent")).unwrap();

    let mut snap = |at: i64, blobs: Vec<(&str, BlobHash)>| {
        let snapshot = Snapshot::new(
            "srv-01",
            Timestamp(at),
            blobs
                .into_iter()
                .map(|(c, h)| (CollectorId(c.to_string()), h))
                .collect::<BTreeMap<_, _>>(),
        );
        store.put_snapshot(&snapshot).unwrap()
    };
    let snap1 = snap(
        1_000,
        vec![("linux.sshd", blob_old), ("linux.accounts", blob_shared)],
    );
    let snap2 = snap(2_000, vec![("linux.sshd", blob_old)]);
    let snap3 = snap(
        100_000,
        vec![
            ("linux.accounts", blob_shared),
            ("linux.packages", blob_new),
        ],
    );

    append_signed(&mut store, &signer, vec![snap1], Timestamp(1_000)).unwrap();
    append_signed(&mut store, &signer, vec![snap2], Timestamp(2_000)).unwrap();
    append_signed(&mut store, &signer, vec![snap3], Timestamp(100_000)).unwrap();

    Fixture {
        store,
        signer,
        snap1,
        snap2,
        snap3,
        blob_old,
        blob_shared,
        blob_new,
    }
}

/// Le test central : purger → l'entrée de purge existe et est signée, les
/// objets sont absents, le blob dédupliqué encore référencé est conservé, la
/// déclaration se relit et son manifeste couvre exactement ce qui a disparu.
#[test]
fn purge_de_bout_en_bout() {
    let mut f = fixture();
    let report = purge_older_than(
        &mut f.store,
        &f.signer,
        Timestamp(50_000),
        "rétention 3 ans (test)",
        Timestamp(200_000),
    )
    .unwrap()
    .expect("il y a des objets à purger");

    // Le compte rendu : période, comptes, manifeste.
    assert_eq!(report.from, Timestamp(1_000));
    assert_eq!(report.to, Timestamp(2_000));
    assert_eq!(report.snapshots_purged, 2);
    assert_eq!(report.blobs_purged, 1);
    let expected_manifest = manifest_hash(&[f.snap1, f.snap2, f.blob_old]).unwrap();
    assert_eq!(report.manifest, expected_manifest);

    // Les objets purgés sont absents ; le blob dédupliqué est conservé.
    assert!(!f.store.has_snapshot(&f.snap1).unwrap());
    assert!(!f.store.has_snapshot(&f.snap2).unwrap());
    assert!(!f.store.has_blob(&f.blob_old).unwrap());
    assert!(f.store.has_snapshot(&f.snap3).unwrap());
    assert!(f.store.has_blob(&f.blob_shared).unwrap());
    assert!(f.store.has_blob(&f.blob_new).unwrap());

    // Les ENTRÉES de journal ne sont jamais supprimées : 3 collectes + 1
    // déclaration, et la chaîne entière se vérifie toujours — rien n'a été
    // réécrit, l'entrée de purge est signée comme les autres.
    let entries = f.store.entries().unwrap();
    assert_eq!(entries.len(), 4);
    verify_chain(&entries, &f.signer.verifying_key()).unwrap();
    assert_eq!(f.store.root().unwrap(), Some(report.root));

    // La déclaration est un constat ordinaire : snapshot `constat`, blob
    // `constat.purge`, relisible, manifeste identique.
    let (_, last) = f.store.last_entry().unwrap().unwrap();
    assert_eq!(last.snapshots.len(), 1);
    let purge_snap = f.store.get_snapshot(&last.snapshots[0]).unwrap();
    assert_eq!(purge_snap.asset.0, PURGE_ASSET);
    let purge_blob_hash = purge_snap.blobs[&CollectorId(PURGE_COLLECTOR.to_string())];
    assert_eq!(purge_blob_hash, report.declaration_blob);
    let declaration = parse_purge_blob(&f.store.get_blob(&purge_blob_hash).unwrap()).unwrap();
    assert_eq!(declaration.manifest, expected_manifest);
    assert_eq!(declaration.objects, 3);
    assert_eq!(declaration.reason, "rétention 3 ans (test)");
    let mut expected_list = vec![f.snap1, f.snap2, f.blob_old];
    expected_list.sort_unstable();
    assert_eq!(declaration.purged, expected_list);
}

/// `plan_purge` est la moitié « lecture » : le plan annonce exactement ce que
/// la purge fera, et n'a **aucun** effet sur le magasin (dry-run).
#[test]
fn le_plan_est_sans_effet() {
    let f = fixture();
    let before_blobs = f.store.blob_count();
    let before_snaps = f.store.snapshot_count();
    let before_entries = f.store.entry_count();

    let plan = plan_purge(&f.store, Timestamp(50_000)).unwrap().unwrap();
    assert_eq!(plan.snapshots, {
        let mut v = vec![f.snap1, f.snap2];
        v.sort_unstable();
        v
    });
    assert_eq!(plan.blobs, vec![f.blob_old]);
    assert_eq!(plan.from, Timestamp(1_000));
    assert_eq!(plan.to, Timestamp(2_000));
    assert!(plan.blob_bytes > 0);

    assert_eq!(f.store.blob_count(), before_blobs);
    assert_eq!(f.store.snapshot_count(), before_snaps);
    assert_eq!(f.store.entry_count(), before_entries);
}

/// Rejouer la purge est idempotent : rien à purger → rien d'écrit, pas de
/// déclaration vide accumulée.
#[test]
fn rejeu_idempotent() {
    let mut f = fixture();
    purge_older_than(
        &mut f.store,
        &f.signer,
        Timestamp(50_000),
        "rétention",
        Timestamp(200_000),
    )
    .unwrap()
    .unwrap();
    let entries_after_first = f.store.entry_count();

    let second = purge_older_than(
        &mut f.store,
        &f.signer,
        Timestamp(50_000),
        "rétention",
        Timestamp(300_000),
    )
    .unwrap();
    assert!(second.is_none(), "rien à purger au second passage");
    assert_eq!(f.store.entry_count(), entries_after_first);
}

/// Les enregistrements de purge survivent aux purges suivantes : sans eux,
/// les absences déjà déclarées redeviendraient des trous inexpliqués.
#[test]
fn les_declarations_de_purge_ne_sont_jamais_purgees() {
    let mut f = fixture();
    let first = purge_older_than(
        &mut f.store,
        &f.signer,
        Timestamp(50_000),
        "première",
        Timestamp(200_000),
    )
    .unwrap()
    .unwrap();

    // Seconde purge, seuil au-delà de TOUT (y compris la déclaration).
    let second = purge_older_than(
        &mut f.store,
        &f.signer,
        Timestamp(1_000_000),
        "seconde",
        Timestamp(2_000_000),
    )
    .unwrap()
    .unwrap();

    // snap3 et ses blobs sont partis, mais la première déclaration est intacte.
    assert!(!f.store.has_snapshot(&f.snap3).unwrap());
    assert!(!f.store.has_blob(&f.blob_shared).unwrap());
    assert!(!f.store.has_blob(&f.blob_new).unwrap());
    assert!(f.store.has_blob(&first.declaration_blob).unwrap());
    assert_eq!(second.snapshots_purged, 1);
    // La chaîne complète (3 collectes + 2 déclarations) se vérifie toujours.
    let entries = f.store.entries().unwrap();
    assert_eq!(entries.len(), 5);
    verify_chain(&entries, &f.signer.verifying_key()).unwrap();
}

/// Après purge, l'export réussit (absences déclarées) ; une absence NON
/// déclarée continue de faire échouer l'export — la distinction est toute la
/// valeur du dispositif.
#[test]
fn export_tolere_le_declare_et_refuse_le_reste() {
    let mut f = fixture();
    purge_older_than(
        &mut f.store,
        &f.signer,
        Timestamp(50_000),
        "rétention",
        Timestamp(200_000),
    )
    .unwrap()
    .unwrap();

    let dir = std::env::temp_dir().join(format!(
        "constat-store-purge-export-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    export_store(&f.store, &dir, &f.signer.verifying_key()).unwrap();
    // L'export ne contient ni les objets purgés, ni de trou non déclaré.
    assert!(!dir
        .join("snapshots")
        .join(format!("{}.cbor", f.snap1.to_hex()))
        .exists());
    assert!(dir
        .join("blobs")
        .join(format!("{}.cbor", f.blob_shared.to_hex()))
        .exists());
    let _ = std::fs::remove_dir_all(&dir);

    // Suppression sauvage (sans déclaration) : l'export doit crier.
    f.store.delete_blob(&f.blob_new).unwrap();
    let dir2 = std::env::temp_dir().join(format!(
        "constat-store-purge-export2-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir2);
    let err = export_store(&f.store, &dir2, &f.signer.verifying_key()).unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)));
    let _ = std::fs::remove_dir_all(&dir2);
}

/// Le backend persistant supprime réellement — et uniquement — blobs et
/// snapshots : le journal, lui, ne rétrécit jamais.
#[test]
fn redb_supprime_blobs_et_snapshots_jamais_le_journal() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = RedbStore::open(dir.path().join("magasin.redb")).unwrap();
    let signer = Signer::generate();

    let old = store.put_blob(&blob("linux.sshd", "vieux")).unwrap();
    let snap_old = store
        .put_snapshot(&Snapshot::new(
            "srv-01",
            Timestamp(1_000),
            BTreeMap::from([(CollectorId("linux.sshd".to_string()), old)]),
        ))
        .unwrap();
    let recent = store.put_blob(&blob("linux.sshd", "récent")).unwrap();
    let snap_recent = store
        .put_snapshot(&Snapshot::new(
            "srv-01",
            Timestamp(100_000),
            BTreeMap::from([(CollectorId("linux.sshd".to_string()), recent)]),
        ))
        .unwrap();
    append_signed(&mut store, &signer, vec![snap_old], Timestamp(1_000)).unwrap();
    append_signed(&mut store, &signer, vec![snap_recent], Timestamp(100_000)).unwrap();

    let report = purge_older_than(
        &mut store,
        &signer,
        Timestamp(50_000),
        "rétention",
        Timestamp(200_000),
    )
    .unwrap()
    .unwrap();
    assert_eq!(report.snapshots_purged, 1);
    assert_eq!(report.blobs_purged, 1);
    assert!(!store.has_blob(&old).unwrap());
    assert!(!store.has_snapshot(&snap_old).unwrap());
    assert!(store.has_blob(&recent).unwrap());

    // Le journal est complet (2 collectes + 1 déclaration) et vérifiable.
    let entries = store.entries().unwrap();
    assert_eq!(entries.len(), 3);
    verify_chain(&entries, &signer.verifying_key()).unwrap();

    // Suppression idempotente : re-supprimer un objet absent rend false.
    assert!(!store.delete_blob(&old).unwrap());
    assert!(!store.delete_snapshot(&snap_old).unwrap());
}
