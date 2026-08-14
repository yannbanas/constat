//! Purge déclarée (§16) côté vérificateur : un objet absent mais déclaré par
//! une purge journalisée postérieure est toléré ; un objet absent NON déclaré
//! reste une altération — LE test discriminant du dispositif.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use constat_model::{Blob, BlobHash, CollectorId, Fact, Snapshot, Timestamp, Value};
use constat_store::purge::{build_purge_blob, manifest_hash, PurgeDeclaration};
use constat_store::{
    export_store, journal::append_signed, purge_older_than, JournalEntry, MemoryStore, Signer,
    Store, PURGE_COLLECTOR,
};
use constat_verify::{verify_export, Export, VerifyError};

fn blob(collector: &str, raw: &str) -> Blob {
    Blob::new(
        collector,
        raw.as_bytes().to_vec(),
        vec![Fact::new("user:jdupont", "user.privileged", true)],
    )
}

/// Un magasin purgé : deux collectes anciennes (purgées), une récente, une
/// déclaration signée. Trois objets manquent de l'export et sont déclarés :
/// deux snapshots + un blob.
fn purged_store() -> (MemoryStore, Signer) {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();

    let blob_old = store.put_blob(&blob("linux.sshd", "ancien")).unwrap();
    let blob_shared = store.put_blob(&blob("linux.accounts", "partagé")).unwrap();
    let mut put_snap = |at: i64, blobs: Vec<(&str, BlobHash)>| {
        store
            .put_snapshot(&Snapshot::new(
                "srv-01",
                Timestamp(at),
                blobs
                    .into_iter()
                    .map(|(c, h)| (CollectorId(c.to_string()), h))
                    .collect::<BTreeMap<_, _>>(),
            ))
            .unwrap()
    };
    let snap1 = put_snap(
        1_000,
        vec![("linux.sshd", blob_old), ("linux.accounts", blob_shared)],
    );
    let snap2 = put_snap(2_000, vec![("linux.sshd", blob_old)]);
    let snap3 = put_snap(100_000, vec![("linux.accounts", blob_shared)]);
    append_signed(&mut store, &signer, vec![snap1], Timestamp(1_000)).unwrap();
    append_signed(&mut store, &signer, vec![snap2], Timestamp(2_000)).unwrap();
    append_signed(&mut store, &signer, vec![snap3], Timestamp(100_000)).unwrap();

    purge_older_than(
        &mut store,
        &signer,
        Timestamp(50_000),
        "rétention 3 ans (test)",
        Timestamp(200_000),
    )
    .unwrap()
    .unwrap();
    (store, signer)
}

/// Reconstruit l'`Export` en mémoire depuis l'état du magasin : les entrées,
/// et tout objet référencé **encore présent**.
fn export_of(store: &MemoryStore, signer: &Signer) -> Export {
    let entries: Vec<JournalEntry> = store
        .entries()
        .unwrap()
        .into_iter()
        .map(|(_, e)| e)
        .collect();
    let mut snapshots = BTreeMap::new();
    let mut blobs = BTreeMap::new();
    for entry in &entries {
        for sh in &entry.snapshots {
            if !store.has_snapshot(sh).unwrap() {
                continue;
            }
            let snapshot = store.get_snapshot(sh).unwrap();
            for bh in snapshot.blobs.values() {
                if store.has_blob(bh).unwrap() {
                    blobs.insert(*bh, store.get_blob(bh).unwrap());
                }
            }
            snapshots.insert(*sh, snapshot);
        }
    }
    Export {
        entries,
        snapshots,
        blobs,
        public_key: signer.verifying_key().to_bytes(),
    }
}

/// Un export purgé est cohérent : les absences déclarées sont comptées, la
/// déclaration (période, motif) est restituée.
#[test]
fn un_export_purge_est_accepte_avec_le_compte_des_purges() {
    let (store, signer) = purged_store();
    let export = export_of(&store, &signer);

    let ok = verify_export(&export).unwrap();
    // 2 snapshots absents et déclarés. Le blob purgé n'est référencé que par
    // eux : aucune référence vivante ne le demande, il n'est donc pas compté
    // — `purged_count` compte les absences RENCONTRÉES et tolérées.
    assert_eq!(ok.purged_count, 2);
    assert_eq!(ok.purges.len(), 1);
    assert_eq!(ok.purges[0].reason, "rétention 3 ans (test)");
    assert_eq!(ok.purges[0].from, Timestamp(1_000));
    assert_eq!(ok.purges[0].to, Timestamp(2_000));
    assert_eq!(ok.purges[0].objects, 3);
    // 4 entrées : 3 collectes + la déclaration.
    assert_eq!(ok.entry_count, 4);
}

/// LE test discriminant : dans le même export purgé, retirer UN objet non
/// déclaré — la vérification doit crier, purge ou pas.
#[test]
fn un_objet_manquant_non_declare_reste_refuse() {
    let (store, signer) = purged_store();

    // Un blob conservé (non déclaré) disparaît de l'export.
    let mut export = export_of(&store, &signer);
    let (kept_blob, _) = export
        .blobs
        .iter()
        .find(|(_, b)| b.collector.0 != PURGE_COLLECTOR)
        .map(|(h, b)| (*h, b.clone()))
        .unwrap();
    export.blobs.remove(&kept_blob);
    match verify_export(&export).unwrap_err() {
        VerifyError::BlobManquant { hash, .. } => assert_eq!(hash, kept_blob),
        autre => panic!("attendu BlobManquant, obtenu : {autre:?}"),
    }

    // Un snapshot conservé (non déclaré) disparaît de l'export.
    let mut export = export_of(&store, &signer);
    let kept_snapshot = *export
        .snapshots
        .iter()
        .find(|(_, s)| s.at == Timestamp(100_000))
        .map(|(h, _)| h)
        .unwrap();
    export.snapshots.remove(&kept_snapshot);
    match verify_export(&export).unwrap_err() {
        VerifyError::SnapshotManquant { hash, .. } => assert_eq!(hash, kept_snapshot),
        autre => panic!("attendu SnapshotManquant, obtenu : {autre:?}"),
    }
}

/// La déclaration doit être POSTÉRIEURE à la référence manquante : une purge
/// déclarée avant la donnée qu'elle prétend couvrir ne couvre rien.
#[test]
fn une_declaration_anterieure_ne_couvre_rien() {
    let signer = Signer::generate();

    // Le snapshot « victime », absent de l'export.
    let victim = Snapshot::new("srv-01", Timestamp(1_000), BTreeMap::new());
    let victim_hash = constat_model::snapshot_hash(&victim).unwrap();

    // Déclaration de purge qui couvre la victime… placée à l'entrée 0,
    // AVANT l'entrée qui la référence.
    let purged = vec![victim_hash];
    let declaration = PurgeDeclaration {
        from: Timestamp(1_000),
        to: Timestamp(1_000),
        reason: "purge prophétique".to_string(),
        objects: 1,
        manifest: manifest_hash(&purged).unwrap(),
        purged,
    };
    let purge_blob = build_purge_blob(&declaration, Timestamp(500));
    let purge_blob_hash = constat_model::blob_hash(&purge_blob).unwrap();
    let purge_snap = Snapshot::new(
        "constat",
        Timestamp(500),
        BTreeMap::from([(CollectorId(PURGE_COLLECTOR.to_string()), purge_blob_hash)]),
    );
    let purge_snap_hash = constat_model::snapshot_hash(&purge_snap).unwrap();

    let entry0 = signer
        .sign_entry(None, vec![purge_snap_hash], Timestamp(500))
        .unwrap();
    let entry0_hash = constat_model::hash_canonical(&entry0).unwrap();
    let entry1 = signer
        .sign_entry(Some(entry0_hash), vec![victim_hash], Timestamp(1_000))
        .unwrap();

    let export = Export {
        entries: vec![entry0, entry1],
        snapshots: BTreeMap::from([(purge_snap_hash, purge_snap)]),
        blobs: BTreeMap::from([(purge_blob_hash, purge_blob)]),
        public_key: signer.verifying_key().to_bytes(),
    };
    match verify_export(&export).unwrap_err() {
        VerifyError::SnapshotManquant { index, hash } => {
            assert_eq!(index, 1);
            assert_eq!(hash, victim_hash);
        }
        autre => panic!("attendu SnapshotManquant, obtenu : {autre:?}"),
    }
}

/// Une déclaration incohérente (manifeste faux) ne couvre rien : l'export
/// est refusé avec le diagnostic dédié, jamais vérifié « sur parole ».
#[test]
fn une_declaration_incoherente_est_refusee() {
    let signer = Signer::generate();

    let victim = Snapshot::new("srv-01", Timestamp(1_000), BTreeMap::new());
    let victim_hash = constat_model::snapshot_hash(&victim).unwrap();

    // Déclaration dont le fait purge.manifest ne correspond PAS à la liste.
    let purged = vec![victim_hash];
    let declaration = PurgeDeclaration {
        from: Timestamp(1_000),
        to: Timestamp(1_000),
        reason: "manifeste faux".to_string(),
        objects: 1,
        manifest: manifest_hash(&purged).unwrap(),
        purged,
    };
    let mut purge_blob = build_purge_blob(&declaration, Timestamp(2_000));
    // Corrompt le fait purge.manifest (le blob reste auto-cohérent côté
    // empreinte : c'est la déclaration qui est incohérente, pas le fichier).
    for fact in &mut purge_blob.facts {
        if fact.attribute.0 == "purge.manifest" {
            fact.value = Value::Fingerprint([0xEE; 32]);
        }
    }
    purge_blob.canonicalize();
    let purge_blob_hash = constat_model::blob_hash(&purge_blob).unwrap();
    let purge_snap = Snapshot::new(
        "constat",
        Timestamp(2_000),
        BTreeMap::from([(CollectorId(PURGE_COLLECTOR.to_string()), purge_blob_hash)]),
    );
    let purge_snap_hash = constat_model::snapshot_hash(&purge_snap).unwrap();

    let entry0 = signer
        .sign_entry(None, vec![victim_hash], Timestamp(1_000))
        .unwrap();
    let entry0_hash = constat_model::hash_canonical(&entry0).unwrap();
    let entry1 = signer
        .sign_entry(Some(entry0_hash), vec![purge_snap_hash], Timestamp(2_000))
        .unwrap();

    let export = Export {
        entries: vec![entry0, entry1],
        snapshots: BTreeMap::from([(purge_snap_hash, purge_snap)]),
        blobs: BTreeMap::from([(purge_blob_hash, purge_blob)]),
        public_key: signer.verifying_key().to_bytes(),
    };
    match verify_export(&export).unwrap_err() {
        VerifyError::DeclarationPurgeInvalide { blob, .. } => assert_eq!(blob, purge_blob_hash),
        autre => panic!("attendu DeclarationPurgeInvalide, obtenu : {autre:?}"),
    }
}

/// Bout en bout avec le VRAI binaire : un export sur disque d'un magasin
/// purgé est accepté, et la sortie déclare les purges (nombre, motif).
#[test]
fn le_binaire_accepte_un_export_purge_et_le_dit() {
    let (store, signer) = purged_store();
    let dir: PathBuf = std::env::temp_dir()
        .join("constat-verify-tests")
        .join(format!("purge-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    export_store(&store, &dir, &signer.verifying_key()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_constat-verify"))
        .arg(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "le binaire doit accepter un export purgé\nstdout : {stdout}\nstderr : {stderr}"
    );
    assert!(
        stdout.contains("2 objet(s) purgé(s) déclaré(s)"),
        "la sortie doit compter les purges : {stdout}"
    );
    assert!(
        stdout.contains("rétention 3 ans (test)"),
        "la sortie doit citer le motif : {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
