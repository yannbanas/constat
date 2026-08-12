//! Test bout-en-bout inter-crates : un magasin réel (`constat-store`) rempli
//! et signé, exporté par `export_store`, puis vérifié par la bibliothèque ET
//! par le vrai binaire `constat-verify`.
//!
//! C'est le test qui garantit que le producteur (constat-store) et le
//! consommateur (constat-verify, FORMAT.md) parlent exactement le même
//! format — la dérive entre les deux invaliderait la promesse du §10.3.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use constat_model::{AssetId, Blob, CollectorId, Fact, Snapshot, Timestamp};
use constat_store::{export_store, journal::append_signed, MemoryStore, Signer, Store};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("constat-verify-tests")
        .join(format!("{}-{name}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_bin(dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_constat-verify"))
        .arg(dir)
        .output()
        .unwrap()
}

/// Remplit un magasin : 3 collectes chaînées et signées sur une machine.
fn populate(store: &mut MemoryStore, signer: &Signer) {
    for i in 0..3i64 {
        let blob = Blob {
            collector: CollectorId("linux.sshd".into()),
            raw: format!("PermitRootLogin no\n# collecte {i}\n").into_bytes(),
            facts: vec![Fact::new("service:sshd", "sshd.PermitRootLogin", "no")],
        };
        let blob_hash = store.put_blob(&blob).unwrap();
        let snapshot_hash = store
            .put_snapshot(&Snapshot {
                asset: AssetId("srv-fic-01".into()),
                at: Timestamp(1_000 + i),
                blobs: BTreeMap::from([(CollectorId("linux.sshd".into()), blob_hash)]),
            })
            .unwrap();
        append_signed(store, signer, vec![snapshot_hash], Timestamp(1_000 + i)).unwrap();
    }
}

#[test]
fn un_export_du_magasin_passe_le_verificateur_autonome() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    populate(&mut store, &signer);

    let dir = temp_dir("roundtrip-magasin");
    export_store(&store, &dir, &signer.verifying_key()).unwrap();

    // Le binaire réel accepte l'export et affiche la racine du magasin.
    let output = run_bin(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "le vérificateur doit accepter un export produit par constat-store\n\
         stdout : {stdout}\nstderr : {stderr}"
    );
    let root = store.root().unwrap().unwrap();
    assert!(
        stdout.contains(&root.to_hex()),
        "la racine affichée doit être celle du magasin : {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn un_export_du_magasin_altere_est_refuse() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    populate(&mut store, &signer);

    let dir = temp_dir("roundtrip-altere");
    export_store(&store, &dir, &signer.verifying_key()).unwrap();

    // Altération d'un octet du blob exporté, nom (empreinte annoncée) conservé.
    let blobs_dir = dir.join("blobs");
    let blob_file = std::fs::read_dir(&blobs_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let mut bytes = std::fs::read(blob_file.path()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(blob_file.path(), &bytes).unwrap();

    let output = run_bin(&dir);
    assert_eq!(
        output.status.code(),
        Some(1),
        "un export altéré doit être refusé"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
