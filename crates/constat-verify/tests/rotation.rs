//! Rotation de clé (FORMAT.md § 4 ter) côté vérificateur : la clé courante
//! est suivie le long de la chaîne, l'usurpation est refusée, une rotation
//! absente n'est jamais tolérée — et le VRAI binaire le dit.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use constat_model::{Blob, CollectorId, Fact, Snapshot, Timestamp};
use constat_store::rotation::{build_rotation_blob, ROTATION_COLLECTOR};
use constat_store::{
    append_signed, export_store, purge_older_than, rotate_key, JournalEntry, MemoryStore,
    RotationDeclaration, Signer, Store,
};
use constat_verify::{verify_export, Export, VerifyError};

fn collecte(store: &mut MemoryStore, signer: &Signer, at: i64, contenu: &str) {
    let blob = Blob::new(
        "linux.sshd",
        format!("PermitRootLogin no # {contenu}\n").into_bytes(),
        vec![Fact::new("service:sshd", "sshd.PermitRootLogin", "no")],
    );
    let blob_hash = store.put_blob(&blob).unwrap();
    let snapshot = Snapshot::new(
        "srv-01",
        Timestamp(at),
        BTreeMap::from([(CollectorId("linux.sshd".into()), blob_hash)]),
    );
    let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
    append_signed(store, signer, vec![snapshot_hash], Timestamp(at)).unwrap();
}

/// Un magasin avec une rotation : deux collectes ancienne clé, la rotation,
/// une collecte nouvelle clé.
fn rotated_store() -> (MemoryStore, Signer, Signer) {
    let mut store = MemoryStore::new();
    let old = Signer::generate();
    let new = Signer::generate();
    collecte(&mut store, &old, 1_000, "avant");
    collecte(&mut store, &old, 2_000, "avant encore");
    rotate_key(
        &mut store,
        &old,
        &new,
        Some("rotation planifiée"),
        Timestamp(3_000),
    )
    .unwrap();
    collecte(&mut store, &new, 4_000, "après");
    (store, old, new)
}

/// Reconstruit l'`Export` en mémoire depuis l'état du magasin, avec la clé
/// de GENÈSE dans `public_key` (le contrat de `pubkey.bin`).
fn export_of(store: &MemoryStore, genesis: &Signer) -> Export {
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
        public_key: genesis.verifying_key().to_bytes(),
    }
}

/// La vérification suit la clé courante : l'export d'un journal avec
/// rotation est accepté, la rotation comptée, la clé finale rendue.
#[test]
fn un_export_avec_rotation_est_accepte_et_compte() {
    let (store, old, new) = rotated_store();
    let export = export_of(&store, &old);

    let ok = verify_export(&export).unwrap();
    assert_eq!(ok.rotation_count, 1);
    assert_eq!(ok.final_key, new.verifying_key().to_bytes());
    // 4 entrées : 2 collectes + la rotation + 1 collecte.
    assert_eq!(ok.entry_count, 4);
    assert_eq!(ok.purged_count, 0);
}

/// Usurpation : une rotation dont old_key n'est pas la clé courante est
/// refusée — `RotationInvalide`, export refusé.
#[test]
fn une_rotation_usurpee_est_refusee() {
    let mut store = MemoryStore::new();
    let legitimate = Signer::generate();
    let attacker = Signer::generate();
    collecte(&mut store, &legitimate, 1_000, "légitime");

    // Blob de rotation dont old_key est la clé de l'ATTAQUANT.
    let declaration = RotationDeclaration {
        old_key: attacker.verifying_key().to_bytes(),
        new_key: Signer::generate().verifying_key().to_bytes(),
        reason: None,
    };
    let blob = build_rotation_blob(&declaration, Timestamp(2_000));
    let blob_hash = store.put_blob(&blob).unwrap();
    let snapshot = Snapshot::new(
        "constat",
        Timestamp(2_000),
        BTreeMap::from([(CollectorId(ROTATION_COLLECTOR.into()), blob_hash)]),
    );
    let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
    append_signed(
        &mut store,
        &legitimate,
        vec![snapshot_hash],
        Timestamp(2_000),
    )
    .unwrap();

    let export = export_of(&store, &legitimate);
    match verify_export(&export).unwrap_err() {
        VerifyError::RotationInvalide { index, detail } => {
            assert_eq!(index, 1);
            assert!(detail.contains("usurpation"), "{detail}");
        }
        autre => panic!("attendu RotationInvalide, obtenu : {autre:?}"),
    }
}

/// Une entrée de rotation signée par une clé étrangère ne vérifie pas : la
/// délégation exige la signature de la clé courante.
#[test]
fn une_rotation_signee_par_une_cle_etrangere_est_refusee() {
    let (store, old, _new) = rotated_store();
    let mut export = export_of(&store, &old);

    // Re-signe l'entrée de rotation (index 2) avec une clé étrangère, en
    // réparant le chaînage aval pour isoler l'échec sur la signature.
    let attacker = Signer::generate();
    let e2 = &export.entries[2];
    let forged = attacker
        .sign_entry(e2.prev, e2.snapshots.clone(), e2.at)
        .unwrap();
    let forged_hash = constat_model::hash_canonical(&forged).unwrap();
    export.entries[2] = forged;
    export.entries[3].prev = Some(forged_hash);
    let e3 = &export.entries[3];
    export.entries[3] = attacker
        .sign_entry(e3.prev, e3.snapshots.clone(), e3.at)
        .unwrap();

    match verify_export(&export).unwrap_err() {
        VerifyError::SignatureInvalide { index } => assert_eq!(index, 2),
        autre => panic!("attendu SignatureInvalide, obtenu : {autre:?}"),
    }
}

/// Un blob de rotation absent n'est JAMAIS toléré — même si une purge
/// postérieure déclare son empreinte : une rotation n'est pas purgeable.
#[test]
fn un_blob_de_rotation_absent_reste_refuse_meme_declare_purge() {
    let (mut store, old, new) = rotated_store();
    // Une purge légitime existe dans la chaîne (elle ne couvre PAS la
    // rotation : plan_purge la protège) — puis on simule un magasin où le
    // blob de rotation a malgré tout disparu.
    collecte(&mut store, &new, 100_000, "récent");
    purge_older_than(
        &mut store,
        &new,
        Timestamp(50_000),
        "rétention (test)",
        Timestamp(200_000),
    )
    .unwrap()
    .unwrap();

    let mut export = export_of(&store, &old);
    let rotation_blob = *export
        .blobs
        .iter()
        .find(|(_, b)| b.collector.0 == ROTATION_COLLECTOR)
        .map(|(h, _)| h)
        .unwrap();
    export.blobs.remove(&rotation_blob);

    match verify_export(&export).unwrap_err() {
        VerifyError::RotationInvalide { detail, .. } => {
            assert!(detail.contains("jamais purgeable"), "{detail}")
        }
        autre => panic!("attendu RotationInvalide, obtenu : {autre:?}"),
    }
}

/// Purge et rotation cohabitent : l'export d'un magasin tourné PUIS purgé
/// se vérifie, avec le compte des deux.
#[test]
fn purge_et_rotation_cohabitent() {
    let (mut store, old, new) = rotated_store();
    collecte(&mut store, &new, 100_000, "récent");
    purge_older_than(
        &mut store,
        &new,
        Timestamp(50_000),
        "rétention (test)",
        Timestamp(200_000),
    )
    .unwrap()
    .unwrap();

    let export = export_of(&store, &old);
    let ok = verify_export(&export).unwrap();
    assert_eq!(ok.rotation_count, 1);
    assert_eq!(ok.final_key, new.verifying_key().to_bytes());
    assert_eq!(ok.purges.len(), 1);
    assert!(ok.purged_count > 0, "les collectes anciennes ont disparu");
}

/// Bout en bout avec le VRAI binaire : l'export sur disque d'un magasin
/// tourné est accepté, et la sortie annonce « 1 rotation(s) de clé » et la
/// clé finale abrégée.
#[test]
fn le_binaire_accepte_un_export_tourne_et_le_dit() {
    let (store, old, new) = rotated_store();
    let dir: PathBuf = std::env::temp_dir()
        .join("constat-verify-tests")
        .join(format!("rotation-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // pubkey.bin = la clé de GENÈSE : l'identité du journal ne change pas.
    export_store(&store, &dir, &old.verifying_key()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_constat-verify"))
        .arg(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "le binaire doit accepter un export tourné\nstdout : {stdout}\nstderr : {stderr}"
    );
    assert!(
        stdout.contains("1 rotation(s) de clé"),
        "la sortie doit compter les rotations : {stdout}"
    );
    let final_hex: String = new
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        stdout.contains(&format!("clé finale {}", &final_hex[..16])),
        "la sortie doit abréger la clé finale : {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
