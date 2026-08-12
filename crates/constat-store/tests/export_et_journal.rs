//! Tests d'intégration : journal Merkle (append, racine, vérification),
//! persistance de RedbStore, et export vers répertoire (layout consommé par
//! constat-verify).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use constat_model::{
    from_canonical_bytes, AssetId, Blob, BlobHash, CollectorId, Snapshot, Timestamp,
};
use constat_store::export::{BLOBS_DIR, PUBKEY_FILE, SNAPSHOTS_DIR};
use constat_store::journal::{append_signed, entry_hash, signable_bytes, verify_chain};
use constat_store::{export_store, JournalEntry, MemoryStore, RedbStore, Signer, Store};

fn blob(text: &str) -> Blob {
    Blob {
        collector: CollectorId("linux.sshd".into()),
        raw: text.as_bytes().to_vec(),
        facts: vec![],
    }
}

fn populate<S: Store>(store: &mut S, signer: &Signer) -> Vec<BlobHash> {
    let mut roots = Vec::new();
    for i in 0..3i64 {
        let blob_hash = store.put_blob(&blob(&format!("config v{i}"))).unwrap();
        let snapshot_hash = store
            .put_snapshot(&Snapshot {
                asset: AssetId("srv-fic-01".into()),
                at: Timestamp(i),
                blobs: BTreeMap::from([(CollectorId("linux.sshd".into()), blob_hash)]),
            })
            .unwrap();
        let (hash, _) = append_signed(store, signer, vec![snapshot_hash], Timestamp(i)).unwrap();
        roots.push(hash);
    }
    roots
}

#[test]
fn journal_chaine_et_racine() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    assert_eq!(store.root().unwrap(), None);

    let roots = populate(&mut store, &signer);
    let entries = store.entries().unwrap();
    assert_eq!(entries.len(), 3);

    // Genèse sans prev, chaînage exact, racine = dernière empreinte.
    assert_eq!(entries[0].1.prev, None);
    assert_eq!(entries[1].1.prev, Some(roots[0]));
    assert_eq!(entries[2].1.prev, Some(roots[1]));
    assert_eq!(store.root().unwrap(), Some(roots[2]));

    verify_chain(&entries, &signer.verifying_key()).expect("chaîne valide");

    // Une clé publique étrangère doit refuser la chaîne.
    let other = Signer::generate();
    assert!(verify_chain(&entries, &other.verifying_key()).is_err());
}

#[test]
fn schema_de_signature_contrat_inter_agents() {
    // Vérifie au bit près le schéma partagé avec constat-verify :
    // octets signables = entrée avec signature vidée ; empreinte = entrée complète.
    let signer = Signer::generate();
    let entry = signer
        .sign_entry(None, vec![BlobHash([7u8; 32])], Timestamp(123))
        .unwrap();

    let unsigned = JournalEntry {
        prev: entry.prev,
        snapshots: entry.snapshots.clone(),
        at: entry.at,
        signature: vec![],
    };
    let expected_bytes = constat_model::to_canonical_bytes(&unsigned).unwrap();
    assert_eq!(signable_bytes(&entry).unwrap(), expected_bytes);

    let expected_hash = constat_model::hash_canonical(&entry).unwrap();
    assert_eq!(entry_hash(&entry).unwrap(), expected_hash);

    // Et la signature vérifie avec ed25519-dalek sur exactement ces octets.
    let sig = constat_store::Signature::try_from(entry.signature.as_slice()).unwrap();
    signer
        .verifying_key()
        .verify_strict(&expected_bytes, &sig)
        .expect("signature conforme au schéma");
}

#[test]
fn append_refuse_un_prev_incoherent() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    populate(&mut store, &signer);

    // Entrée signée mais chaînée sur une empreinte qui n'est pas la dernière.
    let bogus = signer
        .sign_entry(Some(BlobHash([0u8; 32])), vec![], Timestamp(99))
        .unwrap();
    assert!(store.append_entry(&bogus).is_err());
}

#[test]
fn redb_persiste_apres_reouverture() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.redb");
    let signer = Signer::generate();
    let roots = {
        let mut store = RedbStore::open(&path).unwrap();
        populate(&mut store, &signer)
    };

    let store = RedbStore::open(&path).unwrap();
    assert_eq!(store.entry_count().unwrap(), 3);
    assert_eq!(store.root().unwrap(), Some(roots[2]));
    verify_chain(&store.entries().unwrap(), &signer.verifying_key())
        .expect("chaîne intacte après réouverture");
}

#[test]
fn export_layout_stable_et_autoverifiant() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    populate(&mut store, &signer);

    let out = dir.path().join("export");
    export_store(&store, &out, &signer.verifying_key()).unwrap();

    // 1. `pubkey.bin` : exactement les 32 octets de la clé publique.
    let pubkey = std::fs::read(out.join(PUBKEY_FILE)).unwrap();
    assert_eq!(pubkey, signer.verifying_key().as_bytes());

    // 2. Entrées `0.cbor` … `2.cbor` : indices consécutifs, et l'empreinte
    //    des octets du fichier est celle du magasin (chaînage `prev`).
    let entries = store.entries().unwrap();
    for (index, (hash, _)) in entries.iter().enumerate() {
        let bytes = std::fs::read(out.join(format!("{index}.cbor"))).unwrap();
        assert_eq!(
            hex::encode(blake3::hash(&bytes).as_bytes()),
            hash.to_hex(),
            "entrée {index} : blake3(fichier) doit être l'empreinte de chaînage"
        );
    }
    assert!(!out.join("3.cbor").exists());

    // 3. Chaque objet de snapshots/ et blobs/ est auto-vérifiant :
    //    blake3(contenu) == nom (sans l'extension .cbor).
    for sub in [SNAPSHOTS_DIR, BLOBS_DIR] {
        let dir_path = out.join(sub);
        let mut count = 0;
        for f in std::fs::read_dir(&dir_path).unwrap() {
            let f = f.unwrap();
            let bytes = std::fs::read(f.path()).unwrap();
            let name = f.file_name().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".cbor").expect("extension .cbor");
            assert_eq!(
                hex::encode(blake3::hash(&bytes).as_bytes()),
                stem,
                "objet {sub}/{name} : le contenu ne correspond pas à son nom"
            );
            count += 1;
        }
        assert_eq!(count, 3, "{sub} : 3 objets attendus");
    }

    // 4. La chaîne se reconstruit et se vérifie depuis les seuls fichiers,
    //    comme le fera constat-verify.
    let mut rebuilt = Vec::new();
    for index in 0..entries.len() {
        let bytes = std::fs::read(out.join(format!("{index}.cbor"))).unwrap();
        let entry: JournalEntry = from_canonical_bytes(&bytes).unwrap();
        let hash = BlobHash(*blake3::hash(&bytes).as_bytes());
        rebuilt.push((hash, entry));
    }
    verify_chain(&rebuilt, &signer.verifying_key())
        .expect("la chaîne exportée doit se vérifier hors magasin");

    // 5. Les blobs exportés sont décodables et portent le contenu d'origine.
    let (_, first) = &entries[0];
    let snap_bytes = std::fs::read(
        out.join(SNAPSHOTS_DIR)
            .join(format!("{}.cbor", first.snapshots[0].to_hex())),
    )
    .unwrap();
    let snap: Snapshot = from_canonical_bytes(&snap_bytes).unwrap();
    let blob_hash = snap.blobs.values().next().unwrap();
    let blob_bytes = std::fs::read(
        out.join(BLOBS_DIR)
            .join(format!("{}.cbor", blob_hash.to_hex())),
    )
    .unwrap();
    let exported: Blob = from_canonical_bytes(&blob_bytes).unwrap();
    assert_eq!(exported.raw, b"config v0");

    // 6. Idempotence : réexporter le même journal ne change rien.
    export_store(&store, &out, &signer.verifying_key()).unwrap();
}

#[test]
fn export_depuis_redb_identique_a_memory() {
    // Les deux backends doivent produire exactement le même export
    // (mêmes objets canoniques, mêmes empreintes).
    let tmp = tempfile::tempdir().unwrap();
    let signer_bytes = Signer::generate().to_bytes();
    let signer = Signer::from_bytes(&signer_bytes);

    let mut mem = MemoryStore::new();
    populate(&mut mem, &signer);
    let mut redb_store = RedbStore::open(tmp.path().join("s.redb")).unwrap();
    populate(&mut redb_store, &signer);

    let out_mem = tmp.path().join("export-mem");
    let out_redb = tmp.path().join("export-redb");
    export_store(&mem, &out_mem, &signer.verifying_key()).unwrap();
    export_store(&redb_store, &out_redb, &signer.verifying_key()).unwrap();

    for index in 0..3 {
        assert_eq!(
            std::fs::read(out_mem.join(format!("{index}.cbor"))).unwrap(),
            std::fs::read(out_redb.join(format!("{index}.cbor"))).unwrap(),
            "les deux backends doivent produire la même entrée {index} exportée"
        );
    }
    assert_eq!(
        std::fs::read(out_mem.join(PUBKEY_FILE)).unwrap(),
        std::fs::read(out_redb.join(PUBKEY_FILE)).unwrap(),
    );
}
