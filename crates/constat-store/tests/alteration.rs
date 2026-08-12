//! LE test d'altération (§12) — la promesse centrale du produit.
//!
//! On stocke des blobs, des snapshots et des entrées de journal, puis on
//! altère volontairement le magasin (un octet d'un blob, remplacement d'une
//! entrée du journal, troncature) et on vérifie que la vérification CRIE
//! dans chaque cas.
//!
//! Dernier test : la limite documentée (§6.2) — la troncature de la FIN du
//! journal par le détenteur de la clé n'est PAS détectable par la cohérence
//! interne ; seule la comparaison avec une racine ancrée à l'extérieur la
//! révèle.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use constat_model::{
    from_canonical_bytes, to_canonical_bytes, AssetId, Blob, BlobHash, CollectorId, Fact, Snapshot,
    Timestamp, Value,
};
use constat_store::journal::{append_signed, verify_chain, ChainError};
use constat_store::{JournalEntry, RedbStore, Signer, Store, StoreError};
use redb::{Database, ReadableTable, TableDefinition};

const BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");
const JOURNAL: TableDefinition<u64, &[u8]> = TableDefinition::new("journal");
const ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entries");

fn sample_blob(i: u8) -> Blob {
    Blob {
        collector: CollectorId("linux.sshd".into()),
        raw: format!("# sshd_config {i}\nPermitRootLogin no\nPasswordAuthentication no\n")
            .into_bytes(),
        facts: vec![Fact {
            entity: constat_model::EntityId("service:sshd".into()),
            attribute: constat_model::Attribute("sshd.PermitRootLogin".into()),
            value: Value::Text("no".into()),
        }],
    }
}

/// Peuple un magasin : 3 collectes → 3 blobs, 3 snapshots, 3 entrées signées.
/// Retourne (empreintes des blobs, racine finale).
fn populate(store: &mut RedbStore, signer: &Signer) -> (Vec<BlobHash>, BlobHash) {
    let mut blob_hashes = Vec::new();
    for i in 0..3u8 {
        let blob_hash = store.put_blob(&sample_blob(i)).unwrap();
        blob_hashes.push(blob_hash);
        let snapshot = Snapshot {
            asset: AssetId("srv-fic-01".into()),
            at: Timestamp(1_000 + i64::from(i)),
            blobs: BTreeMap::from([(CollectorId("linux.sshd".into()), blob_hash)]),
        };
        let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
        append_signed(
            store,
            signer,
            vec![snapshot_hash],
            Timestamp(1_000 + i64::from(i)),
        )
        .unwrap();
    }
    let root = store.root().unwrap().expect("journal non vide");
    (blob_hashes, root)
}

/// Ouvre le fichier redb directement (hors API du magasin) pour simuler
/// un attaquant qui modifie le fichier sur le disque.
fn tamper<F: FnOnce(&redb::WriteTransaction)>(path: &Path, f: F) {
    let db = Database::create(path).unwrap();
    let tx = db.begin_write().unwrap();
    f(&tx);
    tx.commit().unwrap();
}

// ---------------------------------------------------------------------------
// 1. Altération d'un blob : modifier un octet du contenu stocké.
// ---------------------------------------------------------------------------

#[test]
fn blob_altere_contenu_recompresse_detecte() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.redb");
    let signer = Signer::generate();
    let (blob_hashes, _) = {
        let mut store = RedbStore::open(&path).unwrap();
        populate(&mut store, &signer)
    };
    let target = blob_hashes[0];

    // L'attaquant décompresse, modifie UN octet du contenu ("no" → "nO"),
    // recompresse proprement et réécrit : la valeur stockée est parfaitement
    // bien formée, seule l'empreinte peut le trahir.
    tamper(&path, |tx| {
        let mut table = tx.open_table(BLOBS).unwrap();
        let stored = table
            .get(target.0.as_slice())
            .unwrap()
            .expect("blob présent")
            .value()
            .to_vec();
        let mut bytes = zstd::stream::decode_all(stored.as_slice()).unwrap();
        let mut blob: Blob = from_canonical_bytes(&bytes).unwrap();
        let pos = blob
            .raw
            .windows(2)
            .position(|w| w == b"no")
            .expect("motif présent");
        blob.raw[pos + 1] = b'O';
        bytes = to_canonical_bytes(&blob).unwrap();
        let recompressed = zstd::stream::encode_all(bytes.as_slice(), 3).unwrap();
        table
            .insert(target.0.as_slice(), recompressed.as_slice())
            .unwrap();
    });

    let store = RedbStore::open(&path).unwrap();
    let err = store
        .get_blob(&target)
        .expect_err("l'altération doit crier");
    assert!(
        matches!(err, StoreError::ChainBroken(_)),
        "attendu ChainBroken, obtenu : {err}"
    );
    // Les autres blobs restent lisibles : l'altération est localisée.
    assert!(store.get_blob(&blob_hashes[1]).is_ok());
}

#[test]
fn blob_altere_octet_brut_detecte() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.redb");
    let signer = Signer::generate();
    let (blob_hashes, _) = {
        let mut store = RedbStore::open(&path).unwrap();
        populate(&mut store, &signer)
    };
    let target = blob_hashes[1];

    // Variante brutale : un octet retourné au milieu du flux compressé.
    tamper(&path, |tx| {
        let mut table = tx.open_table(BLOBS).unwrap();
        let mut stored = table
            .get(target.0.as_slice())
            .unwrap()
            .expect("blob présent")
            .value()
            .to_vec();
        let mid = stored.len() / 2;
        stored[mid] ^= 0xFF;
        table
            .insert(target.0.as_slice(), stored.as_slice())
            .unwrap();
    });

    let store = RedbStore::open(&path).unwrap();
    assert!(
        store.get_blob(&target).is_err(),
        "un octet altéré dans le blob stocké doit faire échouer la lecture"
    );
}

// ---------------------------------------------------------------------------
// 2. Remplacement d'une entrée du journal.
// ---------------------------------------------------------------------------

#[test]
fn entree_remplacee_detectee_par_empreinte() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.redb");
    let signer = Signer::generate();
    {
        let mut store = RedbStore::open(&path).unwrap();
        populate(&mut store, &signer);
        verify_chain(&store.entries().unwrap(), &signer.verifying_key())
            .expect("chaîne intacte avant altération");
    }

    // L'attaquant remplace le CONTENU de l'entrée d'index 1 (il antidate la
    // collecte) sans pouvoir mettre à jour l'empreinte référencée ailleurs.
    tamper(&path, |tx| {
        let journal = tx.open_table(JOURNAL).unwrap();
        let hash1 = journal
            .get(1u64)
            .unwrap()
            .expect("entrée 1")
            .value()
            .to_vec();
        drop(journal);
        let mut entries = tx.open_table(ENTRIES).unwrap();
        let stored = entries
            .get(hash1.as_slice())
            .unwrap()
            .expect("entrée présente")
            .value()
            .to_vec();
        let mut entry: JournalEntry = from_canonical_bytes(&stored).unwrap();
        entry.at = Timestamp(1); // antidatage
        let forged = to_canonical_bytes(&entry).unwrap();
        entries.insert(hash1.as_slice(), forged.as_slice()).unwrap();
    });

    let store = RedbStore::open(&path).unwrap();
    let err = verify_chain(&store.entries().unwrap(), &signer.verifying_key())
        .expect_err("l'entrée remplacée doit crier");
    assert!(
        matches!(err, ChainError::HashMismatch { index: 1, .. }),
        "attendu HashMismatch à l'index 1, obtenu : {err}"
    );
}

#[test]
fn entree_reforgee_par_cle_etrangere_detectee_par_signature() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.redb");
    let signer = Signer::generate();
    let attacker = Signer::generate();
    let last_prev;
    {
        let mut store = RedbStore::open(&path).unwrap();
        populate(&mut store, &signer);
        let entries = store.entries().unwrap();
        last_prev = entries[2].1.prev;
    }

    // Attaque plus soignée : l'attaquant reforge la DERNIÈRE entrée avec sa
    // propre clé (chaînage `prev` correct, empreinte cohérente : il met aussi
    // à jour l'index du journal). Seule la signature peut le trahir.
    let forged = attacker
        .sign_entry(last_prev, vec![], Timestamp(9_999))
        .unwrap();
    let forged_hash = constat_store::journal::entry_hash(&forged).unwrap();
    let forged_bytes = to_canonical_bytes(&forged).unwrap();
    tamper(&path, |tx| {
        let mut entries = tx.open_table(ENTRIES).unwrap();
        entries
            .insert(forged_hash.0.as_slice(), forged_bytes.as_slice())
            .unwrap();
        let mut journal = tx.open_table(JOURNAL).unwrap();
        journal.insert(2u64, forged_hash.0.as_slice()).unwrap();
    });

    let store = RedbStore::open(&path).unwrap();
    let err = verify_chain(&store.entries().unwrap(), &signer.verifying_key())
        .expect_err("l'entrée reforgée doit crier");
    assert!(
        matches!(err, ChainError::BadSignature { index: 2 }),
        "attendu BadSignature à l'index 2, obtenu : {err}"
    );
}

// ---------------------------------------------------------------------------
// 3. Troncature.
// ---------------------------------------------------------------------------

#[test]
fn troncature_au_milieu_detectee() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.redb");
    let signer = Signer::generate();
    {
        let mut store = RedbStore::open(&path).unwrap();
        populate(&mut store, &signer);
    }

    // Suppression de l'entrée du MILIEU du journal.
    tamper(&path, |tx| {
        let mut journal = tx.open_table(JOURNAL).unwrap();
        journal.remove(1u64).unwrap();
    });

    let store = RedbStore::open(&path).unwrap();
    let entries = store.entries().unwrap();
    assert_eq!(entries.len(), 2);
    let err = verify_chain(&entries, &signer.verifying_key())
        .expect_err("la troncature au milieu doit crier");
    assert!(
        matches!(err, ChainError::BrokenLink { index: 1, .. }),
        "attendu BrokenLink à l'index 1, obtenu : {err}"
    );
}

#[test]
fn troncature_de_la_fin_invisible_en_interne_mais_visible_par_la_racine_ancree() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.redb");
    let signer = Signer::generate();
    let anchored_root; // racine « envoyée au RSSI » avant l'attaque (§6.3 niveau 2)
    {
        let mut store = RedbStore::open(&path).unwrap();
        let (_, root) = populate(&mut store, &signer);
        anchored_root = root;
    }

    // Le détenteur de la clé supprime la DERNIÈRE entrée (et son maillon).
    tamper(&path, |tx| {
        let mut journal = tx.open_table(JOURNAL).unwrap();
        let removed = journal
            .remove(2u64)
            .unwrap()
            .expect("entrée 2")
            .value()
            .to_vec();
        drop(journal);
        let mut entries = tx.open_table(ENTRIES).unwrap();
        entries.remove(removed.as_slice()).unwrap();
    });

    let store = RedbStore::open(&path).unwrap();
    let entries = store.entries().unwrap();
    assert_eq!(entries.len(), 2);

    // §6.2, noir sur blanc : la chaîne restante est parfaitement valide.
    // La cohérence interne NE détecte PAS la troncature de la fin.
    verify_chain(&entries, &signer.verifying_key())
        .expect("limite documentée : la troncature de la fin passe la vérification interne");

    // C'est la racine ancrée À L'EXTÉRIEUR qui crie.
    let current_root = store.root().unwrap();
    assert_ne!(
        current_root,
        Some(anchored_root),
        "la racine courante doit différer de la racine ancrée : c'est l'ancrage externe \
         qui détecte la troncature, pas la chaîne elle-même"
    );
}
