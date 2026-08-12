//! Tests par propriétés : roundtrip put/get et déduplication idempotente,
//! sur les deux implémentations du magasin.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use constat_model::{Attribute, Blob, CollectorId, EntityId, Fact, Snapshot, Timestamp, Value};
use constat_store::{MemoryStore, RedbStore, Store};
use proptest::prelude::*;

fn value_strategy() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::Int),
        "[a-zA-Z0-9 ._-]{0,32}".prop_map(Value::Text),
        any::<[u8; 32]>().prop_map(Value::Fingerprint),
        Just(Value::Absent),
    ]
}

fn fact_strategy() -> impl Strategy<Value = Fact> {
    (
        "[a-z]{1,8}:[a-z0-9-]{1,12}",
        "[a-z]{1,8}\\.[a-zA-Z]{1,12}",
        value_strategy(),
    )
        .prop_map(|(entity, attribute, value)| Fact {
            entity: EntityId(entity),
            attribute: Attribute(attribute),
            value,
        })
}

fn blob_strategy() -> impl Strategy<Value = Blob> {
    (
        "[a-z]{1,8}\\.[a-z]{1,8}",
        proptest::collection::vec(any::<u8>(), 0..2048),
        proptest::collection::vec(fact_strategy(), 0..8),
    )
        .prop_map(|(collector, raw, facts)| Blob {
            collector: CollectorId(collector),
            raw,
            facts,
        })
}

fn snapshot_strategy() -> impl Strategy<Value = Snapshot> {
    (
        "[a-z]{1,8}-[0-9]{1,3}",
        any::<i64>(),
        proptest::collection::btree_map(
            "[a-z]{1,8}\\.[a-z]{1,8}".prop_map(CollectorId),
            any::<[u8; 32]>().prop_map(constat_model::BlobHash),
            0..4,
        ),
    )
        .prop_map(|(asset, at, blobs)| Snapshot {
            asset: constat_model::AssetId(asset),
            at: Timestamp(at),
            blobs,
        })
}

proptest! {
    /// MemoryStore : ce qu'on range est exactement ce qu'on retrouve, et
    /// re-ranger le même objet est idempotent (même empreinte, aucun doublon).
    #[test]
    fn memory_roundtrip_et_dedup(blob in blob_strategy(), snapshot in snapshot_strategy()) {
        let mut store = MemoryStore::new();

        let h1 = store.put_blob(&blob).unwrap();
        prop_assert!(store.has_blob(&h1).unwrap());
        prop_assert_eq!(store.get_blob(&h1).unwrap(), blob.clone());

        // Déduplication idempotente.
        let h2 = store.put_blob(&blob).unwrap();
        prop_assert_eq!(h1, h2);
        prop_assert_eq!(store.blob_count(), 1);

        let s1 = store.put_snapshot(&snapshot).unwrap();
        prop_assert_eq!(store.get_snapshot(&s1).unwrap(), snapshot.clone());
        let s2 = store.put_snapshot(&snapshot).unwrap();
        prop_assert_eq!(s1, s2);
        prop_assert_eq!(store.snapshot_count(), 1);
    }
}

proptest! {
    // Moins de cas pour redb : chaque cas crée un fichier.
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// RedbStore : roundtrip à travers compression zstd + fichier, dédup idempotente.
    #[test]
    fn redb_roundtrip_et_dedup(blob in blob_strategy(), snapshot in snapshot_strategy()) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = RedbStore::open(dir.path().join("s.redb")).unwrap();

        let h1 = store.put_blob(&blob).unwrap();
        prop_assert!(store.has_blob(&h1).unwrap());
        prop_assert_eq!(store.get_blob(&h1).unwrap(), blob.clone());

        let h2 = store.put_blob(&blob).unwrap();
        prop_assert_eq!(h1, h2);
        prop_assert_eq!(store.blob_count().unwrap(), 1);

        let s1 = store.put_snapshot(&snapshot).unwrap();
        prop_assert_eq!(store.get_snapshot(&s1).unwrap(), snapshot.clone());
        let s2 = store.put_snapshot(&snapshot).unwrap();
        prop_assert_eq!(s1, s2);
        prop_assert_eq!(store.snapshot_count().unwrap(), 1);
    }
}

/// La dédup ne réécrit RIEN : le fichier est identique à l'octet près après
/// un second put du même objet (§3.3 — c'est ce qui rend viable trois ans de
/// rétention : une collecte sans changement n'écrit que des références).
#[test]
fn redb_dedup_ne_reecrit_rien() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.redb");
    let blob = Blob {
        collector: CollectorId("linux.sshd".into()),
        raw: b"PermitRootLogin no\n".repeat(50),
        facts: vec![],
    };
    let snapshot = Snapshot {
        asset: constat_model::AssetId("srv-fic-01".into()),
        at: Timestamp(42),
        blobs: BTreeMap::new(),
    };

    let (h_blob, h_snap) = {
        let mut store = RedbStore::open(&path).unwrap();
        (
            store.put_blob(&blob).unwrap(),
            store.put_snapshot(&snapshot).unwrap(),
        )
    };
    let before = std::fs::read(&path).unwrap();

    {
        let mut store = RedbStore::open(&path).unwrap();
        assert_eq!(store.put_blob(&blob).unwrap(), h_blob);
        assert_eq!(store.put_snapshot(&snapshot).unwrap(), h_snap);
        assert_eq!(store.blob_count().unwrap(), 1);
        assert_eq!(store.snapshot_count().unwrap(), 1);
    }
    let after = std::fs::read(&path).unwrap();
    assert_eq!(
        before, after,
        "put d'un objet déjà présent ne doit pas modifier le fichier d'un octet"
    );
}

/// La compression zstd est bien en place : un artefact texte répétitif
/// occupe nettement moins sur disque que sa taille brute (§9).
#[test]
fn redb_compresse_les_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.redb");
    // ~100 Kio de configuration texte très compressible.
    let raw = b"PermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\n".repeat(1600);
    let raw_len = raw.len();
    let blob = Blob {
        collector: CollectorId("linux.sshd".into()),
        raw,
        facts: vec![],
    };
    let hash = {
        let mut store = RedbStore::open(&path).unwrap();
        store.put_blob(&blob).unwrap()
    };

    // Lire les octets réellement stockés dans la table (le fichier redb est
    // préalloué par gros blocs, sa taille n'est pas un bon indicateur).
    let db = redb::Database::create(&path).unwrap();
    let tx = db.begin_read().unwrap();
    let table = tx
        .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("blobs"))
        .unwrap();
    let stored_len = table
        .get(hash.0.as_slice())
        .unwrap()
        .expect("blob présent")
        .value()
        .len();
    assert!(
        stored_len < raw_len / 5,
        "valeur stockée ({stored_len} o) >= 1/5 du brut ({raw_len} o) : compression absente ?"
    );
}
