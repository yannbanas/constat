//! Fabrique d'exports de test : un petit journal signé, valide par
//! construction, que chaque test altère ensuite à sa façon.

#![allow(clippy::unwrap_used, dead_code)]

use std::collections::BTreeMap;

use constat_model::{
    hash_canonical, to_canonical_bytes, AssetId, Attribute, Blob, BlobHash, CollectorId, EntityId,
    Fact, Snapshot, Timestamp, Value,
};
use constat_store::JournalEntry;
use constat_verify::Export;
use ed25519_dalek::{Signer, SigningKey};

/// Clé de test, déterministe.
pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// Signe une entrée selon le contrat : Ed25519 sur l'encodage canonique de
/// l'entrée avec le champ `signature` vidé.
pub fn signed_entry(prev: Option<BlobHash>, snapshots: Vec<BlobHash>, at: i64) -> JournalEntry {
    let mut entry = JournalEntry {
        prev,
        snapshots,
        at: Timestamp(at),
        signature: Vec::new(),
    };
    let message = to_canonical_bytes(&entry).unwrap();
    entry.signature = signing_key().sign(&message).to_bytes().to_vec();
    entry
}

fn blob(collector: &str, raw: &[u8]) -> Blob {
    Blob {
        collector: CollectorId(collector.to_owned()),
        raw: raw.to_vec(),
        facts: vec![Fact {
            entity: EntityId("service:sshd".to_owned()),
            attribute: Attribute("sshd.PermitRootLogin".to_owned()),
            value: Value::Text("no".to_owned()),
        }],
    }
}

/// Un export valide : 2 blobs, 2 snapshots, 3 entrées chaînées et signées.
pub fn valid_export() -> Export {
    let blob_a = blob("linux.sshd", b"PermitRootLogin no\n");
    let blob_b = blob("linux.accounts", b"root:x:0:0\n");
    let hash_a = hash_canonical(&blob_a).unwrap();
    let hash_b = hash_canonical(&blob_b).unwrap();

    let snap_1 = Snapshot {
        asset: AssetId("srv-fic-01".to_owned()),
        at: Timestamp(1_000),
        blobs: BTreeMap::from([(blob_a.collector.clone(), hash_a)]),
    };
    let snap_2 = Snapshot {
        asset: AssetId("srv-app-01".to_owned()),
        at: Timestamp(2_000),
        blobs: BTreeMap::from([
            (blob_a.collector.clone(), hash_a),
            (blob_b.collector.clone(), hash_b),
        ]),
    };
    let snap_hash_1 = hash_canonical(&snap_1).unwrap();
    let snap_hash_2 = hash_canonical(&snap_2).unwrap();

    let entry_0 = signed_entry(None, vec![snap_hash_1], 1_000);
    let entry_1 = signed_entry(
        Some(hash_canonical(&entry_0).unwrap()),
        vec![snap_hash_2],
        2_000,
    );
    let entry_2 = signed_entry(Some(hash_canonical(&entry_1).unwrap()), vec![], 3_000);

    Export {
        entries: vec![entry_0, entry_1, entry_2],
        snapshots: BTreeMap::from([(snap_hash_1, snap_1), (snap_hash_2, snap_2)]),
        blobs: BTreeMap::from([(hash_a, blob_a), (hash_b, blob_b)]),
        public_key: signing_key().verifying_key().to_bytes(),
    }
}

/// Écrit un export sur disque selon le layout normatif de FORMAT.md.
pub fn write_export(dir: &std::path::Path, export: &Export) {
    std::fs::create_dir_all(dir.join("snapshots")).unwrap();
    std::fs::create_dir_all(dir.join("blobs")).unwrap();
    std::fs::write(dir.join("pubkey.bin"), export.public_key).unwrap();
    for (i, entry) in export.entries.iter().enumerate() {
        std::fs::write(
            dir.join(format!("{i}.cbor")),
            to_canonical_bytes(entry).unwrap(),
        )
        .unwrap();
    }
    for (hash, snapshot) in &export.snapshots {
        std::fs::write(
            dir.join("snapshots")
                .join(format!("{}.cbor", hash.to_hex())),
            to_canonical_bytes(snapshot).unwrap(),
        )
        .unwrap();
    }
    for (hash, blob) in &export.blobs {
        std::fs::write(
            dir.join("blobs").join(format!("{}.cbor", hash.to_hex())),
            to_canonical_bytes(blob).unwrap(),
        )
        .unwrap();
    }
}
