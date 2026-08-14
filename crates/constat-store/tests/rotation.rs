//! Rotation de clé journalisée : la clé courante suit la chaîne, l'ancienne
//! clé délègue, l'usurpation est refusée, et une rotation n'est JAMAIS
//! purgée — sur les deux backends quand la propriété est structurelle.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use constat_model::{Blob, BlobHash, CollectorId, Fact, Snapshot, Timestamp, Value};
use constat_store::rotation::{
    build_rotation_blob, ATTR_ROTATION_NEW, ATTR_ROTATION_OLD, ROTATION_COLLECTOR,
};
use constat_store::{
    append_signed, current_key, genesis_key, purge_older_than, rotate_key, verify_chain,
    verify_chain_rotated, ChainError, MemoryStore, MultiJournalStore, RedbStore,
    RotationDeclaration, Signer, Store, StoreError,
};

fn collecte(store: &mut dyn Store, signer: &Signer, at: i64, contenu: &str) -> BlobHash {
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
    let (root, _) = append_signed(store, signer, vec![snapshot_hash], Timestamp(at)).unwrap();
    root
}

/// Rotation bout-en-bout : collectes avec l'ancienne clé, rotation, collectes
/// avec la nouvelle — la chaîne entière se vérifie en suivant la clé
/// courante, la clé de genèse se retrouve depuis le journal.
#[test]
fn rotation_bout_en_bout_suivie_par_la_verification() {
    let mut store = MemoryStore::new();
    let old = Signer::generate();
    let new = Signer::generate();
    let genesis = old.verifying_key().to_bytes();

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

    let entries = store.entries().unwrap();
    assert_eq!(entries.len(), 4);

    // La vérification rotation-consciente suit la clé courante.
    let trace = verify_chain_rotated(&store, &entries, &old.verifying_key()).unwrap();
    assert_eq!(trace.rotations, 1);
    assert_eq!(trace.final_key, new.verifying_key().to_bytes());

    // Les aides de lecture : clé courante et clé de genèse.
    assert_eq!(
        current_key(&store, &genesis, &entries).unwrap(),
        new.verifying_key().to_bytes()
    );
    assert_eq!(
        genesis_key(&store, &entries, &new.verifying_key().to_bytes()).unwrap(),
        genesis
    );

    // L'ancienne vérification mono-clé, elle, échoue après la rotation :
    // c'est le comportement sûr d'un vérificateur antérieur au format.
    assert!(matches!(
        verify_chain(&entries, &old.verifying_key()).unwrap_err(),
        ChainError::BadSignature { index: 3 }
    ));
}

/// Sans rotation, `verify_chain_rotated` rend le même verdict que
/// `verify_chain` et `genesis_key` retombe sur la clé courante : les
/// journaux existants se vérifient exactement comme avant.
#[test]
fn sans_rotation_rien_ne_change() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    collecte(&mut store, &signer, 1_000, "seule clé");

    let entries = store.entries().unwrap();
    verify_chain(&entries, &signer.verifying_key()).unwrap();
    let trace = verify_chain_rotated(&store, &entries, &signer.verifying_key()).unwrap();
    assert_eq!(trace.rotations, 0);
    assert_eq!(trace.final_key, signer.verifying_key().to_bytes());
    assert_eq!(
        genesis_key(&store, &entries, &signer.verifying_key().to_bytes()).unwrap(),
        signer.verifying_key().to_bytes()
    );
}

/// Usurpation : une « rotation » dont old_key n'est pas la clé courante —
/// quelqu'un tente de détourner la chaîne vers sa clé — est refusée, par la
/// vérification comme par `current_key`.
#[test]
fn rotation_usurpee_refusee() {
    let mut store = MemoryStore::new();
    let legitimate = Signer::generate();
    let attacker = Signer::generate();

    collecte(&mut store, &legitimate, 1_000, "légitime");

    // Le blob prétend déléguer depuis la clé de l'attaquant (≠ courante).
    let declaration = RotationDeclaration {
        old_key: attacker.verifying_key().to_bytes(),
        new_key: Signer::generate().verifying_key().to_bytes(),
        reason: Some("usurpation".into()),
    };
    let blob = build_rotation_blob(&declaration, Timestamp(2_000));
    let blob_hash = store.put_blob(&blob).unwrap();
    let snapshot = Snapshot::new(
        "constat",
        Timestamp(2_000),
        BTreeMap::from([(CollectorId(ROTATION_COLLECTOR.into()), blob_hash)]),
    );
    let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
    // L'entrée est signée par la clé légitime (le détenteur du magasin peut
    // toujours signer) : c'est bien old_key ≠ courante qui doit être refusé.
    append_signed(
        &mut store,
        &legitimate,
        vec![snapshot_hash],
        Timestamp(2_000),
    )
    .unwrap();

    let entries = store.entries().unwrap();
    let err = verify_chain_rotated(&store, &entries, &legitimate.verifying_key()).unwrap_err();
    assert!(
        matches!(err, ChainError::RotationInvalide { index: 1, .. }),
        "{err}"
    );
    let genesis = legitimate.verifying_key().to_bytes();
    assert!(matches!(
        current_key(&store, &genesis, &entries).unwrap_err(),
        StoreError::ChainBroken(_)
    ));
}

/// Une entrée de rotation signée par une clé étrangère (pas la courante) est
/// refusée dès la signature : la délégation exige l'ancienne clé privée.
#[test]
fn rotation_signee_par_une_cle_etrangere_refusee() {
    let mut store = MemoryStore::new();
    let legitimate = Signer::generate();
    let attacker = Signer::generate();
    let took_over = Signer::generate();

    collecte(&mut store, &legitimate, 1_000, "légitime");

    // Rotation « propre » sur le papier (old = clé courante !) mais l'entrée
    // est signée par l'attaquant : hors du magasin légitime, forgée à la main.
    let declaration = RotationDeclaration {
        old_key: legitimate.verifying_key().to_bytes(),
        new_key: took_over.verifying_key().to_bytes(),
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
    let prev = store.last_entry().unwrap().map(|(hash, _)| hash);
    let forged = attacker
        .sign_entry(prev, vec![snapshot_hash], Timestamp(2_000))
        .unwrap();
    store.append_entry(&forged).unwrap(); // le journal par défaut ne vérifie qu'au verify

    let entries = store.entries().unwrap();
    let err = verify_chain_rotated(&store, &entries, &legitimate.verifying_key()).unwrap_err();
    assert!(
        matches!(err, ChainError::BadSignature { index: 1 }),
        "{err}"
    );
}

/// Journaux nommés : la garde structurelle de l'append suit la clé courante.
/// Après une rotation valide, la nouvelle clé écrit dans le journal (nommé
/// par la clé de GENÈSE), l'ancienne ne peut plus, une tierce jamais.
#[test]
fn append_nomme_suit_la_cle_courante_sur_les_deux_backends() {
    let dir = std::env::temp_dir().join(format!(
        "constat-rotation-redb-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let redb = RedbStore::open(dir.join("magasin.redb")).unwrap();

    for mut store in [
        Box::new(MemoryStore::new()) as Box<dyn MultiJournalStore>,
        Box::new(redb) as Box<dyn MultiJournalStore>,
    ] {
        let old = Signer::generate();
        let new = Signer::generate();
        let third = Signer::generate();
        let journal = old.verifying_key().to_bytes(); // l'identité : la GENÈSE

        // Genèse signée par la clé de genèse.
        let entry0 = old.sign_entry(None, vec![], Timestamp(1_000)).unwrap();
        let root0 = store.append_entry_in(&journal, &entry0).unwrap();

        // Entrée de rotation (blob + snapshot dans le magasin partagé),
        // signée par l'ancienne clé.
        let declaration = RotationDeclaration {
            old_key: old.verifying_key().to_bytes(),
            new_key: new.verifying_key().to_bytes(),
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
        let rotation_entry = old
            .sign_entry(Some(root0), vec![snapshot_hash], Timestamp(2_000))
            .unwrap();
        let root1 = store.append_entry_in(&journal, &rotation_entry).unwrap();

        // La nouvelle clé écrit dans le journal de l'identité de genèse…
        let entry2 = new
            .sign_entry(Some(root1), vec![], Timestamp(3_000))
            .unwrap();
        let root2 = store.append_entry_in(&journal, &entry2).unwrap();

        // …l'ANCIENNE clé ne peut plus (elle a délégué)…
        let stale = old
            .sign_entry(Some(root2), vec![], Timestamp(4_000))
            .unwrap();
        assert!(matches!(
            store.append_entry_in(&journal, &stale).unwrap_err(),
            StoreError::ChainBroken(_)
        ));

        // …et une TIERCE clé jamais.
        let foreign = third
            .sign_entry(Some(root2), vec![], Timestamp(4_000))
            .unwrap();
        assert!(matches!(
            store.append_entry_in(&journal, &foreign).unwrap_err(),
            StoreError::ChainBroken(_)
        ));

        // La chaîne du journal nommé se vérifie depuis sa clé de genèse.
        let entries = store.entries_of(&journal).unwrap();
        let trace = verify_chain_rotated(&*store, &entries, &old.verifying_key()).unwrap();
        assert_eq!(trace.rotations, 1);
        assert_eq!(trace.final_key, new.verifying_key().to_bytes());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Purge × rotation : une entrée de rotation n'est JAMAIS purgée, même plus
/// ancienne que le seuil — la purger rendrait toute la suite invérifiable.
#[test]
fn la_purge_ne_purge_jamais_une_rotation() {
    let mut store = MemoryStore::new();
    let old = Signer::generate();
    let new = Signer::generate();

    collecte(&mut store, &old, 1_000, "vieille collecte");
    let (rotation_root, rotation_entry) = rotate_key(
        &mut store,
        &old,
        &new,
        Some("rotation ancienne"),
        Timestamp(2_000),
    )
    .unwrap();
    let _ = rotation_root;
    collecte(&mut store, &new, 100_000, "collecte récente");

    // Seuil bien au-delà de la rotation : la collecte de 1 000 ms est
    // purgée, l'enregistrement de rotation (2 000 ms) est conservé.
    let report = purge_older_than(
        &mut store,
        &new,
        Timestamp(50_000),
        "rétention (test)",
        Timestamp(200_000),
    )
    .unwrap()
    .expect("la vieille collecte devait être purgée");
    assert_eq!(report.snapshots_purged, 1);

    // Le snapshot et le blob de rotation sont toujours là.
    let rotation_snapshot = rotation_entry.snapshots[0];
    assert!(store.has_snapshot(&rotation_snapshot).unwrap());
    let snapshot = store.get_snapshot(&rotation_snapshot).unwrap();
    let rotation_blob = snapshot.blobs[&CollectorId(ROTATION_COLLECTOR.into())];
    assert!(store.has_blob(&rotation_blob).unwrap());

    // Et la chaîne complète (collectes + rotation + purge) se vérifie
    // toujours en suivant la clé courante.
    let entries = store.entries().unwrap();
    let trace = verify_chain_rotated(&store, &entries, &old.verifying_key()).unwrap();
    assert_eq!(trace.rotations, 1);
    assert_eq!(trace.final_key, new.verifying_key().to_bytes());
}

/// Le blob de rotation transporte bien les clés annoncées (faits
/// Fingerprint) : garde-fou sur le contrat normatif de FORMAT.md § 4 ter.
#[test]
fn le_blob_porte_les_cles_en_fingerprint() {
    let old = Signer::generate().verifying_key().to_bytes();
    let new = Signer::generate().verifying_key().to_bytes();
    let blob = build_rotation_blob(
        &RotationDeclaration {
            old_key: old,
            new_key: new,
            reason: None,
        },
        Timestamp(5_000),
    );
    let find = |attr: &str| {
        blob.facts
            .iter()
            .find(|f| f.attribute.0 == attr)
            .map(|f| f.value.clone())
    };
    assert_eq!(find(ATTR_ROTATION_OLD), Some(Value::Fingerprint(old)));
    assert_eq!(find(ATTR_ROTATION_NEW), Some(Value::Fingerprint(new)));
    assert!(blob.facts.iter().all(|f| f.entity.0 == "rotation:5000"));
}
