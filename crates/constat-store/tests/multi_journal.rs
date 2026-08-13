//! Tests d'intégration des journaux nommés (multi-agents, §13 S8) :
//! isolation des chaînes, propriété structurelle (une clé n'écrit que dans
//! son propre journal), migration transparente d'un magasin v0.1.0, et
//! export par journal au layout normatif de `constat-verify`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use constat_model::{
    from_canonical_bytes, AssetId, Blob, BlobHash, CollectorId, Snapshot, Timestamp,
};
use constat_store::export::{BLOBS_DIR, PUBKEY_FILE, SNAPSHOTS_DIR};
use constat_store::{
    append_signed, export_journal, verify_chain, JournalEntry, JournalId, MemoryStore,
    MultiJournalStore, RedbStore, Signer, Store, StoreError,
};

fn blob(text: &str) -> Blob {
    Blob {
        collector: CollectorId("linux.sshd".into()),
        raw: text.as_bytes().to_vec(),
        facts: vec![],
    }
}

/// Ajoute une collecte signée au journal nommé du signataire : blob +
/// snapshot + entrée chaînée sur la dernière entrée de CE journal.
fn append_collecte<S: MultiJournalStore + ?Sized>(
    store: &mut S,
    signer: &Signer,
    asset: &str,
    i: i64,
) -> BlobHash {
    let journal: JournalId = signer.verifying_key().to_bytes();
    let blob_hash = store.put_blob(&blob(&format!("{asset} v{i}"))).unwrap();
    let snapshot_hash = store
        .put_snapshot(&Snapshot {
            asset: AssetId(asset.into()),
            at: Timestamp(i),
            blobs: BTreeMap::from([(CollectorId("linux.sshd".into()), blob_hash)]),
        })
        .unwrap();
    let prev = store.last_entry_of(&journal).unwrap().map(|(h, _)| h);
    let entry = signer
        .sign_entry(prev, vec![snapshot_hash], Timestamp(i))
        .unwrap();
    store.append_entry_in(&journal, &entry).unwrap()
}

/// Deux signataires, poussées entrelacées : deux chaînes indépendantes,
/// chacune vérifiable avec sa clé, et le journal par défaut intact (vide).
fn deux_journaux_entrelaces<S: MultiJournalStore + ?Sized>(store: &mut S) {
    let a = Signer::generate();
    let b = Signer::generate();
    let journal_a: JournalId = a.verifying_key().to_bytes();
    let journal_b: JournalId = b.verifying_key().to_bytes();

    // Entrelacement volontaire : A, B, A, B, A.
    append_collecte(store, &a, "srv-a", 1);
    append_collecte(store, &b, "srv-b", 1);
    append_collecte(store, &a, "srv-a", 2);
    append_collecte(store, &b, "srv-b", 2);
    append_collecte(store, &a, "srv-a", 3);

    let entries_a = store.entries_of(&journal_a).unwrap();
    let entries_b = store.entries_of(&journal_b).unwrap();
    assert_eq!(entries_a.len(), 3);
    assert_eq!(entries_b.len(), 2);

    // Chaque chaîne se vérifie indépendamment, avec SA clé — et pas l'autre.
    verify_chain(&entries_a, &a.verifying_key()).expect("chaîne A intacte");
    verify_chain(&entries_b, &b.verifying_key()).expect("chaîne B intacte");
    assert!(verify_chain(&entries_a, &b.verifying_key()).is_err());

    // Racines distinctes, dernière entrée cohérente.
    let root_a = store.root_of(&journal_a).unwrap().unwrap();
    let root_b = store.root_of(&journal_b).unwrap().unwrap();
    assert_ne!(root_a, root_b);
    assert_eq!(store.last_entry_of(&journal_a).unwrap().unwrap().0, root_a);

    // L'inventaire liste les deux journaux, triés par identifiant.
    let mut expected = vec![journal_a, journal_b];
    expected.sort_unstable();
    assert_eq!(store.journals().unwrap(), expected);

    // Le journal par défaut n'a pas bougé : sémantique v0.1.0 inchangée.
    assert_eq!(store.root().unwrap(), None);
    assert!(store.entries().unwrap().is_empty());

    // Un journal inconnu est vide, pas une erreur.
    assert!(store.entries_of(&[0u8; 32]).unwrap().is_empty());
    assert_eq!(store.root_of(&[0u8; 32]).unwrap(), None);
}

#[test]
fn deux_journaux_entrelaces_en_memoire() {
    let mut store = MemoryStore::new();
    deux_journaux_entrelaces(&mut store);
}

#[test]
fn deux_journaux_entrelaces_sur_redb() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = RedbStore::open(dir.path().join("s.redb")).unwrap();
    deux_journaux_entrelaces(&mut store);
}

/// La propriété structurelle : une entrée signée par B est refusée dans le
/// journal de A, même avec un chaînage `prev` correct — et rien n'est écrit.
fn cle_etrangere_refusee<S: MultiJournalStore + ?Sized>(store: &mut S) {
    let a = Signer::generate();
    let b = Signer::generate();
    let journal_a: JournalId = a.verifying_key().to_bytes();

    let root_a = append_collecte(store, &a, "srv-a", 1);

    // B signe une entrée parfaitement chaînée sur la chaîne de A…
    let intruse = b.sign_entry(Some(root_a), vec![], Timestamp(2)).unwrap();
    let err = store.append_entry_in(&journal_a, &intruse).unwrap_err();
    assert!(matches!(err, StoreError::ChainBroken(_)), "{err}");

    // …et le journal de A n'a pas bougé.
    assert_eq!(store.entries_of(&journal_a).unwrap().len(), 1);
    assert_eq!(store.root_of(&journal_a).unwrap(), Some(root_a));

    // Un identifiant de journal qui n'est pas une clé Ed25519 valide est
    // refusé aussi (toutes les valeurs de 32 octets ne sont pas des points).
    let entry = a.sign_entry(None, vec![], Timestamp(1)).unwrap();
    let mut invalid: JournalId = [0xffu8; 32];
    invalid[31] = 0xff; // n'est pas un point de la courbe
    assert!(store.append_entry_in(&invalid, &entry).is_err());
}

#[test]
fn cle_etrangere_refusee_en_memoire() {
    let mut store = MemoryStore::new();
    cle_etrangere_refusee(&mut store);
}

#[test]
fn cle_etrangere_refusee_sur_redb() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = RedbStore::open(dir.path().join("s.redb")).unwrap();
    cle_etrangere_refusee(&mut store);
}

/// Le chaînage par journal : un `prev` qui ne raccorde pas à la dernière
/// entrée de CE journal est refusé, même signé par la bonne clé.
#[test]
fn prev_incoherent_refuse_par_journal() {
    let mut store = MemoryStore::new();
    let a = Signer::generate();
    let journal_a: JournalId = a.verifying_key().to_bytes();
    append_collecte(&mut store, &a, "srv-a", 1);

    // Une seconde genèse (prev = None) alors que le journal a déjà une entrée.
    let fork = a.sign_entry(None, vec![], Timestamp(2)).unwrap();
    let err = store.append_entry_in(&journal_a, &fork).unwrap_err();
    assert!(matches!(err, StoreError::ChainBroken(_)), "{err}");
    assert_eq!(store.entries_of(&journal_a).unwrap().len(), 1);
}

/// Migration transparente : un magasin peuplé en mono-journal (v0.1.0) se
/// rouvre tel quel — son journal historique est le journal par défaut, les
/// journaux nommés sont vides — puis les deux mondes coexistent.
#[test]
fn migration_dun_magasin_mono_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v010.redb");
    let historique = Signer::generate();

    // Peuplement « v0.1.0 » : uniquement les méthodes historiques du Store.
    let roots = {
        let mut store = RedbStore::open(&path).unwrap();
        let mut roots = Vec::new();
        for i in 0..3i64 {
            let blob_hash = store.put_blob(&blob(&format!("historique v{i}"))).unwrap();
            let snapshot_hash = store
                .put_snapshot(&Snapshot {
                    asset: AssetId("srv-legacy".into()),
                    at: Timestamp(i),
                    blobs: BTreeMap::from([(CollectorId("linux.sshd".into()), blob_hash)]),
                })
                .unwrap();
            let (hash, _) =
                append_signed(&mut store, &historique, vec![snapshot_hash], Timestamp(i)).unwrap();
            roots.push(hash);
        }
        roots
    };

    // Réouverture : le journal historique est le journal par défaut, intact.
    {
        let store = RedbStore::open(&path).unwrap();
        assert_eq!(store.entry_count().unwrap(), 3);
        assert_eq!(store.root().unwrap(), Some(roots[2]));
        verify_chain(&store.entries().unwrap(), &historique.verifying_key())
            .expect("journal par défaut intact après migration");
        // Aucun journal nommé n'est apparu tout seul.
        assert!(store.journals().unwrap().is_empty());
    }

    // Les deux mondes coexistent : un journal nommé s'ajoute sans toucher
    // au journal par défaut, et tout survit à une nouvelle réouverture.
    let agent = Signer::generate();
    let journal: JournalId = agent.verifying_key().to_bytes();
    {
        let mut store = RedbStore::open(&path).unwrap();
        append_collecte(&mut store, &agent, "srv-nouveau", 10);
    }
    let store = RedbStore::open(&path).unwrap();
    assert_eq!(
        store.entry_count().unwrap(),
        3,
        "journal par défaut inchangé"
    );
    assert_eq!(store.root().unwrap(), Some(roots[2]));
    assert_eq!(store.journals().unwrap(), vec![journal]);
    let named = store.entries_of(&journal).unwrap();
    assert_eq!(named.len(), 1);
    verify_chain(&named, &agent.verifying_key()).expect("journal nommé intact");
}

/// Relit un export au layout FORMAT.md et le vérifie comme le ferait
/// `constat-verify` : pubkey.bin, objets auto-vérifiants, chaîne reconstruite
/// depuis les seuls fichiers et vérifiée avec la clé du journal.
fn verifie_export(dir: &Path, journal: &JournalId, attendu: usize) {
    // 1. pubkey.bin = exactement les 32 octets de la clé du journal.
    assert_eq!(std::fs::read(dir.join(PUBKEY_FILE)).unwrap(), journal);

    // 2. Objets auto-vérifiants : blake3(contenu) == nom du fichier.
    for sub in [SNAPSHOTS_DIR, BLOBS_DIR] {
        for f in std::fs::read_dir(dir.join(sub)).unwrap() {
            let f = f.unwrap();
            let bytes = std::fs::read(f.path()).unwrap();
            let name = f.file_name().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".cbor").expect("extension .cbor");
            assert_eq!(
                hex::encode(blake3::hash(&bytes).as_bytes()),
                stem,
                "objet {sub}/{name} : le contenu ne correspond pas à son nom"
            );
        }
    }

    // 3. Chaîne reconstruite depuis les seuls fichiers, indices consécutifs,
    //    vérifiée avec la clé du journal (le contenu de pubkey.bin).
    let key = constat_store::VerifyingKey::from_bytes(journal).unwrap();
    let mut rebuilt: Vec<(BlobHash, JournalEntry)> = Vec::new();
    for index in 0..attendu {
        let bytes = std::fs::read(dir.join(format!("{index}.cbor"))).unwrap();
        let entry: JournalEntry = from_canonical_bytes(&bytes).unwrap();
        rebuilt.push((BlobHash(*blake3::hash(&bytes).as_bytes()), entry));
    }
    assert!(
        !dir.join(format!("{attendu}.cbor")).exists(),
        "pas de trou ni d'excédent"
    );
    verify_chain(&rebuilt, &key).expect("la chaîne exportée doit se vérifier hors magasin");
}

/// Export par journal : un magasin qui porte DEUX journaux produit deux
/// répertoires au layout FORMAT.md, chacun vérifiable indépendamment —
/// l'export de A ne dépend en rien de la chaîne de B.
#[test]
fn export_par_journal_deux_repertoires_independants() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = RedbStore::open(tmp.path().join("s.redb")).unwrap();

    let a = Signer::generate();
    let b = Signer::generate();
    let journal_a: JournalId = a.verifying_key().to_bytes();
    let journal_b: JournalId = b.verifying_key().to_bytes();

    append_collecte(&mut store, &a, "srv-a", 1);
    append_collecte(&mut store, &b, "srv-b", 1);
    append_collecte(&mut store, &a, "srv-a", 2);
    append_collecte(&mut store, &b, "srv-b", 2);
    append_collecte(&mut store, &b, "srv-b", 3);

    let out_a = tmp.path().join("export-a");
    let out_b = tmp.path().join("export-b");
    export_journal(&store, &out_a, &journal_a).unwrap();
    export_journal(&store, &out_b, &journal_b).unwrap();

    verifie_export(&out_a, &journal_a, 2);
    verifie_export(&out_b, &journal_b, 3);

    // La clôture est bien celle de CHAQUE journal : les artefacts de B ne
    // fuient pas dans l'export de A.
    let entries_a = store.entries_of(&journal_a).unwrap();
    for (_, entry) in &store.entries_of(&journal_b).unwrap()[..] {
        for snapshot in &entry.snapshots {
            let leaked = out_a
                .join(SNAPSHOTS_DIR)
                .join(format!("{}.cbor", snapshot.to_hex()));
            assert!(
                !leaked.exists()
                    || entries_a
                        .iter()
                        .any(|(_, e)| e.snapshots.contains(snapshot)),
                "snapshot de B présent dans l'export de A"
            );
        }
    }

    // Idempotence : réexporter ne change rien et ne casse rien.
    export_journal(&store, &out_a, &journal_a).unwrap();
    verifie_export(&out_a, &journal_a, 2);

    // L'export d'un journal inexistant est une clôture vide : pubkey.bin
    // seul, aucune entrée (constat-verify exigera au moins une entrée — le
    // répertoire est cohérent, juste vide).
    let out_vide = tmp.path().join("export-vide");
    export_journal(&store, &out_vide, &[0u8; 32]).unwrap();
    assert!(!out_vide.join("0.cbor").exists());
}
