//! Tests d'altération (§12) : un export valide passe ; toute altération —
//! blob modifié, entrée remplacée, chaîne tronquée au milieu — échoue avec le
//! diagnostic précis. C'est la promesse centrale du produit.

#![allow(clippy::unwrap_used)]

mod common;

use constat_model::hash_canonical;
use constat_verify::{verify_export, VerifyError};

#[test]
fn un_export_valide_passe_et_donne_la_racine() {
    let export = common::valid_export();
    let ok = verify_export(&export).unwrap();
    assert_eq!(ok.entry_count, 3);
    assert_eq!(ok.snapshot_count, 2);
    assert_eq!(ok.blob_count, 2);
    assert_eq!(ok.root, hash_canonical(&export.entries[2]).unwrap());
}

#[test]
fn un_blob_modifie_est_detecte() {
    let mut export = common::valid_export();
    // Altère le contenu brut d'un blob sans changer son empreinte annoncée.
    let (annonce, blob) = export.blobs.iter_mut().next().unwrap();
    let annonce = *annonce;
    blob.raw = b"PermitRootLogin yes\n".to_vec();
    let calcule = hash_canonical(blob).unwrap();

    let err = verify_export(&export).unwrap_err();
    assert_eq!(err, VerifyError::BlobAltere { annonce, calcule });
}

#[test]
fn un_snapshot_modifie_est_detecte() {
    let mut export = common::valid_export();
    let (annonce, snapshot) = export.snapshots.iter_mut().next().unwrap();
    let annonce = *annonce;
    snapshot.at = constat_model::Timestamp(999_999);
    let calcule = hash_canonical(snapshot).unwrap();

    let err = verify_export(&export).unwrap_err();
    assert_eq!(err, VerifyError::SnapshotAltere { annonce, calcule });
}

#[test]
fn une_entree_remplacee_invalide_sa_signature() {
    let mut export = common::valid_export();
    // Remplace le contenu de l'entrée 1 en gardant son ancienne signature :
    // sans la clé privée, impossible de re-signer.
    export.entries[1].at = constat_model::Timestamp(4_000);

    let err = verify_export(&export).unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalide { index: 1 });
}

#[test]
fn une_chaine_tronquee_au_milieu_est_detectee() {
    let mut export = common::valid_export();
    // Supprime l'entrée 1 : l'ex-entrée 2 pointe toujours vers elle.
    let supprimee = export.entries.remove(1);
    let attendu = hash_canonical(&export.entries[0]).unwrap();
    let trouve = hash_canonical(&supprimee).unwrap();

    let err = verify_export(&export).unwrap_err();
    assert_eq!(
        err,
        VerifyError::ChaineRompue {
            index: 1,
            attendu: Some(attendu),
            trouve: Some(trouve),
        }
    );
}

#[test]
fn une_genese_avec_predecesseur_est_refusee() {
    let mut export = common::valid_export();
    // Tronque le début : l'entrée 1 devient la première fournie.
    let entry_0 = export.entries.remove(0);
    let prev = hash_canonical(&entry_0).unwrap();

    let err = verify_export(&export).unwrap_err();
    assert_eq!(err, VerifyError::GeneseInvalide { prev });
}

#[test]
fn un_snapshot_manquant_est_detecte() {
    let mut export = common::valid_export();
    let hash = export.entries[1].snapshots[0];
    export.snapshots.remove(&hash);

    let err = verify_export(&export).unwrap_err();
    assert_eq!(err, VerifyError::SnapshotManquant { index: 1, hash });
}

#[test]
fn un_blob_manquant_est_detecte() {
    let mut export = common::valid_export();
    let (hash, _) = export.blobs.pop_last().unwrap();

    let err = verify_export(&export).unwrap_err();
    match err {
        VerifyError::BlobManquant { hash: h, .. } => assert_eq!(h, hash),
        autre => panic!("diagnostic inattendu : {autre:?}"),
    }
}

#[test]
fn une_signature_malformee_est_detectee() {
    let mut export = common::valid_export();
    export.entries[2].signature.truncate(10);

    let err = verify_export(&export).unwrap_err();
    assert_eq!(
        err,
        VerifyError::SignatureMalformee {
            index: 2,
            longueur: 10
        }
    );
}

#[test]
fn une_signature_d_une_autre_cle_est_refusee() {
    let mut export = common::valid_export();
    export.public_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
        .verifying_key()
        .to_bytes();

    let err = verify_export(&export).unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalide { index: 0 });
}

#[test]
fn un_export_vide_est_refuse() {
    let mut export = common::valid_export();
    export.entries.clear();

    assert_eq!(verify_export(&export).unwrap_err(), VerifyError::ExportVide);
}
