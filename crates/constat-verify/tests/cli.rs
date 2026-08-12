//! Test du binaire `constat-verify` sur un vrai répertoire d'export, au
//! layout normatif de FORMAT.md : succès (code 0) sur un export valide,
//! échec (code 1) avec diagnostic sur un export altéré.

#![allow(clippy::unwrap_used)]

mod common;

use std::path::PathBuf;
use std::process::Command;

use constat_model::{hash_canonical, to_canonical_bytes};

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

fn run_bin(dir: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_constat-verify"))
        .arg(dir)
        .output()
        .unwrap()
}

#[test]
fn le_binaire_accepte_un_export_valide() {
    let export = common::valid_export();
    let dir = temp_dir("valide");
    common::write_export(&dir, &export);

    let output = run_bin(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "code de sortie inattendu : {output:?}"
    );
    assert!(stdout.contains("OK"), "sortie inattendue : {stdout}");
    let racine = hash_canonical(export.entries.last().unwrap()).unwrap();
    assert!(
        stdout.contains(&racine.to_hex()),
        "la racine doit figurer dans la sortie : {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn le_binaire_refuse_un_blob_altere_sur_disque() {
    let export = common::valid_export();
    let dir = temp_dir("blob-altere");
    common::write_export(&dir, &export);

    // Altère un blob sur disque, en gardant son nom (l'empreinte annoncée).
    let (hash, blob) = export.blobs.iter().next().unwrap();
    let mut altere = blob.clone();
    altere.raw = b"PermitRootLogin yes\n".to_vec();
    std::fs::write(
        dir.join("blobs").join(format!("{}.cbor", hash.to_hex())),
        to_canonical_bytes(&altere).unwrap(),
    )
    .unwrap();

    let output = run_bin(&dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("ÉCHEC") && stderr.contains("blob altéré"),
        "diagnostic inattendu : {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn le_binaire_refuse_une_chaine_tronquee_au_milieu() {
    let mut export = common::valid_export();
    export.entries.remove(1);
    let dir = temp_dir("tronque");
    common::write_export(&dir, &export);

    let output = run_bin(&dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("chaîne rompue"),
        "diagnostic inattendu : {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn le_binaire_exige_un_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_constat-verify"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}
