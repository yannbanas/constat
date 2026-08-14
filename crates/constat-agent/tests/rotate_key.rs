//! `constat-agent rotate-key` avec le VRAI binaire : la rotation est
//! journalisée (signée par l'ancienne clé), les archives sont créées, la
//! nouvelle clé est en place — et sans magasin, refus : une rotation non
//! journalisée n'existe pas.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

use constat_agent::keys;
use constat_model::Timestamp;
use constat_store::{append_signed, verify_chain_rotated, RedbStore, Store};

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "constat-rotate-key-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Rotation nominale : entrée de rotation écrite dans le journal, archives
/// `agent.key.<date>.old` / `agent.pub.<date>.old` créées, nouvelle paire en
/// place, chaîne vérifiable depuis la clé de genèse, rappel d'allowlist.
#[test]
fn rotate_key_journalise_archive_et_remplace() {
    let dir = tmp_dir("nominal");
    let keys_dir = dir.join("cles");
    let store_path = dir.join("magasin.redb");

    // La paire d'origine (la future « ancienne » clé = la genèse).
    keys::generate(&keys_dir, false).unwrap();
    let old = keys::load(&keys_dir).unwrap();
    let old_pub = old.verifying_key();
    let old_key_hex = std::fs::read_to_string(keys_dir.join(keys::KEY_FILE)).unwrap();

    // Un magasin avec une collecte signée par l'ancienne clé.
    {
        let mut store = RedbStore::open(&store_path).unwrap();
        append_signed(&mut store, &old, vec![], Timestamp(1_000)).unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_constat-agent"))
        .args([
            "rotate-key",
            "--keys",
            keys_dir.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
            "--reason",
            "rotation planifiée (test)",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotate-key doit réussir\nstdout : {stdout}\nstderr : {stderr}"
    );

    // Les archives existent (une par fichier), la paire en place a changé.
    let archived: Vec<String> = std::fs::read_dir(&keys_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".old"))
        .collect();
    assert!(
        archived.iter().any(|n| n.starts_with("agent.key.")),
        "archive de la clé privée attendue, trouvé : {archived:?}"
    );
    assert!(
        archived.iter().any(|n| n.starts_with("agent.pub.")),
        "archive de la clé publique attendue, trouvé : {archived:?}"
    );
    let new_key_hex = std::fs::read_to_string(keys_dir.join(keys::KEY_FILE)).unwrap();
    assert_ne!(old_key_hex.trim(), new_key_hex.trim());
    // L'archive contient bien l'ANCIENNE clé privée, intacte.
    let key_archive = archived
        .iter()
        .find(|n| n.starts_with("agent.key."))
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(keys_dir.join(key_archive))
            .unwrap()
            .trim(),
        old_key_hex.trim()
    );
    // Aucun fichier temporaire résiduel.
    assert!(!keys_dir.join("agent.key.new").exists());
    assert!(!keys_dir.join("agent.pub.new").exists());

    // Le journal contient l'entrée de rotation et se vérifie depuis la
    // GENÈSE (l'ancienne clé), la clé finale étant la nouvelle.
    let new = keys::load(&keys_dir).unwrap();
    let store = RedbStore::open(&store_path).unwrap();
    let entries = store.entries().unwrap();
    assert_eq!(entries.len(), 2, "collecte + entrée de rotation");
    let trace = verify_chain_rotated(&store, &entries, &old_pub).unwrap();
    assert_eq!(trace.rotations, 1);
    assert_eq!(trace.final_key, new.verifying_key().to_bytes());

    // La sortie donne les deux empreintes et rappelle l'allowlist.
    let old_hex: String = old_pub
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let new_hex: String = new
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(stdout.contains(&old_hex), "ancienne empreinte : {stdout}");
    assert!(stdout.contains(&new_hex), "nouvelle empreinte : {stdout}");
    assert!(
        stdout.contains("allowlist") || stdout.contains("agents autorisés"),
        "rappel d'allowlist attendu : {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Sans magasin accessible : refus, et RIEN ne change — ni les clés en
/// place, ni le moindre fichier temporaire ou d'archive.
#[test]
fn rotate_key_refuse_sans_magasin() {
    let dir = tmp_dir("sans-magasin");
    let keys_dir = dir.join("cles");
    keys::generate(&keys_dir, false).unwrap();
    let key_avant = std::fs::read_to_string(keys_dir.join(keys::KEY_FILE)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_constat-agent"))
        .args([
            "rotate-key",
            "--keys",
            keys_dir.to_str().unwrap(),
            "--store",
            dir.join("inexistant.redb").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "rotate-key doit refuser sans magasin"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("rotation refusée") || stderr.contains("rotation non journalisée"),
        "le refus doit être motivé : {stderr}"
    );

    // Rien n'a bougé.
    assert_eq!(
        std::fs::read_to_string(keys_dir.join(keys::KEY_FILE)).unwrap(),
        key_avant
    );
    let residuals: Vec<String> = std::fs::read_dir(&keys_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".old") || name.ends_with(".new"))
        .collect();
    assert!(residuals.is_empty(), "aucun résidu attendu : {residuals:?}");

    let _ = std::fs::remove_dir_all(&dir);
}
