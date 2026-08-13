//! Tests d'intégration de `constat segmentation` — la jonction avec Calque
//! (§14) : verdicts, codes de sortie, chronologie `--period`, enregistrement
//! signé `--record`, équipement illisible déclaré.
//!
//! Le magasin en mémoire est peuplé avec [`build_network_capture`] — le MÊME
//! assembleur que le collecteur réel `network.configs` — sur une
//! configuration FortiGate minimale (deux interfaces, une règle d'accès et
//! une règle deny explicite, importée avec une fidélité COMPLÈTE par Calque)
//! et sur la fixture réelle de constat-collect (dont l'import est PARTIEL :
//! le verdict doit alors refuser de trancher).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use constat_cli::datetime::parse_timestamp;
use constat_cli::segmentation::{cmd_segmentation, SegmentationArgs};
use constat_cli::{commands, keyres};
use constat_collect::network_configs::{build_network_capture, extract_network_configs_facts};
use constat_model::{Blob, CollectorId, Snapshot, Timestamp};
use constat_store::{append_signed, verify_chain, MemoryStore, Signer, Store};

// ---------------------------------------------------------------------------
// Décor
// ---------------------------------------------------------------------------

/// Configuration FortiGate de test, volontairement plus simple que la
/// fixture du collecteur : uniquement des blocs que l'adaptateur Calque
/// comprend en totalité (fidélité complète), deux interfaces, une règle
/// d'accès lan→dmz et une règle deny explicite dmz→lan.
const FW_V1: &str = r#"#config-version=FGT60F-7.0.5-FW-build0304-220328:opmode=0:vdom=0
config system global
    set hostname "fw-test"
end
config system interface
    edit "lan"
        set vdom "root"
        set ip 10.10.1.1 255.255.255.0
        set type physical
        set role lan
    next
    edit "dmz"
        set vdom "root"
        set ip 10.10.2.1 255.255.255.0
        set type physical
        set role dmz
    next
end
config firewall policy
    edit 1
        set name "lan-vers-dmz"
        set srcintf "lan"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
    edit 2
        set name "dmz-isolement"
        set srcintf "dmz"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
"#;

/// La même configuration après « durcissement » : la règle d'accès lan→dmz
/// devient un deny — le premier flux déclaré passe de conforme à violé.
const FW_V2: &str = r#"#config-version=FGT60F-7.0.5-FW-build0304-220328:opmode=0:vdom=0
config system global
    set hostname "fw-test"
end
config system interface
    edit "lan"
        set vdom "root"
        set ip 10.10.1.1 255.255.255.0
        set type physical
        set role lan
    next
    edit "dmz"
        set vdom "root"
        set ip 10.10.2.1 255.255.255.0
        set type physical
        set role dmz
    next
end
config firewall policy
    edit 1
        set name "lan-vers-dmz-coupe"
        set srcintf "lan"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
    next
    edit 2
        set name "dmz-isolement"
        set srcintf "dmz"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
"#;

/// Deux flux cohérents avec la topologie de `FW_V1` : l'accès autorisé
/// lan→dmz et l'isolement dmz→lan.
const FLOWS_YAML: &str = r#"flows:
  - name: le lan atteint le serveur web de la dmz
    from: 10.10.1.50
    to: 10.10.2.10
    port: 443/tcp
    expect: allow
  - name: la dmz est isolee du lan
    from: 10.10.2.10
    to: 10.10.1.50
    port: any
    expect: deny
"#;

fn ts(s: &str) -> Timestamp {
    parse_timestamp(s).expect("date de test valide")
}

/// Injecte une collecte `network.configs` : blob (capture multi-sections),
/// snapshot, entrée de journal signée — le chemin exact de l'agent.
fn inject_configs(
    store: &mut MemoryStore,
    signer: &Signer,
    asset: &str,
    at: Timestamp,
    devices: &[(&str, &str)],
) {
    let capture = build_network_capture(devices);
    let facts = extract_network_configs_facts(&capture);
    let blob = Blob::new("network.configs", capture.into_bytes(), facts);
    let blob_hash = store.put_blob(&blob).expect("put_blob");
    let snapshot = Snapshot::new(
        asset,
        at,
        BTreeMap::from([(CollectorId("network.configs".to_string()), blob_hash)]),
    );
    let snap_hash = store.put_snapshot(&snapshot).expect("put_snapshot");
    append_signed(store, signer, vec![snap_hash], at).expect("append_signed");
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "constat-segmentation-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("répertoire temporaire");
    dir
}

/// Écrit le fichier de flux et rend son chemin.
fn write_flows(dir: &Path, yaml: &str) -> PathBuf {
    let path = dir.join("flows.yaml");
    std::fs::write(&path, yaml).expect("écriture flows.yaml");
    path
}

fn args<'a>(flows: &'a Path, at: Option<&'a str>, period: Option<&'a str>) -> SegmentationArgs<'a> {
    SegmentationArgs {
        flows_path: flows,
        at,
        period,
        record: false,
        keys: None,
        asset: "reseau",
    }
}

// ---------------------------------------------------------------------------
// --at : verdicts et codes de sortie
// ---------------------------------------------------------------------------

#[test]
fn conforme_code_zero_et_tracabilite_complete() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-01-10T06:00Z"),
        &[("fw-test", FW_V1)],
    );
    let dir = tmp_dir("conforme");
    let flows = write_flows(&dir, FLOWS_YAML);

    let (out, code) = cmd_segmentation(&mut store, &args(&flows, Some("2026-03-03T14:00"), None))
        .expect("évaluation");

    assert_eq!(code, 0, "sortie :\n{out}");
    assert_eq!(out.matches("✔ conforme").count(), 2, "sortie :\n{out}");
    // La fidélité de l'import est affichée, et elle est complète.
    assert!(out.contains("fidélité complète"), "sortie :\n{out}");
    // La règle décisive cite sa source `équipement@date` : la preuve du §14.
    assert!(out.contains("fw-test@2026-01-10T06:00Z"), "sortie :\n{out}");
    // L'attendu et l'observé sont restitués.
    assert!(
        out.contains("attendu allow, observé allow"),
        "sortie :\n{out}"
    );
    assert!(
        out.contains("attendu deny, observé deny"),
        "sortie :\n{out}"
    );
    // La traçabilité Constat : l'empreinte complète du blob de configurations.
    let obs = store.entries().unwrap();
    assert!(!obs.is_empty());
    assert!(
        out.contains("Traçabilité Constat : blob de configurations"),
        "sortie :\n{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn violation_code_un_attendu_contre_observe() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-01-10T06:00Z"),
        &[("fw-test", FW_V2)],
    );
    let dir = tmp_dir("violation");
    let flows = write_flows(&dir, FLOWS_YAML);

    let (out, code) =
        cmd_segmentation(&mut store, &args(&flows, Some("2026-02-01"), None)).expect("évaluation");

    assert_eq!(code, 1, "sortie :\n{out}");
    assert!(out.contains("✘ violé"), "sortie :\n{out}");
    assert!(
        out.contains("attendu allow, observé deny"),
        "sortie :\n{out}"
    );
    // Le second flux reste conforme : la violation ne contamine pas le reste.
    assert!(out.contains("✔ conforme"), "sortie :\n{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn aucune_collecte_anterieure_est_une_erreur_explicite() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-03-10T06:00Z"),
        &[("fw-test", FW_V1)],
    );
    let dir = tmp_dir("anterieure");
    let flows = write_flows(&dir, FLOWS_YAML);

    let err = cmd_segmentation(&mut store, &args(&flows, Some("2026-01-01"), None))
        .expect_err("aucun blob antérieur : erreur attendue");
    assert!(
        err.to_string().contains("aucune collecte network.configs"),
        "erreur : {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Équipement illisible et fidélité partielle : l'honnêteté du verdict
// ---------------------------------------------------------------------------

#[test]
fn equipement_illisible_declare_et_tout_verdict_non_concluant() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    // Le pare-feu lisible PLUS un équipement que Calque ne reconnaît pas.
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-01-10T06:00Z"),
        &[
            ("fw-test", FW_V1),
            (
                "sw-mystere",
                "!! export proprietaire illisible v42\nblob binaire\n",
            ),
        ],
    );
    let dir = tmp_dir("illisible");
    let flows = write_flows(&dir, FLOWS_YAML);

    let (out, code) =
        cmd_segmentation(&mut store, &args(&flows, Some("2026-02-01"), None)).expect("évaluation");

    assert_eq!(code, 3, "sortie :\n{out}");
    // L'équipement illisible est déclaré, avec son motif.
    assert!(out.contains("sw-mystere — ILLISIBLE"), "sortie :\n{out}");
    // TOUS les verdicts sont non concluants : un équipement illisible est un
    // pan du réseau hors modèle, l'outil ne devine jamais.
    assert_eq!(out.matches("? non concluant").count(), 2, "sortie :\n{out}");
    assert!(!out.contains("✔ conforme"), "sortie :\n{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fixture_reelle_import_partiel_verdict_non_concluant() {
    // La fixture RÉELLE du collecteur contient des blocs que Calque ne
    // comprend pas en totalité (`config system admin`…) : l'import est
    // partiel, et un chemin qui traverse ce modèle refuse le verdict ferme.
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../constat-collect/tests/fixtures/netdev-fortigate.conf");
    let raw = std::fs::read_to_string(&fixture).expect("fixture du collecteur");

    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-01-10T06:00Z"),
        &[("fw-dmz-01", &raw)],
    );
    let dir = tmp_dir("fixture");
    // Flux aligné sur la topologie de la fixture (lan 10.10.1.0/24,
    // serveur web 10.10.2.10 en dmz).
    let flows = write_flows(
        &dir,
        r#"flows:
  - name: le lan atteint le serveur web
    from: 10.10.1.50
    to: 10.10.2.10
    port: 443/tcp
    expect: allow
"#,
    );

    let (out, code) =
        cmd_segmentation(&mut store, &args(&flows, Some("2026-02-01"), None)).expect("évaluation");

    assert_eq!(code, 3, "sortie :\n{out}");
    assert!(out.contains("fidélité PARTIELLE"), "sortie :\n{out}");
    assert!(out.contains("? non concluant"), "sortie :\n{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// --period : la chronologie — la réponse à « pendant tout le trimestre »
// ---------------------------------------------------------------------------

#[test]
fn periode_chronologie_deux_intervalles_et_couverture() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    // Deux collectes du même dépôt : la configuration change le 15 février.
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-01-10T06:00Z"),
        &[("fw-test", FW_V1)],
    );
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-02-15T06:00Z"),
        &[("fw-test", FW_V2)],
    );
    let dir = tmp_dir("periode");
    let flows = write_flows(&dir, FLOWS_YAML);

    let (out, code) =
        cmd_segmentation(&mut store, &args(&flows, None, Some("2026-Q1"))).expect("évaluation");

    assert_eq!(code, 1, "sortie :\n{out}");
    assert!(
        out.contains("2 changement(s) de configuration réseau"),
        "sortie :\n{out}"
    );
    // Le premier flux a DEUX intervalles : conforme jusqu'au changement,
    // violé ensuite — datés.
    assert!(
        out.contains("2026-01-10 06:00 → 2026-02-15 06:00   ✔ conforme"),
        "sortie :\n{out}"
    );
    assert!(
        out.contains("2026-02-15 06:00 → 2026-03-31 23:59   ✘ violé"),
        "sortie :\n{out}"
    );
    // Le second flux, lui, reste conforme sur un intervalle unique.
    assert!(
        out.contains("2026-01-10 06:00 → 2026-03-31 23:59   ✔ conforme"),
        "sortie :\n{out}"
    );
    // La couverture de la période est restituée, trous déclarés compris
    // (rien n'a été observé avant le 10 janvier : l'écart est visible).
    assert!(out.contains("Couverture sur la période"), "sortie :\n{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn periode_sans_collecte_est_non_concluante() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2025-06-01T06:00Z"),
        &[("fw-test", FW_V1)],
    );
    let dir = tmp_dir("periode-vide");
    let flows = write_flows(&dir, FLOWS_YAML);

    let (out, code) =
        cmd_segmentation(&mut store, &args(&flows, None, Some("2026-Q1"))).expect("évaluation");
    assert_eq!(code, 3, "sortie :\n{out}");
    assert!(
        out.contains("Aucune collecte network.configs dans la période"),
        "sortie :\n{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// --record : le verdict redevient un fait horodaté, signé (§14)
// ---------------------------------------------------------------------------

#[test]
fn record_ajoute_une_entree_signee_et_des_faits_requetables() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-01-10T06:00Z"),
        &[("fw-test", FW_V1)],
    );
    let dir = tmp_dir("record");
    let flows = write_flows(&dir, FLOWS_YAML);
    // Répertoire de clés au format de l'agent : la clé PRIVÉE, celle qui
    // signe le journal.
    let keys = dir.join("cles");
    std::fs::create_dir_all(&keys).expect("répertoire de clés");
    let key_hex: String = signer
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(keys.join(keyres::KEY_FILE), key_hex).expect("écriture agent.key");

    let before = store.entries().expect("entries").len();
    let (out, code) = cmd_segmentation(
        &mut store,
        &SegmentationArgs {
            flows_path: &flows,
            at: Some("2026-03-03T14:00"),
            period: None,
            record: true,
            keys: Some(&keys),
            asset: "reseau",
        },
    )
    .expect("évaluation avec enregistrement");

    assert_eq!(code, 0, "sortie :\n{out}");
    assert!(
        out.contains("Verdict enregistré au journal"),
        "sortie :\n{out}"
    );

    // Le journal a gagné UNE entrée, et la chaîne se vérifie toujours.
    let entries = store.entries().expect("entries");
    assert_eq!(entries.len(), before + 1);
    verify_chain(&entries, &signer.verifying_key()).expect("chaîne valide après --record");

    // L'entrée porte un snapshot `calque.segmentation` dont le brut est le
    // compte rendu complet : la preuve autonome.
    let (_, last) = entries.last().expect("dernière entrée");
    let snap = store.get_snapshot(&last.snapshots[0]).expect("snapshot");
    assert_eq!(snap.asset.0, "reseau");
    let blob_hash = snap
        .blobs
        .get(&CollectorId("calque.segmentation".to_string()))
        .expect("blob calque.segmentation");
    let blob = store.get_blob(blob_hash).expect("blob");
    let raw = String::from_utf8_lossy(&blob.raw);
    assert!(raw.starts_with("Segmentation au"), "brut :\n{raw}");

    // Les faits flow.* sont requêtables par `constat history`.
    let h = commands::cmd_history(
        &store,
        "flow:le lan atteint le serveur web de la dmz",
        "flow.verdict",
        None,
    )
    .expect("history flow.verdict");
    assert!(h.contains("allow"), "history :\n{h}");
    let h = commands::cmd_history(&store, "flow:la dmz est isolee du lan", "flow.status", None)
        .expect("history flow.status");
    assert!(h.contains("ok"), "history :\n{h}");
    // L'entité de run relie le verdict à ses deux entrées : fichier de flux
    // et blob de configurations évalué.
    let configs_blob_hex = {
        let first = store.entries().expect("entries")[0].1.snapshots[0];
        let s = store.get_snapshot(&first).expect("snapshot configs");
        s.blobs
            .get(&CollectorId("network.configs".to_string()))
            .expect("blob network.configs")
            .to_hex()
    };
    let h = commands::cmd_history(
        &store,
        "segmentation:run",
        "segmentation.configs_blob",
        None,
    )
    .expect("history segmentation.configs_blob");
    assert!(h.contains(&configs_blob_hex), "history :\n{h}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn record_refuse_avec_period() {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    inject_configs(
        &mut store,
        &signer,
        "collecteur-net",
        ts("2026-01-10T06:00Z"),
        &[("fw-test", FW_V1)],
    );
    let dir = tmp_dir("record-period");
    let flows = write_flows(&dir, FLOWS_YAML);

    let err = cmd_segmentation(
        &mut store,
        &SegmentationArgs {
            flows_path: &flows,
            at: None,
            period: Some("2026-Q1"),
            record: true,
            keys: None,
            asset: "reseau",
        },
    )
    .expect_err("--record avec --period doit être refusé");
    assert!(err.to_string().contains("--record"), "erreur : {err}");
    let _ = std::fs::remove_dir_all(&dir);
}
