//! Tests d'intégration des chaînons autrefois marqués TODO(integration) :
//!
//! - `constat export` : le répertoire produit est relu et **revérifié en
//!   entier** par `constat-verify` (le vérificateur autonome du §10.3) ;
//! - `constat anchor --send` : envoi RFC 3161 réel contre un mini-serveur
//!   HTTP local, archivage du jeton délivré, refus motivé en erreur ;
//! - `constat pack` : le jeton archivé et la clé publique réelle figurent
//!   dans le dossier de preuve ;
//! - `Assertion::scope` : la portée sélectionne par faits d'inventaire,
//!   jusqu'au rendu de `constat check`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use constat_cli::datetime::parse_timestamp;
use constat_cli::{anchors, commands};
use constat_model::{
    AssetId, Attribute, Blob, BlobHash, CollectorId, EntityId, Fact, Snapshot, Timestamp, Value,
};
use constat_store::{append_signed, MemoryStore, Signer, Store};

fn ts(s: &str) -> Timestamp {
    parse_timestamp(s).expect("date de test valide")
}

fn fact(entity: &str, attr: &str, value: Value) -> Fact {
    Fact {
        entity: EntityId(entity.to_string()),
        attribute: Attribute(attr.to_string()),
        value,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Injecte une collecte : un blob, un snapshot, une entrée de journal signée.
fn inject(store: &mut MemoryStore, signer: &Signer, asset: &str, at: Timestamp, facts: Vec<Fact>) {
    let blob = Blob {
        collector: CollectorId("test.collecte".to_string()),
        raw: format!("capture expurgée de {asset} au {}", at.0).into_bytes(),
        facts,
    };
    let blob_hash = store.put_blob(&blob).expect("put_blob");
    let mut blobs = BTreeMap::new();
    blobs.insert(CollectorId("test.collecte".to_string()), blob_hash);
    let snap = Snapshot {
        asset: AssetId(asset.to_string()),
        at,
        blobs,
    };
    let snap_hash = store.put_snapshot(&snap).expect("put_snapshot");
    append_signed(store, signer, vec![snap_hash], at).expect("append_signed");
}

/// Deux machines, deux collectes : le socle des tests de ce fichier.
fn scenario() -> (MemoryStore, Signer) {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    inject(
        &mut store,
        &signer,
        "srv-linux",
        ts("2026-01-10T06:00Z"),
        vec![
            fact("asset:srv-linux", "asset.os", Value::Text("linux".into())),
            fact("user:root", "user.privileged", Value::Bool(true)),
        ],
    );
    inject(
        &mut store,
        &signer,
        "srv-mystere",
        ts("2026-01-10T06:05Z"),
        vec![fact("user:root", "user.privileged", Value::Bool(true))],
    );
    (store, signer)
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "constat-integration-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("répertoire temporaire");
    dir
}

/// Écrit un répertoire de clés au format de l'agent (`agent.pub` seul).
fn write_keys_dir(dir: &Path, signer: &Signer) -> PathBuf {
    let keys = dir.join("cles");
    std::fs::create_dir_all(&keys).expect("répertoire de clés");
    std::fs::write(
        keys.join("agent.pub"),
        hex(&signer.verifying_key().to_bytes()),
    )
    .expect("écriture agent.pub");
    keys
}

// ---------------------------------------------------------------------------
// 1. constat export
// ---------------------------------------------------------------------------

/// Relit tous les fichiers d'objets d'un sous-répertoire d'export.
fn read_objects<T: for<'de> serde::Deserialize<'de>>(dir: &Path) -> BTreeMap<BlobHash, T> {
    let mut map = BTreeMap::new();
    if !dir.exists() {
        return map;
    }
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entrée").path();
        let stem = path
            .file_stem()
            .expect("nom de fichier")
            .to_string_lossy()
            .to_string();
        let hash = BlobHash::from_hex(&stem).expect("nom hexadécimal");
        let bytes = std::fs::read(&path).expect("lecture objet");
        map.insert(
            hash,
            ciborium::de::from_reader(bytes.as_slice()).expect("CBOR valide"),
        );
    }
    map
}

/// Recharge un répertoire d'export dans la structure de `constat-verify`.
fn load_export(dir: &Path) -> constat_verify::Export {
    let public_key: [u8; 32] = std::fs::read(dir.join("pubkey.bin"))
        .expect("pubkey.bin lisible")
        .try_into()
        .expect("pubkey.bin : 32 octets");
    let mut entries = Vec::new();
    let mut i = 0usize;
    loop {
        let path = dir.join(format!("{i}.cbor"));
        if !path.exists() {
            break;
        }
        let bytes = std::fs::read(&path).expect("entrée lisible");
        entries.push(ciborium::de::from_reader(bytes.as_slice()).expect("entrée CBOR valide"));
        i += 1;
    }
    constat_verify::Export {
        entries,
        snapshots: read_objects::<Snapshot>(&dir.join("snapshots")),
        blobs: read_objects::<Blob>(&dir.join("blobs")),
        public_key,
    }
}

#[test]
fn export_produit_un_repertoire_verifiable_par_constat_verify() {
    let (store, signer) = scenario();
    let dir = tmp_dir("export");
    let keys = write_keys_dir(&dir, &signer);
    let out = dir.join("export");

    let msg = commands::cmd_export(
        &store,
        &commands::ExportArgs {
            out: &out,
            pubkey: None,
            keys: Some(&keys),
        },
    )
    .expect("export");

    let root = store.root().expect("racine").expect("journal non vide");
    assert!(msg.contains("constat-verify"), "procédure affichée : {msg}");
    assert!(msg.contains(&root.to_hex()), "racine affichée : {msg}");

    // Layout normatif : pubkey.bin (32 octets, la clé du signataire) + 0.cbor.
    let pk = std::fs::read(out.join("pubkey.bin")).expect("pubkey.bin présent");
    assert_eq!(pk, signer.verifying_key().to_bytes().to_vec());
    assert!(out.join("0.cbor").exists(), "entrée de genèse présente");
    assert!(out.join("1.cbor").exists(), "deuxième entrée présente");

    // Auto-cohérence : revérification complète par constat-verify (§10.3),
    // qui recalcule empreintes, chaînage, signatures et références.
    let export = load_export(&out);
    assert_eq!(export.entries.len(), 2);
    let verified = constat_verify::verify_export(&export).expect("export intérieurement cohérent");
    assert_eq!(
        verified.root, root,
        "la racine vérifiée est celle du magasin"
    );
    assert_eq!(verified.snapshot_count, 2);
    assert_eq!(verified.blob_count, 2);

    // Une mauvaise clé publique est refusée AVANT d'écrire un export cassé.
    let autre = Signer::generate();
    let mauvaises = dir.join("mauvaises-cles");
    std::fs::create_dir_all(&mauvaises).expect("répertoire");
    std::fs::write(
        mauvaises.join("agent.pub"),
        hex(&autre.verifying_key().to_bytes()),
    )
    .expect("écriture");
    let err = commands::cmd_export(
        &store,
        &commands::ExportArgs {
            out: &dir.join("export-casse"),
            pubkey: None,
            keys: Some(&mauvaises),
        },
    )
    .expect_err("clé étrangère refusée");
    assert!(err.to_string().contains("ne se vérifie pas"));

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 2. constat anchor --send (mini-serveur TSA local)
// ---------------------------------------------------------------------------

/// TLV DER à longueur courte — pour fabriquer les réponses du faux prestataire.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    assert!(content.len() < 128, "longueur courte uniquement");
    let mut out = vec![tag, content.len() as u8];
    out.extend_from_slice(content);
    out
}

/// `TimeStampResp` « jeton délivré » : statut 0 + un jeton opaque.
/// Renvoie (réponse complète, jeton TLV).
fn granted_response() -> (Vec<u8>, Vec<u8>) {
    let token = tlv(0x30, &tlv(0x02, &[0x2A])); // SEQUENCE { INTEGER 42 }, opaque
    let status_info = tlv(0x30, &tlv(0x02, &[0x00])); // PKIStatusInfo { granted }
    let mut body = status_info;
    body.extend_from_slice(&token);
    (tlv(0x30, &body), token)
}

/// `TimeStampResp` de refus, avec un motif en texte libre.
fn rejection_response(motif: &str) -> Vec<u8> {
    let mut info = tlv(0x02, &[0x02]); // status 2 : rejection
    info.extend_from_slice(&tlv(0x30, &tlv(0x0C, motif.as_bytes())));
    tlv(0x30, &tlv(0x30, &info))
}

/// Sert exactement une requête HTTP : lit le POST (Content-Length), renvoie
/// `reply` en `application/timestamp-reply`, et rend le corps reçu.
fn serve_tsa_once(listener: TcpListener, reply: Vec<u8>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let (header_end, content_length) = loop {
            let n = sock.read(&mut tmp).expect("lecture requête");
            assert!(n > 0, "connexion fermée avant la fin des en-têtes");
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                assert!(
                    head.to_ascii_lowercase()
                        .contains("content-type: application/timestamp-query"),
                    "en-tête RFC 3161 attendu, reçu :\n{head}"
                );
                let cl = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .expect("Content-Length présent");
                break (pos + 4, cl);
            }
        };
        while buf.len() < header_end + content_length {
            let n = sock.read(&mut tmp).expect("lecture corps");
            assert!(n > 0, "corps tronqué");
            buf.extend_from_slice(&tmp[..n]);
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        );
        sock.write_all(head.as_bytes()).expect("écriture");
        sock.write_all(&reply).expect("écriture");
        buf[header_end..header_end + content_length].to_vec()
    })
}

#[test]
fn anchor_send_archive_le_jeton_et_pack_le_joint_au_dossier() {
    let (store, signer) = scenario();
    let dir = tmp_dir("anchor-send");
    let store_path = dir.join("constat.redb");
    let root = store.root().expect("racine").expect("journal non vide");

    // La réponse fabriquée est bien une TimeStampResp valide au sens de
    // constat-anchor (le même décodeur que la CLI).
    let (reply, token) = granted_response();
    let parsed = constat_anchor::rfc3161::parse_response(&reply).expect("réponse de test valide");
    assert!(parsed.status.is_granted());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/tsa", listener.local_addr().expect("addr"));
    let server = serve_tsa_once(listener, reply.clone());

    let msg = commands::cmd_anchor(
        &store,
        &commands::AnchorArgs {
            request_out: None,
            export_out: None,
            keys: None,
            organization: None,
            send: Some(&url),
            store_path: Some(&store_path),
        },
    )
    .expect("anchor --send");
    assert!(msg.contains("délivré"), "sortie : {msg}");

    // Le prestataire a reçu exactement la TimeStampReq DER de constat-anchor.
    let received = server.join().expect("serveur de test");
    assert_eq!(
        received,
        constat_anchor::rfc3161::TimeStampRequest::for_root(&root).to_der()
    );

    // Le jeton est archivé au chemin documenté : <magasin>.anchors/<racine>.tsr,
    // et contient la réponse telle que reçue.
    let tsr = anchors::token_path(&store_path, &root);
    assert_eq!(
        tsr,
        dir.join(format!("constat.redb.anchors/{}.tsr", root.to_hex()))
    );
    assert_eq!(std::fs::read(&tsr).expect("jeton archivé"), reply);
    assert_eq!(
        anchors::read_token(&store_path, &root).expect("relecture"),
        Some(token.clone())
    );

    // pack : le jeton ET la clé publique réelle figurent dans le dossier.
    let keys = write_keys_dir(&dir, &signer);
    let assertions_path = dir.join("assertions.yaml");
    std::fs::write(
        &assertions_path,
        "assertions:\n  - id: ADM-AUCUN\n    title: aucun compte privilégié\n    predicate:\n      never: { entity: \"user:*\", attr: \"user.privileged\", equals: true }\n",
    )
    .expect("écriture assertions");
    let dossier_path = dir.join("dossier.html");
    let msg = commands::cmd_pack(
        &store,
        &commands::PackArgs {
            assertions_path: &assertions_path,
            period: "2026-01",
            out: &dossier_path,
            referential: None,
            organization: Some("Exemple SARL"),
            inventory: None,
            pubkey: None,
            keys: Some(&keys),
            store_path: Some(&store_path),
        },
    )
    .expect("pack");
    assert!(msg.contains("RFC 3161 joint"), "sortie : {msg}");
    let html = std::fs::read_to_string(&dossier_path).expect("dossier lisible");
    assert!(
        html.contains(&format!("jeton présent ({} octets", token.len())),
        "le dossier déclare le jeton"
    );
    assert!(
        html.contains(&hex(&signer.verifying_key().to_bytes())),
        "le dossier porte la clé publique réelle du journal"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn anchor_send_refuse_sort_en_erreur_avec_le_motif() {
    let (store, _) = scenario();
    let dir = tmp_dir("anchor-refus");
    let store_path = dir.join("constat.redb");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/tsa", listener.local_addr().expect("addr"));
    let server = serve_tsa_once(listener, rejection_response("horloge arrêtée"));

    let err = commands::cmd_anchor(
        &store,
        &commands::AnchorArgs {
            request_out: None,
            export_out: None,
            keys: None,
            organization: None,
            send: Some(&url),
            store_path: Some(&store_path),
        },
    )
    .expect_err("un refus est une erreur (code de sortie 1)");
    let text = err.to_string();
    assert!(text.contains("refusé"), "erreur : {text}");
    assert!(text.contains("horloge arrêtée"), "motif transmis : {text}");
    server.join().expect("serveur de test");

    // Aucun jeton archivé après un refus.
    let root = store.root().expect("racine").expect("journal non vide");
    assert!(!anchors::token_path(&store_path, &root).exists());
    assert_eq!(
        anchors::read_token(&store_path, &root).expect("relecture"),
        None,
        "l'absence d'ancrage est un état déclaré, pas une erreur"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn anchor_send_https_est_honnetement_refuse() {
    let (store, _) = scenario();
    let dir = tmp_dir("anchor-https");
    let store_path = dir.join("constat.redb");
    let err = commands::cmd_anchor(
        &store,
        &commands::AnchorArgs {
            request_out: None,
            export_out: None,
            keys: None,
            organization: None,
            send: Some("https://tsa.exemple.fr/tsr"),
            store_path: Some(&store_path),
        },
    )
    .expect_err("https non pris en charge");
    assert!(err.to_string().contains("pas pris en charge"));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 3. Assertion::scope, jusqu'au rendu de `constat check`
// ---------------------------------------------------------------------------

#[test]
fn le_scope_filtre_les_machines_jusque_dans_check() {
    let (store, _) = scenario();
    let dir = tmp_dir("scope");
    let assertions_path = dir.join("assertions.yaml");
    // Le YAML du §5.2 : une portée `os: linux`.
    std::fs::write(
        &assertions_path,
        "assertions:\n  - id: ADM-LINUX\n    title: aucun compte privilégié sur linux\n    scope: { os: linux }\n    predicate:\n      never: { entity: \"user:*\", attr: \"user.privileged\", equals: true }\n",
    )
    .expect("écriture assertions");

    let (out, any_fail) =
        commands::cmd_check(&store, &assertions_path, Some("2026-01"), true).expect("check");

    // srv-linux porte le fait `asset.os = linux` : dans la portée, violé.
    assert!(any_fail, "la violation de srv-linux est constatée");
    assert!(out.contains("srv-linux"), "sortie : {out}");
    // srv-mystere viole le prédicat mais ne porte pas le fait d'inventaire
    // requis : EXCLU — le scope sélectionne, il ne présume pas.
    assert!(
        !out.contains("srv-mystere"),
        "une machine sans fait d'inventaire n'entre pas dans l'assertion : {out}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
