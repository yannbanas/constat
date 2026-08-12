//! Test d'intégration bout-en-bout : le **vrai** client de poussée de
//! `constat-agent` contre le **vrai** écouteur mTLS de `constat-server`,
//! sur `127.0.0.1:port-libre`, avec une PKI générée par rcgen.
//!
//! Vérifie la promesse centrale du transport :
//! - les objets poussés arrivent avec les **mêmes empreintes** et la chaîne
//!   se vérifie côté serveur (`verify_chain`) ;
//! - un client sans certificat (ou signé par la mauvaise autorité) est
//!   refusé à la poignée de main — mTLS obligatoire, pas de repli ;
//! - un blob altéré en vol (empreinte annoncée ≠ recalculée) est refusé,
//!   sans écriture partielle ;
//! - la double poussée est idempotente.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use constat_agent::push::{build_batch, push, PushConfig, PushError};
use constat_model::{blob_hash, Blob, Fact, Snapshot, Timestamp};
use constat_server::serve::{self, SharedStore};
use constat_store::{append_signed, verify_chain, MemoryStore, Signer, Store};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

// ---------------------------------------------------------------------------
// Petite PKI de test : CA serveur, CA agents, certificats feuilles.
// ---------------------------------------------------------------------------

struct TestPki {
    dir: PathBuf,
    /// Autorité du serveur — ce que l'agent passe en `--ca`.
    server_ca: PathBuf,
    /// Autorité des agents — ce que le serveur passe en `--client-ca`.
    agents_ca: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    agent_cert: PathBuf,
    agent_key: PathBuf,
    /// Certificat client signé par une autorité que le serveur NE connaît pas.
    rogue_cert: PathBuf,
    rogue_key: PathBuf,
}

fn make_ca(common_name: &str) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

fn make_leaf(
    common_name: &str,
    sans: Vec<String>,
    eku: ExtendedKeyUsagePurpose,
    issuer: &Certificate,
    issuer_key: &KeyPair,
) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(sans).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.extended_key_usages.push(eku);
    let cert = params.signed_by(&key, issuer, issuer_key).unwrap();
    (cert, key)
}

impl TestPki {
    fn generate(test_name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("constat-e2e-{}-{test_name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (server_ca_cert, server_ca_key) = make_ca("CA serveur Constat (test)");
        let (agents_ca_cert, agents_ca_key) = make_ca("CA agents Constat (test)");
        let (rogue_ca_cert, rogue_ca_key) = make_ca("CA intruse (test)");

        let (server_cert, server_key) = make_leaf(
            "constat-server",
            vec!["localhost".into(), "127.0.0.1".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
            &server_ca_cert,
            &server_ca_key,
        );
        let (agent_cert, agent_key) = make_leaf(
            "agent-01",
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
            &agents_ca_cert,
            &agents_ca_key,
        );
        let (rogue_cert, rogue_key) = make_leaf(
            "intrus",
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
            &rogue_ca_cert,
            &rogue_ca_key,
        );

        let write = |name: &str, contents: String| -> PathBuf {
            let path = dir.join(name);
            std::fs::write(&path, contents).unwrap();
            path
        };
        Self {
            server_ca: write("ca-serveur.pem", server_ca_cert.pem()),
            agents_ca: write("ca-agents.pem", agents_ca_cert.pem()),
            server_cert: write("serveur.pem", server_cert.pem()),
            server_key: write("serveur.key", server_key.serialize_pem()),
            agent_cert: write("agent.pem", agent_cert.pem()),
            agent_key: write("agent.key", agent_key.serialize_pem()),
            rogue_cert: write("intrus.pem", rogue_cert.pem()),
            rogue_key: write("intrus.key", rogue_key.serialize_pem()),
            dir,
        }
    }

    fn push_config(&self, addr: SocketAddr) -> PushConfig {
        PushConfig {
            server_url: format!("https://localhost:{}", addr.port()),
            client_cert: self.agent_cert.clone(),
            client_key: self.agent_key.clone(),
            server_ca: self.server_ca.clone(),
        }
    }
}

impl Drop for TestPki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Démarrage du vrai serveur sur un port libre, magasin partagé inspectable.
// ---------------------------------------------------------------------------

fn start_server(pki: &TestPki) -> (SocketAddr, SharedStore) {
    let tls = serve::load_tls(&pki.server_cert, &pki.server_key, &pki.agents_ca).unwrap();
    let store: SharedStore = Arc::new(Mutex::new(MemoryStore::new()));
    let server = serve::Server::bind("127.0.0.1:0", tls, Arc::clone(&store)).unwrap();
    let addr = server.local_addr().unwrap();
    std::thread::spawn(move || server.run());
    (addr, store)
}

/// Remplit un magasin local d'agent : `n` collectes journalisées et signées.
fn fill_agent_store(n: usize) -> (MemoryStore, Signer) {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    for i in 0..n {
        let blob = Blob::new(
            "linux.sshd",
            format!("PermitRootLogin no # collecte {i}\n").into_bytes(),
            vec![
                Fact::new("service:sshd", "sshd.PermitRootLogin", "no"),
                Fact::new("user:root", "user.privileged", true),
            ],
        );
        let hash = store.put_blob(&blob).unwrap();
        let mut blobs = BTreeMap::new();
        blobs.insert("linux.sshd".into(), hash);
        let snapshot = Snapshot::new("srv-01", Timestamp(1_000 + i as i64), blobs);
        let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
        append_signed(
            &mut store,
            &signer,
            vec![snapshot_hash],
            Timestamp(1_000 + i as i64),
        )
        .unwrap();
    }
    (store, signer)
}

// ---------------------------------------------------------------------------
// Les tests.
// ---------------------------------------------------------------------------

/// Le parcours nominal : magasin local rempli → push mTLS → le magasin du
/// serveur contient les mêmes objets, mêmes empreintes, chaîne vérifiable.
/// Puis : double poussée idempotente, et blob altéré en vol refusé.
#[test]
fn pousse_verifie_rejoue_et_refuse_l_altere() {
    let pki = TestPki::generate("nominal");
    let (addr, server_store) = start_server(&pki);
    let (agent_store, signer) = fill_agent_store(2);
    let config = pki.push_config(addr);

    let batch = build_batch(
        &agent_store,
        signer.verifying_key().to_bytes(),
        "srv-01".into(),
    )
    .unwrap();
    push(&config, &batch).unwrap();

    // Mêmes objets, mêmes empreintes, chaîne vérifiable côté serveur.
    {
        let guard = server_store.lock().unwrap();
        for blob in &batch.blobs {
            let hash = blob_hash(blob).unwrap();
            assert!(
                guard.has_blob(&hash).unwrap(),
                "blob {} absent",
                hash.to_hex()
            );
            assert_eq!(&guard.get_blob(&hash).unwrap(), blob);
        }
        let agent_entries = agent_store.entries().unwrap();
        let server_entries = guard.entries().unwrap();
        assert_eq!(server_entries, agent_entries);
        verify_chain(&server_entries, &signer.verifying_key()).unwrap();
        assert_eq!(guard.root().unwrap(), agent_store.root().unwrap());
    }

    // Double poussée : idempotente, le magasin du serveur ne bouge pas.
    push(&config, &batch).unwrap();
    {
        let guard = server_store.lock().unwrap();
        assert_eq!(guard.entries().unwrap().len(), 2);
        assert_eq!(guard.root().unwrap(), agent_store.root().unwrap());
    }

    // Blob altéré en vol : l'empreinte recalculée ne correspond plus à celle
    // que le snapshot annonce → 422, et aucune écriture partielle.
    let mut tampered = batch.clone();
    tampered.blobs[0].raw.push(b'!');
    let altered_hash = blob_hash(&tampered.blobs[0]).unwrap();
    let err = push(&config, &tampered).unwrap_err();
    assert!(
        matches!(err, PushError::Refused { status: 422 }),
        "attendu un refus 422, obtenu : {err}"
    );
    {
        let guard = server_store.lock().unwrap();
        assert!(!guard.has_blob(&altered_hash).unwrap());
        assert_eq!(guard.entries().unwrap().len(), 2);
    }
}

/// Un client sans certificat est refusé à la poignée de main : le mTLS n'est
/// pas optionnel, il n'existe pas de mode « anonyme ».
#[test]
fn client_sans_certificat_refuse() {
    let pki = TestPki::generate("sans-certificat");
    let (addr, server_store) = start_server(&pki);

    // Client TLS qui fait confiance au serveur mais ne présente RIEN.
    use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&pki.server_ca).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();

    let sock = TcpStream::connect(addr).unwrap();
    let conn =
        rustls::ClientConnection::new(Arc::new(tls), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut stream = rustls::StreamOwned::new(conn, sock);

    let attempt = stream
        .write_all(b"POST /v1/pousse HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .and_then(|_| {
            let mut response = Vec::new();
            stream.read_to_end(&mut response).map(|_| response)
        });
    match attempt {
        Err(_) => {} // refusé à la poignée de main : le cas attendu
        Ok(response) => assert!(
            !response.starts_with(b"HTTP/1.1 200"),
            "un client sans certificat ne doit jamais obtenir un accusé"
        ),
    }
    // Et rien n'a été écrit.
    assert!(server_store.lock().unwrap().root().unwrap().is_none());
}

/// Un certificat client signé par une autorité inconnue du serveur est
/// refusé — être « un » certificat ne suffit pas, il faut LA bonne autorité.
#[test]
fn certificat_d_autorite_inconnue_refuse() {
    let pki = TestPki::generate("autorite-inconnue");
    let (addr, server_store) = start_server(&pki);
    let (agent_store, signer) = fill_agent_store(1);

    let mut config = pki.push_config(addr);
    config.client_cert = pki.rogue_cert.clone();
    config.client_key = pki.rogue_key.clone();

    let batch = build_batch(
        &agent_store,
        signer.verifying_key().to_bytes(),
        "srv-01".into(),
    )
    .unwrap();
    let err = push(&config, &batch).unwrap_err();
    assert!(
        matches!(err, PushError::Io(_) | PushError::Tls(_)),
        "attendu un refus à la poignée de main, obtenu : {err}"
    );
    assert!(server_store.lock().unwrap().root().unwrap().is_none());
}
