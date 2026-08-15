//! Test d'intégration bout-en-bout : le **vrai** client de poussée de
//! `constat-agent` contre le **vrai** écouteur mTLS de `constat-server`,
//! sur `127.0.0.1:port-libre`, avec une PKI générée par rcgen.
//!
//! Vérifie la promesse centrale du transport :
//! - les objets poussés arrivent avec les **mêmes empreintes** et la chaîne
//!   se vérifie côté serveur (`verify_chain`) — dans le journal nommé de la
//!   clé de l'agent, le journal par défaut du magasin restant intact ;
//! - deux agents poussent en **entrelacé** sans se marcher dessus : deux
//!   journaux, deux chaînes vérifiables indépendamment, et une clé qui
//!   rejoue une entrée de l'autre est refusée ;
//! - `--allowed-agents` : une clé absente de l'allowlist est refusée (403)
//!   avant toute écriture ;
//! - un client sans certificat (ou signé par la mauvaise autorité) est
//!   refusé à la poignée de main — mTLS obligatoire, pas de repli ;
//! - un blob altéré en vol (empreinte annoncée ≠ recalculée) est refusé,
//!   sans écriture partielle ;
//! - la double poussée est idempotente.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use constat_agent::push::{build_batch, push, PushBatch, PushConfig, PushError};
use constat_model::{blob_hash, Blob, Fact, Snapshot, Timestamp};
use constat_server::receive::AgentPolicy;
use constat_server::serve::{self, SharedStore};
use constat_store::{append_signed, verify_chain, MemoryStore, Signer, Store};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
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

fn make_ca(common_name: &str) -> (Certificate, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let cert = params.self_signed(&key).unwrap();
    (cert, Issuer::new(params, key))
}

fn make_leaf(
    common_name: &str,
    sans: Vec<String>,
    eku: ExtendedKeyUsagePurpose,
    issuer: &Issuer<'_, KeyPair>,
) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(sans).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.extended_key_usages.push(eku);
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert, key)
}

impl TestPki {
    fn generate(test_name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("constat-e2e-{}-{test_name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (server_ca_cert, server_ca_issuer) = make_ca("CA serveur Constat (test)");
        let (agents_ca_cert, agents_ca_issuer) = make_ca("CA agents Constat (test)");
        // Le certificat de la CA intruse n'est distribué à personne : seule
        // sa capacité à signer le certificat feuille « intrus » compte.
        let (_rogue_ca_cert, rogue_ca_issuer) = make_ca("CA intruse (test)");

        let (server_cert, server_key) = make_leaf(
            "constat-server",
            vec!["localhost".into(), "127.0.0.1".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
            &server_ca_issuer,
        );
        let (agent_cert, agent_key) = make_leaf(
            "agent-01",
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
            &agents_ca_issuer,
        );
        let (rogue_cert, rogue_key) = make_leaf(
            "intrus",
            Vec::new(),
            ExtendedKeyUsagePurpose::ClientAuth,
            &rogue_ca_issuer,
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
    start_server_with_policy(pki, AgentPolicy::Tofu)
}

fn start_server_with_policy(pki: &TestPki, policy: AgentPolicy) -> (SocketAddr, SharedStore) {
    start_server_full(pki, policy, None)
}

fn start_server_with_max(
    pki: &TestPki,
    policy: AgentPolicy,
    max: usize,
) -> (SocketAddr, SharedStore) {
    start_server_full(pki, policy, Some(max))
}

fn start_server_full(
    pki: &TestPki,
    policy: AgentPolicy,
    max: Option<usize>,
) -> (SocketAddr, SharedStore) {
    let tls = serve::load_tls(&pki.server_cert, &pki.server_key, &pki.agents_ca).unwrap();
    let store: SharedStore = Arc::new(Mutex::new(MemoryStore::new()));
    let mut server = serve::Server::bind("127.0.0.1:0", tls, Arc::clone(&store))
        .unwrap()
        .with_policy(policy);
    if let Some(max) = max {
        server = server.with_max_connections(max);
    }
    let addr = server.local_addr().unwrap();
    std::thread::spawn(move || server.run());
    (addr, store)
}

/// Ajoute une collecte journalisée et signée au magasin local d'un agent.
fn add_collecte(store: &mut MemoryStore, signer: &Signer, asset: &str, i: usize) {
    let blob = Blob::new(
        "linux.sshd",
        format!("PermitRootLogin no # {asset} collecte {i}\n").into_bytes(),
        vec![
            Fact::new("service:sshd", "sshd.PermitRootLogin", "no"),
            Fact::new("user:root", "user.privileged", true),
        ],
    );
    let hash = store.put_blob(&blob).unwrap();
    let mut blobs = BTreeMap::new();
    blobs.insert("linux.sshd".into(), hash);
    let snapshot = Snapshot::new(asset, Timestamp(1_000 + i as i64), blobs);
    let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
    append_signed(
        store,
        signer,
        vec![snapshot_hash],
        Timestamp(1_000 + i as i64),
    )
    .unwrap();
}

/// Remplit un magasin local d'agent : `n` collectes journalisées et signées.
fn fill_agent_store(n: usize) -> (MemoryStore, Signer) {
    let mut store = MemoryStore::new();
    let signer = Signer::generate();
    for i in 0..n {
        add_collecte(&mut store, &signer, "srv-01", i);
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

    // Mêmes objets, mêmes empreintes, chaîne vérifiable côté serveur — dans
    // le journal nommé de la clé de l'agent (§13 S8).
    let journal = signer.verifying_key().to_bytes();
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
        let server_entries = guard.entries_of(&journal).unwrap();
        assert_eq!(server_entries, agent_entries);
        verify_chain(&server_entries, &signer.verifying_key()).unwrap();
        assert_eq!(
            guard.root_of(&journal).unwrap(),
            agent_store.root().unwrap()
        );
        // Le journal par défaut du magasin central n'est pas touché.
        assert_eq!(guard.root().unwrap(), None);
    }

    // Double poussée : idempotente, le magasin du serveur ne bouge pas.
    push(&config, &batch).unwrap();
    {
        let guard = server_store.lock().unwrap();
        assert_eq!(guard.entries_of(&journal).unwrap().len(), 2);
        assert_eq!(
            guard.root_of(&journal).unwrap(),
            agent_store.root().unwrap()
        );
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
        assert_eq!(guard.entries_of(&journal).unwrap().len(), 2);
    }
}

/// Deux agents — deux clés, deux chaînes — poussent en entrelacé vers le
/// même serveur : chacun atterrit dans SON journal, les deux chaînes restent
/// intactes et se vérifient indépendamment. Puis une clé rejoue une entrée
/// de l'autre : refusée — une clé ne peut jamais écrire dans le journal
/// d'une autre.
#[test]
fn deux_agents_entrelaces_deux_chaines_independantes() {
    let pki = TestPki::generate("deux-agents");
    let (addr, server_store) = start_server(&pki);
    let config = pki.push_config(addr);

    let mut store_a = MemoryStore::new();
    let signer_a = Signer::generate();
    let mut store_b = MemoryStore::new();
    let signer_b = Signer::generate();
    let journal_a = signer_a.verifying_key().to_bytes();
    let journal_b = signer_b.verifying_key().to_bytes();

    // Poussées entrelacées : A(1), B(1), A(2), B(2), B(3) — chaque poussée
    // rejoue tout le magasin local (idempotent) plus le nouveau.
    let plan: [(&str, usize); 5] = [("a", 1), ("b", 1), ("a", 2), ("b", 2), ("b", 3)];
    for (who, i) in plan {
        let (store, signer, asset) = if who == "a" {
            (&mut store_a, &signer_a, "srv-a")
        } else {
            (&mut store_b, &signer_b, "srv-b")
        };
        add_collecte(store, signer, asset, i);
        let batch = build_batch(store, signer.verifying_key().to_bytes(), asset.into()).unwrap();
        push(&config, &batch).unwrap();
    }

    // Deux journaux, deux chaînes intactes, vérifiées indépendamment —
    // chacune identique à celle du magasin local de son agent.
    {
        let guard = server_store.lock().unwrap();
        let entries_a = guard.entries_of(&journal_a).unwrap();
        let entries_b = guard.entries_of(&journal_b).unwrap();
        assert_eq!(entries_a, store_a.entries().unwrap());
        assert_eq!(entries_b, store_b.entries().unwrap());
        verify_chain(&entries_a, &signer_a.verifying_key()).unwrap();
        verify_chain(&entries_b, &signer_b.verifying_key()).unwrap();
        assert_eq!(guard.journals().unwrap().len(), 2);
        assert_eq!(guard.root().unwrap(), None, "journal par défaut intact");
    }

    // La clé A rejoue une entrée du journal de B (objets déjà connus du
    // serveur, entrée signée par B) : 422, et rien ne bouge nulle part.
    let vol = PushBatch {
        agent_public_key: journal_a,
        asset: "srv-b".into(),
        blobs: vec![],
        snapshots: vec![],
        entries: store_b
            .entries()
            .unwrap()
            .into_iter()
            .map(|(_, e)| e)
            .take(1)
            .collect(),
    };
    let err = push(&config, &vol).unwrap_err();
    assert!(
        matches!(err, PushError::Refused { status: 422 }),
        "attendu un refus 422, obtenu : {err}"
    );
    {
        let guard = server_store.lock().unwrap();
        assert_eq!(
            guard.entries_of(&journal_a).unwrap(),
            store_a.entries().unwrap()
        );
        assert_eq!(
            guard.entries_of(&journal_b).unwrap(),
            store_b.entries().unwrap()
        );
    }
}

/// `--allowed-agents` : la clé absente de l'allowlist est refusée avec 403
/// AVANT toute écriture ; la clé listée passe normalement.
#[test]
fn allowlist_cle_absente_refusee_403() {
    let pki = TestPki::generate("allowlist");
    let (store_a, signer_a) = fill_agent_store(1);
    let (store_b, signer_b) = fill_agent_store(1);

    // Seul A est autorisé.
    let policy = AgentPolicy::Allowlist(BTreeSet::from([signer_a.verifying_key().to_bytes()]));
    let (addr, server_store) = start_server_with_policy(&pki, policy);
    let config = pki.push_config(addr);

    // B (clé absente) : 403, et aucune écriture — pas même un blob.
    let batch_b = build_batch(
        &store_b,
        signer_b.verifying_key().to_bytes(),
        "srv-b".into(),
    )
    .unwrap();
    let err = push(&config, &batch_b).unwrap_err();
    assert!(
        matches!(err, PushError::Refused { status: 403 }),
        "attendu un refus 403, obtenu : {err}"
    );
    {
        let guard = server_store.lock().unwrap();
        assert!(guard.journals().unwrap().is_empty());
        for blob in &batch_b.blobs {
            assert!(!guard.has_blob(&blob_hash(blob).unwrap()).unwrap());
        }
    }

    // A (clé listée) : accepté, son journal existe.
    let batch_a = build_batch(
        &store_a,
        signer_a.verifying_key().to_bytes(),
        "srv-a".into(),
    )
    .unwrap();
    push(&config, &batch_a).unwrap();
    {
        let guard = server_store.lock().unwrap();
        assert_eq!(
            guard.journals().unwrap(),
            vec![signer_a.verifying_key().to_bytes()]
        );
    }
}

/// Rotation de clé bout-en-bout, sur le vrai transport : l'agent pousse,
/// tourne sa clé (`constat_store::rotate_key`, ce que fait
/// `constat-agent rotate-key`), recollecte et repousse — `build_batch`
/// annonce la clé de GENÈSE (l'identité), le serveur suit la clé courante,
/// le Receipt/la racine restent corrects. Une TIERCE clé qui tente de
/// pousser sur ce journal reste refusée.
#[test]
fn rotation_puis_poussee_bout_en_bout() {
    use constat_store::{rotate_key, verify_chain_rotated};

    let pki = TestPki::generate("rotation");
    let (addr, server_store) = start_server(&pki);
    let config = pki.push_config(addr);

    let (mut agent_store, old) = fill_agent_store(1);
    let genesis = old.verifying_key().to_bytes();

    // Première poussée, avant rotation : la clé courante EST la genèse.
    let batch = build_batch(&agent_store, genesis, "srv-01".into()).unwrap();
    assert_eq!(batch.agent_public_key, genesis);
    push(&config, &batch).unwrap();

    // Rotation locale, puis nouvelle collecte signée par la NOUVELLE clé.
    let new = Signer::generate();
    rotate_key(
        &mut agent_store,
        &old,
        &new,
        Some("rotation planifiée"),
        Timestamp(5_000),
    )
    .unwrap();
    add_collecte(&mut agent_store, &new, "srv-01", 9);

    // Repoussée : build_batch retrouve la GENÈSE dans le journal, même si
    // la clé fournie est la clé courante (le nouvel agent.pub).
    let batch = build_batch(
        &agent_store,
        new.verifying_key().to_bytes(),
        "srv-01".into(),
    )
    .unwrap();
    assert_eq!(
        batch.agent_public_key, genesis,
        "le lot annonce l'identité (genèse), pas la clé courante"
    );
    push(&config, &batch).unwrap();

    {
        let guard = server_store.lock().unwrap();
        // Un seul journal : celui de l'identité de genèse.
        assert_eq!(guard.journals().unwrap(), vec![genesis]);
        let entries = guard.entries_of(&genesis).unwrap();
        assert_eq!(entries, agent_store.entries().unwrap());
        assert_eq!(
            guard.root_of(&genesis).unwrap(),
            agent_store.root().unwrap()
        );
        // La chaîne serveur se vérifie en suivant la clé courante.
        let trace = verify_chain_rotated(&*guard, &entries, &old.verifying_key()).unwrap();
        assert_eq!(trace.rotations, 1);
        assert_eq!(trace.final_key, new.verifying_key().to_bytes());
    }

    // Une TIERCE clé forge une entrée sur ce journal : 422, rien ne bouge.
    let third = Signer::generate();
    let root = agent_store.root().unwrap();
    let forged = third.sign_entry(root, vec![], Timestamp(9_000)).unwrap();
    let vol = PushBatch {
        agent_public_key: genesis,
        asset: "srv-01".into(),
        blobs: vec![],
        snapshots: vec![],
        entries: vec![forged],
    };
    let err = push(&config, &vol).unwrap_err();
    assert!(
        matches!(err, PushError::Refused { status: 422 }),
        "attendu un refus 422, obtenu : {err}"
    );
    {
        let guard = server_store.lock().unwrap();
        assert_eq!(
            guard.entries_of(&genesis).unwrap(),
            agent_store.entries().unwrap()
        );
    }
}

/// Disponibilité sous flot : un serveur volontairement étroit (2 connexions
/// simultanées) reçoit 6 poussées légitimes CONCURRENTES — plus que sa borne.
/// Le bornage sérialise les créneaux mais l'acceptation ne panique pas et ne
/// s'interbloque pas : les 6 poussées aboutissent, 6 journaux existent. Le
/// serveur reste réactif sous un flot qui dépasse sa limite.
#[test]
fn flot_de_connexions_sous_la_borne_reste_servi() {
    let pki = TestPki::generate("flot");
    let (addr, server_store) = start_server_with_max(&pki, AgentPolicy::Tofu, 2);

    let n: usize = 6;
    let mut handles = Vec::new();
    for i in 0..n {
        let config = pki.push_config(addr);
        handles.push(std::thread::spawn(move || {
            let mut store = MemoryStore::new();
            let signer = Signer::generate();
            add_collecte(&mut store, &signer, "srv", i);
            let batch =
                build_batch(&store, signer.verifying_key().to_bytes(), "srv".into()).unwrap();
            let result = push(&config, &batch);
            (signer.verifying_key().to_bytes(), result)
        }));
    }

    let mut journals = Vec::new();
    for h in handles {
        let (journal, result) = h.join().unwrap();
        // Chaque poussée aboutit : ni panique d'acceptation, ni interblocage.
        result.unwrap();
        journals.push(journal);
    }

    let guard = server_store.lock().unwrap();
    assert_eq!(
        guard.journals().unwrap().len(),
        n,
        "les {n} poussées concurrentes doivent toutes avoir abouti"
    );
    for journal in journals {
        assert_eq!(guard.entries_of(&journal).unwrap().len(), 1);
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
