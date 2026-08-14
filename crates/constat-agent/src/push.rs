//! Poussée sortante vers `constat-server` — client mTLS synchrone.
//!
//! # Contraintes §7.1, non négociables
//!
//! - **Aucun port en écoute.** L'agent est exclusivement client : il initie
//!   la connexion, pousse, et raccroche. Compromettre le serveur ne donne
//!   aucun moyen d'atteindre l'agent.
//! - **mTLS obligatoire.** L'agent présente son certificat client ; il
//!   vérifie le certificat du serveur contre l'autorité fournie à
//!   l'installation (et elle seule). Pas de repli en clair, jamais : une URL
//!   qui n'est pas `https://` est rejetée avant toute connexion.
//! - **Aucune exécution de code envoyé.** La réponse du serveur est un
//!   accusé de réception, rien d'autre : seul le **statut HTTP** est lu ;
//!   le corps n'est jamais décodé ni interprété (voir `read_status`).
//!
//! # Protocole
//!
//! `POST /v1/pousse` sur la liaison mTLS, en HTTP/1.1 écrit à la main :
//!
//! ```text
//! POST /v1/pousse HTTP/1.1
//! Host: <hôte>:<port>
//! Content-Type: application/cbor
//! Content-Length: <n>
//! Connection: close
//!
//! <encodage canonique CBOR d'un PushBatch>
//! ```
//!
//! Le corps est l'encodage canonique CBOR (celui de `constat-model`, §15)
//! d'un [`PushBatch`]. Le serveur répond `200` avec un accusé (compteurs,
//! jamais d'instruction) ou un code d'erreur : `422` si un objet du lot est
//! refusé (empreinte non résoluble, signature invalide, chaîne incohérente),
//! `400`/`404`/`405`/`411`/`413` pour une requête malformée.
//!
//! La poussée est **idempotente** : les objets sont adressés par contenu,
//! re-pousser un blob déjà connu est un non-événement. L'agent peut donc
//! rejouer sans risque après une coupure — [`build_batch`] émet d'ailleurs
//! tout le contenu du magasin local à chaque poussée, le serveur dédoublonne.
//!
//! Le miroir côté serveur est `constat-server/src/receive.rs` (types) et
//! `constat-server/src/serve.rs` (transport).

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use constat_model::{to_canonical_bytes, Blob, ModelError, Snapshot};
use constat_store::{JournalEntry, Store, StoreError};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};

/// Ce que l'agent pousse : les objets nouveaux depuis la dernière poussée.
///
/// L'ordre importe : blobs, puis snapshots, puis entrées — le serveur peut
/// ainsi vérifier chaque référence au moment où il la rencontre.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushBatch {
    /// Clé publique Ed25519 de l'agent (32 octets) : identifie la source et
    /// permet au serveur de vérifier les signatures des entrées.
    pub agent_public_key: [u8; 32],
    /// Machine concernée (redondant avec les snapshots, mais permet le
    /// contrôle d'inventaire attendu/observé côté serveur).
    pub asset: String,
    /// Blobs nouveaux, déjà expurgés (§7.2) — le serveur ne reçoit jamais
    /// autre chose que la forme expurgée.
    pub blobs: Vec<Blob>,
    /// Snapshots nouveaux.
    pub snapshots: Vec<Snapshot>,
    /// Entrées de journal nouvelles, signées, dans l'ordre de la chaîne.
    pub entries: Vec<JournalEntry>,
}

impl PushBatch {
    /// Un lot sans aucun objet : rien à pousser.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty() && self.snapshots.is_empty() && self.entries.is_empty()
    }
}

/// Configuration de la poussée, fournie à l'installation.
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// URL du serveur, ex. `https://constat.interne` — `https` obligatoire.
    pub server_url: String,
    /// Certificat client de l'agent (PEM).
    pub client_cert: PathBuf,
    /// Clé privée du certificat client (PEM) — distincte de la clé de
    /// signature du journal.
    pub client_key: PathBuf,
    /// Autorité de certification du serveur (PEM) : la seule acceptée.
    pub server_ca: PathBuf,
}

/// Chemin HTTP de la poussée — miroir exact de `constat-server`.
pub const PUSH_PATH: &str = "/v1/pousse";

/// Délai maximal de lecture/écriture sur la liaison : un serveur muet ne
/// doit pas bloquer l'agent indéfiniment.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Taille maximale lue de la réponse. Seul le statut nous intéresse (§7.1) ;
/// un serveur qui répondrait par un déluge d'octets est coupé net.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Erreurs de poussée.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum PushError {
    /// L'URL du serveur n'est pas exploitable (ou n'est pas `https`).
    #[error("URL de serveur invalide : {0}")]
    #[diagnostic(help(
        "format attendu : https://hote[:port] — le schéma https est \
         obligatoire, il n'existe aucun repli en clair (§7.1)"
    ))]
    InvalidUrl(String),

    /// Un fichier PEM (certificat, clé, autorité) est absent ou illisible.
    #[error("fichier PEM illisible ({path}) : {detail}")]
    #[diagnostic(help(
        "vérifiez le chemin et le format PEM : certificat client (--cert), \
         clé privée (--key) et autorité du serveur (--ca) sont fournis à \
         l'installation de l'agent"
    ))]
    Pem { path: String, detail: String },

    /// La configuration TLS est incohérente (certificat/clé dépareillés…).
    #[error("configuration TLS invalide : {0}")]
    Tls(#[from] rustls::Error),

    /// Erreur réseau (connexion, poignée de main mTLS, coupure).
    #[error("erreur réseau pendant la poussée : {0}")]
    #[diagnostic(help(
        "la poussée est idempotente : relancez `constat-agent push` sans \
         risque une fois la liaison rétablie"
    ))]
    Io(#[from] std::io::Error),

    /// La réponse ne ressemble pas à du HTTP/1.1.
    #[error("réponse du serveur illisible : {0}")]
    BadResponse(String),

    /// Le serveur a répondu, mais pas `200` : le lot est refusé.
    #[error("poussée refusée par le serveur : statut HTTP {status}")]
    #[diagnostic(help(
        "422 : un objet du lot a été refusé (empreinte non résoluble, \
         signature ou chaîne invalide) ; la poussée étant idempotente, \
         corrigez la cause puis relancez sans risque"
    ))]
    Refused { status: u16 },

    /// Le magasin local n'a pas pu être lu.
    #[error("erreur du magasin local : {0}")]
    Store(#[from] StoreError),

    /// L'encodage canonique du lot a échoué.
    #[error("erreur d'encodage canonique : {0}")]
    Encoding(#[from] ModelError),
}

/// Construit le lot à pousser à partir du magasin local : tout ce qui est
/// atteignable depuis le journal (entrées → snapshots → blobs), dédoublonné.
///
/// Émettre l'intégralité du magasin à chaque poussée est volontaire : la
/// réception est idempotente (adressage par contenu), donc la reprise après
/// coupure ne demande aucun état côté agent — rejouer est sans effet.
pub fn build_batch(
    store: &dyn Store,
    agent_public_key: [u8; 32],
    asset: String,
) -> Result<PushBatch, PushError> {
    let mut blobs = Vec::new();
    let mut snapshots = Vec::new();
    let mut entries = Vec::new();
    let mut seen_blobs = BTreeSet::new();
    let mut seen_snapshots = BTreeSet::new();

    for (_, entry) in store.entries()? {
        for snapshot_hash in &entry.snapshots {
            if seen_snapshots.insert(*snapshot_hash) {
                let snapshot = store.get_snapshot(snapshot_hash)?;
                for blob_hash in snapshot.blobs.values() {
                    if seen_blobs.insert(*blob_hash) {
                        blobs.push(store.get_blob(blob_hash)?);
                    }
                }
                snapshots.push(snapshot);
            }
        }
        entries.push(entry);
    }

    Ok(PushBatch {
        agent_public_key,
        asset,
        blobs,
        snapshots,
        entries,
    })
}

/// Pousse un lot vers le serveur, en mTLS sortant uniquement.
///
/// Charge le matériel TLS depuis les fichiers de [`PushConfig`] puis délègue
/// à [`push_with_tls`]. Quand l'agent doit abandonner ses privilèges avant
/// la phase réseau (§7.1, mode `--once` démarré root), l'appelant utilise
/// plutôt [`load_tls_config`] **avant** l'abandon, puis [`push_with_tls`]
/// après — voir [`crate::privileges`].
pub fn push(config: &PushConfig, batch: &PushBatch) -> Result<(), PushError> {
    let tls = load_tls_config(config)?;
    push_with_tls(config, tls, batch)
}

/// Pousse un lot avec un matériel TLS déjà chargé : **aucun fichier n'est
/// lu ici**, seule l'URL de [`PushConfig`] est utilisée.
///
/// C'est la moitié « réseau » de [`push`], séparée pour l'abandon de
/// privilèges (§7.1) : l'agent charge certificats et clé en mémoire tant
/// qu'il est root ([`load_tls_config`]), abandonne ses privilèges, puis
/// appelle cette fonction en tant qu'utilisateur cible — les fichiers PEM
/// peuvent donc rester lisibles par root seul (0600).
///
/// Ouvre une connexion TCP sortante, négocie le mTLS (certificat client
/// présenté, serveur vérifié contre l'autorité de [`PushConfig::server_ca`]),
/// écrit une requête `POST /v1/pousse` HTTP/1.1 et lit le **statut** de la
/// réponse — rien d'autre : le corps de l'accusé n'est jamais interprété
/// (§7.1, aucune exécution de code envoyé).
pub fn push_with_tls(
    config: &PushConfig,
    tls: Arc<rustls::ClientConfig>,
    batch: &PushBatch,
) -> Result<(), PushError> {
    let (host, port, path) = parse_server_url(&config.server_url)?;
    let body = to_canonical_bytes(batch)?;

    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| PushError::InvalidUrl(format!("nom de serveur « {host} » : {e}")))?;
    let sock = TcpStream::connect((host.as_str(), port))?;
    sock.set_read_timeout(Some(IO_TIMEOUT))?;
    sock.set_write_timeout(Some(IO_TIMEOUT))?;
    let conn = rustls::ClientConnection::new(tls, server_name)?;
    let mut stream = rustls::StreamOwned::new(conn, sock);

    // HTTP/1.1 écrit à la main : une requête, une réponse, on raccroche.
    let host_header = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: application/cbor\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;

    let status = read_status(&mut stream)?;
    // La liaison est refermée sans lire le reste : la réponse est un accusé
    // de réception, seul le statut compte, le corps n'est pas une donnée.
    stream.conn.send_close_notify();
    let _ = stream.sock.shutdown(std::net::Shutdown::Both);

    if status == 200 {
        Ok(())
    } else {
        Err(PushError::Refused { status })
    }
}

/// Lit la réponse jusqu'à disposer de la ligne de statut, et n'extrait que
/// le code. Le corps de l'accusé n'est **jamais** décodé : c'est la garantie
/// mécanique qu'aucun contenu envoyé par le serveur n'influence l'agent.
fn read_status(stream: &mut impl Read) -> Result<u16, PushError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(2).any(|w| w == b"\r\n") {
        if buf.len() >= MAX_RESPONSE_BYTES {
            return Err(PushError::BadResponse(
                "ligne de statut introuvable dans les premiers 64 Kio".into(),
            ));
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            // Un serveur qui coupe sans close_notify après avoir répondu :
            // si la ligne de statut est déjà là, elle suffit.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => break,
            Err(e) => return Err(e.into()),
        }
    }
    parse_status_line(&buf)
}

/// Extrait le code de statut de la première ligne, ex. `HTTP/1.1 200 OK`.
fn parse_status_line(bytes: &[u8]) -> Result<u16, PushError> {
    let end = bytes
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(bytes.len());
    let line = std::str::from_utf8(&bytes[..end])
        .map_err(|_| PushError::BadResponse("ligne de statut non UTF-8".into()))?;
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(PushError::BadResponse(format!(
            "ligne de statut inattendue : « {line} »"
        )));
    }
    parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| PushError::BadResponse(format!("code de statut illisible : « {line} »")))
}

/// Construit la configuration TLS cliente : autorité du serveur comme seule
/// racine de confiance, certificat client présenté d'office (mTLS).
///
/// **Seule fonction de la poussée qui lit des fichiers** (certificat, clé,
/// autorité). Publique et séparée de [`push_with_tls`] pour l'abandon de
/// privilèges (§7.1) : appelée avant l'abandon, elle laisse la clé cliente
/// lisible par root seul — rien n'est relu ensuite.
///
/// Le fournisseur cryptographique (`ring`) est fixé explicitement : le
/// comportement ne dépend pas des features activées ailleurs dans l'arbre.
pub fn load_tls_config(config: &PushConfig) -> Result<Arc<rustls::ClientConfig>, PushError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in read_certs(&config.server_ca)? {
        roots.add(cert)?;
    }
    let certs = read_certs(&config.client_cert)?;
    let key = PrivateKeyDer::from_pem_file(&config.client_key)
        .map_err(|e| pem_error(&config.client_key, e))?;

    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_client_auth_cert(certs, key)?;
    Ok(Arc::new(tls))
}

/// Lit tous les certificats d'un fichier PEM ; au moins un est exigé.
fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, PushError> {
    let iter = CertificateDer::pem_file_iter(path).map_err(|e| pem_error(path, e))?;
    let certs = iter
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pem_error(path, e))?;
    if certs.is_empty() {
        return Err(PushError::Pem {
            path: path.display().to_string(),
            detail: "aucun certificat dans le fichier".into(),
        });
    }
    Ok(certs)
}

fn pem_error(path: &Path, e: rustls::pki_types::pem::Error) -> PushError {
    PushError::Pem {
        path: path.display().to_string(),
        detail: e.to_string(),
    }
}

/// Décompose `https://hôte[:port][/prefixe]` en (hôte, port, chemin complet).
///
/// Le schéma `https` est obligatoire — refuser `http://` ici, avant toute
/// connexion, est la traduction mécanique de « pas de repli en clair ».
/// Un éventuel préfixe de chemin (serveur derrière un mandataire inverse)
/// est conservé devant [`PUSH_PATH`].
fn parse_server_url(url: &str) -> Result<(String, u16, String), PushError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        PushError::InvalidUrl(format!("« {url} » — le schéma https:// est obligatoire"))
    })?;
    let (authority, base_path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(PushError::InvalidUrl(format!("« {url} » — hôte manquant")));
    }

    let bad_port = |p: &str| PushError::InvalidUrl(format!("« {url} » — port illisible : « {p} »"));
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        // Adresse IPv6 entre crochets, ex. https://[::1]:8443
        let (inside, after) = v6.split_once(']').ok_or_else(|| {
            PushError::InvalidUrl(format!("« {url} » — crochet fermant manquant"))
        })?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| bad_port(p))?,
            None if after.is_empty() => 443,
            None => return Err(PushError::InvalidUrl(format!("« {url} »"))),
        };
        (inside.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().map_err(|_| bad_port(p))?)
    } else {
        (authority.to_string(), 443)
    };
    if host.is_empty() {
        return Err(PushError::InvalidUrl(format!("« {url} » — hôte vide")));
    }
    Ok((host, port, format!("{base_path}{PUSH_PATH}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use constat_model::{Fact, Snapshot, Timestamp};
    use constat_store::{append_signed, MemoryStore, Signer};
    use std::collections::BTreeMap;

    #[test]
    fn url_https_simple() {
        let (host, port, path) = parse_server_url("https://constat.interne").unwrap();
        assert_eq!(
            (host.as_str(), port, path.as_str()),
            ("constat.interne", 443, "/v1/pousse")
        );
    }

    #[test]
    fn url_avec_port_et_prefixe() {
        let (host, port, path) =
            parse_server_url("https://constat.interne:8443/collecte/").unwrap();
        assert_eq!(
            (host.as_str(), port, path.as_str()),
            ("constat.interne", 8443, "/collecte/v1/pousse")
        );
    }

    #[test]
    fn url_ipv6() {
        let (host, port, path) = parse_server_url("https://[::1]:9000").unwrap();
        assert_eq!(
            (host.as_str(), port, path.as_str()),
            ("::1", 9000, "/v1/pousse")
        );
    }

    /// Pas de repli en clair, jamais : http:// est refusé avant toute connexion.
    #[test]
    fn url_http_refusee() {
        assert!(matches!(
            parse_server_url("http://constat.interne").unwrap_err(),
            PushError::InvalidUrl(_)
        ));
        assert!(matches!(
            parse_server_url("https://").unwrap_err(),
            PushError::InvalidUrl(_)
        ));
    }

    #[test]
    fn statut_http_analyse() {
        assert_eq!(parse_status_line(b"HTTP/1.1 200 OK\r\n...").unwrap(), 200);
        assert_eq!(
            parse_status_line(b"HTTP/1.1 422 Unprocessable Content\r\n").unwrap(),
            422
        );
        assert!(parse_status_line(b"SSH-2.0-OpenSSH\r\n").is_err());
        assert!(parse_status_line(b"").is_err());
    }

    /// Le lot contient tout ce qui est atteignable depuis le journal,
    /// dédoublonné, dans l'ordre blobs → snapshots → entrées.
    #[test]
    fn lot_construit_depuis_le_magasin() {
        let mut store = MemoryStore::new();
        let signer = Signer::generate();

        let blob = constat_model::Blob::new(
            "linux.sshd",
            b"PermitRootLogin no\n".to_vec(),
            vec![Fact::new("service:sshd", "sshd.PermitRootLogin", "no")],
        );
        let blob_hash = store.put_blob(&blob).unwrap();
        let mut blobs = BTreeMap::new();
        blobs.insert("linux.sshd".into(), blob_hash);
        let snapshot = Snapshot::new("srv-01", Timestamp(1_000), blobs);
        let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
        append_signed(&mut store, &signer, vec![snapshot_hash], Timestamp(1_000)).unwrap();
        // Deuxième collecte : même contenu → même snapshot, dédoublonné.
        append_signed(&mut store, &signer, vec![snapshot_hash], Timestamp(2_000)).unwrap();

        let batch =
            build_batch(&store, signer.verifying_key().to_bytes(), "srv-01".into()).unwrap();
        assert_eq!(batch.blobs.len(), 1);
        assert_eq!(batch.snapshots.len(), 1);
        assert_eq!(batch.entries.len(), 2);
        assert!(!batch.is_empty());
    }

    #[test]
    fn lot_vide_sur_magasin_vide() {
        let store = MemoryStore::new();
        let batch = build_batch(&store, [0; 32], "srv-01".into()).unwrap();
        assert!(batch.is_empty());
    }
}
