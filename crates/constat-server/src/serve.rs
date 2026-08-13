//! L'écouteur mTLS : rustls synchrone sur `std::net::TcpListener`, un thread
//! par connexion — pas de runtime async, pas de bibliothèque HTTP.
//!
//! # Propriété d'architecture (§17) : aucun chemin de retour
//!
//! Ce module n'appelle jamais `connect` : le serveur écoute, accepte, répond,
//! et c'est tout. La seule réponse possible est l'accusé de réception
//! ([`crate::receive::Receipt`]) ou un statut d'erreur HTTP — jamais une
//! instruction, une configuration ou du code.
//!
//! # mTLS obligatoire
//!
//! Le certificat client est **exigé** et vérifié contre l'autorité
//! `--client-ca` ([`rustls::server::WebPkiClientVerifier`], sans mode
//! optionnel) : une connexion sans certificat valide échoue à la poignée de
//! main, avant qu'un seul octet applicatif ne soit lu.
//!
//! # HTTP/1.1 minimal et strict
//!
//! Une seule requête est servie par connexion : `POST /v1/pousse` avec
//! `Content-Length` obligatoire et borné ([`MAX_BODY_BYTES`]). Tout le reste
//! est refusé : mauvais chemin → `404`, mauvaise méthode → `405`, longueur
//! absente → `411`, taille délirante → `413`, en-tête malformé → `400`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use constat_model::{from_canonical_bytes, to_canonical_bytes};
use constat_store::MultiJournalStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;

use crate::receive::{AgentPolicy, PushBatch, ReceiveError, Receiver, StoreReceiver};

/// Chemin HTTP de la poussée — miroir exact de `constat-agent`.
pub const PUSH_PATH: &str = "/v1/pousse";

/// Taille maximale du corps d'une poussée (64 Mio). Au-delà, `413` : un
/// `Content-Length` délirant ne doit jamais provoquer d'allocation.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Taille maximale de la tête HTTP (ligne de requête + en-têtes).
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Délai maximal de lecture/écriture par connexion : un client muet ne
/// retient pas un thread indéfiniment.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Le magasin partagé entre les threads de connexion. Multi-agents : le
/// receveur range chaque poussée dans le journal nommé de la clé de l'agent
/// ([`constat_store::MultiJournalStore`]).
pub type SharedStore = Arc<Mutex<dyn MultiJournalStore + Send>>;

/// Erreurs de démarrage et de configuration de l'écouteur.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum ServeError {
    /// Un fichier PEM (certificat, clé, autorité) est absent ou illisible.
    #[error("fichier PEM illisible ({path}) : {detail}")]
    #[diagnostic(help(
        "le serveur refuse de démarrer sans mTLS complet : certificat \
         (--cert), clé privée (--key) et autorité des agents (--client-ca)"
    ))]
    Pem { path: String, detail: String },

    /// La configuration TLS est incohérente (certificat/clé dépareillés…).
    #[error("configuration TLS invalide : {0}")]
    Tls(#[from] rustls::Error),

    /// L'autorité des agents ne permet pas de construire le vérificateur.
    #[error("vérificateur de certificats clients inutilisable : {0}")]
    #[diagnostic(help(
        "--client-ca doit contenir au moins un certificat d'autorité valide ; \
         tout agent sans certificat signé par cette autorité sera refusé"
    ))]
    Verifier(String),

    /// L'adresse d'écoute n'a pas pu être liée.
    #[error("impossible d'écouter : {0}")]
    Io(#[from] std::io::Error),
}

/// Charge la configuration TLS du serveur : certificat + clé, et
/// vérification **obligatoire** du certificat client contre `client_ca`.
///
/// Le fournisseur cryptographique (`ring`) est fixé explicitement : le
/// comportement ne dépend pas des features activées ailleurs dans l'arbre.
pub fn load_tls(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
) -> Result<Arc<rustls::ServerConfig>, ServeError> {
    let mut roots = RootCertStore::empty();
    for ca in read_certs(client_ca)? {
        roots.add(ca)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| ServeError::Verifier(e.to_string()))?;

    let certs = read_certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| pem_error(key, e))?;
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

/// Lit tous les certificats d'un fichier PEM ; au moins un est exigé.
fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ServeError> {
    let iter = CertificateDer::pem_file_iter(path).map_err(|e| pem_error(path, e))?;
    let certs = iter
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pem_error(path, e))?;
    if certs.is_empty() {
        return Err(ServeError::Pem {
            path: path.display().to_string(),
            detail: "aucun certificat dans le fichier".into(),
        });
    }
    Ok(certs)
}

fn pem_error(path: &Path, e: rustls::pki_types::pem::Error) -> ServeError {
    ServeError::Pem {
        path: path.display().to_string(),
        detail: e.to_string(),
    }
}

/// L'écouteur lié, prêt à servir.
pub struct Server {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    store: SharedStore,
    /// Politique d'autorisation des clés d'agents ([`AgentPolicy::Tofu`]
    /// par défaut ; allowlist via [`Server::with_policy`]).
    policy: Arc<AgentPolicy>,
}

impl Server {
    /// Lie l'adresse d'écoute. `127.0.0.1:0` est accepté (port libre choisi
    /// par le système — utile aux tests, [`Server::local_addr`] le révèle).
    ///
    /// La politique d'autorisation par défaut est [`AgentPolicy::Tofu`]
    /// (premier-arrivé-enregistré) — voir [`Server::with_policy`] pour une
    /// allowlist.
    pub fn bind(
        addr: &str,
        tls: Arc<rustls::ServerConfig>,
        store: SharedStore,
    ) -> Result<Self, ServeError> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self {
            listener,
            tls,
            store,
            policy: Arc::new(AgentPolicy::Tofu),
        })
    }

    /// Remplace la politique d'autorisation des clés d'agents — typiquement
    /// une [`AgentPolicy::Allowlist`] chargée depuis `--allowed-agents` :
    /// clé absente = `403`, refusé avant toute écriture.
    #[must_use]
    pub fn with_policy(mut self, policy: AgentPolicy) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    /// L'adresse effectivement liée.
    pub fn local_addr(&self) -> Result<SocketAddr, ServeError> {
        Ok(self.listener.local_addr()?)
    }

    /// Sert indéfiniment : un thread `std::thread` par connexion, aucun
    /// runtime. Une connexion en erreur est journalisée et n'affecte pas
    /// les autres.
    pub fn run(self) -> ! {
        loop {
            match self.listener.accept() {
                Ok((sock, _peer)) => {
                    let tls = Arc::clone(&self.tls);
                    let store = Arc::clone(&self.store);
                    let policy = Arc::clone(&self.policy);
                    std::thread::spawn(move || handle_connection(sock, tls, &store, &policy));
                }
                Err(e) => eprintln!("constat-server : connexion non acceptée : {e}"),
            }
        }
    }
}

/// Sert une connexion : poignée de main mTLS (implicite à la première
/// lecture), une requête, une réponse, fermeture.
fn handle_connection(
    sock: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    store: &SharedStore,
    policy: &AgentPolicy,
) {
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
    let conn = match rustls::ServerConnection::new(tls) {
        Ok(conn) => conn,
        Err(_) => return,
    };
    let mut stream = rustls::StreamOwned::new(conn, sock);

    let response = match read_request(&mut stream) {
        Ok(body) => process(&body, store, policy),
        // Poignée de main refusée (pas de certificat client valide) ou
        // coupure : rien à répondre, on raccroche.
        Err(None) => {
            let _ = stream.sock.shutdown(std::net::Shutdown::Both);
            return;
        }
        Err(Some(response)) => response,
    };

    if stream.write_all(&response).is_ok() {
        stream.conn.send_close_notify();
        let _ = stream.flush();
    }
    let _ = stream.sock.shutdown(std::net::Shutdown::Both);
}

/// Lit et valide strictement la requête ; renvoie le corps.
///
/// `Err(Some(réponse))` : requête refusée, réponse HTTP prête à écrire.
/// `Err(None)` : liaison inutilisable (mTLS refusé, coupure), raccrocher.
fn read_request<S: Read>(stream: &mut S) -> Result<Vec<u8>, Option<Vec<u8>>> {
    // --- Tête HTTP : jusqu'à CRLF CRLF, bornée. ---
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(Some(text_response(
                431,
                "Request Header Fields Too Large",
                "tête HTTP trop volumineuse",
            )));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(None),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(None),
        }
    };

    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| Some(text_response(400, "Bad Request", "tête HTTP non UTF-8")))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(Some(text_response(
            400,
            "Bad Request",
            "ligne de requête malformée",
        )));
    }

    // Chemin et méthode exacts, rien d'autre n'existe sur ce serveur.
    let path = target.split(['?', '#']).next().unwrap_or_default();
    if path != PUSH_PATH {
        return Err(Some(text_response(404, "Not Found", "chemin inconnu")));
    }
    if method != "POST" {
        return Err(Some(text_response(
            405,
            "Method Not Allowed",
            "seule la méthode POST est acceptée",
        )));
    }

    // Content-Length obligatoire et borné : refuser les tailles délirantes
    // AVANT toute allocation proportionnelle.
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
                if content_length.is_none() {
                    return Err(Some(text_response(
                        400,
                        "Bad Request",
                        "Content-Length illisible",
                    )));
                }
            }
        }
    }
    let expected = match content_length {
        Some(len) => len,
        None => {
            return Err(Some(text_response(
                411,
                "Length Required",
                "Content-Length obligatoire",
            )))
        }
    };
    if expected > MAX_BODY_BYTES {
        return Err(Some(text_response(
            413,
            "Content Too Large",
            "corps trop volumineux",
        )));
    }

    // --- Corps : exactement Content-Length octets, pas un de plus. ---
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < expected {
        let n = match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(Some(text_response(400, "Bad Request", "corps tronqué")));
            }
            Ok(n) => n,
            Err(_) => return Err(None),
        };
        body.extend_from_slice(&chunk[..n]);
    }
    if body.len() > expected {
        // Octets excédentaires : pas de pipelining sur ce serveur.
        return Err(Some(text_response(
            400,
            "Bad Request",
            "octets excédentaires après le corps",
        )));
    }
    Ok(body)
}

/// Décode le lot, le remet au [`StoreReceiver`], encode l'accusé.
fn process(body: &[u8], store: &SharedStore, policy: &AgentPolicy) -> Vec<u8> {
    let batch: PushBatch = match from_canonical_bytes(body) {
        Ok(batch) => batch,
        Err(e) => {
            return text_response(400, "Bad Request", &format!("CBOR invalide : {e}"));
        }
    };
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return text_response(
                500,
                "Internal Server Error",
                "magasin indisponible (verrou empoisonné)",
            );
        }
    };
    let mut receiver = StoreReceiver::with_policy(&mut *guard, policy.clone());
    match receiver.receive(batch) {
        // L'accusé : des compteurs et des empreintes, rien d'exécutable (§17).
        Ok(receipt) => match to_canonical_bytes(&receipt) {
            Ok(bytes) => response(200, "OK", "application/cbor", &bytes),
            Err(e) => text_response(
                500,
                "Internal Server Error",
                &format!("encodage de l'accusé : {e}"),
            ),
        },
        // Clé absente de l'allowlist : refus avant toute écriture.
        Err(e @ ReceiveError::Forbidden(_)) => text_response(403, "Forbidden", &e.to_string()),
        Err(ReceiveError::Store(e)) => {
            text_response(500, "Internal Server Error", &format!("magasin : {e}"))
        }
        // Lot invalide (empreinte, signature, chaîne) : la faute est au lot.
        Err(e) => text_response(422, "Unprocessable Content", &e.to_string()),
    }
}

/// Première occurrence de `needle` dans `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Assemble une réponse HTTP/1.1 complète.
fn response(status: u16, reason: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Réponse d'erreur en texte brut (diagnostic lisible côté agent — qui, par
/// contrat §7.1, n'interprète de toute façon que le statut).
fn text_response(status: u16, reason: &str, message: &str) -> Vec<u8> {
    response(
        status,
        reason,
        "text/plain; charset=utf-8",
        format!("{message}\n").as_bytes(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Lecteur de test : sert les octets donnés puis signale la fin.
    fn request_of(bytes: &[u8]) -> Result<Vec<u8>, Option<Vec<u8>>> {
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        read_request(&mut cursor)
    }

    fn status_of(response: &[u8]) -> u16 {
        let line = std::str::from_utf8(&response[..response.len().min(32)]).unwrap();
        line.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    #[test]
    fn requete_valide_acceptee() {
        let body =
            request_of(b"POST /v1/pousse HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd").unwrap();
        assert_eq!(body, b"abcd");
    }

    #[test]
    fn chemin_inconnu_404() {
        let err = request_of(b"POST /admin HTTP/1.1\r\nContent-Length: 0\r\n\r\n").unwrap_err();
        assert_eq!(status_of(&err.unwrap()), 404);
    }

    #[test]
    fn methode_interdite_405() {
        let err = request_of(b"GET /v1/pousse HTTP/1.1\r\n\r\n").unwrap_err();
        assert_eq!(status_of(&err.unwrap()), 405);
    }

    #[test]
    fn longueur_obligatoire_411() {
        let err = request_of(b"POST /v1/pousse HTTP/1.1\r\nHost: x\r\n\r\n").unwrap_err();
        assert_eq!(status_of(&err.unwrap()), 411);
    }

    /// Un Content-Length délirant est refusé AVANT toute allocation.
    #[test]
    fn taille_delirante_413() {
        let err = request_of(b"POST /v1/pousse HTTP/1.1\r\nContent-Length: 999999999999\r\n\r\n")
            .unwrap_err();
        assert_eq!(status_of(&err.unwrap()), 413);
    }

    #[test]
    fn corps_tronque_400() {
        let err =
            request_of(b"POST /v1/pousse HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc").unwrap_err();
        assert_eq!(status_of(&err.unwrap()), 400);
    }

    #[test]
    fn ligne_de_requete_malformee_400() {
        let err = request_of(b"n'importe quoi\r\n\r\n").unwrap_err();
        assert_eq!(status_of(&err.unwrap()), 400);
    }
}
