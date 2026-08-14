//! Mini-client HTTP/1.1 synchrone sur `std::net::TcpStream`, avec `https://`
//! via rustls (même profil que l'agent : synchrone, fournisseur `ring` fixé,
//! aucun exécuteur asynchrone).
//!
//! Juste ce qu'il faut pour POSTer une requête d'horodatage RFC 3161 à un
//! prestataire (`Content-Type: application/timestamp-query` →
//! `application/timestamp-reply`), sans embarquer un client HTTP complet.
//!
//! Périmètre assumé, documenté :
//! - `http://` **et** `https://` ; en TLS, le serveur est vérifié contre les
//!   racines Mozilla embarquées (`webpki-roots`) — les prestataires
//!   d'horodatage publics présentent des certificats publics, et le SNI est
//!   l'hôte de l'URL ;
//! - corps de réponse : `Content-Length`, `Transfer-Encoding: chunked`, ou
//!   lecture jusqu'à la fermeture (la requête demande `Connection: close`) ;
//! - aucune redirection suivie, aucun proxy.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use miette::miette;
use rustls::pki_types::ServerName;

/// Délai appliqué à la connexion, à la lecture et à l'écriture.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Réponse HTTP décodée a minima : statut, motif, corps.
#[derive(Debug)]
pub struct Response {
    /// Code de statut HTTP (200, 404, …).
    pub status: u16,
    /// Libellé du statut, tel que renvoyé par le serveur.
    pub reason: String,
    /// Corps de la réponse, dé-chunké si nécessaire.
    pub body: Vec<u8>,
}

/// Schéma de l'URL — décide du port par défaut et de la couche TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

/// Décompose `http(s)://hôte[:port][/chemin]` en
/// (schéma, hôte, port, chemin, en-tête Host).
fn split_url(url: &str) -> miette::Result<(Scheme, String, u16, String, String)> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else {
        return Err(miette!(
            "URL invalide (http://… ou https://… attendu) : {url}"
        ));
    };
    let default_port: u16 = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(miette!("URL sans hôte : {url}"));
    }
    // Hôte IPv6 entre crochets : `[::1]:8080`.
    let (host, port) = if let Some(end) = authority.strip_prefix('[').and_then(|a| a.find(']')) {
        let host = &authority[1..=end];
        match authority[end + 2..].strip_prefix(':') {
            Some(p) => (host, p.parse::<u16>().ok()),
            None => (host, Some(default_port)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok()),
            None => (authority, Some(default_port)),
        }
    };
    let port = port.ok_or_else(|| miette!("port invalide dans l'URL : {url}"))?;
    Ok((
        scheme,
        host.to_string(),
        port,
        path.to_string(),
        authority.to_string(),
    ))
}

/// Connexion TCP avec délais posés — commune aux deux schémas.
fn connect(host: &str, port: u16) -> miette::Result<TcpStream> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| miette!("résolution de {host} impossible : {e}"))?
        .collect();
    let mut stream: Option<TcpStream> = None;
    let mut last_err = String::from("aucune adresse résolue");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let stream =
        stream.ok_or_else(|| miette!("connexion à {host}:{port} impossible : {last_err}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|e| miette!("configuration du délai réseau impossible : {e}"))?;
    Ok(stream)
}

/// Racines de confiance par défaut : le magasin Mozilla embarqué.
fn webpki_root_store() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Configuration TLS cliente. Le fournisseur cryptographique (`ring`) est
/// fixé explicitement : le comportement ne dépend pas des features activées
/// ailleurs dans l'arbre.
fn tls_config(roots: rustls::RootCertStore) -> miette::Result<Arc<rustls::ClientConfig>> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| miette!("configuration TLS impossible : {e}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Écrit la requête, lit la réponse jusqu'à la fermeture. Une fin de flux
/// sans `close_notify` (fréquente chez les serveurs qui coupent après
/// `Connection: close`) n'est pas une erreur si des octets ont été reçus :
/// [`parse_response`] contrôle ensuite la complétude du corps.
fn exchange(
    stream: &mut (impl Read + Write),
    head: &str,
    body: &[u8],
    endpoint: &str,
) -> miette::Result<Vec<u8>> {
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|e| miette!("envoi de la requête à {endpoint} impossible : {e}"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => {
                return Err(miette!(
                    "lecture de la réponse de {endpoint} impossible : {e}"
                ))
            }
        }
    }
    Ok(raw)
}

/// POST synchrone. Renvoie la réponse complète, corps décodé. En `https://`,
/// le serveur est vérifié contre les racines Mozilla embarquées.
pub fn post(url: &str, content_type: &str, accept: &str, body: &[u8]) -> miette::Result<Response> {
    post_with_roots(url, content_type, accept, body, None)
}

/// Comme [`post`], avec des racines de confiance injectées — paramètre
/// interne, pour les tests contre un serveur TLS local ; l'API publique
/// ([`post`]) garde les racines `webpki-roots`.
fn post_with_roots(
    url: &str,
    content_type: &str,
    accept: &str,
    body: &[u8],
    roots: Option<rustls::RootCertStore>,
) -> miette::Result<Response> {
    let (scheme, host, port, path, host_header) = split_url(url)?;
    let mut stream = connect(&host, port)?;

    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: {content_type}\r\n\
         Accept: {accept}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );

    let raw = match scheme {
        Scheme::Http => exchange(&mut stream, &head, body, &format!("{host}:{port}"))?,
        Scheme::Https => {
            // SNI et vérification du certificat : l'hôte de l'URL, rien d'autre.
            let server_name = ServerName::try_from(host.clone())
                .map_err(|e| miette!("nom de serveur TLS invalide « {host} » : {e}"))?;
            let config = tls_config(roots.unwrap_or_else(webpki_root_store))?;
            let conn = rustls::ClientConnection::new(config, server_name)
                .map_err(|e| miette!("initialisation TLS pour {host} impossible : {e}"))?;
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let raw = exchange(&mut tls, &head, body, &format!("{host}:{port} (TLS)"))?;
            tls.conn.send_close_notify();
            let _ = tls.conn.complete_io(&mut tls.sock);
            raw
        }
    };
    parse_response(&raw)
}

/// Position d'une sous-séquence d'octets.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Décode une réponse HTTP/1.x brute (ligne de statut, en-têtes, corps).
fn parse_response(raw: &[u8]) -> miette::Result<Response> {
    let sep =
        find(raw, b"\r\n\r\n").ok_or_else(|| miette!("réponse HTTP tronquée (sans en-têtes)"))?;
    let head = std::str::from_utf8(&raw[..sep])
        .map_err(|_| miette!("en-têtes HTTP illisibles (octets non UTF-8)"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| miette!("réponse HTTP sans ligne de statut"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(miette!("réponse non HTTP/1.x : « {status_line} »"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| miette!("code de statut illisible : « {status_line} »"))?;
    let reason = parts.next().unwrap_or_default().to_string();

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse().ok();
        } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }

    let after = &raw[sep + 4..];
    let body = if chunked {
        decode_chunked(after)?
    } else if let Some(n) = content_length {
        if after.len() < n {
            return Err(miette!(
                "corps de réponse tronqué : {} octets reçus, {n} annoncés",
                after.len()
            ));
        }
        after[..n].to_vec()
    } else {
        // Connection: close — le corps court jusqu'à la fermeture.
        after.to_vec()
    };
    Ok(Response {
        status,
        reason,
        body,
    })
}

/// Décode un corps `Transfer-Encoding: chunked`.
fn decode_chunked(mut data: &[u8]) -> miette::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let pos = find(data, b"\r\n").ok_or_else(|| miette!("bloc chunked sans taille"))?;
        let size_line = std::str::from_utf8(&data[..pos])
            .map_err(|_| miette!("taille de bloc chunked illisible"))?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| miette!("taille de bloc chunked invalide : « {size_hex} »"))?;
        data = &data[pos + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 {
            return Err(miette!("bloc chunked tronqué"));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::TcpListener;

    #[test]
    fn decoupage_d_url() {
        let (s, h, p, path, hh) = split_url("http://tsa.exemple.fr/tsr").unwrap();
        assert_eq!(
            (s, h.as_str(), p, path.as_str(), hh.as_str()),
            (Scheme::Http, "tsa.exemple.fr", 80, "/tsr", "tsa.exemple.fr")
        );
        let (s, h, p, path, hh) = split_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(
            (s, h.as_str(), p, path.as_str(), hh.as_str()),
            (Scheme::Http, "127.0.0.1", 8080, "/", "127.0.0.1:8080")
        );
        // https : pris en charge, port 443 par défaut.
        let (s, h, p, path, hh) = split_url("https://tsa.exemple.fr/tsr").unwrap();
        assert_eq!(
            (s, h.as_str(), p, path.as_str(), hh.as_str()),
            (
                Scheme::Https,
                "tsa.exemple.fr",
                443,
                "/tsr",
                "tsa.exemple.fr"
            )
        );
        let (s, _, p, _, _) = split_url("https://[::1]:8443/tsa").unwrap();
        assert_eq!((s, p), (Scheme::Https, 8443));
        assert!(split_url("ftp://ailleurs").is_err());
    }

    #[test]
    fn analyse_de_reponse_content_length_et_chunked() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello!!").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
        assert_eq!(r.reason, "OK");

        let r = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nhell\r\n1\r\no\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.body, b"hello");

        // Sans longueur : jusqu'à la fermeture.
        let r = parse_response(b"HTTP/1.0 404 Introuvable\r\n\r\nrien").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (404, &b"rien"[..]));

        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ncourt").is_err());
        assert!(parse_response(b"pas du http").is_err());
    }

    /// Fabrique un serveur TLS local : certificat auto-signé pour
    /// `localhost`, une seule requête servie. Renvoie (URL, racine à
    /// injecter côté client, thread — qui rend le corps reçu).
    fn tls_server_once(
        reply: &'static [u8],
    ) -> (
        String,
        rustls::RootCertStore,
        std::thread::JoinHandle<Vec<u8>>,
    ) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("certificat de test");
        let cert_der: CertificateDer<'static> = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("racine de test");

        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocoles TLS")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .expect("configuration serveur");
        let config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!(
            "https://localhost:{}/tsa",
            listener.local_addr().expect("addr").port()
        );

        let handle = std::thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept");
            let conn = rustls::ServerConnection::new(config).expect("connexion serveur");
            let mut stream = rustls::StreamOwned::new(conn, sock);

            // Lit les en-têtes puis le corps (Content-Length).
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let (header_end, content_length) = loop {
                let n = stream.read(&mut tmp).expect("lecture requête");
                assert!(n > 0, "connexion fermée avant la fin des en-têtes");
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
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
                let n = stream.read(&mut tmp).expect("lecture corps");
                assert!(n > 0, "corps tronqué");
                buf.extend_from_slice(&tmp[..n]);
            }

            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            stream.write_all(head.as_bytes()).expect("écriture");
            stream.write_all(reply).expect("écriture");
            stream.flush().expect("flush");
            stream.conn.send_close_notify();
            let _ = stream.conn.complete_io(&mut stream.sock);
            buf[header_end..header_end + content_length].to_vec()
        });
        (url, roots, handle)
    }

    /// Bout-en-bout : POST https contre un serveur TLS local, racine
    /// injectée (le paramètre interne des tests), SNI `localhost`.
    #[test]
    fn post_https_bout_en_bout_avec_racine_injectee() {
        let (url, roots, server) = tls_server_once(b"reponse-tsa");
        let r = post_with_roots(
            &url,
            "application/timestamp-query",
            "application/timestamp-reply",
            b"requete-der",
            Some(roots),
        )
        .expect("POST https");
        assert_eq!((r.status, r.body.as_slice()), (200, &b"reponse-tsa"[..]));
        assert_eq!(
            server.join().expect("serveur de test"),
            b"requete-der",
            "le serveur a reçu exactement le corps envoyé"
        );
    }

    /// L'API publique garde les racines webpki-roots : un certificat
    /// auto-signé local est refusé — pas de TLS approximatif.
    #[test]
    fn post_https_refuse_un_certificat_hors_racines_publiques() {
        let (url, _roots, server) = tls_server_once(b"jamais-lu");
        let err = post(
            &url,
            "application/timestamp-query",
            "application/timestamp-reply",
            b"requete-der",
        )
        .expect_err("certificat inconnu des racines publiques");
        assert!(
            err.to_string().contains("impossible"),
            "erreur lisible : {err}"
        );
        // Le serveur, lui, voit la poignée de main échouer : son thread se
        // termine en erreur — on ne fait que le récolter.
        assert!(server.join().is_err());
    }
}
