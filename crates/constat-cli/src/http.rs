//! Mini-client HTTP/1.1 synchrone sur `std::net::TcpStream`.
//!
//! Juste ce qu'il faut pour POSTer une requête d'horodatage RFC 3161 à un
//! prestataire (`Content-Type: application/timestamp-query` →
//! `application/timestamp-reply`), sans embarquer un client HTTP complet ni
//! un exécuteur asynchrone.
//!
//! Périmètre assumé, documenté :
//! - **`http://` uniquement** — pour `https://`, l'erreur est honnête
//!   (« non pris en charge pour l'instant ») plutôt qu'un TLS approximatif ;
//! - corps de réponse : `Content-Length`, `Transfer-Encoding: chunked`, ou
//!   lecture jusqu'à la fermeture (la requête demande `Connection: close`) ;
//! - aucune redirection suivie, aucun proxy.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use miette::miette;

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

/// Décompose `http://hôte[:port][/chemin]` en (hôte, port, chemin, en-tête Host).
fn split_url(url: &str) -> miette::Result<(String, u16, String, String)> {
    if url.starts_with("https://") {
        return Err(miette!(
            help = "écrivez la requête avec --out puis envoyez-la avec un outil TLS \
                    (curl -H 'Content-Type: application/timestamp-query' --data-binary @requete.tsq <url>), \
                    ou utilisez un prestataire accessible en http://",
            "https:// n'est pas pris en charge pour l'instant par le client d'horodatage intégré"
        ));
    }
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| miette!("URL invalide (http://… attendu) : {url}"))?;
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
            None => (host, Some(80)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok()),
            None => (authority, Some(80)),
        }
    };
    let port = port.ok_or_else(|| miette!("port invalide dans l'URL : {url}"))?;
    Ok((
        host.to_string(),
        port,
        path.to_string(),
        authority.to_string(),
    ))
}

/// POST synchrone. Renvoie la réponse complète, corps décodé.
pub fn post(url: &str, content_type: &str, accept: &str, body: &[u8]) -> miette::Result<Response> {
    let (host, port, path, host_header) = split_url(url)?;

    let addrs: Vec<_> = (host.as_str(), port)
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
    let mut stream =
        stream.ok_or_else(|| miette!("connexion à {host}:{port} impossible : {last_err}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|e| miette!("configuration du délai réseau impossible : {e}"))?;

    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: {content_type}\r\n\
         Accept: {accept}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|e| miette!("envoi de la requête à {host}:{port} impossible : {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| miette!("lecture de la réponse de {host}:{port} impossible : {e}"))?;
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

    #[test]
    fn decoupage_d_url() {
        let (h, p, path, hh) = split_url("http://tsa.exemple.fr/tsr").unwrap();
        assert_eq!(
            (h.as_str(), p, path.as_str(), hh.as_str()),
            ("tsa.exemple.fr", 80, "/tsr", "tsa.exemple.fr")
        );
        let (h, p, path, hh) = split_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(
            (h.as_str(), p, path.as_str(), hh.as_str()),
            ("127.0.0.1", 8080, "/", "127.0.0.1:8080")
        );
        assert!(split_url("ftp://ailleurs").is_err());
        let e = split_url("https://tsa.exemple.fr/tsr").unwrap_err();
        assert!(e.to_string().contains("pas pris en charge"));
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
}
