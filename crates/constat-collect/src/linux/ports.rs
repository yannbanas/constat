//! Collecteur `linux.ports` : ports en écoute — **priorité haute (§7.3)**,
//! c'est la matière première de la segmentation : « qu'est-ce qui écoute,
//! sur quelle adresse, sous quel uid, et depuis quand ? ».
//!
//! ## Sources
//!
//! `/proc/net/tcp`, `/proc/net/tcp6` et `/proc/net/udp` : le format hexadécimal
//! du noyau, du texte pur, lisible sans privilège et sans exécuter de commande.
//! Les trois fichiers sont regroupés en une capture unique par sections
//! (voir [`crate::capture`]).
//!
//! Format d'une ligne noyau (colonnes séparées par des espaces) :
//!
//! ```text
//!   sl  local_address rem_address   st ... uid ...
//!    0: 0100007F:0CEA 00000000:0000 0A ... 102 ...
//! ```
//!
//! - `local_address` : adresse IP en hexadécimal **petit-boutiste par mot de
//!   32 bits** (convention du noyau), deux-points, port en hexadécimal
//!   gros-boutiste (`0016` = 22) ;
//! - `st` : état de la socket en hexadécimal (`0A` = LISTEN pour TCP,
//!   `07` = non connectée pour UDP, c'est-à-dire liée en écoute) ;
//! - `uid` : uid du propriétaire, en décimal.
//!
//! Seules les sockets **en écoute** sont remontées ; les connexions établies
//! (adresses de pairs) ne sortent pas de la machine.
//!
//! ## Faits produits (entité `port:tcp/<n>` ou `port:udp/<n>`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `port.listening` | `Bool` — toujours `true` (seules les écoutes sont remontées) |
//! | `port.bind_address` | `Text` — adresse normalisée (`0.0.0.0`, `127.0.0.1`, `::`, …) ; `List` si le port est lié sur plusieurs adresses |
//! | `port.uid` | `Int` — uid propriétaire ; `List` si plusieurs uids distincts |
//!
//! Aucun secret ici, mais des entrées HOSTILES : lignes tronquées, hexadécimal
//! invalide, colonnes manquantes — tout est ignoré ligne à ligne, jamais de
//! panique.
//!
//! ## Collecte réelle (`#[cfg(unix)]`)
//!
//! Lit `/proc/net/tcp`, `/proc/net/tcp6` et `/proc/net/udp` ; un fichier
//! absent (IPv6 désactivé, par exemple) est toléré, la capture est partielle.

use crate::{capture, redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Noms de sections dans la capture combinée.
pub const SECTION_TCP: &str = "/proc/net/tcp";
/// Voir [`SECTION_TCP`].
pub const SECTION_TCP6: &str = "/proc/net/tcp6";
/// Voir [`SECTION_TCP`].
pub const SECTION_UDP: &str = "/proc/net/udp";

/// État TCP « LISTEN » dans `/proc/net/tcp` (`TCP_LISTEN`).
const TCP_STATE_LISTEN: u8 = 0x0A;
/// État « non connectée » d'une socket UDP (`TCP_CLOSE` réutilisé par UDP) :
/// une socket UDP liée et non connectée est en écoute.
const UDP_STATE_UNCONNECTED: u8 = 0x07;

/// Normalise une adresse hexadécimale du noyau (8 caractères = IPv4,
/// 32 caractères = IPv6, petit-boutiste par mot de 32 bits) en texte
/// (`127.0.0.1`, `::1`, …). `None` si le champ n'est pas une adresse valide.
pub fn normalize_kernel_hex_address(hex: &str) -> Option<String> {
    match hex.len() {
        8 => {
            let word = u32::from_str_radix(hex, 16).ok()?;
            Some(Ipv4Addr::from(word.to_le_bytes()).to_string())
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_exact_mut(4).enumerate() {
                let group = hex.get(i * 8..i * 8 + 8)?;
                let word = u32::from_str_radix(group, 16).ok()?;
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            Some(Ipv6Addr::from(bytes).to_string())
        }
        _ => None,
    }
}

/// Une socket en écoute, extraite d'une ligne de `/proc/net/*`.
struct ListeningSocket {
    port: u16,
    address: String,
    uid: i64,
}

/// Parse une ligne de `/proc/net/tcp{,6}` ou `/proc/net/udp`. Retourne la
/// socket si — et seulement si — elle est en écoute (`listen_state`).
/// Ligne d'en-tête, tronquée ou invalide : `None`, jamais de panique.
fn parse_socket_line(line: &str, listen_state: u8) -> Option<ListeningSocket> {
    let mut words = line.split_whitespace();
    let sl = words.next()?;
    if !sl.ends_with(':') {
        return None; // en-tête (« sl ») ou ligne étrangère
    }
    let local = words.next()?;
    let _remote = words.next()?;
    let state = u8::from_str_radix(words.next()?, 16).ok()?;
    if state != listen_state {
        return None;
    }
    // colonnes suivantes : tx/rx, tr/tm->when, retrnsmt, puis uid (décimal)
    let (_queues, _timer, _retrnsmt) = (words.next()?, words.next()?, words.next()?);
    let uid = words.next()?.parse::<i64>().ok()?;
    let (addr_hex, port_hex) = local.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if port == 0 {
        return None; // port 0 : socket non liée, pas une écoute réelle
    }
    Some(ListeningSocket {
        port,
        address: normalize_kernel_hex_address(addr_hex)?,
        uid,
    })
}

/// Réduit un ensemble à une valeur : scalaire si unique, liste triée sinon.
fn set_to_value<T: Ord>(set: BTreeSet<T>, to_value: fn(T) -> Value) -> Value {
    let mut values: Vec<Value> = set.into_iter().map(to_value).collect();
    match values.len() {
        0 => Value::Absent,
        1 => values.remove(0),
        _ => Value::List(values),
    }
}

/// Agrégat par port en écoute : adresses de liaison et uids observés.
type BindingsByPort = BTreeMap<(&'static str, u16), (BTreeSet<String>, BTreeSet<i64>)>;

/// Extracteur pur : contenus (déjà expurgés) de `/proc/net/tcp`,
/// `/proc/net/tcp6` et `/proc/net/udp` → faits. Les lignes hostiles
/// (tronquées, hexadécimal invalide) sont ignorées, jamais de panique.
pub fn extract_ports_facts(tcp: &str, tcp6: &str, udp: &str) -> Vec<Fact> {
    // (protocole, port) → (adresses de liaison, uids)
    let mut listening: BindingsByPort = BTreeMap::new();
    let inputs: [(&str, &'static str, u8); 3] = [
        (tcp, "tcp", TCP_STATE_LISTEN),
        (tcp6, "tcp", TCP_STATE_LISTEN),
        (udp, "udp", UDP_STATE_UNCONNECTED),
    ];
    for (text, proto, listen_state) in inputs {
        for line in text.split('\n') {
            let Some(socket) = parse_socket_line(line, listen_state) else {
                continue;
            };
            let entry = listening.entry((proto, socket.port)).or_default();
            entry.0.insert(socket.address);
            entry.1.insert(socket.uid);
        }
    }

    let mut facts: Vec<Fact> = Vec::new();
    for ((proto, port), (addresses, uids)) in listening {
        let entity = EntityId(format!("port:{proto}/{port}"));
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("port.listening".to_string()),
            value: Value::Bool(true),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("port.bind_address".to_string()),
            value: set_to_value(addresses, Value::Text),
        });
        facts.push(Fact {
            entity,
            attribute: Attribute("port.uid".to_string()),
            value: set_to_value(uids, Value::Int),
        });
    }
    facts.sort();
    facts
}

/// Collecteur `linux.ports`.
#[derive(Debug, Clone)]
pub struct PortsCollector {
    /// Racine des fichiers systèmes (paramétrable pour les tests ; `/` en production).
    pub root: std::path::PathBuf,
}

impl Default for PortsCollector {
    fn default() -> Self {
        Self {
            root: std::path::PathBuf::from("/"),
        }
    }
}

impl Collector for PortsCollector {
    fn id(&self) -> CollectorId {
        CollectorId("linux.ports".to_string())
    }

    /// Lit `/proc/net/tcp`, `/proc/net/tcp6` et `/proc/net/udp`. Un fichier
    /// illisible est toléré (capture partielle) ; l'échec n'est total que si
    /// aucun des trois n'est lisible.
    #[cfg(unix)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let mut sections: Vec<(&str, String)> = Vec::new();
        for name in [SECTION_TCP, SECTION_TCP6, SECTION_UDP] {
            let path = self.root.join(name.trim_start_matches('/'));
            if let Ok(content) = std::fs::read_to_string(&path) {
                sections.push((name, content));
            }
        }
        if sections.is_empty() {
            return Err(CollectError::Unavailable(
                "linux.ports : aucun fichier /proc/net/{tcp,tcp6,udp} lisible".to_string(),
            ));
        }
        let borrowed: Vec<(&str, &str)> = sections.iter().map(|(n, c)| (*n, c.as_str())).collect();
        Ok(RawCapture(capture::join_sections(&borrowed).into_bytes()))
    }

    #[cfg(not(unix))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "linux.ports : collecteur Linux, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        let sections = capture::split_sections(&text);
        let tcp = capture::find_section(&sections, SECTION_TCP).unwrap_or("");
        let tcp6 = capture::find_section(&sections, SECTION_TCP6).unwrap_or("");
        let udp = capture::find_section(&sections, SECTION_UDP).unwrap_or("");
        Ok(extract_ports_facts(tcp, tcp6, udp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
        \x20  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21001 1 0000000000000000 100 0 0 10 0\n\
        \x20  1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   102        0 21002 1 0000000000000000 100 0 0 10 0\n\
        \x20  2: AC10000A:0016 AC10000B:D2F4 01 00000000:00000000 00:00000000 00000000     0        0 21003 1 0000000000000000 20 4 30 10 -1\n";

    fn value<'a>(facts: &'a [Fact], entity: &str, attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.entity.0 == entity && f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {entity} {attr}"))
            .value
    }

    #[test]
    fn adresses_hexadecimales_normalisees() {
        assert_eq!(
            normalize_kernel_hex_address("0100007F").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            normalize_kernel_hex_address("00000000").as_deref(),
            Some("0.0.0.0")
        );
        assert_eq!(
            normalize_kernel_hex_address("00000000000000000000000001000000").as_deref(),
            Some("::1")
        );
        assert_eq!(
            normalize_kernel_hex_address("00000000000000000000000000000000").as_deref(),
            Some("::")
        );
        assert_eq!(normalize_kernel_hex_address("xyz"), None);
        assert_eq!(normalize_kernel_hex_address("0100007G"), None);
    }

    #[test]
    fn seules_les_ecoutes_sont_remontees() {
        let facts = extract_ports_facts(TCP, "", "");
        assert_eq!(
            value(&facts, "port:tcp/22", "port.listening"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "port:tcp/22", "port.bind_address"),
            &Value::Text("0.0.0.0".to_string())
        );
        assert_eq!(value(&facts, "port:tcp/22", "port.uid"), &Value::Int(0));
        assert_eq!(
            value(&facts, "port:tcp/3306", "port.bind_address"),
            &Value::Text("127.0.0.1".to_string())
        );
        assert_eq!(value(&facts, "port:tcp/3306", "port.uid"), &Value::Int(102));
        // la connexion ÉTABLIE (état 01) ne produit aucun fait : l'adresse du
        // pair ne sort jamais de la machine
        assert!(!facts.iter().any(|f| format!("{f:?}").contains("172.16.")));
    }

    #[test]
    fn tcp4_et_tcp6_agreges_sur_la_meme_entite() {
        let tcp6 = "  sl  local_address                         rem_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
            \x20  0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21004 1\n";
        let facts = extract_ports_facts(TCP, tcp6, "");
        assert_eq!(
            value(&facts, "port:tcp/22", "port.bind_address"),
            &Value::List(vec![
                Value::Text("0.0.0.0".to_string()),
                Value::Text("::".to_string())
            ])
        );
    }

    #[test]
    fn udp_non_connectee_est_une_ecoute() {
        let udp = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
            \x20 100: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 21005 2 0000000000000000 0\n";
        let facts = extract_ports_facts("", "", udp);
        assert_eq!(
            value(&facts, "port:udp/68", "port.listening"),
            &Value::Bool(true)
        );
        assert_eq!(value(&facts, "port:udp/68", "port.uid"), &Value::Int(101));
    }

    #[test]
    fn lignes_hostiles_ignorees_sans_panique() {
        let hostile = "   0: 0100007F\n\
                       \x20  1: ZZZZZZZZ:0016 00000000:0000 0A 0:0 0:0 0 0 0 1\n\
                       \x20  2: 0100007F:GGGG 00000000:0000 0A 0:0 0:0 0 0 0 1\n\
                       \x20  3: 0100007F:0016 00000000:0000 ZZ 0:0 0:0 0 0 0 1\n\
                       \x20  4: 0100007F:0000 00000000:0000 0A 0:0 0:0 0 0 0 1\n\
                       n'importe quoi \u{0}\n";
        assert!(extract_ports_facts(hostile, hostile, hostile).is_empty());
    }
}
