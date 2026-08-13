//! # Expurgation (§7.2) — règle absolue : aucun secret ne quitte la machine.
//!
//! Ce module implémente une **liste de refus explicite et testée** :
//!
//! | Motif | Traitement |
//! |---|---|
//! | Blocs PEM `-----BEGIN … PRIVATE KEY-----` | bloc entier remplacé par `[EXPURGÉ:cle-privee]` |
//! | Hachages `crypt(3)` modulaires (`$6$…`, `$y$…`, `$2b$…`, …) | sel et empreinte remplacés, seul `$id$` (l'algorithme) est conservé |
//! | Valeurs de `password=` / `passwd:` / `secret=` / `token=` … | valeur remplacée par un marqueur typé |
//! | Longues chaînes base64 dans un contexte sensible | remplacées par `[EXPURGÉ:base64]` |
//! | Configurations réseau (FortiGate, Cisco IOS, XML) | motifs dédiés : voir [`redact_network_config`] |
//!
//! Le remplacement est un marqueur `[EXPURGÉ:<type>]`. Quand la *présence*
//! d'un secret doit rester prouvable sans révéler le secret, utiliser
//! [`fingerprint`] qui produit un [`Value::Fingerprint`] (empreinte BLAKE3).
//!
//! **Philosophie** : en cas de doute, sur-expurger. Perdre un octet de
//! configuration est un désagrément ; laisser fuir un secret est la faute
//! impardonnable (§12).
//!
//! **Limites documentées** : un secret sans aucune structure (par exemple un
//! hachage DES historique de 13 caractères hors de `/etc/shadow`, ou un mot de
//! passe nu au milieu d'un commentaire sans mot-clef) n'est pas détectable par
//! liste de refus générique. Les collecteurs qui manipulent des fichiers dont
//! la structure est connue (comme `/etc/shadow`) appliquent en plus une
//! expurgation structurelle exhaustive ([`redact_shadow_hash_field`]).

use constat_model::Value;

/// Marqueur : clé privée (PEM ou assimilé).
pub const MARKER_PRIVATE_KEY: &str = "[EXPURGÉ:cle-privee]";
/// Marqueur : hachage de mot de passe.
pub const MARKER_HASH: &str = "[EXPURGÉ:hachage]";
/// Marqueur : mot de passe en clair.
pub const MARKER_PASSWORD: &str = "[EXPURGÉ:mot-de-passe]";
/// Marqueur : secret générique (clé d'API, clé d'accès…).
pub const MARKER_SECRET: &str = "[EXPURGÉ:secret]";
/// Marqueur : jeton d'authentification.
pub const MARKER_TOKEN: &str = "[EXPURGÉ:jeton]";
/// Marqueur : chaîne base64 longue dans un contexte sensible.
pub const MARKER_BASE64: &str = "[EXPURGÉ:base64]";
/// Marqueur : communauté SNMP (équipements réseau).
pub const MARKER_SNMP_COMMUNITY: &str = "[EXPURGÉ:communauté-snmp]";
/// Marqueur : clé partagée (PSK IPsec, clé TACACS/RADIUS, `key-string`…).
pub const MARKER_SHARED_KEY: &str = "[EXPURGÉ:cle-partagee]";

/// Empreinte BLAKE3 d'un secret : la présence reste prouvable, jamais le contenu.
pub fn fingerprint(secret: &[u8]) -> Value {
    Value::Fingerprint(*blake3::hash(secret).as_bytes())
}

/// Découpe une ligne sur `:` en traitant les marqueurs `[EXPURGÉ:<type>]`
/// comme atomiques : le `:` du marqueur ne compte pas comme séparateur.
///
/// Indispensable pour les fichiers à champs séparés par `:` (`/etc/shadow`,
/// `/etc/passwd`) : l'expurgation y insère des marqueurs, et l'extraction
/// doit retrouver les champs d'origine. Ne panique jamais.
pub fn split_colon_fields(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut fields: Vec<&str> = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        // marqueur atomique ? (test uniquement sur borne de caractère)
        if bytes[i] == b'[' && line.get(i..).is_some_and(|s| s.starts_with("[EXPURG")) {
            if let Some(rest) = line.get(i..) {
                match rest.find(']') {
                    Some(off) => {
                        i += off + 1;
                        continue;
                    }
                    None => break, // marqueur jamais refermé : plus de séparateur
                }
            }
        }
        if bytes[i] == b':' {
            fields.push(&line[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    fields.push(line.get(start..).unwrap_or(""));
    fields
}

/// Expurge une capture brute (octets). L'entrée est HOSTILE : les octets
/// non-UTF-8 sont remplacés (décodage avec perte) — un artefact de
/// configuration est du texte ; ce qui n'en est pas n'a pas à sortir tel quel.
pub fn redact_bytes(raw: &[u8]) -> Vec<u8> {
    redact_text(&String::from_utf8_lossy(raw)).into_bytes()
}

/// Expurge un texte : applique toute la liste de refus, dans l'ordre
/// (blocs PEM multi-lignes, puis ligne à ligne : valeurs sensibles,
/// hachages `crypt(3)`, base64 en contexte sensible).
///
/// Ne panique jamais, quelle que soit l'entrée.
pub fn redact_text(text: &str) -> String {
    let without_pem = redact_pem_blocks(text);
    let mut out = String::with_capacity(without_pem.len());
    let mut first = true;
    for line in without_pem.split('\n') {
        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(&redact_line(line));
    }
    out
}

/// Expurge une seule ligne : valeurs de clefs sensibles, hachages, base64.
fn redact_line(line: &str) -> String {
    let line = redact_sensitive_kv(line);
    let line = redact_crypt_hashes(&line);
    redact_base64_in_sensitive_context(&line)
}

// ---------------------------------------------------------------------------
// Blocs PEM
// ---------------------------------------------------------------------------

fn is_pem_private_begin(line: &str) -> bool {
    line.contains("-----BEGIN") && line.contains("PRIVATE KEY")
}

fn is_pem_private_end(line: &str) -> bool {
    line.contains("-----END") && line.contains("PRIVATE KEY")
}

/// Remplace chaque bloc `-----BEGIN … PRIVATE KEY----- … -----END …-----`
/// (en-têtes compris) par une ligne [`MARKER_PRIVATE_KEY`]. Un bloc jamais
/// refermé est expurgé jusqu'à la fin du texte : mieux vaut trop que pas assez.
fn redact_pem_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_block = false;
    let mut first = true;
    for line in text.split('\n') {
        if in_block {
            if is_pem_private_end(line) {
                in_block = false;
            }
            continue; // la ligne appartient au bloc : supprimée
        }
        if is_pem_private_begin(line) {
            in_block = true;
            if !first {
                out.push('\n');
            }
            first = false;
            out.push_str(MARKER_PRIVATE_KEY);
            // si BEGIN et END sont sur la même ligne, le bloc est déjà clos
            if is_pem_private_end(line) {
                in_block = false;
            }
            continue;
        }
        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(line);
    }
    out
}

// ---------------------------------------------------------------------------
// Valeurs de clefs sensibles (password=, secret:, token=, …)
// ---------------------------------------------------------------------------

/// Suffixes d'identifiants considérés sensibles, avec le marqueur associé.
/// Correspondance par **suffixe** (insensible à la casse) pour attraper
/// `db_password`, `user-token`, `AWS_SECRET_ACCESS_KEY`… sans expurger à tort
/// `PasswordAuthentication` (qui ne se termine pas par un mot sensible).
const SENSITIVE_SUFFIXES: &[(&str, &str)] = &[
    ("password", MARKER_PASSWORD),
    ("passwd", MARKER_PASSWORD),
    ("pwd", MARKER_PASSWORD),
    ("passphrase", MARKER_PASSWORD),
    ("authtok", MARKER_TOKEN),
    ("token", MARKER_TOKEN),
    ("secret", MARKER_SECRET),
    ("apikey", MARKER_SECRET),
    ("api_key", MARKER_SECRET),
    ("access_key", MARKER_SECRET),
    ("secret_key", MARKER_SECRET),
    ("private_key", MARKER_SECRET),
    ("_key", MARKER_SECRET),
    ("credentials", MARKER_SECRET),
];

/// Si `ident` (déjà en minuscules) se termine par un suffixe sensible,
/// retourne le marqueur correspondant. Les identifiants exactement `key` ou
/// `pass` sont sensibles aussi (le suffixe seul serait trop large : `monkey`,
/// `bypass`… ne doivent pas déclencher).
fn sensitive_marker(ident: &str) -> Option<&'static str> {
    // exclusion : les étiquettes sudoers `NOPASSWD:`/`PASSWD:` précèdent une
    // COMMANDE, pas un secret — les expurger détruirait un fait d'audit
    if ident.ends_with("nopasswd") {
        return None;
    }
    if ident == "key" || ident == "pass" {
        return Some(MARKER_SECRET);
    }
    SENSITIVE_SUFFIXES
        .iter()
        .find(|(suffix, _)| ident.ends_with(suffix))
        .map(|(_, marker)| *marker)
}

/// Extrait l'identifiant qui précède immédiatement un délimiteur : on ignore
/// les espaces et guillemets de fin, puis on collecte les caractères
/// d'identifiant (alphanumériques, `_`, `-`, `.`). Retourné en minuscules.
fn trailing_identifier(before: &str) -> String {
    let trimmed = before.trim_end().trim_end_matches(['"', '\'']);
    let ident_start = trimmed
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .last()
        .map(|(i, _)| i);
    match ident_start {
        Some(i) => trimmed[i..].to_ascii_lowercase(),
        None => String::new(),
    }
}

/// Cherche `<identifiant sensible> = <valeur>` ou `<identifiant sensible>: <valeur>`
/// et remplace tout ce qui suit le délimiteur par le marqueur typé.
///
/// L'expurgation va jusqu'à la fin de la ligne : une valeur peut contenir des
/// espaces, des guillemets, d'autres délimiteurs — dans le doute, tout part.
fn redact_sensitive_kv(line: &str) -> String {
    for (i, b) in line.bytes().enumerate() {
        if b != b'=' && b != b':' {
            continue;
        }
        let ident = trailing_identifier(&line[..i]);
        if ident.is_empty() {
            continue;
        }
        if let Some(marker) = sensitive_marker(&ident) {
            let value = line[i + 1..].trim();
            if value.is_empty() {
                // rien à expurger, et « vide » est une information honnête
                return line.to_string();
            }
            return format!("{}{}", &line[..=i], marker);
        }
    }
    line.to_string()
}

// ---------------------------------------------------------------------------
// Hachages crypt(3) modulaires ($id$sel$empreinte)
// ---------------------------------------------------------------------------

fn is_crypt_body_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'/' || c == b'$' || c == b'=' || c == b','
}

/// Remplace toute séquence `$id$<sel+empreinte>` (format modulaire de
/// `crypt(3)` : `$1$`, `$5$`, `$6$`, `$2b$`, `$y$`, `$7$`, `$gy$`, …) par
/// `$id$[EXPURGÉ:hachage]`. L'identifiant d'algorithme est conservé : c'est
/// une donnée de conformité, pas un secret.
fn redact_crypt_hashes(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            // identifiant : 1 à 3 caractères alphanumériques puis '$'
            let id_start = i + 1;
            let mut id_end = id_start;
            while id_end < bytes.len()
                && id_end - id_start < 3
                && bytes[id_end].is_ascii_alphanumeric()
            {
                id_end += 1;
            }
            if id_end > id_start && id_end < bytes.len() && bytes[id_end] == b'$' {
                // corps : sel + empreinte
                let body_start = id_end + 1;
                let mut body_end = body_start;
                while body_end < bytes.len() && is_crypt_body_char(bytes[body_end]) {
                    body_end += 1;
                }
                if body_end - body_start >= 8 {
                    // c'est un hachage plausible : on garde $id$, on expurge le reste
                    out.push_str(&line[i..=id_end]);
                    out.push_str(MARKER_HASH);
                    i = body_end;
                    continue;
                }
            }
        }
        // avancer d'un caractère UTF-8 complet
        let ch_len = utf8_char_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        if let Some(s) = line.get(i..end) {
            out.push_str(s);
        }
        i = end;
    }
    out
}

/// Longueur d'un caractère UTF-8 d'après son premier octet (jamais 0).
fn utf8_char_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >= 0xF0 {
        4
    } else if first >= 0xE0 {
        3
    } else if first >= 0xC0 {
        2
    } else {
        1 // octet de continuation isolé : entrée hostile, on avance quand même
    }
}

// ---------------------------------------------------------------------------
// Base64 long en contexte sensible
// ---------------------------------------------------------------------------

/// Mots qui rendent une ligne « sensible » pour la règle base64.
const SENSITIVE_CONTEXT_WORDS: &[&str] = &[
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "auth",
    "credential",
    "cert",
    "private",
];

/// Longueur minimale d'une séquence base64 jugée suspecte.
const BASE64_MIN_LEN: usize = 40;

fn is_base64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' || c == b'-' || c == b'_'
}

/// Sur une ligne dont le contexte est sensible (elle contient `key`, `secret`,
/// `token`, …), remplace toute séquence base64 d'au moins [`BASE64_MIN_LEN`]
/// caractères par [`MARKER_BASE64`].
fn redact_base64_in_sensitive_context(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    if !SENSITIVE_CONTEXT_WORDS.iter().any(|w| lower.contains(w)) {
        return line.to_string();
    }
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if is_base64_char(bytes[i]) {
            let start = i;
            let mut end = i;
            while end < bytes.len() && is_base64_char(bytes[end]) {
                end += 1;
            }
            if end - start >= BASE64_MIN_LEN {
                out.push_str(MARKER_BASE64);
            } else if let Some(s) = line.get(start..end) {
                out.push_str(s);
            }
            i = end;
            continue;
        }
        let ch_len = utf8_char_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        if let Some(s) = line.get(i..end) {
            out.push_str(s);
        }
        i = end;
    }
    out
}

// ---------------------------------------------------------------------------
// Configurations d'équipements réseau (S7) — les configs regorgent de secrets
// ---------------------------------------------------------------------------
//
// Les formats d'équipements (FortiGate, Cisco IOS, XML OPNsense/pfSense…)
// n'utilisent ni `=` ni `:` pour leurs secrets : la liste de refus générique
// ne les voit pas. D'où cette passe dédiée, appliquée AVANT la générique.
// Principe inchangé : la STRUCTURE de la ligne survit (un auditeur voit
// qu'une clé était configurée), la valeur ne sort jamais.

/// Attributs FortiGate sensibles : `set <attr> <valeur>` (correspondance par
/// suffixe, insensible à la casse, pour attraper `admin-password`,
/// `login-passwd`…). La valeur entière est remplacée par le marqueur.
const FORTIGATE_SENSITIVE_SET_SUFFIXES: &[(&str, &str)] = &[
    ("passwd", MARKER_PASSWORD),
    ("password", MARKER_PASSWORD),
    ("passphrase", MARKER_PASSWORD),
    ("auth-pwd", MARKER_PASSWORD),
    ("psksecret", MARKER_SHARED_KEY),
    ("ppk-secret", MARKER_SHARED_KEY),
    ("private-key", MARKER_PRIVATE_KEY),
    ("secret", MARKER_SECRET),
];

/// `set <attr sensible> <valeur>` (FortiGate) → `set <attr> <marqueur>`.
/// `None` si la ligne n'est pas concernée (elle reste telle quelle).
fn redact_fortigate_set_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    let rest = trimmed.strip_prefix("set ")?;
    let (attr, value) = rest.split_once(char::is_whitespace)?;
    if value.trim().is_empty() {
        return None; // rien à expurger, « vide » est une information honnête
    }
    let attr_lower = attr.to_ascii_lowercase();
    let (_, marker) = FORTIGATE_SENSITIVE_SET_SUFFIXES
        .iter()
        .find(|(suffix, _)| attr_lower.ends_with(suffix))?;
    Some(format!("{indent}set {attr} {marker}"))
}

/// Longueur minimale d'un blob `ENC` jugé secret (les blobs FortiGate réels
/// font des centaines de caractères ; 8 suffit pour ne rien laisser passer).
const ENC_MIN_LEN: usize = 8;

/// Valeurs chiffrées FortiGate : tout jeton `ENC <base64>` voit son blob
/// remplacé par [`MARKER_BASE64`] (le mot-clef `ENC` reste : la présence
/// d'une valeur chiffrée est une donnée d'audit).
fn redact_fortigate_enc_values(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(pos) = rest.find("ENC ") {
        // borne de mot à gauche : ne pas déclencher sur `AGENCE ...`
        let at_word_start = pos == 0
            || rest[..pos]
                .chars()
                .next_back()
                .is_some_and(|c| !c.is_ascii_alphanumeric());
        let after = &rest[pos + 4..];
        let blob_len = after.bytes().take_while(|b| is_base64_char(*b)).count();
        if at_word_start && blob_len >= ENC_MIN_LEN {
            out.push_str(&rest[..pos + 4]);
            out.push_str(MARKER_BASE64);
            rest = &after[blob_len..];
        } else {
            out.push_str(&rest[..pos + 4]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Découpe une ligne en jetons (séparés par des blancs) avec leur position
/// d'octet de début — pour reconstruire la ligne en conservant l'espacement
/// d'origine à gauche du point d'expurgation.
fn tokens_with_positions(line: &str) -> Vec<(usize, &str)> {
    let mut tokens = Vec::new();
    let mut offset = 0;
    for token in line.split_whitespace() {
        // `find` à partir d'offset : les jetons apparaissent dans l'ordre
        if let Some(pos) = line[offset..].find(token) {
            let start = offset + pos;
            tokens.push((start, token));
            offset = start + token.len();
        }
    }
    tokens
}

/// Reconstruit `<début de ligne intact><marqueur>[ <suite conservée>]`.
fn splice_marker(line: &str, from: usize, marker: &str, kept_tail: Option<usize>) -> String {
    let mut out = String::with_capacity(line.len());
    out.push_str(line.get(..from).unwrap_or(""));
    out.push_str(marker);
    if let Some(tail) = kept_tail {
        if let Some(rest) = line.get(tail..) {
            out.push(' ');
            out.push_str(rest);
        }
    }
    out
}

/// Un jeton est-il un identifiant de chiffrage IOS (`0`, `4`, `5`, `6`, `7`,
/// `8`, `9`) ? Conservé, comme `$id$` des hachages : donnée de conformité.
fn is_ios_encoding_digit(token: &str) -> bool {
    matches!(token, "0" | "4" | "5" | "6" | "7" | "8" | "9")
}

/// Expurge une ligne Cisco IOS. Motifs couverts (voir les tests) :
/// `enable secret|password`, `username … secret|password`,
/// `snmp-server community`, clés `tacacs`/`radius`, `crypto isakmp key`,
/// `standby … authentication`, `key-string`, et les lignes `key …` isolées
/// des blocs `tacacs server`/`radius server` (un simple numéro de clé,
/// `key 1` d'une key chain, est conservé). `None` si la ligne n'est pas
/// concernée.
fn redact_cisco_line(line: &str) -> Option<String> {
    let tokens = tokens_with_positions(line);
    let lower: Vec<String> = tokens.iter().map(|(_, t)| t.to_ascii_lowercase()).collect();
    let word = |i: usize| lower.get(i).map(String::as_str);
    // position d'octet du jeton i (début), pour découper la ligne
    let start = |i: usize| tokens.get(i).map(|(p, _)| *p);

    // enable secret|password [level N] [chiffrage] <valeur>
    if word(0) == Some("enable") && matches!(word(1), Some("secret") | Some("password")) {
        let marker = if word(1) == Some("secret") {
            MARKER_HASH
        } else {
            MARKER_PASSWORD
        };
        let mut i = 2;
        if word(i) == Some("level") {
            i += 2; // `level` et son numéro sont conservés
        }
        if word(i).is_some_and(is_ios_encoding_digit) {
            i += 1;
        }
        if start(i).is_some() {
            return Some(splice_marker(line, start(i)?, marker, None));
        }
        return None;
    }

    // username <nom> … secret|password [chiffrage] <valeur>
    if word(0) == Some("username") {
        let kw =
            (1..lower.len()).find(|i| matches!(word(*i), Some("secret") | Some("password")))?;
        let marker = if word(kw) == Some("secret") {
            MARKER_HASH
        } else {
            MARKER_PASSWORD
        };
        let mut i = kw + 1;
        if word(i).is_some_and(is_ios_encoding_digit) {
            i += 1;
        }
        return Some(splice_marker(line, start(i)?, marker, None));
    }

    // snmp-server community <communauté> [RO|RW|vue|ACL…] : seule la
    // communauté part, le reste de la ligne survit (donnée d'audit)
    if word(0) == Some("snmp-server") && word(1) == Some("community") {
        let from = start(2)?;
        let tail = start(3);
        return Some(splice_marker(line, from, MARKER_SNMP_COMMUNITY, tail));
    }

    // crypto isakmp key [chiffrage] <clé> address|hostname <suite conservée>
    if word(0) == Some("crypto") && word(1) == Some("isakmp") && word(2) == Some("key") {
        let mut i = 3;
        if word(i).is_some_and(is_ios_encoding_digit) {
            i += 1;
        }
        let from = start(i)?;
        let tail = (i..lower.len())
            .find(|j| matches!(word(*j), Some("address") | Some("hostname")))
            .and_then(start);
        return Some(splice_marker(line, from, MARKER_SHARED_KEY, tail));
    }

    // standby|vrrp … authentication [md5|text|key-string] <valeur>
    if matches!(word(0), Some("standby") | Some("vrrp")) {
        let auth = (1..lower.len()).find(|i| word(*i) == Some("authentication"))?;
        let mut i = auth + 1;
        while matches!(word(i), Some("md5") | Some("text") | Some("key-string")) {
            i += 1;
        }
        if word(i).is_some_and(is_ios_encoding_digit) {
            i += 1;
        }
        return Some(splice_marker(line, start(i)?, MARKER_SHARED_KEY, None));
    }

    // key-string [chiffrage] <valeur> (key chains, RIP/EIGRP/OSPF)
    if word(0) == Some("key-string") {
        let mut i = 1;
        if word(i).is_some_and(is_ios_encoding_digit) {
            i += 1;
        }
        return Some(splice_marker(line, start(i)?, MARKER_SHARED_KEY, None));
    }

    // clés TACACS/RADIUS : `tacacs-server host … key [chiffrage] <valeur>`,
    // `radius-server key …`, ou ` key 7 <valeur>` isolée dans un bloc
    // `tacacs server`/`radius server`
    let mentions_aaa = lower
        .iter()
        .any(|t| t.contains("tacacs") || t.contains("radius"));
    if let Some(kw) = (0..lower.len()).find(|i| word(*i) == Some("key")) {
        let standalone = kw == 0;
        // `key chain <nom>` : une déclaration de chaîne, pas un secret
        // (le secret d'une key chain est sa ligne `key-string`, déjà couverte)
        if word(kw + 1) == Some("chain") {
            return None;
        }
        if mentions_aaa || standalone {
            let mut i = kw + 1;
            if word(i).is_some_and(is_ios_encoding_digit) && word(i + 1).is_some() {
                i += 1;
            }
            // `key 1` d'une key chain : un simple numéro n'est pas un secret
            let remaining: Vec<&str> = (i..lower.len()).filter_map(word).collect();
            let only_number =
                remaining.len() == 1 && remaining[0].bytes().all(|b| b.is_ascii_digit());
            if !remaining.is_empty() && !only_number {
                return Some(splice_marker(line, start(i)?, MARKER_SHARED_KEY, None));
            }
        }
    }

    None
}

/// Balises XML sensibles (OPNsense/pfSense…) : le contenu part, la balise
/// reste. Retourne le marqueur associé au nom de balise (minuscules, préfixe
/// d'espace de noms retiré), ou `None` si la balise n'est pas sensible.
fn xml_sensitive_marker(tag: &str) -> Option<&'static str> {
    let local = tag.rsplit(':').next().unwrap_or(tag).to_ascii_lowercase();
    match local.as_str() {
        "community" | "rocommunity" | "rwcommunity" => return Some(MARKER_SNMP_COMMUNITY),
        "psk" | "psksecret" | "pre-shared-key" | "preshared_key" => return Some(MARKER_SHARED_KEY),
        "authkey" | "privkey" | "authpass" | "privpass" => return Some(MARKER_SECRET),
        _ => {}
    }
    if local.ends_with("key") {
        return Some(MARKER_SECRET); // apikey, sharedkey, authentication_key…
    }
    // la logique générique par suffixe (password, secret, token, passphrase…)
    sensitive_marker(&local)
}

/// Nom de la première balise ouvrante `<tag …>` de la ligne, avec la
/// position d'octet juste après son `>`, hors balises fermantes,
/// auto-fermantes, commentaires et déclarations.
fn first_opening_tag(line: &str) -> Option<(String, usize)> {
    let mut search_from = 0;
    while let Some(rel) = line.get(search_from..)?.find('<') {
        let open = search_from + rel;
        let rest = line.get(open + 1..)?;
        if rest.starts_with(['/', '?', '!']) {
            search_from = open + 1;
            continue;
        }
        let close_rel = rest.find('>')?;
        let inner = &rest[..close_rel];
        if inner.ends_with('/') {
            search_from = open + 1 + close_rel + 1;
            continue; // auto-fermante : pas de contenu
        }
        let name: String = inner.chars().take_while(|c| !c.is_whitespace()).collect();
        if name.is_empty() {
            search_from = open + 1;
            continue;
        }
        return Some((name, open + 1 + close_rel + 1));
    }
    None
}

/// Expurge la configuration d'UN équipement réseau : blocs PEM d'abord
/// (avant toute règle ligne à ligne, pour ne jamais orpheliner un corps de
/// clé), puis les motifs dédiés (FortiGate, Cisco IOS, balises XML — y
/// compris multi-lignes : tout le contenu d'un élément sensible ouvert est
/// remplacé jusqu'à sa balise fermante), et enfin toute la liste de refus
/// générique ([`redact_text`]). Ne panique jamais.
pub fn redact_network_config(text: &str) -> String {
    let text = redact_pem_blocks(text);
    let mut out: Vec<String> = Vec::new();
    // élément XML sensible ouvert : (nom de balise, marqueur déjà émis)
    let mut open_xml: Option<String> = None;
    for line in text.split('\n') {
        if let Some(tag) = &open_xml {
            // contenu multi-lignes d'un élément sensible : tout part
            if let Some(pos) = line.find(&format!("</{tag}")) {
                out.push(line.get(pos..).unwrap_or("").to_string());
                open_xml = None;
            }
            continue;
        }
        if let Some(redacted) = redact_fortigate_set_line(line) {
            out.push(redacted);
            continue;
        }
        if let Some(redacted) = redact_cisco_line(line) {
            out.push(redacted);
            continue;
        }
        if let Some((tag, content_start)) = first_opening_tag(line) {
            if let Some(marker) = xml_sensitive_marker(&tag) {
                let closing = format!("</{tag}");
                let head = line.get(..content_start).unwrap_or("");
                match line.get(content_start..).and_then(|r| r.find(&closing)) {
                    Some(rel) => {
                        // <tag>secret</tag> sur une seule ligne
                        let close_abs = content_start + rel;
                        let tail = line.get(close_abs..).unwrap_or("");
                        if close_abs > content_start {
                            out.push(format!("{head}{marker}{tail}"));
                        } else {
                            out.push(line.to_string()); // contenu vide : honnête
                        }
                    }
                    None => {
                        // élément ouvert sans fermeture : contenu multi-lignes
                        out.push(format!("{head}{marker}"));
                        open_xml = Some(tag);
                    }
                }
                continue;
            }
        }
        out.push(redact_fortigate_enc_values(line));
    }
    redact_text(&out.join("\n"))
}

// ---------------------------------------------------------------------------
// Expurgation structurelle de /etc/shadow
// ---------------------------------------------------------------------------

/// Expurge le champ 2 (hachage) d'une ligne de `/etc/shadow`, de façon
/// **structurelle et exhaustive** : quelle que soit la forme du hachage
/// (modulaire, DES historique, inconnu), il est remplacé.
///
/// Ce qui est conservé, parce que c'est une donnée de conformité :
/// - le préfixe de verrouillage (`!`, `!!`, `*`) ;
/// - l'identifiant d'algorithme `$id$` s'il existe.
///
/// Sel et empreinte sont **toujours** remplacés par [`MARKER_HASH`].
pub fn redact_shadow_hash_field(field: &str) -> String {
    // 1. préfixe de verrouillage
    let lock_len = field
        .bytes()
        .take_while(|b| *b == b'!' || *b == b'*')
        .count();
    let (lock, rest) = field.split_at(lock_len.min(field.len()));
    if rest.is_empty() {
        return lock.to_string();
    }
    // 2. identifiant d'algorithme $id$
    let bytes = rest.as_bytes();
    if bytes[0] == b'$' {
        let mut id_end = 1;
        while id_end < bytes.len() && id_end - 1 < 3 && bytes[id_end].is_ascii_alphanumeric() {
            id_end += 1;
        }
        if id_end > 1 && id_end < bytes.len() && bytes[id_end] == b'$' {
            return format!("{}{}{}", lock, &rest[..=id_end], MARKER_HASH);
        }
    }
    // 3. tout le reste (DES historique, format inconnu) : expurgation totale
    format!("{lock}{MARKER_HASH}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_prive_expurge_entierement() {
        let texte = "avant\n-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n-----END RSA PRIVATE KEY-----\napres";
        let expurge = redact_text(texte);
        assert!(!expurge.contains("MIIEvQIBADAN"));
        assert!(expurge.contains(MARKER_PRIVATE_KEY));
        assert!(expurge.contains("avant"));
        assert!(expurge.contains("apres"));
    }

    #[test]
    fn pem_jamais_referme_expurge_jusqu_a_la_fin() {
        let texte = "ok\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\npas de fin";
        let expurge = redact_text(texte);
        assert!(!expurge.contains("b3BlbnNzaC1rZXktdjEA"));
        assert!(!expurge.contains("pas de fin"));
        assert!(expurge.contains("ok"));
    }

    #[test]
    fn pem_cle_publique_conservee() {
        let texte = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----";
        // une clé PUBLIQUE n'est pas un secret : le bloc reste (le corps base64
        // peut être expurgé par la règle base64 si le contexte est sensible,
        // ce qui est une sur-expurgation acceptable)
        assert!(redact_text(texte).contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn valeur_password_expurgee_cle_conservee() {
        assert_eq!(
            redact_text("password=Sup3rS3cret!"),
            format!("password={MARKER_PASSWORD}")
        );
        assert_eq!(
            redact_text("db_password = \"avec espaces et # tout\""),
            format!("db_password ={MARKER_PASSWORD}")
        );
        assert_eq!(
            redact_text("token: ghp_abcdef123456"),
            format!("token:{MARKER_TOKEN}")
        );
    }

    #[test]
    fn password_authentication_pas_expurge() {
        // « PasswordAuthentication » ne se termine PAS par un mot sensible :
        // la directive sshd doit survivre à l'expurgation, même écrite avec '='.
        assert_eq!(
            redact_text("PasswordAuthentication=no"),
            "PasswordAuthentication=no"
        );
        assert_eq!(
            redact_text("PasswordAuthentication no"),
            "PasswordAuthentication no"
        );
    }

    #[test]
    fn valeur_vide_conservee() {
        assert_eq!(redact_text("password="), "password=");
    }

    #[test]
    fn hachage_crypt_expurge_algorithme_conserve() {
        let expurge = redact_text("$6$Wh4tAS4lt$0123456789abcdefghijklmnopqrstuvwxyzABCDEF");
        assert_eq!(expurge, format!("$6${MARKER_HASH}"));
        let y = redact_text("$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X9pE");
        assert!(y.starts_with("$y$"));
        assert!(!y.contains("F5Jx5fExrKuPp53xLKQ"));
    }

    #[test]
    fn champ_shadow_structurel() {
        assert_eq!(
            redact_shadow_hash_field("$6$sel$empreinte"),
            format!("$6${MARKER_HASH}")
        );
        assert_eq!(
            redact_shadow_hash_field("!$6$sel$empreinte"),
            format!("!$6${MARKER_HASH}")
        );
        assert_eq!(redact_shadow_hash_field("!"), "!");
        assert_eq!(redact_shadow_hash_field("*"), "*");
        assert_eq!(redact_shadow_hash_field(""), "");
        // DES historique : expurgation totale
        assert_eq!(redact_shadow_hash_field("abJnggxhB/yWI"), MARKER_HASH);
    }

    #[test]
    fn base64_long_en_contexte_sensible() {
        let ligne = "api_response_key AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA1234567890";
        let expurge = redact_text(ligne);
        assert!(!expurge.contains("AAAAB3NzaC1yc2EA"));
        assert!(expurge.contains(MARKER_BASE64));
        // hors contexte sensible, une longue chaîne est conservée
        let neutre = "checksum AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA1234567890";
        assert!(redact_text(neutre).contains("AAAAB3NzaC1yc2EA"));
    }

    #[test]
    fn empreinte_est_un_fingerprint() {
        match fingerprint(b"secret") {
            Value::Fingerprint(h) => assert_eq!(h, *blake3::hash(b"secret").as_bytes()),
            autre => panic!("attendu Fingerprint, obtenu {autre:?}"),
        }
    }

    // -- configurations réseau ----------------------------------------------

    #[test]
    fn fortigate_set_sensible_expurge_structure_conservee() {
        assert_eq!(
            redact_network_config("    set passwd ENC AbCdEfGh0123456789=="),
            format!("    set passwd {MARKER_PASSWORD}")
        );
        assert_eq!(
            redact_network_config("    set psksecret ENC AbCdEfGh0123456789=="),
            format!("    set psksecret {MARKER_SHARED_KEY}")
        );
        assert_eq!(
            redact_network_config("    set admin-password MotDePasseNu"),
            format!("    set admin-password {MARKER_PASSWORD}")
        );
        // attribut non sensible : intact
        assert_eq!(
            redact_network_config("    set hostname \"fw-lab-01\""),
            "    set hostname \"fw-lab-01\""
        );
    }

    #[test]
    fn fortigate_enc_hors_set_sensible_expurge() {
        let expurge = redact_network_config("set unknown-attr ENC AbCdEfGh0123456789==");
        assert!(!expurge.contains("AbCdEfGh0123456789"));
        assert!(expurge.contains("ENC "));
        // `AGENCE` ne déclenche pas la règle ENC
        assert_eq!(
            redact_network_config("set comment AGENCE lyonnaise"),
            "set comment AGENCE lyonnaise"
        );
    }

    #[test]
    fn cisco_enable_secret_et_username() {
        assert_eq!(
            redact_network_config("enable secret 5 $1$abcd$efghijklmnopqrstuvwxyz012"),
            format!("enable secret 5 {MARKER_HASH}")
        );
        assert_eq!(
            redact_network_config("username ops secret 5 $1$abcd$efghijklmnopqrstuvwxyz012"),
            format!("username ops secret 5 {MARKER_HASH}")
        );
        assert_eq!(
            redact_network_config("username invite password 0 MotEnClair"),
            format!("username invite password 0 {MARKER_PASSWORD}")
        );
    }

    #[test]
    fn cisco_communaute_snmp_la_structure_survit() {
        assert_eq!(
            redact_network_config("snmp-server community lecture-fictive RO"),
            format!("snmp-server community {MARKER_SNMP_COMMUNITY} RO")
        );
    }

    #[test]
    fn cisco_cles_partagees() {
        assert_eq!(
            redact_network_config("crypto isakmp key ClefFictive address 10.200.1.1"),
            format!("crypto isakmp key {MARKER_SHARED_KEY} address 10.200.1.1")
        );
        assert_eq!(
            redact_network_config("tacacs-server host 10.20.2.40 key 7 0822455D0A16"),
            format!("tacacs-server host 10.20.2.40 key 7 {MARKER_SHARED_KEY}")
        );
        assert_eq!(
            redact_network_config(" standby 1 authentication md5 key-string ClefHsrp"),
            format!(" standby 1 authentication md5 key-string {MARKER_SHARED_KEY}")
        );
        assert_eq!(
            redact_network_config("  key-string 7 ClefChaine"),
            format!("  key-string 7 {MARKER_SHARED_KEY}")
        );
        // un numéro de clé de key chain n'est PAS un secret
        assert_eq!(redact_network_config(" key 1"), " key 1");
        assert_eq!(
            redact_network_config("key chain SECOURS"),
            "key chain SECOURS"
        );
        // mais la clé isolée d'un bloc radius server part
        assert_eq!(
            redact_network_config(" key 7 ClefRadius"),
            format!(" key 7 {MARKER_SHARED_KEY}")
        );
    }

    #[test]
    fn xml_balises_sensibles_expurgees_structure_conservee() {
        assert_eq!(
            redact_network_config("    <password>$2y$10$HachageFictif</password>"),
            format!("    <password>{MARKER_PASSWORD}</password>")
        );
        assert_eq!(
            redact_network_config("<apikey>CleFictive123</apikey>"),
            format!("<apikey>{MARKER_SECRET}</apikey>")
        );
        assert_eq!(
            redact_network_config("<rocommunity>public</rocommunity>"),
            format!("<rocommunity>{MARKER_SNMP_COMMUNITY}</rocommunity>")
        );
        // balise vide ou auto-fermante : intacte (l'absence est honnête)
        assert_eq!(
            redact_network_config("<password></password>"),
            "<password></password>"
        );
        assert_eq!(redact_network_config("<authkey/>"), "<authkey/>");
        // balise non sensible : intacte
        assert_eq!(
            redact_network_config("<gateway>10.200.0.1</gateway>"),
            "<gateway>10.200.0.1</gateway>"
        );
    }

    #[test]
    fn xml_element_sensible_multi_lignes_expurge() {
        let texte =
            "<system>\n<privkey>ligne1secrete\nligne2secrete</privkey>\n<hostname>fw</hostname>";
        let expurge = redact_network_config(texte);
        assert!(!expurge.contains("ligne1secrete"));
        assert!(!expurge.contains("ligne2secrete"));
        assert!(expurge.contains(MARKER_SECRET));
        assert!(expurge.contains("<hostname>fw</hostname>"));
    }

    #[test]
    fn pem_dans_config_fortigate_expurge_avant_les_regles_ligne() {
        let texte = "config vpn certificate local\n    edit \"srv\"\n        set private-key \"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\n-----END ENCRYPTED PRIVATE KEY-----\"\n    next\nend";
        let expurge = redact_network_config(texte);
        assert!(!expurge.contains("MIIEvQIBADAN"));
        assert!(expurge.contains(MARKER_PRIVATE_KEY));
        assert!(expurge.contains("config vpn certificate local"));
    }

    #[test]
    fn nftables_traverse_sans_dommage() {
        let texte = "table inet filtre {\n    chain entree {\n        type filter hook input priority 0; policy drop;\n        ip saddr 10.20.30.0/24 tcp dport { 22, 443 } accept\n    }\n}";
        assert_eq!(redact_network_config(texte), texte);
    }

    #[test]
    fn octets_non_utf8_ne_paniquent_pas() {
        let brut = vec![
            0xff, 0xfe, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', b'=', b'x', 0x80,
        ];
        let _ = redact_bytes(&brut);
    }
}
