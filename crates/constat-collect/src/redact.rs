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

    #[test]
    fn octets_non_utf8_ne_paniquent_pas() {
        let brut = vec![
            0xff, 0xfe, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', b'=', b'x', 0x80,
        ];
        let _ = redact_bytes(&brut);
    }
}
