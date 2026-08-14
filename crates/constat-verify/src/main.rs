//! Binaire `constat-verify` — vérification d'un export par un tiers (§10.3).
//!
//! Usage : `constat-verify <répertoire-export>`
//!
//! Le layout attendu du répertoire est défini dans `FORMAT.md` (normatif) :
//! `pubkey.bin`, `0.cbor` … `N.cbor`, `snapshots/<hex>.cbor`,
//! `blobs/<hex>.cbor`.
//!
//! Parsing d'arguments à la main, volontairement : le binaire doit rester sans
//! dépendance lourde, réimplémentable en une centaine de lignes par un
//! auditeur méfiant. Sortie en français, code de sortie 0 (succès) ou 1.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use constat_model::{from_canonical_bytes, Blob, BlobHash, Snapshot};
use constat_store::JournalEntry;
use constat_verify::{verify_export, Export};

const USAGE: &str = "\
Usage : constat-verify <répertoire-export>

Vérifie un export de journal Constat sans dépendre de Constat :
  1. chaque snapshot et chaque blob correspond à son empreinte (nom de fichier) ;
  2. la chaîne d'empreintes est intacte de la genèse à la racine ;
  3. chaque entrée porte une signature Ed25519 valide de la clé courante :
     pubkey.bin (genèse), puis la clé déléguée par chaque rotation de clé
     journalisée (blob constat.rotation, signé par l'ancienne clé) ;
  4. tout objet référencé est présent dans l'export (ou déclaré purgé).

Layout attendu (normatif : voir crates/constat-verify/FORMAT.md) :
  <répertoire>/pubkey.bin           clé publique Ed25519, 32 octets bruts
  <répertoire>/0.cbor … N.cbor      entrées du journal, indices consécutifs
  <répertoire>/snapshots/<hex>.cbor snapshots, nommés par empreinte BLAKE3
  <répertoire>/blobs/<hex>.cbor     blobs, nommés par empreinte BLAKE3

Code de sortie : 0 si la vérification réussit, 1 sinon.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let dir = match args.as_slice() {
        [d] => d.clone(),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    match run(Path::new(&dir)) {
        Ok(rapport) => {
            println!("{rapport}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("ÉCHEC — {message}");
            ExitCode::FAILURE
        }
    }
}

/// Charge l'export depuis le disque puis délègue à la bibliothèque pure.
fn run(dir: &Path) -> Result<String, String> {
    if !dir.is_dir() {
        return Err(format!(
            "le répertoire d'export « {} » n'existe pas ou n'est pas un répertoire",
            dir.display()
        ));
    }

    // Clé publique : 32 octets bruts.
    let pubkey_path = dir.join("pubkey.bin");
    let pubkey_bytes = std::fs::read(&pubkey_path)
        .map_err(|e| format!("lecture de {} impossible : {e}", pubkey_path.display()))?;
    let public_key: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{} : attendu 32 octets (clé publique Ed25519), trouvé {}",
            pubkey_path.display(),
            pubkey_bytes.len()
        )
    })?;

    // Entrées : 0.cbor, 1.cbor, … — indices consécutifs, sans trou.
    let mut entries: Vec<JournalEntry> = Vec::new();
    loop {
        let path = dir.join(format!("{}.cbor", entries.len()));
        if !path.is_file() {
            break;
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("lecture de {} impossible : {e}", path.display()))?;
        let entry: JournalEntry = from_canonical_bytes(&bytes)
            .map_err(|e| format!("{} : entrée illisible ({e})", path.display()))?;
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err(format!(
            "aucune entrée de journal trouvée (fichier {} absent)",
            dir.join("0.cbor").display()
        ));
    }

    let snapshots: BTreeMap<BlobHash, Snapshot> = read_hash_dir(&dir.join("snapshots"), |b| {
        from_canonical_bytes(b).map_err(|e| e.to_string())
    })?;
    let blobs: BTreeMap<BlobHash, Blob> = read_hash_dir(&dir.join("blobs"), |b| {
        from_canonical_bytes(b).map_err(|e| e.to_string())
    })?;

    let export = Export {
        entries,
        snapshots,
        blobs,
        public_key,
    };

    let ok = verify_export(&export).map_err(|e| e.to_string())?;

    // Purges journalisées (§16) : des objets absents mais DÉCLARÉS ne sont
    // pas une altération — le résultat le dit explicitement, période et
    // motif compris. Un export sans purge garde la sortie historique.
    let purge_note = if ok.purged_count == 0 && ok.purges.is_empty() {
        String::new()
    } else {
        let mut note = format!(
            "cohérent — {} objet(s) purgé(s) déclaré(s) :\n",
            ok.purged_count
        );
        for p in &ok.purges {
            note.push_str(&format!(
                "  - période {} → {}, motif « {} », {} objet(s), manifeste {}\n",
                date(p.from),
                date(p.to),
                p.reason,
                p.objects,
                p.manifest.to_hex()
            ));
        }
        note
    };

    // Rotations de clé (FORMAT.md § 4 ter) : la clé courante a été suivie le
    // long de la chaîne ; le résultat le dit et donne la clé finale — celle
    // qui signera l'entrée suivante. Un export sans rotation garde la sortie
    // historique.
    let rotation_note = if ok.rotation_count == 0 {
        String::new()
    } else {
        let final_hex: String = ok.final_key.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "{} rotation(s) de clé, clé finale {}…\n",
            ok.rotation_count,
            &final_hex[..16]
        )
    };

    Ok(format!(
        "OK — export vérifié : chaîne intacte, signatures valides, artefacts conformes.\n\
         {purge_note}\
         {rotation_note}\
         Racine    : {}\n\
         Entrées   : {}\n\
         Snapshots : {}\n\
         Blobs     : {}\n\
         Rappel (§6.2) : sans ancrage externe, ce résultat prouve la cohérence\n\
         interne du journal, pas la non-répudiation. Comparez la racine ci-dessus\n\
         à une racine ancrée hors du système (courriel, jeton RFC 3161).",
        ok.root.to_hex(),
        ok.entry_count,
        ok.snapshot_count,
        ok.blob_count
    ))
}

/// Date lisible (RFC 3339) pour la sortie ; millisecondes brutes si la valeur
/// sort de l'intervalle représentable.
fn date(t: constat_model::Timestamp) -> String {
    t.to_rfc3339().unwrap_or_else(|_| format!("{} ms", t.0))
}

/// Lit un répertoire d'objets adressés par contenu : chaque fichier doit se
/// nommer `<64 caractères hexadécimaux>.cbor`. Un répertoire absent vaut un
/// répertoire vide (un journal peut ne référencer aucun objet).
fn read_hash_dir<T>(
    dir: &Path,
    decode: impl Fn(&[u8]) -> Result<T, String>,
) -> Result<BTreeMap<BlobHash, T>, String> {
    let mut out = BTreeMap::new();
    if !dir.exists() {
        return Ok(out);
    }
    let iter = std::fs::read_dir(dir)
        .map_err(|e| format!("lecture du répertoire {} impossible : {e}", dir.display()))?;
    for item in iter {
        let item =
            item.map_err(|e| format!("lecture du répertoire {} impossible : {e}", dir.display()))?;
        let path = item.path();
        let name = item.file_name();
        let name = name.to_string_lossy();
        let stem = name.strip_suffix(".cbor").ok_or_else(|| {
            format!(
                "{} : nom de fichier inattendu (attendu <hex>.cbor)",
                path.display()
            )
        })?;
        let hash = parse_hex32(stem).ok_or_else(|| {
            format!(
                "{} : nom de fichier inattendu (attendu 64 caractères hexadécimaux)",
                path.display()
            )
        })?;
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("lecture de {} impossible : {e}", path.display()))?;
        let value: T =
            decode(&bytes).map_err(|e| format!("{} : contenu illisible ({e})", path.display()))?;
        out.insert(BlobHash(hash), value);
    }
    Ok(out)
}

/// Décodage hexadécimal de 64 caractères vers 32 octets, à la main : pas de
/// dépendance pour dix lignes de code.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = hex_val(pair[0])?
            .checked_mul(16)?
            .checked_add(hex_val(pair[1])?)?;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
