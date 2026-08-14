//! Gestion de la paire de clés locale de l'agent.
//!
//! La clé privée signe les entrées du journal (§3.3, §6.1) via
//! [`constat_store::Signer`]. Elle ne quitte jamais la machine. Sur unix,
//! le fichier est créé avec des permissions restrictives (0600, répertoire
//! 0700).

use std::path::{Path, PathBuf};

use constat_store::Signer;
use miette::miette;

/// Nom du fichier de clé privée (32 octets, hexadécimal).
pub const KEY_FILE: &str = "agent.key";
/// Nom du fichier de clé publique (32 octets, hexadécimal).
pub const PUB_FILE: &str = "agent.pub";

/// Répertoire de clés par défaut, relatif au répertoire de travail.
pub const DEFAULT_KEYS_DIR: &str = "./constat-agent.keys";

/// Résout le répertoire de clés : option `--keys` sinon défaut.
pub fn resolve_keys_dir(flag: Option<PathBuf>) -> PathBuf {
    flag.unwrap_or_else(|| PathBuf::from(DEFAULT_KEYS_DIR))
}

/// Génère la paire de clés et l'écrit dans `dir`. Renvoie le chemin de la
/// clé privée et la clé publique en hexadécimal.
///
/// Refuse d'écraser une clé existante sans `force` : régénérer la clé rend
/// les anciennes signatures invérifiables par la nouvelle clé publique.
pub fn generate(dir: &Path, force: bool) -> miette::Result<(PathBuf, String)> {
    let key_path = dir.join(KEY_FILE);
    let pub_path = dir.join(PUB_FILE);
    if key_path.exists() && !force {
        return Err(miette!(
            help = "utilisez --force pour régénérer (la nouvelle clé ne pourra plus \
                    vérifier les entrées signées avec l'ancienne)",
            "une clé existe déjà : {}",
            key_path.display()
        ));
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| miette!("impossible de créer {} : {e}", dir.display()))?;

    let signer = Signer::generate();
    let public_hex = hex::encode(signer.verifying_key().to_bytes());
    std::fs::write(&key_path, hex::encode(signer.to_bytes()))
        .map_err(|e| miette!("impossible d'écrire {} : {e}", key_path.display()))?;
    std::fs::write(&pub_path, &public_hex)
        .map_err(|e| miette!("impossible d'écrire {} : {e}", pub_path.display()))?;

    restrict_permissions(dir, &key_path)?;
    Ok((key_path, public_hex))
}

/// Les chemins produits par une rotation de fichiers de clés
/// ([`rotate_files`]).
#[derive(Debug)]
pub struct RotatedFiles {
    /// L'ancienne clé privée, archivée (`agent.key.<date>.old`).
    pub old_key_archive: PathBuf,
    /// L'ancienne clé publique, archivée (`agent.pub.<date>.old`) — `None`
    /// si `agent.pub` n'existait pas.
    pub old_pub_archive: Option<PathBuf>,
    /// La nouvelle clé privée en place (`agent.key`).
    pub key_path: PathBuf,
    /// La nouvelle clé publique en place (`agent.pub`).
    pub pub_path: PathBuf,
}

/// Étiquette de date pour les fichiers d'archive : RFC 3339 sans les
/// caractères interdits dans un nom de fichier (les `:` deviennent des
/// `-`), sans la fraction de seconde. Ex. `2026-08-14T09-30-05Z`.
pub fn archive_label(at: constat_model::Timestamp) -> String {
    let text = at.to_rfc3339().unwrap_or_else(|_| format!("{}ms", at.0));
    let text = match text.split_once('.') {
        Some((head, _)) => format!("{head}Z"),
        None => text,
    };
    text.replace(':', "-")
}

/// Phase 1 de la rotation des fichiers : écrit la **nouvelle** paire dans
/// `dir` sous des noms temporaires (`agent.key.new`, `agent.pub.new`),
/// permissions restrictives comprises. À appeler AVANT d'écrire l'entrée de
/// rotation dans le journal : la nouvelle clé privée doit être durable sur
/// disque avant que le journal ne la désigne comme courante.
pub fn stage_new_keys(dir: &Path, new: &Signer) -> miette::Result<(PathBuf, PathBuf)> {
    let key_tmp = dir.join(format!("{KEY_FILE}.new"));
    let pub_tmp = dir.join(format!("{PUB_FILE}.new"));
    for tmp in [&key_tmp, &pub_tmp] {
        if tmp.exists() {
            return Err(miette!(
                help = "une rotation précédente s'est interrompue : examinez ce fichier \
                        (il contient une paire jamais journalisée) puis supprimez-le",
                "fichier résiduel d'une rotation interrompue : {}",
                tmp.display()
            ));
        }
    }
    std::fs::write(&key_tmp, hex::encode(new.to_bytes()))
        .map_err(|e| miette!("impossible d'écrire {} : {e}", key_tmp.display()))?;
    std::fs::write(&pub_tmp, hex::encode(new.verifying_key().to_bytes()))
        .map_err(|e| miette!("impossible d'écrire {} : {e}", pub_tmp.display()))?;
    restrict_permissions(dir, &key_tmp)?;
    Ok((key_tmp, pub_tmp))
}

/// Phase 2 de la rotation des fichiers, APRÈS que l'entrée de rotation est
/// journalisée : archive l'ancienne paire (`agent.key.<date>.old`,
/// `agent.pub.<date>.old` — les renommages conservent les permissions
/// restrictives) puis met la nouvelle paire en place.
///
/// Si cette phase échoue à mi-chemin, la nouvelle clé privée reste durable
/// dans `agent.key.new` : rien n'est perdu, l'opérateur termine à la main
/// (l'erreur le lui dit).
pub fn commit_rotated_keys(
    dir: &Path,
    key_tmp: &Path,
    pub_tmp: &Path,
    label: &str,
) -> miette::Result<RotatedFiles> {
    let key_path = dir.join(KEY_FILE);
    let pub_path = dir.join(PUB_FILE);
    let old_key_archive = dir.join(format!("{KEY_FILE}.{label}.old"));
    let old_pub_archive = dir.join(format!("{PUB_FILE}.{label}.old"));
    let recover = "la rotation est déjà journalisée ; terminez à la main : archivez \
                   agent.key/agent.pub puis renommez agent.key.new → agent.key et \
                   agent.pub.new → agent.pub";

    if old_key_archive.exists() || old_pub_archive.exists() {
        return Err(miette!(
            "une archive du même instant existe déjà : {}",
            old_key_archive.display()
        ));
    }
    std::fs::rename(&key_path, &old_key_archive).map_err(|e| {
        miette!(
            help = recover,
            "impossible d'archiver {} : {e}",
            key_path.display()
        )
    })?;
    let archived_pub = if pub_path.exists() {
        std::fs::rename(&pub_path, &old_pub_archive).map_err(|e| {
            miette!(
                help = recover,
                "impossible d'archiver {} : {e}",
                pub_path.display()
            )
        })?;
        Some(old_pub_archive)
    } else {
        None
    };
    std::fs::rename(key_tmp, &key_path).map_err(|e| {
        miette!(
            help = recover,
            "impossible de mettre en place {} : {e}",
            key_path.display()
        )
    })?;
    std::fs::rename(pub_tmp, &pub_path).map_err(|e| {
        miette!(
            help = recover,
            "impossible de mettre en place {} : {e}",
            pub_path.display()
        )
    })?;
    restrict_permissions(dir, &key_path)?;
    Ok(RotatedFiles {
        old_key_archive,
        old_pub_archive: archived_pub,
        key_path,
        pub_path,
    })
}

/// Charge la clé de signature depuis `dir`.
pub fn load(dir: &Path) -> miette::Result<Signer> {
    let key_path = dir.join(KEY_FILE);
    let text = std::fs::read_to_string(&key_path).map_err(|e| {
        miette!(
            help = "générez la paire de clés avec `constat-agent keygen`",
            "impossible de lire la clé {} : {e}",
            key_path.display()
        )
    })?;
    let bytes = hex::decode(text.trim())
        .map_err(|e| miette!("clé illisible dans {} : {e}", key_path.display()))?;
    Signer::from_slice(&bytes)
        .map_err(|e| miette!("clé invalide dans {} : {e}", key_path.display()))
}

/// Permissions restrictives : effectif sur unix, sans objet ailleurs.
#[cfg(unix)]
fn restrict_permissions(dir: &Path, key_path: &Path) -> miette::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| miette!("impossible de restreindre {} : {e}", dir.display()))?;
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| miette!("impossible de restreindre {} : {e}", key_path.display()))?;
    Ok(())
}

/// Sous Windows, les ACL héritées du profil utilisateur s'appliquent ;
/// un durcissement icacls pourra compléter — hors périmètre du binaire.
#[cfg(not(unix))]
fn restrict_permissions(_dir: &Path, _key_path: &Path) -> miette::Result<()> {
    Ok(())
}
