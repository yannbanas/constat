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
