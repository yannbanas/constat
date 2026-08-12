//! Résolution des clés du journal côté CLI.
//!
//! La paire de clés vit dans le répertoire de clés de l'**agent**
//! (`constat-agent keygen`). La CLI ne dépend pas du crate de l'agent :
//! elle relit le même format de fichiers, volontairement trivial :
//!
//! - `agent.key` : clé privée Ed25519, 32 octets en hexadécimal ;
//! - `agent.pub` : clé publique Ed25519, 32 octets en hexadécimal.
//!
//! ## Ordre de résolution de la clé publique
//!
//! Le même pour `constat export` et `constat pack` :
//!
//! 1. `--pubkey <fichier>` : un fichier contenant la clé publique, en
//!    hexadécimal (64 caractères) **ou** en binaire brut (32 octets — le
//!    format du `pubkey.bin` d'un export) ;
//! 2. `<répertoire de clés>/agent.pub` (hexadécimal) ;
//! 3. à défaut, dérivée de `<répertoire de clés>/agent.key`.
//!
//! Le répertoire de clés est celui de `--keys <dossier>`, sinon
//! `./constat-agent.keys` (le défaut de l'agent).

use std::path::{Path, PathBuf};

use constat_store::{SigningKey, VerifyingKey};
use miette::miette;

/// Nom du fichier de clé privée (32 octets, hexadécimal) — celui de l'agent.
pub const KEY_FILE: &str = "agent.key";
/// Nom du fichier de clé publique (32 octets, hexadécimal) — celui de l'agent.
pub const PUB_FILE: &str = "agent.pub";
/// Répertoire de clés par défaut, relatif au répertoire de travail — celui
/// de l'agent.
pub const DEFAULT_KEYS_DIR: &str = "./constat-agent.keys";

/// Décodage hexadécimal sans dépendance.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Répertoire de clés effectif : `--keys` sinon le défaut de l'agent.
fn keys_dir(keys: Option<&Path>) -> PathBuf {
    keys.map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEYS_DIR))
}

/// Interprète 32 octets comme une clé publique Ed25519.
fn verifying_key_from(bytes: &[u8], origin: &Path) -> miette::Result<VerifyingKey> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        miette!(
            "clé publique de taille invalide dans {} ({} octets, 32 attendus)",
            origin.display(),
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| miette!("clé publique invalide dans {} : {e}", origin.display()))
}

/// Lit un fichier de clé publique : hexadécimal (64 caractères, format
/// `agent.pub`) ou binaire brut (32 octets, format `pubkey.bin`).
fn read_pubkey_file(path: &Path) -> miette::Result<VerifyingKey> {
    let raw = std::fs::read(path).map_err(|e| {
        miette!(
            help = "indiquez un fichier au format d'agent.pub (hexadécimal) ou de \
                    pubkey.bin (32 octets bruts)",
            "impossible de lire la clé publique {} : {e}",
            path.display()
        )
    })?;
    if raw.len() == 32 {
        return verifying_key_from(&raw, path);
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| miette!("clé publique illisible dans {}", path.display()))?;
    let bytes = hex_decode(text.trim()).ok_or_else(|| {
        miette!(
            "clé publique illisible dans {} (hexadécimal ou 32 octets bruts attendus)",
            path.display()
        )
    })?;
    verifying_key_from(&bytes, path)
}

/// Charge la clé de **signature** du journal depuis le répertoire de clés de
/// l'agent (fichier `agent.key`, 32 octets hexadécimaux).
pub fn load_signing_key(dir: &Path) -> miette::Result<SigningKey> {
    let path = dir.join(KEY_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        miette!(
            help = "générez la paire de clés avec `constat-agent keygen`",
            "impossible de lire la clé {} : {e}",
            path.display()
        )
    })?;
    let bytes = hex_decode(text.trim()).ok_or_else(|| {
        miette!(
            "clé illisible dans {} (hexadécimal attendu)",
            path.display()
        )
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        miette!(
            "clé de taille invalide dans {} (32 octets attendus)",
            path.display()
        )
    })?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Résout la clé **publique** du journal (voir l'ordre en tête de module).
/// Erreur si aucune source n'aboutit.
pub fn resolve_public_key(
    pubkey: Option<&Path>,
    keys: Option<&Path>,
) -> miette::Result<VerifyingKey> {
    if let Some(path) = pubkey {
        return read_pubkey_file(path);
    }
    let dir = keys_dir(keys);
    let pub_path = dir.join(PUB_FILE);
    if pub_path.exists() {
        return read_pubkey_file(&pub_path);
    }
    let key_path = dir.join(KEY_FILE);
    if key_path.exists() {
        return Ok(load_signing_key(&dir)?.verifying_key());
    }
    Err(miette!(
        help = "indiquez la clé avec --pubkey <fichier>, ou le répertoire de clés de \
                l'agent avec --keys <dossier> (généré par `constat-agent keygen`)",
        "aucune clé publique trouvée : ni {} ni {}",
        pub_path.display(),
        key_path.display()
    ))
}

/// Comme [`resolve_public_key`], mais l'absence de clé n'est pas une erreur
/// quand rien n'a été demandé explicitement : `Ok(None)`.
///
/// Utilisée par `constat pack` : sans clé, le dossier déclare l'absence au
/// lieu d'échouer. En revanche, un `--pubkey` ou `--keys` explicite qui
/// n'aboutit pas reste une erreur — on ne passe pas sous silence une
/// demande de l'utilisateur.
pub fn try_resolve_public_key(
    pubkey: Option<&Path>,
    keys: Option<&Path>,
) -> miette::Result<Option<VerifyingKey>> {
    if pubkey.is_some() || keys.is_some() {
        return resolve_public_key(pubkey, keys).map(Some);
    }
    let dir = keys_dir(None);
    if dir.join(PUB_FILE).exists() || dir.join(KEY_FILE).exists() {
        resolve_public_key(None, None).map(Some)
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "constat-keyres-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolution_hex_brut_et_derivee() {
        let dir = tmp_dir("resolution");
        let signer = constat_store::Signer::generate();
        let public = signer.verifying_key();
        let public_hex: String = public
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        // 1. --pubkey en hexadécimal.
        let hex_path = dir.join("cle.pub");
        std::fs::write(&hex_path, &public_hex).unwrap();
        assert_eq!(resolve_public_key(Some(&hex_path), None).unwrap(), public);

        // 1 bis. --pubkey en binaire brut (format pubkey.bin).
        let raw_path = dir.join("pubkey.bin");
        std::fs::write(&raw_path, public.to_bytes()).unwrap();
        assert_eq!(resolve_public_key(Some(&raw_path), None).unwrap(), public);

        // 2. agent.pub dans le répertoire de clés.
        let keys = dir.join("cles");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join(PUB_FILE), &public_hex).unwrap();
        assert_eq!(resolve_public_key(None, Some(&keys)).unwrap(), public);

        // 3. dérivée d'agent.key quand agent.pub manque.
        let keys2 = dir.join("cles-privee");
        std::fs::create_dir_all(&keys2).unwrap();
        let private_hex: String = signer
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(keys2.join(KEY_FILE), private_hex).unwrap();
        assert_eq!(resolve_public_key(None, Some(&keys2)).unwrap(), public);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absence_toleree_seulement_sans_demande_explicite() {
        let dir = tmp_dir("absence");
        // Répertoire explicite mais vide : erreur.
        assert!(try_resolve_public_key(None, Some(&dir)).is_err());
        // --pubkey explicite mais introuvable : erreur.
        assert!(try_resolve_public_key(Some(&dir.join("absente.pub")), None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
