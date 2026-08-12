//! Archivage des jetons d'horodatage à côté du magasin (§6.3, niveau 3).
//!
//! ## Emplacement documenté
//!
//! Un jeton délivré par `constat anchor --send <url>` est archivé dans :
//!
//! ```text
//! <magasin>.anchors/<racine-hex>.tsr
//! ```
//!
//! c'est-à-dire, pour un magasin `./constat.redb`, le fichier
//! `./constat.redb.anchors/<racine>.tsr`. Le fichier contient la
//! **`TimeStampResp` complète** (DER), telle que reçue du prestataire —
//! vérifiable avec les outils standard
//! (`openssl ts -reply -in <fichier>.tsr -text`).
//!
//! Le nom du fichier est la racine horodatée : `constat pack` y retrouve le
//! jeton de la racine **courante** et le joint au dossier de preuve. Une
//! racine plus récente que le dernier ancrage n'a pas de jeton — le dossier
//! déclare alors l'absence, il ne recycle jamais un jeton d'une autre racine.

use std::path::{Path, PathBuf};

use constat_model::BlobHash;
use miette::miette;

/// Répertoire des ancrages d'un magasin : `<magasin>.anchors`.
pub fn anchors_dir(store_path: &Path) -> PathBuf {
    let mut os = store_path.as_os_str().to_os_string();
    os.push(".anchors");
    PathBuf::from(os)
}

/// Chemin du jeton archivé pour une racine : `<magasin>.anchors/<racine>.tsr`.
pub fn token_path(store_path: &Path, root: &BlobHash) -> PathBuf {
    anchors_dir(store_path).join(format!("{}.tsr", root.to_hex()))
}

/// Archive la réponse d'horodatage (DER, telle que reçue) pour `root`.
/// Renvoie le chemin écrit.
pub fn write_response(store_path: &Path, root: &BlobHash, der: &[u8]) -> miette::Result<PathBuf> {
    let dir = anchors_dir(store_path);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette!("impossible de créer {} : {e}", dir.display()))?;
    let path = token_path(store_path, root);
    std::fs::write(&path, der)
        .map_err(|e| miette!("impossible d'écrire {} : {e}", path.display()))?;
    Ok(path)
}

/// Relit le jeton (`TimeStampToken`, DER) archivé pour `root`, s'il existe.
///
/// - fichier absent → `Ok(None)` : l'absence d'ancrage est un état déclaré,
///   pas une erreur ;
/// - fichier présent mais illisible ou sans jeton → erreur : un ancrage
///   corrompu ne doit jamais passer sous silence dans un dossier de preuve.
pub fn read_token(store_path: &Path, root: &BlobHash) -> miette::Result<Option<Vec<u8>>> {
    let path = token_path(store_path, root);
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        std::fs::read(&path).map_err(|e| miette!("impossible de lire {} : {e}", path.display()))?;
    let response = constat_anchor::rfc3161::parse_response(&bytes).map_err(|e| {
        miette!(
            help = "le fichier doit contenir la TimeStampResp DER reçue du prestataire \
                    (écrite par `constat anchor --send`)",
            "réponse d'horodatage illisible dans {} : {e}",
            path.display()
        )
    })?;
    match response.token {
        Some(token) => Ok(Some(token)),
        None => Err(miette!(
            "la réponse archivée dans {} ne contient aucun jeton (statut sans délivrance)",
            path.display()
        )),
    }
}
