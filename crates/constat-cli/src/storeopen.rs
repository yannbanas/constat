//! Ouverture du magasin local (backend redb de `constat-store`).
//!
//! Le chemin est résolu dans cet ordre : option `--store`, variable
//! d'environnement `CONSTAT_STORE`, puis `./constat.redb`.

use std::path::{Path, PathBuf};

use constat_store::{RedbStore, Store};
use miette::miette;

/// Nom de la variable d'environnement qui désigne le magasin.
pub const STORE_ENV: &str = "CONSTAT_STORE";

/// Chemin par défaut du magasin.
pub const STORE_DEFAULT: &str = "./constat.redb";

/// Résout le chemin du magasin : `--store` > `CONSTAT_STORE` > défaut.
pub fn resolve_store_path(flag: Option<PathBuf>) -> PathBuf {
    flag.or_else(|| std::env::var_os(STORE_ENV).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(STORE_DEFAULT))
}

/// Ouvre le magasin en lecture.
///
/// La CLI interroge, elle ne collecte pas : un magasin inexistant est une
/// erreur explicite (et non un fichier vide créé en silence sur un chemin
/// mal orthographié).
pub fn open_store(path: &Path) -> miette::Result<Box<dyn Store>> {
    if !path.exists() {
        return Err(miette!(
            help = "lancez d'abord une collecte (`constat-agent run --once`), ou \
                    désignez le magasin avec --store ou la variable CONSTAT_STORE",
            "magasin introuvable : {}",
            path.display()
        ));
    }
    let store = RedbStore::open(path)
        .map_err(|e| miette!("impossible d'ouvrir le magasin {} : {e}", path.display()))?;
    Ok(Box::new(store))
}
