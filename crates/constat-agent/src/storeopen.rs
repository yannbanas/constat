//! Ouverture du magasin local de l'agent (backend redb de `constat-store`).

use std::path::{Path, PathBuf};

use constat_store::{RedbStore, Store};
use miette::miette;

/// Variable d'environnement désignant le magasin.
pub const STORE_ENV: &str = "CONSTAT_STORE";
/// Chemin par défaut du magasin.
pub const STORE_DEFAULT: &str = "./constat.redb";

/// Résout le chemin du magasin : `--store` > `CONSTAT_STORE` > défaut.
pub fn resolve_store_path(flag: Option<PathBuf>) -> PathBuf {
    flag.or_else(|| std::env::var_os(STORE_ENV).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(STORE_DEFAULT))
}

/// Ouvre (ou crée) le magasin local en écriture — la seule écriture que
/// l'agent fait sur la machine, avec ses fichiers de clés.
pub fn open_store(path: &Path) -> miette::Result<Box<dyn Store>> {
    let store = RedbStore::open(path)
        .map_err(|e| miette!("impossible d'ouvrir le magasin {} : {e}", path.display()))?;
    Ok(Box::new(store))
}
