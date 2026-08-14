//! Export du magasin vers un répertoire — le format que `constat-verify`
//! consomme en autonome, sans dépendre de Constat (§10.3).
//!
//! Deux exporteurs, un seul format : [`export_store`] exporte le journal par
//! défaut, [`export_journal`] exporte un journal nommé (multi-agents, §13 S8).
//! Dans les deux cas : **un export = un journal d'un signataire**, layout
//! normatif identique.
//!
//! # Layout — CONTRAT NORMATIF
//!
//! Le document normatif est `crates/constat-verify/FORMAT.md` : c'est lui
//! qu'un auditeur réimplémente. Cet exporteur le produit exactement :
//!
//! ```text
//! <dir>/
//! ├── pubkey.bin           # clé publique Ed25519 du signataire : 32 octets bruts
//! ├── 0.cbor               # entrée de journal 0 (la genèse), CBOR canonique,
//! │                        # signature INCLUSE
//! ├── 1.cbor … N.cbor      # entrées suivantes — indices consécutifs, sans trou
//! ├── snapshots/<hex>.cbor # un snapshot par fichier, nommé par son empreinte
//! └── blobs/<hex>.cbor     # un blob par fichier, NON compressé, nommé par
//!                          # son empreinte
//! ```
//!
//! Propriétés du format :
//! - **les objets de `snapshots/` et `blobs/` sont auto-vérifiants** : le nom
//!   du fichier est l'empreinte BLAKE3 de son contenu (les octets canoniques,
//!   tels qu'écrits) — `blake3(fichier) == nom` ;
//! - l'empreinte d'une entrée `i` est `blake3(octets de i.cbor)` : c'est elle
//!   que l'entrée `i+1` porte dans `prev`, et celle de la dernière entrée est
//!   la racine à ancrer (§6.3) ;
//! - les blobs sont exportés **décompressés** : le vérificateur n'a besoin ni
//!   de zstd ni de redb, seulement de BLAKE3, d'Ed25519 et d'un décodeur CBOR ;
//! - seuls les objets **atteignables depuis le journal** sont exportés
//!   (entrée → snapshots → blobs) : l'export est exactement la clôture de la
//!   preuve, rien d'autre ;
//! - l'export est déterministe : deux magasins au même contenu produisent des
//!   exports identiques à l'octet près ;
//! - un objet référencé mais **absent** du magasin est toléré si — et
//!   seulement si — son empreinte figure dans le manifeste d'un
//!   enregistrement de purge présent ([`crate::purge`], §16) : la clôture
//!   exportée est alors « tout ce qui existe encore, plus la déclaration de
//!   ce qui a été purgé », et `constat-verify` sait la lire (FORMAT.md,
//!   § « Objets purgés »). Une absence NON déclarée reste une erreur.
//!
//! L'algorithme de vérification complet (7 étapes) est documenté dans
//! `crates/constat-verify/FORMAT.md`.

use std::fs;
use std::path::Path;

use constat_model::{to_canonical_bytes, BlobHash};
use ed25519_dalek::VerifyingKey;

use crate::{JournalEntry, JournalId, MultiJournalStore, Store, StoreError};

/// Nom du fichier contenant la clé publique Ed25519 (32 octets bruts).
pub const PUBKEY_FILE: &str = "pubkey.bin";
/// Sous-répertoire des snapshots.
pub const SNAPSHOTS_DIR: &str = "snapshots";
/// Sous-répertoire des blobs (décompressés).
pub const BLOBS_DIR: &str = "blobs";

fn io_err(what: &str, e: std::io::Error) -> StoreError {
    StoreError::Backend(format!("export ({what}) : {e}"))
}

/// Écrit `bytes` dans `dir/<hex>.cbor` si le fichier n'existe pas déjà
/// (les objets sont adressés par contenu, donc immuables).
fn write_object(dir: &Path, hex: &str, bytes: &[u8]) -> Result<(), StoreError> {
    let path = dir.join(format!("{hex}.cbor"));
    if path.exists() {
        return Ok(());
    }
    fs::write(&path, bytes).map_err(|e| io_err(&format!("objet {hex}"), e))
}

/// Exporte la clôture complète de la preuve vers `dir` (créé si nécessaire),
/// au format normatif de `constat-verify` (voir le rustdoc du module).
///
/// `public_key` est la clé publique du signataire du journal : elle est
/// écrite dans `pubkey.bin`, et c'est avec elle que le vérificateur
/// contrôlera chaque signature.
///
/// L'export parcourt le journal et suit les références : entrées → snapshots
/// → blobs. Un objet référencé mais absent du magasin fait échouer l'export
/// ([`StoreError::NotFound`]) — un export partiel ne serait pas une preuve —
/// **sauf** si son absence est déclarée par un enregistrement de purge
/// présent ([`crate::declared_purged`]) : la purge journalisée (§16) est la
/// seule absence honnête, et le vérificateur la contrôle.
/// Un répertoire contenant déjà un export **plus long** (un fichier d'entrée
/// au-delà de la dernière écrite) fait échouer l'export : un fichier
/// résiduel casserait la vérification — exportez vers un répertoire propre.
pub fn export_store<S: Store + ?Sized>(
    store: &S,
    dir: &Path,
    public_key: &VerifyingKey,
) -> Result<(), StoreError> {
    let entries = store.entries()?;
    export_entries(store, dir, public_key.as_bytes(), &entries)
}

/// Exporte **un journal nommé** vers `dir`, au même layout normatif
/// (`FORMAT.md`) que [`export_store`] : un export = un journal d'un
/// signataire, `pubkey.bin` = la clé du journal ([`JournalId`]).
///
/// Un serveur multi-agents exporte ainsi N répertoires — un par clé — chacun
/// vérifiable indépendamment par `constat-verify`. La clôture exportée est
/// celle de **ce** journal uniquement (ses entrées → leurs snapshots → leurs
/// blobs) ; les objets partagés avec d'autres journaux sont recopiés dans
/// chaque export concerné, puisque chaque répertoire doit se suffire.
///
/// [`export_store`] reste l'export du journal par défaut — sémantique
/// inchangée. Mêmes règles d'échec que lui (objet manquant, entrée
/// résiduelle d'un export plus long).
pub fn export_journal<S: MultiJournalStore + ?Sized>(
    store: &S,
    dir: &Path,
    journal_id: &JournalId,
) -> Result<(), StoreError> {
    let entries = store.entries_of(journal_id)?;
    export_entries(store, dir, journal_id, &entries)
}

/// Cœur commun des deux exports : écrit `pubkey.bin` (32 octets bruts) puis
/// la clôture de la chaîne `entries` (entrées → snapshots → blobs), au
/// layout normatif du module.
fn export_entries<S: Store + ?Sized>(
    store: &S,
    dir: &Path,
    public_key: &[u8; 32],
    entries: &[(BlobHash, JournalEntry)],
) -> Result<(), StoreError> {
    let snapshots_dir = dir.join(SNAPSHOTS_DIR);
    let blobs_dir = dir.join(BLOBS_DIR);
    for d in [dir, &snapshots_dir, &blobs_dir] {
        fs::create_dir_all(d).map_err(|e| io_err("création des répertoires", e))?;
    }

    fs::write(dir.join(PUBKEY_FILE), public_key).map_err(|e| io_err(PUBKEY_FILE, e))?;

    // Absences tolérées : les empreintes déclarées purgées par les
    // enregistrements `constat.purge` atteignables depuis CE journal (§16).
    // Tout autre objet manquant fait échouer l'export, comme avant.
    let purged = crate::purge::declared_purged(store, entries)?;

    for (index, (_hash, entry)) in entries.iter().enumerate() {
        // Entrée complète, signature incluse : blake3(fichier) est l'empreinte
        // de chaînage que l'entrée suivante porte dans `prev`.
        let bytes = to_canonical_bytes(entry)?;
        fs::write(dir.join(format!("{index}.cbor")), &bytes)
            .map_err(|e| io_err(&format!("entrée {index}"), e))?;

        for snapshot_hash in &entry.snapshots {
            let snapshot = match store.get_snapshot(snapshot_hash) {
                Ok(snapshot) => snapshot,
                // Purgé ET déclaré : absence honnête, le vérificateur la
                // contrôlera contre le manifeste. Rien à exporter.
                Err(StoreError::NotFound(_)) if purged.contains(snapshot_hash) => continue,
                Err(e) => return Err(e),
            };
            let snapshot_bytes = to_canonical_bytes(&snapshot)?;
            write_object(&snapshots_dir, &snapshot_hash.to_hex(), &snapshot_bytes)?;

            for blob_hash in snapshot.blobs.values() {
                let blob = match store.get_blob(blob_hash) {
                    Ok(blob) => blob,
                    Err(StoreError::NotFound(_)) if purged.contains(blob_hash) => continue,
                    Err(e) => return Err(e),
                };
                let blob_bytes = to_canonical_bytes(&blob)?;
                write_object(&blobs_dir, &blob_hash.to_hex(), &blob_bytes)?;
            }
        }
    }

    // Un fichier d'entrée résiduel (export précédent plus long) rendrait
    // l'export incohérent : le vérificateur lirait une entrée de trop.
    let stale = dir.join(format!("{}.cbor", entries.len()));
    if stale.exists() {
        return Err(StoreError::Backend(format!(
            "export : le répertoire contient déjà une entrée résiduelle ({}) — \
             exportez vers un répertoire propre",
            stale.display()
        )));
    }
    Ok(())
}
