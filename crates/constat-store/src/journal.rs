//! Journal Merkle : construction, signature et vérification de la chaîne.
//!
//! Chaque entrée contient l'empreinte de la précédente : modifier ou insérer
//! une entrée au milieu casse la chaîne, et c'est détectable immédiatement
//! (§6.1). La racine ([`crate::Store::root`]) — l'empreinte de la dernière
//! entrée — est ce qu'on ancre à l'extérieur (§6.3).
//!
//! # Ce que la chaîne ne protège PAS — à lire avant de s'y fier (§6.2)
//!
//! **La troncature par le détenteur de la clé.** Celui qui contrôle à la fois
//! le magasin et la clé de signature peut supprimer la fin du journal, ou tout
//! effacer et repartir à zéro : la chaîne restante est parfaitement valide, et
//! [`verify_chain`] ne dira rien. Or c'est précisément l'administrateur audité
//! qui fait tourner l'outil.
//!
//! > Sans ancrage externe, le journal prouve la **cohérence interne**, pas la
//! > **non-répudiation**. La détection de la troncature exige de comparer la
//! > racine à une racine ancrée hors du système (courriel au RSSI, dépôt tiers,
//! > horodatage qualifié RFC 3161 — c'est le rôle de `constat-anchor`).
//!
//! Cette limite doit rester écrite noir sur blanc dans la documentation et
//! dans chaque dossier généré.
//!
//! # Schéma de signature (contrat inter-crates)
//!
//! Voir [`crate::signer`] : octets signables = CBOR canonique de l'entrée avec
//! `signature` vidé ; empreinte de chaînage = `hash_canonical` de l'entrée
//! complète, signature incluse.

use constat_model::{hash_canonical, to_canonical_bytes, BlobHash, ModelError, Timestamp};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{JournalEntry, Signer, Store, StoreError};

/// Octets signables d'une entrée : encodage canonique de l'entrée avec le
/// champ `signature` **vidé**. C'est sur ces octets que porte la signature
/// Ed25519 — `constat-verify` recalcule exactement la même chose.
pub fn signable_bytes(entry: &JournalEntry) -> Result<Vec<u8>, ModelError> {
    let unsigned = JournalEntry {
        prev: entry.prev,
        snapshots: entry.snapshots.clone(),
        at: entry.at,
        signature: Vec::new(),
    };
    to_canonical_bytes(&unsigned)
}

/// Empreinte d'une entrée pour le chaînage `prev` : encodage canonique de
/// l'entrée **complète**, signature incluse.
pub fn entry_hash(entry: &JournalEntry) -> Result<BlobHash, ModelError> {
    hash_canonical(entry)
}

/// Construit, signe et ajoute une entrée au journal.
///
/// `prev` est déterminé automatiquement : empreinte de la dernière entrée du
/// magasin, `None` si le journal est vide (genèse). Retourne l'empreinte de
/// la nouvelle entrée (la nouvelle racine) et l'entrée elle-même.
///
/// ```
/// use constat_model::Timestamp;
/// use constat_store::{append_signed, verify_chain, MemoryStore, Signer, Store};
///
/// let mut store = MemoryStore::new();
/// let signer = Signer::generate();
/// let (genesis, entry) = append_signed(&mut store, &signer, vec![], Timestamp(1))?;
/// assert!(entry.prev.is_none());
/// let (root, entry2) = append_signed(&mut store, &signer, vec![], Timestamp(2))?;
/// assert_eq!(entry2.prev, Some(genesis));
/// assert_eq!(store.root()?, Some(root));
/// verify_chain(&store.entries()?, &signer.verifying_key()).unwrap();
/// # Ok::<(), constat_store::StoreError>(())
/// ```
pub fn append_signed<S: Store + ?Sized>(
    store: &mut S,
    signer: &Signer,
    snapshots: Vec<BlobHash>,
    at: Timestamp,
) -> Result<(BlobHash, JournalEntry), StoreError> {
    let prev = store.last_entry()?.map(|(hash, _)| hash);
    let entry = signer.sign_entry(prev, snapshots, at)?;
    let hash = store.append_entry(&entry)?;
    Ok((hash, entry))
}

/// Défaut détecté par [`verify_chain`]. Chaque variante désigne l'index fautif.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// L'encodage canonique d'une entrée a échoué (données inexploitables).
    #[error("entrée {index} : encodage canonique impossible : {source}")]
    Encoding {
        index: usize,
        #[source]
        source: ModelError,
    },

    /// L'empreinte recalculée de l'entrée ne correspond pas à celle annoncée :
    /// l'entrée stockée a été modifiée ou remplacée.
    #[error("entrée {index} : empreinte annoncée {claimed}, recalculée {actual} — entrée altérée")]
    HashMismatch {
        index: usize,
        claimed: String,
        actual: String,
    },

    /// L'entrée de genèse (index 0) référence une entrée précédente.
    #[error("entrée 0 (genèse) : `prev` devrait être absent, or elle référence {found}")]
    BadGenesis { found: String },

    /// Le champ `prev` d'une entrée ne référence pas l'entrée précédente :
    /// insertion, suppression ou réordonnancement au milieu de la chaîne.
    #[error("entrée {index} : `prev` = {found} ne référence pas l'entrée précédente ({expected}) — chaîne rompue")]
    BrokenLink {
        index: usize,
        expected: String,
        found: String,
    },

    /// La signature n'a pas la forme d'une signature Ed25519 (64 octets).
    #[error("entrée {index} : signature malformée ({len} octets, 64 attendus)")]
    MalformedSignature { index: usize, len: usize },

    /// La signature ne vérifie pas avec la clé publique fournie.
    #[error("entrée {index} : signature invalide pour la clé publique fournie")]
    BadSignature { index: usize },
}

/// Vérifie l'intégrité complète d'une chaîne d'entrées, dans l'ordre d'append.
///
/// Pour chaque entrée :
/// 1. recalcule son empreinte ([`entry_hash`]) et la compare à celle annoncée ;
/// 2. vérifie le chaînage : `prev` de l'entrée *i* = empreinte de l'entrée
///    *i−1* (et absent pour la genèse) ;
/// 3. vérifie la signature Ed25519 sur les [`signable_bytes`] avec `pubkey`.
///
/// Une chaîne vide est valide (magasin neuf).
///
/// **Rappel §6.2** : cette fonction prouve la cohérence interne. Elle ne
/// détecte PAS la troncature de la fin du journal par le détenteur de la clé —
/// pour cela, comparer [`crate::Store::root`] à une racine ancrée à l'extérieur.
pub fn verify_chain(
    entries: &[(BlobHash, JournalEntry)],
    pubkey: &VerifyingKey,
) -> Result<(), ChainError> {
    let mut prev_hash: Option<BlobHash> = None;
    for (index, (claimed, entry)) in entries.iter().enumerate() {
        // 1. Empreinte : l'entrée stockée est-elle bien celle annoncée ?
        let actual = entry_hash(entry).map_err(|source| ChainError::Encoding { index, source })?;
        if actual != *claimed {
            return Err(ChainError::HashMismatch {
                index,
                claimed: claimed.to_hex(),
                actual: actual.to_hex(),
            });
        }

        // 2. Chaînage : `prev` référence-t-il l'entrée précédente ?
        match (index, entry.prev, prev_hash) {
            (0, None, _) => {}
            (0, Some(found), _) => {
                return Err(ChainError::BadGenesis {
                    found: found.to_hex(),
                })
            }
            (_, Some(found), Some(expected)) if found == expected => {}
            (_, found, expected) => {
                return Err(ChainError::BrokenLink {
                    index,
                    expected: expected.map(|h| h.to_hex()).unwrap_or_default(),
                    found: found.map(|h| h.to_hex()).unwrap_or_else(|| "absent".into()),
                });
            }
        }

        // 3. Signature Ed25519 sur les octets signables (signature vidée).
        let bytes =
            signable_bytes(entry).map_err(|source| ChainError::Encoding { index, source })?;
        let signature = Signature::try_from(entry.signature.as_slice()).map_err(|_| {
            ChainError::MalformedSignature {
                index,
                len: entry.signature.len(),
            }
        })?;
        pubkey
            .verify_strict(&bytes, &signature)
            .map_err(|_| ChainError::BadSignature { index })?;

        prev_hash = Some(*claimed);
    }
    Ok(())
}
