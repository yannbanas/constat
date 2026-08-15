//! Rotation de la clé de signature **journalisée** — extension ADDITIVE.
//!
//! > Une clé qui ne tourne jamais est une clé qui finira par fuir. Mais une
//! > clé qui change sans trace casserait la vérification : les entrées
//! > suivantes ne se vérifieraient plus avec la clé publique distribuée. La
//! > rotation doit donc être **déclarée dans le journal lui-même**, signée
//! > par l'ancienne clé — c'est elle qui délègue.
//!
//! # Le modèle : la rotation est un constat comme un autre (motif de la purge)
//!
//! L'enregistrement de rotation est un [`Blob`] du collecteur réservé
//! [`ROTATION_COLLECTOR`] (`constat.rotation`), référencé par un [`Snapshot`]
//! de la machine [`ROTATION_ASSET`] (`constat` — l'outil lui-même), lui-même
//! référencé par une **nouvelle entrée signée par l'ANCIENNE clé**. Rien
//! n'est réécrit : la chaîne existante reste intacte au bit près. Les entrées
//! **suivantes** sont signées par la NOUVELLE clé.
//!
//! Contenu du blob (normatif — voir `crates/constat-verify/FORMAT.md`,
//! § 4 ter « Rotation de clé ») :
//!
//! - `raw` : un document texte lisible (date, ancienne clé hex, nouvelle clé
//!   hex, motif optionnel) ;
//! - `facts` : une entité `rotation:<horodatage ms>` portant :
//!
//! | attribut | type | contenu |
//! |---|---|---|
//! | `rotation.old_key` | `Fingerprint` | les 32 octets de l'ancienne clé publique |
//! | `rotation.new_key` | `Fingerprint` | les 32 octets de la nouvelle clé publique |
//! | `rotation.reason`  | `Text` ou `Absent` | motif (une ligne), ou absent |
//!
//! # La clé courante d'une chaîne
//!
//! La clé courante commence à la **clé de genèse** (celle de `pubkey.bin`
//! pour un export, le [`crate::JournalId`] pour un journal nommé), puis
//! chaque rotation **valide** la remplace. Une rotation n'est valide que si :
//!
//! 1. l'entrée qui la porte est signée par la clé courante (l'ancienne clé
//!    délègue — personne d'autre ne peut la remplacer) ;
//! 2. `rotation.old_key` est égal à la clé courante — sinon c'est une
//!    tentative d'usurpation, et toute la chaîne est refusée
//!    ([`ChainError::RotationInvalide`]).
//!
//! **L'identité du journal ne change pas** : un journal nommé reste identifié
//! par sa clé de **genèse** ([`crate::JournalId`]), quelle que soit la clé de
//! signature courante. C'est ce qui rend les listes d'autorisation stables
//! (elles listent des identités, pas des clés du moment) et l'historique
//! continu (« qui a signé quoi, quand » se lit dans la chaîne).
//!
//! # Interaction avec la purge (§16)
//!
//! Une entrée de rotation n'est **jamais purgeable** — même règle que les
//! enregistrements de purge, appliquée dans [`crate::purge::plan_purge`] :
//! purger une rotation rendrait toute la suite de la chaîne invérifiable
//! (la clé courante deviendrait introuvable). Côté vérificateur, un blob de
//! rotation absent — même « déclaré purgé » — est un refus, pas une
//! tolérance.

use constat_model::{Blob, BlobHash, CollectorId, Fact, ModelError, Snapshot, Timestamp, Value};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::journal::{append_signed, entry_hash, signable_bytes, ChainError};
use crate::{JournalEntry, Signer, Store, StoreError};

/// Collecteur réservé des enregistrements de rotation. Aucun collecteur de
/// machine ne doit porter ce nom.
pub const ROTATION_COLLECTOR: &str = "constat.rotation";

/// Machine (asset) des snapshots de rotation : l'outil lui-même, comme pour
/// la purge ([`crate::purge::PURGE_ASSET`]).
pub const ROTATION_ASSET: &str = "constat";

/// Attribut : les 32 octets de l'ancienne clé publique (celle qui délègue).
pub const ATTR_ROTATION_OLD: &str = "rotation.old_key";
/// Attribut : les 32 octets de la nouvelle clé publique.
pub const ATTR_ROTATION_NEW: &str = "rotation.new_key";
/// Attribut : motif de la rotation (optionnel).
pub const ATTR_ROTATION_REASON: &str = "rotation.reason";

/// Erreur de lecture d'un blob de rotation : la déclaration est malformée ou
/// incohérente. Un vérificateur qui la rencontre doit **refuser** la chaîne :
/// sans rotation lisible, la clé courante est indéterminable.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// Le blob n'est pas du collecteur [`ROTATION_COLLECTOR`].
    #[error("collecteur « {0} » au lieu de « {ROTATION_COLLECTOR} »")]
    BadCollector(String),
    /// Un fait attendu est absent ou d'un type inattendu.
    #[error("fait {0} manquant ou mal typé")]
    MissingFact(&'static str),
    /// Un fait attendu apparaît plusieurs fois avec des valeurs distinctes.
    #[error("fait {0} en double")]
    DuplicateFact(&'static str),
    /// La déclaration est intérieurement incohérente (clé invalide,
    /// rotation vers la même clé).
    #[error("déclaration incohérente : {0}")]
    Incoherent(String),
    /// Échec d'encodage canonique.
    #[error(transparent)]
    Model(#[from] ModelError),
}

/// Une déclaration de rotation, décodée depuis un blob [`ROTATION_COLLECTOR`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationDeclaration {
    /// L'ancienne clé publique (32 octets) — celle qui signe l'entrée de
    /// rotation et délègue à la nouvelle.
    pub old_key: [u8; 32],
    /// La nouvelle clé publique (32 octets) — celle qui signe les entrées
    /// suivantes.
    pub new_key: [u8; 32],
    /// Motif, s'il a été déclaré.
    pub reason: Option<String>,
}

/// Ce qu'une vérification rotation-consciente rapporte en plus du verdict :
/// combien de rotations la chaîne contient, et quelle clé la termine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationTrace {
    /// Nombre de rotations valides rencontrées le long de la chaîne.
    pub rotations: usize,
    /// La clé courante au bout de la chaîne (la clé de genèse si aucune
    /// rotation) : c'est elle qui signera l'entrée suivante.
    pub final_key: [u8; 32],
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Date lisible pour le document brut : RFC 3339 quand la valeur le permet,
/// millisecondes brutes sinon (jamais d'échec pour un affichage).
fn readable(t: Timestamp) -> String {
    t.to_rfc3339().unwrap_or_else(|_| format!("{} ms", t.0))
}

/// Construit le blob de rotation (document brut + faits) d'une déclaration.
///
/// `at` est l'horodatage de la rotation : il nomme l'entité
/// (`rotation:<ms>`) et date le document. Le motif est ramené à une seule
/// ligne, comme celui de la purge.
pub fn build_rotation_blob(declaration: &RotationDeclaration, at: Timestamp) -> Blob {
    let reason = declaration
        .reason
        .as_ref()
        .map(|r| r.replace(['\r', '\n'], " ").trim().to_string());

    let mut raw = String::new();
    raw.push_str("Rotation de clé de signature — Constat\n");
    raw.push_str(&format!("Date : {} ({} ms)\n", readable(at), at.0));
    raw.push_str(&format!("Ancienne clé : {}\n", hex(&declaration.old_key)));
    raw.push_str(&format!("Nouvelle clé : {}\n", hex(&declaration.new_key)));
    match &reason {
        Some(reason) => raw.push_str(&format!("Motif : {reason}\n")),
        None => raw.push_str("Motif : (non déclaré)\n"),
    }
    raw.push_str(
        "\nCette entrée est signée par l'ANCIENNE clé : c'est elle qui délègue.\n\
         Les entrées suivantes du journal sont signées par la nouvelle clé.\n",
    );

    let entity = format!("rotation:{}", at.0);
    let facts = vec![
        Fact::new(
            entity.as_str(),
            ATTR_ROTATION_OLD,
            Value::Fingerprint(declaration.old_key),
        ),
        Fact::new(
            entity.as_str(),
            ATTR_ROTATION_NEW,
            Value::Fingerprint(declaration.new_key),
        ),
        match &reason {
            Some(reason) => Fact::new(entity.as_str(), ATTR_ROTATION_REASON, reason.clone()),
            None => Fact::new(entity.as_str(), ATTR_ROTATION_REASON, Value::Absent),
        },
    ];
    Blob::new(ROTATION_COLLECTOR, raw.into_bytes(), facts)
}

/// Relit une déclaration de rotation depuis un blob [`ROTATION_COLLECTOR`]
/// et vérifie sa cohérence interne :
///
/// - `rotation.old_key` et `rotation.new_key` présents, uniques ;
/// - la nouvelle clé est un point Ed25519 valide (elle devra vérifier des
///   signatures) ;
/// - ancienne et nouvelle clés distinctes (une rotation vers soi-même ne
///   délègue rien).
///
/// # Erreurs
///
/// [`RotationError`] si la déclaration est malformée ou incohérente — auquel
/// cas la chaîne qui la porte est invérifiable et doit être refusée.
pub fn parse_rotation_blob(blob: &Blob) -> Result<RotationDeclaration, RotationError> {
    if blob.collector.0 != ROTATION_COLLECTOR {
        return Err(RotationError::BadCollector(blob.collector.0.clone()));
    }

    fn set_once<T: PartialEq>(
        slot: &mut Option<T>,
        value: T,
        name: &'static str,
    ) -> Result<(), RotationError> {
        match slot {
            Some(existing) if *existing == value => Ok(()),
            Some(_) => Err(RotationError::DuplicateFact(name)),
            None => {
                *slot = Some(value);
                Ok(())
            }
        }
    }

    let mut old_key: Option<[u8; 32]> = None;
    let mut new_key: Option<[u8; 32]> = None;
    let mut reason: Option<String> = None;
    for fact in &blob.facts {
        match (fact.attribute.0.as_str(), &fact.value) {
            (ATTR_ROTATION_OLD, Value::Fingerprint(v)) => {
                set_once(&mut old_key, *v, ATTR_ROTATION_OLD)?
            }
            (ATTR_ROTATION_NEW, Value::Fingerprint(v)) => {
                set_once(&mut new_key, *v, ATTR_ROTATION_NEW)?
            }
            (ATTR_ROTATION_REASON, Value::Text(v)) => {
                set_once(&mut reason, v.clone(), ATTR_ROTATION_REASON)?
            }
            _ => {}
        }
    }
    let old_key = old_key.ok_or(RotationError::MissingFact(ATTR_ROTATION_OLD))?;
    let new_key = new_key.ok_or(RotationError::MissingFact(ATTR_ROTATION_NEW))?;

    if old_key == new_key {
        return Err(RotationError::Incoherent(
            "rotation vers la même clé : rien n'est délégué".into(),
        ));
    }
    if VerifyingKey::from_bytes(&new_key).is_err() {
        return Err(RotationError::Incoherent(format!(
            "la nouvelle clé {} n'est pas une clé publique Ed25519 valide",
            hex(&new_key)
        )));
    }

    Ok(RotationDeclaration {
        old_key,
        new_key,
        reason,
    })
}

/// Effectue une rotation de clé **journalisée** : écrit le blob de rotation,
/// son snapshot (machine [`ROTATION_ASSET`], daté `at`) et une nouvelle
/// entrée **signée par l'ANCIENNE clé** — c'est elle qui délègue. Les
/// entrées suivantes doivent être signées par la nouvelle clé.
///
/// Retourne l'empreinte de l'entrée de rotation (la nouvelle racine) et
/// l'entrée elle-même, comme [`append_signed`].
///
/// ```
/// use constat_model::Timestamp;
/// use constat_store::{
///     append_signed, current_key, rotate_key, verify_chain_rotated, MemoryStore, Signer, Store,
/// };
///
/// let mut store = MemoryStore::new();
/// let old = Signer::generate();
/// let new = Signer::generate();
/// append_signed(&mut store, &old, vec![], Timestamp(1))?;
/// rotate_key(&mut store, &old, &new, Some("rotation planifiée"), Timestamp(2))?;
/// append_signed(&mut store, &new, vec![], Timestamp(3))?;
///
/// let entries = store.entries()?;
/// let genesis = old.verifying_key().to_bytes();
/// assert_eq!(current_key(&store, &genesis, &entries)?, new.verifying_key().to_bytes());
/// let trace = verify_chain_rotated(&store, &entries, &old.verifying_key()).unwrap();
/// assert_eq!(trace.rotations, 1);
/// # Ok::<(), constat_store::StoreError>(())
/// ```
pub fn rotate_key<S: Store + ?Sized>(
    store: &mut S,
    old: &Signer,
    new: &Signer,
    reason: Option<&str>,
    at: Timestamp,
) -> Result<(BlobHash, JournalEntry), StoreError> {
    let declaration = RotationDeclaration {
        old_key: old.verifying_key().to_bytes(),
        new_key: new.verifying_key().to_bytes(),
        reason: reason.map(str::to_string),
    };
    let blob = build_rotation_blob(&declaration, at);
    let blob_hash = store.put_blob(&blob)?;
    let snapshot = Snapshot::new(
        ROTATION_ASSET,
        at,
        [(CollectorId(ROTATION_COLLECTOR.to_string()), blob_hash)]
            .into_iter()
            .collect(),
    );
    let snapshot_hash = store.put_snapshot(&snapshot)?;
    // Signée par l'ANCIENNE clé : la délégation vient de celle qui détenait
    // la chaîne. append_signed raccorde `prev` à la dernière entrée.
    append_signed(store, old, vec![snapshot_hash], at)
}

/// Les enregistrements de rotation atteignables depuis `entries`, dans
/// l'ordre de la chaîne : `(index d'entrée, déclaration)`.
///
/// Un snapshot absent du magasin est ignoré (on ne peut pas savoir ce qu'il
/// contenait — la vérification de signatures échouera d'elle-même si une
/// rotation a été escamotée) ; un blob de rotation **absent alors que son
/// snapshot est présent** est une erreur : une rotation illisible rend la
/// clé courante indéterminable.
fn rotations_of<S: Store + ?Sized>(
    store: &S,
    entries: &[(BlobHash, JournalEntry)],
) -> Result<Vec<(usize, RotationDeclaration)>, StoreError> {
    let rotation_collector = CollectorId(ROTATION_COLLECTOR.to_string());
    let mut out = Vec::new();
    for (index, (_, entry)) in entries.iter().enumerate() {
        for snapshot_hash in &entry.snapshots {
            if !store.has_snapshot(snapshot_hash)? {
                continue;
            }
            let snapshot = store.get_snapshot(snapshot_hash)?;
            let Some(blob_hash) = snapshot.blobs.get(&rotation_collector) else {
                continue;
            };
            if !store.has_blob(blob_hash)? {
                return Err(StoreError::ChainBroken(format!(
                    "entrée {index} : blob de rotation {} absent — une rotation n'est \
                     jamais purgeable, la clé courante est indéterminable",
                    blob_hash.to_hex()
                )));
            }
            let blob = store.get_blob(blob_hash)?;
            let declaration = parse_rotation_blob(&blob).map_err(|e| {
                StoreError::ChainBroken(format!(
                    "entrée {index} : déclaration de rotation illisible (blob {}) : {e}",
                    blob_hash.to_hex()
                ))
            })?;
            out.push((index, declaration));
        }
    }
    Ok(out)
}

/// La **clé courante** d'une chaîne : la clé de genèse `genesis`, puis
/// chaque rotation valide la remplace.
///
/// Ne vérifie pas les signatures (c'est le rôle de [`verify_chain_rotated`]
/// et des gardes d'append) ; vérifie en revanche que chaque rotation part
/// bien de la clé courante — sinon [`StoreError::ChainBroken`] : une
/// rotation dont `old_key` n'est pas la clé courante est une usurpation.
pub fn current_key<S: Store + ?Sized>(
    store: &S,
    genesis: &[u8; 32],
    entries: &[(BlobHash, JournalEntry)],
) -> Result<[u8; 32], StoreError> {
    let mut current = *genesis;
    for (index, declaration) in rotations_of(store, entries)? {
        if declaration.old_key != current {
            return Err(StoreError::ChainBroken(format!(
                "entrée {index} : rotation usurpée — old_key = {} mais la clé courante \
                 de la chaîne est {}",
                hex(&declaration.old_key),
                hex(&current)
            )));
        }
        current = declaration.new_key;
    }
    Ok(current)
}

/// La **clé de genèse** d'une chaîne, quand on ne connaît que la clé
/// courante `current` : la clé ne change que par rotation, donc la genèse
/// est l'`old_key` de la **première** rotation — et `current` s'il n'y en a
/// aucune.
///
/// C'est ce que l'agent utilise pour annoncer son **identité** (la clé de
/// genèse, stable) au serveur, alors que son fichier de clés ne contient
/// plus que la clé courante.
pub fn genesis_key<S: Store + ?Sized>(
    store: &S,
    entries: &[(BlobHash, JournalEntry)],
    current: &[u8; 32],
) -> Result<[u8; 32], StoreError> {
    Ok(rotations_of(store, entries)?
        .first()
        .map(|(_, declaration)| declaration.old_key)
        .unwrap_or(*current))
}

/// [`crate::verify_chain`], en suivant la **clé courante** le long de la
/// chaîne : les signatures se vérifient avec la clé de genèse `genesis`
/// jusqu'à la première rotation valide, puis avec la nouvelle clé, etc.
///
/// A besoin du magasin pour lire les blobs de rotation (l'entrée ne porte
/// que des empreintes). Sur une chaîne sans rotation, le verdict est
/// identique à [`crate::verify_chain`] — les journaux existants se vérifient
/// exactement comme avant.
///
/// Une rotation n'est suivie que si elle est **valide** :
/// - l'entrée qui la porte est signée par la clé courante (vérifié comme
///   toutes les signatures) ;
/// - `rotation.old_key` est la clé courante — sinon
///   [`ChainError::RotationInvalide`], la chaîne entière est refusée ;
/// - la déclaration est lisible et cohérente (sinon refus aussi).
///
/// **Rappel §6.2** : comme [`crate::verify_chain`], cette fonction prouve la
/// cohérence interne, pas la non-répudiation — la racine doit être comparée
/// à une racine ancrée hors du système.
pub fn verify_chain_rotated<S: Store + ?Sized>(
    store: &S,
    entries: &[(BlobHash, JournalEntry)],
    genesis: &VerifyingKey,
) -> Result<RotationTrace, ChainError> {
    let rotation_collector = CollectorId(ROTATION_COLLECTOR.to_string());
    let mut current = *genesis;
    let mut rotations = 0usize;
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

        // 3. Signature Ed25519, vérifiée avec la clé COURANTE : l'entrée de
        // rotation elle-même est signée par l'ancienne clé (la délégation),
        // les suivantes par la nouvelle.
        let bytes =
            signable_bytes(entry).map_err(|source| ChainError::Encoding { index, source })?;
        let signature = Signature::try_from(entry.signature.as_slice()).map_err(|_| {
            ChainError::MalformedSignature {
                index,
                len: entry.signature.len(),
            }
        })?;
        current
            .verify_strict(&bytes, &signature)
            .map_err(|_| ChainError::BadSignature { index })?;

        // 4. Rotations portées par cette entrée : la clé courante bascule
        // pour les entrées SUIVANTES.
        for snapshot_hash in &entry.snapshots {
            let has = store
                .has_snapshot(snapshot_hash)
                .map_err(|e| rotation_invalide(index, format!("magasin illisible : {e}")))?;
            if !has {
                continue;
            }
            let snapshot = store
                .get_snapshot(snapshot_hash)
                .map_err(|e| rotation_invalide(index, format!("magasin illisible : {e}")))?;
            let Some(blob_hash) = snapshot.blobs.get(&rotation_collector) else {
                continue;
            };
            let blob = match store.get_blob(blob_hash) {
                Ok(blob) => blob,
                Err(StoreError::NotFound(_)) => {
                    return Err(rotation_invalide(
                        index,
                        format!(
                            "blob de rotation {} absent — une rotation n'est jamais purgeable",
                            blob_hash.to_hex()
                        ),
                    ))
                }
                Err(e) => return Err(rotation_invalide(index, format!("magasin illisible : {e}"))),
            };
            let declaration = parse_rotation_blob(&blob)
                .map_err(|e| rotation_invalide(index, format!("déclaration illisible : {e}")))?;
            if declaration.old_key != current.to_bytes() {
                return Err(rotation_invalide(
                    index,
                    format!(
                        "old_key = {} mais la clé courante de la chaîne est {} — \
                         tentative d'usurpation",
                        hex(&declaration.old_key),
                        hex(&current.to_bytes())
                    ),
                ));
            }
            current = VerifyingKey::from_bytes(&declaration.new_key).map_err(|_| {
                rotation_invalide(
                    index,
                    format!(
                        "la nouvelle clé {} n'est pas une clé Ed25519 valide",
                        hex(&declaration.new_key)
                    ),
                )
            })?;
            rotations += 1;
        }

        prev_hash = Some(*claimed);
    }

    Ok(RotationTrace {
        rotations,
        final_key: current.to_bytes(),
    })
}

fn rotation_invalide(index: usize, detail: String) -> ChainError {
    ChainError::RotationInvalide { index, detail }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn declaration() -> RotationDeclaration {
        let old = Signer::generate().verifying_key().to_bytes();
        let new = Signer::generate().verifying_key().to_bytes();
        RotationDeclaration {
            old_key: old,
            new_key: new,
            reason: Some("rotation planifiée".to_string()),
        }
    }

    /// Aller-retour : le blob construit se relit à l'identique.
    #[test]
    fn aller_retour_du_blob_de_rotation() {
        let decl = declaration();
        let blob = build_rotation_blob(&decl, Timestamp(3_000));
        assert_eq!(blob.collector.0, ROTATION_COLLECTOR);
        assert_eq!(parse_rotation_blob(&blob).unwrap(), decl);
    }

    /// Sans motif : le fait `rotation.reason` vaut `Absent`, la relecture
    /// rend `None`.
    #[test]
    fn motif_absent_reste_absent() {
        let mut decl = declaration();
        decl.reason = None;
        let blob = build_rotation_blob(&decl, Timestamp(3_000));
        assert_eq!(parse_rotation_blob(&blob).unwrap(), decl);
    }

    /// Une rotation vers la même clé ne délègue rien : refusée.
    #[test]
    fn rotation_vers_soi_meme_refusee() {
        let mut decl = declaration();
        decl.new_key = decl.old_key;
        let blob = build_rotation_blob(&decl, Timestamp(3_000));
        assert!(matches!(
            parse_rotation_blob(&blob),
            Err(RotationError::Incoherent(_))
        ));
    }

    /// Un blob d'un autre collecteur est refusé d'emblée.
    #[test]
    fn collecteur_etranger_refuse() {
        let mut blob = build_rotation_blob(&declaration(), Timestamp(3_000));
        blob.collector = CollectorId("linux.sshd".to_string());
        assert!(matches!(
            parse_rotation_blob(&blob),
            Err(RotationError::BadCollector(_))
        ));
    }

    /// Une nouvelle clé qui n'est pas un point Ed25519 valide est refusée :
    /// elle ne pourra jamais vérifier une signature.
    #[test]
    fn nouvelle_cle_invalide_refusee() {
        // Le premier motif constant qui n'est PAS un encodage de point
        // valide (environ la moitié des octets candidats ne le sont pas).
        let invalid = (0u8..=255)
            .map(|b| [b; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("au moins un motif d'octets n'encode pas un point valide");
        let mut decl = declaration();
        decl.new_key = invalid;
        let blob = build_rotation_blob(&decl, Timestamp(3_000));
        assert!(matches!(
            parse_rotation_blob(&blob),
            Err(RotationError::Incoherent(_))
        ));
    }

    /// Le collecteur de rotation appartient à l'espace de noms réservé
    /// partagé : l'agent et le serveur s'appuient dessus pour le distinguer
    /// d'une collecte ordinaire (défense en profondeur).
    #[test]
    fn rotation_collector_est_reserve() {
        assert!(ROTATION_COLLECTOR.starts_with(crate::RESERVED_COLLECTOR_PREFIX));
        assert!(crate::is_reserved_collector(&CollectorId(
            ROTATION_COLLECTOR.to_string()
        )));
    }
}
