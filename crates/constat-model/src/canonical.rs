//! Sérialisation canonique et empreintes (§15 — le détail qui casse tout).
//!
//! Toute la chaîne de preuve repose sur des empreintes, et une empreinte ne
//! vaut que si les **mêmes données produisent toujours exactement les mêmes
//! octets**. D'où les règles appliquées ici et dans tout le modèle :
//!
//! - encodage CBOR déterministe (`ciborium`) : entiers en forme minimale,
//!   champs de structures dans l'ordre de déclaration — jamais de JSON pour
//!   ce qui est haché ;
//! - `BTreeMap` partout dans les structures hachées, jamais `HashMap` ;
//! - aucun flottant dans une [`Value`](crate::Value) ;
//! - dates en entier UTC de précision fixe ([`Timestamp`](crate::Timestamp)).
//!
//! La propriété vérifiée par les tests (des milliers de valeurs générées) :
//! `hash(decode(encode(x))) == hash(x)`, et plus fort encore
//! `encode(decode(encode(x))) == encode(x)`. Des empreintes de valeurs
//! connues sont en outre figées en tests de non-régression : tout changement
//! d'encodage — même involontaire — fait échouer la suite.

use crate::store_objects::BlobHash;
use serde::{Deserialize, Serialize};

/// Erreurs du cœur.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("échec d'encodage canonique : {0}")]
    Encode(String),
    #[error("échec de décodage : {0}")]
    Decode(String),
}

/// Encode en CBOR canonique (déterministe). Jamais de JSON pour ce qui est haché.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ModelError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| ModelError::Encode(e.to_string()))?;
    Ok(out)
}

/// Décode depuis l'encodage canonique.
pub fn from_canonical_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ModelError> {
    ciborium::from_reader(bytes).map_err(|e| ModelError::Decode(e.to_string()))
}

/// Empreinte BLAKE3 de l'encodage canonique d'une valeur.
///
/// Attention : pour un [`Blob`](crate::Blob), passer par
/// [`blob_hash`](crate::blob_hash) qui garantit l'ordre canonique des faits.
pub fn hash_canonical<T: Serialize>(value: &T) -> Result<BlobHash, ModelError> {
    let bytes = to_canonical_bytes(value)?;
    Ok(BlobHash(*blake3::hash(&bytes).as_bytes()))
}
