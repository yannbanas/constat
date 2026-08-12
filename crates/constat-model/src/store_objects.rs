//! Objets du magasin adressé par contenu, calqués sur Git (§3.3) :
//! blobs, snapshots, empreintes.
//!
//! # Ordre canonique des faits
//!
//! Un [`Blob`] porte ses faits dans un `Vec` : l'ordre d'insertion dépend du
//! collecteur, mais **le contenu est un ensemble**. Deux blobs aux mêmes
//! faits dans des ordres différents doivent produire **la même empreinte**,
//! sinon la déduplication s'effondre. D'où [`blob_hash`], qui trie (et
//! dédoublonne) les faits avant hachage. Ne jamais hacher un `Blob` avec
//! [`hash_canonical`](crate::hash_canonical) directement.

use crate::canonical::{hash_canonical, ModelError};
use crate::fact::Fact;
use crate::ids::{AssetId, CollectorId};
use crate::time::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Empreinte BLAKE3 (32 octets) d'un objet encodé canoniquement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlobHash(pub [u8; 32]);

impl BlobHash {
    /// Représentation hexadécimale complète (pour affichage et preuve).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Hexadécimal tronqué façon Git, 8 caractères, ex. `"7f3a91c2"`.
    /// Pour l'affichage compact ; la preuve exige [`BlobHash::to_hex`].
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }

    /// Reconstruit une empreinte depuis ses 64 caractères hexadécimaux.
    pub fn from_hex(s: &str) -> Result<Self, ModelError> {
        let bytes = hex::decode(s)
            .map_err(|e| ModelError::Decode(format!("empreinte hexadécimale invalide : {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
            ModelError::Decode(format!("empreinte de {} octets, 32 attendus", b.len()))
        })?;
        Ok(BlobHash(arr))
    }
}

/// Affichage tronqué façon Git : `7f3a91c2…` (voir §10.1).
impl fmt::Display for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}…", self.short_hex())
    }
}

/// Les faits + le brut d'UN collecteur sur UNE machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    pub collector: CollectorId,
    /// Artefact brut, tel que collecté, APRÈS expurgation.
    pub raw: Vec<u8>,
    /// Faits extraits, triés (ordre canonique).
    pub facts: Vec<Fact>,
}

impl Blob {
    /// Construit un blob en **canonicalisant** les faits (tri + suppression
    /// des doublons exacts). C'est le constructeur à utiliser partout.
    pub fn new(collector: impl Into<CollectorId>, raw: Vec<u8>, facts: Vec<Fact>) -> Self {
        let mut blob = Blob {
            collector: collector.into(),
            raw,
            facts,
        };
        blob.canonicalize();
        blob
    }

    /// Met les faits en ordre canonique : tri total, puis suppression des
    /// doublons exacts (un fait répété n'apporte aucune information).
    pub fn canonicalize(&mut self) {
        self.facts.sort();
        self.facts.dedup();
    }

    /// Les faits sont-ils déjà en ordre canonique (strictement croissants) ?
    pub fn is_canonical(&self) -> bool {
        self.facts.windows(2).all(|w| w[0] < w[1])
    }
}

/// Manifeste : machine + date + { collecteur → empreinte de blob }.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub asset: AssetId,
    pub at: Timestamp,
    pub blobs: BTreeMap<CollectorId, BlobHash>,
}

impl Snapshot {
    /// Constructeur ergonomique. La `BTreeMap` garantit d'elle-même l'ordre
    /// canonique des clés (§15 : jamais de `HashMap` dans ce qui est haché).
    pub fn new(
        asset: impl Into<AssetId>,
        at: Timestamp,
        blobs: BTreeMap<CollectorId, BlobHash>,
    ) -> Self {
        Snapshot {
            asset: asset.into(),
            at,
            blobs,
        }
    }
}

/// Empreinte canonique d'un [`Blob`].
///
/// Garantit l'ordre canonique des faits avant hachage : deux blobs au même
/// contenu — quel que soit l'ordre d'insertion des faits — produisent la
/// même empreinte. Si le blob est déjà canonique, aucun clonage n'a lieu.
pub fn blob_hash(blob: &Blob) -> Result<BlobHash, ModelError> {
    if blob.is_canonical() {
        hash_canonical(blob)
    } else {
        let mut canonical = blob.clone();
        canonical.canonicalize();
        hash_canonical(&canonical)
    }
}

/// Empreinte canonique d'un [`Snapshot`].
///
/// La `BTreeMap` interne rend l'encodage déjà déterministe ; cette fonction
/// est le point d'entrée nommé que le magasin doit utiliser.
pub fn snapshot_hash(snapshot: &Snapshot) -> Result<BlobHash, ModelError> {
    hash_canonical(snapshot)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fact::Fact;

    fn facts_desordonnes() -> Vec<Fact> {
        vec![
            Fact::new("user:root", "user.privileged", true),
            Fact::new("service:sshd", "sshd.PermitRootLogin", "no"),
            Fact::absent("service:sshd", "sshd.PasswordAuthentication"),
        ]
    }

    /// La propriété centrale : l'ordre d'insertion des faits ne change pas
    /// l'empreinte du blob.
    #[test]
    fn blob_hash_independant_de_l_ordre_des_faits() {
        let facts = facts_desordonnes();
        let mut renverses = facts.clone();
        renverses.reverse();

        let a = Blob {
            collector: "linux.sshd".into(),
            raw: b"PermitRootLogin no\n".to_vec(),
            facts,
        };
        let b = Blob {
            collector: "linux.sshd".into(),
            raw: b"PermitRootLogin no\n".to_vec(),
            facts: renverses,
        };
        assert_eq!(blob_hash(&a).unwrap(), blob_hash(&b).unwrap());
    }

    /// Un doublon exact n'apporte aucune information : même empreinte.
    #[test]
    fn blob_hash_ignore_les_doublons_exacts() {
        let mut facts = facts_desordonnes();
        facts.push(facts[0].clone());
        let avec_doublon = Blob {
            collector: "linux.sshd".into(),
            raw: Vec::new(),
            facts,
        };
        let sans_doublon = Blob {
            collector: "linux.sshd".into(),
            raw: Vec::new(),
            facts: facts_desordonnes(),
        };
        assert_eq!(
            blob_hash(&avec_doublon).unwrap(),
            blob_hash(&sans_doublon).unwrap()
        );
    }

    /// En revanche le brut, lui, compte octet par octet.
    #[test]
    fn blob_hash_sensible_au_brut() {
        let a = Blob::new("linux.sshd", b"a".to_vec(), Vec::new());
        let b = Blob::new("linux.sshd", b"b".to_vec(), Vec::new());
        assert_ne!(blob_hash(&a).unwrap(), blob_hash(&b).unwrap());
    }

    #[test]
    fn constructeur_canonicalise() {
        let blob = Blob::new("linux.sshd", Vec::new(), facts_desordonnes());
        assert!(blob.is_canonical());
        // blob_hash sur un blob canonique == hash_canonical direct.
        assert_eq!(
            blob_hash(&blob).unwrap(),
            crate::canonical::hash_canonical(&blob).unwrap()
        );
    }

    #[test]
    fn hex_aller_retour() {
        let h = BlobHash([0x7f; 32]);
        assert_eq!(BlobHash::from_hex(&h.to_hex()).unwrap(), h);
        assert_eq!(h.short_hex(), "7f7f7f7f");
        assert_eq!(h.to_string(), "7f7f7f7f…");
        assert!(BlobHash::from_hex("abcd").is_err()); // trop court
        assert!(BlobHash::from_hex("zz").is_err()); // pas de l'hexadécimal
    }
}
