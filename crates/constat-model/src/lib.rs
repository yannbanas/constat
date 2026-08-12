//! # constat-model — cœur pur
//!
//! Faits, entités, snapshots et sérialisation canonique.
//!
//! **Règles non négociables** (voir CONSTAT-ARCHITECTURE.md §1, §15) :
//! - aucune entrée-sortie dans ce crate ;
//! - `BTreeMap`/`BTreeSet` partout, jamais `HashMap` ;
//! - aucun flottant dans une valeur hachée ;
//! - dates en UTC, entier de millisecondes depuis l'époque Unix ;
//! - encodage canonique déterministe : mêmes données → mêmes octets → même empreinte.
//!
//! **CONTRAT PUBLIC** : les types ci-dessous sont le contrat partagé par tous les
//! crates du workspace. On peut les étendre (nouvelles méthodes, nouveaux modules),
//! jamais les casser. Tout est ré-exporté à la racine du crate : les modules
//! internes sont un détail d'organisation.
//!
//! ## Points d'entrée
//!
//! - [`Fact::new`], [`Value`] et ses conversions `From` — construire des faits ;
//! - [`EntityId::parse`] — valider le format `"type:nom"` ;
//! - [`Timestamp::from_rfc3339`] / [`Timestamp::to_rfc3339`] — temps lisible ;
//! - [`to_canonical_bytes`] / [`from_canonical_bytes`] / [`hash_canonical`] —
//!   encodage canonique ;
//! - [`blob_hash`] / [`snapshot_hash`] — empreintes des objets du magasin
//!   (à utiliser à la place de `hash_canonical` pour un [`Blob`] : elles
//!   garantissent l'ordre canonique des faits) ;
//! - module [`testing`] (feature `testing`) — générateurs proptest
//!   réutilisables par les autres crates.

mod canonical;
mod fact;
mod ids;
mod store_objects;
mod time;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use canonical::{from_canonical_bytes, hash_canonical, to_canonical_bytes, ModelError};
pub use fact::{Fact, Value};
pub use ids::{AssetId, Attribute, CollectorId, EntityId, EntityIdError};
pub use store_objects::{blob_hash, snapshot_hash, Blob, BlobHash, Snapshot};
pub use time::{DurationMs, Timestamp, TimestampError};

// ---------------------------------------------------------------------------
// Tests transverses : stabilité de la sérialisation canonique (§15)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod canonical_stability_tests {
    use crate::testing::*;
    use crate::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    /// La propriété exigée par la spec (§15) : `hash(decode(encode(x))) == hash(x)`,
    /// renforcée par la stabilité des octets eux-mêmes :
    /// `encode(decode(encode(x))) == encode(x)`.
    macro_rules! roundtrip {
        ($x:expr) => {{
            let x = $x;
            let bytes = to_canonical_bytes(&x).unwrap();
            let decoded = from_canonical_bytes(&bytes).unwrap();
            prop_assert_eq!(&x, &decoded, "l'aller-retour doit être identitaire");
            prop_assert_eq!(
                hash_canonical(&x).unwrap(),
                hash_canonical(&decoded).unwrap(),
                "hash(decode(encode(x))) != hash(x)"
            );
            let bytes2 = to_canonical_bytes(&decoded).unwrap();
            prop_assert_eq!(bytes, bytes2, "encode(decode(encode(x))) != encode(x)");
        }};
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        #[test]
        fn valeur(x in value_strategy()) {
            roundtrip!(x);
        }

        #[test]
        fn fait(x in fact_strategy()) {
            roundtrip!(x);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn blob(x in blob_strategy()) {
            roundtrip!(x);
        }

        #[test]
        fn snapshot(x in snapshot_strategy()) {
            roundtrip!(x);
        }

        /// L'empreinte d'un blob ne dépend pas de l'ordre d'insertion des faits.
        #[test]
        fn blob_hash_invariant_par_permutation(mut x in blob_strategy()) {
            let avant = blob_hash(&x).unwrap();
            x.facts.reverse();
            prop_assert_eq!(blob_hash(&x).unwrap(), avant);
        }

        /// Deux encodages successifs de la même valeur : mêmes octets.
        #[test]
        fn double_encodage_stable(x in snapshot_strategy()) {
            prop_assert_eq!(
                to_canonical_bytes(&x).unwrap(),
                to_canonical_bytes(&x).unwrap()
            );
        }
    }

    // -----------------------------------------------------------------------
    // Non-régression : empreintes figées de valeurs connues.
    //
    // Si l'un de ces tests casse, c'est que L'ENCODAGE CANONIQUE A CHANGÉ :
    // toute empreinte déjà stockée devient introuvable et l'historique entier
    // est invalidé (§15). Ne JAMAIS mettre à jour ces constantes sans une
    // décision d'architecture explicite (ADR) et une migration du magasin.
    // -----------------------------------------------------------------------

    fn frozen(value_hex: &str, actual: BlobHash, what: &str) {
        assert_eq!(
            actual.to_hex(),
            value_hex,
            "EMPREINTE CANONIQUE MODIFIÉE pour {what} — voir le commentaire du test"
        );
    }

    #[test]
    fn empreintes_figees_des_valeurs() {
        frozen(
            "fdb8c0839d262e3865d992cccd527e48d8083a391c5322b06ff789dac24c15ba",
            hash_canonical(&Value::Absent).unwrap(),
            "Value::Absent",
        );
        frozen(
            "a2b00bc0276d5660d52af7503205ce05ea4c8d4db83ae9b2dcce027a0e629080",
            hash_canonical(&Value::Bool(false)).unwrap(),
            "Value::Bool(false)",
        );
        frozen(
            "511a988d140bcbd997665821488d29b240fa9d76923093ef3b4034417a5acf89",
            hash_canonical(&Value::Int(-42)).unwrap(),
            "Value::Int(-42)",
        );
        frozen(
            "ff407a6efa2a8a5e779614fe7423b13f0484d489b5165982b3d0d24aaab0b5a1",
            hash_canonical(&Value::Text("no".into())).unwrap(),
            "Value::Text(\"no\")",
        );
        frozen(
            "5da4bba8a1089679d0b800190ff296fa4c18fc77eb6d0ac90c308230bf2187b4",
            hash_canonical(&Value::List(vec![Value::Int(1), Value::Absent])).unwrap(),
            "Value::List([Int(1), Absent])",
        );
        frozen(
            "636214ceb303273b88ef80b767c34ebdc4d1a045ab7dacfdfc3595acf40b01cf",
            hash_canonical(&Value::Fingerprint([0u8; 32])).unwrap(),
            "Value::Fingerprint([0; 32])",
        );
    }

    #[test]
    fn empreinte_figee_d_un_fait() {
        let fact = Fact::new("service:sshd", "sshd.PermitRootLogin", "no");
        frozen(
            "8f3b303de7d2e4e0b80ce69e81b783a708c996a82e29a525dd24b4c063fbff96",
            hash_canonical(&fact).unwrap(),
            "Fact{service:sshd sshd.PermitRootLogin = no}",
        );
    }

    #[test]
    fn empreinte_figee_d_un_blob() {
        let blob = Blob::new(
            "linux.sshd",
            b"PermitRootLogin no\n".to_vec(),
            vec![
                Fact::new("user:root", "user.privileged", true),
                Fact::new("service:sshd", "sshd.PermitRootLogin", "no"),
                Fact::absent("service:sshd", "sshd.PasswordAuthentication"),
            ],
        );
        frozen(
            "f9d737629500f906a48cbbcf25ab825c88b9e86da66ec14d91b717f71c9f4dca",
            blob_hash(&blob).unwrap(),
            "Blob de référence",
        );
    }

    #[test]
    fn empreinte_figee_d_un_snapshot() {
        let mut blobs = BTreeMap::new();
        blobs.insert(CollectorId("linux.sshd".into()), BlobHash([0x7f; 32]));
        blobs.insert(CollectorId("linux.accounts".into()), BlobHash([0x01; 32]));
        let snapshot = Snapshot::new(
            "srv-fic-01",
            Timestamp::from_rfc3339("2026-03-03T14:00:00Z").unwrap(),
            blobs,
        );
        frozen(
            "828cf8e51905060c31d723a050126fbbef538e508001e5d46e9fe4684277b736",
            snapshot_hash(&snapshot).unwrap(),
            "Snapshot de référence",
        );
    }
}
