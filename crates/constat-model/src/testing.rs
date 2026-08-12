//! Générateurs [proptest](https://docs.rs/proptest) pour tous les types du
//! modèle — réutilisables par les autres crates du workspace.
//!
//! Activer la feature `testing` pour en disposer hors de ce crate :
//!
//! ```toml
//! [dev-dependencies]
//! constat-model = { workspace = true, features = ["testing"] }
//! proptest = { workspace = true }
//! ```
//!
//! Les générateurs couvrent tout le domaine des types (entiers extrêmes,
//! chaînes Unicode arbitraires, listes imbriquées) : c'est volontaire, la
//! stabilité des empreintes doit tenir sur des données hostiles, pas
//! seulement sur des exemples raisonnables.
//!
//! Note : [`blob_strategy`] génère des faits **dans un ordre arbitraire**
//! (non canonique), pour que les tests exercent le tri de
//! [`blob_hash`](crate::blob_hash).

use crate::{
    AssetId, Attribute, Blob, BlobHash, CollectorId, DurationMs, EntityId, Fact, Snapshot,
    Timestamp, Value,
};
use proptest::prelude::*;

/// Instant arbitraire sur tout le domaine `i64`.
pub fn timestamp_strategy() -> impl Strategy<Value = Timestamp> {
    any::<i64>().prop_map(Timestamp)
}

/// Durée arbitraire sur tout le domaine `u64`.
pub fn duration_strategy() -> impl Strategy<Value = DurationMs> {
    any::<u64>().prop_map(DurationMs)
}

/// Identifiant d'entité bien formé (`"type:nom"`).
pub fn entity_id_strategy() -> impl Strategy<Value = EntityId> {
    ("[a-z]{1,10}", "[a-zA-Z0-9_./-]{1,24}").prop_map(|(t, n)| EntityId(format!("{t}:{n}")))
}

/// Attribut plausible (`"sshd.PermitRootLogin"`, `"user.privileged"`, …).
pub fn attribute_strategy() -> impl Strategy<Value = Attribute> {
    "[a-z]{1,10}(\\.[a-zA-Z0-9_]{1,16}){0,3}".prop_map(Attribute)
}

/// Identifiant de machine plausible.
pub fn asset_id_strategy() -> impl Strategy<Value = AssetId> {
    "[a-z][a-z0-9-]{0,24}".prop_map(AssetId)
}

/// Identifiant de collecteur plausible.
pub fn collector_id_strategy() -> impl Strategy<Value = CollectorId> {
    "[a-z]{1,10}(\\.[a-z]{1,12}){0,2}".prop_map(CollectorId)
}

/// Empreinte arbitraire (32 octets quelconques).
pub fn blob_hash_strategy() -> impl Strategy<Value = BlobHash> {
    any::<[u8; 32]>().prop_map(BlobHash)
}

/// Valeur arbitraire, récursive : listes imbriquées, chaînes Unicode
/// quelconques, entiers extrêmes, empreintes, `Absent`.
pub fn value_strategy() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Absent),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::Int),
        any::<String>().prop_map(Value::Text),
        any::<[u8; 32]>().prop_map(Value::Fingerprint),
    ];
    leaf.prop_recursive(
        3,  // profondeur maximale
        24, // taille totale visée
        6,  // éléments par liste
        |inner| prop::collection::vec(inner, 0..6).prop_map(Value::List),
    )
}

/// Triplet entité-attribut-valeur arbitraire.
pub fn fact_strategy() -> impl Strategy<Value = Fact> {
    (entity_id_strategy(), attribute_strategy(), value_strategy()).prop_map(
        |(entity, attribute, value)| Fact {
            entity,
            attribute,
            value,
        },
    )
}

/// Blob arbitraire. Les faits sont générés **dans un ordre quelconque**
/// (délibérément non canonique) et le brut est un tas d'octets arbitraires.
pub fn blob_strategy() -> impl Strategy<Value = Blob> {
    (
        collector_id_strategy(),
        prop::collection::vec(any::<u8>(), 0..256),
        prop::collection::vec(fact_strategy(), 0..8),
    )
        .prop_map(|(collector, raw, facts)| Blob {
            collector,
            raw,
            facts,
        })
}

/// Snapshot arbitraire (la `BTreeMap` s'ordonne d'elle-même).
pub fn snapshot_strategy() -> impl Strategy<Value = Snapshot> {
    (
        asset_id_strategy(),
        timestamp_strategy(),
        prop::collection::btree_map(collector_id_strategy(), blob_hash_strategy(), 0..6),
    )
        .prop_map(|(asset, at, blobs)| Snapshot { asset, at, blobs })
}
