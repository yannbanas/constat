//! Requêtes de lecture sur le magasin (§10) : état à une date, différence,
//! historique d'un attribut.
//!
//! Toutes les fonctions sont écrites contre `&dyn Store` : elles s'exercent
//! aussi bien sur un magasin en mémoire (tests) que sur le fichier redb une
//! fois le backend concret livré. Aucune écriture, jamais — la CLI est en
//! lecture seule, comme tout le produit.

use std::collections::{BTreeMap, BTreeSet};

use constat_diff::FactDiff;
use constat_model::{
    AssetId, Attribute, Blob, BlobHash, CollectorId, EntityId, Fact, Snapshot, Timestamp, Value,
};
use constat_store::{Store, StoreError};
use constat_time::{CoverageReport, Period, TimeError};

/// Erreur d'une requête : magasin ou calcul de couverture.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("couverture incalculable : {0}")]
    Time(#[from] TimeError),
}

/// Un fait observé, avec sa provenance complète : machine, date, collecteur
/// et empreinte du blob de preuve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub asset: AssetId,
    pub at: Timestamp,
    pub collector: CollectorId,
    /// Empreinte du blob d'où provient le fait — le renvoi vers la preuve brute.
    pub blob: BlobHash,
    pub fact: Fact,
}

/// Tous les snapshots référencés par le journal, dédupliqués et triés par date.
pub fn snapshots(store: &dyn Store) -> Result<Vec<(BlobHash, Snapshot)>, StoreError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (_, entry) in store.entries()? {
        for sh in &entry.snapshots {
            if seen.insert(*sh) {
                out.push((*sh, store.get_snapshot(sh)?));
            }
        }
    }
    out.sort_by(|a, b| a.1.at.cmp(&b.1.at).then_with(|| a.1.asset.cmp(&b.1.asset)));
    Ok(out)
}

/// Tous les faits du magasin, avec leur provenance, triés par date de snapshot.
///
/// Les blobs sont lus une seule fois même s'ils sont référencés par plusieurs
/// snapshots (c'est le cas normal : la déduplication est le cœur du modèle §3.3).
pub fn observations(store: &dyn Store) -> Result<Vec<Observation>, StoreError> {
    let mut cache: BTreeMap<BlobHash, Blob> = BTreeMap::new();
    let mut out = Vec::new();
    for (_, snap) in snapshots(store)? {
        for (cid, bh) in &snap.blobs {
            if !cache.contains_key(bh) {
                cache.insert(*bh, store.get_blob(bh)?);
            }
            // La table vient d'être garnie : l'accès est nécessairement présent.
            if let Some(blob) = cache.get(bh) {
                for fact in &blob.facts {
                    out.push(Observation {
                        asset: snap.asset.clone(),
                        at: snap.at,
                        collector: cid.clone(),
                        blob: *bh,
                        fact: fact.clone(),
                    });
                }
            }
        }
    }
    Ok(out)
}

/// L'état d'une machine tel que restitué par `constat state`.
#[derive(Debug, Clone)]
pub struct StateView {
    /// Empreinte du snapshot restitué.
    pub snapshot_hash: BlobHash,
    pub snapshot: Snapshot,
    /// Les faits, avec le collecteur et le blob de preuve d'où ils viennent.
    pub facts: Vec<(CollectorId, BlobHash, Fact)>,
}

/// Dernier snapshot antérieur ou égal à `at` pour la machine `asset`,
/// avec l'ensemble de ses faits. `None` si aucune observation n'existe.
pub fn state_at(
    store: &dyn Store,
    asset: &AssetId,
    at: Timestamp,
) -> Result<Option<StateView>, StoreError> {
    let found = snapshots(store)?
        .into_iter()
        .filter(|(_, s)| &s.asset == asset && s.at <= at)
        .max_by_key(|(_, s)| s.at);
    let Some((snapshot_hash, snapshot)) = found else {
        return Ok(None);
    };
    let mut facts = Vec::new();
    for (cid, bh) in &snapshot.blobs {
        let blob = store.get_blob(bh)?;
        for f in blob.facts {
            facts.push((cid.clone(), *bh, f));
        }
    }
    facts.sort_by(|a, b| (&a.2.entity, &a.2.attribute).cmp(&(&b.2.entity, &b.2.attribute)));
    Ok(Some(StateView {
        snapshot_hash,
        snapshot,
        facts,
    }))
}

/// Résultat de `constat diff` : la différence, et les dates réelles des deux
/// snapshots comparés (qui peuvent précéder les dates demandées).
#[derive(Debug, Clone)]
pub struct DiffView {
    pub diff: FactDiff,
    pub before_at: Timestamp,
    pub after_at: Timestamp,
}

/// Différence d'état d'une machine entre deux dates, via `constat_diff::diff`.
/// `None` si l'une des deux dates n'a aucun snapshot antérieur.
pub fn diff_asset(
    store: &dyn Store,
    asset: &AssetId,
    from: Timestamp,
    to: Timestamp,
) -> Result<Option<DiffView>, StoreError> {
    let (Some(a), Some(b)) = (state_at(store, asset, from)?, state_at(store, asset, to)?) else {
        return Ok(None);
    };
    let fa: Vec<Fact> = a.facts.iter().map(|(_, _, f)| f.clone()).collect();
    let fb: Vec<Fact> = b.facts.iter().map(|(_, _, f)| f.clone()).collect();
    Ok(Some(DiffView {
        diff: constat_diff::diff(&fa, &fb),
        before_at: a.snapshot.at,
        after_at: b.snapshot.at,
    }))
}

/// Un changement daté de la valeur d'un attribut, avec sa preuve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryChange {
    pub at: Timestamp,
    pub asset: AssetId,
    /// `None` pour la toute première observation (il n'y a pas d'« avant »).
    pub before: Option<Value>,
    pub after: Value,
    /// Empreinte du blob de preuve où le nouvel état est constaté.
    pub evidence: BlobHash,
}

/// Résultat de `constat history` : les changements datés et la couverture.
#[derive(Debug, Clone)]
pub struct History {
    pub changes: Vec<HistoryChange>,
    /// Couverture de la période parcourue — `None` si rien n'a été observé.
    pub coverage: Option<CoverageReport>,
}

/// Parcourt le journal et restitue les changements datés de `(entity, attr)`,
/// chacun avec l'empreinte du blob de preuve, plus la couverture de la période.
///
/// La valeur est suivie par machine : la même entité (ex. `user:jdupont`)
/// peut être observée sur plusieurs machines, et chaque changement cite la
/// machine où il a été constaté (§10.1).
pub fn history(
    store: &dyn Store,
    entity: &EntityId,
    attr: &Attribute,
    period: Option<Period>,
) -> Result<History, QueryError> {
    let obs = observations(store)?;
    let mut last: BTreeMap<AssetId, Value> = BTreeMap::new();
    let mut changes = Vec::new();
    let mut relevant_assets: BTreeSet<AssetId> = BTreeSet::new();

    for o in obs
        .iter()
        .filter(|o| &o.fact.entity == entity && &o.fact.attribute == attr)
    {
        if let Some(p) = period {
            if o.at < p.from || o.at > p.to {
                continue;
            }
        }
        relevant_assets.insert(o.asset.clone());
        let before = last.get(&o.asset);
        match before {
            None => changes.push(HistoryChange {
                at: o.at,
                asset: o.asset.clone(),
                before: None,
                after: o.fact.value.clone(),
                evidence: o.blob,
            }),
            Some(prev) if *prev != o.fact.value => changes.push(HistoryChange {
                at: o.at,
                asset: o.asset.clone(),
                before: Some(prev.clone()),
                after: o.fact.value.clone(),
                evidence: o.blob,
            }),
            Some(_) => {}
        }
        last.insert(o.asset.clone(), o.fact.value.clone());
    }

    // Couverture : les dates de collecte des machines où l'entité vit.
    let times: Vec<Timestamp> = snapshots(store)?
        .iter()
        .filter(|(_, s)| relevant_assets.contains(&s.asset))
        .map(|(_, s)| s.at)
        .collect();
    let coverage = if times.is_empty() {
        None
    } else {
        let span = period.unwrap_or(Period {
            // `times` est non vide : les bornes existent.
            from: times.iter().min().copied().unwrap_or(Timestamp(0)),
            to: times.iter().max().copied().unwrap_or(Timestamp(0)),
        });
        Some(crate::coverage::coverage_report(
            &times,
            span,
            crate::coverage::DEFAULT_MAX_EXPECTED_GAP,
        )?)
    };

    Ok(History { changes, coverage })
}
