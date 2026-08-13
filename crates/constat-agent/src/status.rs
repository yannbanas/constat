//! `constat-agent status` — l'état du magasin local, en lecture seule.
//!
//! Répond à la question de l'exploitant : « la collecte tourne-t-elle
//! encore ? ». La commande lit le journal du magasin et affiche, par
//! machine observée, la date de la dernière collecte ; puis le nombre
//! d'entrées, la racine courante et l'âge de la dernière entrée — avec un
//! avertissement si cet âge dépasse **deux fois** l'intervalle attendu
//! (`--every`) : une collecte planifiée en bonne santé ne saute jamais deux
//! échéances.
//!
//! Le calcul ([`compute`]) est séparé du rendu ([`render`]) : le premier ne
//! touche que le magasin, le second reçoit l'horloge en paramètre — les
//! deux se testent sans dormir ni patcher le temps.

use std::collections::{BTreeMap, BTreeSet};

use constat_model::{AssetId, BlobHash, DurationMs, Timestamp};
use constat_store::{Store, StoreError};

/// Ce que le magasin sait d'une machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetStatus {
    /// Date de la dernière collecte (le `at` du snapshot le plus récent).
    pub last: Timestamp,
    /// Nombre de snapshots distincts observés pour cette machine.
    pub snapshots: u64,
}

/// Photographie du magasin, sans horloge : uniquement ce qui est écrit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusData {
    /// Nombre d'entrées du journal.
    pub entry_count: u64,
    /// Racine courante (empreinte de la dernière entrée), `None` si vide.
    pub root: Option<BlobHash>,
    /// Date de la dernière entrée de journal, `None` si vide.
    pub last_entry_at: Option<Timestamp>,
    /// État par machine, trié par identifiant (BTreeMap : ordre stable).
    pub assets: BTreeMap<AssetId, AssetStatus>,
}

/// Parcourt le journal et agrège l'état par machine. Lecture seule.
pub fn compute(store: &dyn Store) -> Result<StatusData, StoreError> {
    let entries = store.entries()?;
    let mut assets: BTreeMap<AssetId, AssetStatus> = BTreeMap::new();
    let mut seen: BTreeSet<BlobHash> = BTreeSet::new();

    for (_, entry) in &entries {
        for snapshot_hash in &entry.snapshots {
            if !seen.insert(*snapshot_hash) {
                continue; // déjà compté (entrées pouvant re-référencer un snapshot)
            }
            let snapshot = store.get_snapshot(snapshot_hash)?;
            let status = assets.entry(snapshot.asset.clone()).or_insert(AssetStatus {
                last: snapshot.at,
                snapshots: 0,
            });
            status.snapshots += 1;
            if snapshot.at > status.last {
                status.last = snapshot.at;
            }
        }
    }

    Ok(StatusData {
        entry_count: entries.len() as u64,
        root: store.root()?,
        last_entry_at: entries.last().map(|(_, e)| e.at),
        assets,
    })
}

/// Rend l'état lisible. `now` et `expected` sont injectés : le rendu est
/// une fonction pure, testable à date fixe.
pub fn render(data: &StatusData, store_path: &str, now: Timestamp, expected: DurationMs) -> String {
    let mut out = format!("Magasin : {store_path}\n");

    if data.entry_count == 0 {
        out.push_str(
            "Journal vide : aucune collecte enregistrée dans ce magasin. \
             Lancez `constat-agent run --once`.\n",
        );
        return out;
    }

    match &data.root {
        Some(root) => out.push_str(&format!(
            "Entrées de journal : {} — racine courante {root}\n",
            data.entry_count
        )),
        None => out.push_str(&format!("Entrées de journal : {}\n", data.entry_count)),
    }
    if let Some(last) = data.last_entry_at {
        out.push_str(&format!(
            "Dernière entrée : {} (il y a {})\n",
            ts_display(last),
            format_age(age_ms(now, last))
        ));
    }

    out.push_str(&format!("Machines observées : {}\n", data.assets.len()));
    for (asset, status) in &data.assets {
        out.push_str(&format!(
            "  {}  dernière collecte {} (il y a {})  {} snapshot(s)\n",
            asset.0,
            ts_display(status.last),
            format_age(age_ms(now, status.last)),
            status.snapshots
        ));
    }

    if let Some(last) = data.last_entry_at {
        let age = age_ms(now, last);
        if age > expected.0.saturating_mul(2) {
            out.push_str(&format!(
                "\nAVERTISSEMENT : la dernière entrée date d'il y a {}, plus de deux fois \
                 l'intervalle attendu ({}) — la collecte planifiée est peut-être arrêtée. \
                 Le trou restera déclaré dans la couverture (§4.2) ; mieux vaut le refermer.\n",
                format_age(age),
                format_age(expected.0)
            ));
        }
    }
    out
}

/// Âge en millisecondes, jamais négatif (une horloge recalée en arrière ne
/// produit pas d'« âge négatif », juste zéro).
fn age_ms(now: Timestamp, then: Timestamp) -> u64 {
    now.0.saturating_sub(then.0).max(0) as u64
}

/// Un instant, en RFC 3339 UTC — ou brut en millisecondes si l'année sort
/// de la plage représentable (on affiche alors la vérité, pas une invention).
pub fn ts_display(t: Timestamp) -> String {
    t.to_rfc3339()
        .unwrap_or_else(|_| format!("{} ms depuis l'époque Unix", t.0))
}

/// Durée lisible et approximative — c'est un âge, pas une preuve :
/// `45 s`, `12 min`, `3 h 05 min`, `2 j 4 h`.
pub fn format_age(ms: u64) -> String {
    let secs = ms / 1_000;
    if secs < 60 {
        format!("{secs} s")
    } else if secs < 3_600 {
        format!("{} min", secs / 60)
    } else if secs < 48 * 3_600 {
        let h = secs / 3_600;
        let min = (secs % 3_600) / 60;
        if min == 0 {
            format!("{h} h")
        } else {
            format!("{h} h {min:02} min")
        }
    } else {
        let days = secs / 86_400;
        let h = (secs % 86_400) / 3_600;
        if h == 0 {
            format!("{days} j")
        } else {
            format!("{days} j {h} h")
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use constat_model::{Blob, Fact, Snapshot};
    use constat_store::{append_signed, MemoryStore, Signer};

    /// Une collecte pour `asset` à l'instant `at` : blob + snapshot + entrée.
    fn collecte(store: &mut MemoryStore, signer: &Signer, asset: &str, at: i64) {
        let blob = Blob::new(
            "linux.sshd",
            format!("PermitRootLogin no # {at}\n").into_bytes(),
            vec![Fact::new("service:sshd", "sshd.PermitRootLogin", "no")],
        );
        let blob_hash = store.put_blob(&blob).unwrap();
        let mut blobs = BTreeMap::new();
        blobs.insert("linux.sshd".into(), blob_hash);
        let snapshot = Snapshot::new(asset, Timestamp(at), blobs);
        let snapshot_hash = store.put_snapshot(&snapshot).unwrap();
        append_signed(store, signer, vec![snapshot_hash], Timestamp(at)).unwrap();
    }

    #[test]
    fn magasin_vide_dit_la_verite() {
        let store = MemoryStore::new();
        let data = compute(&store).unwrap();
        assert_eq!(data.entry_count, 0);
        assert!(data.assets.is_empty());
        let rendu = render(&data, "./test.redb", Timestamp(0), DurationMs(1_000));
        assert!(rendu.contains("Journal vide"));
        assert!(!rendu.contains("AVERTISSEMENT"));
    }

    #[test]
    fn statut_par_machine_et_racine() {
        let mut store = MemoryStore::new();
        let signer = Signer::generate();
        collecte(&mut store, &signer, "srv-01", 1_000);
        collecte(&mut store, &signer, "srv-02", 2_000);
        collecte(&mut store, &signer, "srv-01", 3_000);

        let data = compute(&store).unwrap();
        assert_eq!(data.entry_count, 3);
        assert_eq!(data.root, store.root().unwrap());
        assert!(data.root.is_some());
        assert_eq!(data.last_entry_at, Some(Timestamp(3_000)));

        let srv01 = &data.assets[&AssetId("srv-01".into())];
        assert_eq!(srv01.last, Timestamp(3_000)); // la plus récente, pas la première
        assert_eq!(srv01.snapshots, 2);
        let srv02 = &data.assets[&AssetId("srv-02".into())];
        assert_eq!(srv02.last, Timestamp(2_000));
        assert_eq!(srv02.snapshots, 1);
    }

    #[test]
    fn rendu_recent_sans_avertissement() {
        let mut store = MemoryStore::new();
        let signer = Signer::generate();
        collecte(&mut store, &signer, "srv-01", 0);
        let data = compute(&store).unwrap();

        // 1 h après la collecte, intervalle attendu 6 h : tout va bien.
        let rendu = render(
            &data,
            "./test.redb",
            Timestamp(3_600_000),
            DurationMs(6 * 3_600_000),
        );
        assert!(rendu.contains("srv-01"));
        assert!(rendu.contains("1970-01-01T00:00:00.000Z"));
        assert!(rendu.contains("il y a 1 h"));
        assert!(rendu.contains("Entrées de journal : 1"));
        assert!(!rendu.contains("AVERTISSEMENT"));
    }

    #[test]
    fn rendu_en_retard_avertit() {
        let mut store = MemoryStore::new();
        let signer = Signer::generate();
        collecte(&mut store, &signer, "srv-01", 0);
        let data = compute(&store).unwrap();

        // 13 h après la collecte, intervalle attendu 6 h : > 2× — alerte.
        let rendu = render(
            &data,
            "./test.redb",
            Timestamp(13 * 3_600_000),
            DurationMs(6 * 3_600_000),
        );
        assert!(rendu.contains("AVERTISSEMENT"));
        assert!(rendu.contains("il y a 13 h"));
        assert!(rendu.contains("(6 h)"));

        // Exactement 2× : pas encore d'alerte (strictement supérieur).
        let rendu = render(
            &data,
            "./test.redb",
            Timestamp(12 * 3_600_000),
            DurationMs(6 * 3_600_000),
        );
        assert!(!rendu.contains("AVERTISSEMENT"));
    }

    #[test]
    fn ages_lisibles() {
        assert_eq!(format_age(45_000), "45 s");
        assert_eq!(format_age(12 * 60_000), "12 min");
        assert_eq!(format_age(3 * 3_600_000 + 5 * 60_000), "3 h 05 min");
        assert_eq!(format_age(52 * 3_600_000), "2 j 4 h");
        assert_eq!(format_age(0), "0 s");
    }

    /// Horloge recalée en arrière : l'âge affiché est nul, pas négatif.
    #[test]
    fn age_jamais_negatif() {
        assert_eq!(age_ms(Timestamp(1_000), Timestamp(5_000)), 0);
    }
}
