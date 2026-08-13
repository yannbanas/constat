//! Inventaire des journaux du magasin — le socle de l'inventaire
//! attendu/observé du dossier de preuve (§10.2).
//!
//! Un serveur multi-agents porte N journaux nommés (un par clé d'agent,
//! voir [`MultiJournalStore`]) plus, éventuellement, le journal par défaut
//! d'un magasin v0.1.0 migré. La sous-commande `constat-server journals`
//! affiche ce que ce module calcule : par journal, la clé abrégée, le nombre
//! d'entrées, la date de la dernière entrée et la racine — c'est-à-dire ce
//! qu'on compare aux agents *attendus* pour détecter l'écart.
//!
//! Lecture seule, comme tout le produit : ce module n'écrit jamais rien.

use constat_model::{BlobHash, Timestamp};
use constat_store::{JournalEntry, JournalId, MultiJournalStore, StoreError};

/// Résumé d'un journal : ce que `constat-server journals` affiche.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSummary {
    /// Clé publique du signataire — `None` pour le journal par défaut
    /// (magasin v0.1.0 migré, ou agent local).
    pub id: Option<JournalId>,
    /// Nombre d'entrées du journal.
    pub entry_count: usize,
    /// Date (`at`) de la dernière entrée, `None` si le journal est vide.
    pub last_at: Option<Timestamp>,
    /// Racine du journal : empreinte de la dernière entrée (§6.3).
    pub root: Option<BlobHash>,
}

/// Inventorie les journaux du magasin : le journal par défaut d'abord (s'il
/// n'est pas vide), puis les journaux nommés, triés par clé.
pub fn inventory(store: &dyn MultiJournalStore) -> Result<Vec<JournalSummary>, StoreError> {
    let mut rows = Vec::new();
    let default_entries = store.entries()?;
    if !default_entries.is_empty() {
        rows.push(summarize(None, &default_entries));
    }
    for id in store.journals()? {
        let entries = store.entries_of(&id)?;
        rows.push(summarize(Some(id), &entries));
    }
    Ok(rows)
}

fn summarize(id: Option<JournalId>, entries: &[(BlobHash, JournalEntry)]) -> JournalSummary {
    let last = entries.last();
    JournalSummary {
        id,
        entry_count: entries.len(),
        last_at: last.map(|(_, entry)| entry.at),
        root: last.map(|(hash, _)| *hash),
    }
}

/// Rend l'inventaire en texte : une ligne par journal — clé hex abrégée,
/// nombre d'entrées, date RFC 3339 de la dernière entrée, racine abrégée.
pub fn render(rows: &[JournalSummary]) -> String {
    if rows.is_empty() {
        return "aucun journal : le magasin est vide.\n".to_string();
    }
    let mut out = format!(
        "{:<19}  {:>8}  {:<24}  {}\n",
        "JOURNAL", "ENTRÉES", "DERNIÈRE ENTRÉE", "RACINE"
    );
    for row in rows {
        let journal = match row.id {
            Some(id) => abbrev(&hex::encode(id)),
            None => "(journal par défaut)".to_string(),
        };
        let last = match row.last_at {
            Some(at) => at
                .to_rfc3339()
                .unwrap_or_else(|_| format!("{} ms", at.as_unix_millis())),
            None => "—".to_string(),
        };
        let root = match row.root {
            Some(root) => abbrev(&root.to_hex()),
            None => "—".to_string(),
        };
        out.push_str(&format!(
            "{:<19}  {:>8}  {:<24}  {}\n",
            journal, row.entry_count, last, root
        ));
    }
    out
}

/// Abrège une empreinte ou une clé hex : 16 caractères puis une ellipse —
/// assez pour distinguer, jamais ambigu à l'écran (le complet reste dans le
/// magasin et les exports).
fn abbrev(hex: &str) -> String {
    match hex.get(..16) {
        Some(head) => format!("{head}…"),
        None => hex.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use constat_store::{append_signed, MemoryStore, Signer, Store};

    #[test]
    fn magasin_vide_inventaire_vide() {
        let store = MemoryStore::new();
        let rows = inventory(&store).unwrap();
        assert!(rows.is_empty());
        assert_eq!(render(&rows), "aucun journal : le magasin est vide.\n");
    }

    #[test]
    fn journal_par_defaut_puis_journaux_nommes() {
        let mut store = MemoryStore::new();

        // Journal par défaut : une entrée (magasin v0.1.0 migré).
        let historique = Signer::generate();
        append_signed(&mut store, &historique, vec![], Timestamp(1_000)).unwrap();

        // Deux journaux nommés.
        let a = Signer::generate();
        let b = Signer::generate();
        for (signer, n) in [(&a, 2i64), (&b, 3i64)] {
            let journal = signer.verifying_key().to_bytes();
            for i in 0..n {
                let prev = store.last_entry_of(&journal).unwrap().map(|(h, _)| h);
                let entry = signer
                    .sign_entry(prev, vec![], Timestamp(2_000 + i))
                    .unwrap();
                store.append_entry_in(&journal, &entry).unwrap();
            }
        }

        let rows = inventory(&store).unwrap();
        assert_eq!(rows.len(), 3);
        // Le journal par défaut d'abord…
        assert_eq!(rows[0].id, None);
        assert_eq!(rows[0].entry_count, 1);
        assert_eq!(rows[0].last_at, Some(Timestamp(1_000)));
        assert_eq!(rows[0].root, store.root().unwrap());
        // …puis les journaux nommés, triés par clé, chacun avec SA racine.
        let named: Vec<_> = rows[1..].iter().collect();
        assert!(named[0].id.unwrap() < named[1].id.unwrap());
        for row in named {
            let id = row.id.unwrap();
            assert_eq!(row.root, store.root_of(&id).unwrap());
            assert_eq!(row.entry_count, store.entries_of(&id).unwrap().len());
        }

        // Le rendu : une ligne d'en-tête + une par journal, clés abrégées.
        let text = render(&rows);
        assert_eq!(text.lines().count(), 4);
        assert!(text.contains("(journal par défaut)"));
        assert!(text.contains(&abbrev(&hex::encode(a.verifying_key().to_bytes()))));
        // Dernières entrées : 2001 ms et 2002 ms depuis l'époque.
        assert!(text.contains("1970-01-01T00:00:02.001Z"));
        assert!(text.contains("1970-01-01T00:00:02.002Z"));
    }
}
