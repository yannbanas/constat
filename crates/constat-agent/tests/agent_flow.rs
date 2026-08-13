//! Bout-en-bout local de l'agent : collecte (collecteur factice) → magasin
//! redb réel → réouverture → `status`. Exerce le vrai chemin d'écriture et
//! de relecture, indépendamment de la plateforme — c'est le socle des tests
//! d'intégration futurs du mode continu (via l'option de test `--max-cycles`).

#![allow(clippy::unwrap_used)]

use constat_agent::{run, status};
use constat_collect::{CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{AssetId, CollectorId, DurationMs, Fact, Timestamp};
use constat_store::{RedbStore, Signer, Store};

/// Collecteur factice, déterministe — jamais présenté comme une donnée
/// réelle : il n'existe que dans ce test.
struct FakeCollector;

impl Collector for FakeCollector {
    fn id(&self) -> CollectorId {
        CollectorId("test.fake".to_string())
    }
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Ok(RawCapture(b"cle = valeur\n".to_vec()))
    }
    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(raw.0)
    }
    fn extract(&self, _redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        Ok(vec![Fact::new("service:test", "test.cle", "valeur")])
    }
}

#[test]
fn collecte_puis_statut_sur_magasin_redb() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("constat-agent-test-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("magasin.redb");

    let signer = Signer::generate();
    let collectors: Vec<Box<dyn Collector>> = vec![Box::new(FakeCollector)];
    let asset = AssetId("machine-test".to_string());

    // Deux collectes espacées d'une heure, comme en ferait le mode --every.
    {
        let mut store = RedbStore::open(&path).unwrap();
        let outcome = run::run_once(
            &mut store,
            &signer,
            &collectors,
            asset.clone(),
            Timestamp(1_000),
        )
        .unwrap();
        match outcome {
            run::RunOutcome::Collected(report) => {
                assert_eq!(report.collected.len(), 1);
                assert!(report.failed.is_empty());
            }
            run::RunOutcome::NothingAvailable { .. } => {
                panic!("le collecteur factice devait produire un blob")
            }
        }
        run::run_once(
            &mut store,
            &signer,
            &collectors,
            asset.clone(),
            Timestamp(3_600_000 + 1_000),
        )
        .unwrap();
    }

    // Réouverture à froid : le statut ne reflète que ce qui est écrit.
    let store = RedbStore::open(&path).unwrap();
    let data = status::compute(&store).unwrap();
    assert_eq!(data.entry_count, 2);
    assert_eq!(data.root, store.root().unwrap());
    assert_eq!(data.last_entry_at, Some(Timestamp(3_600_000 + 1_000)));

    let machine = &data.assets[&asset];
    assert_eq!(machine.last, Timestamp(3_600_000 + 1_000));
    assert_eq!(machine.snapshots, 2);

    // Rendu 13 h après la dernière collecte, intervalle attendu 6 h :
    // plus de deux fois l'intervalle, l'avertissement doit sortir.
    let rendu = status::render(
        &data,
        "magasin.redb",
        Timestamp(3_600_000 + 1_000 + 13 * 3_600_000),
        DurationMs(6 * 3_600_000),
    );
    assert!(rendu.contains("machine-test"));
    assert!(rendu.contains("2 snapshot(s)"));
    assert!(rendu.contains("AVERTISSEMENT"));

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
