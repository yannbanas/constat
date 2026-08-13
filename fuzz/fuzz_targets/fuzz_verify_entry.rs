//! Le vérificateur autonome (§10.3) est exécuté par un auditeur sur un export
//! qu'il n'a aucune raison de croire bien formé. Décoder des octets
//! arbitraires en `JournalEntry` puis vérifier ne doit **jamais paniquer** :
//! au pire une erreur structurée (`VerifyError`), jamais un plantage.

#![no_main]

use std::collections::BTreeMap;

use constat_model::from_canonical_bytes;
use constat_store::JournalEntry;
use constat_verify::{verify_export, Export};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    // Les 32 premiers octets alimentent la clé publique (souvent invalide :
    // c'est voulu, ClePubliqueInvalide est un chemin à couvrir), le reste est
    // décodé en entrée de journal.
    let mut public_key = [0u8; 32];
    let split = data.len().min(32);
    public_key[..split].copy_from_slice(&data[..split]);
    let rest = &data[split..];

    // Une entrée seule…
    if let Ok(entry) = from_canonical_bytes::<JournalEntry>(rest) {
        let export = Export {
            entries: vec![entry],
            snapshots: BTreeMap::new(),
            blobs: BTreeMap::new(),
            public_key,
        };
        let _ = verify_export(&export);
    }

    // …ou une chaîne complète décodée d'un bloc.
    if let Ok(entries) = from_canonical_bytes::<Vec<JournalEntry>>(rest) {
        let export = Export {
            entries,
            snapshots: BTreeMap::new(),
            blobs: BTreeMap::new(),
            public_key,
        };
        let _ = verify_export(&export);
    }
});
