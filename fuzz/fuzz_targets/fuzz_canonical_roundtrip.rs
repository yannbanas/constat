//! `constat_model::from_canonical_bytes` décode des octets qui, côté serveur
//! et côté vérificateur, viennent du réseau ou du disque : hostiles par
//! définition. Sur octets arbitraires, le décodage ne doit **jamais paniquer**
//! — seulement `Err`. Et ce qui décode doit ré-encoder puis re-décoder à
//! l'identique (la chaîne de preuve repose sur cette stabilité, §15).

#![no_main]

use constat_model::{from_canonical_bytes, to_canonical_bytes, Blob, Fact, Snapshot, Value};
use libfuzzer_sys::fuzz_target;

fn roundtrip<T>(data: &[u8])
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    if let Ok(decoded) = from_canonical_bytes::<T>(data) {
        // ce qui a décodé doit ré-encoder sans panique…
        let bytes = to_canonical_bytes(&decoded).expect("ré-encodage d'une valeur décodée");
        // …et l'encodage canonique doit être un point fixe
        let decoded2 =
            from_canonical_bytes::<T>(&bytes).expect("re-décodage de l'encodage canonique");
        let bytes2 = to_canonical_bytes(&decoded2).expect("ré-encodage (2)");
        assert_eq!(bytes, bytes2, "encodage canonique instable (§15)");
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    roundtrip::<Value>(data);
    roundtrip::<Fact>(data);
    roundtrip::<Blob>(data);
    roundtrip::<Snapshot>(data);
});
