//! `constat_policy::parse_assertions` avale du YAML écrit par un humain :
//! entrée non fiable (§12). Quel que soit le texte, la fonction doit rendre
//! `Ok` ou une erreur structurée — jamais paniquer, jamais diverger
//! (l'imbrication des prédicats est bornée par `MAX_PREDICATE_DEPTH`,
//! le fuzzing vérifie que la borne tient face à du YAML arbitraire).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = constat_policy::parse_assertions(text);
    }
});
