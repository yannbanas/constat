//! L'expurgation (§7.2) est la surface la plus exposée : elle avale la
//! capture brute, hostile par définition. Deux propriétés vérifiées :
//!
//! 1. **jamais de panique**, quels que soient les octets ;
//! 2. **croissance au plus linéaire** de la sortie : les marqueurs
//!    `[EXPURGÉ:…]` remplacent des séquences, ils ne doivent jamais faire
//!    croître la sortie de façon quadratique (borne : 16·n + 64 octets).
//!
//! La taille d'entrée est bornée (256 Kio) pour que chaque itération reste
//! rapide ; le temps global est borné par `-max_total_time` / `-timeout`.

#![no_main]

use constat_collect::redact::{
    redact_bytes, redact_shadow_hash_field, redact_text, split_colon_fields,
};
use libfuzzer_sys::fuzz_target;

/// Borne linéaire sur la taille de sortie. Le pire cas réel observé est un
/// marqueur (~30 octets) par ligne minuscule (`pwd=x`), soit un facteur ~6 ;
/// 16·n + 64 laisse de la marge tout en attrapant toute croissance
/// super-linéaire.
const GROWTH_FACTOR: usize = 16;
const GROWTH_SLACK: usize = 64;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    // 1. redact_bytes : le point d'entrée des collecteurs.
    let out = redact_bytes(data);
    assert!(
        out.len() <= GROWTH_FACTOR * data.len() + GROWTH_SLACK,
        "croissance super-linéaire : {} octets en entrée, {} en sortie",
        data.len(),
        out.len()
    );

    // 2. Idempotence approchée : ré-expurger une sortie ne panique pas et
    //    reste bornée (les marqueurs ne doivent pas s'auto-amplifier).
    let text = String::from_utf8_lossy(&out);
    let again = redact_text(&text);
    assert!(
        again.len() <= GROWTH_FACTOR * out.len() + GROWTH_SLACK,
        "ré-expurgation super-linéaire"
    );

    // 3. Les aides structurelles (shadow, champs « : ») ne paniquent jamais.
    let lossy = String::from_utf8_lossy(data);
    let _ = split_colon_fields(&lossy);
    for line in lossy.split('\n') {
        let _ = redact_shadow_hash_field(line);
    }
});
