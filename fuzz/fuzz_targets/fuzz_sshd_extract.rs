//! L'extracteur sshd ne doit jamais paniquer, quels que soient les octets
//! (§12 : les configurations sont des entrées non fiables). On passe par le
//! chemin réel — expurgation puis extraction au travers du trait `Collector` —
//! et par l'extracteur pur directement.

#![no_main]

use constat_collect::linux::sshd::{extract_sshd_facts, SshdCollector};
use constat_collect::{Collector, RawCapture};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Le chemin de production : capture brute hostile → redact → extract.
    let collector = SshdCollector::default();
    let redacted = collector.redact(RawCapture(data.to_vec()));
    let _ = collector.extract(&redacted);

    // 2. L'extracteur pur, sur le texte non expurgé : mêmes garanties.
    let text = String::from_utf8_lossy(data);
    let _ = extract_sshd_facts(&text);
});
