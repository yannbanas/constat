# Fuzzing — les configurations sont des entrées non fiables (§12)

Ce répertoire est un workspace **indépendant** (table `[workspace]` vide dans
son `Cargo.toml`) : il exige la chaîne nightly, le workspace principal reste
sur Rust stable.

## Les cibles

| Cible | Une ligne |
|---|---|
| `fuzz_sshd_extract` | l'extracteur sshd (expurgation + extraction, via le trait `Collector` et l'API pure) ne panique jamais sur des octets hostiles. |
| `fuzz_redact` | l'expurgation ne panique jamais et sa sortie croît au plus linéairement (borne 16·n + 64) — jamais de façon quadratique. |
| `fuzz_policy_yaml` | `constat_policy::parse_assertions` rend `Ok` ou une erreur structurée sur du YAML arbitraire, jamais une panique. |
| `fuzz_canonical_roundtrip` | `constat_model::from_canonical_bytes` sur octets arbitraires ne panique jamais (seulement `Err`), et ce qui décode ré-encode de façon stable (§15). |
| `fuzz_verify_entry` | décoder des octets arbitraires en `JournalEntry` et les passer à `constat_verify::verify_export` ne panique jamais. |

## Lancer

```bash
rustup toolchain install nightly    # une fois
cargo install cargo-fuzz            # une fois

# depuis la racine du dépôt :
cargo +nightly fuzz list
cargo +nightly fuzz run fuzz_redact -- -max_total_time=60 -timeout=25
```

Toute panique trouvée est une vraie trouvaille : l'entrée fautive est écrite
dans `fuzz/artifacts/<cible>/` — la joindre au rapport de bogue, puis en faire
un cas de corpus (`corpus/`, règle 4 de `corpus/README.md`).

Un passage court (60 s par cible) tourne chaque semaine en CI :
`.github/workflows/fuzz.yml`.

## Limitation connue : l'exécution se fait sous Linux

Sous **Windows (MSVC)**, l'édition de liens échoue : `redb` (dépendance de
`constat-store`) déclare le crate-type `cdylib` pour ses liaisons Python, et
une DLL Windows ne tolère pas les symboles sancov non résolus que
l'instrumentation de cargo-fuzz y laisse (redb embarque le contournement
équivalent pour macOS — `-undefined dynamic_lookup` — mais pas pour Windows).
Ce n'est pas un défaut des cibles : elles compilent (`cargo +nightly check`
dans `fuzz/` passe, clippy et rustfmt aussi). **L'exécution des cibles se fait
sous Linux** — c'est là que tourne le job CI (`ubuntu-latest`), où le format
ELF admet ces symboles à l'édition de liens.
