# constat-bench — harnais de charge

Répond chiffres en main à la question : **« est-ce que ça tient un vrai
parc ? »** — et en particulier à la promesse économique du §3.3 de
`CONSTAT-ARCHITECTURE.md` : sur un parc qui ne bouge presque pas, une
collecte régulière ne stocke presque rien, ce qui rend viable une rétention
de trois ans.

Ce n'est **pas** un banc de micro-mesures (pas de criterion) : on simule des
scénarios longs — un parc entier, des mois de collecte — contre un **vrai
`RedbStore` sur disque**, puis on mesure ce que coûtent les requêtes du
produit sur le magasin plein (`state --at`, `history`, `check`), l'export
vérifiable et sa vérification par `constat-verify`.

Comme `fuzz/`, ce répertoire est un **workspace indépendant** (table
`[workspace]` vide dans son `Cargo.toml`, dépendances par chemin vers
`../crates/*`) : il ne modifie aucun crate du produit et n'entre pas dans
son arbre de dépendances.

## Ce qui est simulé

- un parc paramétrable (défaut : **200 machines × 90 jours × 1 collecte
  toutes les 6 h = 72 000 snapshots**) ;
- **~153 faits par machine** répartis sur 6 collecteurs réalistes :
  `linux.inventory`, `linux.accounts`, `linux.sshd`, `linux.packages`
  (110 paquets), `linux.ports`, `linux.kernel_params` — chacun avec un
  artefact brut de taille réaliste (texte de configuration, ~22 Kio
  collectés par machine et par collecte, encodage canonique compris) ;
- un **taux de dérive** paramétrable : N % des machines changent UN fait
  (une version de paquet) par jour, le reste ne bouge pas — le cas nominal
  de la promesse §3.3 ;
- des horodatages simulés déterministes, un PRNG maison (splitmix64) à
  graine fixe, **une seule clé de signature** dérivée de la graine : deux
  exécutions aux mêmes paramètres produisent le même magasin ;
- une entrée de journal signée **par vague de collecte** (le serveur signe
  la vague entière : 4 entrées de 200 empreintes par jour) — un déploiement
  qui signerait par machine multiplierait les entrées par le nombre de
  machines.

Détails de fidélité :

- `sshd_config`, ports et paramètres noyau sont identiques sur tout le parc
  (configuration déployée par gestionnaire de configuration) : la
  déduplication **inter-machines** joue pour eux, c'est réaliste ;
- comptes, inventaire et paquets diffèrent par machine (nom d'hôte, bruit de
  versions) : pour eux seule la déduplication **temporelle** joue — c'est
  elle que mesure la promesse §3.3.

## Ce qui est mesuré

Chaque mesure est imprimée **et** écrite en JSON dans `results/<label>.json` :

- **ingestion** : snapshots/s, temps total, répartition (`put_blob`,
  `put_snapshot`, `append_signed`, génération) + micro-mesures séparées du
  hachage de blob et de la signature d'entrée ;
- **taille du magasin** : points de contrôle tous les 30 jours, ratio
  octets-stockés / octets-collectés (l'effet dédup + zstd — LE chiffre du
  §3.3), extrapolation **linéaire** à 3 ans, affichée comme telle ;
- **requêtes sur le magasin plein**, via les API `lib` de `constat-cli`
  (`queries::state_at`, `queries::history`, et l'assemblage exact de
  `constat check` : `observations` → `build_inputs_with_gaps` →
  `evaluate_park`) ;
- **export complet** (`export_store`) : durée, taille et nombre de fichiers ;
  puis rechargement et **`verify_export`** (bibliothèque `constat-verify`) ;
- **mémoire** : working set et pointe (`PeakWorkingSetSize`) sur Windows ;
  omise (et dite omise) ailleurs.

## Lancer

```bash
cd bench

# Itération rapide (20 machines × 14 jours, ~10 s) :
cargo run --release -- --quick

# Le scénario nominal de la promesse §3.3 (200 × 90 j, dérive 1 %/jour) :
cargo run --release -- --label nominal --drift 1.0

# Les deux bornes :
cargo run --release -- --label parc-fige  --drift 0.0    # borne basse
cargo run --release -- --label parc-agite --drift 10.0   # borne haute
```

Options (`--help` pour la liste complète) : `--machines`, `--days`,
`--per-day`, `--drift <pct>`, `--seed`, `--state-samples`, `--out <dir>`,
`--workdir <dir>` (défaut : répertoire temporaire système, supprimé à la
fin — `--keep` pour le conserver).

Chaque scénario complet (200 × 90 j) prend de l'ordre de 5 à 10 minutes sur
un portable avec SSD NVMe ; le magasin et l'export temporaires occupent
quelques centaines de Mio pendant l'exécution.

Les résultats analysés et le verdict sur la promesse §3.3 sont dans
[`../docs/benchmarks.md`](../docs/benchmarks.md).
