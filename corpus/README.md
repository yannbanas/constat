# Corpus — captures réelles anonymisées et verdicts attendus

Ce répertoire est le filet de sécurité **sémantique** des extracteurs de faits
(CONSTAT-ARCHITECTURE.md §12). Les tests unitaires attrapent les erreurs de
code ; le corpus attrape les erreurs de **compréhension** : une directive mal
interprétée, un défaut système oublié, une absence confondue avec un faux.

## Principe

Chaque cas du corpus associe :

- **une capture réelle, anonymisée** — un fichier de configuration tel qu'un
  collecteur le lirait sur une vraie machine, débarrassé de tout ce qui
  identifierait son origine (noms d'hôtes, adresses, comptes réels, secrets) ;
- **les faits attendus** — les triplets que l'extracteur doit produire à
  partir de cette capture, y compris les cas `Absent`.

**Chaque cas est exécuté par `crates/constat-collect/tests/corpus.rs`** : le
harnais découvre tous les répertoires de cas, choisit l'extracteur d'après le
premier segment du chemin (`sshd/` → extracteur sshd, `accounts/`,
`packages/`, `kernel_params/`…), passe `capture.txt` par le pipeline de
production `redact` → `extract` du collecteur, et compare fait à fait avec
`attendu.yaml` — **dans les deux sens** : un fait attendu manquant, un fait
produit non attendu ou une valeur différente cassent le test avec un diff
lisible. Un répertoire de cas sans `attendu.yaml` est un échec : un cas sans
verdict attendu n'est pas un cas. Toute divergence casse la CI.

Corollaire : la liste `facts:` d'un `attendu.yaml` est **exhaustive** — elle
décrit tout ce que l'extracteur produit sur cette capture, cas `Absent`
compris.

## Organisation

```
corpus/
└── <collecteur>/            # sshd, accounts, packages, kernel_params, ...
    └── <cas>/               # basique, defaut-implicite, hostile, ...
        ├── capture.txt      # l'artefact brut anonymisé
        └── attendu.yaml     # les faits attendus
```

## Le format d'`attendu.yaml`

```yaml
collector: sshd        # premier segment du chemin (choisit l'extracteur)
case: basique          # nom du répertoire de cas

facts:                 # liste EXHAUSTIVE de triplets entité-attribut-valeur
  - entity: "service:sshd"
    attribute: "sshd.Port"
    value: { int: 22 }
```

La valeur est un objet YAML à **une clef**, qui nomme le type du modèle
(`constat_model::Value`) :

| Écriture | Valeur du modèle |
|---|---|
| `value: { bool: true }` | `Value::Bool(true)` |
| `value: { int: 22 }` | `Value::Int(22)` |
| `value: { text: "no" }` | `Value::Text("no")` |
| `value: { list: [{ int: 22 }, { int: 2222 }] }` | `Value::List([...])` (récursif) |
| `value: { absent: true }` | `Value::Absent` |

L'absence est une **balise dédiée**, jamais une chaîne : `{ absent: true }`
et `{ text: "absent" }` sont deux faits différents, et le format doit rendre
la confusion impossible (c'est tout l'objet de l'ADR 001). `absent: false`
est rejeté par le harnais — pour une valeur présente, on écrit son type.

## Règles d'ajout d'un cas

1. **Anonymiser réellement.** Aucun nom d'hôte, d'utilisateur, de domaine ou
   d'adresse provenant d'un système réel. Aucun secret, même invalide, même
   expiré : le corpus est public et les blobs sont soumis au test anti-fuite.
2. **Garder le réalisme.** Une capture de corpus doit ressembler à ce que la
   machine produit vraiment : commentaires, ordre des directives, variantes de
   casse, espaces — c'est précisément ce qui piège les extracteurs.
3. **Toujours inclure au moins un fait `Absent` quand le format s'y prête.**
   « L'attribut n'existe pas » et « l'attribut vaut faux » sont deux faits
   différents (ADR 001) ; le corpus doit vérifier que l'extracteur ne les
   confond pas.
4. Tout bogue d'extraction corrigé donne lieu à un cas de corpus qui
   l'aurait attrapé.

## Les cas présents

### `sshd/basique`

Un `sshd_config` Linux réaliste et anonymisé. Points vérifiés :

- directives explicites (`PermitRootLogin no`, `PasswordAuthentication no`…) ;
- casse non normalisée et commentaires ignorés ;
- **`sshd.X11Forwarding` attendu `absent`** : la directive ne figure pas dans
  le fichier — le défaut du système s'applique, et l'extracteur ne doit ni
  l'inventer ni le confondre avec `no` (une directive en commentaire n'est
  pas une directive).

### `sshd/blocs-match`

Directives **dupliquées** (première occurrence gagnante, sémantique OpenSSH)
et blocs **`Match`** : une directive conditionnelle n'est jamais un fait
global — `X11Forwarding no` dans un bloc Match donne `absent` au niveau
global, pas `no`.

### `accounts/comptes-verrouilles`

`/etc/passwd` + `/etc/group` + `/etc/shadow` (section shadow sous forme
expurgée, la seule qui quitte la machine). Comptes **verrouillés** : `*`
(pas de mot de passe) et `!` (verrouillé, hachage conservé) sont deux états
distincts, et un compte verrouillé peut rester membre de `sudo` — le fait
d'audit par excellence. Algorithme `absent` quand aucun hachage n'existe.

### `packages/half-configured`

Fichier d'état dpkg : l'état est le **troisième mot** de `Status:`. Un paquet
`half-configured` a une version mais n'est **pas** installé au sens de la
conformité ; un paragraphe sans champ `Version:` donne `pkg.version` `absent`.

### `kernel_params/partiel`

Dump sysctl **partiel** (IPv6 désactivé au démarrage, module Yama absent) :
chaque clé de la liste blanche produit un fait même quand elle manque —
`absent`, jamais 0 ni un défaut inventé. Les clés hors liste blanche ne
produisent rien.
