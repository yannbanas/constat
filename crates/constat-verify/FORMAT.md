# Format d'export et algorithme de vérification — document normatif

Ce document décrit **exactement** ce que `constat-verify` attend et vérifie.
Il est volontairement assez simple pour qu'un auditeur méfiant réimplémente
la vérification en une centaine de lignes, dans le langage de son choix,
sans faire confiance à Constat (§10.3 de l'architecture).

## 1. Layout du répertoire d'export

```
export/
├── pubkey.bin              clé publique Ed25519 du signataire : 32 octets bruts
├── 0.cbor                  entrée de journal 0 (la genèse), CBOR canonique
├── 1.cbor … N.cbor         entrées suivantes — indices consécutifs, sans trou
├── snapshots/
│   └── <hex>.cbor          un snapshot par fichier
└── blobs/
    └── <hex>.cbor          un blob par fichier
```

- `<hex>` est l'empreinte **BLAKE3** (32 octets) du contenu du fichier,
  en hexadécimal minuscule (64 caractères).
- Les fichiers `.cbor` contiennent **exactement** l'encodage CBOR canonique
  de l'objet — les mêmes octets que ceux qui ont été hachés. Un vérificateur
  indépendant peut donc hacher directement les octets du fichier, sans
  décoder, pour contrôler `blobs/` et `snapshots/`.
- Les répertoires `snapshots/` et `blobs/` peuvent être absents s'ils sont
  vides. Les fichiers non référencés par le journal sont tolérés mais leur
  intégrité est tout de même vérifiée.

## 2. Structures (CBOR, encodage serde/ciborium)

Les structures sont des maps CBOR à clés textuelles, champs dans l'ordre de
déclaration. Types élémentaires :

- *empreinte* : tableau de 32 entiers (octets) ;
- *date* : entier, millisecondes UTC depuis l'époque Unix ;
- *octets* : tableau d'entiers (octets).

**Entrée de journal** (`0.cbor`, `1.cbor`, …) :

| clé | type |
|---|---|
| `prev` | `null` (genèse uniquement) ou *empreinte* de l'entrée précédente |
| `snapshots` | tableau d'*empreintes* de snapshots |
| `at` | *date* |
| `signature` | *octets* — signature Ed25519, 64 octets |

**Snapshot** (`snapshots/<hex>.cbor`) :

| clé | type |
|---|---|
| `asset` | texte (identifiant de machine) |
| `at` | *date* |
| `blobs` | map texte (collecteur) → *empreinte* de blob |

**Blob** (`blobs/<hex>.cbor`) :

| clé | type |
|---|---|
| `collector` | texte |
| `raw` | *octets* — l'artefact brut, après expurgation |
| `facts` | tableau de faits (opaque pour la vérification) |

## 3. Le schéma de signature et d'empreinte (contrat, au bit près)

- **Octets signables** d'une entrée : l'encodage CBOR canonique de l'entrée
  avec le champ `signature` remplacé par un tableau **vide**
  (`{prev, snapshots, at, signature: []}`).
- **Signature** : Ed25519 sur ces octets signables, vérifiable avec
  `pubkey.bin` (vérification stricte : point canonique, pas de clé de petit
  ordre).
- **Empreinte d'une entrée** (utilisée par le chaînage `prev`) : BLAKE3 de
  l'encodage CBOR canonique de l'entrée **complète, signature incluse** —
  c'est-à-dire BLAKE3 des octets du fichier `i.cbor`.
- **Empreinte d'un snapshot ou d'un blob** : BLAKE3 des octets du fichier.

## 4. Algorithme de vérification

Entrées : le répertoire d'export. Sortie : « OK + racine » ou un échec
désignant l'objet et la vérification en cause.

1. **Clé** — lire `pubkey.bin` (exactement 32 octets), la décoder comme clé
   publique Ed25519. Échec sinon.
2. **Intégrité des artefacts** — pour chaque fichier de `snapshots/` et de
   `blobs/` : `BLAKE3(octets du fichier) == nom du fichier`. Échec
   « snapshot altéré » / « blob altéré » sinon.
3. **Entrées** — lire `0.cbor`, `1.cbor`, … tant que le fichier suivant
   existe. Au moins une entrée exigée.
4. **Chaînage** — l'entrée 0 doit avoir `prev = null`. Pour chaque entrée
   `i > 0` : `prev` doit être égal à `BLAKE3(octets de (i−1).cbor)`. Échec
   « chaîne rompue à l'entrée i » sinon.
5. **Signatures** — pour chaque entrée : reconstruire les octets signables
   (champ `signature` vidé, ré-encodage canonique), vérifier la signature
   Ed25519 (64 octets) avec la clé publique. Échec « signature invalide à
   l'entrée i » sinon.
6. **Références** — pour chaque entrée : chaque empreinte de `snapshots`
   doit exister dans `snapshots/` ; pour chaque snapshot, chaque empreinte
   de `blobs` doit exister dans `blobs/`. Échec « objet manquant » sinon —
   à **une** exception près : une absence **déclarée par une purge
   journalisée postérieure** (voir la section « Objets purgés » ci-dessous).
7. **Racine** — `BLAKE3(octets du dernier fichier d'entrée)`. C'est la
   valeur à comparer aux ancrages externes.

## 4 bis. Objets purgés — les absences déclarées (§16 de l'architecture)

> Une suppression liée à la rétention crée un trou dans les données, et un
> trou non déclaré est indistinguable d'un effacement malveillant. La purge
> écrit donc dans le journal **qu'elle a eu lieu**, sur quelle période et
> pour quel motif, sans réécrire la chaîne.

**Note de version du format.** Cette section est une extension **additive**
introduite après la v0.3.0 : un export produit avant la purge (sans blob
`constat.purge`) reste valide et se vérifie exactement comme avant — l'étape
6 historique s'applique alors sans exception. Un vérificateur antérieur qui
rencontre un export purgé échouera sur « objet manquant » : c'est le
comportement sûr, jamais un faux « OK ».

### 4 bis.1 L'enregistrement de purge

Une purge est déclarée par un blob ordinaire du **collecteur réservé**
`constat.purge`, référencé par un snapshot (machine `constat`), lui-même
référencé par une **nouvelle entrée signée** — la chaîne existante n'est
jamais réécrite, la déclaration s'ajoute à la fin.

Le blob porte :

- dans `facts`, une entité `purge:<horodatage ms>` avec exactement :

  | attribut | type | contenu |
  |---|---|---|
  | `purge.from` | entier | début de la période purgée (ms UTC) |
  | `purge.to` | entier | fin de la période purgée (ms UTC), ≥ `purge.from` |
  | `purge.reason` | texte | motif (une seule ligne) |
  | `purge.objects` | entier | nombre d'empreintes purgées |
  | `purge.manifest` | *empreinte* (variante `Fingerprint`) | BLAKE3 de la **liste canonique** (ci-dessous) |

- dans `raw` (UTF-8), un document texte lisible qui contient la **liste
  complète des empreintes purgées** : toute ligne du document composée —
  après suppression des blancs de début et de fin — d'exactement **64
  caractères hexadécimaux minuscules** est une empreinte de la liste ; toute
  autre ligne est du commentaire lisible (date, motif, période…).

**Liste canonique** : les empreintes relues de `raw`, triées par ordre
croissant d'octets et dédupliquées. **Manifeste** : BLAKE3 de l'encodage
CBOR canonique de cette liste (un tableau de tableaux de 32 entiers — le
même encodage que partout ailleurs dans ce format).

### 4 bis.2 Validité d'une déclaration

Une déclaration n'est prise en compte que si **tout** ce qui suit est vrai
(sinon : échec « déclaration de purge invalide », l'export est refusé) :

1. le blob est présent dans l'export et son intégrité est vérifiée (étape 2) ;
2. `purge.from` ≤ `purge.to` et `purge.objects` ≥ 0 ;
3. le nombre d'empreintes de la liste canonique est égal à `purge.objects` ;
4. le manifeste recalculé sur la liste canonique est égal à `purge.manifest`.

### 4 bis.3 L'étape 6 modifiée — algorithme exact

Avant l'étape 6, construire l'index des purges : pour chaque entrée `j` (de
la genèse à la racine), pour chaque snapshot présent référencé par `j` qui
contient la clé de collecteur `constat.purge`, lire et valider la
déclaration ; pour chaque empreinte `h` de sa liste canonique, retenir
`decl(h)` = le **plus petit** `j` qui la déclare.

À l'étape 6, une empreinte référencée à l'entrée `i` (snapshot manquant, ou
blob manquant référencé par un snapshot de l'entrée `i`) mais absente de
l'export est **tolérée** si et seulement si `decl(h)` existe et
`decl(h) > i` — la déclaration est **strictement postérieure** dans la
chaîne à la référence : une purge suit toujours la donnée qu'elle supprime,
jamais l'inverse. Toute autre absence reste un échec « objet manquant ».

Le résultat compte les empreintes tolérées (`purged_count`) et restitue
chaque déclaration (période, motif, nombre d'objets, manifeste) :
« cohérent — N objet(s) purgé(s) déclaré(s) (période …, motif …) ».

### 4 bis.4 Ce que la purge déclarée ne permet pas

- Elle ne supprime **jamais** d'entrée de journal : les fichiers `0.cbor` …
  `N.cbor` restent des indices consécutifs, sans trou, et la chaîne se
  vérifie intégralement (étapes 3 à 5 inchangées).
- Elle ne couvre pas une entrée manquante, une signature invalide, ni un
  objet **présent mais altéré** : seules les *absences* listées dans un
  manifeste valide et postérieur sont tolérées.
- Un objet présent dont l'empreinte figure dans un manifeste se vérifie
  normalement : déclarer plus que ce qui a réellement disparu est bénin.

## 5. Ce que cette vérification prouve — et ne prouve pas

**Elle prouve** que l'export est **intérieurement cohérent** : personne n'a
modifié, inséré ou supprimé une entrée *au milieu* de la chaîne, ni altéré un
artefact référencé, sans posséder la clé privée.

**Elle ne prouve pas** (§6.2 de l'architecture, à lire noir sur blanc) :

- **la non-troncature** : celui qui contrôle le magasin et la clé peut
  supprimer la fin du journal, ou tout effacer et repartir de zéro. La parade
  est l'ancrage externe (§6.3) : comparez la racine calculée à l'étape 7 avec
  une racine envoyée hors du système (courriel au RSSI, dépôt tiers) ou avec
  un jeton d'horodatage RFC 3161 délivré par un prestataire de confiance ;
- **la sincérité des agents** : un agent compromis peut mentir sur l'état de
  sa machine. Le journal prouve ce qui a été *enregistré*, pas ce qui était
  *vrai* ;
- quoi que ce soit sur une machine où aucun agent n'a jamais collecté.

## 6. Réimplémentation

Un vérificateur indépendant a besoin de : un décodeur CBOR, BLAKE3, Ed25519.
Les étapes 1 à 7 ci-dessus (plus la section 4 bis si l'export contient des
purges déclarées) sont l'intégralité de l'algorithme. La seule subtilité est
l'étape 5 : les octets signables sont le **ré-encodage canonique** de
l'entrée avec `signature: []` — l'encodage est déterministe (maps ordonnées,
entiers, pas de flottants), donc le ré-encodage de l'entrée décodée redonne
les octets d'origine, au champ `signature` près.
