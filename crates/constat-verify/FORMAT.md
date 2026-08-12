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
   de `blobs` doit exister dans `blobs/`. Échec « objet manquant » sinon.
7. **Racine** — `BLAKE3(octets du dernier fichier d'entrée)`. C'est la
   valeur à comparer aux ancrages externes.

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
Les étapes 1 à 7 ci-dessus sont l'intégralité de l'algorithme. La seule
subtilité est l'étape 5 : les octets signables sont le **ré-encodage
canonique** de l'entrée avec `signature: []` — l'encodage est déterministe
(maps ordonnées, entiers, pas de flottants), donc le ré-encodage de l'entrée
décodée redonne les octets d'origine, au champ `signature` près.
