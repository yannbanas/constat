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

- `<hex>` est l'empreinte **BLAKE3** (32 octets) des **octets du fichier**,
  en hexadécimal minuscule (64 caractères).
- Les fichiers `.cbor` contiennent **exactement** l'encodage CBOR **canonique**
  de l'objet — les mêmes octets que ceux qui ont été hachés. Le contrôle
  d'intégrité est donc, mot pour mot : **`BLAKE3(octets du fichier) == nom`**.
  Un vérificateur indépendant peut hacher **directement les octets du fichier,
  sans décoder** — c'est la méthode la plus simple et elle suffit sur tout
  export conforme.
- **L'encodage canonique est normatif, pas seulement conseillé.** Un fichier
  dont les octets ne sont **pas** l'encodage canonique de leur contenu
  (entier en forme longue, longueur de map non minimale, etc.) n'est **pas**
  conforme, même s'il se décode : il a `BLAKE3(octets) ≠ nom` et un
  vérificateur qui hache les octets bruts le **rejette**. Un vérificateur qui
  ne dispose que d'une primitive « BLAKE3 de l'encodage canonique d'un objet »
  (comme `constat-verify`, bâti sur `constat-model`) obtient le **même verdict**
  en exigeant les deux conditions équivalentes : (a) le fichier se décode en un
  objet, (b) **le ré-encodage canonique de cet objet est identique, octet pour
  octet, aux octets du fichier**, et (c) `BLAKE3(ce ré-encodage) == nom`. Comme
  (b) impose octets du fichier == encodage canonique, (c) équivaut alors à
  `BLAKE3(octets du fichier) == nom`. Un fichier non canonique est refusé au
  point (b) — voir § 3 bis. Le décodage ne sert **qu'à** ce contrôle et à
  suivre les références ; il ne « répare » jamais des octets non canoniques.
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
- **Empreinte d'une entrée** (utilisée par le chaînage `prev` et pour la
  racine) : BLAKE3 des **octets du fichier `i.cbor`** — c'est-à-dire BLAKE3 de
  l'encodage CBOR canonique de l'entrée **complète, signature incluse**. Comme
  ces octets sont canoniques (§ 3 bis), les deux formulations coïncident.
- **Empreinte d'un snapshot ou d'un blob** : BLAKE3 des **octets du fichier**.

## 3 bis. L'encodage canonique est vérifié (le fichier == ses octets hachés)

Toutes les empreintes de ce format portent sur les **octets du fichier**, pas
sur une re-sérialisation « équivalente ». CBOR autorise plusieurs encodages du
même objet (entier en forme minimale ou longue, longueur de map/chaîne sur 0,
1, 2… octets) ; un décodeur permissif — ciborium l'est — accepte les formes
non minimales. Un fichier non canonique décode donc vers le bon objet tout en
ayant `BLAKE3(octets) ≠ nom`.

Le vérificateur **exige l'encodage canonique** pour chaque fichier lu — entrée
`i.cbor`, `snapshots/<hex>.cbor`, `blobs/<hex>.cbor` — de la manière suivante,
avant tout autre contrôle sur l'objet :

1. décoder les octets du fichier en un objet ;
2. **ré-encoder canoniquement** cet objet et exiger que le résultat soit
   **identique, octet pour octet, aux octets du fichier**. Sinon : échec
   (« octets CBOR non canoniques »), l'export est refusé.

Une fois (2) acquis, les octets du fichier **sont** l'encodage canonique de
l'objet, donc `BLAKE3(octets du fichier) == BLAKE3(encodage canonique) ==
empreinte de l'objet décodé`. Le contrôle d'intégrité de l'étape 2 de
l'algorithme (nom == empreinte) est alors, au bit près, `BLAKE3(octets du
fichier) == nom` — exactement ce qu'un réimplémenteur calcule en hachant les
octets bruts.

**Pourquoi ce détour.** Un réimplémenteur dispose d'un « BLAKE3 des octets
bruts » et va au plus court. `constat-verify`, lui, ne dépend que de
`constat-model` (règle § 8) qui n'expose que « BLAKE3 de l'encodage canonique
d'un objet » ; il obtient le **même verdict** par le contrôle (1)-(2)
ci-dessus. Sur un export **conforme** (donc canonique), les deux méthodes
acceptent exactement les mêmes fichiers et rejettent exactement les mêmes ; sur
un fichier non canonique, les deux rejettent. C'est la garantie de l'§10.3 :
« vérifiable sans Constat, verdict identique ».

## 4. Algorithme de vérification

Entrées : le répertoire d'export. Sortie : « OK + racine » ou un échec
désignant l'objet et la vérification en cause.

1. **Clé** — lire `pubkey.bin` (exactement 32 octets), la décoder comme clé
   publique Ed25519. Échec sinon.
2. **Intégrité des artefacts** — pour chaque fichier de `snapshots/` et de
   `blobs/` : `BLAKE3(octets du fichier) == nom du fichier`. `constat-verify`
   l'établit via le contrôle canonique du § 3 bis (décoder, ré-encoder,
   exiger octets identiques, puis empreinte == nom). Échec « octets CBOR non
   canoniques » si le fichier n'est pas canonique, « snapshot altéré » /
   « blob altéré » si l'empreinte ne vaut pas le nom.
3. **Entrées** — lire `0.cbor`, `1.cbor`, … tant que le fichier suivant
   existe. Chaque fichier d'entrée est soumis au même contrôle canonique
   (§ 3 bis) : un fichier `i.cbor` non canonique est refusé, car son
   `BLAKE3(octets du fichier)` — l'empreinte de chaînage — ne serait pas
   celle qu'un vérificateur tiers calcule. Au moins une entrée exigée.
4. **Chaînage** — l'entrée 0 doit avoir `prev = null`. Pour chaque entrée
   `i > 0` : `prev` doit être égal à `BLAKE3(octets de (i−1).cbor)`. Échec
   « chaîne rompue à l'entrée i » sinon.
5. **Signatures** — pour chaque entrée : reconstruire les octets signables
   (champ `signature` vidé, ré-encodage canonique), vérifier la signature
   Ed25519 (64 octets) avec la **clé courante** — `pubkey.bin` jusqu'à la
   première rotation de clé valide, puis la clé déléguée (voir la section
   « Rotation de clé » ci-dessous ; sans rotation dans l'export, la clé
   courante est `pubkey.bin` du début à la fin, comme historiquement).
   Échec « signature invalide à l'entrée i » sinon.
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

## 4 ter. Rotation de clé — le suivi de la clé de signature

> Une clé de signature doit pouvoir tourner (usure, compromission) sans que
> le journal cesse d'être vérifiable, et sans que personne d'autre que le
> détenteur de la clé puisse opérer ce remplacement. La rotation est donc
> **déclarée dans le journal lui-même**, signée par l'ancienne clé — c'est
> elle qui délègue.

**Note de version du format.** Cette section est une extension **additive** :
un export sans blob `constat.rotation` se vérifie exactement comme avant,
avec `pubkey.bin` de la genèse à la racine. Un vérificateur antérieur qui
rencontre un export avec rotation échouera sur « signature invalide » à la
première entrée post-rotation : c'est le comportement sûr, jamais un faux
« OK ».

### 4 ter.1 L'enregistrement de rotation

Une rotation est déclarée par un blob ordinaire du **collecteur réservé**
`constat.rotation`, référencé par un snapshot (machine `constat`), lui-même
référencé par une **nouvelle entrée signée par l'ANCIENNE clé** — la chaîne
existante n'est jamais réécrite. Les entrées **suivantes** sont signées par
la nouvelle clé.

Le blob porte :

- dans `facts`, une entité `rotation:<horodatage ms>` avec :

  | attribut | type | contenu |
  |---|---|---|
  | `rotation.old_key` | *empreinte* (variante `Fingerprint`) | les 32 octets de l'ancienne clé publique |
  | `rotation.new_key` | *empreinte* (variante `Fingerprint`) | les 32 octets de la nouvelle clé publique |
  | `rotation.reason` | texte ou `Absent` | motif (une seule ligne), optionnel |

- dans `raw` (UTF-8), un document texte lisible (date, ancienne clé en
  hexadécimal, nouvelle clé en hexadécimal, motif) — informatif : seuls les
  faits font foi.

### 4 ter.2 La clé courante — algorithme exact

Maintenir une **clé courante**, initialisée à `pubkey.bin` (la clé de
genèse). Pour chaque entrée `i`, de la genèse à la racine :

1. vérifier la signature de l'entrée `i` avec la **clé courante**
   (étape 5) — l'entrée de rotation elle-même est donc signée par
   l'ancienne clé : c'est la délégation ;
2. ensuite, pour chaque snapshot présent référencé par `i` qui contient la
   clé de collecteur `constat.rotation` : lire le blob de rotation et
   valider la déclaration (ci-dessous). Si elle est valide, la clé courante
   **devient** `rotation.new_key` pour les entrées suivantes.

Une déclaration de rotation n'est valide que si **tout** ce qui suit est
vrai — sinon : échec « rotation invalide », l'export entier est refusé
(jamais une tolérance) :

1. le blob de rotation est **présent** dans l'export et son intégrité est
   vérifiée (étape 2). Un blob de rotation absent est un refus **même si
   son empreinte figure dans un manifeste de purge** : une entrée de
   rotation n'est jamais purgeable (voir 4 ter.4) ;
2. `rotation.old_key` et `rotation.new_key` sont présents, uniques, et
   distincts l'un de l'autre ;
3. `rotation.new_key` est une clé publique Ed25519 valide ;
4. `rotation.old_key` est **égal à la clé courante** de la chaîne à cet
   endroit. Une rotation dont `old_key` n'est pas la clé courante est une
   **tentative d'usurpation** — quelqu'un essaie de détourner la chaîne
   vers une clé qu'aucun détenteur légitime n'a déléguée — et l'export est
   refusé.

Le résultat compte les rotations suivies et restitue la **clé finale**
(celle qui signe la dernière entrée et signera la suivante) :
« N rotation(s) de clé, clé finale <hex abrégé> ».

### 4 ter.3 L'identité du journal ne change pas

`pubkey.bin` reste la clé de **genèse**, avant comme après toute rotation :
c'est l'**identité** du journal (et l'identifiant du journal côté serveur
central). La rotation change la clé de *signature courante*, jamais
l'identité — l'historique « qui a signé quoi, quand » se lit dans la chaîne
elle-même. Un vérificateur qui reçoit une clé publique de la part de
l'opérateur reçoit donc toujours la clé de genèse.

### 4 ter.4 Interaction avec la purge (§ 4 bis)

Une entrée de rotation (son snapshot et son blob `constat.rotation`) n'est
**jamais purgeable** — même règle que les enregistrements de purge, et pour
une raison plus forte encore : purger une rotation rendrait la clé courante
indéterminable, donc **toute la suite de la chaîne invérifiable**. Côté
vérificateur, un blob de rotation manquant est un échec « rotation
invalide », que son empreinte figure ou non dans un manifeste de purge.

**Portée exacte de ce contrôle, et ce qui le complète.** Le refus ci-dessus se
déclenche quand le **snapshot** de rotation est **présent** : le vérificateur y
lit la clé de collecteur `constat.rotation`, constate que le **blob** pointé
manque, et refuse. Mais si c'est le **snapshot lui-même** qui est déclaré
purgé (donc **absent** de l'export), le vérificateur ne peut pas savoir ce
qu'il portait — un snapshot absent n'a plus ni `asset` ni `blobs` à
inspecter — et il tolère l'absence comme n'importe quelle autre absence
déclarée (§ 4 bis.3). Déterminer « ce snapshot absent portait-il une
rotation ? » exigerait précisément le snapshot qui manque : c'est
**indécidable sans lui**.

Dans ce cas, l'invariant « une rotation n'est jamais purgeable » tient par un
**effet de bord garanti**, pas par un contrôle dédié : une rotation qui a
réellement eu lieu a fait signer **les entrées suivantes par la nouvelle
clé**. Si son snapshot est faussement déclaré purgé, la rotation n'est pas
suivie, la clé courante reste l'ancienne, et **la première entrée postérieure
signée par la nouvelle clé échoue à la vérification de signature** (étape 5) —
l'export est refusé. Une rotation cachée ne peut donc « passer » que si aucune
entrée ne dépend d'elle (elle est la dernière du journal) : elle est alors sans
effet observable, et l'omettre est bénin (la clé courante rapportée reste la
clé de genèse, ce qu'un réimplémenteur conclut également). Aucun scénario ne
permet à une rotation faussement purgée de valider une entrée forgée. Un
producteur conforme, du reste, ne purge jamais une rotation
(`plan_purge` la protège) : ce paragraphe ne concerne qu'un export
**malveillant**, et il en décrit le rejet.

### 4 ter.5 Ce que la rotation ne permet pas

- Elle ne « répare » pas une chaîne : chaînage, empreintes et signatures
  (étapes 3 à 5) se vérifient intégralement, rotation ou pas.
- Elle ne permet pas à un tiers de s'approprier un journal : la délégation
  exige la signature de l'entrée de rotation par la clé courante **et**
  `old_key` égal à la clé courante. Sans l'ancienne clé privée, aucune
  rotation valide n'est constructible.
- Elle ne protège pas contre un détenteur légitime malveillant : celui qui
  possède la clé courante peut déléguer à qui il veut — comme il pouvait
  déjà signer ce qu'il voulait. Les limites de §6.2 (troncature, ancrage
  externe) s'appliquent inchangées.

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
purges déclarées, et la section 4 ter s'il contient des rotations de clé)
sont l'intégralité de l'algorithme.

**Le plus court chemin** : hacher les **octets bruts** de chaque fichier
(`BLAKE3(octets) == nom` pour `snapshots/` et `blobs/` ; empreinte de chaînage
et racine = `BLAKE3(octets de i.cbor)`). C'est suffisant sur tout export
conforme, car ceux-ci sont canoniques (§ 1, § 3 bis).

Deux subtilités si l'on veut coller **au bit près** à `constat-verify` :

- **Étape 2, canonicité (§ 3 bis).** `constat-verify` ne hache pas les octets
  bruts directement (il ne dépend que de `constat-model`, qui n'expose que
  « BLAKE3 de l'encodage canonique d'un objet ») : il **décode, ré-encode
  canoniquement, exige des octets identiques**, puis compare l'empreinte au
  nom. Le verdict est le même que « BLAKE3 des octets bruts == nom » sur tout
  fichier canonique, et rejette tout fichier **non** canonique. Un
  réimplémenteur qui hache les octets bruts obtient le même verdict ; s'il veut
  la même stricte égalité, il vérifie aussi que les octets sont canoniques.
- **Étape 5, octets signables.** Ils sont le **ré-encodage canonique** de
  l'entrée avec `signature: []`. L'encodage est déterministe (maps ordonnées,
  entiers minimaux, pas de flottants), donc le ré-encodage de l'entrée décodée
  redonne les octets d'origine, au champ `signature` près — à condition, là
  encore, que le fichier `i.cbor` soit canonique (garanti par l'étape 3).
