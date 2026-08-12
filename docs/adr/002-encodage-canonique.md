# ADR 002 — Encodage canonique : CBOR canonique, BTreeMap imposé, aucun flottant haché, dates en entier UTC

- **Statut** : acceptée
- **Date** : 2026-08-12
- **Décideurs** : Yann Banas
- **Référence** : CONSTAT-ARCHITECTURE.md §15

## Contexte

Toute la chaîne de preuve de Constat repose sur des empreintes : blobs
adressés par contenu, snapshots, journal chaîné, racine de Merkle signée et
ancrée. Une empreinte ne vaut que si les **mêmes données produisent toujours
exactement les mêmes octets** — sur toutes les plateformes, toutes les
architectures, toutes les versions du logiciel, pour toute la durée de
rétention (trois ans et plus).

Trois pièges classiques, chacun suffisant à faire diverger une empreinte sur
des données identiques :

| Piège | Conséquence |
|---|---|
| Ordre des clés non déterministe (`HashMap`) | même fait, deux empreintes |
| Représentation des flottants | `1.0` contre `1`, arrondis de plateforme |
| Dates non normalisées | fuseaux, précision variable, secondes intercalaires |

Ces décisions doivent être prises au premier commit : une divergence
d'empreinte découverte après un an de collecte invaliderait tout l'historique.
Elles sont coûteuses, voire impossibles, à rattraper ensuite.

## Décision

Pour toute structure dont l'empreinte est calculée (faits, blobs, snapshots,
entrées de journal) :

1. **Encodage CBOR canonique** au sens de la RFC 8949 §4.2 : clés triées par
   représentation octale, longueurs définies, encodage entier le plus court.
   **Jamais de JSON standard pour ce qui est haché** — le JSON ne fixe ni
   l'ordre des clés, ni la représentation des nombres, ni l'échappement.
   (Le JSON et le YAML restent admis pour ce qui n'est pas haché : fichiers
   d'assertions, sorties d'affichage.)

2. **`BTreeMap` partout dans les structures hachées, jamais `HashMap`.**
   L'ordre d'itération d'une `HashMap` dépend d'une graine aléatoire par
   processus : la sérialisation de la même table donnerait des octets
   différents d'une exécution à l'autre, la déduplication s'effondrerait et
   les empreintes deviendraient instables. Le tri de `BTreeMap` rend l'ordre
   canonique structurel, pas dépendant d'une étape de normalisation qu'on
   pourrait oublier.

3. **Aucun flottant dans une valeur hachée.** Le type `Value` de
   `constat-model` n'a pas de variant flottant. Les ratios et pourcentages
   sont stockés en **entiers avec dénominateur explicite** (par exemple
   `992 / 1000` plutôt que `0.992`). Les flottants cumulent les pièges :
   représentations multiples d'une même valeur, NaN non égal à lui-même,
   arrondis dépendant de la plateforme et du mode de compilation.
   (Les flottants restent admis dans les sorties de présentation, comme le
   `observed_ratio` d'un rapport de couverture — jamais dans ce qui est haché.)

4. **Dates en UTC, précision fixe à la milliseconde, sérialisées en entier
   signé depuis l'époque Unix.** Jamais de chaîne de date dans une structure
   hachée : les représentations textuelles varient (fuseau, précision des
   fractions de seconde, forme du décalage), un entier ne varie pas.

5. **Tests permanents** :
   - un test par propriétés (`proptest`) vérifie
     `hash(decode(encode(x))) == hash(x)` sur des milliers de valeurs
     générées ;
   - le job CI `hash-stability` exécute les tests de `constat-model` sur
     x86-64 **et** sur ARM : le même corpus doit produire les mêmes
     empreintes sur les deux architectures. Ce test est non négociable.

## Conséquences

### Positives

- Les empreintes sont stables entre exécutions, plateformes et architectures :
  la déduplication fonctionne, la chaîne de preuve est vérifiable des années
  plus tard, y compris par une réimplémentation indépendante (`constat-verify`
  et au-delà : l'algorithme est réimplémentable par un auditeur méfiant).
- CBOR canonique est un standard publié (RFC 8949) : la canonicité n'est pas
  une convention interne du projet, elle est spécifiée publiquement.
- L'interdiction structurelle (pas de variant flottant, `BTreeMap` dans les
  types) vaut mieux qu'une discipline : le compilateur et la revue de code
  l'imposent.

### Négatives (assumées)

- L'encodeur doit être vérifié en canonicité (l'écosystème serde/CBOR ne
  garantit pas la forme canonique par défaut) : c'est le rôle des tests par
  propriétés et du corpus de vecteurs de test figés.
- Les ratios en entiers sont moins commodes à manipuler que des flottants —
  conversion explicite aux frontières d'affichage.
- `BTreeMap` est légèrement plus lent que `HashMap` en insertion et recherche.
  Négligeable aux volumes de Constat, et sans alternative : le déterminisme
  prime.
- Toute évolution du schéma des structures hachées devra être versionnée
  explicitement (les anciennes empreintes restent vérifiables avec l'ancien
  schéma) — cette rigueur est le prix d'un historique opposable.
