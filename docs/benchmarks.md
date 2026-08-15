# Benchmarks de charge

Ce document rapporte des mesures **réelles** produites par le harnais `bench/`
(voir `bench/README.md` pour le relancer). Objectif : vérifier chiffres en main
la promesse économique du §3.3 de l'architecture — *« sur un parc de deux cents
machines qui ne bougent pas, une collecte quotidienne ne stocke presque rien […]
c'est ce qui rend viable une rétention de trois ans »* — et identifier les
goulots avant la production.

## Méthode

Un parc simulé est ingéré dans un **vrai** `RedbStore` sur disque, puis
interrogé. Chaque scénario : **200 machines × 90 jours × 4 collectes/jour =
72 000 snapshots**, ~150 faits par machine répartis sur les collecteurs réels
(comptes, sshd, ~120 paquets, ports, paramètres noyau), une seule clé de
signature, horodatages déterministes (graine fixe). Le seul paramètre qui varie
est le **taux de dérive** : la part des machines qui changent un fait par jour.

- `parc-fige` — dérive 0 % (borne basse de stockage) ;
- `nominal` — dérive 1 %/jour (le cas de la promesse) ;
- `parc-agite` — dérive 10 %/jour (borne haute).

**Machine de mesure** : Intel Core i5-9300H (4 cœurs, 2,4 GHz, 2019), 16 Gio RAM,
SSD NVMe, Windows 11. C'est un portable de milieu de gamme — un serveur récent
fera mieux. Les chiffres sont donc **conservateurs**.

## Résultats

| Mesure | parc-figé (0 %) | nominal (1 %) | parc-agité (10 %) |
|---|--:|--:|--:|
| Ingestion (snapshots/s) | 272 | 350 | 242 |
| **Magasin à 90 j** | **89,5 Mio** | **89,6 Mio** | **100,8 Mio** |
| Données collectées (cumul) | 1 616 Mio | 1 616 Mio | 1 616 Mio |
| **Ratio stocké / collecté** | **0,049** | **0,055** | **0,062** |
| Blobs distincts à 90 j | 603 | 781 | 2 286 |
| Snapshots stockés | 72 000 | 72 000 | 72 000 |
| Extrapolation 3 ans (linéaire) | ~1,09 Gio | ~1,09 Gio | ~1,23 Gio |
| `state --at` (médiane) | 6,05 s | 2,11 s | 3,33 s |
| `history` d'une entité | 23,4 s | 15,0 s | 16,2 s |
| `check` parc entier, 90 j | 41 s | 26 s | 26 s |
| **`check` — mémoire de pointe** | **4,8 Gio** | **4,9 Gio** | **4,8 Gio** |
| Export (répertoire vérifiable) | 311 s | 292 s | 351 s |
| Taille de l'export | 44,9 Mio | 47,9 Mio | 47,9 Mio |
| **`constat-verify` de l'export** | **0,73 s** | **1,76 s** | **0,73 s** |

## Analyse

### La promesse §3.3 tient — largement

Même le parc **agité** (10 % de changements quotidiens, très au-delà d'un parc
réel) stocke **6 % de ce qu'il collecte**, et un parc nominal **5,5 %**. Sur
trois ans, 200 machines tiennent dans **~1,1 à 1,2 Gio** — une clé USB. La
rétention de trois ans annoncée par la spec n'est pas un vœu : c'est mesuré, et
confortable. La déduplication + zstd font exactement ce qui était promis.

**Nuance importante révélée par la mesure** : ce ne sont pas les blobs qui
dominent le magasin, ce sont les **manifestes de snapshots**. Un parc figé ne
stocke que 603 blobs distincts sur 90 jours — mais 72 000 snapshots, chacun
étant un petit manifeste (machine + date + table collecteur→empreinte) écrit à
chaque collecte, même quand rien ne change. C'est ~1,2 Kio par snapshot. C'est
ce plancher, et non les données, qui fixe la taille du magasin. Conséquence
pratique : la taille dépend surtout du **nombre de collectes** (machines ×
fréquence × durée), très peu de la dérive. Réduire la fréquence de collecte est
le levier de stockage le plus efficace ; la purge de rétention (§16) borne le
reste.

### L'ingestion n'est pas un goulot

242–350 snapshots/s. Un vrai parc de 200 machines collectant toutes les 6 h
produit **800 snapshots/jour**, soit ~3 secondes d'ingestion quotidienne côté
serveur. Il faudrait un parc de plusieurs **milliers** de machines pour que
l'ingestion devienne visible. La signature Ed25519 (~150–370 µs/entrée) et le
hachage BLAKE3 (~14–42 µs/blob) sont négligeables.

### Goulot n° 1 — la mémoire de `check` et `history` (à corriger avant les gros parcs)

**C'est le point d'attention le plus sérieux.** `check` sur tout le parc et
toute la période charge **11 millions d'observations en mémoire** et culmine à
**~4,8 Gio**. Sur cette configuration (200 machines × 90 jours) ça passe ; mais
la consommation croît linéairement avec `machines × durée`. Extrapolé à 3 ans,
le même parc demanderait **plusieurs dizaines de Gio** — un OOM.

`history` (pic ~4 Gio) souffre du même schéma : il matérialise toutes les
observations avant de filtrer.

**Recommandation** : rendre `check` et `history` **fenêtrés/en flux** — évaluer
par tranches de temps (ou par machine) et agréger, plutôt que tout charger. Le
cœur pur (`constat-time`, `constat-policy`) est déjà par machine ; c'est
l'adaptateur `constat-cli` (`eval::build_inputs`, `queries::observations`) qui
matérialise tout. C'est un chantier ciblé, sans changement de format ni de
sémantique. **À faire avant tout déploiement sur un parc large ou une longue
rétention.** En l'état, `check`/`history` conviennent à un parc de quelques
centaines de machines sur des périodes de quelques mois, ou à une machine
dotée de beaucoup de RAM.

### Goulot n° 2 — la latence de `state --at` (gênant en interactif)

2 à 6 secondes pour restituer l'état d'**une** machine à **une** date. Pour une
commande d'audit ponctuelle c'est tolérable ; pour un usage interactif répété
c'est lent. La cause probable : le parcours cherche le bon snapshot sans index
temporel par machine. **Recommandation** : un index (machine → snapshots triés
par date) rendrait `state` quasi instantané. Non bloquant, mais à prévoir.

### Ce qui est déjà excellent — la vérification

L'export est lent (~5 min) mais c'est du **remplissage de 73 000 petits
fichiers**, borné par le système de fichiers, fait une fois pour constituer un
dossier. En revanche `constat-verify` — le chemin de l'auditeur, celui qui doit
inspirer confiance — vérifie 72 000 snapshots et 360 entrées signées en
**moins de 2 secondes**. La preuve est chère à produire, quasi gratuite à
contrôler : exactement le bon compromis.

## Verdict

| Aspect | Verdict |
|---|---|
| Promesse de stockage §3.3 (3 ans / 200 machines ≈ 1 Gio) | ✅ **tenue, avec marge** |
| Ingestion | ✅ non goulot jusqu'à plusieurs milliers de machines |
| Vérification par un tiers | ✅ < 2 s, excellent |
| `check` / `history` — mémoire | ⚠️ **à fenêtrer avant les gros parcs / longues rétentions** |
| `state --at` — latence | ⚠️ à indexer (confort, non bloquant) |

Pour un **pilote** (dizaines à quelques centaines de machines, quelques mois) :
les performances sont bonnes en l'état. Pour un **déploiement large ou une
rétention de plusieurs années**, le fenêtrage de `check`/`history` est le
prérequis n° 1, identifié ici chiffres à l'appui.
