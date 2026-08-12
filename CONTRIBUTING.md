# Contribuer à Constat

Merci de votre intérêt. Constat est un outil de preuve : la barre de qualité est
volontairement haute, parce que la sortie du logiciel sert de pièce d'audit.
Ce document décrit ce qui est attendu de toute contribution.

## Avant de commencer

Lisez [CONSTAT-ARCHITECTURE.md](CONSTAT-ARCHITECTURE.md), en particulier :

- §1 — les trois contraintes (lecture seule, cœur pur, aucune exécution arbitraire) ;
- §15 — la sérialisation canonique ;
- §17 — la chaîne d'approvisionnement ;
- §18 — les huit principes à ne pas trahir.

Une contribution qui viole l'un de ces principes sera refusée, quelle que soit
sa qualité technique.

## Conventions de code

### Obligatoire sur chaque PR

```bash
cargo fmt --all                          # formatage (rustfmt.toml à la racine)
cargo clippy --workspace --all-targets   # aucun nouvel avertissement introduit
cargo test --workspace                   # tous les tests passent
```

La CI exécute ces trois commandes sur Linux et Windows, plus `cargo-deny` et le
test de stabilité d'empreinte multi-architecture (x86-64 et ARM). Une PR dont
la CI est rouge n'est pas relue.

### Tests obligatoires

Tout changement de comportement est accompagné de tests. Selon la couche :

- **cœur pur** (`constat-model`, `constat-time`, `constat-policy`, `constat-diff`) :
  tests unitaires, et tests par propriétés (`proptest`) pour tout ce qui touche
  aux intervalles, à la couverture ou à la sérialisation ;
- **extracteurs de faits** : tests par instantanés (`insta`) et, si l'entrée est
  un format de configuration, un cas dans `corpus/` ;
- **magasin et journal** : le test d'altération (modification volontaire du
  magasin → le vérificateur doit crier) ne doit jamais régresser.

### Règles non négociables dans le cœur

Ces règles découlent du §15 de la spécification — l'empreinte d'un même ensemble
de données doit être stable sur toutes les plateformes, pour toujours :

- **`BTreeMap`, jamais `HashMap`**, dans toute structure sérialisée ou hachée.
  L'ordre d'itération d'une `HashMap` n'est pas déterministe : même fait, deux
  empreintes, déduplication effondrée.
- **Aucun flottant** dans une valeur hachée (`Value`, faits, snapshots). Les
  ratios sont stockés en entiers avec dénominateur explicite.
- **Dates en UTC, précision milliseconde, entier depuis l'époque Unix.** Jamais
  de chaîne de date dans une structure hachée.
- **Encodage CBOR canonique** (RFC 8949 §4.2) pour tout ce qui est haché.
  Jamais de JSON standard.
- Les crates purs ne font **aucune entrée-sortie** et ne dépendent que de
  crates purs.

### Dépendances : aucune sans justification écrite

Conformément au §17 : peu de dépendances, et **aucune ajoutée sans justification
écrite**. Toute PR qui ajoute une entrée à un `Cargo.toml` doit contenir, dans
sa description :

1. le besoin précis, et pourquoi il ne peut pas être couvert par la bibliothèque
   standard ou une dépendance existante ;
2. l'examen de la crate : mainteneurs, activité, dépendances transitives,
   licence, `unsafe` ;
3. la surface introduite dans l'arbre (`cargo tree`) et le verdict de
   `cargo deny check`.

Une dépendance dans un crate pur qui fait de l'entrée-sortie, ou une dépendance
sous licence copyleft fort, est refusée d'office (voir `deny.toml`).

## Certificat d'origine (DCO)

Le projet utilise le [Developer Certificate of Origin](https://developercertificate.org/)
(DCO 1.1) plutôt qu'un CLA. En signant vos commits, vous certifiez que vous avez
le droit de soumettre votre contribution sous la licence Apache-2.0 du projet.

Chaque commit doit porter la ligne :

```
Signed-off-by: Prénom Nom <adresse@exemple.org>
```

soit `git commit -s`. Les PR dont les commits ne sont pas signés seront
renvoyées avec une demande de re-signature.

## Processus ADR

Les décisions d'architecture sont consignées dans `docs/adr/` au format
classique (contexte / décision / conséquences). Les ADR existantes font foi :
une PR qui contredit une ADR acceptée doit d'abord proposer une nouvelle ADR
qui la remplace.

Quand écrire une ADR : tout choix difficile à défaire ensuite — format de
sérialisation, schéma du magasin, protocole, ajout d'une dépendance lourde,
modification du modèle de données.

Procédure :

1. copier le gabarit d'une ADR existante :
   `docs/adr/NNN-titre-court.md` (numéro suivant, titre en minuscules avec tirets) ;
2. statut initial : « proposée » ; renseigner contexte, décision, conséquences
   (y compris les conséquences négatives — une ADR sans inconvénient est suspecte) ;
3. ouvrir une PR dédiée à l'ADR ; la discussion a lieu sur la PR ;
4. au merge, le statut passe à « acceptée » avec la date. Une ADR remplacée
   passe à « remplacée par NNN » — on ne supprime jamais une ADR.

## En pratique

- Une PR = un sujet. Les PR fourre-tout sont découpées.
- Les messages de commit expliquent le *pourquoi*, pas seulement le *quoi*.
- Les questions se posent dans les issues ; les vulnérabilités, jamais dans les
  issues — voir [SECURITY.md](SECURITY.md).
