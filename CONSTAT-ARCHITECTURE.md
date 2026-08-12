# Constat — architecture de développement

> **Ce que c'est** : un outil qui enregistre l'état de configuration d'une infrastructure dans la durée, de façon non falsifiable, et qui produit la preuve qu'un auditeur accepte.
> **Licence** : Apache-2.0
> **Langage** : Rust
> **Statut** : spécification de développement, v1

---

## 1. La règle qui structure tout le projet

> **Lecture seule, toujours. Cœur pur. Aucune exécution de code arbitraire, nulle part.**

Ces trois contraintes ne sont pas des limitations : ce sont les arguments de vente.

- **Lecture seule** — `Constat` ne peut rien casser. C'est ce qui rend le produit acceptable sur un parc de production et ce qui borne la responsabilité de l'éditeur.
- **Cœur pur** — `constat-model`, `constat-time`, `constat-policy` et `constat-diff` ne font aucune entrée-sortie. Donc testables exhaustivement, et surtout : deux évaluations sur les mêmes données donnent le même verdict. Indispensable pour un outil dont la sortie sert de preuve.
- **Aucune exécution arbitraire** — l'agent n'a pas, et n'aura jamais, la capacité d'exécuter un script envoyé par le serveur. C'est ce qui empêche `Constat` de devenir le vecteur de compromission de tout le parc.

Un test d'intégration continue vérifie l'arbre de dépendances et échoue si une impureté entre dans le cœur.

---

## 2. Le problème réel, et pourquoi les outils existants ne le résolvent pas

Un auditeur demande : « prouvez que le 3 mars, la connexion root en SSH était désactivée sur tous vos serveurs. »

| Outil | Ce qu'il sait | Ce qui manque |
|---|---|---|
| SIEM | les **événements** : « une commande a été lancée à 14h32 » | l'**état** à une date donnée |
| Ansible, Puppet | l'**intention** : ce qui *devrait* être | ce qui **était**, et l'historique |
| osquery, GLPI, Wazuh | l'état **actuel** | l'historique, et la non-falsifiabilité |
| Plateformes GRC | ce que l'humain a **déclaré** dans un formulaire | le lien avec la réalité machine |

Analogie : un SIEM, c'est la caméra du couloir — elle filme les passages. L'auditeur, lui, veut **l'inventaire de la pièce à une date donnée**, avec la garantie que personne n'a modifié l'inventaire après coup.

---

## 3. Le modèle de données

### 3.1 Deux choses à stocker, pas une

C'est la première décision de conception, et elle est structurante.

| | Pour quoi | Forme |
|---|---|---|
| **L'artefact brut** | la preuve — un auditeur peut vouloir lire le vrai `sshd_config` | texte, tel que collecté, après expurgation |
| **Les faits extraits** | l'interrogation et l'évaluation des règles | triplets typés |

Ne stocker que les faits, c'est perdre la valeur probante. Ne stocker que le brut, c'est ne rien pouvoir interroger. **Les deux, dédupliqués.**

### 3.2 Les faits

```rust
// constat-model — pur

pub struct Fact {
    pub entity:    EntityId,      // "user:root", "service:sshd", "pkg:openssh-server"
    pub attribute: Attribute,     // "sshd.PermitRootLogin", "user.privileged"
    pub value:     Value,
}

pub enum Value {
    Bool(bool),
    Int(i64),
    Text(String),
    List(Vec<Value>),
    Fingerprint([u8; 32]),   // empreinte d'un secret, jamais le secret
    Absent,                  // l'absence est un fait, et souvent LE fait important
}
```

**Pourquoi le modèle entité-attribut-valeur plutôt que des structures typées par collecteur.** Trois raisons :

1. Une règle peut porter sur plusieurs collecteurs et plusieurs systèmes d'exploitation sans code spécifique.
2. Le calcul de différence devient générique : une différence, c'est une soustraction d'ensembles de triplets.
3. Ajouter un collecteur n'oblige pas à modifier le moteur.

**`Absent` mérite son variant.** En conformité, « l'attribut n'existe pas » et « l'attribut vaut faux » sont deux choses différentes. Un `sshd_config` sans directive `PermitRootLogin` applique le défaut du système, qui varie. Confondre les deux produit des verdicts faux.

### 3.3 Le magasin, calqué sur Git

```
Blob      = les faits + le brut d'UN collecteur sur UNE machine, sérialisés
            → adressé par son empreinte
Snapshot  = manifeste : machine + date + { collecteur → empreinte de blob }
            → adressé par son empreinte
Entry     = entrée du journal : empreinte de l'entrée précédente
            + empreintes de snapshots + date + signature
```

**La granularité du blob est par collecteur, et c'est le bon compromis.** Un blob par machine ferait tout réécrire au moindre changement. Un blob par fait produirait des millions de minuscules objets. Un blob par collecteur regroupe ce qui change ensemble.

**Conséquence économique décisive** : sur un parc de deux cents machines qui ne bougent pas, une collecte quotidienne ne stocke presque rien — les empreintes sont identiques, on n'écrit qu'une référence. C'est ce qui rend viable une rétention de trois ans.

---

## 4. Le modèle temporel — la vraie difficulté, et le vrai différenciateur

### 4.1 Le piège de l'instantané

Approche naïve : stocker des instantanés aux dates T1, T2, T3, et répondre « état à T » en cherchant le dernier antérieur.

Ça marche, et **c'est malhonnête**.

Si tu collectes une fois par jour et que quelqu'un active la connexion root à 14h puis la désactive à 16h, ton instantané ne l'a jamais vue. Affirmer « conforme sur toute la période » serait un mensonge.

### 4.2 Des intervalles avec couverture, pas des points

```rust
// constat-time — pur

pub enum Coverage {
    /// On a observé, à cette date précise.
    Observed { at: Timestamp },

    /// Deux observations encadrantes, sans changement constaté,
    /// avec l'écart maximal entre deux collectes sur l'intervalle.
    Inferred { from: Timestamp, to: Timestamp, max_gap: Duration },

    /// Aucune donnée : agent arrêté, machine éteinte, collecte en échec.
    Gap { from: Timestamp, to: Timestamp, reason: GapReason },
}

pub struct CoverageReport {
    pub period:        Period,
    pub observed_ratio: f64,      // part de la période réellement couverte
    pub max_gap:       Duration,
    pub gaps:          Vec<Gap>,  // déclarés explicitement, jamais masqués
}
```

Une affirmation ne renvoie donc jamais un simple vrai ou faux. Elle renvoie **un verdict accompagné de sa couverture** :

```
Conforme sur la période du 01/01 au 31/03.
  Couverture : 99,2 % — écart maximal entre deux collectes : 26 h
  3 interruptions déclarées :
    - srv-fic-02  : 12/02 03h00 → 12/02 07h12  (machine arrêtée, maintenance)
    - srv-app-01  : 28/02 14h00 → 28/02 14h45  (agent indisponible)
    - srv-app-01  : 03/03 01h00 → 03/03 09h30  (agent indisponible)
```

> **C'est ce qui distingue une preuve d'un joli tableau de bord.** Un auditeur qui lit « 100 % conforme, aucune interruption » sait que l'outil ment. Un auditeur qui voit les trous déclarés fait confiance au reste.

C'est aussi la fonctionnalité la plus difficile à copier, parce qu'elle exige d'avoir choisi le bon modèle dès le départ.

---

## 5. Le langage d'assertions

### 5.1 Volontairement faible

```rust
// constat-policy — pur

pub struct Assertion {
    pub id:         AssertionId,
    pub title:      String,
    pub scope:      AssetSelector,
    pub predicate:  Predicate,
    pub exceptions: Vec<Exception>,   // documentées, justifiées, datées
}

pub enum Predicate {
    Never   { entity: EntityPattern, attr: Attribute, equals: Value },
    Always  { entity: EntityPattern, attr: Attribute, equals: Value },
    ForAll  { over: EntityPattern, satisfies: Box<Predicate> },
    Exists  { matching: EntityPattern },
    Fresher { entity: EntityPattern, attr: Attribute, than: Duration },
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
}
```

**Ne pas écrire un langage de script.** Ni Rhai, ni Lua, ni Starlark. Trois raisons :

1. Un prédicat total et terminant peut être analysé, expliqué et prouvé. Un langage complet, non.
2. Un moteur de règles capable d'exécuter du code arbitraire est une faille dans un outil de conformité.
3. C'est ce qui permet à `Constat` d'expliquer **pourquoi** une assertion échoue, pas seulement qu'elle échoue.

### 5.2 En YAML

```yaml
assertions:
  - id: SSH-ROOT
    title: la connexion root en SSH est désactivée
    scope: { os: linux }
    predicate:
      never: { entity: "service:sshd", attr: "sshd.PermitRootLogin", equals: "yes" }

  - id: ADM-MFA
    title: tous les comptes privilégiés ont l'authentification forte
    scope: { domain: "*" }
    predicate:
      forall:
        over: { type: user, where: { privileged: true } }
        satisfies:
          always: { attr: "user.mfa_enabled", equals: true }
    exceptions:
      - entity: "user:svc-sauvegarde"
        reason: "compte de service, authentification par certificat"
        approved_by: "RSSI"
        expires: 2027-01-01     # une exception sans date d'expiration est un mensonge

  - id: BKP-24H
    title: sauvegarde réussie dans les dernières 24 heures
    scope: { tag: production }
    predicate:
      fresher: { attr: "backup.last_success", than: 24h }
```

Le champ `expires` sur chaque exception est obligatoire par conception. Une exception permanente n'est pas une exception, c'est un changement de politique non assumé.

### 5.3 L'évaluation explique

```rust
pub struct Evaluation {
    pub verdict:   Verdict,           // Pass | Fail | Undetermined
    pub coverage:  CoverageReport,
    pub violations: Vec<Violation>,
}

pub struct Violation {
    pub asset:     AssetId,
    pub entity:    EntityId,
    pub observed:  Value,
    pub expected:  Value,
    pub first_seen: Timestamp,
    pub last_seen:  Timestamp,
    pub evidence:  BlobHash,          // vers l'artefact brut
}
```

`Undetermined` est un verdict à part entière : la couverture était insuffisante pour se prononcer. Un outil qui n'a que « conforme » et « non conforme » ment forcément dans un cas sur deux.

---

## 6. La non-falsifiabilité — modèle de menace explicite

Section la plus importante du document. Un outil de preuve qui surestime ses garanties est pire qu'inutile.

### 6.1 Ce que le journal Merkle protège

Chaque entrée contient l'empreinte de la précédente. Modifier ou insérer une entrée au milieu casse la chaîne, et c'est détectable immédiatement.

### 6.2 Ce qu'il ne protège pas

**La troncature.** Celui qui contrôle le magasin et la clé de signature peut supprimer la fin du journal, ou tout effacer et repartir à zéro. Or c'est précisément l'administrateur audité qui fait tourner l'outil.

> Sans ancrage externe, le journal prouve la **cohérence interne**, pas la **non-répudiation**. Ce doit être écrit noir sur blanc dans la documentation et dans chaque dossier généré.

### 6.3 L'ancrage externe, par ordre de force

| Niveau | Mécanisme | Protège contre |
|---|---|---|
| 0 | signature locale | modification accidentelle |
| 1 | chaînage Merkle | réécriture de l'historique |
| 2 | racine envoyée quotidiennement hors du système (courriel au RSSI, dépôt tiers) | troncature simple |
| 3 | **horodatage qualifié RFC 3161** auprès d'un prestataire de confiance | troncature, et opposabilité juridique |
| 4 | co-signature par un tiers (infogérant, auditeur) | collusion d'un seul acteur |

Le niveau 3 est le bon objectif produit : l'horodatage qualifié est reconnu par le règlement eIDAS, des prestataires qualifiés français existent, et ça transforme le dossier en pièce opposable. **C'est aussi un argument de souveraineté réel, pas décoratif.**

### 6.4 Ce que `Constat` ne prétend pas faire

- Détecter un agent compromis qui mentirait sur l'état de sa machine. Un agent est une source, pas un oracle.
- Prouver quoi que ce soit sur une machine où l'agent n'a jamais été installé. D'où l'importance de l'inventaire des machines *attendues* face aux machines *observées* — l'écart est lui-même un constat.
- Remplacer une supervision temps réel. La granularité est celle de la collecte.

Écrire ces limites dans le produit augmente la confiance au lieu de la diminuer.

---

## 7. L'agent

### 7.1 Contraintes de sécurité, non négociables

L'agent tourne sur toutes les machines et lit des configurations sensibles. C'est une cible de premier choix.

| Contrainte | Raison |
|---|---|
| **Aucun port en écoute.** Poussée sortante en mTLS uniquement. | compromettre le serveur ne donne pas d'exécution de code sur le parc |
| **Aucune exécution de code envoyé.** Les collecteurs sont compilés dans le binaire. | supprime la classe entière des attaques par la chaîne de gestion |
| **Privilèges minimaux.** Capacités Linux ciblées plutôt que root complet quand c'est possible, abandon après collecte. | réduction du rayon d'explosion |
| **Expurgation avant émission.** | voir ci-dessous |
| **Binaire unique, sans dépendance.** | si l'installation prend plus de cinq minutes, le produit est mort |

### 7.2 L'expurgation se fait sur la machine, jamais sur le serveur

Règle absolue : **aucun secret ne quitte la machine.**

```rust
pub trait Collector {
    fn id(&self) -> CollectorId;
    fn collect(&self) -> Result<RawCapture>;
    fn redact(&self, raw: RawCapture) -> RedactedCapture;   // AVANT émission
    fn extract(&self, r: &RedactedCapture) -> Vec<Fact>;
}
```

Exemple concret avec `/etc/shadow` : on veut vérifier la politique de mots de passe, donc on collecte l'algorithme de hachage, l'âge du mot de passe, l'état verrouillé ou non. **On ne stocke jamais l'empreinte elle-même.** Idem pour les clés privées : on enregistre qu'une clé existe et son empreinte publique, pas la clé.

Une liste de refus explicite, testée, avec un test d'intégration continue qui échoue si un motif de secret connu apparaît dans un blob.

### 7.3 Les collecteurs, par ordre de valeur

**Priorité maximale — ce qu'on demande toujours et que personne ne sait produire**

| Collecteur | Faits produits |
|---|---|
| **Comptes privilégiés** | appartenance aux groupes d'administration, dans le temps. « Qui était admin en mars ? » |
| **Preuve de sauvegarde** | dernière sauvegarde réussie par périmètre, rétention effective, **date du dernier test de restauration** |

Ces deux-là sont le coin d'entrée. Un outil qui ne fait que ça, mais parfaitement, se vend.

**Priorité haute**
- Authentification forte : activée, sur quels comptes, depuis quand
- Correctifs : versions installées dans le temps, donc délai réel d'application
- Segmentation : règles de filtrage, VLAN — *et c'est ici que `Calque` se branche*
- Chiffrement au repos, certificats et expirations

**Ensuite**
- Linux : `sshd_config`, `sudoers`, utilisateurs et groupes, unités systemd, paquets, ports en écoute, nftables, paramètres noyau, tâches planifiées
- Windows et Active Directory : GPO, politique de mots de passe, comptes de service, délégations, administrateurs locaux
- Hyperviseurs : inventaire des machines virtuelles, politiques d'instantané
- Équipements réseau : configuration courante

---

## 8. Découpage en crates

```
constat/
├── Cargo.toml
├── deny.toml
├── LICENSE                      # Apache-2.0
│
├── crates/
│   ├── constat-model/           # PUR — faits, entités, snapshots
│   ├── constat-time/            # PUR — intervalles, couverture, interruptions
│   ├── constat-policy/          # PUR — assertions, évaluation, explications
│   ├── constat-diff/            # PUR — différence entre deux dates
│   │
│   ├── constat-store/           # magasin adressé par contenu + journal Merkle
│   │                            # backend derrière un trait → testable en mémoire
│   ├── constat-anchor/          # ancrage externe : RFC 3161, export de racine
│   │
│   ├── constat-collect/         # les collecteurs, isolés
│   │   ├── linux/
│   │   ├── windows/
│   │   ├── network/
│   │   └── backup/
│   │
│   ├── constat-report/          # dossiers de preuve, tables de correspondance
│   ├── constat-verify/          # VÉRIFICATEUR AUTONOME — voir §10.3
│   │
│   ├── constat-agent/           # binaire
│   ├── constat-server/          # binaire collecteur
│   └── constat-cli/             # binaire
│
├── corpus/                      # captures anonymisées + verdicts attendus
├── fuzz/
└── docs/adr/
```

**Règle de dépendance** : les crates purs ne voient que des crates purs. `constat-verify` ne dépend que de `constat-model` et `constat-store` — il doit rester minuscule et auditable.

---

## 9. Dépendances

| Besoin | Crate | Note |
|---|---|---|
| Index et journal | `redb` | fichier unique, transactionnel, pur Rust, aucune dépendance C |
| Empreintes | `blake3` | rapide, arbre de hachage natif |
| Signature | `ed25519-dalek` | standard, petit |
| Compression | `zstd` | les configurations texte compressent d'un facteur dix |
| TLS mutuel | `rustls` + `rcgen` | pas d'OpenSSL |
| Sérialisation | `serde` + `postcard` ou `ciborium` | déterministe, indispensable pour que l'empreinte soit stable |
| CLI | `clap` | — |
| Erreurs lisibles | `miette` | — |
| Tests par propriétés | `proptest` | pour le modèle temporel |
| Tests par instantanés | `insta` | pour les extracteurs de faits |
| Fuzzing | `cargo-fuzz` | les configurations sont des entrées non fiables |
| Horodatage | client RFC 3161 | à écrire, le protocole est simple |
| Rendu de dossier | `typst` en sous-processus, ou HTML puis impression | éviter une bibliothèque PDF lourde |

**Point d'attention majeur : la sérialisation doit être déterministe.** Si le même ensemble de faits produit deux octets différents selon l'ordre d'itération d'une table de hachage, la déduplication s'effondre et les empreintes deviennent instables. D'où `BTreeMap` partout dans le modèle, jamais `HashMap`, et un test par propriétés qui vérifie la stabilité de la sérialisation.

---

## 10. Interface en ligne de commande

```bash
# Collecte
constat agent run --once
constat agent install --server https://constat.interne --token XXX

# Interrogation
constat state --asset srv-fic-01 --at 2026-03-03T14:00
constat diff --asset srv-fic-01 --from 2026-03-01 --to 2026-03-31
constat history --entity "user:jdupont" --attr "user.privileged"
constat timeline --assertion SSH-ROOT --period 2026-Q1

# Évaluation
constat check                                  # évalue assertions.yaml
constat check --period 2026-Q1 --explain

# Preuve
constat pack --period 2026-Q1 --referential recyf --out dossier-Q1.pdf
constat anchor                                 # horodate la racine courante

# Vérification, par un tiers
constat-verify dossier-Q1.pdf --store ./export
```

### 10.1 La commande qui vend : `constat history`

```
$ constat history --entity "user:jdupont" --attr "user.privileged"

2025-11-04 09:12   false → true    (ajouté au groupe Admins du domaine)
                   preuve : blob 7f3a91c2…  srv-ad-01
2026-02-18 16:40   true  → false   (retiré du groupe Admins du domaine)
                   preuve : blob b81e4402…  srv-ad-01

Couverture sur la période : 99,7 % — 2 interruptions déclarées
```

Trois lignes, et elles répondent à une question à laquelle aucune organisation ne sait répondre aujourd'hui sans y passer une journée.

### 10.2 Le dossier de preuve

Contenu minimal :

1. Couverture : organisation, période, périmètre, date de génération
2. Inventaire des machines **attendues** face aux machines **observées** — l'écart est un constat en soi
3. Par exigence du référentiel : l'assertion, le verdict, la couverture, les exceptions avec leur justification et leur expiration
4. Les interruptions de collecte, déclarées explicitement
5. Annexe : les artefacts bruts, avec leurs empreintes
6. Preuve : racine de Merkle, signature, jeton d'horodatage, **et la procédure de vérification**

### 10.3 Le vérificateur autonome — condition de crédibilité

> **La vérification doit être possible sans `Constat`.**

Si contrôler un dossier exige de faire confiance à l'outil qui l'a produit, ce n'est pas une preuve, c'est une déclaration.

D'où `constat-verify` : un binaire minuscule, sans dépendance, qui recalcule la chaîne d'empreintes, vérifie la signature et le jeton d'horodatage, et confirme que les artefacts cités correspondent bien à leurs empreintes. L'algorithme est documenté publiquement, assez simplement pour être réimplémenté en une centaine de lignes par un auditeur méfiant.

C'est la meilleure réponse à « pourquoi devrais-je vous croire ».

---

## 11. Ce que `Constat` ne fait pas

| Non-fonction | Raison |
|---|---|
| Ne modifie rien, jamais | argument de vente, limitation de responsabilité, réduction de surface d'attaque |
| Ne remplace pas un SIEM | complémentaire : le SIEM a les événements, `Constat` a l'état. Le dire évite un combat perdu |
| Ne scanne pas les vulnérabilités | OpenVAS et Nessus existent et sont bons |
| Ne fait pas l'analyse de risque | travail humain, donc prestation, pas logiciel |
| N'exécute aucun code envoyé | contrainte de sécurité fondamentale |
| Ne stocke aucun secret | expurgation sur la machine, avant émission |

---

## 12. Validation

| Niveau | Outil | Ce qu'il attrape |
|---|---|---|
| Propriétés | `proptest` sur `constat-time` | erreurs d'intervalles et de couverture, le point le plus subtil |
| Propriétés | `proptest` sur la sérialisation | instabilité des empreintes |
| Instantanés | `insta` sur les extracteurs | régressions silencieuses |
| Corpus | captures réelles anonymisées + verdicts attendus | erreurs de sémantique |
| Fuzzing | `cargo-fuzz` sur les extracteurs | robustesse face à des entrées hostiles |
| **Anti-fuite** | test dédié cherchant des motifs de secrets dans les blobs | la faute impardonnable |
| **Altération** | modification volontaire du magasin, le vérificateur doit crier | la promesse centrale du produit |

Les deux derniers sont les tests qui décident si le produit tient sa promesse. Ils doivent exister dès la première semaine.

---

## 13. Feuille de route

### S1 — Le socle (3 semaines)
`constat-model`, `constat-store`, journal Merkle, signature, agent Linux avec **les deux collecteurs du coin d'entrée** : comptes privilégiés et preuve de sauvegarde. `constat state --at`.

> **Sortie** : sur trois machines, modifier un droit d'administration, puis restituer l'état exact d'une semaine plus tôt — et démontrer qu'une altération du magasin est détectée.

### S2 — Le temps (2 semaines)
`constat-time`, couverture, interruptions, `constat diff`, `constat history`.

> **Sortie** : arrêter un agent pendant six heures, et vérifier que le rapport déclare honnêtement l'interruption au lieu de la masquer.

### S3 — Les assertions (2 à 3 semaines)
`constat-policy`, YAML, exceptions avec expiration, `constat check --explain`.

> **Sortie** : une assertion qui échoue désigne la machine, l'entité, la valeur observée, les dates et l'artefact de preuve.

### S4 — Le dossier et le vérificateur (3 semaines)
Génération du dossier, première table de correspondance, `constat-verify` autonome.

> **Sortie** : un vrai RSSI accepte de montrer le dossier à un vrai auditeur. **C'est le seul test qui compte.**

### S5 — Windows et Active Directory (3 à 4 semaines)
Agent Windows, GPO, groupes privilégiés, comptes de service.

### S6 — Ancrage qualifié (2 semaines)
Client RFC 3161, ancrage automatique, procédure de vérification documentée.

### S7 — Équipements réseau, et jonction avec `Calque` (3 semaines)
Collecte des configurations réseau, et production de la preuve de segmentation combinée.

### S8 — Multi-organisation
Mode hébergé pour les infogérants — le multiplicateur de distribution.

**Séquence à respecter** : le vérificateur autonome à S4, pas plus tard. C'est lui qui rend le dossier crédible ; sans lui, tout ce qui précède n'est qu'un rapport de plus.

---

## 14. La jonction avec `Calque`

Les deux outils partagent le même modèle d'état structuré. Leur point de rencontre est une exigence que personne ne sait satisfaire aujourd'hui :

> « Prouvez-moi que votre réseau industriel était isolé de votre réseau bureautique pendant tout le trimestre. »

- `Constat` prouve **quel était l'état** de la configuration, à chaque date, sans falsification possible.
- `Calque` calcule **ce que cet état impliquait** en accessibilité réelle.

Techniquement : `Constat` fournit les configurations historiques, `Calque` les évalue, et le verdict d'accessibilité redevient un fait horodaté dans le journal.

Séparément, chacun est utile. Ensemble, c'est une catégorie de produit.

---

## 15. La sérialisation canonique — le détail qui casse tout s'il est raté

Toute la chaîne de preuve repose sur des empreintes. Or une empreinte ne vaut que si les **mêmes données produisent toujours exactement les mêmes octets**.

Trois pièges classiques, chacun suffisant à faire diverger une empreinte sur des données identiques :

| Piège | Conséquence |
|---|---|
| Ordre des clés non déterministe (`HashMap`) | même fait, deux empreintes |
| Représentation des flottants | `1.0` contre `1`, arrondis de plateforme |
| Dates non normalisées | fuseaux, précision variable, secondes intercalaires |

Décisions à prendre au premier commit, coûteuses à rattraper ensuite :

- **Encodage CBOR canonique** (RFC 8949 §4.2) ou un encodage maison strict. Jamais du JSON standard pour ce qui est haché.
- **`BTreeMap` partout** dans les structures hachées, jamais `HashMap`.
- **Aucun flottant** dans un `FactValue`. Les ratios sont stockés en entiers avec dénominateur explicite.
- **Dates en UTC, précision fixe** à la milliseconde, sérialisées en entier depuis l'époque Unix.
- Un test de propriété qui vérifie que `hash(decode(encode(x))) == hash(x)` sur des milliers de valeurs générées.

> **Test d'intégration continue non négociable** : recompiler sur une autre architecture et vérifier que le même corpus produit la même racine de Merkle. Une divergence entre x86 et ARM découverte après un an de collecte invaliderait tout l'historique.

---

## 16. Données personnelles

Les noms de comptes, les appartenances aux groupes et les journaux de connexion sont des données à caractère personnel. Un outil de conformité qui serait lui-même non conforme ne se vendrait pas — et l'objection tombera au premier rendez-vous commercial.

À intégrer dès la conception, pas après :

- **Finalité documentée** et registre de traitement fourni avec le produit, prêt à être versé au dossier du client.
- **Durée de conservation configurable**, avec une valeur par défaut alignée sur les besoins d'audit et non sur « le maximum possible ».
- **Purge journalisée**. Point subtil et important : une suppression liée à la rétention crée un trou dans les données, et un trou non déclaré est indistinguable d'un effacement malveillant. La purge doit donc écrire dans le journal *qu'elle a eu lieu*, sur quelle période et pour quel motif, sans réécrire la chaîne.
- **Pseudonymisation optionnelle** des identifiants de comptes, avec table de correspondance conservée séparément et sous contrôle du client.
- **Droit d'accès et d'effacement** : savoir répondre à une demande portant sur une personne, ce qui suppose un index par identifiant de compte.

---

## 17. La chaîne d'approvisionnement — l'outil est lui-même une cible

Un agent déployé sur toutes les machines d'une organisation est un vecteur de compromission idéal. Et une base contenant l'historique des comptes privilégiés et des règles de filtrage de tout un parc est un objectif de choix.

Trois volets.

**L'agent, en tant que logiciel distribué**
- versions signées, empreintes publiées ;
- **compilations reproductibles** — un tiers doit pouvoir recompiler et obtenir le même binaire ;
- nomenclature logicielle (SBOM) publiée à chaque version ;
- `cargo-deny` et `cargo-audit` en intégration continue, sur les licences *et* sur les vulnérabilités connues ;
- peu de dépendances, et aucune ajoutée sans justification écrite.

**Le serveur, en tant que dépôt de données sensibles**
- chiffrement au repos et en transit ;
- **aucun chemin de retour vers les machines auditées** : compromettre le serveur ne donne pas le contrôle du parc, puisqu'il n'a aucun moyen d'agir sur elles. C'est une propriété d'architecture, pas un réglage ;
- auto-hébergement complet possible, sans aucun appel sortant obligatoire.

**La transparence, en tant qu'argument commercial**
- code ouvert intégral. Un outil de conformité en boîte noire ne se vend pas à un RSSI ;
- le vérificateur autonome doit rester assez petit pour être audité par un tiers en une heure. C'est ce qui rend la preuve crédible, et cela impose de résister à la tentation d'y ajouter des fonctionnalités.

---

## 18. Les principes à ne pas trahir

1. **Lecture seule, toujours.**
2. **Le cœur est pur et déterministe.** Vérifié par l'intégration continue.
3. **Aucun secret ne quitte la machine.** Expurgation à la source, test anti-fuite permanent.
4. **Aucune exécution de code envoyé, jamais.**
5. **Déclarer les trous.** Un outil qui masque ses angles morts détruit sa propre valeur probante.
6. **La vérification doit être possible sans l'outil.**
7. **Les octets sont canoniques.** Une empreinte instable invalide toute la chaîne de preuve.
8. **Le produit est la preuve, pas la collecte.** La collecte est un moyen ; ce qui se vend, c'est le document qu'on pose sur la table.

---

## 19. Premier commit

Le workspace, `deny.toml`, `LICENSE`, et deux ADR datées :

- **ADR 001** — modèle entité-attribut-valeur, stockage double brut plus faits ;
- **ADR 002** — encodage canonique retenu, `BTreeMap` imposé, aucun flottant haché, dates en entier UTC.

Puis `constat-model` avec les types de la section 3, le magasin adressé par contenu, et **le test d'altération** — le jour un, parce que c'est la promesse centrale du produit.

Enfin, avant tout collecteur : le test de stabilité d'empreinte multi-architecture. Il coûte une heure au démarrage et sauve l'historique entier.
