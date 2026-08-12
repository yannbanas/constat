# Constat

[![Licence : Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/yannbanas/constat/actions/workflows/ci.yml/badge.svg)](https://github.com/yannbanas/constat/actions/workflows/ci.yml)

**Constat enregistre l'état de configuration d'une infrastructure dans la durée, de façon non falsifiable, et produit la preuve qu'un auditeur accepte.**

Un auditeur demande : « prouvez que le 3 mars, la connexion root en SSH était désactivée sur tous vos serveurs. » Aucun outil courant ne sait répondre à cette question. Constat existe pour ça.

---

## Pourquoi les outils existants ne suffisent pas

| Outil | Ce qu'il sait | Ce qui manque |
|---|---|---|
| SIEM | les **événements** : « une commande a été lancée à 14h32 » | l'**état** à une date donnée |
| Ansible, Puppet | l'**intention** : ce qui *devrait* être | ce qui **était**, et l'historique |
| osquery, GLPI, Wazuh | l'état **actuel** | l'historique, et la non-falsifiabilité |
| Plateformes GRC | ce que l'humain a **déclaré** dans un formulaire | le lien avec la réalité machine |

Analogie : un SIEM, c'est la caméra du couloir — elle filme les passages. L'auditeur, lui, veut **l'inventaire de la pièce à une date donnée**, avec la garantie que personne n'a modifié l'inventaire après coup.

Constat ne remplace aucun de ces outils : il occupe la place qu'aucun d'eux n'occupe — **l'état, dans le temps, avec preuve**.

---

## Les trois contraintes qui structurent tout

> **Lecture seule, toujours. Cœur pur. Aucune exécution de code arbitraire, nulle part.**

Ces contraintes ne sont pas des limitations : ce sont les arguments de vente.

- **Lecture seule** — Constat ne peut rien casser. C'est ce qui rend le produit acceptable sur un parc de production et ce qui borne la responsabilité de l'éditeur.
- **Cœur pur** — `constat-model`, `constat-time`, `constat-policy` et `constat-diff` ne font aucune entrée-sortie. Donc testables exhaustivement, et surtout : deux évaluations sur les mêmes données donnent le même verdict. Indispensable pour un outil dont la sortie sert de preuve.
- **Aucune exécution arbitraire** — l'agent n'a pas, et n'aura jamais, la capacité d'exécuter un script envoyé par le serveur. C'est ce qui empêche Constat de devenir le vecteur de compromission de tout le parc.

Un test d'intégration continue vérifie l'arbre de dépendances et échoue si une impureté entre dans le cœur.

---

## La commande qui montre tout : `constat history`

```
$ constat history --entity "user:jdupont" --attr "user.privileged"

2025-11-04 09:12   false → true    (ajouté au groupe Admins du domaine)
                   preuve : blob 7f3a91c2…  srv-ad-01
2026-02-18 16:40   true  → false   (retiré du groupe Admins du domaine)
                   preuve : blob b81e4402…  srv-ad-01

Couverture sur la période : 99,7 % — 2 interruptions déclarées
```

Trois lignes, et elles répondent à une question à laquelle aucune organisation ne sait répondre aujourd'hui sans y passer une journée. Notez les deux détails qui comptent : chaque changement pointe vers **son artefact de preuve**, et la couverture déclare **ses interruptions** au lieu de les masquer.

---

## Démarrage rapide

### Compiler depuis les sources

```bash
git clone https://github.com/yannbanas/constat
cd constat
cargo build --release --workspace
```

Les binaires sont produits dans `target/release/`.

### Première collecte

```bash
# une collecte unique, en local, sans serveur
constat-agent run --once
```

L'agent lit les configurations de la machine (lecture seule), expurge les secrets **avant** toute émission, extrait les faits et les enregistre dans le magasin adressé par contenu.

### Première évaluation

```bash
# évalue les assertions de assertions.yaml contre l'historique
constat check
constat check --period 2026-Q1 --explain
```

Chaque verdict est accompagné de sa **couverture** : la part de la période réellement observée, l'écart maximal entre deux collectes et les interruptions, déclarées explicitement. Un verdict sans couverture n'est pas une preuve.

---

## Ce que Constat ne prétend pas faire

Un outil de preuve qui surestime ses garanties est pire qu'inutile. Ces limites sont écrites ici, et dans chaque dossier généré.

- **Cohérence interne ≠ non-répudiation.** Le journal chaîné (Merkle) garantit qu'on ne peut pas modifier ou insérer une entrée au milieu de l'historique sans que ce soit détectable. Il ne protège **pas** contre la troncature : celui qui contrôle le magasin et la clé de signature peut supprimer la fin du journal, ou tout effacer et repartir à zéro — et c'est précisément l'administrateur audité qui fait tourner l'outil. **Sans ancrage externe (export de racine hors du système, horodatage qualifié RFC 3161, co-signature par un tiers), le journal prouve la cohérence interne, pas la non-répudiation.**
- **Un agent est une source, pas un oracle.** Constat ne détecte pas un agent compromis qui mentirait sur l'état de sa machine.
- **Pas d'agent, pas de preuve.** Constat ne prouve rien sur une machine où l'agent n'a jamais été installé. D'où l'inventaire des machines *attendues* face aux machines *observées* — l'écart est lui-même un constat.
- **Pas une supervision temps réel.** La granularité est celle de la collecte. Les intervalles entre deux observations sont modélisés comme tels (`Inferred`, avec écart maximal déclaré), jamais présentés comme des observations.

Par ailleurs, Constat ne modifie rien, ne remplace pas un SIEM, ne scanne pas les vulnérabilités, ne fait pas d'analyse de risque, n'exécute aucun code envoyé et ne stocke aucun secret.

---

## Structure du workspace

Douze crates, avec une règle de dépendance stricte : **les crates purs ne voient que des crates purs.** Un test d'intégration continue vérifie l'arbre de dépendances.

```
crates/
├── constat-model/     PUR — faits, entités, snapshots, encodage canonique
├── constat-time/      PUR — intervalles, couverture, interruptions
├── constat-policy/    PUR — assertions, évaluation, explications
├── constat-diff/      PUR — différence d'état entre deux dates
│
├── constat-store/     magasin adressé par contenu + journal Merkle
├── constat-anchor/    ancrage externe : RFC 3161, export de racine
├── constat-collect/   les collecteurs (Linux, Windows, réseau, sauvegarde), isolés
├── constat-report/    dossiers de preuve, tables de correspondance
├── constat-verify/    vérificateur AUTONOME — minuscule, auditable, ne dépend
│                      que de constat-model et constat-store
│
├── constat-agent/     binaire : collecte en lecture seule, expurgation à la source
├── constat-server/    binaire : réception mTLS, dépôt — aucun chemin de retour
│                      vers les machines auditées
└── constat-cli/       binaire : state, diff, history, check, pack, anchor
```

Le vérificateur mérite une mention : **la vérification doit être possible sans Constat.** Si contrôler un dossier exige de faire confiance à l'outil qui l'a produit, ce n'est pas une preuve, c'est une déclaration. `constat-verify` recalcule la chaîne d'empreintes, vérifie la signature et le jeton d'horodatage — et son algorithme est documenté assez simplement pour être réimplémenté en une centaine de lignes par un auditeur méfiant.

---

## Les huit principes à ne pas trahir

1. **Lecture seule, toujours.**
2. **Le cœur est pur et déterministe.** Vérifié par l'intégration continue.
3. **Aucun secret ne quitte la machine.** Expurgation à la source, test anti-fuite permanent.
4. **Aucune exécution de code envoyé, jamais.**
5. **Déclarer les trous.** Un outil qui masque ses angles morts détruit sa propre valeur probante.
6. **La vérification doit être possible sans l'outil.**
7. **Les octets sont canoniques.** Une empreinte instable invalide toute la chaîne de preuve.
8. **Le produit est la preuve, pas la collecte.** La collecte est un moyen ; ce qui se vend, c'est le document qu'on pose sur la table.

---

## Documentation

- [CONSTAT-ARCHITECTURE.md](CONSTAT-ARCHITECTURE.md) — la spécification complète
- [docs/adr/](docs/adr/) — les décisions d'architecture (ADR)
- [corpus/](corpus/) — captures réelles anonymisées et verdicts attendus
- [CONTRIBUTING.md](CONTRIBUTING.md) — conventions et processus de contribution
- [SECURITY.md](SECURITY.md) — divulgation responsable des vulnérabilités

## Licence

Apache License 2.0 — voir [LICENSE](LICENSE) et [NOTICE](NOTICE).

Copyright 2026 Yann Banas.
