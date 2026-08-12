# ADR 001 — Modèle entité-attribut-valeur et stockage double (brut + faits)

- **Statut** : acceptée
- **Date** : 2026-08-12
- **Décideurs** : Yann Banas
- **Référence** : CONSTAT-ARCHITECTURE.md §3

## Contexte

Constat collecte l'état de configuration de machines hétérogènes (Linux,
Windows, équipements réseau, solutions de sauvegarde) et doit pouvoir :

1. produire une **preuve** qu'un auditeur accepte — ce qui suppose de pouvoir
   présenter l'artefact original (le vrai `sshd_config`, tel que collecté) ;
2. **interroger** cet état dans le temps (`constat history`, `constat state --at`)
   et **évaluer des règles** dessus (`constat check`) — ce qui suppose des
   données structurées et typées ;
3. calculer des **différences** d'état entre deux dates, sur n'importe quel
   type de donnée collectée.

Deux questions de conception se posent : quelle forme donner aux données
structurées, et faut-il conserver l'artefact brut en plus.

L'alternative au modèle retenu serait des structures Rust typées par
collecteur (`SshdConfig { permit_root_login: bool, ... }`), naturelles à écrire
mais qui lient le moteur d'évaluation, le moteur de différence et le schéma de
stockage à chaque collecteur.

## Décision

### 1. Les faits sont des triplets entité-attribut-valeur

```rust
pub struct Fact {
    pub entity:    EntityId,      // "user:root", "service:sshd"
    pub attribute: Attribute,     // "sshd.PermitRootLogin", "user.privileged"
    pub value:     Value,
}
```

Trois raisons (§3.2), chacune suffisante :

1. **Une règle peut porter sur plusieurs collecteurs et plusieurs systèmes
   d'exploitation sans code spécifique.** « Tous les comptes privilégiés ont
   l'authentification forte » s'évalue de la même façon que les faits viennent
   d'Active Directory, de `/etc/group` ou d'un annuaire LDAP.
2. **Le calcul de différence devient générique** : une différence, c'est une
   soustraction d'ensembles de triplets. `constat-diff` n'a pas besoin de
   connaître les collecteurs.
3. **Ajouter un collecteur n'oblige pas à modifier le moteur.** Le moteur
   d'évaluation, le magasin et le vérificateur ignorent tout des formats
   sources.

Le type `Value` comporte un variant **`Absent`** : en conformité, « l'attribut
n'existe pas » et « l'attribut vaut faux » sont deux choses différentes. Un
`sshd_config` sans directive `PermitRootLogin` applique le défaut du système,
qui varie selon les versions. Confondre les deux produit des verdicts faux.

### 2. On stocke deux choses, pas une : l'artefact brut ET les faits

| | Pour quoi | Forme |
|---|---|---|
| **L'artefact brut** | la preuve — un auditeur peut vouloir lire le vrai `sshd_config` | texte, tel que collecté, après expurgation |
| **Les faits extraits** | l'interrogation et l'évaluation des règles | triplets typés |

Ne stocker que les faits, c'est perdre la valeur probante : un triplet
`sshd.PermitRootLogin = no` est une interprétation de l'outil, pas une pièce.
Ne stocker que le brut, c'est ne rien pouvoir interroger. **Les deux,
dédupliqués** par adressage par contenu (la granularité du blob — par
collecteur et par machine — est traitée en §3.3 de la spécification).

Chaque violation rapportée par le moteur de règles pointe vers l'empreinte du
blob brut qui la prouve (`evidence: BlobHash`).

## Conséquences

### Positives

- Moteurs d'évaluation, de différence et d'historique **génériques** : aucun
  code par collecteur hors de `constat-collect`.
- La chaîne verdict → fait → artefact brut est complète : chaque affirmation
  du dossier de preuve est adossée à une pièce lisible par l'auditeur.
- La déduplication par contenu rend la rétention de trois ans viable : sur un
  parc stable, une collecte quotidienne n'écrit presque que des références.
- L'ajout d'un collecteur est une opération locale, sans migration du magasin.

### Négatives (assumées)

- **Le typage se déplace vers les conventions de nommage** des attributs
  (`sshd.PermitRootLogin`). Le compilateur ne détecte pas une faute de frappe
  dans un nom d'attribut : les tests par instantanés (`insta`) sur les
  extracteurs et le corpus de captures avec verdicts attendus servent de filet.
- Le stockage double coûte de l'espace par rapport aux seuls faits — coût
  contenu par la déduplication et la compression zstd, et de toute façon non
  négociable : sans le brut, pas de preuve.
- Les requêtes « toutes les propriétés de cette entité » exigent un
  regroupement de triplets, moins direct qu'un accès à une structure. Coût
  accepté : c'est le magasin qui indexe, pas le cœur.
