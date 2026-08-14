# Registre de traitement — modèle pour un déploiement de Constat

Modèle de fiche de registre (article 30 du RGPD) prêt à être adapté et versé
au dossier du responsable de traitement. Les champs entre crochets sont à
compléter par le client ; les valeurs proposées correspondent au
fonctionnement réel de Constat, sans embellissement.

> Constat collecte des états de configuration de machines. Certains de ces
> états contiennent des données à caractère personnel : noms de comptes,
> appartenances aux groupes, journaux liés aux comptes. Un outil de
> conformité doit être lui-même conforme — cette fiche existe pour cela
> (architecture, §16).

## 1. Identité

| Champ | Valeur |
|---|---|
| Responsable de traitement | [organisation cliente] |
| Représentant / contact | [nom, fonction, adresse, courriel] |
| Délégué à la protection des données | [le cas échéant] |
| Traitement | Journalisation probante de l'état de configuration du parc informatique (produit : Constat, auto-hébergé) |

## 2. Finalités

- Constituer la **preuve dans la durée** de l'état de configuration des
  machines du parc (comptes, services, règles réseau), à des fins d'audit de
  sécurité et de conformité (ex. exigences ISO 27001, NIS2, PCI DSS —
  selon le référentiel retenu par le client).
- Détecter et dater les **écarts** de configuration (qui était privilégié,
  quand, sur quelle machine).
- Produire des **dossiers de preuve** vérifiables par un tiers.

Le traitement ne comporte **aucune prise de décision automatisée** produisant
des effets juridiques sur les personnes, aucun profilage, aucune finalité
commerciale.

## 3. Catégories de données et de personnes concernées

| Catégorie de données | Exemples | Personnes concernées |
|---|---|---|
| Identifiants de comptes locaux et de domaine | nom de compte (`jdupont`), UID/SID, shell, verrouillage | employés, prestataires, comptes de service |
| Appartenances aux groupes | membre de `sudo`, d'`Administrateurs`, de groupes AD | idem |
| Attributs de sécurité des comptes | présence/absence de mot de passe, privilèges, dates de politique | idem |
| Configurations système et réseau | `sshd_config`, services, règles de filtrage | (en principe non personnelles ; peuvent citer des comptes) |

Ce que Constat **ne collecte pas** : mots de passe et secrets (expurgés à la
source, avant stockage — seule une empreinte peut subsister), contenus de
fichiers utilisateurs, frappes, historique de navigation, données de santé ou
toute catégorie particulière au sens de l'article 9.

## 4. Durée de conservation

- Durée par défaut proposée : **3 ans** (`1095j`), alignée sur un cycle
  d'audit triennal — et non « le maximum possible ». À ajuster : [durée
  retenue et justification].
- La purge est exécutée par `constat purge --older-than <durée>` (ou une
  planification l'appelant) et elle est **journalisée** : la suppression est
  déclarée, datée et motivée dans le journal signé, sans réécrire
  l'historique de preuve. Voir `docs/rgpd/purge.md`.
- Limite assumée : les **entrées de journal** (empreintes, dates, signatures
  — sans contenu personnel) et les **déclarations de purge** sont conservées
  au-delà de la rétention, car elles constituent la chaîne de preuve
  elle-même. Les contenus (artefacts et faits, dont les données
  personnelles) sont, eux, réellement supprimés.

## 5. Destinataires

- [équipe sécurité / administration du SI de l'organisation] — accès au
  magasin et aux dossiers de preuve ;
- [auditeurs internes ou externes] — dossiers de preuve et exports
  vérifiables, sur la période auditée ;
- prestataire d'horodatage qualifié (le cas échéant) : ne reçoit **que
  l'empreinte de la racine** du journal (32 octets), aucune donnée
  personnelle ;
- **aucun autre destinataire** : Constat est auto-hébergé et ne comporte
  aucun appel sortant obligatoire.

## 6. Transferts hors Union européenne

Aucun du fait du produit. [À compléter si l'hébergement ou l'auditeur du
client en implique un.]

## 7. Mesures de sécurité

- collecte en **lecture seule** sur les machines ; aucune exécution de code
  reçu ;
- **expurgation des secrets à la source**, avant toute écriture, avec test
  anti-fuite en intégration continue ;
- journal chaîné (Merkle) et **signé** (Ed25519) : toute altération a
  posteriori est détectable ; ancrage externe possible (RFC 3161) ;
- chiffrement en transit (mTLS entre agents et serveur) ; [chiffrement au
  repos : à décrire selon l'hébergement] ;
- purge de rétention **journalisée** (voir § 4) ;
- code source ouvert, binaires signés, nomenclature logicielle (SBOM)
  publiée.

## 8. Exercice des droits

- **Droit d'accès** : les faits relatifs à un compte s'interrogent par
  identifiant (`constat history --entity "user:<compte>"`) ; le responsable
  de traitement peut ainsi restituer ce qui est enregistré sur une personne.
- **Droit d'effacement** : traité par la politique de rétention et la purge
  journalisée. Une demande d'effacement anticipé doit être arbitrée par le
  responsable de traitement face à l'obligation de conservation de la preuve
  d'audit [décrire la procédure d'arbitrage retenue].
- Limite honnête : un dossier de preuve **déjà exporté et remis** à un
  auditeur est hors de portée de la purge — le registre du destinataire
  s'applique.

[Date, version de la fiche, signataire.]
