# Modèle de menace

Ce document énonce, sans complaisance, ce que Constat protège, ce qu'il ne
protège pas, et pourquoi. Il complète le §6 de `CONSTAT-ARCHITECTURE.md`. Un
outil de preuve qui surestime ses garanties est pire qu'inutile : les limites
sont donc écrites noir sur blanc, ici et dans chaque dossier généré.

## 1. Biens à protéger

| Bien | Menace principale | Contre-mesure |
|---|---|---|
| L'**intégrité de l'historique** (personne n'a modifié le passé) | réécriture/insertion d'une entrée | journal Merkle : chaque entrée porte l'empreinte de la précédente, signée Ed25519 |
| La **non-répudiation** (le passé ne peut être nié) | troncature de la fin par le détenteur de la clé | **ancrage externe** (§6.3 : export de racine, RFC 3161) — sans lui, seule la cohérence interne est prouvée |
| La **confidentialité des secrets du parc** | un secret qui fuit dans un blob stocké/poussé | expurgation **à la source**, avant émission ; test anti-fuite permanent |
| L'**absence de chemin de retour** vers le parc | compromettre le serveur pour agir sur les machines | propriété d'architecture : le serveur n'initie aucune connexion, ne renvoie rien d'exécutable |
| La **disponibilité** du serveur de collecte | déni de service | bornage des connexions, tailles bornées avant allocation, délais d'attente |

## 2. Acteurs et hypothèses

- **L'administrateur audité** fait tourner l'outil sur son propre parc. C'est
  l'hypothèse inconfortable et honnête : il détient la clé de signature et le
  magasin. Il peut donc **tronquer** ou **repartir de zéro** — Constat ne le
  masque pas, il rend cette action visible par l'ancrage externe (une racine
  ancrée hier ne peut être reniée aujourd'hui).
- **Un agent** est une **source**, pas un oracle. Un agent compromis peut mentir
  sur l'état de sa machine ; Constat prouve ce qui a été *enregistré*, pas ce qui
  était *vrai*. D'où l'importance de l'inventaire attendu/observé : une machine
  sans agent est elle-même un constat.
- **Un tiers réseau** ne peut ni lire ni écrire : mTLS obligatoire, certificat
  client exigé, isolation des journaux par clé.
- **Un auditeur** ne fait confiance à rien : il vérifie le dossier avec
  `constat-verify`, binaire séparé, sans dépendre de Constat (§10.3).

## 3. Ce que Constat ne prétend pas faire

- Détecter un agent qui mentirait sur sa propre machine.
- Prouver quoi que ce soit sur une machine où aucun agent n'a jamais collecté.
- Empêcher la troncature **sans** ancrage externe (cohérence interne ≠
  non-répudiation).
- Remplacer une supervision temps réel : la granularité est celle de la collecte.

## 4. Résultats des revues adversariales internes (2026-08-14)

Deux revues adversariales indépendantes ont été menées avant tout audit externe :
l'une visant à **falsifier une preuve**, l'autre à **faire fuiter un secret** et à
**compromettre l'agent/serveur**. Détail complet dans
[`revue-adversariale-interne.md`](revue-adversariale-interne.md).

**Synthèse** :
- **Falsification de preuve** : aucun vecteur exploitable trouvé. Le cœur
  cryptographique tient (chaînage, signatures `verify_strict` partout, adressage
  par contenu, purge et rotation signées). Un écart de conformité du vérificateur
  (il re-encodait au lieu de hacher les octets bruts) a été **corrigé** —
  désormais aligné au bit près sur `FORMAT.md`.
- **Fuite de secrets** : trois vecteurs réels trouvés (identifiants d'URL,
  XML compact, secrets positionnels) — **tous corrigés**, chacun avec un test de
  non-régression qui reproduit l'attaque. C'est la démonstration de la valeur
  d'un regard adversarial : ces formes n'étaient pas couvertes par les ~580 tests
  préexistants.
- **Compromission agent/serveur** : axe jugé solide (abandon de privilèges
  correct, mTLS obligatoire, `unsafe` confiné en lecture seule, aucune panique
  atteignable). Un DoS de disponibilité a été **corrigé** (bornage des
  connexions).

Aucune trouvaille CRITIQUE ou HAUTE ne reste ouverte à la date de ce document.

## 5. Ce qu'un audit externe doit encore couvrir

Les revues internes ne remplacent pas un audit indépendant. Un auditeur tiers
devrait en priorité :

1. **Rejouer l'analyse de l'expurgation** sur un corpus de configurations réelles
   (anonymisées) de l'organisation cliente — c'est là que les angles morts
   vivent, par construction (on ne teste que les formats qu'on imagine).
2. **Auditer les blocs `unsafe`** (FFI Win32 dans `constat-collect/src/windows/`,
   abandon de privilèges dans `constat-agent/src/privileges.rs`) — confinés et
   commentés, mais l'`unsafe` mérite un œil externe.
3. **Vérifier la chaîne d'approvisionnement** : reproduire une compilation
   (objectif : build reproductible, non encore atteint), contrôler la provenance
   SLSA et la SBOM publiées.
4. **Pentester le serveur** en conditions réelles (mTLS, charge, connexions
   hostiles) au-delà du DoS déjà corrigé.
5. **Réimplémenter `constat-verify`** à partir de `FORMAT.md` seul, sans lire le
   code : c'est le test ultime de la promesse « vérifiable sans l'outil ». La
   correction de conformité récente rend ce test à présent significatif.
