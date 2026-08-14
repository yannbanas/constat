# Cycle de vie des clés de signature

Ce document décrit la gestion complète des clés Ed25519 qui signent les
journaux Constat : génération, garde, rotation planifiée, compromission, et
le lien avec l'ancrage externe. Il complète le modèle de menace du §6 de
`CONSTAT-ARCHITECTURE.md` et le format normatif de
`crates/constat-verify/FORMAT.md` (§ 4 ter, rotation de clé).

Deux clés cohabitent sur un agent, à ne pas confondre :

| Clé | Rôle | Fichiers | Gérée par |
|---|---|---|---|
| **Clé de signature du journal** (Ed25519) | signe chaque entrée du journal — c'est elle qui fait la preuve | `agent.key` / `agent.pub` | ce document |
| Clé du certificat client mTLS | authentifie le transport vers le serveur | PEM `--cert`/`--key` | votre PKI interne |

Ce document ne traite que de la première. La seconde suit les procédures de
votre PKI (révocation par CRL, réémission) — la compromettre ne permet pas
de forger des entrées de journal, seulement de tenter des poussées, que la
signature des entrées refuse.

## 1. Les deux identités d'un journal : genèse et clé courante

- La **clé de genèse** est celle qui a signé la première entrée du journal.
  C'est l'**identité** du journal, stable pour toute sa vie :
  - c'est elle que `pubkey.bin` contient dans un export, avant comme après
    toute rotation ;
  - c'est elle qui nomme le journal sur le serveur central (`JournalId`) ;
  - c'est elle que la liste d'agents autorisés (`--allowed-agents`)
    contient.
- La **clé courante** est celle qui signe les nouvelles entrées :
  la genèse au départ, puis la clé déléguée par chaque **rotation
  journalisée** (voir §3). Le vérificateur la suit le long de la chaîne —
  personne n'a besoin de la distribuer.

Conséquence pratique : **la clé publique à remettre à un vérificateur est
toujours la clé de genèse**, et elle ne change jamais. La rotation est une
opération interne au journal, pas un changement d'identité.

## 2. Génération et garde

### Génération

```
constat-agent keygen --keys /var/lib/constat/cles
```

Une paire par agent, générée **sur la machine** (CSPRNG du système), jamais
copiée depuis un modèle ni distribuée par un outil de gestion de parc. Sur
Unix, le répertoire est en `0700` et `agent.key` en `0600`.

### Garde

- La clé privée **ne quitte jamais la machine** — même règle que pour les
  secrets collectés (§7.2 : aucun secret ne quitte la machine ; la clé de
  signature est un secret).
- Ne pas la mettre dans une sauvegarde, un dépôt de configuration, un
  gestionnaire de secrets centralisé ou un partage réseau.

### Pourquoi on ne sauvegarde PAS la clé privée d'agent

C'est un choix délibéré, pas un oubli :

- **La clé est remplaçable par rotation.** Sa perte n'a rien
  d'irrémédiable (voir ci-dessous) ; sa **copie**, si.
- **Chaque copie est un risque net.** Une copie de sauvegarde est un
  deuxième endroit d'où la clé peut fuir — vers quelqu'un qui pourra alors
  signer de fausses entrées « authentiques ». La valeur probante du journal
  repose précisément sur le fait que *seule cette machine* pouvait signer.
- **La perte de clé sans rotation préalable n'est pas une perte de
  preuve.** Le journal existant reste intégralement vérifiable avec la clé
  *publique* de genèse (elle, distribuée et archivable sans risque).
  Procédure :
  1. exporter et archiver la chaîne close (`constat export`), ancrer sa
     racine (§6.3) : c'est un dossier complet, vérifiable pour toujours ;
  2. générer une nouvelle paire (`constat-agent keygen --force` sur un
     magasin neuf, ou nouveau chemin de magasin) : un **nouveau journal**
     commence, nouvelle identité de genèse ;
  3. côté serveur, ajouter la nouvelle identité
     (`constat-server agents --file <fichier> add <hex> [nom]`) — et
     retirer l'ancienne si une allowlist est en place ;
  4. noter la transition dans votre documentation d'exploitation : l'écart
     de continuité entre les deux journaux est lui-même un fait déclaré,
     pas un trou masqué.

  L'ancienne chaîne est **close** : plus personne ne peut y écrire (la clé
  n'existe plus), mais tout le monde peut encore la vérifier. C'est
  exactement l'état recherché — comparez avec le coût d'une copie de clé
  qui fuit.

La clé **publique** (`agent.pub`, `pubkey.bin` des exports), elle, se
distribue et s'archive librement : au RSSI, dans le dossier d'audit, avec
chaque export.

## 3. Rotation planifiée

### Principe

Une rotation est un **constat réservé**, sur le modèle de la purge
journalisée : un blob `constat.rotation` (ancienne clé, nouvelle clé, motif)
référencé par une nouvelle entrée **signée par l'ANCIENNE clé** — c'est
elle qui délègue. Les entrées suivantes sont signées par la nouvelle clé.
Rien n'est réécrit ; le vérificateur suit la clé courante le long de la
chaîne et annonce « N rotation(s) de clé, clé finale … ».

Une entrée de rotation n'est **jamais purgeable** (même règle que les
enregistrements de purge) : la purger rendrait toute la suite de la chaîne
invérifiable.

### Commande

```
constat-agent rotate-key [--keys <dossier>] [--reason <motif>] [--store <chemin>]
```

Ce qu'elle fait, dans l'ordre :

1. refuse si le magasin est inaccessible — **une rotation non journalisée
   n'existe pas** ;
2. génère la nouvelle paire et l'écrit sur disque (fichiers temporaires,
   permissions restrictives) ;
3. écrit l'entrée de rotation, signée par l'ancienne clé ;
4. archive l'ancienne paire en `agent.key.<date>.old` et
   `agent.pub.<date>.old` (les permissions restrictives sont conservées)
   et met la nouvelle paire en place.

Aucune action côté serveur n'est requise : l'allowlist liste des identités
de genèse, la rotation ne la concerne pas. La poussée suivante transporte
l'entrée de rotation et le serveur bascule sa validation de lui-même.

### L'ancienne clé archivée

`agent.key.<date>.old` n'a plus aucun pouvoir sur le journal (le magasin et
le serveur refusent désormais ses signatures pour les nouvelles entrées).
La conserver quelque temps peut aider une investigation (prouver qu'on la
détient encore) ; la supprimer ensuite est sain. Elle reste un secret tant
qu'elle existe : mêmes règles de garde.

### Cadence recommandée

- **Annuelle** par défaut, alignée sur votre cycle d'audit : une rotation
  par campagne d'audit borne la fenêtre d'exposition d'une clé à un
  exercice.
- **Immédiate** à chaque départ d'un administrateur ayant eu un accès root
  à la machine, et à chaque soupçon de compromission (voir §4).
- Éviter les cadences très courtes (mensuelle et moins) : chaque rotation
  est une entrée de plus à vie dans le journal, et la valeur de sécurité
  marginale est faible pour une clé qui ne quitte jamais la machine. La
  vraie protection contre la falsification n'est pas la rotation, c'est
  l'**ancrage externe** (§5).

## 4. Compromission

Hypothèse : la clé privée d'un agent a (peut-être) fui — la machine a été
compromise, ou un accès root non prévu a eu lieu.

### Ce que la compromission permet — et ne permet pas — de falsifier

À relire avec §6.2 de l'architecture (« ce que le journal ne protège pas »).

Avec la clé privée, un attaquant **peut** :

- signer de nouvelles entrées « authentiques » à partir de maintenant —
  y compris des collectes mensongères (l'agent est une source, pas un
  oracle : §6.4) ;
- tronquer la fin du journal **local** et re-signer une fin alternative,
  ou repartir de zéro (§6.2) ;
- opérer une rotation « légitime » vers une clé à lui : la délégation est
  cryptographiquement valide — c'est pour cela que la **révocation côté
  serveur retire l'identité entière**, rotations comprises.

Il **ne peut pas** :

- réécrire le passé déjà **ancré** : toute entrée antérieure à une racine
  ancrée hors du système (courriel, dépôt tiers, jeton RFC 3161) est figée
  — modifier quoi que ce soit avant elle change la racine et l'écart est
  détectable ;
- réécrire le passé déjà **poussé** au serveur : le serveur refuse toute
  chaîne qui ne se raccorde pas à ce qu'il détient (troncature ou
  réécriture = poussée refusée, à consigner) ;
- écrire dans le journal d'un **autre** agent (propriété structurelle du
  magasin), ni pousser sous une autre identité listée.

La fenêtre de falsification est donc : **depuis la dernière racine ancrée
(ou la dernière poussée serveur), jusqu'à la révocation**. D'où la
procédure.

### Procédure

1. **Révoquer côté serveur, immédiatement** :

   ```
   constat-server agents --file <fichier-allowlist> revoke <clé de genèse hex>
   ```

   (sur le fichier passé via `--allowed-agents`, puis relancer le serveur).
   La révocation retire l'**identité entière** — plus aucune poussée sur ce
   journal, quelle que soit la clé courante, rotation d'attaquant comprise.
   Elle est **tracée** : une note datée reste en commentaire dans le
   fichier. Si le serveur tournait en TOFU (sans allowlist), c'est le
   moment de passer en allowlist : le TOFU n'a pas de révocation.

2. **Ancrer la racine** du journal tel qu'il est **maintenant**, côté
   serveur (`constat-server journals` donne la racine ; `constat anchor`
   pour un jeton RFC 3161) : cela fige l'état au moment de la découverte et
   borne ce que l'attaquant pourrait encore raconter.

3. **Rotation immédiate** sur la machine, une fois assainie :
   `constat-agent rotate-key --reason "compromission <date>"`. Si la
   machine ne peut pas être considérée comme assainie, traiter comme une
   perte de clé : nouveau journal (§2), nouvelle identité, l'ancienne
   restant révoquée.

4. **Réadmettre** explicitement : `constat-server agents add` de
   l'identité concernée (la même après simple rotation ; la nouvelle après
   nouveau journal). La note de révocation reste dans le fichier —
   l'histoire est conservée.

5. **Investiguer depuis la dernière racine ancrée** : tout ce qui précède
   la dernière racine ancrée (ou poussée) est digne de confiance ; tout ce
   qui la suit, jusqu'à la révocation, doit être recoupé — comparez le
   journal local avec la copie du serveur (`constat diff`, exports des deux
   côtés), et traitez les écarts comme des constats. La qualité de cette
   investigation dépend directement de la **fréquence d'ancrage** : c'est
   l'argument décisif pour ancrer quotidiennement (§5).

## 5. Lien avec l'ancrage externe

La rotation gère le cycle de vie de la clé ; elle ne remplace **aucun** des
niveaux d'ancrage du §6.3 :

| Niveau | Mécanisme | Ce que la rotation y change |
|---|---|---|
| 1 | chaînage Merkle | rien — la rotation est une entrée comme une autre |
| 2 | racine envoyée hors du système | rien — continuez d'envoyer la racine (quotidien recommandé) |
| 3 | horodatage qualifié RFC 3161 | rien — `constat anchor --send` fonctionne à l'identique |

Sans ancrage, le détenteur de la clé courante peut toujours tronquer et
re-signer (§6.2) — rotation ou pas. L'ancrage régulier est ce qui borne la
fenêtre de falsification d'une compromission (§4) ; la rotation est ce qui
borne la durée de vie du secret. Les deux se complètent, aucun ne remplace
l'autre.

Recommandation d'exploitation : ancrer la racine **après** chaque rotation
(l'entrée de rotation est alors elle-même sous ancrage : la délégation
devient incontestable), en plus de la cadence régulière.
