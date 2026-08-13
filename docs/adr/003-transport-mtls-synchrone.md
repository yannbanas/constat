# ADR 003 — Transport mTLS synchrone, sans runtime async

- **Statut** : acceptée
- **Date** : 2026-08-12
- **Décideurs** : Yann Banas
- **Référence** : CONSTAT-ARCHITECTURE.md §7.1, §17 ; `crates/constat-agent/src/push.rs`, `crates/constat-server/src/serve.rs`

## Contexte

L'agent pousse ses objets vers le serveur (`POST /v1/pousse`) et le serveur
les reçoit. C'est le seul échange réseau du produit, et il est minuscule :
une requête par poussée, un corps CBOR, un accusé de réception dont seul le
**statut HTTP** est lu. L'écosystème Rust pousse naturellement vers
tokio + hyper/axum côté serveur et reqwest côté client — des dizaines de
dépendances transitives pour servir un unique chemin HTTP.

Or l'agent est déployé sur toutes les machines du parc (§17 : l'outil est
lui-même une cible), le serveur détient l'historique des comptes privilégiés
de toute l'organisation, et la règle §17 est explicite : *peu de dépendances,
et aucune ajoutée sans justification écrite*.

## Décision

Le transport est **synchrone, écrit à la main, sans runtime async et sans
bibliothèque HTTP** :

1. **rustls en mode synchrone** (`StreamOwned` sur `std::net::TcpStream`),
   fournisseur cryptographique **`ring` fixé explicitement** des deux côtés :
   le comportement ne dépend pas des features activées ailleurs dans l'arbre
   de dépendances.
2. **HTTP/1.1 minimal écrit à la main.** Côté agent : la requête est quelques
   `write` (ligne de requête, quatre en-têtes, corps CBOR canonique) ; seule
   la ligne de statut de la réponse est lue, le corps n'est jamais décodé ni
   interprété (§7.1 : aucune exécution de code envoyé — pas même une
   désérialisation). Côté serveur : une seule requête par connexion,
   `Content-Length` obligatoire et borné (64 Mio), tête HTTP bornée (16 Kio),
   tout le reste refusé (`400`/`404`/`405`/`411`/`413`).
3. **Un thread par connexion** côté serveur, délais d'entrée-sortie de
   30 secondes des deux côtés : un pair muet ne retient ni l'agent ni un
   thread du serveur indéfiniment.
4. **mTLS obligatoire, sans repli.** L'agent refuse toute URL non-`https`
   avant même d'ouvrir une connexion ; le serveur exige et vérifie le
   certificat client (`WebPkiClientVerifier`, sans mode optionnel) à la
   poignée de main, avant de lire le moindre octet applicatif.

## Justification

- **Surface d'audit.** Le transport complet (deux modules) se lit en une
  heure. Un runtime async + une pile HTTP ajouteraient des dizaines de crates
  à l'arbre que `cargo-deny`/`cargo-audit` surveillent et qu'un RSSI doit
  pouvoir auditer (§17 : la transparence est un argument commercial).
- **La charge ne le justifie pas.** Une poussée par agent et par intervalle
  de collecte, sur un parc de quelques centaines de machines : quelques
  connexions par minute. Un thread par connexion avec des délais stricts est
  au-delà du besoin ; l'async résout un problème que Constat n'a pas.
- **Le protocole est borné par construction.** Un serveur qui ne sert qu'un
  chemin, une méthode, un type de contenu et une taille maximale n'a pas
  besoin d'un routeur ; un client qui ne lit qu'une ligne de statut n'a pas
  besoin d'un client HTTP. Écrire ces deux automates à la main les rend
  exhaustivement vérifiables — et rend structurel le « aucun chemin de
  retour » (§17) : le serveur n'appelle jamais `connect`, l'agent n'appelle
  jamais `bind`.
- **Déterminisme du binaire.** Pas d'exécuteur, pas de tâches : le
  comportement de l'agent est séquentiel et reproductible, ce qui compte pour
  un binaire qu'on veut compiler de façon reproductible (§17).

## Conséquences

### Positives

- Arbre de dépendances réseau réduit à `rustls` (+ `ring`, `webpki`) — déjà
  requis pour le mTLS quelle que soit l'architecture retenue.
- Les limites (64 Mio corps, 16 Kio tête, 30 s d'entrée-sortie, 64 Kio de
  réponse lue côté agent) sont visibles dans le code, testées, et non
  configurables par le pair.
- Le protocole est trivialement rejouable : la poussée est idempotente
  (adressage par contenu), une coupure se rattrape en re-poussant.

### Négatives (assumées)

- Pas de HTTP/2, pas de keep-alive, pas de multiplexage : une connexion TLS
  complète par poussée. Coût accepté — la poussée est rare et par lots.
- Un thread par connexion ne passerait pas à l'échelle de dizaines de
  milliers d'agents à intervalle court. Si ce besoin arrive, la décision sera
  revue **en gardant le contrat visible sur le fil** (même chemin, même CBOR,
  mêmes statuts) : le protocole est indépendant de l'implémentation du
  transport.
- HTTP/1.1 à la main impose la rigueur du parseur (d'où les bornes strictes
  et le fuzzing §12) plutôt que la délégation à une bibliothèque éprouvée.
  Le parseur du serveur refuse tout ce qu'il ne comprend pas, sans jamais
  allouer sur la foi d'un `Content-Length` non vérifié.
