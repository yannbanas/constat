# Journal des modifications

Tous les changements notables de ce projet sont documentés ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le
projet adhère au [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

## [0.2.0] — 2026-08-13

### Ajouté

- **Collecteurs Windows et Active Directory** (chantier S5) :
  `windows.accounts`, `windows.password_policy`, `windows.services`,
  `ad.groups`, `ad.gpo_security` — collecte en lecture seule via les API
  Win32 (aucune commande exécutée), détection des privilèges par SID
  (`S-1-5-32-544`, RID 512/519 — jamais les noms localisés), capture texte
  normalisée, extracteurs purs testables sur tout OS. Hors domaine, `ad.*`
  se déclare indisponible avec le motif.
- **Agent en mode continu** : `constat-agent run --every 6h` (gigue ±10 %, un
  échec de cycle n'arrête pas la boucle), poussée optionnelle après chaque
  collecte (`--push`), `constat-agent install` (unités systemd ou tâche
  planifiée Windows) et `constat-agent status`.
- **CLI** : tables de correspondance par référentiel dans le dossier de preuve
  (`constat pack --referential <fichier-ou-nom>`, format YAML documenté,
  exemples dans `referentials/`), envoi des requêtes d'horodatage RFC 3161 en
  `https://` (client TLS minimal synchrone, racines Mozilla embarquées), et
  `constat verify` qui rappelle la procédure de vérification indépendante.
- **Journaux nommés côté magasin** (multi-agents) : chaque agent a sa propre
  chaîne (`MultiJournalStore`), isolation vérifiée par tests, migration
  transparente d'un magasin v0.1.0, export par journal au layout de
  `constat-verify`.
- **Fuzzing** (§12) : cinq cibles cargo-fuzz dans `fuzz/` (workspace
  indépendant, nightly) — extracteur sshd, expurgation (avec borne de
  croissance linéaire), YAML d'assertions, décodage canonique, vérification
  d'entrées de journal — et un job CI hebdomadaire de 60 s par cible
  (`.github/workflows/fuzz.yml`).
- **Corpus étendu** : `sshd/blocs-match` (directives dupliquées, blocs
  `Match`), `accounts/comptes-verrouilles` (`!` contre `*`, verrouillé mais
  toujours membre de sudo), `packages/half-configured` (l'état dpkg est le
  troisième mot de `Status:`), `kernel_params/partiel` (clés absentes ≠ 0).
- **ADR 003** — transport mTLS synchrone sans runtime async : HTTP/1.1 écrit
  à la main sur rustls synchrone, fournisseur `ring` fixé, un thread par
  connexion ; la surface d'audit prime, la charge ne justifie pas l'async.

## [0.1.0] — 2026-08-12

Première version publique.

### Ajouté

- **Collecte en lecture seule** — agent Linux avec 8 collecteurs : comptes
  privilégiés, preuve de sauvegarde, `sshd_config`, sudoers, paquets, ports en
  écoute, unités systemd, paramètres noyau. Expurgation des secrets **à la
  source** : aucun secret ne quitte la machine, vérifié par un test anti-fuite
  permanent.
- **Magasin adressé par contenu** (redb + zstd, déduplication) avec **journal
  Merkle signé Ed25519** : toute altération du magasin est détectée.
- **Modèle temporel honnête** : chaque verdict est accompagné de sa
  couverture ; les interruptions de collecte sont déclarées, jamais masquées.
- **Assertions en YAML** (langage volontairement non Turing-complet),
  exceptions à expiration obligatoire, verdict `Indéterminé` à part entière,
  explications complètes (`constat check --explain`).
- **Poussée mTLS** agent → serveur, certificat client obligatoire, aucun
  chemin de retour vers le parc par construction.
- **Ancrage externe** : export de racine signé et horodatage RFC 3161
  (`constat anchor --send`).
- **Dossier de preuve HTML** (`constat pack`) avec la section « Ce que ce
  dossier ne prouve pas ».
- **Vérificateur autonome** `constat-verify` : contrôle un export sans faire
  confiance à Constat — algorithme public dans
  [FORMAT.md](crates/constat-verify/FORMAT.md), réimplémentable en une
  centaine de lignes.
- Distribution : archives Linux x86_64/aarch64 et Windows x86_64 (empreintes
  SHA-256 jointes), image conteneur `ghcr.io/yannbanas/constat:0.1.0`.
- Qualité : 354 tests (propriétés, snapshots, altération, anti-fuite,
  bout-en-bout mTLS), clippy sans avertissement, CI multi-OS avec test de
  stabilité d'empreinte x86/ARM.

### Limites connues (déclarées par conception)

Sans ancrage externe, le journal prouve la **cohérence interne**, pas la
non-répudiation : celui qui détient la clé peut tronquer la fin du journal.
Constat ne détecte pas un agent compromis qui mentirait, et ne dit rien d'une
machine sans agent.

[Non publié] : https://github.com/yannbanas/constat/compare/v0.2.0...HEAD
[0.2.0] : https://github.com/yannbanas/constat/compare/v0.1.0...v0.2.0
[0.1.0] : https://github.com/yannbanas/constat/releases/tag/v0.1.0
