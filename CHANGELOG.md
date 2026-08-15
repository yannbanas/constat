# Journal des modifications

Tous les changements notables de ce projet sont documentés ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le
projet adhère au [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

## [0.4.0] — 2026-08-14

Version de préparation à la production : les bloquants identifiés lors de la
revue de maturité sont levés, une revue de sécurité adversariale a été menée
et ses trouvailles corrigées, et la promesse de stockage du §3.3 est vérifiée
chiffres en main.

### Sécurité

- **Revue adversariale interne** (`docs/securite/`) : deux revues indépendantes
  (falsification de preuve ; fuite de secrets et compromission). Aucune
  falsification de preuve possible (cœur cryptographique solide). Vecteurs de
  fuite de secrets trouvés **et corrigés**, chacun avec un test qui reproduit
  l'attaque : identifiants d'URL (`postgres://user:pass@…`, **critique**), XML
  compact multi-balises, secrets positionnels (`-pXXX`, `--password X`).
  Conformité du vérificateur rétablie (il exige désormais
  `blake3(octets du fichier) == nom`, comme `FORMAT.md` le promet — deux
  vérificateurs conformes ne peuvent plus diverger). DoS de disponibilité
  corrigé : connexions serveur bornées (sémaphore, `--max-connections`). Espace
  de noms `constat.*` réservé aux déclarations signées.

### Performance

- **`check` et `history` à empreinte mémoire bornée** : le benchmark a chiffré
  un pic à ~4,8 Gio (dépliage de toutes les observations du parc). Ces deux
  commandes traitent désormais les machines une par une (pic ~80 Mio, croissance
  bornée au lieu de tendre vers l'OOM). Verdicts, format et empreintes
  strictement inchangés (le chemin global des tests est réécrit sur le même
  accumulateur en flux). `docs/benchmarks.md` : résultats réels (200 machines ×
  90 jours × 3 profils de dérive) — promesse §3.3 tenue (3 ans / 200 machines
  ≈ 1 Gio), vérification par un tiers < 2 s.

### Ajouté

- **Purge de rétention journalisée** (§16, bloquant de production) : la purge se
  déclare dans le journal **avant** de supprimer (période, motif, manifeste des
  empreintes), la chaîne n'est jamais réécrite. `constat-verify` distingue une
  absence légitimement purgée (postérieurement déclarée) d'une altération.
  `constat purge` / `constat retention`, trous `RetentionPurge` dans la
  couverture, `docs/rgpd/` (registre de traitement, fonctionnement).
- **Privilèges minimaux de l'agent** (§7.1) : en mode `--once`, abandon
  `setgroups`/`setresgid`/`setresuid` avant toute connexion réseau, avec
  vérification que la réacquisition échoue. Unité systemd durcie (chaque
  directive commentée).
- **Gestion et rotation des clés de signature** (bloquant de production) —
  une rotation est un constat réservé, sur le modèle de la purge : blob
  `constat.rotation` (faits `rotation.old_key`/`rotation.new_key` en
  `Fingerprint`, `rotation.reason` optionnel, document brut lisible),
  référencé par une **nouvelle entrée signée par l'ANCIENNE clé** — c'est
  elle qui délègue ; les entrées suivantes sont signées par la nouvelle.
  Tout est additif : journaux et exports existants restent valides tels
  quels, empreintes de `constat-model` intactes.
  - **Magasin** (`constat-store`) : module `rotation` — `rotate_key`,
    `current_key` (la clé de genèse, puis chaque rotation valide la
    remplace), `genesis_key` (retrouve l'identité depuis le journal),
    `verify_chain_rotated` (suit la clé courante ; nouvelle variante
    `ChainError::RotationInvalide` : une rotation dont `old_key` n'est pas
    la clé courante est une usurpation, chaîne refusée). La garde
    structurelle `append_entry_in` suit la clé courante : après rotation,
    seule la clé déléguée écrit dans le journal (nommé par la clé de
    GENÈSE — l'identité ne change pas). Purge × rotation : un
    enregistrement de rotation n'est **jamais** purgeable (même règle que
    les enregistrements de purge) — le purger rendrait toute la suite de
    la chaîne invérifiable.
  - **Vérificateur** (`constat-verify`) : les signatures se vérifient avec
    la clé courante — `pubkey.bin` (la genèse, inchangé) jusqu'à la
    première rotation valide, puis la clé déléguée ; sortie « N
    rotation(s) de clé, clé finale <hex abrégé> », nouveaux champs
    `rotation_count`/`final_key`, nouvelle erreur `RotationInvalide`
    (usurpation, déclaration illisible, ou blob de rotation absent — même
    déclaré purgé). FORMAT.md : nouvelle section normative « 4 ter.
    Rotation de clé » (algorithme exact, note de version : un vérificateur
    antérieur échoue sûrement, jamais de faux OK).
  - **Agent** : `constat-agent rotate-key [--keys] [--reason] [--store]` —
    refuse si le magasin est inaccessible (une rotation non journalisée
    n'existe pas), écrit l'entrée de rotation signée par l'ancienne clé,
    archive l'ancienne paire (`agent.key.<date>.old`,
    `agent.pub.<date>.old`, permissions conservées) et met la nouvelle en
    place ; affiche anciennes/nouvelles empreintes et le rappel
    d'allowlist. La poussée annonce désormais la clé de **GENÈSE**
    (l'identité, dérivée du journal par `genesis_key`) — inchangée tant
    qu'aucune rotation n'a eu lieu.
  - **Serveur** : le `StoreReceiver` suit la clé courante de chaque
    journal (une poussée contenant une rotation valide bascule la
    validation ; nouvelle erreur `RotationInvalide`, lot refusé avant
    toute écriture). Le `JournalId` reste la clé de GENÈSE — choix
    documenté : l'identité du journal ne change pas, seule la clé de
    signature courante change ; l'allowlist liste donc des identités, une
    rotation ne casse jamais l'autorisation, une révocation retire
    l'identité entière. Sous-commandes `constat-server agents --file <f>
    list|add <hex> [nom]|remove <hex>|revoke <hex>` : édition propre du
    fichier d'allowlist (commentaires et ordre préservés, nom en
    commentaire de fin de ligne), révocation **tracée** par une note datée
    dans le fichier.
  - **CLI** : `constat export` vérifie la chaîne en suivant les rotations
    et écrit dans `pubkey.bin` la clé de genèse retrouvée depuis le
    journal (la clé fournie via `--pubkey`/`--keys` est la clé courante).
  - **Docs** : `docs/cles.md` — cycle de vie complet en français :
    génération, garde (pourquoi on ne sauvegarde PAS la clé privée : elle
    est remplaçable par rotation, une copie est un risque ; perte sans
    rotation = nouveau journal, ancienne chaîne close et toujours
    vérifiable), rotation planifiée (cadence recommandée), compromission
    (révocation + rotation + ancrage + investigation depuis la dernière
    racine ancrée, en lien avec §6.2), lien avec l'ancrage externe.
- **Purge de rétention journalisée** (§16, bloquant de production) — un trou
  non déclaré est indistinguable d'un effacement malveillant ; la purge
  déclare donc **qu'elle a eu lieu**, sur quelle période et pour quel motif,
  sans réécrire la chaîne. Tout est additif : les magasins et exports v0.3.0
  restent valides tels quels.
  - **Magasin** (`constat-store`) : module `purge` — l'enregistrement de
    purge est un constat ordinaire (blob du collecteur réservé
    `constat.purge` : document brut lisible avec la liste complète des
    empreintes purgées, faits `purge.from`/`purge.to`/`purge.reason`/
    `purge.objects`/`purge.manifest` — BLAKE3 de la liste canonique),
    référencé par une **nouvelle entrée signée**. `plan_purge` (lecture
    seule) et `purge_older_than`/`execute_plan` : déclaration écrite AVANT
    la suppression, blobs dédupliqués encore référencés conservés, clôtures
    des journaux nommés intouchées, rejeu idempotent (rien à purger → rien
    d'écrit). Nouveau sous-trait `PurgeableStore` (`delete_blob`,
    `delete_snapshot` — jamais les entrées de journal) implémenté par les
    deux backends, et `Store::has_snapshot` (défaut fourni).
  - **Export** : un objet référencé mais absent est toléré si son empreinte
    figure dans un manifeste de purge présent ; toute autre absence échoue
    comme avant.
  - **Vérificateur** (`constat-verify`) : une absence est acceptée si — et
    seulement si — elle est déclarée par une purge **postérieure** dans la
    chaîne, au manifeste revérifié ; sortie « cohérent — N objet(s) purgé(s)
    déclaré(s) (période, motif) », nouveaux champs `purged_count` et
    `purges` du résultat, nouvelle erreur `DeclarationPurgeInvalide`. Un
    objet manquant non déclaré reste une erreur d'altération. FORMAT.md :
    nouvelle section normative « Objets purgés » (algorithme exact, note de
    version : les exports pré-purge restent valides).
  - **CLI** : `constat purge --older-than <durée> --reason <motif>
    [--keys <dossier>] [--dry-run] [--yes]` — récapitulatif puis
    confirmation interactive (une purge est irréversible), deuxième commande
    d'écriture de la CLI après `segmentation --record`, documentée comme
    telle dans l'aide ; `constat retention --show|--check <durée>` (lecture
    seule : âge des données, purges déjà déclarées, simulation).
  - **Couverture** : les périodes purgées apparaissent comme des trous
    `RetentionPurge` dans `constat history` et `constat check` — déclarés,
    jamais masqués en `Unknown`.
  - **Docs RGPD** : `docs/rgpd/registre-de-traitement.md` (modèle art. 30
    prêt à verser au dossier du client, rétention par défaut 3 ans alignée
    sur l'audit) et `docs/rgpd/purge.md` (fonctionnement, garanties, et ce
    que la purge ne fait pas).
- **Paquets Linux (.deb + .rpm)** : `packaging/build-packages.sh` assemble
  trois paquets (`constat-tools` : CLI + vérificateur ; `constat-agent` et
  `constat-server`, qui en dépendent — aucun binaire dupliqué, agent et
  serveur co-installables) avec `dpkg-deb` et `rpmbuild` à partir de
  squelettes versionnés dans `packaging/` — explicite, auditable, sans
  générateur opaque. Unités systemd livrées (timer de collecte 6 h, service
  serveur sous utilisateur système `constat`), conffiles
  `/etc/constat/*.env`, `/var/lib/constat` en 0750, **rien d'activé
  automatiquement** et magasin **conservé à la désinstallation** (c'est de
  la preuve). Job de release `paquets-linux` : x86_64 et aarch64 (natif sur
  runner ARM), empreintes SHA-256 jointes.
- **Provenance SLSA et SBOM des artefacts** (§17) : chaque archive, paquet
  et SBOM de release est attesté par `actions/attest-build-provenance`
  (signature Sigstore liant l'artefact au commit et au workflow —
  vérifiable par `gh attestation verify … --repo yannbanas/constat`) ;
  nomenclature SPDX générée par syft depuis les sources au tag exact
  (`Cargo.lock`, compilation `--locked`), attachée à la release avec son
  empreinte.
- **Supervision du serveur** : `constat-server status` — par journal/agent :
  dernière entrée, âge, nombre d'entrées, racine. `--max-age <durée>` :
  code de sortie 1 si un journal est en retard (check cron/Nagios) ;
  `--expected <fichier>` (clé publique hex + nom optionnel par ligne) :
  journaux attendus absents et journaux inattendus signalés — l'écart
  d'inventaire est un constat (§10.2) ; `--format prometheus` : métriques
  textfile (`constat_agent_last_entry_timestamp_seconds`,
  `constat_agent_entries_total`, `constat_agent_stale`,
  `constat_store_size_bytes`, compteurs d'écart) pour le textfile collector
  de node_exporter. **Aucun port ni endpoint nouveau** : la supervision est
  un binaire qu'on lance, pas une surface d'attaque (§17).
- **Guide d'exploitation** (`docs/exploitation.md`) : installation par
  paquets, vérification des empreintes/attestations/SBOM, sauvegarde du
  magasin (export normatif recommandé — vérifiable —, copie à froid en
  alternative), restauration, supervision (cron + Prometheus), journaux
  applicatifs via journald, mise à jour, désinstallation, et la liste
  honnête de ce qui n'est pas encore automatisé (MSI/winget Windows,
  sauvegarde à chaud, réimportation d'export, dépôt apt/yum, reproduction
  indépendante du build).

## [0.3.0] — 2026-08-13

### Ajouté

- **Collecteur `network.configs`** (S7) : répertoire de dépôt
  (`/var/lib/constat/network-configs/`,
  `C:\ProgramData\constat\network-configs\`) — un fichier par équipement
  réseau (FortiGate, Cisco IOS, nftables, OPNsense), capture multi-sections
  déterministe, expurgation dédiée (`psksecret`, blobs `ENC`,
  `enable secret`, communautés SNMP, balises XML sensibles — la structure
  survit, jamais la valeur), faits `netdev.config_present`,
  `netdev.config_lines`, `netdev.format_hint`.
- **`constat segmentation` — la jonction avec Calque** (§14, chantier S7) :
  évalue les configurations réseau historiques du magasin avec le moteur de
  Calque (v0.3.0, épinglé par tag git — exception justifiée dans `deny.toml`).
  - `--flows <fichier> --at <date>` : relit le dernier blob `network.configs`
    antérieur à la date, importe chaque équipement (`calque-vendors`, libellé
    `<équipement>@<date>` — chaque règle décisive cite sa source et sa ligne),
    assemble le réseau (`calque-engine`) et évalue les flux déclarés
    (`calque-policy`, même `flows.yaml` que `calque test`). Verdicts trois
    états (conforme / violé / non concluant), équipement illisible ou import
    partiel **déclaré** et bloquant tout verdict ferme, traçabilité par
    empreinte du blob de configurations. Codes de sortie 0/1/3.
  - `--period <p>` : chronologie des verdicts à chaque changement de
    configuration observé dans la période, intervalles datés par flux,
    couverture et trous déclarés.
  - `--record [--keys <dossier>] [--asset <machine>]` : le verdict redevient
    un fait horodaté — entrée signée au journal, collecteur
    `calque.segmentation` (compte rendu complet en artefact brut, faits
    `flow.expected`/`flow.verdict`/`flow.status`/`flow.rule` et entité
    `segmentation:run` avec les empreintes du fichier de flux et du blob
    évalué). **La seule commande de la CLI qui écrit dans le magasin**,
    documentée comme telle dans l'aide.

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

[Non publié] : https://github.com/yannbanas/constat/compare/v0.4.0...HEAD
[0.4.0] : https://github.com/yannbanas/constat/compare/v0.3.0...v0.4.0
[0.3.0] : https://github.com/yannbanas/constat/compare/v0.2.0...v0.3.0
[0.2.0] : https://github.com/yannbanas/constat/compare/v0.1.0...v0.2.0
[0.1.0] : https://github.com/yannbanas/constat/releases/tag/v0.1.0
