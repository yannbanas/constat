# Revue adversariale interne — 2026-08-14

Deux revues adversariales indépendantes ont été menées sur l'ensemble du code,
en amont de tout audit externe. Chaque revue partait d'un **objectif d'attaquant**
et cherchait des failles concrètes, pas une conformité de surface. Ce document
consigne toutes les trouvailles, leur traitement, et sert de point de départ à un
audit tiers.

Méthode de correction : **chaque faille exploitable a d'abord été reproduite par
un test qui échoue, puis corrigée jusqu'à ce que le test passe.** Les tests de
reproduction restent dans la suite comme non-régression.

## Revue A — Falsification de preuve (cible : `constat-verify` et la chaîne)

Objectif : forger un export accepté par `constat-verify`, ou faire accepter une
altération réelle.

**Résultat : aucun vecteur de forge trouvé.** Le cœur cryptographique est
cohérent avec le modèle de menace.

| # | Sévérité | Trouvaille | État |
|---|---|---|---|
| M1 | Moyenne | Le vérificateur re-encodait l'objet décodé au lieu de hacher les octets bruts du fichier, comme `FORMAT.md §1` le promet. Sur du CBOR non canonique (ciborium est permissif au décodage), `constat-verify` acceptait un fichier qu'un vérificateur tiers conforme aurait rejeté → deux vérificateurs conformes pouvaient diverger. | **Corrigé** : le vérificateur exige `to_canonical_bytes(décodé) == octets_lus` avant de faire confiance, ce qui établit `blake3(octets)==nom` au bit près. `FORMAT.md` §1/§3/§3 bis mis en conformité. Test de non-régression (blob à en-tête CBOR non minimal → rejeté). |
| F2 | Faible | Un snapshot de rotation absent mais « déclaré purgé » était toléré, l'invariant « rotation jamais purgeable » ne tenant que par effet de bord. | **Documenté et testé** : l'invariant repose explicitement (FORMAT.md §4 ter.4) sur le rejet de signature aval ; test ajouté (rotation faussement déclarée purgée → `SignatureInvalide`, export rejeté). |
| F3 | Faible | Espace de noms réservé (`constat.purge`/`constat.rotation`) non imposé à la collecte/réception (défense en profondeur ; pas une injection d'attaquant, collecteurs compilés). | **Corrigé** : préfixe `constat.` réservé, rejeté à la collecte (agent) et à la réception (serveur) hors protocole signé. |
| F4 | Faible | `verify_export` hache les blobs via `hash_canonical` (cohérent, faits opaques à la vérification, blobs non canoniques déjà refusés à l'ingestion). | Note de cohérence, sans action. |

**Angles sans faille (information d'audit positive)** : crypto (`verify_strict`
partout → pas de malléabilité de signature, points de petit ordre rejetés),
rotation (usurpation impossible sans la clé courante), purge (manifeste recalculé,
règle « strictement postérieure » correcte, auto-purge impossible),
troncature/réécriture (chaînage `prev` signé ; la troncature de fin reste la
limite documentée §6.2), malléabilité d'encodage (tout le graphe est signé sur un
encodage déterministe).

## Revue B — Fuite de secrets et compromission (cible : agent, serveur, collecte)

Objectif : (A) faire fuiter un secret via un blob ; (B) compromettre l'agent ou
le serveur.

**Résultat : axe compromission solide ; axe fuite avait de vrais angles morts,
tous corrigés.**

| # | Sévérité | Trouvaille | État |
|---|---|---|---|
| A1 | **Critique** | Identifiants embarqués dans une URL/chaîne de connexion (`DATABASE_URL=postgres://user:S3cr3t@host`) fuyaient **en clair** : aucun délimiteur sensible ne déclenchait, valeur trop courte pour la règle base64. Non couvert par le test anti-fuite. | **Corrigé** : passe `redact_uri_credentials` appliquée à tous les collecteurs, détecte `schéma://userinfo@` et expurge le secret. Test de reproduction (6 schémas). |
| A2 | Haute | XML compact : une balise sensible non-première sur la ligne (`<user><password>…`) fuyait (seule la première balise était inspectée). | **Corrigé** : toutes les balises sensibles de la ligne sont expurgées. Test de reproduction. |
| A3 | Moyenne | Secret positionnel en option (`-pMotDePasse`, `--password X` séparé par espace) fuyait, jusque dans le fait `service.exec_start`. | **Corrigé** : liste d'options portant un secret, forme collée et forme espacée. Test de reproduction. |
| A4 | Moyenne | Règle base64 : double condition (mot de contexte **et** ≥ 40 c.) laisse passer un secret court sous une clé anodine. | **Décision documentée** : seuil conservé pour ne pas générer de faux positifs sur les empreintes légitimes (qui doivent rester) ; les fuites courtes réelles sont désormais traitées par les passes dédiées A1/A3. Limite explicitée dans le rustdoc. |
| B1 | Moyenne | DoS : un thread par connexion sans borne + Mutex global + 64 Mio/connexion → épuisement possible (disponibilité seulement, §17 tient). | **Corrigé** : bornage des connexions simultanées (sémaphore RAII, défaut 64, `--max-connections`), délai d'attente dès la poignée de main. |
| — | Faible | DES 13 c. hors `/etc/shadow` ; TOFU si `--allowed-agents` oublié. | Limites documentées, faible probabilité. |

**Angles sans faille** : abandon de privilèges (séquence
`setgroups→setresgid→setresuid`, vérification que `setuid(0)` échoue, échec
fatal), obligation mTLS (certificat client exigé, poignée refusée avant tout octet
applicatif), parsing HTTP maison (tailles bornées avant allocation, pas de panique
atteignable), isolation des journaux par clé (structurelle), édition d'allowlist
(pas d'injection), blocs `unsafe` (FFI Win32 en lecture seule stricte, gardes
RAII).

## Bilan

À la clôture de cette revue : **aucune trouvaille Critique ou Haute ouverte**. Les
correctifs ont ajouté 17 tests (dont 6 de reproduction d'attaque). Le durcissement
est le commit `68e5c10`.

Ces revues internes **ne remplacent pas** un audit externe indépendant — voir
[`modele-de-menace.md`](modele-de-menace.md) §5 pour ce qu'un auditeur tiers doit
encore couvrir. Elles en constituent le dossier d'entrée.
