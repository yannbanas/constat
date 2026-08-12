# Politique de sécurité

Constat est un outil de preuve d'état de configuration. Sa sécurité n'est pas
un à-côté : c'est le produit. Nous prenons chaque signalement au sérieux.

## Signaler une vulnérabilité

**Ne signalez jamais une vulnérabilité dans une issue publique.**

Contact : **yannbanas@gmail.com** — indiquez `[SECURITY][constat]` dans l'objet.

Merci d'inclure, dans la mesure du possible :

- une description du problème et de son impact ;
- les étapes de reproduction (versions, plateforme, configuration) ;
- votre évaluation de la gravité ;
- si vous en avez un, un correctif ou une piste de correctif.

Si vous souhaitez chiffrer votre message, dites-le dans un premier courriel non
chiffré et une clé vous sera fournie.

## Engagement de réponse

- **Accusé de réception : sous 72 heures.**
- **Première analyse (confirmation, gravité, plan) : sous 7 jours.**
- Correctif : selon la gravité — les vulnérabilités critiques (fuite de secret,
  contournement de la chaîne de preuve, exécution de code) sont traitées en
  priorité absolue sur tout autre travail.
- Nous vous tenons informé à chaque étape, et nous vous créditons dans l'avis
  de sécurité si vous le souhaitez.
- Divulgation coordonnée : nous demandons un délai raisonnable (90 jours par
  défaut, négociable) avant publication, le temps de livrer le correctif.

## Périmètre — ce qui nous inquiète particulièrement

Le modèle de menace complet est décrit dans
[CONSTAT-ARCHITECTURE.md](CONSTAT-ARCHITECTURE.md) (§6, §7, §17). En résumé :

**L'agent lit des configurations sensibles** (`sshd_config`, `sudoers`,
comptes, politiques de mots de passe…) sur toutes les machines du parc. Sont
donc critiques :

- toute **fuite de secret** : un secret (empreinte de mot de passe, clé privée,
  jeton) qui quitterait la machine au lieu d'être expurgé à la source ;
- toute **élévation de privilèges** via l'agent, ou tout écart à la lecture
  seule ;
- tout chemin par lequel l'agent pourrait être amené à **exécuter du code
  envoyé** — cette capacité n'existe pas par conception, et tout ce qui s'en
  approche est une vulnérabilité critique ;
- la robustesse des extracteurs face à des **entrées hostiles** (les fichiers
  de configuration sont des entrées non fiables).

**Le serveur est un dépôt de données sensibles** : l'historique des comptes
privilégiés et des configurations de tout un parc. Sont donc critiques :

- tout accès non autorisé aux données, au repos ou en transit ;
- tout **chemin de retour du serveur vers les machines auditées** — il ne doit
  pas en exister, c'est une propriété d'architecture ;
- toute faiblesse du mTLS ou de l'authentification des agents.

**La chaîne de preuve** elle-même :

- toute possibilité de modifier le magasin sans que `constat-verify` le
  détecte ;
- toute instabilité d'empreinte (deux encodages différents des mêmes données) ;
- toute faiblesse dans la signature ou l'ancrage.

## Versions prises en charge

Le projet est en pré-version (0.x) : seule la branche principale et la dernière
version publiée reçoivent des correctifs de sécurité.
