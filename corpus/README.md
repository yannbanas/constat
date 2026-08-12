# Corpus — captures réelles anonymisées et verdicts attendus

Ce répertoire est le filet de sécurité **sémantique** des extracteurs de faits
(CONSTAT-ARCHITECTURE.md §12). Les tests unitaires attrapent les erreurs de
code ; le corpus attrape les erreurs de **compréhension** : une directive mal
interprétée, un défaut système oublié, une absence confondue avec un faux.

## Principe

Chaque cas du corpus associe :

- **une capture réelle, anonymisée** — un fichier de configuration tel qu'un
  collecteur le lirait sur une vraie machine, débarrassé de tout ce qui
  identifierait son origine (noms d'hôtes, adresses, comptes réels, secrets) ;
- **les faits attendus** — les triplets que l'extracteur doit produire à
  partir de cette capture, y compris les cas `Absent`.

Un test d'intégration parcourt le corpus, exécute l'extracteur sur chaque
capture et compare fait à fait avec l'attendu. Toute divergence casse la CI.

## Organisation

```
corpus/
└── <collecteur>/            # sshd, sudoers, users, ...
    └── <cas>/               # basique, defaut-implicite, hostile, ...
        ├── capture.txt      # l'artefact brut anonymisé
        └── attendu.yaml     # les faits attendus
```

## Règles d'ajout d'un cas

1. **Anonymiser réellement.** Aucun nom d'hôte, d'utilisateur, de domaine ou
   d'adresse provenant d'un système réel. Aucun secret, même invalide, même
   expiré : le corpus est public et les blobs sont soumis au test anti-fuite.
2. **Garder le réalisme.** Une capture de corpus doit ressembler à ce que la
   machine produit vraiment : commentaires, ordre des directives, variantes de
   casse, espaces — c'est précisément ce qui piège les extracteurs.
3. **Toujours inclure au moins un fait `Absent` quand le format s'y prête.**
   « L'attribut n'existe pas » et « l'attribut vaut faux » sont deux faits
   différents (ADR 001) ; le corpus doit vérifier que l'extracteur ne les
   confond pas.
4. Tout bogue d'extraction corrigé donne lieu à un cas de corpus qui
   l'aurait attrapé.

## Premier cas : `sshd/basique`

Un `sshd_config` Linux réaliste et anonymisé. Points vérifiés :

- directives explicites (`PermitRootLogin no`, `PasswordAuthentication no`…) ;
- casse non normalisée et commentaires ignorés ;
- **`sshd.X11Forwarding` attendu `absent`** : la directive ne figure pas dans
  le fichier — le défaut du système s'applique, et l'extracteur ne doit ni
  l'inventer ni le confondre avec `no` (une directive en commentaire n'est
  pas une directive).
