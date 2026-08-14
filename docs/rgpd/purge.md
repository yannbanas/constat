# La purge de rétention journalisée

> Une suppression liée à la rétention crée un trou dans les données, et un
> trou non déclaré est indistinguable d'un effacement malveillant. La purge
> doit donc écrire dans le journal **qu'elle a eu lieu**, sur quelle période
> et pour quel motif, sans réécrire la chaîne. (Architecture, §16.)

## Fonctionnement

`constat purge --older-than <durée> --reason <motif>` supprime du magasin :

- les **snapshots** plus vieux que la durée de rétention ;
- les **blobs** (artefacts bruts + faits extraits) qui ne sont plus
  référencés par aucun snapshot conservé. Un blob dédupliqué encore
  référencé par un snapshot récent est conservé : on ne troue jamais une
  preuve encore vivante.

Avant toute suppression, la purge écrit sa **déclaration** dans le journal :
un enregistrement `constat.purge` (période purgée, motif, date, nombre
d'objets, liste complète des empreintes supprimées et son empreinte BLAKE3),
référencé par une **nouvelle entrée signée**. L'ordre est délibéré — déclarer
d'abord, supprimer ensuite : si la suppression s'interrompt, il existe une
déclaration qui couvre des objets encore présents (bénin), jamais des objets
absents sans déclaration (la signature d'un effacement malveillant).

La commande est irréversible : elle affiche un récapitulatif et exige une
confirmation (`--yes` pour l'automatisation, `--dry-run` pour simuler).
`constat retention --show` montre l'âge des données ; `constat retention
--check <durée>` montre ce qu'une politique de rétention purgerait, sans rien
modifier.

## Garanties

- **La chaîne n'est jamais réécrite.** Les entrées de journal existantes
  restent intactes au bit près ; la déclaration s'ajoute à la fin, signée
  comme n'importe quelle collecte. Les racines déjà ancrées (courriel,
  RFC 3161) restent donc valables.
- **Le trou est déclaré, jamais masqué.** Après purge, `constat history` et
  `constat check` montrent la période purgée comme une interruption « purge
  de rétention journalisée » — pas comme un trou inexpliqué.
- **La vérification par un tiers distingue purge et altération.** Le
  vérificateur autonome (`constat-verify`) accepte un objet absent **si et
  seulement si** son empreinte figure dans le manifeste d'une déclaration de
  purge postérieure, revérifiée (compte et empreinte BLAKE3 de la liste). Il
  répond alors « cohérent — N objets purgés déclarés (période, motif) ». Un
  objet manquant **non déclaré** reste une erreur d'altération. L'algorithme
  exact est normatif : `crates/constat-verify/FORMAT.md`, § « Objets purgés ».
- **Rejouer une purge est sans effet.** Une purge qui ne trouve rien à
  supprimer n'écrit rien : pas de déclarations vides accumulées.
- **Les exports produits avant l'existence de la purge restent valides** et
  se vérifient exactement comme avant.

## Ce que la purge ne fait pas

Par honnêteté, ces limites sont assumées et documentées :

- **Elle ne supprime pas les entrées de journal.** Empreintes, dates et
  signatures (sans contenu personnel) sont la chaîne de preuve : elles ne
  rétrécissent jamais. Sont également conservées les déclarations de purge
  elles-mêmes — les supprimer rendrait les anciennes purges indistinguables
  d'un effacement.
- **Elle n'atteint pas ce qui a déjà quitté le magasin.** Un export remis à
  un auditeur, un dossier de preuve archivé ailleurs, une copie de
  sauvegarde : la purge porte sur le magasin local, pas sur les copies. La
  politique de rétention de ces copies relève de leurs détenteurs.
- **Elle ne purge pas les journaux des autres signataires.** Sur un magasin
  central multi-agents, tout objet encore référencé par le journal nommé
  d'un autre agent est conservé : on ne troue jamais la chaîne d'autrui.
- **Elle n'est pas un droit à l'oubli instantané.** C'est une politique de
  rétention : régulière, datée, motivée. Un effacement anticipé et ciblé
  demande un arbitrage du responsable de traitement entre droit d'effacement
  et obligation de preuve (voir `registre-de-traitement.md`, § 8).
