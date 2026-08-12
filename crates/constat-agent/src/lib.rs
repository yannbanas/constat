//! # constat-agent — bibliothèque
//!
//! Le cœur de l'agent de collecte, exposé en bibliothèque pour que les tests
//! d'intégration (notamment le bout-en-bout de `constat-server`) exercent le
//! **vrai** code de l'agent — le binaire `constat-agent` n'est qu'une couche
//! d'arguments au-dessus de ces modules.
//!
//! # Contraintes §7.1, non négociables
//!
//! - **Aucun port en écoute.** Aucun module de ce crate n'appelle
//!   `bind`/`listen` : la seule communication réseau est la poussée sortante
//!   mTLS du module [`push`], qui initie la connexion, pousse, et raccroche.
//! - **Aucune exécution de code envoyé.** Les collecteurs sont compilés dans
//!   le binaire (`constat-collect`) ; la réponse du serveur est un accusé de
//!   réception dont seul le statut HTTP est lu, jamais le corps.
//! - **Lecture seule** sur la machine auditée : les seules écritures sont le
//!   magasin local et les fichiers de clés.
//! - **Expurgation avant émission** (§7.2) : `redact` s'applique avant toute
//!   écriture dans le magasin — le serveur ne reçoit jamais autre chose que
//!   la forme expurgée.

pub mod keys;
pub mod push;
pub mod run;
pub mod storeopen;
