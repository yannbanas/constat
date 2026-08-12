//! # constat-cli — la surface d'interrogation (§10)
//!
//! Bibliothèque interne du binaire `constat`. Toute la logique est écrite
//! contre `&dyn Store` : le test de fumée l'exerce sur un magasin en mémoire,
//! et le câblage du backend concret (redb) se limite à
//! [`storeopen::open_store`].
//!
//! La CLI est en lecture seule, comme tout le produit (§1) : aucune commande
//! n'écrit dans le magasin. Les seules écritures se font **à côté** : export
//! vérifiable, fichiers d'ancrage, dossier de preuve.

pub mod anchors;
pub mod commands;
pub mod coverage;
pub mod datetime;
pub mod eval;
pub mod http;
pub mod keyres;
pub mod queries;
pub mod render;
pub mod storeopen;
