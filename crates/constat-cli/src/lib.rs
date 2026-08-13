//! # constat-cli — la surface d'interrogation (§10)
//!
//! Bibliothèque interne du binaire `constat`. Toute la logique est écrite
//! contre `&dyn Store` : le test de fumée l'exerce sur un magasin en mémoire,
//! et le câblage du backend concret (redb) se limite à
//! [`storeopen::open_store`].
//!
//! La CLI est en lecture seule, comme tout le produit (§1), à UNE exception
//! près, assumée et documentée : `segmentation --record` ([`segmentation`]),
//! qui archive le verdict d'accessibilité comme entrée **signée** du journal
//! — le §14 en fait un fait horodaté de plein droit. Toutes les autres
//! écritures se font **à côté** du magasin : export vérifiable, fichiers
//! d'ancrage, dossier de preuve.

pub mod anchors;
pub mod commands;
pub mod coverage;
pub mod datetime;
pub mod eval;
pub mod http;
pub mod keyres;
pub mod queries;
pub mod referential;
pub mod render;
pub mod segmentation;
pub mod storeopen;
