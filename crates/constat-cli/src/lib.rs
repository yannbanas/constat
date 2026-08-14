//! # constat-cli — la surface d'interrogation (§10)
//!
//! Bibliothèque interne du binaire `constat`. Toute la logique est écrite
//! contre `&dyn Store` : le test de fumée l'exerce sur un magasin en mémoire,
//! et le câblage du backend concret (redb) se limite à
//! [`storeopen::open_store`].
//!
//! La CLI est en lecture seule, comme tout le produit (§1), à DEUX exceptions
//! près, assumées et documentées :
//!
//! - `segmentation --record` ([`segmentation`]) : archive le verdict
//!   d'accessibilité comme entrée **signée** du journal — le §14 en fait un
//!   fait horodaté de plein droit ;
//! - `purge` ([`purge`]) : la purge de rétention journalisée (§16) —
//!   supprime blobs et snapshots au-delà de la rétention et **déclare la
//!   purge dans une nouvelle entrée signée** ; les entrées de journal, elles,
//!   ne sont jamais supprimées.
//!
//! Toutes les autres écritures se font **à côté** du magasin : export
//! vérifiable, fichiers d'ancrage, dossier de preuve.

pub mod anchors;
pub mod commands;
pub mod coverage;
pub mod datetime;
pub mod eval;
pub mod http;
pub mod keyres;
pub mod purge;
pub mod queries;
pub mod referential;
pub mod render;
pub mod segmentation;
pub mod storeopen;
