//! # constat-verify — vérificateur autonome
//!
//! **La vérification doit être possible sans Constat** (§10.3).
//! Ce crate doit rester minuscule et auditable par un tiers en une heure :
//! il recalcule la chaîne d'empreintes, vérifie signature et jeton
//! d'horodatage, et confirme que les artefacts correspondent à leurs empreintes.
//!
//! Dépend UNIQUEMENT de constat-model et constat-store (règle §8).

// Le contenu est développé par l'agent responsable du vérificateur.
