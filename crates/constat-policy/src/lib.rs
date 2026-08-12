//! # constat-policy — cœur pur
//!
//! Langage d'assertions volontairement faible (§5) : total, terminant,
//! analysable. Ni Rhai, ni Lua, ni Starlark — jamais.
//! Aucune entrée-sortie : le YAML arrive en `&str`, l'évaluation est une
//! fonction pure — deux évaluations sur les mêmes données donnent le même
//! verdict.
//!
//! Points d'entrée :
//!
//! - [`parse_assertions`] — parse et valide le YAML d'assertions (§5.2) ;
//! - [`evaluate`] / [`evaluate_with`] — évalue une assertion sur une machine
//!   à partir de faits datés et d'un rapport de couverture ;
//! - [`explain`] — produit l'explication humaine, en français (§5.3) ;
//! - [`parse_duration`] / [`format_duration`] — durées lisibles (« 24h ») ;
//! - [`parse_date`] / [`format_date`] / [`format_datetime`] — dates UTC.
//!
//! **CONTRAT PUBLIC** : extensible, jamais cassé.

use constat_model::{AssetId, Attribute, BlobHash, EntityId, Timestamp, Value};
use constat_time::CoverageReport;
use serde::{Deserialize, Serialize};

pub mod dates;
pub mod duration;
mod error;
mod eval;
mod explain;
mod parse;
mod pattern;
pub(crate) mod value_repr;

pub use dates::{format_date, format_datetime, parse_date};
pub use duration::{format_duration, parse_duration};
pub use error::PolicyError;
pub use eval::{
    evaluate, evaluate_with, EvaluationInput, EvaluationOptions, TimedFact,
    DEFAULT_MIN_OBSERVED_PPM, NO_EVIDENCE,
};
pub use explain::{explain, format_value};
pub use parse::{parse_assertions, validate_assertion};
pub use pattern::glob_match;

/// Profondeur maximale d'imbrication d'un prédicat.
///
/// Garantit que le parsing et l'évaluation terminent avec une pile bornée,
/// même face à un document hostile. Soixante-quatre niveaux dépassent très
/// largement tout besoin réel d'une politique de conformité.
pub const MAX_PREDICATE_DEPTH: usize = 64;

/// Identifiant d'assertion, ex. `"SSH-ROOT"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AssertionId(pub String);

/// Sélecteur de machines (portée d'une assertion).
///
/// Le filtrage effectif des machines appartient à l'appelant (la CLI) :
/// le cœur ne connaît pas l'inventaire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetSelector {
    /// Système d'exploitation, ex. `linux`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Étiquette, ex. `production`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Domaine, `"*"` pour tous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Motif d'entités, ex. `"service:sshd"`, ou sélection typée avec filtre.
///
/// Voir [`EntityPattern::matches`] pour la sémantique de correspondance
/// (jokers `*`/`?` pour la forme glob, filtre `where` sur les faits pour la
/// forme typée).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EntityPattern {
    /// Motif littéral avec jokers `*`, ex. `"user:*"`.
    Glob(String),
    /// Sélection typée : `{ type: user, where: { privileged: true } }`.
    Typed {
        /// Type d'entité : le préfixe avant `:` de l'identifiant.
        #[serde(rename = "type")]
        entity_type: String,
        /// Clauses sur les faits de l'entité ; la clé `k` vise l'attribut
        /// `k` ou `"{type}.{k}"`. Valeurs en YAML naturel (`true`, `3`,
        /// `"texte"`, `null` pour l'absence).
        #[serde(default, rename = "where", with = "crate::value_repr::map_repr")]
        filter: std::collections::BTreeMap<String, Value>,
    },
}

/// Prédicat total et terminant (§5.1).
///
/// Les valeurs `equals` s'écrivent en YAML naturel (`equals: true`,
/// `equals: "yes"`, `equals: 3`), les durées `than` en texte lisible
/// (`than: 24h`). La sémantique d'évaluation — notamment celle de l'absence
/// (§3.2) — est documentée sur [`evaluate_with`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Predicate {
    /// Aucune entité correspondante ne porte jamais `attr == equals`.
    Never {
        /// Entités visées.
        entity: EntityPattern,
        /// Attribut visé.
        attr: Attribute,
        /// Valeur interdite.
        #[serde(with = "crate::value_repr")]
        equals: Value,
    },
    /// Les entités de la portée portent toujours `attr == equals`.
    Always {
        /// Entités visées ; absent : l'entité liée par `forall`, sinon
        /// toutes les entités portant l'attribut.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entity: Option<EntityPattern>,
        /// Attribut visé.
        attr: Attribute,
        /// Valeur attendue.
        #[serde(with = "crate::value_repr")]
        equals: Value,
    },
    /// Le sous-prédicat vaut pour chaque entité correspondant à `over`.
    ForAll {
        /// Entités liées une à une.
        over: EntityPattern,
        /// Prédicat évalué pour chaque entité liée.
        satisfies: Box<Predicate>,
    },
    /// Au moins une entité correspond au motif.
    Exists {
        /// Motif recherché.
        matching: EntityPattern,
    },
    /// La valeur la plus récente de `attr` date de moins de `than`.
    ///
    /// Si la valeur du fait est un entier, elle est interprétée comme une
    /// date (millisecondes d'époque, §15) ; sinon la fraîcheur est celle de
    /// la dernière observation.
    Fresher {
        /// Entités visées ; absent : comme pour `always`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entity: Option<EntityPattern>,
        /// Attribut visé.
        attr: Attribute,
        /// Durée lisible, ex. `"24h"` — voir [`parse_duration`].
        than: String,
    },
    /// Conjonction : toutes les branches doivent tenir.
    And(Vec<Predicate>),
    /// Disjonction : au moins une branche doit tenir.
    Or(Vec<Predicate>),
    /// Négation du prédicat interne.
    Not(Box<Predicate>),
}

/// Exception documentée, justifiée, datée. `expires` obligatoire par
/// conception : une exception permanente n'est pas une exception, c'est un
/// changement de politique non assumé (§5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    /// Entité couverte ; les jokers `*`/`?` sont admis, ex. `"user:svc-*"`.
    pub entity: String,
    /// Justification — obligatoire et non vide.
    pub reason: String,
    /// Approbateur — obligatoire et non vide.
    pub approved_by: String,
    /// Date d'expiration (« AAAA-MM-JJ », UTC). Une exception sans date
    /// d'expiration est un mensonge (§5.2) : refusée au parsing.
    pub expires: String,
}

impl Exception {
    /// Date d'expiration parsée (minuit UTC du jour indiqué).
    ///
    /// # Erreurs
    ///
    /// [`PolicyError::InvalidDate`] si `expires` est illisible — ne peut pas
    /// se produire pour une exception issue de [`parse_assertions`].
    pub fn expires_at(&self) -> Result<Timestamp, PolicyError> {
        dates::parse_date(&self.expires)
    }

    /// L'exception couvre-t-elle cette entité ? (correspondance glob)
    #[must_use]
    pub fn matches(&self, entity: &EntityId) -> bool {
        pattern::glob_match(&self.entity, &entity.0)
    }
}

/// Une assertion de conformité.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    /// Identifiant, ex. `SSH-ROOT`.
    pub id: AssertionId,
    /// Titre humain, ex. « la connexion root en SSH est désactivée ».
    pub title: String,
    /// Portée : quelles machines sont concernées.
    #[serde(default)]
    pub scope: AssetSelector,
    /// Le prédicat évalué.
    ///
    /// Représenté en YAML par une table à clé unique (`never:`, `forall:`,
    /// `and:`…), y compris pour les prédicats imbriqués — c'est la forme de
    /// la spécification (§5.2).
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub predicate: Predicate,
    /// Exceptions documentées, justifiées, datées.
    #[serde(default)]
    pub exceptions: Vec<Exception>,
}

/// Verdict : `Undetermined` est un verdict à part entière (§5.3) — la
/// couverture était insuffisante pour se prononcer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Conforme sur la période, avec la couverture indiquée.
    Pass,
    /// Au moins une violation constatée — chacune est expliquée.
    Fail,
    /// Couverture insuffisante pour se prononcer.
    Undetermined,
}

impl Verdict {
    /// Libellé français du verdict.
    #[must_use]
    pub fn label_fr(&self) -> &'static str {
        match self {
            Verdict::Pass => "CONFORME",
            Verdict::Fail => "NON CONFORME",
            Verdict::Undetermined => "INDÉTERMINÉ",
        }
    }
}

/// Violation constatée, avec renvoi vers la preuve brute.
///
/// Convention : pour un prédicat `never`, `expected` porte la **valeur
/// interdite** (l'attendu est « toute autre valeur ») ; le champ [`detail`]
/// l'explicite toujours en clair.
///
/// [`detail`]: Violation::detail
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Machine concernée.
    pub asset: AssetId,
    /// Entité concernée, ex. `user:jdupont`.
    pub entity: EntityId,
    /// Valeur observée ([`Value::Absent`] si le fait manquait).
    pub observed: Value,
    /// Valeur attendue (voir la convention ci-dessus pour `never`).
    pub expected: Value,
    /// Début de l'intervalle de constat.
    pub first_seen: Timestamp,
    /// Fin de l'intervalle de constat.
    pub last_seen: Timestamp,
    /// Vers l'artefact brut ([`NO_EVIDENCE`] quand le constat porte sur une
    /// absence : il n'existe alors aucun blob à citer).
    pub evidence: BlobHash,
    /// Le **pourquoi**, en français — toujours renseigné par le moteur.
    #[serde(default)]
    pub detail: String,
}

/// Exception appliquée : la violation est neutralisée mais reste tracée —
/// jamais passée sous silence (§5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedException {
    /// L'exception qui a joué.
    pub exception: Exception,
    /// La violation qu'elle neutralise.
    pub neutralized: Violation,
}

/// Résultat d'évaluation : un verdict accompagné de sa couverture, jamais un
/// simple booléen (§4.2, §5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    /// Assertion évaluée.
    pub assertion: AssertionId,
    /// Titre de l'assertion (repris pour les explications).
    #[serde(default)]
    pub title: String,
    /// Machine évaluée, si l'évaluation porte sur une machine unique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<AssetId>,
    /// Le verdict.
    pub verdict: Verdict,
    /// La couverture de la période — toujours déclarée.
    pub coverage: CoverageReport,
    /// Les violations restantes (non neutralisées), chacune expliquée.
    pub violations: Vec<Violation>,
    /// Les exceptions qui ont neutralisé des violations — tracées.
    #[serde(default)]
    pub applied_exceptions: Vec<AppliedException>,
}
