//! # constat-report — le dossier de preuve (§10.2)
//!
//! Le produit est la preuve, pas la collecte (§18.8) : ce crate assemble le
//! document qu'on pose sur la table de l'auditeur. Contenu minimal, dans
//! l'ordre du dossier :
//!
//! 1. couverture : organisation, période, périmètre, date de génération ;
//! 2. inventaire des machines **attendues** face aux machines **observées**
//!    — l'écart est un constat en soi (§6.4) ;
//! 3. par exigence : l'assertion, le verdict, la couverture, les exceptions
//!    avec leur justification et leur expiration ;
//! 4. les interruptions de collecte, déclarées explicitement, jamais
//!    masquées (§4.2) ;
//! 5. annexe : les artefacts bruts, avec leurs empreintes ;
//! 6. bloc de preuve : racine de Merkle, signature, jeton d'horodatage, et
//!    la procédure de vérification par `constat-verify`.
//!
//! Le rendu ([`render_html`]) est un HTML autonome, imprimable (§9 : HTML
//! puis impression, pas de bibliothèque PDF). Il inclut **toujours** la
//! section « Ce que ce dossier ne prouve pas » (§6.4) : écrire les limites
//! dans le produit augmente la confiance au lieu de la diminuer.
//!
//! Les structures de ce module sont **remplies par l'appelant** (constat-cli)
//! à partir des évaluations de `constat-policy` et des couvertures de
//! `constat-time` ; elles n'utilisent que les types stables de
//! `constat-model`, aucun flottant (les ratios sont en pour-mille, §15).

use constat_model::{AssetId, BlobHash, DurationMs, Timestamp};
use serde::{Deserialize, Serialize};

mod render;
mod time_format;

pub use render::render_html;
pub use time_format::{format_duration, format_timestamp};

/// Erreurs du dossier de preuve.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("dossier invalide : {0}")]
    Invalid(String),
}

/// Page de couverture : qui, quoi, quand (§10.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cover {
    /// Organisation auditée.
    pub organization: String,
    /// Début de la période couverte (inclus).
    pub period_start: Timestamp,
    /// Fin de la période couverte (incluse).
    pub period_end: Timestamp,
    /// Périmètre, en clair (ex. « serveurs de production, site de Lyon »).
    pub scope: String,
    /// Date de génération du dossier.
    pub generated_at: Timestamp,
    /// Référentiel d'exigences, s'il y a lieu (ex. « RECYF v2 »).
    pub referential: Option<String>,
}

/// Inventaire attendu face à l'observé (§10.2.2). **L'écart est un constat
/// en soi** : une machine attendue jamais observée est un trou de preuve,
/// une machine observée non attendue est un défaut d'inventaire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    /// Machines que l'organisation déclare posséder dans le périmètre.
    pub expected: Vec<AssetId>,
    /// Machines effectivement observées par la collecte sur la période.
    pub observed: Vec<AssetId>,
}

impl Inventory {
    /// Machines attendues jamais observées : rien ne peut être prouvé à leur
    /// sujet (§6.4).
    pub fn missing(&self) -> Vec<&AssetId> {
        self.expected
            .iter()
            .filter(|a| !self.observed.contains(a))
            .collect()
    }

    /// Machines observées mais absentes de l'inventaire déclaré.
    pub fn unexpected(&self) -> Vec<&AssetId> {
        self.observed
            .iter()
            .filter(|a| !self.expected.contains(a))
            .collect()
    }
}

/// Verdict d'une exigence. `Undetermined` est un verdict à part entière :
/// la couverture était insuffisante pour se prononcer (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Conforme sur la période.
    Pass,
    /// Non conforme : au moins une violation constatée.
    Fail,
    /// Couverture insuffisante pour se prononcer.
    Undetermined,
}

impl Verdict {
    /// Libellé français du verdict.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Pass => "Conforme",
            Verdict::Fail => "Non conforme",
            Verdict::Undetermined => "Indéterminé",
        }
    }
}

/// Résumé de couverture d'une exigence (§4.2). Ratio en **pour-mille**
/// (992 = 99,2 %) : aucun flottant dans un dossier de preuve (§15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSummary {
    /// Part de la période réellement couverte, en pour-mille (0..=1000).
    pub observed_permille: u16,
    /// Écart maximal entre deux collectes sur la période.
    pub max_gap: DurationMs,
    /// Nombre d'interruptions déclarées touchant cette exigence.
    pub gap_count: u32,
}

/// Exception documentée, justifiée, datée (§5.2). Une exception sans date
/// d'expiration est un mensonge : le champ est obligatoire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionNote {
    /// Entité exemptée (ex. `"user:svc-sauvegarde"`).
    pub entity: String,
    /// Justification en clair.
    pub reason: String,
    /// Qui a approuvé l'exception.
    pub approved_by: String,
    /// Date d'expiration — obligatoire par conception.
    pub expires: Timestamp,
}

impl ExceptionNote {
    /// Une exception expirée à la date donnée n'excuse plus rien : elle est
    /// signalée comme telle dans le dossier.
    pub fn is_expired(&self, at: Timestamp) -> bool {
        self.expires.0 <= at.0
    }
}

/// Une exigence du référentiel : assertion, verdict, couverture, exceptions
/// (§10.2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementReport {
    /// Identifiant de l'assertion (ex. `"SSH-ROOT"`).
    pub assertion_id: String,
    /// Titre lisible de l'assertion.
    pub title: String,
    /// Exigence du référentiel couverte, s'il y a lieu (ex. « RECYF 4.2 »).
    pub requirement_ref: Option<String>,
    pub verdict: Verdict,
    pub coverage: CoverageSummary,
    /// Exceptions applicables — les expirées restent listées et marquées.
    pub exceptions: Vec<ExceptionNote>,
}

/// Interruption de collecte, déclarée explicitement (§10.2.4). Un trou non
/// déclaré est indistinguable d'un effacement malveillant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outage {
    pub asset: AssetId,
    pub from: Timestamp,
    pub to: Timestamp,
    /// Motif en clair (ex. « machine arrêtée, maintenance »).
    pub reason: String,
}

/// Référence d'artefact brut en annexe (§10.2.5) : l'auditeur peut demander
/// le blob et contrôler son empreinte avec `constat-verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub asset: AssetId,
    /// Collecteur d'origine (ex. `"linux.sshd"`).
    pub collector: String,
    /// Empreinte BLAKE3 du blob dans le magasin.
    pub blob: BlobHash,
    pub collected_at: Timestamp,
}

/// Verdict et couverture d'une assertion, tels que repris dans la table de
/// correspondance : le même verdict que la section des exigences, jamais
/// recalculé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionOutcome {
    /// Identifiant de l'assertion (ex. `"SSH-ROOT"`).
    pub assertion_id: String,
    /// Titre lisible de l'assertion.
    pub title: String,
    pub verdict: Verdict,
    pub coverage: CoverageSummary,
}

/// Verdict agrégé d'une exigence du référentiel. Distinct de [`Verdict`] :
/// une exigence sans aucune assertion mappée est **non couverte** — un état
/// déclaré, jamais passé sous silence, et jamais confondu avec « indéterminé
/// faute de couverture de collecte ».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementVerdict {
    /// Toutes les assertions qui la couvrent sont conformes.
    Pass,
    /// Au moins une assertion non conforme.
    Fail,
    /// Aucune non conforme, mais au moins une indéterminée.
    Undetermined,
    /// Aucune assertion ne couvre cette exigence : rien ne peut être affirmé.
    NotCovered,
}

impl RequirementVerdict {
    /// Libellé français du verdict agrégé.
    pub fn label(&self) -> &'static str {
        match self {
            RequirementVerdict::Pass => "Conforme",
            RequirementVerdict::Fail => "Non conforme",
            RequirementVerdict::Undetermined => "Indéterminé",
            RequirementVerdict::NotCovered => "Non couverte",
        }
    }
}

/// Une exigence du référentiel dans la table de correspondance : son
/// identifiant, son titre, et les assertions qui la couvrent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappedRequirement {
    /// Identifiant de l'exigence dans le référentiel (ex. `"EX-1"`).
    pub id: String,
    /// Titre de l'exigence, tel qu'énoncé par le référentiel.
    pub title: String,
    /// Les assertions mappées sur cette exigence, avec leur verdict — vide
    /// si l'exigence n'est couverte par aucune assertion.
    pub assertions: Vec<AssertionOutcome>,
}

impl MappedRequirement {
    /// Verdict agrégé : `Fail` si une assertion échoue, sinon `Undetermined`
    /// si une est indéterminée, sinon `Pass` — et `NotCovered` si aucune
    /// assertion n'est mappée.
    pub fn verdict(&self) -> RequirementVerdict {
        if self.assertions.is_empty() {
            return RequirementVerdict::NotCovered;
        }
        if self.assertions.iter().any(|a| a.verdict == Verdict::Fail) {
            return RequirementVerdict::Fail;
        }
        if self
            .assertions
            .iter()
            .any(|a| a.verdict == Verdict::Undetermined)
        {
            return RequirementVerdict::Undetermined;
        }
        RequirementVerdict::Pass
    }
}

/// Table de correspondance par référentiel (§10.2.3) : par exigence, les
/// assertions qui la couvrent et le verdict agrégé ; en annexe, les
/// assertions évaluées qu'aucune exigence ne référence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrespondenceTable {
    /// Identifiant du référentiel (ex. `"exemple"`).
    pub referential_id: String,
    /// Titre du référentiel.
    pub referential_title: String,
    /// Version du référentiel (ex. `"v1"`).
    pub referential_version: String,
    /// Les exigences, dans l'ordre du fichier de référentiel.
    pub requirements: Vec<MappedRequirement>,
    /// Annexe : assertions évaluées non rattachées à une exigence.
    pub unmapped_assertions: Vec<AssertionOutcome>,
    /// Avertissements de construction (ex. une exigence référence une
    /// assertion absente du fichier d'assertions) — listés, jamais tus.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Bloc de preuve (§10.2.6) : ce qui rend le dossier vérifiable sans Constat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBlock {
    /// Racine de Merkle : empreinte de la dernière entrée du journal.
    pub merkle_root: BlobHash,
    /// Signature Ed25519 de la dernière entrée (64 octets).
    pub root_signature: Vec<u8>,
    /// Clé publique Ed25519 du journal (32 octets) — celle que le tiers
    /// passe à `constat-verify` via `pubkey.bin`.
    pub public_key: Vec<u8>,
    /// Jeton d'horodatage RFC 3161 (DER), si la racine a été ancrée au
    /// niveau 3. Son absence est déclarée dans le dossier, pas masquée.
    pub timestamp_token: Option<Vec<u8>>,
    /// Nombre d'entrées du journal au moment de la génération.
    pub entry_count: u64,
}

/// Le dossier de preuve complet (§10.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDossier {
    pub cover: Cover,
    pub inventory: Inventory,
    pub requirements: Vec<RequirementReport>,
    /// Table de correspondance par référentiel, si un référentiel a été
    /// fourni (`constat pack --referential`). Champ optionnel et `default` :
    /// un dossier sérialisé avant son introduction se relit tel quel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correspondence: Option<CorrespondenceTable>,
    pub outages: Vec<Outage>,
    pub artifacts: Vec<ArtifactRef>,
    pub proof: ProofBlock,
}
