//! Table de correspondance par référentiel (§10.2, point 3).
//!
//! Un référentiel mappe des **exigences** (RECYF, ISO 27001, politique
//! interne…) sur les **assertions** du fichier `assertions.yaml`. Le dossier
//! de preuve peut alors répondre dans la langue de l'auditeur : par exigence,
//! les assertions qui la couvrent, leur verdict, et le verdict agrégé.
//!
//! ## Format YAML documenté
//!
//! ```yaml
//! referential:
//!   id: exemple            # identifiant court, stable
//!   title: Référentiel d'hygiène — exemple
//!   version: v1
//! requirements:
//!   - id: EX-1
//!     title: L'accès administrateur à distance est maîtrisé
//!     assertions: [SSH-ROOT]
//!   - id: EX-2
//!     title: Les comptes privilégiés exigent une authentification forte
//!     assertions: [ADM-MFA]
//! ```
//!
//! ## Résolution de `--referential <fichier-ou-nom>`
//!
//! 1. si l'argument est un chemin de fichier existant, il est chargé tel
//!    quel ;
//! 2. sinon, `referentials/<nom>.yaml` relatif au répertoire courant.
//!
//! ## Construction de la table
//!
//! Les verdicts viennent de l'évaluation existante (`constat check`), jamais
//! recalculés ici. Une exigence qui référence une assertion absente du
//! fichier d'assertions produit un **avertissement listé** (dans la table et
//! sur la sortie), pas une erreur : le référentiel peut être plus large que
//! la collecte du trimestre — mais l'écart est déclaré, jamais tu.

use std::path::{Path, PathBuf};

use constat_report::{AssertionOutcome, CorrespondenceTable, MappedRequirement};
use miette::miette;
use serde::Deserialize;

/// Le fichier de référentiel, tel que désérialisé.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferentialFile {
    /// Identité du référentiel.
    pub referential: ReferentialMeta,
    /// Les exigences, dans l'ordre du document.
    #[serde(default)]
    pub requirements: Vec<RequirementSpec>,
}

/// Identité du référentiel : id, titre, version.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferentialMeta {
    /// Identifiant court et stable (ex. `"recyf"`).
    pub id: String,
    /// Titre lisible.
    pub title: String,
    /// Version du référentiel (ex. `"v2"`).
    pub version: String,
}

/// Une exigence du référentiel et les assertions censées la couvrir.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementSpec {
    /// Identifiant de l'exigence dans le référentiel (ex. `"4.2"`).
    pub id: String,
    /// Titre de l'exigence, tel qu'énoncé par le référentiel.
    pub title: String,
    /// Identifiants d'assertions (`assertions.yaml`) couvrant l'exigence —
    /// vide : l'exigence sera déclarée **non couverte** dans le dossier.
    #[serde(default)]
    pub assertions: Vec<String>,
}

/// Analyse et valide un référentiel YAML (erreurs lisibles, champs stricts).
pub fn parse(text: &str) -> miette::Result<ReferentialFile> {
    let file: ReferentialFile = serde_yaml::from_str(text).map_err(|e| {
        miette!(
            help = "format attendu : referential: { id, title, version } puis \
                    requirements: [{ id, title, assertions: [SSH-ROOT, …] }, …] \
                    (voir referentials/exemple.yaml)",
            "référentiel illisible : {e}"
        )
    })?;
    if file.referential.id.trim().is_empty() {
        return Err(miette!("référentiel invalide : `referential.id` est vide"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for req in &file.requirements {
        if req.id.trim().is_empty() {
            return Err(miette!(
                "référentiel invalide : une exigence sans `id` (titre : « {} »)",
                req.title
            ));
        }
        if !seen.insert(req.id.as_str()) {
            return Err(miette!(
                "référentiel invalide : l'identifiant d'exigence « {} » apparaît deux fois",
                req.id
            ));
        }
    }
    Ok(file)
}

/// Résout `--referential <fichier-ou-nom>` par rapport à `base` :
/// le chemin tel quel s'il existe, sinon `referentials/<nom>.yaml`.
pub fn resolve(spec: &str, base: &Path) -> miette::Result<PathBuf> {
    // `Path::join` sur un chemin absolu renvoie ce chemin absolu : les deux
    // formes (chemin complet, nom court) passent par la même ligne.
    let direct = base.join(spec);
    if direct.is_file() {
        return Ok(direct);
    }
    let named = base.join("referentials").join(format!("{spec}.yaml"));
    if named.is_file() {
        return Ok(named);
    }
    Err(miette!(
        help = "indiquez un chemin de fichier YAML, ou le nom d'un référentiel \
                présent dans ./referentials/<nom>.yaml",
        "référentiel « {spec} » introuvable : ni {} ni {}",
        direct.display(),
        named.display()
    ))
}

/// Charge un référentiel depuis un chemin **ou** un nom (voir [`resolve`]),
/// relatif au répertoire courant.
pub fn load(spec: &str) -> miette::Result<ReferentialFile> {
    let path = resolve(spec, Path::new("."))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| miette!("impossible de lire le référentiel {} : {e}", path.display()))?;
    parse(&text).map_err(|e| miette!("dans {} : {e}", path.display()))
}

/// Construit la table de correspondance à partir du référentiel et des
/// verdicts déjà évalués (`outcomes` : une entrée par assertion du fichier
/// d'assertions, verdicts de l'évaluation existante).
///
/// - une assertion référencée mais absente d'`outcomes` produit un
///   **avertissement listé** dans la table, jamais un échec ;
/// - une exigence sans assertion résolue reste dans la table, déclarée non
///   couverte au rendu ;
/// - les assertions d'`outcomes` qu'aucune exigence ne référence sont
///   reportées en annexe (`unmapped_assertions`).
pub fn build_table(file: &ReferentialFile, outcomes: &[AssertionOutcome]) -> CorrespondenceTable {
    let mut warnings = Vec::new();
    let mut referenced = std::collections::BTreeSet::new();
    let mut requirements = Vec::with_capacity(file.requirements.len());

    for req in &file.requirements {
        let mut mapped = Vec::with_capacity(req.assertions.len());
        for id in &req.assertions {
            referenced.insert(id.clone());
            match outcomes.iter().find(|o| &o.assertion_id == id) {
                Some(outcome) => mapped.push(outcome.clone()),
                None => warnings.push(format!(
                    "l'exigence {} référence une assertion inconnue du fichier \
                     d'assertions : {id}",
                    req.id
                )),
            }
        }
        requirements.push(MappedRequirement {
            id: req.id.clone(),
            title: req.title.clone(),
            assertions: mapped,
        });
    }

    let unmapped_assertions = outcomes
        .iter()
        .filter(|o| !referenced.contains(&o.assertion_id))
        .cloned()
        .collect();

    CorrespondenceTable {
        referential_id: file.referential.id.clone(),
        referential_title: file.referential.title.clone(),
        referential_version: file.referential.version.clone(),
        requirements,
        unmapped_assertions,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use constat_model::DurationMs;
    use constat_report::{CoverageSummary, RequirementVerdict, Verdict};

    const EXEMPLE: &str = "\
referential:
  id: exemple
  title: Référentiel d'essai
  version: v1
requirements:
  - id: EX-1
    title: accès administrateur maîtrisé
    assertions: [SSH-ROOT, ADM-MFA]
  - id: EX-2
    title: sauvegarde prouvée
    assertions: [BKP-24H]
  - id: EX-3
    title: journalisation centralisée
";

    fn outcome(id: &str, verdict: Verdict) -> AssertionOutcome {
        AssertionOutcome {
            assertion_id: id.to_string(),
            title: format!("titre de {id}"),
            verdict,
            coverage: CoverageSummary {
                observed_permille: 990,
                max_gap: DurationMs(3_600_000),
                gap_count: 1,
            },
        }
    }

    #[test]
    fn parse_valide_et_erreurs_lisibles() {
        let file = parse(EXEMPLE).unwrap();
        assert_eq!(file.referential.id, "exemple");
        assert_eq!(file.requirements.len(), 3);
        assert_eq!(file.requirements[0].assertions, ["SSH-ROOT", "ADM-MFA"]);
        assert!(file.requirements[2].assertions.is_empty());

        // YAML invalide : le message reste en français, avec l'aide au format.
        let err = parse("pas: un: référentiel").unwrap_err();
        assert!(err.to_string().contains("illisible"), "erreur : {err}");

        // Champ inconnu : refusé (deny_unknown_fields), pas ignoré en silence.
        assert!(parse("referential: { id: a, title: b, version: c }\nextra: 1").is_err());

        // Identifiant d'exigence en double : refusé.
        let double = "\
referential: { id: a, title: b, version: c }
requirements:
  - { id: R1, title: t1 }
  - { id: R1, title: t2 }
";
        let err = parse(double).unwrap_err();
        assert!(err.to_string().contains("deux fois"), "erreur : {err}");
    }

    /// Le référentiel d'exemple livré à la racine du dépôt reste valide :
    /// c'est la documentation exécutable du format.
    #[test]
    fn l_exemple_livre_est_valide() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../referentials/exemple.yaml");
        let text = std::fs::read_to_string(&path).expect("referentials/exemple.yaml lisible");
        let file = parse(&text).expect("l'exemple livré doit parser");
        assert_eq!(file.referential.id, "exemple");
        assert_eq!(file.requirements.len(), 3);
        let ids: Vec<&str> = file
            .requirements
            .iter()
            .flat_map(|r| r.assertions.iter().map(String::as_str))
            .collect();
        assert_eq!(ids, ["SSH-ROOT", "ADM-MFA", "BKP-24H"]);
    }

    #[test]
    fn resolution_chemin_puis_nom() {
        let base = std::env::temp_dir().join(format!(
            "constat-referential-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(base.join("referentials")).unwrap();
        std::fs::write(base.join("referentials/exemple.yaml"), EXEMPLE).unwrap();
        std::fs::write(base.join("ailleurs.yaml"), EXEMPLE).unwrap();

        // 1. chemin de fichier existant, tel quel.
        assert_eq!(
            resolve("ailleurs.yaml", &base).unwrap(),
            base.join("ailleurs.yaml")
        );
        // 2. nom court → referentials/<nom>.yaml.
        assert_eq!(
            resolve("exemple", &base).unwrap(),
            base.join("referentials").join("exemple.yaml")
        );
        // 3. introuvable : l'erreur cite les deux emplacements essayés.
        let err = resolve("absent", &base).unwrap_err().to_string();
        assert!(err.contains("introuvable"), "erreur : {err}");
        assert!(err.contains("absent.yaml"), "erreur : {err}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn table_verdicts_agreges_annexe_et_avertissements() {
        let file = parse(EXEMPLE).unwrap();
        let outcomes = vec![
            outcome("SSH-ROOT", Verdict::Pass),
            outcome("ADM-MFA", Verdict::Fail),
            outcome("HORS-REF", Verdict::Undetermined),
        ];
        let table = build_table(&file, &outcomes);

        assert_eq!(table.referential_id, "exemple");
        assert_eq!(table.requirements.len(), 3);

        // EX-1 : Pass + Fail → Fail (une assertion en échec suffit).
        assert_eq!(table.requirements[0].verdict(), RequirementVerdict::Fail);
        assert_eq!(table.requirements[0].assertions.len(), 2);

        // EX-2 : BKP-24H est inconnue → avertissement listé, pas un crash,
        // et l'exigence reste non couverte.
        assert_eq!(
            table.requirements[1].verdict(),
            RequirementVerdict::NotCovered
        );
        assert_eq!(table.warnings.len(), 1);
        assert!(table.warnings[0].contains("EX-2"), "{:?}", table.warnings);
        assert!(
            table.warnings[0].contains("BKP-24H"),
            "{:?}",
            table.warnings
        );

        // EX-3 : aucune assertion mappée → non couverte, déclarée.
        assert_eq!(
            table.requirements[2].verdict(),
            RequirementVerdict::NotCovered
        );

        // Annexe : HORS-REF n'est référencée par aucune exigence.
        assert_eq!(table.unmapped_assertions.len(), 1);
        assert_eq!(table.unmapped_assertions[0].assertion_id, "HORS-REF");
    }
}
