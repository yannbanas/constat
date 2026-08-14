//! Harnais de corpus (§12) : « captures réelles anonymisées + verdicts
//! attendus — attrape les erreurs de sémantique ».
//!
//! Chaque répertoire `corpus/<collecteur>/<cas>/` contient `capture.txt`
//! (l'artefact brut anonymisé) et `attendu.yaml` (les faits attendus, format
//! documenté dans `corpus/README.md`). Le harnais découvre TOUS les cas,
//! choisit l'extracteur d'après le premier segment du chemin, passe la
//! capture par le pipeline de production `redact` → `extract` du collecteur,
//! et compare fait à fait — dans les DEUX sens : un fait attendu manquant,
//! un fait produit non attendu ou une valeur différente cassent le test,
//! avec un diff lisible.
//!
//! Un répertoire de cas sans `attendu.yaml` est un échec : un cas sans
//! verdict attendu n'est pas un cas.

use constat_collect::linux::accounts::AccountsCollector;
use constat_collect::linux::kernel_params::KernelParamsCollector;
use constat_collect::linux::packages::PackagesCollector;
use constat_collect::linux::sshd::SshdCollector;
use constat_collect::{Collector, RawCapture};
use constat_model::{Fact, Value};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Le format d'attendu.yaml (documenté dans corpus/README.md)
// ---------------------------------------------------------------------------

/// Fichier `attendu.yaml` complet.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attendu {
    /// Doit correspondre au nom du répertoire de collecteur.
    collector: String,
    /// Doit correspondre au nom du répertoire de cas.
    case: String,
    facts: Vec<AttenduFact>,
}

/// Un fait attendu : triplet entité-attribut-valeur.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttenduFact {
    entity: String,
    attribute: String,
    value: AttenduValue,
}

/// Valeur attendue. Représentation YAML : un objet à UNE clef qui nomme le
/// type — `{ bool: true }`, `{ int: 22 }`, `{ text: "no" }`,
/// `{ list: [...] }` — et l'absence est une balise dédiée `{ absent: true }`,
/// jamais une chaîne : `Absent` et `Text("absent")` sont deux faits
/// différents et le format doit rendre la confusion impossible.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttenduValue {
    #[serde(rename = "bool")]
    bool_: Option<bool>,
    #[serde(rename = "int")]
    int_: Option<i64>,
    #[serde(rename = "text")]
    text_: Option<String>,
    #[serde(rename = "list")]
    list_: Option<Vec<AttenduValue>>,
    #[serde(rename = "absent")]
    absent_: Option<bool>,
}

impl AttenduValue {
    /// Convertit vers la valeur du modèle. Exactement UNE clef doit être
    /// présente, et `absent: false` n'a pas de sens : ce sont des erreurs
    /// de rédaction du corpus, signalées comme telles.
    fn to_value(&self) -> Result<Value, String> {
        let keys = usize::from(self.bool_.is_some())
            + usize::from(self.int_.is_some())
            + usize::from(self.text_.is_some())
            + usize::from(self.list_.is_some())
            + usize::from(self.absent_.is_some());
        if keys != 1 {
            return Err(format!(
                "une valeur attendue porte exactement UNE clef \
                 (bool, int, text, list ou absent), {keys} trouvée(s)"
            ));
        }
        if let Some(b) = self.bool_ {
            return Ok(Value::Bool(b));
        }
        if let Some(n) = self.int_ {
            return Ok(Value::Int(n));
        }
        if let Some(t) = &self.text_ {
            return Ok(Value::Text(t.clone()));
        }
        if let Some(items) = &self.list_ {
            return Ok(Value::List(
                items
                    .iter()
                    .map(AttenduValue::to_value)
                    .collect::<Result<Vec<_>, _>>()?,
            ));
        }
        match self.absent_ {
            Some(true) => Ok(Value::Absent),
            _ => Err("`absent: false` n'a pas de sens : \
                      pour une valeur présente, écrire son type"
                .to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Sélection du collecteur d'après le premier segment du chemin
// ---------------------------------------------------------------------------

fn collector_for(name: &str) -> Option<Box<dyn Collector>> {
    match name {
        "sshd" => Some(Box::new(SshdCollector::default())),
        "accounts" => Some(Box::new(AccountsCollector::default())),
        "packages" => Some(Box::new(PackagesCollector::default())),
        "kernel_params" => Some(Box::new(KernelParamsCollector::default())),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Exécution d'un cas
// ---------------------------------------------------------------------------

fn render(value: &Value) -> String {
    format!("{value:?}")
}

/// Exécute un cas : pipeline `redact` → `extract`, puis comparaison exacte
/// (dans les deux sens) avec l'attendu. Retourne la liste des divergences.
fn run_case(collector_name: &str, case_name: &str, dir: &Path) -> Result<(), String> {
    let capture_path = dir.join("capture.txt");
    let attendu_path = dir.join("attendu.yaml");
    if !attendu_path.is_file() {
        return Err(
            "attendu.yaml manquant : un cas sans verdict attendu n'est pas un cas".to_string(),
        );
    }
    if !capture_path.is_file() {
        return Err("capture.txt manquant".to_string());
    }

    let collector = collector_for(collector_name).ok_or_else(|| {
        format!(
            "aucun extracteur connu pour le répertoire `{collector_name}` \
             (attendus : sshd, accounts, packages, kernel_params)"
        )
    })?;

    let attendu_text = std::fs::read_to_string(&attendu_path)
        .map_err(|e| format!("lecture d'attendu.yaml : {e}"))?;
    let attendu: Attendu =
        serde_yaml::from_str(&attendu_text).map_err(|e| format!("attendu.yaml invalide : {e}"))?;
    if attendu.collector != collector_name {
        return Err(format!(
            "champ `collector: {}` incohérent avec le répertoire `{collector_name}`",
            attendu.collector
        ));
    }
    if attendu.case != case_name {
        return Err(format!(
            "champ `case: {}` incohérent avec le répertoire `{case_name}`",
            attendu.case
        ));
    }

    // Le pipeline de PRODUCTION : expurgation puis extraction. Le corpus est
    // déjà anonymisé/expurgé — l'expurgation doit être idempotente, et la
    // passer ici le prouve à chaque exécution.
    let raw = std::fs::read(&capture_path).map_err(|e| format!("lecture de capture.txt : {e}"))?;
    let redacted = collector.redact(RawCapture(raw));
    let produced: Vec<Fact> = collector
        .extract(&redacted)
        .map_err(|e| format!("extraction en échec : {e}"))?;

    // Indexation par (entité, attribut) — les doublons sont des erreurs.
    let mut expected: BTreeMap<(String, String), Value> = BTreeMap::new();
    for fact in &attendu.facts {
        let key = (fact.entity.clone(), fact.attribute.clone());
        let value = fact
            .value
            .to_value()
            .map_err(|e| format!("{} {} : {e}", fact.entity, fact.attribute))?;
        if expected.insert(key, value).is_some() {
            return Err(format!(
                "fait attendu en double : {} {}",
                fact.entity, fact.attribute
            ));
        }
    }
    let mut got: BTreeMap<(String, String), Value> = BTreeMap::new();
    for fact in produced {
        let key = (fact.entity.0.clone(), fact.attribute.0.clone());
        if got.insert(key, fact.value).is_some() {
            return Err(format!(
                "fait produit en double : {} {}",
                fact.entity.0, fact.attribute.0
            ));
        }
    }

    // Diff lisible, dans les deux sens.
    let mut diff = String::new();
    for ((entity, attribute), value) in &expected {
        match got.get(&(entity.clone(), attribute.clone())) {
            None => {
                let _ = writeln!(
                    diff,
                    "  fait MANQUANT     : {entity} {attribute} — attendu {}",
                    render(value)
                );
            }
            Some(produced) if produced != value => {
                let _ = writeln!(
                    diff,
                    "  VALEUR DIFFÉRENTE : {entity} {attribute} — attendu {}, produit {}",
                    render(value),
                    render(produced)
                );
            }
            Some(_) => {}
        }
    }
    for ((entity, attribute), value) in &got {
        if !expected.contains_key(&(entity.clone(), attribute.clone())) {
            let _ = writeln!(
                diff,
                "  fait INATTENDU    : {entity} {attribute} — produit {}",
                render(value)
            );
        }
    }

    if diff.is_empty() {
        Ok(())
    } else {
        Err(diff)
    }
}

// ---------------------------------------------------------------------------
// Découverte : TOUS les cas sous corpus/
// ---------------------------------------------------------------------------

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn subdirs(path: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn dir_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[test]
fn tous_les_cas_du_corpus_produisent_les_faits_attendus() {
    let root = corpus_root();
    assert!(
        root.is_dir(),
        "répertoire corpus/ introuvable : {}",
        root.display()
    );

    let mut executed = 0usize;
    let mut failures = String::new();
    for collector_dir in subdirs(&root) {
        let collector_name = dir_name(&collector_dir);
        let cases = subdirs(&collector_dir);
        assert!(
            !cases.is_empty(),
            "corpus/{collector_name} : aucun cas — un répertoire de collecteur sans cas n'a pas \
             de raison d'exister"
        );
        for case_dir in cases {
            let case_name = dir_name(&case_dir);
            executed += 1;
            if let Err(message) = run_case(&collector_name, &case_name, &case_dir) {
                let _ = writeln!(failures, "corpus/{collector_name}/{case_name} :");
                let _ = writeln!(failures, "{}", message.trim_end());
            }
        }
    }

    assert!(
        executed > 0,
        "aucun cas de corpus découvert sous {}",
        root.display()
    );
    assert!(
        failures.is_empty(),
        "\n{executed} cas exécutés, divergences :\n{failures}"
    );
}
