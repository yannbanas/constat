//! Collecteur `linux.packages` : paquets installés — **priorité haute (§7.3)**.
//! « Versions installées dans le temps, donc délai réel d'application des
//! correctifs » : chaque capture datée donne la version effective, et la
//! différence entre deux dates donne le délai d'application.
//!
//! ## Sources
//!
//! - **dpkg** : le fichier d'état `/var/lib/dpkg/status` est du texte pur,
//!   parsable sans exécuter de commande. C'est la source de vérité sur
//!   Debian/Ubuntu.
//! - **rpm** (et autres gestionnaires) : la base rpm est binaire (BerkeleyDB
//!   ou sqlite), pas parsable en pur sans dépendance lourde. À la place, un
//!   **format texte documenté** est accepté : un crochet post-transaction
//!   (ou un cron) écrit `/var/lib/constat/packages` :
//!
//! ```text
//! # liste de paquets constat, v1
//! # une ligne par paquet : <nom> <version> <statut>
//! openssl 3.0.13-1 installed
//! nginx 1.24.0-2 installed
//! ```
//!
//! La détection est automatique : un texte contenant des champs `Package:`
//! est traité comme un fichier d'état dpkg, sinon comme le format v1.
//!
//! ## Faits produits (entité `pkg:<nom>`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `pkg.version` | `Text` — version installée, ou `Absent` si le champ manque |
//! | `pkg.status` | `Text` — état dpkg normalisé (`installed`, `half-configured`, `half-installed`, `unpacked`, `config-files`, …), ou `Absent` |
//!
//! L'état est le **troisième mot** du champ dpkg `Status: <want> <flag> <status>`
//! (« install ok installed » → `installed`) : c'est lui qui distingue un paquet
//! réellement installé d'un paquet semi-configuré ou seulement dépaqueté.
//!
//! ## Collecte réelle (`#[cfg(unix)]`)
//!
//! Lit `/var/lib/dpkg/status` s'il existe, sinon `/var/lib/constat/packages`
//! (format v1). Aucune commande n'est exécutée.

use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::BTreeSet;

/// Chemin du fichier d'état dpkg.
pub const DPKG_STATUS_PATH: &str = "/var/lib/dpkg/status";

/// Chemin du fichier au format texte documenté (gestionnaires non-dpkg).
pub const PACKAGES_LIST_PATH: &str = "/var/lib/constat/packages";

/// Un paquet en cours d'assemblage pendant le parcours d'un fichier d'état.
#[derive(Default)]
struct PendingPackage {
    name: Option<String>,
    version: Option<String>,
    status: Option<String>,
}

/// Normalise un champ dpkg `Status: <want> <flag> <status>` : seul le
/// troisième mot (l'état réel) est un fait ; à défaut, le texte entier
/// est conservé tel quel plutôt qu'inventé.
fn normalize_dpkg_status(raw: &str) -> String {
    let mut words = raw.split_whitespace();
    match (words.next(), words.next(), words.next()) {
        (Some(_), Some(_), Some(status)) => status.to_string(),
        _ => raw.trim().to_string(),
    }
}

/// Pousse les faits d'un paquet complet ; « première occurrence gagnante »
/// pour un nom dupliqué (entrée hostile).
fn flush_package(pending: &mut PendingPackage, seen: &mut BTreeSet<String>, facts: &mut Vec<Fact>) {
    let taken = std::mem::take(pending);
    let Some(name) = taken.name else {
        return;
    };
    if name.is_empty() || !seen.insert(name.clone()) {
        return;
    }
    let entity = EntityId(format!("pkg:{name}"));
    facts.push(Fact {
        entity: entity.clone(),
        attribute: Attribute("pkg.version".to_string()),
        value: match taken.version {
            Some(v) if !v.is_empty() => Value::Text(v),
            _ => Value::Absent,
        },
    });
    facts.push(Fact {
        entity,
        attribute: Attribute("pkg.status".to_string()),
        value: match taken.status {
            Some(s) if !s.is_empty() => Value::Text(s),
            _ => Value::Absent,
        },
    });
}

/// Parse un fichier d'état dpkg : paragraphes séparés par des lignes vides,
/// champs `Clef: valeur`, lignes de continuation indentées (ignorées — la
/// description n'est pas un fait).
fn extract_dpkg_facts(text: &str) -> Vec<Fact> {
    let mut facts: Vec<Fact> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut pending = PendingPackage::default();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            flush_package(&mut pending, &mut seen, &mut facts);
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue; // continuation (description multi-lignes)
        }
        let Some((key, value)) = line.split_once(':') else {
            continue; // ligne malformée : ignorée, jamais de panique
        };
        let value = value.trim();
        if key.eq_ignore_ascii_case("Package") {
            // un nouveau « Package: » sans ligne vide : entrée hostile,
            // on clôt le paragraphe précédent plutôt que de mélanger
            if pending.name.is_some() {
                flush_package(&mut pending, &mut seen, &mut facts);
            }
            pending.name = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("Version") {
            pending.version = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("Status") {
            pending.status = Some(normalize_dpkg_status(value));
        }
    }
    flush_package(&mut pending, &mut seen, &mut facts);
    facts
}

/// Parse le format texte documenté v1 : `<nom> <version> <statut>` par ligne.
fn extract_list_facts(text: &str) -> Vec<Fact> {
    let mut facts: Vec<Fact> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(name), Some(version)) = (words.next(), words.next()) else {
            continue; // moins de deux mots : pas exploitable
        };
        let status = words.next();
        let mut pending = PendingPackage {
            name: Some(name.to_string()),
            version: Some(version.to_string()),
            status: status.map(str::to_string),
        };
        flush_package(&mut pending, &mut seen, &mut facts);
    }
    facts
}

/// Extracteur pur : texte (déjà expurgé) → faits. Détecte le format
/// (fichier d'état dpkg ou format v1), ignore les lignes malformées,
/// ne panique jamais.
pub fn extract_packages_facts(text: &str) -> Vec<Fact> {
    let is_dpkg = text.split('\n').any(|l| {
        l.strip_prefix("Package")
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    });
    let mut facts = if is_dpkg {
        extract_dpkg_facts(text)
    } else {
        extract_list_facts(text)
    };
    facts.sort();
    facts
}

/// Collecteur `linux.packages`.
#[derive(Debug, Clone)]
pub struct PackagesCollector {
    /// Racine des fichiers systèmes (paramétrable pour les tests ; `/` en production).
    pub root: std::path::PathBuf,
}

impl Default for PackagesCollector {
    fn default() -> Self {
        Self {
            root: std::path::PathBuf::from("/"),
        }
    }
}

impl Collector for PackagesCollector {
    fn id(&self) -> CollectorId {
        CollectorId("linux.packages".to_string())
    }

    /// Lit `/var/lib/dpkg/status` (Debian/Ubuntu), à défaut
    /// `/var/lib/constat/packages` (format texte documenté v1).
    #[cfg(unix)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        for rel in [DPKG_STATUS_PATH, PACKAGES_LIST_PATH] {
            let path = self.root.join(rel.trim_start_matches('/'));
            match std::fs::read(&path) {
                Ok(bytes) => return Ok(RawCapture(bytes)),
                Err(_) => continue,
            }
        }
        Err(CollectError::Unavailable(format!(
            "linux.packages : ni {DPKG_STATUS_PATH} ni {PACKAGES_LIST_PATH} n'est lisible"
        )))
    }

    #[cfg(not(unix))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "linux.packages : collecteur Linux, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        RedactedCapture(redact::redact_bytes(&raw.0))
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_packages_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(facts: &'a [Fact], entity: &str, attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.entity.0 == entity && f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {entity} {attr}"))
            .value
    }

    #[test]
    fn dpkg_installe_et_semi_configure() {
        let status = "Package: openssl\n\
                      Status: install ok installed\n\
                      Version: 3.0.13-1\n\
                      \n\
                      Package: casse\n\
                      Status: install ok half-configured\n\
                      Version: 2.0-1\n";
        let facts = extract_packages_facts(status);
        assert_eq!(
            value(&facts, "pkg:openssl", "pkg.version"),
            &Value::Text("3.0.13-1".to_string())
        );
        assert_eq!(
            value(&facts, "pkg:openssl", "pkg.status"),
            &Value::Text("installed".to_string())
        );
        assert_eq!(
            value(&facts, "pkg:casse", "pkg.status"),
            &Value::Text("half-configured".to_string())
        );
    }

    #[test]
    fn dpkg_champ_manquant_donne_absent() {
        let facts = extract_packages_facts("Package: sans-version\nStatus: install ok unpacked\n");
        assert_eq!(
            value(&facts, "pkg:sans-version", "pkg.version"),
            &Value::Absent
        );
        assert_eq!(
            value(&facts, "pkg:sans-version", "pkg.status"),
            &Value::Text("unpacked".to_string())
        );
    }

    #[test]
    fn dpkg_continuation_et_doublon_hostile() {
        let status = "Package: outil\n\
                      Version: 1.0\n\
                      Description: un outil\n\
                      \tavec une suite indentee Version: 9.9\n\
                      Package: outil\n\
                      Version: 6.6\n";
        let facts = extract_packages_facts(status);
        // première occurrence gagnante, la continuation n'est pas un champ
        assert_eq!(
            value(&facts, "pkg:outil", "pkg.version"),
            &Value::Text("1.0".to_string())
        );
    }

    #[test]
    fn format_v1_trois_colonnes() {
        let liste = "# liste de paquets constat, v1\n\
                     nginx 1.24.0-2 installed\n\
                     incomplet\n\
                     sans-statut 0.1\n";
        let facts = extract_packages_facts(liste);
        assert_eq!(
            value(&facts, "pkg:nginx", "pkg.version"),
            &Value::Text("1.24.0-2".to_string())
        );
        assert_eq!(
            value(&facts, "pkg:nginx", "pkg.status"),
            &Value::Text("installed".to_string())
        );
        assert_eq!(
            value(&facts, "pkg:sans-statut", "pkg.status"),
            &Value::Absent
        );
        assert!(!facts.iter().any(|f| f.entity.0 == "pkg:incomplet"));
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_packages_facts("Package:\n:\n\u{0}\nPackage: a\nPackage: b\n");
        let _ = extract_packages_facts("");
    }
}
