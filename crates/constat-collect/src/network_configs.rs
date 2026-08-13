//! Collecteur `network.configs` : configurations d'équipements réseau —
//! **priorité haute (§7.3), segmentation** : règles de filtrage, VLAN — c'est
//! ici que `Calque` se branche (§14, S7).
//!
//! ## Le modèle du répertoire de dépôt
//!
//! Les équipements réseau (pare-feu, routeurs, commutateurs) ne peuvent pas
//! héberger d'agent. Le modèle est celui de `backup.proof` : l'exploitant
//! **dépose** dans un répertoire — par sa sauvegarde de configurations
//! existante (rancid, oxidized), ou un simple script — **un fichier par
//! équipement**, contenant sa configuration brute telle qu'exportée
//! (FortiGate, Cisco IOS, nftables, XML OPNsense/pfSense…).
//!
//! | Plateforme | Répertoire de dépôt |
//! |---|---|
//! | Unix | [`NETWORK_CONFIGS_DIR_UNIX`] (`/var/lib/constat/network-configs/`) |
//! | Windows | [`NETWORK_CONFIGS_DIR_WINDOWS`] (`C:\ProgramData\constat\network-configs\`) |
//!
//! Contrairement aux collecteurs `linux.*` et `windows.*`, celui-ci existe
//! sur **les deux** plateformes : seul le répertoire par défaut dépend de la
//! plateforme (`#[cfg]` dans [`Default`]) ; la collecte elle-même est
//! portable. Répertoire absent ou vide → [`CollectError::Unavailable`] avec
//! le motif — jamais un blob vide.
//!
//! ## Le format de capture : un blob multi-documents
//!
//! Un seul blob par collecte (§3.3), découpé par les lignes marqueurs de
//! [`crate::capture`], une section par équipement :
//!
//! ```text
//! ### constat:fichier netdev:fw-dmz-01
//! config system global
//!     set hostname "fw-dmz-01"
//! end
//! ### constat:fichier netdev:rtr-agence-02
//! version 15.4
//! hostname rtr-agence-02
//! ```
//!
//! - **Délimiteur** : la ligne `### constat:fichier netdev:<nom>` — le
//!   préfixe complet est `capture::SECTION_PREFIX` (`### constat:fichier `)
//!   suivi de [`SECTION_NETDEV_PREFIX`] (`netdev:`) puis du nom. La jonction
//!   (constat-cli) re-découpe avec [`crate::capture::split_sections`] et
//!   retrouve chaque équipement par le préfixe `netdev:`.
//! - **Nom d'équipement** : le nom du fichier déposé, **sans extension**
//!   (`fw-dmz-01.conf` → `fw-dmz-01`), assaini ([`sanitize_device_name`]) :
//!   seuls `[A-Za-z0-9._-]` survivent, le reste devient `_` — le nom ne peut
//!   donc jamais contenir le délimiteur ni une fin de ligne.
//! - **Échappement** : aucun. Une configuration hostile qui contiendrait
//!   elle-même une ligne `### constat:fichier …` fragmente sa propre section
//!   (comportement documenté de [`crate::capture`]) : l'extraction de CET
//!   équipement se dégrade, rien ne fuit, les autres équipements sont
//!   intacts. Les vraies configurations d'équipements ne contiennent jamais
//!   cette ligne.
//! - **Ordre** : sections triées par nom d'équipement (puis nom de fichier) —
//!   le même dépôt produit toujours la même capture, donc la même empreinte.
//!
//! ## Expurgation (§7.2) — critique ici
//!
//! Les configurations réseau regorgent de secrets : `enable secret`,
//! communautés SNMP, PSK IPsec, valeurs `ENC`, balises `<password>`…
//! Chaque section passe par [`crate::redact::redact_network_config`]
//! (motifs FortiGate, Cisco IOS, XML, puis toute la liste de refus
//! générique). La structure des lignes survit : un auditeur voit
//! `snmp-server community [EXPURGÉ:communauté-snmp] RO` — jamais la valeur.
//!
//! ## Faits produits (entité `netdev:<nom>`)
//!
//! | Attribut | Valeur |
//! |---|---|
//! | `netdev.config_present` | `Bool(true)` — une configuration est déposée |
//! | `netdev.config_lines` | `Int` — nombre de lignes **après expurgation** |
//! | `netdev.format_hint` | `Text` — `"fortigate"`, `"cisco-ios"`, `"nftables"`, `"xml"` ou `"inconnu"` |
//!
//! `format_hint` est un **indice** obtenu par détection légère de motifs
//! ([`detect_format_hint`]) — utile pour trier, jamais une interprétation :
//! la vraie analyse des configurations appartient à `Calque`, via la
//! jonction. Le collecteur archive le brut (expurgé), rien de plus.

use crate::{capture, redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};
use std::collections::BTreeSet;

/// Identifiant du collecteur.
pub const COLLECTOR_ID: &str = "network.configs";

/// Répertoire de dépôt par défaut sur Unix.
pub const NETWORK_CONFIGS_DIR_UNIX: &str = "/var/lib/constat/network-configs";

/// Répertoire de dépôt par défaut sur Windows.
pub const NETWORK_CONFIGS_DIR_WINDOWS: &str = "C:\\ProgramData\\constat\\network-configs";

/// Préfixe des noms de section de la capture (suivi du nom d'équipement).
pub const SECTION_NETDEV_PREFIX: &str = "netdev:";

/// Indice de format : FortiGate.
pub const HINT_FORTIGATE: &str = "fortigate";
/// Indice de format : Cisco IOS.
pub const HINT_CISCO_IOS: &str = "cisco-ios";
/// Indice de format : nftables.
pub const HINT_NFTABLES: &str = "nftables";
/// Indice de format : document XML (OPNsense/pfSense…).
pub const HINT_XML: &str = "xml";
/// Indice de format : non reconnu.
pub const HINT_INCONNU: &str = "inconnu";

// ---------------------------------------------------------------------------
// Aides pures
// ---------------------------------------------------------------------------

/// Assainit un nom d'équipement (issu du nom de fichier sans extension) :
/// seuls les caractères `[A-Za-z0-9._-]` survivent, le reste devient `_` ;
/// un nom vide devient `equipement`. Le nom ne peut donc jamais contenir le
/// délimiteur de section ni une fin de ligne. Ne panique jamais.
pub fn sanitize_device_name(stem: &str) -> String {
    let cleaned: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "equipement".to_string()
    } else {
        cleaned
    }
}

/// Détection **légère** du format d'une configuration, par motifs. C'est un
/// indice (`netdev.format_hint`), pas une interprétation — la vraie analyse
/// appartient à `Calque`. Motifs, dans l'ordre :
///
/// - [`HINT_XML`] : la première ligne non vide commence par `<?xml` ;
/// - [`HINT_FORTIGATE`] : une ligne `config system global`, ou une première
///   ligne `#config-version=` ;
/// - [`HINT_CISCO_IOS`] : une ligne `version <n>.<n>` ET une ligne
///   `interface …` ;
/// - [`HINT_NFTABLES`] : une ligne `table inet|ip|ip6 …` ;
/// - [`HINT_INCONNU`] sinon.
pub fn detect_format_hint(text: &str) -> &'static str {
    if text
        .split('\n')
        .map(str::trim)
        .find(|l| !l.is_empty())
        .is_some_and(|l| l.starts_with("<?xml"))
    {
        return HINT_XML;
    }
    let mut fortigate = false;
    let mut cisco_version = false;
    let mut cisco_interface = false;
    let mut nftables = false;
    for raw in text.split('\n') {
        let line = raw.trim();
        if line == "config system global" || line.starts_with("#config-version=") {
            fortigate = true;
        }
        if let Some(rest) = line.strip_prefix("version ") {
            let mut parts = rest.split('.');
            let is_num = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
            if parts.next().is_some_and(is_num)
                && parts.next().is_some_and(is_num)
                && parts.next().is_none()
            {
                cisco_version = true;
            }
        }
        if line.starts_with("interface ") {
            cisco_interface = true;
        }
        if line.starts_with("table inet ")
            || line.starts_with("table ip ")
            || line.starts_with("table ip6 ")
        {
            nftables = true;
        }
    }
    if fortigate {
        HINT_FORTIGATE
    } else if cisco_version && cisco_interface {
        HINT_CISCO_IOS
    } else if nftables {
        HINT_NFTABLES
    } else {
        HINT_INCONNU
    }
}

/// Nombre de lignes d'un contenu (les fins de ligne sont des séparateurs :
/// l'éventuelle ligne vide finale n'est pas comptée). Jamais de panique.
fn count_lines(text: &str) -> i64 {
    let mut n = text.split('\n').count();
    if text.ends_with('\n') || text.is_empty() {
        n = n.saturating_sub(1);
    }
    n as i64
}

/// Assemble la capture multi-documents à partir de couples
/// `(nom d'équipement, contenu brut)` : noms assainis, sections triées par
/// nom (déterminisme des empreintes). Fonction pure, partagée entre la
/// collecte réelle et les tests.
pub fn build_network_capture(devices: &[(&str, &str)]) -> String {
    let mut sections: Vec<(String, &str)> = devices
        .iter()
        .map(|(name, content)| {
            (
                format!("{SECTION_NETDEV_PREFIX}{}", sanitize_device_name(name)),
                *content,
            )
        })
        .collect();
    sections.sort_by(|a, b| a.0.cmp(&b.0));
    let refs: Vec<(&str, &str)> = sections.iter().map(|(n, c)| (n.as_str(), *c)).collect();
    capture::join_sections(&refs)
}

/// Expurge une capture multi-documents : chaque section passe par
/// [`redact::redact_network_config`] ; le texte hors section (capture
/// malformée) est **supprimé** — dans le doute, rien ne sort (§7.2).
/// Ne panique jamais.
pub fn redact_network_configs_capture(text: &str) -> String {
    let sections = capture::split_sections(text);
    let redacted: Vec<(String, String)> = sections
        .into_iter()
        .map(|(name, content)| {
            // le nom de section vient d'un nom de fichier assaini ; sur une
            // capture hostile il passe quand même par la liste de refus
            let name = redact::redact_text(&name);
            (name, redact::redact_network_config(&content))
        })
        .collect();
    let refs: Vec<(&str, &str)> = redacted
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_str()))
        .collect();
    capture::join_sections(&refs)
}

/// Extracteur **pur** : capture multi-documents (déjà expurgée) → faits.
/// Une section `netdev:<nom>` produit l'entité `netdev:<nom>` ; les sections
/// sans préfixe `netdev:` sont ignorées ; en cas de doublon, première
/// occurrence gagnante. Jamais de panique.
pub fn extract_network_configs_facts(capture_text: &str) -> Vec<Fact> {
    let sections = capture::split_sections(capture_text);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut facts: Vec<Fact> = Vec::new();
    for (name, content) in &sections {
        let Some(device) = name.strip_prefix(SECTION_NETDEV_PREFIX) else {
            continue;
        };
        let device = device.trim();
        if device.is_empty() || !seen.insert(device.to_string()) {
            continue;
        }
        let entity = EntityId(format!("netdev:{device}"));
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("netdev.config_present".to_string()),
            value: Value::Bool(true),
        });
        facts.push(Fact {
            entity: entity.clone(),
            attribute: Attribute("netdev.config_lines".to_string()),
            value: Value::Int(count_lines(content)),
        });
        facts.push(Fact {
            entity,
            attribute: Attribute("netdev.format_hint".to_string()),
            value: Value::Text(detect_format_hint(content).to_string()),
        });
    }
    facts.sort();
    facts
}

// ---------------------------------------------------------------------------
// Le collecteur
// ---------------------------------------------------------------------------

/// Collecteur `network.configs`.
#[derive(Debug, Clone)]
pub struct NetworkConfigsCollector {
    /// Répertoire de dépôt (paramétrable pour les tests).
    pub dir: std::path::PathBuf,
}

impl Default for NetworkConfigsCollector {
    #[cfg(windows)]
    fn default() -> Self {
        Self {
            dir: std::path::PathBuf::from(NETWORK_CONFIGS_DIR_WINDOWS),
        }
    }

    #[cfg(not(windows))]
    fn default() -> Self {
        Self {
            dir: std::path::PathBuf::from(NETWORK_CONFIGS_DIR_UNIX),
        }
    }
}

impl Collector for NetworkConfigsCollector {
    fn id(&self) -> CollectorId {
        CollectorId(COLLECTOR_ID.to_string())
    }

    /// Lit le répertoire de dépôt (lecture seule) : un fichier par
    /// équipement, les sous-répertoires et fichiers cachés (`.`) sont
    /// ignorés. Répertoire absent, illisible ou vide :
    /// [`CollectError::Unavailable`] avec le motif — jamais un blob vide.
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let entries = std::fs::read_dir(&self.dir).map_err(|e| {
            CollectError::Unavailable(format!(
                "network.configs : répertoire de dépôt illisible ({} : {e})",
                self.dir.display()
            ))
        })?;
        // (nom d'équipement, nom de fichier, contenu) — tri final déterministe
        let mut files: Vec<(String, String, String)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            // suit les liens symboliques : le dépôt peut pointer ailleurs
            if !path.is_file() {
                continue;
            }
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if file_name.starts_with('.') {
                continue; // fichiers cachés / temporaires d'éditeurs
            }
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| file_name.clone());
            let bytes = std::fs::read(&path)
                .map_err(|e| CollectError::Io(format!("{} : {e}", path.display())))?;
            files.push((
                sanitize_device_name(&stem),
                file_name,
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
        if files.is_empty() {
            return Err(CollectError::Unavailable(format!(
                "network.configs : aucun fichier déposé dans {}",
                self.dir.display()
            )));
        }
        files.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        let devices: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, _, content)| (name.as_str(), content.as_str()))
            .collect();
        Ok(RawCapture(build_network_capture(&devices).into_bytes()))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        let text = String::from_utf8_lossy(&raw.0);
        RedactedCapture(redact_network_configs_capture(&text).into_bytes())
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_network_configs_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn value<'a>(facts: &'a [Fact], entity: &str, attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.entity.0 == entity && f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {entity} {attr}"))
            .value
    }

    /// Répertoire temporaire unique, peuplé de fichiers. Nettoyé par l'appelant.
    fn temp_deposit_dir(files: &[(&str, &str)]) -> std::path::PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "constat-netcfg-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("création du répertoire de test : {e}"));
        for (name, content) in files {
            std::fs::write(dir.join(name), content)
                .unwrap_or_else(|e| panic!("écriture de la fixture {name} : {e}"));
        }
        dir
    }

    #[test]
    fn indices_de_format() {
        assert_eq!(
            detect_format_hint("config system global\n    set hostname \"fw\"\nend\n"),
            HINT_FORTIGATE
        );
        assert_eq!(
            detect_format_hint("#config-version=FGT60F-7.0.5:opmode=0\nconfig firewall policy\n"),
            HINT_FORTIGATE
        );
        assert_eq!(
            detect_format_hint("version 15.4\nhostname rtr\ninterface GigabitEthernet0/0\n"),
            HINT_CISCO_IOS
        );
        assert_eq!(
            detect_format_hint("flush ruleset\ntable inet filtre {\n}\n"),
            HINT_NFTABLES
        );
        assert_eq!(
            detect_format_hint("<?xml version=\"1.0\"?>\n<opnsense></opnsense>\n"),
            HINT_XML
        );
        // `version 15.4` sans `interface` ne suffit pas : indice, pas pari
        assert_eq!(detect_format_hint("version 15.4\n"), HINT_INCONNU);
        assert_eq!(detect_format_hint(""), HINT_INCONNU);
        assert_eq!(detect_format_hint("du texte quelconque\n"), HINT_INCONNU);
    }

    #[test]
    fn noms_d_equipement_assainis() {
        assert_eq!(sanitize_device_name("fw-dmz-01"), "fw-dmz-01");
        assert_eq!(sanitize_device_name("fw dmz/01"), "fw_dmz_01");
        assert_eq!(sanitize_device_name("été\n"), "_t__");
        assert_eq!(sanitize_device_name(""), "equipement");
    }

    #[test]
    fn extraction_multi_documents() {
        let capture_text = build_network_capture(&[
            ("rtr-b", "version 15.4\ninterface Gi0/0\n"),
            ("fw-a", "config system global\nend\n"),
        ]);
        // ordre trié par nom, quel que soit l'ordre de dépôt
        let idx_a = capture_text
            .find("netdev:fw-a")
            .unwrap_or_else(|| panic!("section fw-a manquante"));
        let idx_b = capture_text
            .find("netdev:rtr-b")
            .unwrap_or_else(|| panic!("section rtr-b manquante"));
        assert!(idx_a < idx_b, "les sections doivent être triées par nom");

        let facts = extract_network_configs_facts(&capture_text);
        assert_eq!(facts.len(), 6);
        assert_eq!(
            value(&facts, "netdev:fw-a", "netdev.config_present"),
            &Value::Bool(true)
        );
        assert_eq!(
            value(&facts, "netdev:fw-a", "netdev.format_hint"),
            &Value::Text(HINT_FORTIGATE.to_string())
        );
        assert_eq!(
            value(&facts, "netdev:fw-a", "netdev.config_lines"),
            &Value::Int(2)
        );
        assert_eq!(
            value(&facts, "netdev:rtr-b", "netdev.format_hint"),
            &Value::Text(HINT_CISCO_IOS.to_string())
        );
    }

    #[test]
    fn doublon_premiere_occurrence_gagnante() {
        let capture_text = capture::join_sections(&[
            ("netdev:fw", "config system global\nend\n"),
            ("netdev:fw", "version 15.4\ninterface Gi0/0\n"),
        ]);
        let facts = extract_network_configs_facts(&capture_text);
        assert_eq!(facts.len(), 3);
        assert_eq!(
            value(&facts, "netdev:fw", "netdev.format_hint"),
            &Value::Text(HINT_FORTIGATE.to_string())
        );
    }

    #[test]
    fn collecte_reelle_ordre_deterministe_et_extensions_retirees() {
        let dir = temp_deposit_dir(&[
            ("rtr-agence-02.conf", "version 15.4\ninterface Gi0/0\n"),
            ("fw-dmz-01.conf", "config system global\nend\n"),
            (".fw-dmz-01.conf.swp", "brouillon d'éditeur : ignoré"),
        ]);
        let collector = NetworkConfigsCollector { dir: dir.clone() };
        let raw = collector
            .collect()
            .unwrap_or_else(|e| panic!("collecte en échec : {e}"));
        let text = String::from_utf8_lossy(&raw.0).into_owned();
        assert!(text.contains("### constat:fichier netdev:fw-dmz-01\n"));
        assert!(text.contains("### constat:fichier netdev:rtr-agence-02\n"));
        assert!(!text.contains("brouillon"));
        let facts = collector
            .extract(&collector.redact(raw))
            .unwrap_or_else(|e| panic!("extraction en échec : {e}"));
        assert_eq!(facts.len(), 6);
        assert_eq!(
            value(&facts, "netdev:fw-dmz-01", "netdev.config_present"),
            &Value::Bool(true)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repertoire_absent_est_unavailable() {
        let collector = NetworkConfigsCollector {
            dir: std::env::temp_dir().join("constat-netcfg-inexistant-abc123"),
        };
        match collector.collect() {
            Err(CollectError::Unavailable(motif)) => {
                assert!(motif.contains("network.configs"), "motif : {motif}");
            }
            autre => panic!("attendu Unavailable, obtenu {autre:?}"),
        }
    }

    #[test]
    fn repertoire_vide_est_unavailable_pas_un_blob_vide() {
        let dir = temp_deposit_dir(&[]);
        let collector = NetworkConfigsCollector { dir: dir.clone() };
        match collector.collect() {
            Err(CollectError::Unavailable(motif)) => {
                assert!(motif.contains("aucun fichier"), "motif : {motif}");
            }
            autre => panic!("attendu Unavailable, obtenu {autre:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_lines_compte_apres_expurgation() {
        let brut = build_network_capture(&[(
            "fw",
            "config system global\n    set admin-password SecretNu\nend\n",
        )]);
        let collector = NetworkConfigsCollector::default();
        let redacted = collector.redact(RawCapture(brut.into_bytes()));
        let facts = collector
            .extract(&redacted)
            .unwrap_or_else(|e| panic!("extraction en échec : {e}"));
        // l'expurgation conserve la structure : même nombre de lignes
        assert_eq!(
            value(&facts, "netdev:fw", "netdev.config_lines"),
            &Value::Int(3)
        );
        assert!(!String::from_utf8_lossy(&redacted.0).contains("SecretNu"));
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_network_configs_facts("");
        let _ = extract_network_configs_facts("### constat:fichier netdev:\n\u{0}\n[");
        let _ = redact_network_configs_capture("pas de section\n### constat:fichier x\n<a>");
        let _ = redact_network_configs_capture("");
    }
}
