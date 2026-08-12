//! Collecteur `linux.kernel_params` : paramètres noyau (sysctl) pertinents en
//! conformité — durcissement réseau et mémoire (§7.3).
//!
//! ## Liste blanche, pas d'aspirateur
//!
//! Un dump sysctl complet contient des milliers de clés, dont certaines
//! peuvent porter des données sensibles (`kernel.core_pattern` avec des
//! arguments, plages d'uid, noms d'hôtes internes…). Ce collecteur ne remonte
//! que les clés d'une **liste blanche documentée** ([`TRACKED_SYSCTL_KEYS`]) :
//! celles que les référentiels de durcissement (CIS, ANSSI) demandent
//! toujours. Les clés hors liste blanche sont **ignorées** — pas de bruit,
//! pas de fuite — et ce à DEUX niveaux : l'expurgation supprime leurs lignes
//! de la capture ([`redact_kernel_params_capture`]), et l'extraction ne
//! produit de fait que pour la liste blanche.
//!
//! ## Le format d'entrée
//!
//! Un dump au format `clé = valeur`, une par ligne (le format de sortie de
//! `sysctl -a`, également accepté sans espaces : `clé=valeur`). Lignes vides,
//! commentaires `#` et lignes malformées : ignorés, jamais de panique.
//!
//! ## Faits produits (entité `host:kernel`)
//!
//! Un fait `sysctl.<clé>` par clé de la liste blanche, TOUJOURS :
//! `Int` si la valeur est un entier, `Text` sinon, et [`Value::Absent`] si la
//! clé manque dans le dump — l'absence est un fait (§3.2), pas un défaut
//! inventé.
//!
//! ## Collecte réelle (`#[cfg(unix)]`)
//!
//! Aucune commande n'est exécutée : chaque clé de la liste blanche est lue
//! directement dans `/proc/sys/<clé avec « . » → « / »>` (par exemple
//! `net.ipv4.ip_forward` → `/proc/sys/net/ipv4/ip_forward`). Une clé
//! illisible (module absent, IPv6 désactivé) est simplement omise du dump —
//! son fait sera `Absent`.

use crate::{redact, CollectError, Collector, RawCapture, RedactedCapture};
use constat_model::{Attribute, CollectorId, EntityId, Fact, Value};

/// Entité porteuse des faits sysctl.
const ENTITY: &str = "host:kernel";

/// La liste blanche : les paramètres noyau exigés par les référentiels de
/// durcissement. Chaque clé produit toujours un fait (`Absent` compris).
pub const TRACKED_SYSCTL_KEYS: &[&str] = &[
    // routage et anti-usurpation
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    // redirections ICMP (empoisonnement de route)
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    // protection SYN flood
    "net.ipv4.tcp_syncookies",
    // IPv6
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.all.disable_ipv6",
    // exposition d'informations noyau
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "kernel.sysrq",
    "kernel.yama.ptrace_scope",
    "kernel.unprivileged_bpf_disabled",
    // durcissement mémoire et exécution
    "kernel.randomize_va_space",
    "vm.mmap_min_addr",
    "fs.suid_dumpable",
    "fs.protected_symlinks",
    "fs.protected_hardlinks",
];

/// Expurgation **structurelle** d'un dump sysctl : seules les lignes
/// `clé = valeur` dont la clé est dans la liste blanche survivent (les
/// commentaires et tout le reste sont supprimés), puis la liste de refus
/// générique s'applique aux valeurs restantes. Défense en profondeur : la
/// collecte réelle ne lit déjà que la liste blanche, mais une capture
/// hostile plus large ne doit rien faire sortir de plus.
pub fn redact_kernel_params_capture(text: &str) -> String {
    let kept: Vec<&str> = text
        .split('\n')
        .filter(|line| {
            line.split_once('=')
                .is_some_and(|(key, _)| TRACKED_SYSCTL_KEYS.contains(&key.trim()))
        })
        .collect();
    redact::redact_text(&kept.join("\n"))
}

/// Extracteur pur : dump sysctl (déjà expurgé) → faits. Seules les clés de
/// la liste blanche produisent un fait ; première occurrence gagnante ;
/// jamais de panique.
pub fn extract_kernel_params_facts(text: &str) -> Vec<Fact> {
    let entity = EntityId(ENTITY.to_string());
    // indice dans la liste blanche → valeur observée
    let mut seen: Vec<(usize, String)> = Vec::new();
    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let Some(idx) = TRACKED_SYSCTL_KEYS.iter().position(|k| *k == key) else {
            continue; // hors liste blanche : ignoré, ni bruit ni fuite
        };
        if !seen.iter().any(|(i, _)| *i == idx) {
            seen.push((idx, value.trim().to_string()));
        }
    }

    let mut facts: Vec<Fact> = TRACKED_SYSCTL_KEYS
        .iter()
        .enumerate()
        .map(|(idx, key)| Fact {
            entity: entity.clone(),
            attribute: Attribute(format!("sysctl.{key}")),
            value: match seen.iter().find(|(i, _)| *i == idx) {
                None => Value::Absent,
                Some((_, raw)) => match raw.parse::<i64>() {
                    Ok(n) => Value::Int(n),
                    Err(_) => Value::Text(raw.clone()),
                },
            },
        })
        .collect();
    facts.sort();
    facts
}

/// Collecteur `linux.kernel_params`.
#[derive(Debug, Clone)]
pub struct KernelParamsCollector {
    /// Racine des fichiers systèmes (paramétrable pour les tests ; `/` en production).
    pub root: std::path::PathBuf,
}

impl Default for KernelParamsCollector {
    fn default() -> Self {
        Self {
            root: std::path::PathBuf::from("/"),
        }
    }
}

impl Collector for KernelParamsCollector {
    fn id(&self) -> CollectorId {
        CollectorId("linux.kernel_params".to_string())
    }

    /// Lit chaque clé de la liste blanche dans `/proc/sys/…` (jamais de
    /// commande) et assemble un dump `clé = valeur`.
    #[cfg(unix)]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        let mut dump = String::new();
        for key in TRACKED_SYSCTL_KEYS {
            let rel = format!("proc/sys/{}", key.replace('.', "/"));
            let Ok(raw) = std::fs::read_to_string(self.root.join(rel)) else {
                continue; // clé illisible : son fait sera Absent
            };
            // les valeurs multiples sont séparées par des tabulations :
            // normalisées en espaces simples pour rester sur une ligne
            let value = raw.split_whitespace().collect::<Vec<_>>().join(" ");
            dump.push_str(key);
            dump.push_str(" = ");
            dump.push_str(&value);
            dump.push('\n');
        }
        if dump.is_empty() {
            return Err(CollectError::Unavailable(
                "linux.kernel_params : /proc/sys illisible".to_string(),
            ));
        }
        Ok(RawCapture(dump.into_bytes()))
    }

    #[cfg(not(unix))]
    fn collect(&self) -> Result<RawCapture, CollectError> {
        Err(CollectError::Unavailable(
            "linux.kernel_params : collecteur Linux, plateforme non prise en charge".to_string(),
        ))
    }

    fn redact(&self, raw: RawCapture) -> RedactedCapture {
        let text = String::from_utf8_lossy(&raw.0);
        RedactedCapture(redact_kernel_params_capture(&text).into_bytes())
    }

    fn extract(&self, redacted: &RedactedCapture) -> Result<Vec<Fact>, CollectError> {
        let text = String::from_utf8_lossy(&redacted.0);
        Ok(extract_kernel_params_facts(&text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(facts: &'a [Fact], attr: &str) -> &'a Value {
        &facts
            .iter()
            .find(|f| f.attribute.0 == attr)
            .unwrap_or_else(|| panic!("fait manquant : {attr}"))
            .value
    }

    #[test]
    fn cle_de_la_liste_blanche_extraite_en_int() {
        let facts =
            extract_kernel_params_facts("net.ipv4.ip_forward = 0\nkernel.randomize_va_space=2\n");
        assert_eq!(value(&facts, "sysctl.net.ipv4.ip_forward"), &Value::Int(0));
        assert_eq!(
            value(&facts, "sysctl.kernel.randomize_va_space"),
            &Value::Int(2)
        );
    }

    #[test]
    fn cle_absente_donne_absent_jamais_un_defaut() {
        let facts = extract_kernel_params_facts("net.ipv4.ip_forward = 1\n");
        assert_eq!(value(&facts, "sysctl.kernel.kptr_restrict"), &Value::Absent);
        // et TOUTES les clés de la liste blanche ont un fait
        assert_eq!(facts.len(), TRACKED_SYSCTL_KEYS.len());
    }

    #[test]
    fn cle_hors_liste_blanche_ignoree() {
        let facts = extract_kernel_params_facts(
            "kernel.hostname = srv-interne-secret\nnet.core.somaxconn = 4096\n",
        );
        assert!(!facts.iter().any(|f| f.attribute.0.contains("hostname")));
        assert!(!facts.iter().any(|f| f.attribute.0.contains("somaxconn")));
        assert!(!format!("{facts:?}").contains("srv-interne-secret"));
    }

    #[test]
    fn valeur_non_entiere_conservee_en_text() {
        let facts = extract_kernel_params_facts("vm.mmap_min_addr = pas-un-nombre\n");
        assert_eq!(
            value(&facts, "sysctl.vm.mmap_min_addr"),
            &Value::Text("pas-un-nombre".to_string())
        );
    }

    #[test]
    fn premiere_occurrence_gagnante() {
        let facts =
            extract_kernel_params_facts("net.ipv4.ip_forward = 0\nnet.ipv4.ip_forward = 1\n");
        assert_eq!(value(&facts, "sysctl.net.ipv4.ip_forward"), &Value::Int(0));
    }

    #[test]
    fn entree_hostile_sans_panique() {
        let _ = extract_kernel_params_facts("");
        let _ = extract_kernel_params_facts("= = =\n\u{0}\n#\nnet.ipv4.ip_forward\n");
    }

    #[test]
    fn expurgation_structurelle_ne_garde_que_la_liste_blanche() {
        let expurge = redact_kernel_params_capture(
            "# commentaire\n\
             net.ipv4.ip_forward = 0\n\
             kernel.hostname = srv-interne-secret\n\
             texte libre sans egal\n\
             kernel.kptr_restrict=1\n",
        );
        assert!(expurge.contains("net.ipv4.ip_forward = 0"));
        assert!(expurge.contains("kernel.kptr_restrict=1"));
        assert!(!expurge.contains("srv-interne-secret"));
        assert!(!expurge.contains("commentaire"));
        assert!(!expurge.contains("texte libre"));
    }

    #[test]
    fn la_liste_blanche_fait_une_vingtaine_de_cles_sans_doublon() {
        assert!(TRACKED_SYSCTL_KEYS.len() >= 20);
        let mut dedup = TRACKED_SYSCTL_KEYS.to_vec();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(dedup.len(), TRACKED_SYSCTL_KEYS.len());
    }
}
