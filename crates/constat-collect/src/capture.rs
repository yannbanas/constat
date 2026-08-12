//! Assemblage de plusieurs fichiers dans UNE capture (§3.3 : un blob par
//! collecteur). Certains collecteurs lisent plusieurs fichiers (`/etc/passwd`,
//! `/etc/group`, `/etc/shadow`) ; ils sont regroupés dans une capture texte
//! unique, découpée en sections par des lignes marqueurs lisibles par un
//! auditeur :
//!
//! ```text
//! ### constat:fichier /etc/passwd
//! root:x:0:0:root:/root:/bin/bash
//! ### constat:fichier /etc/group
//! root:x:0:
//! ```
//!
//! Le découpage ne panique jamais. Une entrée hostile peut au pire injecter
//! une fausse ligne marqueur dans son propre contenu — cela fragmente la
//! section, ce qui dégrade l'extraction mais ne fait rien fuir.

/// Préfixe des lignes marqueurs de section.
pub const SECTION_PREFIX: &str = "### constat:fichier ";

/// Assemble des sections nommées en une capture texte unique.
pub fn join_sections(sections: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (name, content) in sections {
        out.push_str(SECTION_PREFIX);
        out.push_str(name);
        out.push('\n');
        out.push_str(content);
        if !content.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// Découpe une capture en sections nommées, dans l'ordre d'apparition.
/// Le texte précédant le premier marqueur est ignoré (capture malformée :
/// on extrait ce qu'on peut, on ne panique jamais).
pub fn split_sections(text: &str) -> Vec<(String, String)> {
    let mut sections: Vec<(String, Vec<&str>)> = Vec::new();
    for line in text.split('\n') {
        if let Some(name) = line.strip_prefix(SECTION_PREFIX) {
            sections.push((name.trim().to_string(), Vec::new()));
        } else if let Some((_, lines)) = sections.last_mut() {
            lines.push(line);
        }
    }
    sections
        .into_iter()
        .map(|(name, lines)| (name, lines.join("\n")))
        .collect()
}

/// Retrouve la première section portant ce nom.
pub fn find_section<'a>(sections: &'a [(String, String)], name: &str) -> Option<&'a str> {
    sections
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, c)| c.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour() {
        let capture = join_sections(&[("/etc/passwd", "a:b\nc:d"), ("/etc/group", "g:h\n")]);
        let sections = split_sections(&capture);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].0, "/etc/passwd");
        assert_eq!(sections[0].1, "a:b\nc:d");
        assert_eq!(find_section(&sections, "/etc/group"), Some("g:h\n"));
    }

    #[test]
    fn texte_sans_marqueur() {
        assert!(split_sections("pas de marqueur\ndu tout").is_empty());
    }
}
