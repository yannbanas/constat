//! Gestion du fichier d'agents autorisés (`--allowed-agents`) : lister,
//! ajouter, retirer, révoquer — en **préservant** le fichier tel que
//! l'opérateur l'a écrit (commentaires, lignes vides, ordre).
//!
//! Le format est celui de [`crate::receive::AgentPolicy::from_allowlist_file`] :
//! une clé publique Ed25519 en hexadécimal (64 caractères) par ligne,
//! commentaires avec `#` (pleine ligne ou fin de ligne), lignes vides
//! ignorées. Le nom d'un agent vit donc dans le commentaire de fin de ligne :
//! `abc123… # serveur-fichiers-01`.
//!
//! **Ces clés sont des clés de GENÈSE** — des identités de journaux, stables
//! à travers les rotations (`constat-agent rotate-key`). Une rotation ne
//! demande donc **aucune** modification de ce fichier ; retirer une clé
//! révoque l'identité entière, clé courante comprise.
//!
//! [`revoke`] est un retrait **tracé** : la clé est retirée et une note
//! datée est ajoutée en commentaire — le fichier raconte lui-même qui a été
//! révoqué et quand, ce qui compte au moment d'investiguer une
//! compromission (voir `docs/cles.md`).
//!
//! Les fonctions de ce module sont pures (texte → texte) : le binaire lit
//! et écrit le fichier, les tests travaillent sur des chaînes.

/// Une ligne d'agent autorisé, telle que relue du fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLine {
    /// La clé publique de genèse, en hexadécimal minuscule (64 caractères).
    pub key_hex: String,
    /// Le nom lisible, s'il figure en commentaire de fin de ligne.
    pub name: Option<String>,
}

/// Erreurs d'édition du fichier d'agents autorisés.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum AgentsError {
    /// L'argument n'est pas une clé publique hexadécimale de 64 caractères.
    #[error("« {0} » n'est pas une clé publique hexadécimale de 64 caractères")]
    #[diagnostic(help(
        "la clé attendue est la clé publique Ed25519 de GENÈSE de l'agent \
         (32 octets, 64 caractères hexadécimaux — le contenu d'agent.pub \
         d'origine, ou l'`old_key` de la première rotation)"
    ))]
    BadKey(String),
    /// La clé figure déjà dans le fichier.
    #[error("la clé {0} figure déjà dans la liste")]
    AlreadyPresent(String),
    /// La clé ne figure pas dans le fichier.
    #[error("la clé {0} ne figure pas dans la liste")]
    NotFound(String),
    /// Une ligne existante du fichier n'est pas une clé valide.
    #[error("ligne {line} : « {text} » n'est pas une clé publique hexadécimale de 64 caractères")]
    BadLine { line: usize, text: String },
}

/// Normalise et valide une clé donnée en argument : hexadécimal de 64
/// caractères, ramené en minuscules.
pub fn normalize_key(input: &str) -> Result<String, AgentsError> {
    let key = input.trim().to_ascii_lowercase();
    if key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(key)
    } else {
        Err(AgentsError::BadKey(input.trim().to_string()))
    }
}

/// La partie « clé » d'une ligne (avant tout commentaire), ou `None` pour
/// une ligne vide ou de pur commentaire.
fn key_part(line: &str) -> Option<&str> {
    let text = line.split('#').next().unwrap_or_default().trim();
    (!text.is_empty()).then_some(text)
}

/// Relit les agents du fichier, dans l'ordre, avec leur nom éventuel
/// (le commentaire de fin de ligne).
pub fn list(text: &str) -> Result<Vec<AgentLine>, AgentsError> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let Some(key) = key_part(raw) else { continue };
        if normalize_key(key).is_err() {
            return Err(AgentsError::BadLine {
                line: index + 1,
                text: key.to_string(),
            });
        }
        let name = raw
            .split_once('#')
            .map(|(_, comment)| comment.trim().to_string())
            .filter(|comment| !comment.is_empty());
        out.push(AgentLine {
            key_hex: key.to_ascii_lowercase(),
            name,
        });
    }
    Ok(out)
}

/// Le texte contient-il la clé `key_hex` (déjà normalisée) ?
fn contains(text: &str, key_hex: &str) -> bool {
    text.lines()
        .filter_map(key_part)
        .any(|k| k.eq_ignore_ascii_case(key_hex))
}

/// S'assure que `text` se termine par un saut de ligne (sans en ajouter à
/// un texte vide), pour que les ajouts restent ligne à ligne.
fn ensure_trailing_newline(mut text: String) -> String {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// Ajoute la clé `key` (avec le nom optionnel en commentaire de fin de
/// ligne) à la fin du fichier. Tout le reste du fichier est préservé à
/// l'octet près.
pub fn add(text: &str, key: &str, name: Option<&str>) -> Result<String, AgentsError> {
    let key = normalize_key(key)?;
    if contains(text, &key) {
        return Err(AgentsError::AlreadyPresent(key));
    }
    let mut out = ensure_trailing_newline(text.to_string());
    match name {
        // Le nom vit dans le commentaire : la partie « clé » de la ligne
        // doit rester du pur hexadécimal pour le chargeur de l'allowlist.
        Some(name) => out.push_str(&format!("{key} # {}\n", name.replace(['\r', '\n'], " "))),
        None => out.push_str(&format!("{key}\n")),
    }
    Ok(out)
}

/// Retire la (les) ligne(s) portant la clé `key`. Les commentaires et
/// lignes vides — y compris les commentaires de pleine ligne qui
/// entourent la clé retirée — sont préservés.
pub fn remove(text: &str, key: &str) -> Result<String, AgentsError> {
    let key = normalize_key(key)?;
    if !contains(text, &key) {
        return Err(AgentsError::NotFound(key));
    }
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| key_part(line).is_none_or(|k| !k.eq_ignore_ascii_case(&key)))
        .collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

/// Révoque la clé `key` : la retire **et** ajoute une note datée en
/// commentaire — la révocation est tracée dans le fichier lui-même.
///
/// `date` est une date lisible fournie par l'appelant (l'horloge n'entre
/// pas dans ce module, qui reste pur et testable).
pub fn revoke(text: &str, key: &str, date: &str) -> Result<String, AgentsError> {
    let key = normalize_key(key)?;
    let mut out = remove(text, &key)?;
    out = ensure_trailing_newline(out);
    out.push_str(&format!(
        "# {date} : clé {key} RÉVOQUÉE — identité retirée (rotation comprise), \
         ne pas réadmettre sans décision explicite. Voir docs/cles.md.\n"
    ));
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn fichier() -> String {
        format!(
            "# Agents autorisés — identités de GENÈSE\n\
             \n\
             {KEY_A} # serveur-fichiers-01\n\
             # commentaire libre au milieu\n\
             {KEY_B}\n"
        )
    }

    /// `list` rend clés et noms, dans l'ordre du fichier.
    #[test]
    fn list_cles_et_noms() {
        let agents = list(&fichier()).unwrap();
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].key_hex, KEY_A);
        assert_eq!(agents[0].name.as_deref(), Some("serveur-fichiers-01"));
        assert_eq!(agents[1].key_hex, KEY_B);
        assert_eq!(agents[1].name, None);
    }

    /// `add` ajoute en fin de fichier sans toucher au reste ; le doublon est
    /// refusé ; la clé invalide est refusée.
    #[test]
    fn add_preserve_et_refuse_le_doublon() {
        let key_c = "c".repeat(64);
        let avant = fichier();
        let apres = add(&avant, &key_c, Some("nouveau")).unwrap();
        assert!(
            apres.starts_with(&avant),
            "le fichier existant est préservé"
        );
        assert!(apres.ends_with(&format!("{key_c} # nouveau\n")));
        assert!(matches!(
            add(&apres, &key_c, None),
            Err(AgentsError::AlreadyPresent(_))
        ));
        assert!(matches!(
            add(&avant, "pas-une-clé", None),
            Err(AgentsError::BadKey(_))
        ));
        // Le fichier édité reste chargeable par la politique du serveur.
        assert_eq!(list(&apres).unwrap().len(), 3);
    }

    /// `remove` retire la ligne visée et garde commentaires et lignes vides ;
    /// une clé absente est une erreur explicite.
    #[test]
    fn remove_garde_les_commentaires() {
        let apres = remove(&fichier(), KEY_A).unwrap();
        assert!(!apres.contains(KEY_A));
        assert!(apres.contains(KEY_B));
        assert!(apres.contains("# Agents autorisés — identités de GENÈSE"));
        assert!(apres.contains("# commentaire libre au milieu"));
        assert!(apres.contains('\n'), "les lignes vides restent des lignes");
        assert!(matches!(
            remove(&apres, KEY_A),
            Err(AgentsError::NotFound(_))
        ));
    }

    /// `revoke` = retrait + note datée en commentaire : la révocation est
    /// tracée dans le fichier, et le fichier reste chargeable.
    #[test]
    fn revoke_trace_la_revocation() {
        let apres = revoke(&fichier(), KEY_A, "2026-08-14").unwrap();
        assert!(!list(&apres)
            .unwrap()
            .iter()
            .any(|agent| agent.key_hex == KEY_A));
        assert!(apres.contains("2026-08-14"));
        assert!(apres.contains("RÉVOQUÉE"));
        // La note cite la clé (en commentaire : le chargeur l'ignore).
        assert!(apres.contains(KEY_A));
        assert_eq!(list(&apres).unwrap().len(), 1);
    }

    /// Les majuscules en entrée sont normalisées : le fichier écrit reste en
    /// minuscules, et le retrait retrouve une clé écrite en minuscules.
    #[test]
    fn normalisation_des_majuscules() {
        let upper = KEY_A.to_ascii_uppercase();
        let apres = remove(&fichier(), &upper).unwrap();
        assert!(!apres.contains(KEY_A));
        let ajout = add("", &upper, None).unwrap();
        assert_eq!(ajout, format!("{KEY_A}\n"));
    }
}
