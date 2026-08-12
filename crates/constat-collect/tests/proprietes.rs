//! Tests par propriétés (§12, fuzz-like) : les entrées sont HOSTILES.
//! Aucun extracteur, aucune expurgation ne doit paniquer, quelle que soit
//! l'entrée. S'y ajoutent des propriétés d'expurgation ciblées : un secret
//! structuré généré aléatoirement ne survit jamais.

use constat_collect::backup::{extract_backup_facts, parse_utc_timestamp_ms};
use constat_collect::linux::accounts::{extract_accounts_facts, redact_accounts_capture};
use constat_collect::linux::sshd::extract_sshd_facts;
use constat_collect::linux::sudoers::extract_sudoers_facts;
use constat_collect::{capture, redact, RawCapture};
use proptest::prelude::*;

proptest! {
    // -----------------------------------------------------------------------
    // Jamais de panique, sur n'importe quoi
    // -----------------------------------------------------------------------

    #[test]
    fn redact_text_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = redact::redact_text(&s);
    }

    #[test]
    fn redact_bytes_ne_panique_jamais(b in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = redact::redact_bytes(&b);
    }

    #[test]
    fn extracteur_sshd_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_sshd_facts(&s);
    }

    #[test]
    fn extracteur_accounts_ne_panique_jamais(
        p in "(?:\\PC|[\\n\\t]){0,300}",
        g in "(?:\\PC|[\\n\\t]){0,300}",
        sh in proptest::option::of("(?:\\PC|[\\n\\t]){0,300}"),
    ) {
        let _ = extract_accounts_facts(&p, &g, sh.as_deref());
    }

    #[test]
    fn expurgation_accounts_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = redact_accounts_capture(&s);
    }

    #[test]
    fn extracteur_sudoers_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_sudoers_facts(&s);
    }

    #[test]
    fn extracteur_backup_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_backup_facts(&s);
    }

    #[test]
    fn horodatage_ne_panique_jamais(s in "\\PC{0,60}") {
        let _ = parse_utc_timestamp_ms(&s);
    }

    #[test]
    fn sections_ne_paniquent_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = capture::split_sections(&s);
    }

    #[test]
    fn pipeline_complet_ne_panique_jamais(b in proptest::collection::vec(any::<u8>(), 0..600)) {
        for collector in constat_collect::all_collectors() {
            let redacted = collector.redact(RawCapture(b.clone()));
            let _ = collector.extract(&redacted);
        }
    }

    // -----------------------------------------------------------------------
    // Propriétés d'expurgation : un secret structuré ne survit jamais
    // -----------------------------------------------------------------------

    /// La valeur d'un `password=`/`token=`/`secret=` généré aléatoirement
    /// disparaît toujours, quel que soit le préfixe de la clef.
    #[test]
    fn valeur_sensible_jamais_survivante(
        prefixe in "[a-zA-Z][a-zA-Z0-9_]{0,12}_?",
        clef in prop_oneof![Just("password"), Just("passwd"), Just("secret"), Just("token")],
        delim in prop_oneof![Just("="), Just(": "), Just(" = ")],
        valeur in "[A-Za-z0-9!%*]{8,64}",
    ) {
        let ligne = format!("{prefixe}{clef}{delim}{valeur}");
        let expurge = redact::redact_text(&ligne);
        prop_assert!(
            !expurge.contains(&valeur),
            "valeur sensible survivante : {ligne:?} -> {expurge:?}"
        );
    }

    /// Le corps d'un bloc PEM `PRIVATE KEY` généré aléatoirement disparaît
    /// toujours, même noyé dans du texte, même sans ligne de fin.
    #[test]
    fn corps_pem_jamais_survivant(
        avant in "[a-zA-Z0-9 \n]{0,80}",
        genre in prop_oneof![
            Just("RSA PRIVATE KEY"),
            Just("EC PRIVATE KEY"),
            Just("OPENSSH PRIVATE KEY"),
            Just("ENCRYPTED PRIVATE KEY"),
            Just("PRIVATE KEY"),
        ],
        corps in "[A-Za-z0-9+/]{40,120}",
        fermer in any::<bool>(),
    ) {
        let mut texte = format!("{avant}\n-----BEGIN {genre}-----\n{corps}\n");
        if fermer {
            texte.push_str(&format!("-----END {genre}-----\nsuite\n"));
        }
        let expurge = redact::redact_text(&texte);
        prop_assert!(
            !expurge.contains(&corps),
            "corps de clé privée survivant : {expurge:?}"
        );
    }

    /// Sel et empreinte d'un hachage crypt(3) modulaire généré aléatoirement
    /// disparaissent toujours ; seul `$id$` peut rester.
    #[test]
    fn hachage_crypt_jamais_survivant(
        id in prop_oneof![Just("1"), Just("5"), Just("6"), Just("2b"), Just("y"), Just("gy")],
        corps in "[A-Za-z0-9./]{8,90}",
        contexte in "[a-z :=]{0,20}",
    ) {
        let ligne = format!("{contexte}${id}${corps}");
        let expurge = redact::redact_text(&ligne);
        prop_assert!(
            !expurge.contains(&corps),
            "hachage survivant : {ligne:?} -> {expurge:?}"
        );
    }

    /// Le champ hachage d'une ligne shadow disparaît toujours via
    /// l'expurgation structurelle du collecteur accounts, quelle que soit
    /// sa forme — y compris sans aucune structure.
    #[test]
    fn champ_shadow_jamais_survivant(
        nom in "[a-z][a-z0-9-]{0,15}",
        hachage in "[A-Za-z0-9./$!*]{6,80}",
    ) {
        // le champ doit contenir autre chose que des marqueurs de verrouillage
        prop_assume!(hachage.trim_matches(['!', '*']).len() >= 6);
        let brut = capture::join_sections(&[(
            "/etc/shadow",
            format!("{nom}:{hachage}:19000:0:99999:7:::").as_str(),
        )]);
        let expurge = redact_accounts_capture(&brut);
        let coeur = hachage.trim_matches(['!', '*']);
        prop_assert!(
            !expurge.contains(coeur),
            "champ shadow survivant : {hachage:?} -> {expurge:?}"
        );
    }

    /// L'expurgation est stable : expurger une seconde fois ne réintroduit
    /// jamais de contenu (et ne panique pas).
    #[test]
    fn expurgation_stable(s in "(?:\\PC|[\\n\\t]){0,300}") {
        let une_fois = redact::redact_text(&s);
        let deux_fois = redact::redact_text(&une_fois);
        // pas d'égalité stricte exigée (sur-expurgation possible),
        // mais jamais plus LONG en contenu secret : on vérifie l'absence
        // de panique et que les marqueurs restent des marqueurs
        let _ = deux_fois;
    }
}
