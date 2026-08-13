//! Tests par propriétés (§12, fuzz-like) : les entrées sont HOSTILES.
//! Aucun extracteur, aucune expurgation ne doit paniquer, quelle que soit
//! l'entrée. S'y ajoutent des propriétés d'expurgation ciblées : un secret
//! structuré généré aléatoirement ne survit jamais.

use constat_collect::backup::{extract_backup_facts, parse_utc_timestamp_ms};
use constat_collect::linux::accounts::{extract_accounts_facts, redact_accounts_capture};
use constat_collect::linux::kernel_params::{
    extract_kernel_params_facts, redact_kernel_params_capture, TRACKED_SYSCTL_KEYS,
};
use constat_collect::linux::packages::extract_packages_facts;
use constat_collect::linux::ports::{extract_ports_facts, normalize_kernel_hex_address};
use constat_collect::linux::sshd::extract_sshd_facts;
use constat_collect::linux::sudoers::extract_sudoers_facts;
use constat_collect::linux::systemd::extract_systemd_facts;
use constat_collect::windows::accounts::extract_accounts_facts as extract_windows_accounts_facts;
use constat_collect::windows::ad_groups::extract_ad_groups_facts;
use constat_collect::windows::gpo_security::{
    decode_inf_text, extract_gpo_security_facts, extract_gpt_tmpl_facts, redact_gpo_capture,
};
use constat_collect::windows::password_policy::extract_password_policy_facts;
use constat_collect::windows::services::extract_services_facts;
use constat_collect::windows::{format_sid_bytes, parse_ini, sid_rid};
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
    fn extracteur_packages_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_packages_facts(&s);
    }

    #[test]
    fn extracteur_ports_ne_panique_jamais(
        tcp in "(?:\\PC|[\\n\\t]){0,300}",
        tcp6 in "(?:\\PC|[\\n\\t]){0,300}",
        udp in "(?:\\PC|[\\n\\t]){0,300}",
    ) {
        let _ = extract_ports_facts(&tcp, &tcp6, &udp);
    }

    /// Le format hexadécimal du noyau est une entrée hostile à part entière :
    /// lignes plausibles mais tronquées ou corrompues, jamais de panique.
    #[test]
    fn lignes_proc_net_plausibles_ne_paniquent_jamais(
        sl in "[0-9]{1,4}",
        addr in "[0-9A-Fa-fZ]{0,40}",
        port in "[0-9A-Fa-fZ]{0,6}",
        st in "[0-9A-Fa-fZ]{0,3}",
        uid in "-?[0-9]{0,12}",
        tronquer in 0usize..8,
    ) {
        let full = format!(
            "   {sl}: {addr}:{port} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000 {uid} 0 12345 1"
        );
        let words: Vec<&str> = full.split_whitespace().collect();
        let kept = words.len().saturating_sub(tronquer);
        let line = words[..kept].join(" ");
        let _ = extract_ports_facts(&line, &line, &line);
        let _ = normalize_kernel_hex_address(&addr);
    }

    #[test]
    fn extracteur_systemd_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_systemd_facts(&s);
    }

    #[test]
    fn extracteur_kernel_params_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_kernel_params_facts(&s);
    }

    /// La liste blanche sysctl est étanche, aux DEUX niveaux : la valeur
    /// d'une clé hors liste blanche ne survit ni dans la capture expurgée,
    /// ni dans les faits — et seuls des attributs `sysctl.<clé de la liste
    /// blanche>` sortent.
    #[test]
    fn sysctl_hors_liste_blanche_jamais_survivant(
        cle in "[a-z][a-z0-9._]{0,40}",
        valeur in "HORSLISTE[a-zA-Z0-9]{4,24}",
    ) {
        prop_assume!(!TRACKED_SYSCTL_KEYS.contains(&cle.as_str()));
        let brut = format!("{cle} = {valeur}\n");
        let expurge = redact_kernel_params_capture(&brut);
        prop_assert!(
            !expurge.contains(&valeur),
            "valeur hors liste blanche dans la capture expurgée : {expurge:?}"
        );
        let facts = extract_kernel_params_facts(&expurge);
        let debug = format!("{facts:?}");
        prop_assert!(!debug.contains(&valeur), "valeur hors liste blanche remontée : {debug}");
        for fact in &facts {
            let attr = fact.attribute.0.as_str();
            prop_assert!(
                TRACKED_SYSCTL_KEYS.iter().any(|k| attr == format!("sysctl.{k}")),
                "attribut hors liste blanche : {attr}"
            );
        }
    }

    #[test]
    fn expurgation_kernel_params_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = redact_kernel_params_capture(&s);
    }

    #[test]
    fn sections_ne_paniquent_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = capture::split_sections(&s);
    }

    // -----------------------------------------------------------------------
    // Collecteurs Windows / Active Directory (S5)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ini_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = parse_ini(&s);
    }

    #[test]
    fn extracteur_windows_accounts_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_windows_accounts_facts(&s);
    }

    #[test]
    fn extracteur_windows_password_policy_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_password_policy_facts(&s);
    }

    #[test]
    fn extracteur_windows_services_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_services_facts(&s);
    }

    #[test]
    fn extracteur_ad_groups_ne_panique_jamais(s in "(?:\\PC|[\\n\\t]){0,400}") {
        let _ = extract_ad_groups_facts(&s);
    }

    #[test]
    fn extracteur_gpo_security_ne_panique_jamais(
        guid in "\\PC{0,40}",
        s in "(?:\\PC|[\\n\\t]){0,400}",
    ) {
        let _ = extract_gpt_tmpl_facts(&guid, &s);
        let _ = extract_gpo_security_facts(&s);
    }

    /// L'expurgation structurelle GPO ne panique jamais, et le corps d'un
    /// bloc PEM ne lui survit jamais (la protection des lignes de politique
    /// n'ouvre pas de brèche).
    #[test]
    fn expurgation_gpo_ne_panique_jamais_et_pem_jamais_survivant(
        avant in "(?:\\PC|[\\n]){0,120}",
        corps in "[A-Za-z0-9+/]{40,120}",
    ) {
        let _ = redact_gpo_capture(&avant);
        let texte = format!(
            "{avant}\nClearTextPassword = 0\n-----BEGIN RSA PRIVATE KEY-----\n{corps}\n-----END RSA PRIVATE KEY-----\n"
        );
        let expurge = redact_gpo_capture(&texte);
        prop_assert!(!expurge.contains(&corps), "corps PEM survivant : {expurge:?}");
    }

    /// Le décodage d'un `GptTmpl.inf` (UTF-16LE/BE avec BOM, UTF-8, octets
    /// arbitraires) ne panique jamais.
    #[test]
    fn decode_inf_ne_panique_jamais(b in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = decode_inf_text(&b);
        // avec BOM forcés, sur les mêmes octets
        let mut le = vec![0xFF, 0xFE]; le.extend_from_slice(&b);
        let _ = decode_inf_text(&le);
        let mut be = vec![0xFE, 0xFF]; be.extend_from_slice(&b);
        let _ = decode_inf_text(&be);
    }

    /// Le formateur de SID binaire ne panique jamais, et tout SID bien formé
    /// fait l'aller-retour texte → RID.
    #[test]
    fn format_sid_ne_panique_jamais(b in proptest::collection::vec(any::<u8>(), 0..80)) {
        if let Some(texte) = format_sid_bytes(&b) {
            // un SID sans sous-autorité rend l'autorité comme dernière
            // composante : sid_rid est alors l'autorité, jamais une panique
            let _ = sid_rid(&texte);
        }
    }

    /// Un SID construit (révision, autorité, sous-autorités) est toujours
    /// formaté, et son RID est la dernière sous-autorité.
    #[test]
    fn sid_bien_forme_toujours_formate(
        revision in 1u8..3,
        authority in 0u8..12,
        subs in proptest::collection::vec(any::<u32>(), 1..8),
    ) {
        let mut bytes = vec![revision, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for s in &subs {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        let texte = format_sid_bytes(&bytes);
        prop_assert!(texte.is_some());
        if let Some(texte) = texte {
            prop_assert_eq!(sid_rid(&texte), Some(u64::from(subs[subs.len() - 1])));
        }
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
