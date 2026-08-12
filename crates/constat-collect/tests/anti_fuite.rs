//! # LE test anti-fuite (§12) — la faute impardonnable.
//!
//! Un corpus de secrets connus (clés PEM factices, lignes shadow, mots de
//! passe en clair, jetons, base64 sensibles) est injecté dans une capture
//! hostile pour CHAQUE collecteur. Après le pipeline de production
//! (`redact` puis `extract`), **aucun motif de secret ne doit apparaître** :
//! ni dans la [`RedactedCapture`], ni dans les faits extraits.
//!
//! Chaque secret du corpus porte un marqueur unique (`FUITE<nn>`) : si ce
//! marqueur survit quelque part, le test désigne exactement quel secret a
//! fui et par où.

use constat_collect::backup::BackupProofCollector;
use constat_collect::linux::accounts::{
    AccountsCollector, SECTION_GROUP, SECTION_PASSWD, SECTION_SHADOW,
};
use constat_collect::linux::kernel_params::KernelParamsCollector;
use constat_collect::linux::packages::PackagesCollector;
use constat_collect::linux::ports::{PortsCollector, SECTION_TCP, SECTION_UDP};
use constat_collect::linux::sshd::SshdCollector;
use constat_collect::linux::sudoers::SudoersCollector;
use constat_collect::linux::systemd::{SystemdCollector, SECTION_UNIT_FILES};
use constat_collect::{capture, Collector, RawCapture};

// ---------------------------------------------------------------------------
// Le corpus de secrets. Tous factices, tous uniques, tous traçables.
// ---------------------------------------------------------------------------

/// Corps d'une fausse clé privée RSA (PEM).
const SECRET_PEM_RSA: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAFUITE01";
/// Corps d'une fausse clé privée OpenSSH.
const SECRET_PEM_OPENSSH: &str = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZUFUITE02";
/// Corps d'une fausse clé privée EC, BEGIN/END génériques (PKCS#8).
const SECRET_PEM_EC: &str = "MHcCAQEEIFuiteEc0000000000000000000000000000FUITE03";
/// Sel et empreinte SHA-512 factices (format shadow `$6$`).
const SECRET_SHADOW_SHA512_SALT: &str = "SelFuite04";
const SECRET_SHADOW_SHA512_HASH: &str = "EmpreinteFuite04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Sel et empreinte yescrypt factices (`$y$`).
const SECRET_SHADOW_YESCRYPT: &str = "SelFuite05$EmpreinteFuite05aaaaaaaaaaaaaaa";
/// Empreinte bcrypt factice (`$2b$`).
const SECRET_SHADOW_BCRYPT: &str = "SelFuite06EmpreinteFuite06aaaaaaaaaaaaaaaaaaaa";
/// Hachage DES historique factice (13 caractères, sans structure).
const SECRET_SHADOW_DES: &str = "abFuite07yWIx";
/// Mots de passe en clair.
const SECRET_PASSWORD_1: &str = "MotDePasseFuite08!";
const SECRET_PASSWORD_2: &str = "S3cretFuite09";
/// Jeton d'authentification.
const SECRET_TOKEN: &str = "ghp_Fuite10Fuite10Fuite10Fuite10abcd";
/// Longue chaîne base64 (fausse clé symétrique) en contexte sensible.
const SECRET_BASE64: &str = "ZmF1c3NlY2xlZkZ1aXRlMTFmYXVzc2VjbGVmRnVpdGUxMQ==";

/// Les motifs qui ne doivent JAMAIS survivre à l'expurgation.
fn secret_markers() -> Vec<(&'static str, String)> {
    vec![
        ("pem-rsa", SECRET_PEM_RSA.to_string()),
        ("pem-openssh", SECRET_PEM_OPENSSH.to_string()),
        ("pem-ec", SECRET_PEM_EC.to_string()),
        ("shadow-sha512-sel", SECRET_SHADOW_SHA512_SALT.to_string()),
        (
            "shadow-sha512-empreinte",
            SECRET_SHADOW_SHA512_HASH.to_string(),
        ),
        ("shadow-yescrypt", SECRET_SHADOW_YESCRYPT.to_string()),
        ("shadow-bcrypt", SECRET_SHADOW_BCRYPT.to_string()),
        ("shadow-des", SECRET_SHADOW_DES.to_string()),
        ("mot-de-passe-1", SECRET_PASSWORD_1.to_string()),
        ("mot-de-passe-2", SECRET_PASSWORD_2.to_string()),
        ("jeton", SECRET_TOKEN.to_string()),
        ("base64", SECRET_BASE64.to_string()),
        // sous-motif traçant commun : si une variante non listée fuit, il crie
        ("traceur", "Fuite".to_string()),
        ("traceur-pem", "FUITE".to_string()),
    ]
}

fn fake_pem(kind: &str, body: &str) -> String {
    format!("-----BEGIN {kind}-----\n{body}\n{body}\n-----END {kind}-----")
}

/// Vérifie qu'aucun motif du corpus n'apparaît dans le texte donné.
fn assert_no_secret(context: &str, haystack: &str) {
    for (name, marker) in secret_markers() {
        assert!(
            !haystack.contains(&marker),
            "FUITE DE SECRET ({name}) dans {context} : le motif {marker:?} a survécu à l'expurgation.\n--- contenu fautif ---\n{haystack}"
        );
    }
}

/// Déroule le pipeline de production et vérifie l'absence de secret dans la
/// capture expurgée ET dans les faits extraits.
fn assert_pipeline_leak_free(collector: &dyn Collector, hostile_raw: &str) {
    let id = collector.id().0;
    let redacted = collector.redact(RawCapture(hostile_raw.as_bytes().to_vec()));
    let redacted_text = String::from_utf8_lossy(&redacted.0).into_owned();
    assert_no_secret(&format!("la RedactedCapture de {id}"), &redacted_text);

    let facts = collector
        .extract(&redacted)
        .unwrap_or_else(|e| panic!("{id} : extraction en échec sur entrée hostile : {e}"));
    let facts_text = format!("{facts:?}");
    assert_no_secret(&format!("les faits extraits de {id}"), &facts_text);
}

// ---------------------------------------------------------------------------
// linux.sshd
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_sshd() {
    let hostile = format!(
        "Port 22\n\
         PermitRootLogin no\n\
         # note d'un admin peu soigneux : password={p1}\n\
         AdminToken={t}\n\
         # cle de secours collee dans la config :\n\
         {pem_rsa}\n\
         {pem_openssh}\n\
         # hachage recopie depuis shadow : $6${salt}${hash}\n\
         BackupKey {b64}\n\
         PasswordAuthentication yes\n",
        p1 = SECRET_PASSWORD_1,
        t = SECRET_TOKEN,
        pem_rsa = fake_pem("RSA PRIVATE KEY", SECRET_PEM_RSA),
        pem_openssh = fake_pem("OPENSSH PRIVATE KEY", SECRET_PEM_OPENSSH),
        salt = SECRET_SHADOW_SHA512_SALT,
        hash = SECRET_SHADOW_SHA512_HASH,
        b64 = SECRET_BASE64,
    );
    assert_pipeline_leak_free(&SshdCollector::default(), &hostile);
}

// ---------------------------------------------------------------------------
// linux.accounts — y compris /etc/shadow, le cas le plus sensible
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_accounts() {
    let passwd = format!(
        "root:x:0:0:root:/root:/bin/bash\n\
         jdupont:x:1000:1000:Jean Dupont:/home/jdupont:/bin/bash\n\
         mallory:x:1002:1002:gecos hostile password={p2}:/home/mallory:/bin/bash\n",
        p2 = SECRET_PASSWORD_2
    );
    let group = "root:x:0:\nsudo:x:27:jdupont\njdupont:x:1000:\nmallory:x:1002:\n".to_string();
    let shadow = format!(
        "root:$6${s6}${h6}:19345:0:99999:7:::\n\
         jdupont:$y$j9T${sy}:20493:0:365:14:::\n\
         mallory:$2b$12${sb}:20120:0:99999:7:::\n\
         ancien:{des}:15000:0:99999:7:::\n\
         verrouille:!$6${s6}${h6}:19000:0:99999:7:::\n\
         bizarre:motdepasseenclair{p1}:19000:0:99999:7:::\n",
        s6 = SECRET_SHADOW_SHA512_SALT,
        h6 = SECRET_SHADOW_SHA512_HASH,
        sy = SECRET_SHADOW_YESCRYPT,
        sb = SECRET_SHADOW_BCRYPT,
        des = SECRET_SHADOW_DES,
        p1 = SECRET_PASSWORD_1,
    );
    let hostile = capture::join_sections(&[
        (SECTION_PASSWD, passwd.as_str()),
        (SECTION_GROUP, group.as_str()),
        (SECTION_SHADOW, shadow.as_str()),
    ]);
    assert_pipeline_leak_free(&AccountsCollector::default(), &hostile);
}

/// Le champ 2 de shadow est expurgé STRUCTURELLEMENT : même un contenu sans
/// aucune forme connue (mot de passe en clair posé là par erreur) disparaît.
#[test]
fn anti_fuite_shadow_champ_sans_structure() {
    let shadow = format!("bizarre:{p}:19000:0:99999:7:::\n", p = SECRET_PASSWORD_2);
    let hostile = capture::join_sections(&[
        (
            SECTION_PASSWD,
            "bizarre:x:1003:1003::/home/bizarre:/bin/sh\n",
        ),
        (SECTION_GROUP, "bizarre:x:1003:\n"),
        (SECTION_SHADOW, shadow.as_str()),
    ]);
    assert_pipeline_leak_free(&AccountsCollector::default(), &hostile);
}

// ---------------------------------------------------------------------------
// linux.sudoers
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_sudoers() {
    let hostile = format!(
        "Defaults env_reset\n\
         # rappel : le token={t}\n\
         # et l'ancien mot de passe root : passwd: {p1}\n\
         {pem}\n\
         # hachage : $y$j9T${sy}\n\
         root ALL=(ALL:ALL) ALL\n\
         %sudo ALL=(ALL) NOPASSWD: ALL\n\
         api_key: {b64}\n",
        t = SECRET_TOKEN,
        p1 = SECRET_PASSWORD_1,
        pem = fake_pem("EC PRIVATE KEY", SECRET_PEM_EC),
        sy = SECRET_SHADOW_YESCRYPT,
        b64 = SECRET_BASE64,
    );
    assert_pipeline_leak_free(&SudoersCollector::default(), &hostile);
}

// ---------------------------------------------------------------------------
// backup.proof
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_backup() {
    let hostile = format!(
        "[srv-fichiers]\n\
         last_success = 2026-08-11T02:14:00Z\n\
         encryption_key = {b64}\n\
         repository_password = {p1}\n\
         auth_token = {t}\n\
         # cle privee du depot, collee la par un outil mal configure :\n\
         {pem}\n\
         [base-de-donnees]\n\
         last_success = 2026-08-11T03:00:00Z\n\
         db_secret: {p2}\n",
        b64 = SECRET_BASE64,
        p1 = SECRET_PASSWORD_1,
        t = SECRET_TOKEN,
        pem = fake_pem("PRIVATE KEY", SECRET_PEM_RSA),
        p2 = SECRET_PASSWORD_2,
    );
    assert_pipeline_leak_free(&BackupProofCollector::default(), &hostile);
}

// ---------------------------------------------------------------------------
// linux.packages
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_packages() {
    let hostile = format!(
        "Package: outil-interne\n\
         Status: install ok half-configured\n\
         Version: 1.2-3\n\
         Maintainer: Op Interne <op@example.invalid> password={p1}\n\
         Description: paquet hostile\n\
         \x20note d'un mainteneur : token = {t}\n\
         \x20cle recopiee : deploy_key={b64}\n\
         \n\
         Package: autre\n\
         Status: install ok installed\n\
         Version: $6${salt}${hash}\n\
         Description: version hostile imitant un hachage\n\
         {pem}\n",
        p1 = SECRET_PASSWORD_1,
        t = SECRET_TOKEN,
        b64 = SECRET_BASE64,
        salt = SECRET_SHADOW_SHA512_SALT,
        hash = SECRET_SHADOW_SHA512_HASH,
        pem = fake_pem("RSA PRIVATE KEY", SECRET_PEM_RSA),
    );
    assert_pipeline_leak_free(&PackagesCollector::default(), &hostile);
}

// ---------------------------------------------------------------------------
// linux.ports
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_ports() {
    let tcp = format!(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
         \x20  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21001 1\n\
         # ligne hostile injectee : password={p1}\n\
         \x20  1: 0100007F:1F90 00000000:0000 0A 0:0 0:0 0 auth_token={t} 0 1\n\
         $y$j9T${sy}\n",
        p1 = SECRET_PASSWORD_1,
        t = SECRET_TOKEN,
        sy = SECRET_SHADOW_YESCRYPT,
    );
    let udp = format!(
        "session_key {b64}\n{pem}\n",
        b64 = SECRET_BASE64,
        pem = fake_pem("EC PRIVATE KEY", SECRET_PEM_EC),
    );
    let hostile =
        capture::join_sections(&[(SECTION_TCP, tcp.as_str()), (SECTION_UDP, udp.as_str())]);
    assert_pipeline_leak_free(&PortsCollector::default(), &hostile);
}

// ---------------------------------------------------------------------------
// linux.systemd — ExecStart et Environment sont les points de fuite classiques
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_systemd() {
    let unit = format!(
        "[Unit]\n\
         Description=Service hostile\n\
         [Service]\n\
         User=svc-app\n\
         Environment=APP_TOKEN={t}\n\
         Environment=DB_PASSWORD={p1}\n\
         ExecStart=/usr/bin/app --user admin --password={p2} --verbose\n\
         # cle privee collee dans l'unite :\n\
         {pem}\n\
         # hachage recopie : $2b$12${sb}\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        t = SECRET_TOKEN,
        p1 = SECRET_PASSWORD_1,
        p2 = SECRET_PASSWORD_2,
        pem = fake_pem("OPENSSH PRIVATE KEY", SECRET_PEM_OPENSSH),
        sb = SECRET_SHADOW_BCRYPT,
    );
    let hostile = capture::join_sections(&[
        (SECTION_UNIT_FILES, "app.service enabled\n"),
        ("/etc/systemd/system/app.service", unit.as_str()),
    ]);
    assert_pipeline_leak_free(&SystemdCollector::default(), &hostile);
}

/// L'argument d'`ExecStart` expurgé ne réapparaît pas dans le fait
/// `service.exec_start` : le fait est extrait de la capture DÉJÀ expurgée.
#[test]
fn anti_fuite_systemd_exec_start_expurge_dans_les_faits() {
    let unit = format!(
        "[Service]\nExecStart=/usr/bin/app --password={p1}\n",
        p1 = SECRET_PASSWORD_1
    );
    let hostile = capture::join_sections(&[("/etc/systemd/system/app.service", unit.as_str())]);
    let collector = SystemdCollector::default();
    let redacted = collector.redact(RawCapture(hostile.into_bytes()));
    let facts = collector
        .extract(&redacted)
        .unwrap_or_else(|e| panic!("extraction en échec : {e}"));
    let exec = facts
        .iter()
        .find(|f| f.attribute.0 == "service.exec_start")
        .unwrap_or_else(|| panic!("fait service.exec_start manquant"));
    let debug = format!("{exec:?}");
    assert!(
        debug.contains("/usr/bin/app"),
        "la commande doit rester : {debug}"
    );
    assert!(
        debug.contains(constat_collect::redact::MARKER_PASSWORD),
        "le marqueur doit attester le secret : {debug}"
    );
}

// ---------------------------------------------------------------------------
// linux.kernel_params — la liste blanche est la seconde ligne de défense
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_kernel_params() {
    let hostile = format!(
        "net.ipv4.ip_forward = 0\n\
         kernel.core_pattern = |/usr/bin/exfiltre --token={t}\n\
         mot.de.hostile = password={p1}\n\
         autre.cle.hostile = $6${salt}${hash}\n\
         {pem}\n\
         cle.api.secret={b64}\n\
         kernel.randomize_va_space = 2\n",
        t = SECRET_TOKEN,
        p1 = SECRET_PASSWORD_1,
        salt = SECRET_SHADOW_SHA512_SALT,
        hash = SECRET_SHADOW_SHA512_HASH,
        pem = fake_pem("PRIVATE KEY", SECRET_PEM_RSA),
        b64 = SECRET_BASE64,
    );
    assert_pipeline_leak_free(&KernelParamsCollector::default(), &hostile);
}

// ---------------------------------------------------------------------------
// Transversal : tout le corpus, dans tous les collecteurs à la fois
// ---------------------------------------------------------------------------

/// Le corpus complet concaténé, injecté tel quel dans chaque collecteur du
/// registre : quel que soit le fichier où un secret structuré atterrit,
/// il ne doit pas sortir.
#[test]
fn anti_fuite_corpus_complet_dans_chaque_collecteur() {
    let corpus = format!(
        "{pem1}\n{pem2}\n{pem3}\n\
         hash1=$6${s6}${h6}\n\
         hash2 $y$j9T${sy}\n\
         hash3 $2b$12${sb}\n\
         password={p1}\n\
         user_passwd: {p2}\n\
         token = {t}\n\
         master_key={b64}\n",
        pem1 = fake_pem("RSA PRIVATE KEY", SECRET_PEM_RSA),
        pem2 = fake_pem("OPENSSH PRIVATE KEY", SECRET_PEM_OPENSSH),
        pem3 = fake_pem("EC PRIVATE KEY", SECRET_PEM_EC),
        s6 = SECRET_SHADOW_SHA512_SALT,
        h6 = SECRET_SHADOW_SHA512_HASH,
        sy = SECRET_SHADOW_YESCRYPT,
        sb = SECRET_SHADOW_BCRYPT,
        p1 = SECRET_PASSWORD_1,
        p2 = SECRET_PASSWORD_2,
        t = SECRET_TOKEN,
        b64 = SECRET_BASE64,
    );
    for collector in constat_collect::all_collectors() {
        assert_pipeline_leak_free(collector.as_ref(), &corpus);
    }
}

/// La capture expurgée doit rester utile : les marqueurs `[EXPURGÉ:…]`
/// attestent qu'un secret était là — la présence reste prouvable (§7.2).
#[test]
fn les_marqueurs_d_expurgation_attestent_la_presence() {
    let collector = SshdCollector::default();
    let hostile = format!(
        "{}\npassword={}\n",
        fake_pem("RSA PRIVATE KEY", SECRET_PEM_RSA),
        SECRET_PASSWORD_1
    );
    let redacted = collector.redact(RawCapture(hostile.into_bytes()));
    let text = String::from_utf8_lossy(&redacted.0).into_owned();
    assert!(text.contains(constat_collect::redact::MARKER_PRIVATE_KEY));
    assert!(text.contains(constat_collect::redact::MARKER_PASSWORD));
}
