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
use constat_collect::network_configs::{
    build_network_capture, NetworkConfigsCollector, SECTION_NETDEV_PREFIX,
};
use constat_collect::windows::accounts::AccountsCollector as WindowsAccountsCollector;
use constat_collect::windows::ad_groups::AdGroupsCollector;
use constat_collect::windows::gpo_security::{GpoSecurityCollector, SECTION_GPO_PREFIX};
use constat_collect::windows::password_policy::PasswordPolicyCollector;
use constat_collect::windows::services::ServicesCollector;
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
/// Blob `ENC` FortiGate factice (charset base64, traçable).
const SECRET_FORTI_ENC: &str = "FuiteEnc12FuiteEnc12FuiteEnc12==";
/// PSK IPsec FortiGate factice, en clair.
const SECRET_FORTI_PSK: &str = "FuitePsk13!";
/// Communauté SNMP factice.
const SECRET_SNMP_COMMUNITY: &str = "FuiteCommunaute14";
/// Clé pré-partagée ISAKMP factice.
const SECRET_ISAKMP_KEY: &str = "FuiteIsakmp15";
/// Clé TACACS factice (type 7).
const SECRET_TACACS_KEY: &str = "0822455DFuite16";
/// `key-string` factice (key chain / HSRP).
const SECRET_KEY_STRING: &str = "FuiteKs17";
/// Contenus de balises XML sensibles factices.
const SECRET_XML_PASSWORD: &str = "MotXmlFuite18";
const SECRET_XML_APIKEY: &str = "CleApiFuite19";
const SECRET_XML_AUTHKEY: &str = "AuthFuite20";
const SECRET_XML_PRIVKEY: &str = "PrivFuite21";

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
        ("fortigate-enc", SECRET_FORTI_ENC.to_string()),
        ("fortigate-psk", SECRET_FORTI_PSK.to_string()),
        ("communaute-snmp", SECRET_SNMP_COMMUNITY.to_string()),
        ("cle-isakmp", SECRET_ISAKMP_KEY.to_string()),
        ("cle-tacacs", SECRET_TACACS_KEY.to_string()),
        ("key-string", SECRET_KEY_STRING.to_string()),
        ("xml-password", SECRET_XML_PASSWORD.to_string()),
        ("xml-apikey", SECRET_XML_APIKEY.to_string()),
        ("xml-authkey", SECRET_XML_AUTHKEY.to_string()),
        ("xml-privkey", SECRET_XML_PRIVKEY.to_string()),
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
// windows.accounts — commentaires hostiles dans une capture INI
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_windows_accounts() {
    let hostile = format!(
        "[localgroup S-1-5-32-544]\n\
         name = Administrateurs\n\
         # note d'un admin : password={p1}\n\
         \n\
         [user S-1-5-21-1-500]\n\
         name = Administrateur\n\
         enabled = true\n\
         password_never_expires = true\n\
         groups = S-1-5-32-544\n\
         # jeton oublié : token={t}\n\
         # hachage recopié : $6${salt}${hash}\n\
         recovery_key={b64}\n\
         {pem}\n",
        p1 = SECRET_PASSWORD_1,
        t = SECRET_TOKEN,
        salt = SECRET_SHADOW_SHA512_SALT,
        hash = SECRET_SHADOW_SHA512_HASH,
        b64 = SECRET_BASE64,
        pem = fake_pem("RSA PRIVATE KEY", SECRET_PEM_RSA),
    );
    assert_pipeline_leak_free(&WindowsAccountsCollector, &hostile);
}

// ---------------------------------------------------------------------------
// windows.password_policy
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_windows_password_policy() {
    let hostile = format!(
        "[password_policy]\n\
         min_password_length = 8\n\
         # rappel du mot de passe du compte de secours : passwd: {p2}\n\
         admin_token = {t}\n\
         {pem}\n",
        p2 = SECRET_PASSWORD_2,
        t = SECRET_TOKEN,
        pem = fake_pem("EC PRIVATE KEY", SECRET_PEM_EC),
    );
    assert_pipeline_leak_free(&PasswordPolicyCollector, &hostile);
}

// ---------------------------------------------------------------------------
// windows.services — ImagePath est le point de fuite classique
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_windows_services() {
    let hostile = format!(
        "[AppInterne]\n\
         start = 2\n\
         object_name = .\\svc-app\n\
         image_path = C:\\app\\service.exe --user admin --password={p1} --verbose\n\
         \n\
         [AutreService]\n\
         start = 3\n\
         image_path = C:\\outil.exe --api_key={b64}\n\
         # cle privee collee dans une valeur : {pem}\n\
         # jeton : token = {t}\n",
        p1 = SECRET_PASSWORD_1,
        b64 = SECRET_BASE64,
        pem = fake_pem("PRIVATE KEY", SECRET_PEM_RSA),
        t = SECRET_TOKEN,
    );
    assert_pipeline_leak_free(&ServicesCollector, &hostile);
}

/// La commande d'`image_path` reste utile après expurgation : le chemin
/// survit, le secret devient un marqueur — dans les faits aussi.
#[test]
fn anti_fuite_windows_services_image_path_expurge_dans_les_faits() {
    let hostile = format!(
        "[AppInterne]\nstart = 2\nimage_path = C:\\app\\service.exe --password={p1}\n",
        p1 = SECRET_PASSWORD_1
    );
    let collector = ServicesCollector;
    let redacted = collector.redact(RawCapture(hostile.into_bytes()));
    let facts = collector
        .extract(&redacted)
        .unwrap_or_else(|e| panic!("extraction en échec : {e}"));
    let path = facts
        .iter()
        .find(|f| f.attribute.0 == "service.image_path")
        .unwrap_or_else(|| panic!("fait service.image_path manquant"));
    let debug = format!("{path:?}");
    assert!(
        debug.contains("service.exe"),
        "le chemin doit rester : {debug}"
    );
    assert!(
        debug.contains(constat_collect::redact::MARKER_PASSWORD),
        "le marqueur doit attester le secret : {debug}"
    );
}

// ---------------------------------------------------------------------------
// ad.groups
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_ad_groups() {
    let hostile = format!(
        "[domain]\n\
         name = EXEMPLE\n\
         \n\
         [group S-1-5-21-1-2-3-512]\n\
         name = Admins du domaine\n\
         member = Administrateur\n\
         # mot de passe du compte de service : password={p1}\n\
         # hachage : $2b$12${sb}\n\
         sync_token = {t}\n\
         {pem}\n",
        p1 = SECRET_PASSWORD_1,
        sb = SECRET_SHADOW_BCRYPT,
        t = SECRET_TOKEN,
        pem = fake_pem("OPENSSH PRIVATE KEY", SECRET_PEM_OPENSSH),
    );
    assert_pipeline_leak_free(&AdGroupsCollector, &hostile);
}

// ---------------------------------------------------------------------------
// ad.gpo_security — un GptTmpl.inf hostile
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_ad_gpo_security() {
    let inf = format!(
        "[System Access]\r\n\
         MinimumPasswordLength = 8\r\n\
         ; note laissée dans la GPO : password={p1}\r\n\
         AutoAdminPassword = {p2}\r\n\
         [Privilege Rights]\r\n\
         SeDebugPrivilege = *S-1-5-32-544\r\n\
         [Registry Values]\r\n\
         MACHINE\\Software\\Exemple\\ApiToken=1,\"{t}\"\r\n\
         {pem}\r\n\
         deploy_key = {b64}\r\n",
        p1 = SECRET_PASSWORD_1,
        p2 = SECRET_PASSWORD_2,
        t = SECRET_TOKEN,
        pem = fake_pem("RSA PRIVATE KEY", SECRET_PEM_RSA),
        b64 = SECRET_BASE64,
    );
    let hostile = capture::join_sections(&[(
        &format!("{SECTION_GPO_PREFIX}{{AAAA-HOSTILE}}"),
        inf.as_str(),
    )]);
    assert_pipeline_leak_free(&GpoSecurityCollector, &hostile);
}

// ---------------------------------------------------------------------------
// network.configs — chaque famille de secrets d'équipement réseau (S7)
// ---------------------------------------------------------------------------

#[test]
fn anti_fuite_network_configs() {
    let fortigate = format!(
        "config system global\n\
         \x20   set hostname \"fw-hostile\"\n\
         end\n\
         config system admin\n\
         \x20   edit \"admin\"\n\
         \x20       set password ENC {enc}\n\
         \x20   next\n\
         end\n\
         config vpn ipsec phase1-interface\n\
         \x20   edit \"vpn\"\n\
         \x20       set psksecret {psk}\n\
         \x20       set passphrase {p1}\n\
         \x20   next\n\
         end\n\
         config vpn certificate local\n\
         \x20   edit \"srv\"\n\
         \x20       set private-key \"{pem}\"\n\
         \x20   next\n\
         end\n",
        enc = SECRET_FORTI_ENC,
        psk = SECRET_FORTI_PSK,
        p1 = SECRET_PASSWORD_1,
        pem = fake_pem("ENCRYPTED PRIVATE KEY", SECRET_PEM_RSA),
    );
    let cisco = format!(
        "version 15.4\n\
         hostname rtr-hostile\n\
         enable secret 5 $1${salt}${hash}\n\
         enable password {p2}\n\
         username ops secret 5 $1${salt}${hash}\n\
         username invite password 0 {p1}\n\
         interface GigabitEthernet0/0\n\
         \x20standby 1 authentication md5 key-string {ks}\n\
         key chain SECOURS\n\
         \x20key 1\n\
         \x20 key-string {ks}\n\
         crypto isakmp key {isakmp} address 10.200.1.9\n\
         tacacs-server host 10.20.2.40 key 7 {tacacs}\n\
         radius-server host 10.20.2.41 key {tacacs}\n\
         snmp-server community {snmp} RO\n\
         end\n",
        salt = SECRET_SHADOW_SHA512_SALT,
        hash = SECRET_SHADOW_SHA512_HASH,
        p1 = SECRET_PASSWORD_1,
        p2 = SECRET_PASSWORD_2,
        ks = SECRET_KEY_STRING,
        isakmp = SECRET_ISAKMP_KEY,
        tacacs = SECRET_TACACS_KEY,
        snmp = SECRET_SNMP_COMMUNITY,
    );
    let nftables = format!(
        "table inet filtre {{\n\
         \x20   chain entree {{\n\
         \x20       type filter hook input priority 0; policy drop;\n\
         \x20       # note hostile d'un exploitant : password={p1}\n\
         \x20       tcp dport 22 accept comment \"api_key: {t}\"\n\
         \x20   }}\n\
         }}\n",
        p1 = SECRET_PASSWORD_1,
        t = SECRET_TOKEN,
    );
    let xml = format!(
        "<?xml version=\"1.0\"?>\n\
         <opnsense>\n\
         \x20 <system>\n\
         \x20   <user>\n\
         \x20     <password>{xp}</password>\n\
         \x20     <apikey>{xa}</apikey>\n\
         \x20   </user>\n\
         \x20 </system>\n\
         \x20 <snmpd>\n\
         \x20   <rocommunity>{snmp}</rocommunity>\n\
         \x20   <authkey>{xk}</authkey>\n\
         \x20   <privkey>{xv}\n\
         {xv}</privkey>\n\
         \x20 </snmpd>\n\
         </opnsense>\n",
        xp = SECRET_XML_PASSWORD,
        xa = SECRET_XML_APIKEY,
        snmp = SECRET_SNMP_COMMUNITY,
        xk = SECRET_XML_AUTHKEY,
        xv = SECRET_XML_PRIVKEY,
    );
    let hostile = build_network_capture(&[
        ("fw-hostile", &fortigate),
        ("rtr-hostile", &cisco),
        ("nft-hostile", &nftables),
        ("opn-hostile", &xml),
    ]);
    assert_pipeline_leak_free(&NetworkConfigsCollector::default(), &hostile);
}

/// La structure survit à l'expurgation : l'auditeur voit qu'une communauté
/// SNMP était configurée (`RO` conservé), jamais sa valeur — et les faits ne
/// portent que des comptages et des indices de format.
#[test]
fn anti_fuite_network_configs_la_structure_atteste() {
    let cisco = format!(
        "version 15.4\ninterface Gi0/0\nsnmp-server community {snmp} RO\n",
        snmp = SECRET_SNMP_COMMUNITY
    );
    let hostile = build_network_capture(&[("rtr", &cisco)]);
    let collector = NetworkConfigsCollector::default();
    let redacted = collector.redact(RawCapture(hostile.into_bytes()));
    let text = String::from_utf8_lossy(&redacted.0).into_owned();
    assert!(
        text.contains(&format!(
            "snmp-server community {} RO",
            constat_collect::redact::MARKER_SNMP_COMMUNITY
        )),
        "la structure de la ligne doit survivre : {text}"
    );
    assert!(text.contains(&format!("{SECTION_NETDEV_PREFIX}rtr")));
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
