//! Instantanés `insta` (§12) sur chaque extracteur : le pipeline complet
//! `redact` → `extract` est exercé sur des captures d'exemple réalistes et
//! anonymisées (`tests/fixtures/`). Toute régression silencieuse d'un
//! extracteur ou de l'expurgation casse un instantané.

use constat_collect::backup::BackupProofCollector;
use constat_collect::linux::accounts::{
    AccountsCollector, SECTION_GROUP, SECTION_PASSWD, SECTION_SHADOW,
};
use constat_collect::linux::kernel_params::KernelParamsCollector;
use constat_collect::linux::packages::PackagesCollector;
use constat_collect::linux::ports::{PortsCollector, SECTION_TCP, SECTION_TCP6, SECTION_UDP};
use constat_collect::linux::sshd::SshdCollector;
use constat_collect::linux::sudoers::SudoersCollector;
use constat_collect::linux::systemd::{SystemdCollector, SECTION_UNIT_FILES};
use constat_collect::{capture, Collector, RawCapture};

const SSHD_CONFIG: &str = include_str!("fixtures/sshd_config");
const PASSWD: &str = include_str!("fixtures/passwd");
const GROUP: &str = include_str!("fixtures/group");
const SHADOW: &str = include_str!("fixtures/shadow");
const SUDOERS: &str = include_str!("fixtures/sudoers");
const BACKUP_STATUS: &str = include_str!("fixtures/backup-status");
const DPKG_STATUS: &str = include_str!("fixtures/dpkg-status");
const PROC_NET_TCP: &str = include_str!("fixtures/proc-net-tcp");
const PROC_NET_TCP6: &str = include_str!("fixtures/proc-net-tcp6");
const PROC_NET_UDP: &str = include_str!("fixtures/proc-net-udp");
const SYSTEMD_UNIT_FILES: &str = include_str!("fixtures/systemd-unit-files");
const UNIT_SAUVEGARDE: &str = include_str!("fixtures/sauvegarde.service");
const UNIT_APACHE2: &str = include_str!("fixtures/apache2.service");
const SYSCTL_DUMP: &str = include_str!("fixtures/sysctl-dump");

/// Déroule le pipeline de production : expurgation puis extraction.
/// Retourne (capture expurgée en texte, faits) pour l'instantané.
fn pipeline(collector: &dyn Collector, raw: &str) -> (String, Vec<constat_model::Fact>) {
    let redacted = collector.redact(RawCapture(raw.as_bytes().to_vec()));
    let facts = collector
        .extract(&redacted)
        .unwrap_or_else(|e| panic!("extraction en échec : {e}"));
    (String::from_utf8_lossy(&redacted.0).into_owned(), facts)
}

#[test]
fn instantane_sshd() {
    let (redacted, facts) = pipeline(&SshdCollector::default(), SSHD_CONFIG);
    insta::assert_snapshot!("sshd_capture_expurgee", redacted);
    insta::assert_debug_snapshot!("sshd_faits", facts);
}

#[test]
fn instantane_accounts() {
    let raw = capture::join_sections(&[
        (SECTION_PASSWD, PASSWD),
        (SECTION_GROUP, GROUP),
        (SECTION_SHADOW, SHADOW),
    ]);
    let (redacted, facts) = pipeline(&AccountsCollector::default(), &raw);
    insta::assert_snapshot!("accounts_capture_expurgee", redacted);
    insta::assert_debug_snapshot!("accounts_faits", facts);
}

#[test]
fn instantane_sudoers() {
    let (redacted, facts) = pipeline(&SudoersCollector::default(), SUDOERS);
    insta::assert_snapshot!("sudoers_capture_expurgee", redacted);
    insta::assert_debug_snapshot!("sudoers_faits", facts);
}

#[test]
fn instantane_backup() {
    let (redacted, facts) = pipeline(&BackupProofCollector::default(), BACKUP_STATUS);
    insta::assert_snapshot!("backup_capture_expurgee", redacted);
    insta::assert_debug_snapshot!("backup_faits", facts);
}

#[test]
fn instantane_packages() {
    let (redacted, facts) = pipeline(&PackagesCollector::default(), DPKG_STATUS);
    insta::assert_snapshot!("packages_capture_expurgee", redacted);
    insta::assert_debug_snapshot!("packages_faits", facts);
}

#[test]
fn instantane_ports() {
    let raw = capture::join_sections(&[
        (SECTION_TCP, PROC_NET_TCP),
        (SECTION_TCP6, PROC_NET_TCP6),
        (SECTION_UDP, PROC_NET_UDP),
    ]);
    let (redacted, facts) = pipeline(&PortsCollector::default(), &raw);
    insta::assert_snapshot!("ports_capture_expurgee", redacted);
    insta::assert_debug_snapshot!("ports_faits", facts);
}

#[test]
fn instantane_systemd() {
    let raw = capture::join_sections(&[
        (SECTION_UNIT_FILES, SYSTEMD_UNIT_FILES),
        ("/etc/systemd/system/sauvegarde.service", UNIT_SAUVEGARDE),
        ("/usr/lib/systemd/system/apache2.service", UNIT_APACHE2),
    ]);
    let (redacted, facts) = pipeline(&SystemdCollector::default(), &raw);
    insta::assert_snapshot!("systemd_capture_expurgee", redacted);
    insta::assert_debug_snapshot!("systemd_faits", facts);
}

#[test]
fn instantane_kernel_params() {
    let (redacted, facts) = pipeline(&KernelParamsCollector::default(), SYSCTL_DUMP);
    insta::assert_snapshot!("kernel_params_capture_expurgee", redacted);
    insta::assert_debug_snapshot!("kernel_params_faits", facts);
}
