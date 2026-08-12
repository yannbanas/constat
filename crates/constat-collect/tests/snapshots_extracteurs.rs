//! Instantanés `insta` (§12) sur chaque extracteur : le pipeline complet
//! `redact` → `extract` est exercé sur des captures d'exemple réalistes et
//! anonymisées (`tests/fixtures/`). Toute régression silencieuse d'un
//! extracteur ou de l'expurgation casse un instantané.

use constat_collect::backup::BackupProofCollector;
use constat_collect::linux::accounts::{
    AccountsCollector, SECTION_GROUP, SECTION_PASSWD, SECTION_SHADOW,
};
use constat_collect::linux::sshd::SshdCollector;
use constat_collect::linux::sudoers::SudoersCollector;
use constat_collect::{capture, Collector, RawCapture};

const SSHD_CONFIG: &str = include_str!("fixtures/sshd_config");
const PASSWD: &str = include_str!("fixtures/passwd");
const GROUP: &str = include_str!("fixtures/group");
const SHADOW: &str = include_str!("fixtures/shadow");
const SUDOERS: &str = include_str!("fixtures/sudoers");
const BACKUP_STATUS: &str = include_str!("fixtures/backup-status");

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
