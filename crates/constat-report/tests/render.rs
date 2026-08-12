//! Snapshot insta du rendu HTML sur un dossier d'exemple (§12) : toute
//! régression silencieuse du dossier de preuve doit être visible en revue.

#![allow(clippy::unwrap_used)]

use constat_model::{AssetId, BlobHash, DurationMs, Timestamp};
use constat_report::{
    render_html, ArtifactRef, Cover, CoverageSummary, EvidenceDossier, ExceptionNote, Inventory,
    Outage, ProofBlock, RequirementReport, Verdict,
};

/// Un dossier d'exemple complet et déterministe : Q1 2026, un écart
/// d'inventaire, trois verdicts différents, une exception expirée, deux
/// interruptions, pas de jeton d'horodatage (le cas honnête par défaut).
fn dossier_exemple() -> EvidenceDossier {
    EvidenceDossier {
        cover: Cover {
            organization: "Exemple SAS".to_owned(),
            period_start: Timestamp(1_767_225_600_000), // 2026-01-01 00:00:00 UTC
            period_end: Timestamp(1_775_001_599_000),   // 2026-03-31 23:59:59 UTC
            scope: "Serveurs de production, site de Lyon".to_owned(),
            generated_at: Timestamp(1_775_120_400_000), // 2026-04-02 09:00:00 UTC
            referential: Some("RECYF v2".to_owned()),
        },
        inventory: Inventory {
            expected: vec![
                AssetId("srv-fic-01".to_owned()),
                AssetId("srv-fic-02".to_owned()),
                AssetId("srv-app-01".to_owned()),
            ],
            observed: vec![
                AssetId("srv-fic-01".to_owned()),
                AssetId("srv-app-01".to_owned()),
                AssetId("srv-dev-99".to_owned()),
            ],
        },
        requirements: vec![
            RequirementReport {
                assertion_id: "SSH-ROOT".to_owned(),
                title: "la connexion root en SSH est désactivée".to_owned(),
                requirement_ref: Some("RECYF 4.2".to_owned()),
                verdict: Verdict::Pass,
                coverage: CoverageSummary {
                    observed_permille: 992,
                    max_gap: DurationMs(26 * 3_600_000),
                    gap_count: 3,
                },
                exceptions: vec![],
            },
            RequirementReport {
                assertion_id: "ADM-MFA".to_owned(),
                title: "tous les comptes privilégiés ont l'authentification forte".to_owned(),
                requirement_ref: Some("RECYF 2.1".to_owned()),
                verdict: Verdict::Fail,
                coverage: CoverageSummary {
                    observed_permille: 997,
                    max_gap: DurationMs(25 * 3_600_000),
                    gap_count: 2,
                },
                exceptions: vec![
                    ExceptionNote {
                        entity: "user:svc-sauvegarde".to_owned(),
                        reason: "compte de service, authentification par certificat".to_owned(),
                        approved_by: "RSSI".to_owned(),
                        expires: Timestamp(1_798_761_600_000), // 2027-01-01
                    },
                    ExceptionNote {
                        entity: "user:svc-legacy".to_owned(),
                        reason: "application ancienne sans prise en charge MFA".to_owned(),
                        approved_by: "RSSI".to_owned(),
                        expires: Timestamp(1_767_225_600_000), // 2026-01-01 : expirée
                    },
                ],
            },
            RequirementReport {
                assertion_id: "BKP-24H".to_owned(),
                title: "sauvegarde réussie dans les dernières 24 heures".to_owned(),
                requirement_ref: None,
                verdict: Verdict::Undetermined,
                coverage: CoverageSummary {
                    observed_permille: 640,
                    max_gap: DurationMs(9 * 24 * 3_600_000),
                    gap_count: 1,
                },
                exceptions: vec![],
            },
        ],
        outages: vec![
            Outage {
                asset: AssetId("srv-fic-02".to_owned()),
                from: Timestamp(1_770_865_200_000), // 2026-02-12 03:00
                to: Timestamp(1_770_880_320_000),   // 2026-02-12 07:12
                reason: "machine arrêtée, maintenance".to_owned(),
            },
            Outage {
                asset: AssetId("srv-app-01".to_owned()),
                from: Timestamp(1_772_287_200_000), // 2026-02-28 14:00
                to: Timestamp(1_772_289_900_000),   // 2026-02-28 14:45
                reason: "agent indisponible".to_owned(),
            },
        ],
        artifacts: vec![
            ArtifactRef {
                asset: AssetId("srv-fic-01".to_owned()),
                collector: "linux.sshd".to_owned(),
                blob: BlobHash([0x7F; 32]),
                collected_at: Timestamp(1_770_508_800_000), // 2026-02-08
            },
            ArtifactRef {
                asset: AssetId("srv-app-01".to_owned()),
                collector: "linux.accounts".to_owned(),
                blob: BlobHash([0xB8; 32]),
                collected_at: Timestamp(1_770_508_800_000),
            },
        ],
        proof: ProofBlock {
            merkle_root: BlobHash([0xAB; 32]),
            root_signature: vec![0xCD; 64],
            public_key: vec![0xEF; 32],
            timestamp_token: None,
            entry_count: 91,
        },
    }
}

#[test]
fn le_rendu_html_du_dossier_exemple_est_stable() {
    insta::assert_snapshot!("dossier_exemple", render_html(&dossier_exemple()));
}

#[test]
fn le_dossier_declare_toujours_ses_limites() {
    let html = render_html(&dossier_exemple());
    // §6.4 : la section des limites est inconditionnelle.
    assert!(html.contains("Ce que ce dossier ne prouve pas"));
    // §6.2 : la phrase sur la non-répudiation, noir sur blanc.
    assert!(html.contains("cohérence interne"));
    assert!(html.contains("non-répudiation"));
    // §10.3 : la procédure de vérification autonome.
    assert!(html.contains("constat-verify"));
    assert!(html.contains("FORMAT.md"));
}

#[test]
fn l_ecart_d_inventaire_est_un_constat() {
    let dossier = dossier_exemple();
    let manquantes: Vec<_> = dossier.inventory.missing();
    let inattendues: Vec<_> = dossier.inventory.unexpected();
    assert_eq!(manquantes.len(), 1);
    assert_eq!(manquantes[0].0, "srv-fic-02");
    assert_eq!(inattendues.len(), 1);
    assert_eq!(inattendues[0].0, "srv-dev-99");

    let html = render_html(&dossier);
    assert!(html.contains("srv-fic-02"));
    assert!(html.contains("srv-dev-99"));
}

#[test]
fn une_exception_expiree_est_marquee() {
    let html = render_html(&dossier_exemple());
    assert!(html.contains("EXPIRÉE"));
}

#[test]
fn le_contenu_est_echappe() {
    let mut dossier = dossier_exemple();
    dossier.cover.organization = "<script>alert(1)</script>".to_owned();
    let html = render_html(&dossier);
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;"));
}
