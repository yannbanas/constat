//! Snapshot insta du rendu HTML sur un dossier d'exemple (§12) : toute
//! régression silencieuse du dossier de preuve doit être visible en revue.

#![allow(clippy::unwrap_used)]

use constat_model::{AssetId, BlobHash, DurationMs, Timestamp};
use constat_report::{
    render_html, ArtifactRef, AssertionOutcome, CorrespondenceTable, Cover, CoverageSummary,
    EvidenceDossier, ExceptionNote, Inventory, MappedRequirement, Outage, ProofBlock,
    RequirementReport, RequirementVerdict, Verdict,
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
        correspondence: None,
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

/// Reprend le verdict d'une exigence de [`dossier_exemple`] sous la forme
/// de la table de correspondance — les mêmes verdicts, jamais recalculés.
fn outcome_of(req: &RequirementReport) -> AssertionOutcome {
    AssertionOutcome {
        assertion_id: req.assertion_id.clone(),
        title: req.title.clone(),
        verdict: req.verdict,
        coverage: req.coverage,
    }
}

/// Le dossier d'exemple, complété d'une table de correspondance : une
/// exigence couverte en échec, une exigence conforme, une exigence **non
/// couverte**, une assertion hors référentiel en annexe, un avertissement.
fn dossier_avec_table() -> EvidenceDossier {
    let mut dossier = dossier_exemple();
    let ssh = outcome_of(&dossier.requirements[0]); // SSH-ROOT, Pass
    let mfa = outcome_of(&dossier.requirements[1]); // ADM-MFA, Fail
    let bkp = outcome_of(&dossier.requirements[2]); // BKP-24H, Undetermined
    dossier.correspondence = Some(CorrespondenceTable {
        referential_id: "exemple".to_owned(),
        referential_title: "Référentiel d'hygiène — exemple".to_owned(),
        referential_version: "v1".to_owned(),
        requirements: vec![
            MappedRequirement {
                id: "EX-1".to_owned(),
                title: "L'accès administrateur à distance est maîtrisé".to_owned(),
                assertions: vec![ssh, mfa],
            },
            MappedRequirement {
                id: "EX-2".to_owned(),
                title: "La sauvegarde est prouvée sous 24 heures".to_owned(),
                assertions: vec![bkp.clone()],
            },
            MappedRequirement {
                id: "EX-3".to_owned(),
                title: "La journalisation est centralisée".to_owned(),
                assertions: vec![],
            },
        ],
        unmapped_assertions: vec![AssertionOutcome {
            assertion_id: "HORS-REF".to_owned(),
            title: "assertion évaluée mais hors référentiel".to_owned(),
            verdict: Verdict::Pass,
            coverage: CoverageSummary {
                observed_permille: 1000,
                max_gap: DurationMs(3_600_000),
                gap_count: 0,
            },
        }],
        warnings: vec![
            "l'exigence EX-2 référence une assertion inconnue du fichier d'assertions : \
             LOG-CENTRAL"
                .to_owned(),
        ],
    });
    dossier
}

#[test]
fn le_rendu_html_du_dossier_exemple_est_stable() {
    insta::assert_snapshot!("dossier_exemple", render_html(&dossier_exemple()));
}

#[test]
fn le_rendu_html_de_la_table_de_correspondance_est_stable() {
    insta::assert_snapshot!("dossier_referentiel", render_html(&dossier_avec_table()));
}

#[test]
fn le_verdict_d_exigence_s_agrege_sans_indulgence() {
    let dossier = dossier_avec_table();
    let table = dossier.correspondence.as_ref().unwrap();
    // Pass + Fail → Fail : une assertion en échec suffit.
    assert_eq!(table.requirements[0].verdict(), RequirementVerdict::Fail);
    // Une seule assertion, indéterminée → Undetermined.
    assert_eq!(
        table.requirements[1].verdict(),
        RequirementVerdict::Undetermined
    );
    // Aucune assertion mappée → NotCovered, un état à part entière.
    assert_eq!(
        table.requirements[2].verdict(),
        RequirementVerdict::NotCovered
    );
    assert_eq!(RequirementVerdict::NotCovered.label(), "Non couverte");
}

#[test]
fn une_exigence_non_couverte_est_declaree_jamais_tue() {
    let html = render_html(&dossier_avec_table());
    // L'exigence sans assertion apparaît, son état est déclaré.
    assert!(html.contains("EX-3"));
    assert!(html.contains("Non couverte"));
    assert!(html.contains("Exigence non couverte"));
    // L'avertissement de construction est listé dans le dossier.
    assert!(html.contains("LOG-CENTRAL"));
    // L'annexe liste l'assertion hors référentiel.
    assert!(html.contains("HORS-REF"));
    assert!(html.contains("non rattachées au référentiel"));
}

#[test]
fn la_table_renumerote_les_sections_sans_changer_le_dossier_sans_table() {
    // Sans table : numérotation historique, aucune section de table.
    let sans = render_html(&dossier_exemple());
    assert!(sans.contains("<h2>3. Interruptions"));
    assert!(sans.contains("<h2>6. Ce que ce dossier ne prouve pas"));
    assert!(!sans.contains("Table de correspondance"));
    // Avec table : elle est la section 3, les suivantes glissent d'un cran.
    let avec = render_html(&dossier_avec_table());
    assert!(avec.contains("<h2>3. Table de correspondance"));
    assert!(avec.contains("<h2>4. Interruptions"));
    assert!(avec.contains("<h2>7. Ce que ce dossier ne prouve pas"));
}

#[test]
fn le_dossier_avec_table_se_serialise_et_se_relit() {
    fn roundtrip(dossier: &EvidenceDossier) -> (Vec<u8>, EvidenceDossier) {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(dossier, &mut bytes).unwrap();
        let relu = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        (bytes, relu)
    }

    // Rétrocompatibilité serde : un dossier sérialisé SANS le champ
    // `correspondence` (format d'avant) se relit tel quel (default → None).
    let dossier = dossier_exemple();
    let (bytes, relu) = roundtrip(&dossier);
    let cle = b"correspondence";
    assert!(
        !bytes.windows(cle.len()).any(|w| w == cle),
        "None n'est pas sérialisé (skip_serializing_if) : l'encodage est celui d'avant"
    );
    assert_eq!(relu, dossier);

    // Et l'aller-retour complet avec la table.
    let dossier = dossier_avec_table();
    let (_, relu) = roundtrip(&dossier);
    assert_eq!(relu, dossier);
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
