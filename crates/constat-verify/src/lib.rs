//! # constat-verify — le vérificateur autonome (§10.3)
//!
//! > **La vérification doit être possible sans Constat.**
//!
//! Si contrôler un dossier exige de faire confiance à l'outil qui l'a produit,
//! ce n'est pas une preuve, c'est une déclaration. Ce crate est donc minuscule,
//! pur (aucune entrée-sortie dans la bibliothèque), et ne dépend que de
//! `constat-model`, `constat-store` et `ed25519-dalek` (règle §8). L'algorithme
//! complet est documenté dans `FORMAT.md`, à côté de ce fichier, assez
//! simplement pour être réimplémenté en une centaine de lignes par un auditeur
//! méfiant.
//!
//! ## Ce que la vérification établit
//!
//! À partir d'un export (entrées de journal + snapshots + blobs + clé
//! publique), [`verify_export`] :
//!
//! 1. recalcule l'empreinte BLAKE3 de chaque snapshot et de chaque blob
//!    fournis, et la compare à l'empreinte annoncée (le nom du fichier) ;
//! 2. vérifie le chaînage `prev` de la genèse (entrée 0, `prev` absent)
//!    jusqu'à la dernière entrée : `prev` de l'entrée *i* doit être
//!    l'empreinte de l'entrée *i − 1* complète (signature incluse) ;
//! 3. vérifie la signature Ed25519 de chaque entrée : la signature porte sur
//!    l'encodage canonique de l'entrée **avec le champ `signature` vidé** ;
//! 4. vérifie que chaque snapshot référencé par une entrée, et chaque blob
//!    référencé par un snapshot, est présent dans l'export.
//!
//! Le résultat est structuré : [`VerifiedExport`] avec la racine (empreinte de
//! la dernière entrée) en cas de succès, ou [`VerifyError`] désignant
//! précisément l'entrée et la vérification qui a échoué.
//!
//! ## Ce que la vérification n'établit PAS (§6.2)
//!
//! **Sans ancrage externe, le journal prouve la cohérence interne, pas la
//! non-répudiation.** Celui qui contrôle le magasin et la clé de signature
//! peut supprimer la fin du journal, ou tout effacer et repartir de zéro,
//! sans que ce vérificateur puisse le voir. La racine doit donc être comparée
//! à une racine ancrée hors du système (courriel au RSSI, jeton d'horodatage
//! RFC 3161 — voir `constat-anchor`).
//!
//! ## Layout d'export attendu par le binaire
//!
//! Voir `FORMAT.md` pour la définition normative. En résumé :
//!
//! ```text
//! export/
//! ├── pubkey.bin          # 32 octets bruts : clé publique Ed25519
//! ├── 0.cbor              # entrée 0 (genèse), CBOR canonique
//! ├── 1.cbor … N.cbor     # entrées suivantes, indices consécutifs sans trou
//! ├── snapshots/
//! │   └── <hex>.cbor      # un snapshot par fichier, nommé par son empreinte
//! └── blobs/
//!     └── <hex>.cbor      # un blob par fichier, nommé par son empreinte
//! ```

use std::collections::BTreeMap;
use std::fmt;

use constat_model::{hash_canonical, to_canonical_bytes, Blob, BlobHash, CollectorId, Snapshot};
use constat_store::JournalEntry;
use ed25519_dalek::{Signature, VerifyingKey};

/// Un export complet, déjà décodé, prêt à être vérifié.
///
/// Les clés des tables `snapshots` et `blobs` sont les empreintes **annoncées**
/// (dans le layout sur disque : le nom hexadécimal du fichier). La vérification
/// recalcule chaque empreinte et la compare à la clé — c'est ce qui détecte un
/// fichier altéré.
#[derive(Debug, Clone)]
pub struct Export {
    /// Entrées du journal, dans l'ordre : la genèse en premier.
    pub entries: Vec<JournalEntry>,
    /// Snapshots fournis, indexés par empreinte annoncée.
    pub snapshots: BTreeMap<BlobHash, Snapshot>,
    /// Blobs fournis, indexés par empreinte annoncée.
    pub blobs: BTreeMap<BlobHash, Blob>,
    /// Clé publique Ed25519 (32 octets) du signataire du journal.
    pub public_key: [u8; 32],
}

/// Résultat d'une vérification réussie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedExport {
    /// La racine : empreinte de la dernière entrée du journal, signature
    /// incluse. C'est cette valeur qu'il faut comparer à une racine ancrée
    /// hors du système (§6.3).
    pub root: BlobHash,
    /// Nombre d'entrées vérifiées.
    pub entry_count: usize,
    /// Nombre de snapshots fournis (tous vérifiés contre leur empreinte).
    pub snapshot_count: usize,
    /// Nombre de blobs fournis (tous vérifiés contre leur empreinte).
    pub blob_count: usize,
}

/// Échec de vérification : désigne précisément l'objet et la vérification en
/// cause. Chaque variant correspond à une étape de l'algorithme de `FORMAT.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// L'export ne contient aucune entrée de journal.
    ExportVide,
    /// La clé publique fournie n'est pas un point Ed25519 valide.
    ClePubliqueInvalide,
    /// Échec d'encodage canonique (ne devrait jamais arriver sur des données
    /// décodables ; signalé plutôt qu'ignoré).
    Encodage { detail: String },
    /// L'entrée 0 (genèse) déclare une entrée précédente : la chaîne ne
    /// commence pas au début.
    GeneseInvalide { prev: BlobHash },
    /// Le champ `prev` de l'entrée `index` ne correspond pas à l'empreinte
    /// recalculée de l'entrée précédente : chaîne rompue (entrée modifiée,
    /// insérée ou supprimée en amont).
    ChaineRompue {
        index: usize,
        attendu: Option<BlobHash>,
        trouve: Option<BlobHash>,
    },
    /// La signature de l'entrée `index` n'a pas la taille d'une signature
    /// Ed25519 (64 octets).
    SignatureMalformee { index: usize, longueur: usize },
    /// La signature Ed25519 de l'entrée `index` est invalide pour la clé
    /// publique fournie : l'entrée a été modifiée ou signée par une autre clé.
    SignatureInvalide { index: usize },
    /// L'entrée `index` référence un snapshot absent de l'export.
    SnapshotManquant { index: usize, hash: BlobHash },
    /// Un snapshot fourni ne correspond pas à son empreinte annoncée :
    /// le fichier a été altéré.
    SnapshotAltere {
        annonce: BlobHash,
        calcule: BlobHash,
    },
    /// Le snapshot `snapshot` référence, pour le collecteur `collecteur`,
    /// un blob absent de l'export.
    BlobManquant {
        snapshot: BlobHash,
        collecteur: CollectorId,
        hash: BlobHash,
    },
    /// Un blob fourni ne correspond pas à son empreinte annoncée :
    /// le fichier a été altéré.
    BlobAltere {
        annonce: BlobHash,
        calcule: BlobHash,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::ExportVide => {
                write!(f, "l'export ne contient aucune entrée de journal")
            }
            VerifyError::ClePubliqueInvalide => {
                write!(f, "la clé publique n'est pas une clé Ed25519 valide")
            }
            VerifyError::Encodage { detail } => {
                write!(f, "échec d'encodage canonique : {detail}")
            }
            VerifyError::GeneseInvalide { prev } => write!(
                f,
                "entrée 0 (genèse) : déclare une entrée précédente ({}) alors \
                 que la chaîne doit commencer sans prédécesseur — l'export ne \
                 commence pas au début du journal",
                prev.to_hex()
            ),
            VerifyError::ChaineRompue {
                index,
                attendu,
                trouve,
            } => write!(
                f,
                "entrée {index} : chaîne rompue — empreinte précédente attendue {}, trouvée {}",
                opt_hex(attendu),
                opt_hex(trouve)
            ),
            VerifyError::SignatureMalformee { index, longueur } => write!(
                f,
                "entrée {index} : signature malformée ({longueur} octets au lieu de 64)"
            ),
            VerifyError::SignatureInvalide { index } => write!(
                f,
                "entrée {index} : signature Ed25519 invalide pour la clé publique fournie"
            ),
            VerifyError::SnapshotManquant { index, hash } => write!(
                f,
                "entrée {index} : le snapshot {} est référencé mais absent de l'export",
                hash.to_hex()
            ),
            VerifyError::SnapshotAltere { annonce, calcule } => write!(
                f,
                "snapshot altéré : empreinte annoncée {}, empreinte recalculée {}",
                annonce.to_hex(),
                calcule.to_hex()
            ),
            VerifyError::BlobManquant {
                snapshot,
                collecteur,
                hash,
            } => write!(
                f,
                "snapshot {} : le blob {} (collecteur « {} ») est référencé \
                 mais absent de l'export",
                snapshot.to_hex(),
                hash.to_hex(),
                collecteur.0
            ),
            VerifyError::BlobAltere { annonce, calcule } => write!(
                f,
                "blob altéré : empreinte annoncée {}, empreinte recalculée {}",
                annonce.to_hex(),
                calcule.to_hex()
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

fn opt_hex(h: &Option<BlobHash>) -> String {
    match h {
        Some(h) => h.to_hex(),
        None => "(aucune)".to_owned(),
    }
}

/// Vérifie un export complet. Voir la documentation du crate et `FORMAT.md`
/// pour l'algorithme exact.
///
/// Fonction pure : aucune entrée-sortie. Le chargement des fichiers est
/// l'affaire du binaire `constat-verify`.
///
/// # Erreurs
///
/// Renvoie le **premier** échec rencontré, dans l'ordre de l'algorithme :
/// intégrité des snapshots fournis, intégrité des blobs fournis, puis pour
/// chaque entrée de la genèse à la racine : chaînage, signature, présence des
/// snapshots référencés et des blobs qu'ils référencent.
pub fn verify_export(export: &Export) -> Result<VerifiedExport, VerifyError> {
    if export.entries.is_empty() {
        return Err(VerifyError::ExportVide);
    }

    let key = VerifyingKey::from_bytes(&export.public_key)
        .map_err(|_| VerifyError::ClePubliqueInvalide)?;

    // Étape 1 — chaque snapshot fourni correspond à son empreinte annoncée.
    for (annonce, snapshot) in &export.snapshots {
        let calcule = hash_canonical(snapshot).map_err(encodage)?;
        if calcule != *annonce {
            return Err(VerifyError::SnapshotAltere {
                annonce: *annonce,
                calcule,
            });
        }
    }

    // Étape 2 — chaque blob fourni correspond à son empreinte annoncée.
    for (annonce, blob) in &export.blobs {
        let calcule = hash_canonical(blob).map_err(encodage)?;
        if calcule != *annonce {
            return Err(VerifyError::BlobAltere {
                annonce: *annonce,
                calcule,
            });
        }
    }

    // Étape 3 — chaînage, signatures, références, de la genèse à la racine.
    let mut prev: Option<BlobHash> = None;
    for (index, entry) in export.entries.iter().enumerate() {
        // 3a. Chaînage `prev`.
        if entry.prev != prev {
            return match (index, entry.prev) {
                (0, Some(p)) => Err(VerifyError::GeneseInvalide { prev: p }),
                _ => Err(VerifyError::ChaineRompue {
                    index,
                    attendu: prev,
                    trouve: entry.prev,
                }),
            };
        }

        // 3b. Signature Ed25519 sur l'encodage canonique de l'entrée avec le
        // champ `signature` vidé (contrat partagé avec constat-store).
        let sig_bytes: [u8; 64] =
            entry
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::SignatureMalformee {
                    index,
                    longueur: entry.signature.len(),
                })?;
        let signature = Signature::from_bytes(&sig_bytes);
        let non_signee = JournalEntry {
            prev: entry.prev,
            snapshots: entry.snapshots.clone(),
            at: entry.at,
            signature: Vec::new(),
        };
        let message = to_canonical_bytes(&non_signee).map_err(encodage)?;
        key.verify_strict(&message, &signature)
            .map_err(|_| VerifyError::SignatureInvalide { index })?;

        // 3c. Chaque snapshot référencé est présent, et chaque blob qu'il
        // référence l'est aussi (leur intégrité a été vérifiée aux étapes 1-2).
        for hash in &entry.snapshots {
            let snapshot = export
                .snapshots
                .get(hash)
                .ok_or(VerifyError::SnapshotManquant { index, hash: *hash })?;
            for (collecteur, blob_hash) in &snapshot.blobs {
                if !export.blobs.contains_key(blob_hash) {
                    return Err(VerifyError::BlobManquant {
                        snapshot: *hash,
                        collecteur: collecteur.clone(),
                        hash: *blob_hash,
                    });
                }
            }
        }

        // 3d. L'empreinte de l'entrée COMPLÈTE (signature incluse) chaîne
        // l'entrée suivante.
        prev = Some(hash_canonical(entry).map_err(encodage)?);
    }

    match prev {
        Some(root) => Ok(VerifiedExport {
            root,
            entry_count: export.entries.len(),
            snapshot_count: export.snapshots.len(),
            blob_count: export.blobs.len(),
        }),
        // Impossible : entries est non vide, la boucle a affecté `prev`.
        None => Err(VerifyError::ExportVide),
    }
}

fn encodage(e: constat_model::ModelError) -> VerifyError {
    VerifyError::Encodage {
        detail: e.to_string(),
    }
}
