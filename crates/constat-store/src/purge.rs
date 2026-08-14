//! Purge de rétention **journalisée** (§16) — extension ADDITIVE.
//!
//! > Une suppression liée à la rétention crée un trou dans les données, et un
//! > trou non déclaré est indistinguable d'un effacement malveillant. La purge
//! > doit donc écrire dans le journal **qu'elle a eu lieu**, sur quelle
//! > période et pour quel motif, sans réécrire la chaîne.
//!
//! # Le modèle : la purge est un constat comme un autre
//!
//! L'enregistrement de purge est un [`Blob`] du collecteur réservé
//! [`PURGE_COLLECTOR`] (`constat.purge`), référencé par un [`Snapshot`] de la
//! machine [`PURGE_ASSET`] (`constat`), lui-même référencé par une **nouvelle
//! entrée signée** du journal. Rien n'est réécrit : la chaîne existante reste
//! intacte au bit près, la déclaration s'ajoute à la fin, signée comme
//! n'importe quelle collecte.
//!
//! Contenu du blob (normatif — voir `crates/constat-verify/FORMAT.md`, § « Objets
//! purgés ») :
//!
//! - `raw` : un document texte lisible (date, motif, période, nombre
//!   d'objets, empreinte du manifeste) qui contient la **liste complète des
//!   empreintes purgées**, une par ligne, en hexadécimal minuscule (64
//!   caractères), triées ;
//! - `facts` : une entité `purge:<horodatage ms>` portant :
//!
//! | attribut | type | contenu |
//! |---|---|---|
//! | `purge.from` | `Int` | début de la période purgée (ms UTC) |
//! | `purge.to` | `Int` | fin de la période purgée (ms UTC) |
//! | `purge.reason` | `Text` | motif de la purge (une ligne) |
//! | `purge.objects` | `Int` | nombre d'objets purgés (snapshots + blobs) |
//! | `purge.manifest` | `Fingerprint` | BLAKE3 de la **liste canonique** des empreintes purgées |
//!
//! La liste canonique est le `Vec<BlobHash>` trié croissant et dédupliqué,
//! encodé en CBOR canonique ([`constat_model::to_canonical_bytes`]) ; le
//! manifeste est [`constat_model::hash_canonical`] de cette liste
//! ([`manifest_hash`]). La liste elle-même vit dans `raw` : le vérificateur
//! la relit, recalcule le manifeste et le compare au fait `purge.manifest` —
//! toute divergence invalide la déclaration.
//!
//! # Ce qui est purgé — et ce qui ne l'est jamais
//!
//! - **Purgés** : les snapshots dont `at < cutoff` référencés par le journal
//!   par défaut, et les blobs qui ne sont plus référencés par **aucun**
//!   snapshot conservé. Un blob dédupliqué encore référencé par un snapshot
//!   récent est conservé.
//! - **Jamais purgés** :
//!   - les **entrées de journal** — la chaîne est la preuve, elle ne rétrécit
//!     jamais ;
//!   - les **enregistrements de purge** eux-mêmes (blob `constat.purge` et son
//!     snapshot), quel que soit leur âge : les supprimer effacerait la
//!     déclaration dont les exports ont besoin pour rester vérifiables ;
//!   - les **enregistrements de rotation de clé** (blob `constat.rotation` et
//!     son snapshot, [`crate::rotation`]) : les supprimer rendrait la clé
//!     courante indéterminable, donc toute la suite de la chaîne
//!     invérifiable ;
//!   - tout objet atteignable depuis un **journal nommé** (multi-agents,
//!     [`crate::MultiJournalStore`]) : la purge ne déclare que dans le journal
//!     par défaut, elle n'a donc pas le droit de trouer les chaînes des autres
//!     signataires. Un magasin central multi-agents se purge journal par
//!     journal, côté serveur — hors du périmètre de ce module.
//!
//! # L'ordre des opérations : déclarer AVANT de supprimer
//!
//! [`execute_plan`] écrit d'abord la déclaration (blob, snapshot, entrée
//! signée), **puis** supprime. Si la suppression échoue à mi-chemin, le
//! magasin contient une déclaration qui couvre des objets encore présents —
//! parfaitement bénin (un objet présent et déclaré purgé se vérifie
//! normalement), et le rejeu suivant achève le nettoyage. L'ordre inverse
//! serait la faute impardonnable : des objets absents sans déclaration, soit
//! exactement la signature d'un effacement malveillant (§16, §12).
//!
//! Au sein de la suppression, les **blobs partent avant les snapshots** : si
//! elle s'interrompt, il reste des snapshots présents (replanifiables au rejeu
//! suivant) plutôt que des blobs orphelins injoignables.
//!
//! # Idempotence
//!
//! [`plan_purge`] ignore les objets déjà absents : rejouer une purge sur un
//! magasin déjà purgé ne trouve rien, n'écrit **aucune** entrée et retourne
//! `None`. Chaque entrée de purge du journal correspond donc à une purge qui a
//! réellement supprimé quelque chose.

use std::collections::{BTreeMap, BTreeSet};

use constat_model::{
    hash_canonical, to_canonical_bytes, Blob, BlobHash, CollectorId, Fact, ModelError, Snapshot,
    Timestamp, Value,
};

use crate::journal::append_signed;
use crate::{MultiJournalStore, PurgeableStore, Signer, Store, StoreError};

/// Collecteur réservé des enregistrements de purge. Aucun collecteur de
/// machine ne doit porter ce nom.
pub const PURGE_COLLECTOR: &str = "constat.purge";

/// Machine (asset) des snapshots de purge : l'outil lui-même, pas une machine
/// du parc.
pub const PURGE_ASSET: &str = "constat";

/// Attribut : début de la période purgée (ms UTC).
pub const ATTR_PURGE_FROM: &str = "purge.from";
/// Attribut : fin de la période purgée (ms UTC).
pub const ATTR_PURGE_TO: &str = "purge.to";
/// Attribut : motif de la purge.
pub const ATTR_PURGE_REASON: &str = "purge.reason";
/// Attribut : nombre d'objets purgés.
pub const ATTR_PURGE_OBJECTS: &str = "purge.objects";
/// Attribut : empreinte BLAKE3 de la liste canonique des empreintes purgées.
pub const ATTR_PURGE_MANIFEST: &str = "purge.manifest";

/// Erreur de lecture d'un blob de purge : la déclaration est malformée ou
/// incohérente. Un vérificateur qui rencontre cette erreur doit **refuser**
/// de tolérer les absences que ce blob prétendait couvrir.
#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    /// Le blob n'est pas du collecteur [`PURGE_COLLECTOR`].
    #[error("collecteur « {0} » au lieu de « {PURGE_COLLECTOR} »")]
    BadCollector(String),
    /// Un fait attendu est absent ou d'un type inattendu.
    #[error("fait {0} manquant ou mal typé")]
    MissingFact(&'static str),
    /// Un fait attendu apparaît plusieurs fois avec des valeurs distinctes.
    #[error("fait {0} en double")]
    DuplicateFact(&'static str),
    /// La déclaration est intérieurement incohérente (compte, manifeste,
    /// période) : elle ne couvre rien.
    #[error("déclaration incohérente : {0}")]
    Incoherent(String),
    /// Échec d'encodage canonique lors du recalcul du manifeste.
    #[error(transparent)]
    Model(#[from] ModelError),
}

/// Une déclaration de purge, décodée depuis un blob [`PURGE_COLLECTOR`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeDeclaration {
    /// Début de la période purgée (le `at` du plus ancien snapshot purgé).
    pub from: Timestamp,
    /// Fin de la période purgée (le `at` du plus récent snapshot purgé).
    pub to: Timestamp,
    /// Motif, tel que déclaré.
    pub reason: String,
    /// Nombre d'objets purgés (snapshots + blobs) — égal à `purged.len()`.
    pub objects: u64,
    /// BLAKE3 de la liste canonique des empreintes purgées ([`manifest_hash`]).
    pub manifest: BlobHash,
    /// Les empreintes purgées, triées croissant, dédupliquées.
    pub purged: Vec<BlobHash>,
}

/// Empreinte du manifeste : BLAKE3 de l'encodage CBOR canonique de la liste
/// **triée croissant et dédupliquée** des empreintes purgées.
///
/// C'est la « liste canonique » du fait `purge.manifest` : un vérificateur
/// indépendant trie et déduplique les empreintes relues du document brut,
/// les encode canoniquement (tableau de tableaux de 32 entiers) et hache le
/// résultat en BLAKE3.
pub fn manifest_hash(purged: &[BlobHash]) -> Result<BlobHash, ModelError> {
    let mut list = purged.to_vec();
    list.sort_unstable();
    list.dedup();
    hash_canonical(&list)
}

/// Date lisible pour le document brut : RFC 3339 quand la valeur le permet,
/// millisecondes brutes sinon (jamais d'échec pour un affichage).
fn readable(t: Timestamp) -> String {
    t.to_rfc3339().unwrap_or_else(|_| format!("{} ms", t.0))
}

/// Construit le blob de purge (document brut + faits) d'une déclaration.
///
/// `at` est l'horodatage de la purge elle-même : il nomme l'entité
/// (`purge:<ms>`) et date le document. Le motif est ramené à une seule ligne
/// (les sauts de ligne deviennent des espaces) : le document brut est ligne à
/// ligne, et la liste des empreintes ne doit jamais pouvoir être polluée.
pub fn build_purge_blob(declaration: &PurgeDeclaration, at: Timestamp) -> Blob {
    let reason: String = declaration
        .reason
        .replace(['\r', '\n'], " ")
        .trim()
        .to_string();

    let mut raw = String::new();
    raw.push_str("Purge de rétention — Constat\n");
    raw.push_str(&format!("Date : {} ({} ms)\n", readable(at), at.0));
    raw.push_str(&format!("Motif : {reason}\n"));
    raw.push_str(&format!(
        "Période purgée : {} → {} ({}..{} ms)\n",
        readable(declaration.from),
        readable(declaration.to),
        declaration.from.0,
        declaration.to.0
    ));
    raw.push_str(&format!("Objets purgés : {}\n", declaration.objects));
    raw.push_str(&format!(
        "Manifeste BLAKE3 (liste canonique) : {}\n",
        declaration.manifest.to_hex()
    ));
    raw.push('\n');
    raw.push_str("Empreintes purgées (une par ligne, triées) :\n");
    for hash in &declaration.purged {
        raw.push_str(&hash.to_hex());
        raw.push('\n');
    }

    let entity = format!("purge:{}", at.0);
    let facts = vec![
        Fact::new(entity.as_str(), ATTR_PURGE_FROM, declaration.from.0),
        Fact::new(entity.as_str(), ATTR_PURGE_TO, declaration.to.0),
        Fact::new(entity.as_str(), ATTR_PURGE_REASON, reason),
        // `objects` tient dans un i64 : c'est un compte d'objets d'un magasin.
        Fact::new(
            entity.as_str(),
            ATTR_PURGE_OBJECTS,
            declaration.objects as i64,
        ),
        Fact::new(
            entity.as_str(),
            ATTR_PURGE_MANIFEST,
            Value::Fingerprint(declaration.manifest.0),
        ),
    ];
    Blob::new(PURGE_COLLECTOR, raw.into_bytes(), facts)
}

/// Relit une déclaration de purge depuis un blob [`PURGE_COLLECTOR`] et
/// vérifie sa cohérence interne.
///
/// La liste des empreintes purgées est relue du document brut : toute ligne
/// composée d'exactement 64 caractères hexadécimaux minuscules (après
/// suppression des blancs de bordure) est une empreinte. La liste est ensuite
/// triée et dédupliquée, puis confrontée aux faits :
///
/// - `purge.objects` doit être égal au nombre d'empreintes ;
/// - `purge.manifest` doit être égal à [`manifest_hash`] de la liste ;
/// - `purge.from` ≤ `purge.to`.
///
/// # Erreurs
///
/// [`PurgeError`] si la déclaration est malformée ou incohérente — auquel cas
/// elle ne couvre **aucune** absence.
pub fn parse_purge_blob(blob: &Blob) -> Result<PurgeDeclaration, PurgeError> {
    if blob.collector.0 != PURGE_COLLECTOR {
        return Err(PurgeError::BadCollector(blob.collector.0.clone()));
    }

    fn set_once<T: PartialEq>(
        slot: &mut Option<T>,
        value: T,
        name: &'static str,
    ) -> Result<(), PurgeError> {
        match slot {
            Some(existing) if *existing == value => Ok(()),
            Some(_) => Err(PurgeError::DuplicateFact(name)),
            None => {
                *slot = Some(value);
                Ok(())
            }
        }
    }

    let mut from: Option<i64> = None;
    let mut to: Option<i64> = None;
    let mut reason: Option<String> = None;
    let mut objects: Option<i64> = None;
    let mut manifest: Option<[u8; 32]> = None;
    for fact in &blob.facts {
        match (fact.attribute.0.as_str(), &fact.value) {
            (ATTR_PURGE_FROM, Value::Int(v)) => set_once(&mut from, *v, ATTR_PURGE_FROM)?,
            (ATTR_PURGE_TO, Value::Int(v)) => set_once(&mut to, *v, ATTR_PURGE_TO)?,
            (ATTR_PURGE_REASON, Value::Text(v)) => {
                set_once(&mut reason, v.clone(), ATTR_PURGE_REASON)?
            }
            (ATTR_PURGE_OBJECTS, Value::Int(v)) => set_once(&mut objects, *v, ATTR_PURGE_OBJECTS)?,
            (ATTR_PURGE_MANIFEST, Value::Fingerprint(v)) => {
                set_once(&mut manifest, *v, ATTR_PURGE_MANIFEST)?
            }
            _ => {}
        }
    }
    let from = Timestamp(from.ok_or(PurgeError::MissingFact(ATTR_PURGE_FROM))?);
    let to = Timestamp(to.ok_or(PurgeError::MissingFact(ATTR_PURGE_TO))?);
    let reason = reason.ok_or(PurgeError::MissingFact(ATTR_PURGE_REASON))?;
    let objects = objects.ok_or(PurgeError::MissingFact(ATTR_PURGE_OBJECTS))?;
    let manifest = BlobHash(manifest.ok_or(PurgeError::MissingFact(ATTR_PURGE_MANIFEST))?);

    if from > to {
        return Err(PurgeError::Incoherent(format!(
            "période inversée : purge.from = {} > purge.to = {}",
            from.0, to.0
        )));
    }
    if objects < 0 {
        return Err(PurgeError::Incoherent(format!(
            "purge.objects négatif : {objects}"
        )));
    }

    // La liste des empreintes vit dans le document brut, une par ligne.
    let text = String::from_utf8_lossy(&blob.raw);
    let mut purged: Vec<BlobHash> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.len() == 64
            && line
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            purged.push(
                BlobHash::from_hex(line)
                    .map_err(|e| PurgeError::Incoherent(format!("empreinte illisible : {e}")))?,
            );
        }
    }
    purged.sort_unstable();
    purged.dedup();

    if purged.len() as i64 != objects {
        return Err(PurgeError::Incoherent(format!(
            "purge.objects = {objects} mais le document liste {} empreinte(s)",
            purged.len()
        )));
    }
    let computed = manifest_hash(&purged)?;
    if computed != manifest {
        return Err(PurgeError::Incoherent(format!(
            "manifeste annoncé {}, recalculé {}",
            manifest.to_hex(),
            computed.to_hex()
        )));
    }

    Ok(PurgeDeclaration {
        from,
        to,
        reason,
        objects: objects as u64,
        manifest,
        purged,
    })
}

/// Ce qu'une purge à un seuil donné supprimerait — calculé sans rien modifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgePlan {
    /// Le seuil : tout snapshot `at < cutoff` est candidat.
    pub cutoff: Timestamp,
    /// Snapshots à supprimer (présents dans le magasin), triés.
    pub snapshots: Vec<BlobHash>,
    /// Blobs à supprimer (présents, plus référencés par aucun snapshot
    /// conservé ni aucun journal nommé), triés.
    pub blobs: Vec<BlobHash>,
    /// Début de la période purgée : `at` du plus ancien snapshot du plan.
    pub from: Timestamp,
    /// Fin de la période purgée : `at` du plus récent snapshot du plan.
    pub to: Timestamp,
    /// Volume des blobs à supprimer, en octets canoniques (décompressés).
    pub blob_bytes: u64,
}

impl PurgePlan {
    /// Nombre total d'objets du plan (snapshots + blobs).
    pub fn object_count(&self) -> usize {
        self.snapshots.len() + self.blobs.len()
    }

    /// La liste canonique des empreintes du plan (triée, dédupliquée) — celle
    /// dont [`manifest_hash`] fait le manifeste.
    pub fn manifest_list(&self) -> Vec<BlobHash> {
        let mut list: Vec<BlobHash> = self
            .snapshots
            .iter()
            .chain(self.blobs.iter())
            .copied()
            .collect();
        list.sort_unstable();
        list.dedup();
        list
    }
}

/// Calcule ce qu'une purge au seuil `cutoff` supprimerait. **Ne modifie
/// rien** : c'est la moitié « lecture » de la purge, réutilisée par
/// `constat retention --check` et par le mode `--dry-run`.
///
/// Règles (voir la documentation du module) :
///
/// - candidats : snapshots du journal par défaut avec `at < cutoff`, hors
///   enregistrements de purge ([`PURGE_COLLECTOR`]) et de **rotation de
///   clé** ([`crate::rotation::ROTATION_COLLECTOR`]), encore présents ;
/// - conservés : tout snapshot restant, tout enregistrement de purge ou de
///   rotation, et toute la clôture des **journaux nommés** ;
/// - blobs supprimés : référencés uniquement par des snapshots candidats.
///
/// Retourne `None` si rien n'est à purger (rejouer une purge est sans effet).
pub fn plan_purge<S: MultiJournalStore + ?Sized>(
    store: &S,
    cutoff: Timestamp,
) -> Result<Option<PurgePlan>, StoreError> {
    let purge_collector = CollectorId(PURGE_COLLECTOR.to_string());
    let rotation_collector = CollectorId(crate::rotation::ROTATION_COLLECTOR.to_string());

    // 1. Clôture des journaux nommés : tout y est conservé — la purge ne
    //    déclare que dans le journal par défaut (voir le rustdoc du module).
    let mut kept_snapshots: BTreeSet<BlobHash> = BTreeSet::new();
    let mut kept_blobs: BTreeSet<BlobHash> = BTreeSet::new();
    for journal in store.journals()? {
        for (_, entry) in store.entries_of(&journal)? {
            for snapshot_hash in &entry.snapshots {
                if !store.has_snapshot(snapshot_hash)? {
                    continue;
                }
                kept_snapshots.insert(*snapshot_hash);
                let snapshot = store.get_snapshot(snapshot_hash)?;
                kept_blobs.extend(snapshot.blobs.values().copied());
            }
        }
    }

    // 2. Journal par défaut : classement conservé / candidat.
    let mut candidates: BTreeMap<BlobHash, Snapshot> = BTreeMap::new();
    for (_, entry) in store.entries()? {
        for snapshot_hash in &entry.snapshots {
            if kept_snapshots.contains(snapshot_hash) || candidates.contains_key(snapshot_hash) {
                continue;
            }
            if !store.has_snapshot(snapshot_hash)? {
                // Déjà purgé (et déclaré) lors d'une purge antérieure.
                continue;
            }
            let snapshot = store.get_snapshot(snapshot_hash)?;
            // Jamais purgés : les enregistrements de purge (la déclaration
            // dont les exports ont besoin) et les enregistrements de
            // ROTATION — purger une rotation rendrait la clé courante
            // indéterminable, donc toute la suite de la chaîne invérifiable.
            let is_reserved_record = snapshot.blobs.contains_key(&purge_collector)
                || snapshot.blobs.contains_key(&rotation_collector);
            if snapshot.at < cutoff && !is_reserved_record {
                candidates.insert(*snapshot_hash, snapshot);
            } else {
                kept_snapshots.insert(*snapshot_hash);
                kept_blobs.extend(snapshot.blobs.values().copied());
            }
        }
    }
    if candidates.is_empty() {
        return Ok(None);
    }

    // 3. Blobs : supprimés seulement s'ils ne sont référencés par AUCUN
    //    snapshot conservé (déduplication : un blob partagé est conservé).
    let mut purge_blobs: BTreeSet<BlobHash> = BTreeSet::new();
    for snapshot in candidates.values() {
        for blob_hash in snapshot.blobs.values() {
            if !kept_blobs.contains(blob_hash) && store.has_blob(blob_hash)? {
                purge_blobs.insert(*blob_hash);
            }
        }
    }

    // 4. Période déclarée et volume.
    // `candidates` est non vide : min/max existent.
    let from = candidates
        .values()
        .map(|s| s.at)
        .min()
        .unwrap_or(Timestamp(0));
    let to = candidates
        .values()
        .map(|s| s.at)
        .max()
        .unwrap_or(Timestamp(0));
    let mut blob_bytes: u64 = 0;
    for blob_hash in &purge_blobs {
        let blob = store.get_blob(blob_hash)?;
        blob_bytes += to_canonical_bytes(&blob)?.len() as u64;
    }

    Ok(Some(PurgePlan {
        cutoff,
        snapshots: candidates.keys().copied().collect(),
        blobs: purge_blobs.into_iter().collect(),
        from,
        to,
        blob_bytes,
    }))
}

/// Le compte rendu d'une purge exécutée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    /// Début de la période purgée.
    pub from: Timestamp,
    /// Fin de la période purgée.
    pub to: Timestamp,
    /// Motif déclaré.
    pub reason: String,
    /// Nombre de snapshots supprimés.
    pub snapshots_purged: usize,
    /// Nombre de blobs supprimés.
    pub blobs_purged: usize,
    /// Empreinte du manifeste ([`manifest_hash`] de la liste canonique).
    pub manifest: BlobHash,
    /// Empreinte du blob de déclaration (`constat.purge`).
    pub declaration_blob: BlobHash,
    /// Nouvelle racine du journal : l'empreinte de l'entrée de purge.
    pub root: BlobHash,
}

/// Exécute un plan de purge : **déclare d'abord, supprime ensuite**.
///
/// 1. Écrit le blob de déclaration ([`build_purge_blob`]), son snapshot
///    (machine [`PURGE_ASSET`], daté `at`) et une **nouvelle entrée signée**
///    du journal par défaut — la chaîne n'est jamais réécrite.
/// 2. Supprime les blobs du plan, puis les snapshots.
///
/// Si la suppression échoue à mi-chemin, la déclaration existe déjà : les
/// objets encore présents restent vérifiables, et le rejeu suivant achève le
/// nettoyage. Voir le rustdoc du module pour la justification de cet ordre.
pub fn execute_plan<S: PurgeableStore + ?Sized>(
    store: &mut S,
    signer: &Signer,
    plan: &PurgePlan,
    reason: &str,
    at: Timestamp,
) -> Result<PurgeReport, StoreError> {
    let purged = plan.manifest_list();
    let manifest = manifest_hash(&purged)?;
    let declaration = PurgeDeclaration {
        from: plan.from,
        to: plan.to,
        reason: reason.to_string(),
        objects: purged.len() as u64,
        manifest,
        purged,
    };

    // 1. La déclaration, AVANT toute suppression.
    let blob = build_purge_blob(&declaration, at);
    let declaration_blob = store.put_blob(&blob)?;
    let snapshot = Snapshot::new(
        PURGE_ASSET,
        at,
        BTreeMap::from([(CollectorId(PURGE_COLLECTOR.to_string()), declaration_blob)]),
    );
    let snapshot_hash = store.put_snapshot(&snapshot)?;
    let (root, _) = append_signed(store, signer, vec![snapshot_hash], at)?;

    // 2. La suppression : blobs d'abord, snapshots ensuite (voir le module).
    for hash in &plan.blobs {
        store.delete_blob(hash)?;
    }
    for hash in &plan.snapshots {
        store.delete_snapshot(hash)?;
    }

    Ok(PurgeReport {
        from: plan.from,
        to: plan.to,
        reason: declaration.reason,
        snapshots_purged: plan.snapshots.len(),
        blobs_purged: plan.blobs.len(),
        manifest,
        declaration_blob,
        root,
    })
}

/// Purge de rétention journalisée : supprime les objets antérieurs à `cutoff`
/// et **déclare la purge dans une nouvelle entrée signée** du journal (§16).
///
/// Enchaîne [`plan_purge`] et [`execute_plan`] ; `at` date la déclaration
/// (l'horloge est fournie par l'appelant — ce crate reste déterministe et
/// testable). Retourne `None` si rien n'était à purger : dans ce cas **rien
/// n'est écrit** — rejouer une purge est idempotent.
///
/// ```
/// use constat_model::Timestamp;
/// use constat_store::{purge_older_than, MemoryStore, Signer};
///
/// let mut store = MemoryStore::new();
/// let signer = Signer::generate();
/// // Magasin vide : rien à purger, rien n'est écrit.
/// let report = purge_older_than(&mut store, &signer, Timestamp(1), "rétention", Timestamp(2))?;
/// assert!(report.is_none());
/// # Ok::<(), constat_store::StoreError>(())
/// ```
pub fn purge_older_than<S: PurgeableStore + ?Sized>(
    store: &mut S,
    signer: &Signer,
    cutoff: Timestamp,
    reason: &str,
    at: Timestamp,
) -> Result<Option<PurgeReport>, StoreError> {
    match plan_purge(store, cutoff)? {
        Some(plan) => execute_plan(store, signer, &plan, reason, at).map(Some),
        None => Ok(None),
    }
}

/// L'ensemble des empreintes déclarées purgées par les enregistrements de
/// purge atteignables depuis `entries` (blobs [`PURGE_COLLECTOR`] présents
/// dans le magasin).
///
/// C'est ce que l'export utilise pour tolérer les absences **déclarées** —
/// et seulement elles. Une déclaration malformée est une erreur
/// ([`StoreError::Encoding`]) : on n'exporte pas une preuve dont la
/// tolérance repose sur un document illisible.
pub fn declared_purged<S: Store + ?Sized>(
    store: &S,
    entries: &[(BlobHash, crate::JournalEntry)],
) -> Result<BTreeSet<BlobHash>, StoreError> {
    let purge_collector = CollectorId(PURGE_COLLECTOR.to_string());
    let mut declared = BTreeSet::new();
    let mut seen_blobs = BTreeSet::new();
    for (_, entry) in entries {
        for snapshot_hash in &entry.snapshots {
            if !store.has_snapshot(snapshot_hash)? {
                continue;
            }
            let snapshot = store.get_snapshot(snapshot_hash)?;
            let Some(blob_hash) = snapshot.blobs.get(&purge_collector) else {
                continue;
            };
            if !seen_blobs.insert(*blob_hash) || !store.has_blob(blob_hash)? {
                continue;
            }
            let blob = store.get_blob(blob_hash)?;
            let declaration = parse_purge_blob(&blob).map_err(|e| {
                StoreError::Encoding(format!(
                    "déclaration de purge illisible (blob {}) : {e}",
                    blob_hash.to_hex()
                ))
            })?;
            declared.extend(declaration.purged);
        }
    }
    Ok(declared)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn declaration() -> PurgeDeclaration {
        let purged = {
            let mut v = vec![BlobHash([0x22; 32]), BlobHash([0x11; 32])];
            v.sort_unstable();
            v
        };
        PurgeDeclaration {
            from: Timestamp(1_000),
            to: Timestamp(2_000),
            reason: "rétention 3 ans".to_string(),
            objects: 2,
            manifest: manifest_hash(&purged).unwrap(),
            purged,
        }
    }

    /// Aller-retour : le blob construit se relit à l'identique.
    #[test]
    fn aller_retour_du_blob_de_purge() {
        let decl = declaration();
        let blob = build_purge_blob(&decl, Timestamp(3_000));
        assert_eq!(blob.collector.0, PURGE_COLLECTOR);
        let relu = parse_purge_blob(&blob).unwrap();
        assert_eq!(relu, decl);
    }

    /// Le manifeste est insensible à l'ordre et aux doublons de la liste.
    #[test]
    fn manifeste_canonique() {
        let a = BlobHash([1; 32]);
        let b = BlobHash([2; 32]);
        assert_eq!(
            manifest_hash(&[a, b]).unwrap(),
            manifest_hash(&[b, a, b]).unwrap()
        );
        assert_ne!(manifest_hash(&[a]).unwrap(), manifest_hash(&[b]).unwrap());
    }

    /// Une empreinte retirée du document invalide la déclaration : le compte
    /// et le manifeste ne collent plus.
    #[test]
    fn document_ampute_refuse() {
        let decl = declaration();
        let mut blob = build_purge_blob(&decl, Timestamp(3_000));
        let text = String::from_utf8(blob.raw.clone()).unwrap();
        let hex = decl.purged[0].to_hex();
        blob.raw = text.replacen(&format!("{hex}\n"), "", 1).into_bytes();
        assert!(matches!(
            parse_purge_blob(&blob),
            Err(PurgeError::Incoherent(_))
        ));
    }

    /// Un motif multi-lignes ne peut pas injecter d'empreinte dans la liste.
    #[test]
    fn motif_multiligne_assaini() {
        let mut decl = declaration();
        decl.reason = format!("motif\n{}", BlobHash([0x33; 32]).to_hex());
        let blob = build_purge_blob(&decl, Timestamp(3_000));
        // La déclaration reste cohérente : l'empreinte du motif a été
        // neutralisée (motif sur une ligne), la liste n'a pas bougé.
        let relu = parse_purge_blob(&blob).unwrap();
        assert_eq!(relu.purged, decl.purged);
        assert!(!relu.reason.contains('\n'));
    }

    /// Un blob d'un autre collecteur est refusé d'emblée.
    #[test]
    fn collecteur_etranger_refuse() {
        let mut blob = build_purge_blob(&declaration(), Timestamp(3_000));
        blob.collector = CollectorId("linux.sshd".to_string());
        assert!(matches!(
            parse_purge_blob(&blob),
            Err(PurgeError::BadCollector(_))
        ));
    }
}
