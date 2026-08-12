//! Signature Ed25519 des entrées du journal.
//!
//! ## Schéma de signature — contrat inter-crates, stable au bit près
//!
//! `constat-verify` réimplémente exactement ce schéma :
//!
//! 1. **octets signables** d'une entrée = `constat_model::to_canonical_bytes`
//!    de la [`JournalEntry`] avec le champ `signature` **vidé** (`vec![]`) ;
//! 2. **signature** = Ed25519 (ed25519-dalek) sur ces octets ;
//! 3. **empreinte** de l'entrée (le maillon `prev` du chaînage) =
//!    `constat_model::hash_canonical` de l'entrée **complète**, signature incluse.

use constat_model::{BlobHash, Timestamp};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::journal::signable_bytes;
use crate::{JournalEntry, StoreError};

/// Longueur en octets d'une clé de signature sérialisée.
pub const KEY_LENGTH: usize = 32;

/// Clé de signature du journal (Ed25519).
///
/// La clé privée ne sort de cette struct que par [`Signer::to_bytes`] —
/// à stocker avec les précautions d'usage. Le `Debug` n'affiche que la
/// clé publique.
///
/// ```
/// use constat_model::Timestamp;
/// use constat_store::Signer;
///
/// let signer = Signer::generate();
/// // Sérialisation / rechargement : même clé publique.
/// let reloaded = Signer::from_bytes(&signer.to_bytes());
/// assert_eq!(signer.verifying_key(), reloaded.verifying_key());
///
/// let entry = signer.sign_entry(None, vec![], Timestamp(0))?;
/// assert_eq!(entry.signature.len(), 64);
/// # Ok::<(), constat_store::StoreError>(())
/// ```
pub struct Signer {
    key: SigningKey,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("verifying_key", &self.key.verifying_key())
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Génère une nouvelle clé aléatoire (CSPRNG du système).
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Recharge une clé depuis ses 32 octets (voir [`Signer::to_bytes`]).
    pub fn from_bytes(bytes: &[u8; KEY_LENGTH]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
        }
    }

    /// Recharge une clé depuis une tranche d'octets de longueur quelconque.
    ///
    /// # Erreurs
    /// [`StoreError::Encoding`] si la tranche ne fait pas exactement 32 octets.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, StoreError> {
        let arr: [u8; KEY_LENGTH] = bytes.try_into().map_err(|_| {
            StoreError::Encoding(format!(
                "clé de signature : {} octets reçus, {KEY_LENGTH} attendus",
                bytes.len()
            ))
        })?;
        Ok(Self::from_bytes(&arr))
    }

    /// Sérialise la clé privée (32 octets). À protéger.
    pub fn to_bytes(&self) -> [u8; KEY_LENGTH] {
        self.key.to_bytes()
    }

    /// Clé publique de vérification, à distribuer aux vérificateurs.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Construit et signe une entrée du journal selon le schéma du module.
    ///
    /// `prev` est l'empreinte de la dernière entrée (`None` pour la genèse) —
    /// voir [`crate::journal::append_signed`] qui la détermine automatiquement.
    pub fn sign_entry(
        &self,
        prev: Option<BlobHash>,
        snapshots: Vec<BlobHash>,
        at: Timestamp,
    ) -> Result<JournalEntry, StoreError> {
        let mut entry = JournalEntry {
            prev,
            snapshots,
            at,
            signature: Vec::new(),
        };
        let bytes = signable_bytes(&entry)?;
        entry.signature = self.key.sign(&bytes).to_bytes().to_vec();
        Ok(entry)
    }
}
