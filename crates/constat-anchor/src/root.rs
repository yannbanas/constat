//! Export de racine — niveau 2 de l'ancrage (§6.3).
//!
//! Un document signé `{ racine, date, organisation }`, sérialisé
//! canoniquement, prêt à être envoyé **hors du système** : courriel au RSSI,
//! dépôt chez un tiers, impression au coffre. Le destinataire n'a besoin que
//! de la clé publique du journal pour vérifier le document, et n'a rien à
//! installer : c'est ce qui rend une troncature simple détectable — la
//! racine reçue hier doit apparaître dans la chaîne d'aujourd'hui.
//!
//! Rappel §6.2, noir sur blanc : **sans un tel ancrage externe, le journal
//! prouve la cohérence interne, pas la non-répudiation.**

use constat_model::{to_canonical_bytes, BlobHash, Timestamp};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::AnchorError;

/// Le document à ancrer : la racine du journal à une date, pour une
/// organisation. C'est l'encodage canonique de **cette structure** qui est
/// signé — pas une représentation textuelle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootExportDocument {
    /// Racine du journal : empreinte de la dernière entrée, signature incluse.
    pub root: BlobHash,
    /// Date de l'export (UTC, millisecondes Unix).
    pub at: Timestamp,
    /// Organisation concernée, en clair (le destinataire doit pouvoir lire
    /// le document sans outil).
    pub organization: String,
}

/// Le document accompagné de sa signature Ed25519 : l'objet qui part hors
/// du système.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRootExport {
    pub document: RootExportDocument,
    /// Signature Ed25519 (64 octets) de l'encodage canonique de `document`.
    pub signature: Vec<u8>,
}

impl SignedRootExport {
    /// Octets canoniques du document signé complet, prêts à être transmis
    /// (pièce jointe de courriel, dépôt tiers). Déterministes : mêmes
    /// données, mêmes octets.
    pub fn to_transport_bytes(&self) -> Result<Vec<u8>, AnchorError> {
        to_canonical_bytes(self).map_err(|e| AnchorError::Encoding(e.to_string()))
    }
}

/// Signe un document d'export de racine avec la clé du journal.
pub fn sign_root_export(
    document: RootExportDocument,
    key: &SigningKey,
) -> Result<SignedRootExport, AnchorError> {
    let message =
        to_canonical_bytes(&document).map_err(|e| AnchorError::Encoding(e.to_string()))?;
    let signature = key.sign(&message).to_bytes().to_vec();
    Ok(SignedRootExport {
        document,
        signature,
    })
}

/// Vérifie un export de racine reçu : la signature doit être celle de la clé
/// publique du journal, sur l'encodage canonique du document.
pub fn verify_root_export(
    export: &SignedRootExport,
    key: &VerifyingKey,
) -> Result<(), AnchorError> {
    let signature_bytes: [u8; 64] = export
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| AnchorError::BadSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let message =
        to_canonical_bytes(&export.document).map_err(|e| AnchorError::Encoding(e.to_string()))?;
    key.verify(&message, &signature)
        .map_err(|_| AnchorError::BadSignature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn document() -> RootExportDocument {
        RootExportDocument {
            root: BlobHash([0x42; 32]),
            at: Timestamp(1_775_120_400_000),
            organization: "Exemple SAS".to_owned(),
        }
    }

    #[test]
    fn aller_retour_signature_et_verification() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let signed = sign_root_export(document(), &key).unwrap();
        verify_root_export(&signed, &key.verifying_key()).unwrap();
    }

    #[test]
    fn un_document_modifie_est_refuse() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let mut signed = sign_root_export(document(), &key).unwrap();
        signed.document.root = BlobHash([0x43; 32]);
        assert!(verify_root_export(&signed, &key.verifying_key()).is_err());
    }

    #[test]
    fn une_autre_cle_est_refusee() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let autre = SigningKey::from_bytes(&[2u8; 32]);
        let signed = sign_root_export(document(), &key).unwrap();
        assert!(verify_root_export(&signed, &autre.verifying_key()).is_err());
    }

    #[test]
    fn les_octets_de_transport_sont_deterministes_et_relisibles() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let signed = sign_root_export(document(), &key).unwrap();
        let bytes = signed.to_transport_bytes().unwrap();
        assert_eq!(bytes, signed.to_transport_bytes().unwrap());
        let relu: SignedRootExport = constat_model::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(relu, signed);
        verify_root_export(&relu, &key.verifying_key()).unwrap();
    }
}
