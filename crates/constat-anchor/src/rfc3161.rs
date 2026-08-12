//! Horodatage qualifié RFC 3161 — niveau 3 de l'ancrage (§6.3).
//!
//! Encodage **pur** de la `TimeStampReq` (DER) et décodage **minimal** de la
//! `TimeStampResp` : statut et jeton opaque, conservé tel quel. Le jeton
//! (`TimeStampToken`, une structure CMS signée par le prestataire) n'est
//! jamais interprété ici — il se vérifie avec les outils standard
//! (`openssl ts -verify`) ou chez le prestataire, et c'est très bien ainsi :
//! moins ce crate interprète, plus la preuve est solide.
//!
//! **Aucun transport ici** : la requête produite par
//! [`TimeStampRequest::to_der`] s'envoie en HTTP POST
//! (`Content-Type: application/timestamp-query`) par le binaire appelant ;
//! la réponse (`application/timestamp-reply`) se décode avec
//! [`parse_response`].
//!
//! Rappel §6.2 : sans cet ancrage (ou l'export de racine du module
//! [`crate::root`]), le journal prouve la cohérence interne, pas la
//! non-répudiation.
//!
//! ## Structures ASN.1 concernées (RFC 3161, §2.4)
//!
//! ```text
//! TimeStampReq ::= SEQUENCE {
//!     version        INTEGER { v1(1) },
//!     messageImprint MessageImprint,
//!     reqPolicy      TSAPolicyId  OPTIONAL,   -- non émis
//!     nonce          INTEGER      OPTIONAL,
//!     certReq        BOOLEAN      DEFAULT FALSE,
//!     extensions [0] IMPLICIT Extensions OPTIONAL }  -- non émis
//!
//! MessageImprint ::= SEQUENCE {
//!     hashAlgorithm  AlgorithmIdentifier,     -- SHA-256
//!     hashedMessage  OCTET STRING }
//!
//! TimeStampResp ::= SEQUENCE {
//!     status         PKIStatusInfo,
//!     timeStampToken TimeStampToken OPTIONAL }
//!
//! PKIStatusInfo ::= SEQUENCE {
//!     status       INTEGER,
//!     statusString PKIFreeText OPTIONAL,      -- SEQUENCE OF UTF8String
//!     failInfo     PKIFailureInfo OPTIONAL }  -- BIT STRING
//! ```

use crate::der::{
    boolean, decode_integer_u64, integer_u64, tlv, Reader, TAG_BIT_STRING, TAG_INTEGER, TAG_NULL,
    TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_UTF8_STRING,
};
use crate::AnchorError;
use constat_model::BlobHash;
use sha2::{Digest, Sha256};

/// OID 2.16.840.1.101.3.4.2.1 (SHA-256), TLV DER complet.
const SHA256_OID_TLV: [u8; 11] = [
    TAG_OID, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

/// SHA-256 d'un message. Les prestataires RFC 3161 exigent un algorithme
/// normalisé : la racine BLAKE3 du journal est donc elle-même hachée en
/// SHA-256 avant d'être horodatée.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Une requête d'horodatage à construire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampRequest {
    /// Le digest SHA-256 du message à horodater.
    pub digest_sha256: [u8; 32],
    /// Nonce anti-rejeu, recommandé en production (tirage aléatoire par
    /// l'appelant : ce crate est pur et ne tire rien).
    pub nonce: Option<u64>,
    /// Demander au prestataire d'inclure son certificat dans le jeton
    /// (recommandé : le jeton reste vérifiable seul, des années plus tard).
    pub cert_req: bool,
}

impl TimeStampRequest {
    /// Requête d'horodatage pour une racine de journal : le digest est le
    /// SHA-256 des 32 octets de la racine BLAKE3. Certificat demandé,
    /// pas de nonce (à ajouter par l'appelant s'il le souhaite).
    pub fn for_root(root: &BlobHash) -> Self {
        TimeStampRequest {
            digest_sha256: sha256(&root.0),
            nonce: None,
            cert_req: true,
        }
    }

    /// Encode la `TimeStampReq` en DER, prête à être envoyée en HTTP POST
    /// avec `Content-Type: application/timestamp-query`.
    pub fn to_der(&self) -> Vec<u8> {
        // AlgorithmIdentifier ::= SEQUENCE { OID sha256, NULL }
        let mut alg = Vec::new();
        alg.extend_from_slice(&SHA256_OID_TLV);
        alg.extend_from_slice(&tlv(TAG_NULL, &[]));
        let algorithm = tlv(TAG_SEQUENCE, &alg);

        // MessageImprint ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
        let mut imprint = algorithm;
        imprint.extend_from_slice(&tlv(TAG_OCTET_STRING, &self.digest_sha256));
        let message_imprint = tlv(TAG_SEQUENCE, &imprint);

        // TimeStampReq ::= SEQUENCE { version, messageImprint, [nonce], [certReq] }
        let mut body = integer_u64(1);
        body.extend_from_slice(&message_imprint);
        if let Some(nonce) = self.nonce {
            body.extend_from_slice(&integer_u64(nonce));
        }
        if self.cert_req {
            // DEFAULT FALSE : en DER, la valeur par défaut ne s'encode pas.
            body.extend_from_slice(&boolean(true));
        }
        tlv(TAG_SEQUENCE, &body)
    }
}

/// Statut PKI d'une réponse (RFC 3161 §2.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiStatus {
    /// 0 — jeton délivré.
    Granted,
    /// 1 — jeton délivré, avec modifications.
    GrantedWithMods,
    /// 2 — refusé.
    Rejection,
    /// 3 — en attente.
    Waiting,
    /// 4 — avertissement de révocation imminente.
    RevocationWarning,
    /// 5 — notification de révocation.
    RevocationNotification,
    /// Valeur hors nomenclature, conservée telle quelle.
    Other(u64),
}

impl PkiStatus {
    fn from_u64(value: u64) -> Self {
        match value {
            0 => PkiStatus::Granted,
            1 => PkiStatus::GrantedWithMods,
            2 => PkiStatus::Rejection,
            3 => PkiStatus::Waiting,
            4 => PkiStatus::RevocationWarning,
            5 => PkiStatus::RevocationNotification,
            other => PkiStatus::Other(other),
        }
    }

    /// Un jeton a-t-il été délivré ?
    pub fn is_granted(&self) -> bool {
        matches!(self, PkiStatus::Granted | PkiStatus::GrantedWithMods)
    }
}

/// Réponse d'horodatage décodée a minima : le statut est interprété, le
/// jeton est conservé **opaque, tel quel** (octets DER complets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampResponse {
    pub status: PkiStatus,
    /// Textes libres du prestataire (motif de refus, le plus souvent).
    pub status_text: Vec<String>,
    /// `PKIFailureInfo` brut (contenu du BIT STRING), si présent.
    pub fail_info: Option<Vec<u8>>,
    /// Le `TimeStampToken` complet (TLV DER), à archiver tel quel dans
    /// [`crate::Anchor::token`] et à vérifier avec les outils standard.
    pub token: Option<Vec<u8>>,
}

/// Décode une `TimeStampResp` DER (corps d'une réponse HTTP
/// `application/timestamp-reply`).
pub fn parse_response(der: &[u8]) -> Result<TimeStampResponse, AnchorError> {
    let invalid = |e: crate::der::DerError| AnchorError::InvalidToken(e.to_string());

    let mut outer = Reader::new(der);
    let response = outer.read_expect(TAG_SEQUENCE).map_err(invalid)?;
    if !outer.is_empty() {
        return Err(AnchorError::InvalidToken(
            "octets excédentaires après la TimeStampResp".to_owned(),
        ));
    }

    let mut fields = Reader::new(response.content);

    // PKIStatusInfo
    let status_info = fields.read_expect(TAG_SEQUENCE).map_err(invalid)?;
    let mut info = Reader::new(status_info.content);
    let status_int = info.read_expect(TAG_INTEGER).map_err(invalid)?;
    let status = PkiStatus::from_u64(decode_integer_u64(status_int.content).map_err(invalid)?);

    let mut status_text = Vec::new();
    if info.peek_tag() == Some(TAG_SEQUENCE) {
        let free_text = info.read_expect(TAG_SEQUENCE).map_err(invalid)?;
        let mut texts = Reader::new(free_text.content);
        while !texts.is_empty() {
            let s = texts.read_expect(TAG_UTF8_STRING).map_err(invalid)?;
            status_text.push(String::from_utf8_lossy(s.content).into_owned());
        }
    }

    let mut fail_info = None;
    if info.peek_tag() == Some(TAG_BIT_STRING) {
        let bits = info.read_expect(TAG_BIT_STRING).map_err(invalid)?;
        fail_info = Some(bits.content.to_vec());
    }
    if !info.is_empty() {
        return Err(AnchorError::InvalidToken(
            "champ inattendu dans PKIStatusInfo".to_owned(),
        ));
    }

    // TimeStampToken optionnel : un ContentInfo CMS (SEQUENCE), gardé opaque.
    let token = if fields.is_empty() {
        None
    } else {
        let t = fields.read_expect(TAG_SEQUENCE).map_err(invalid)?;
        Some(t.raw.to_vec())
    };
    if !fields.is_empty() {
        return Err(AnchorError::InvalidToken(
            "octets excédentaires après le TimeStampToken".to_owned(),
        ));
    }

    if status.is_granted() && token.is_none() {
        return Err(AnchorError::InvalidToken(
            "statut « délivré » mais aucun jeton dans la réponse".to_owned(),
        ));
    }

    Ok(TimeStampResponse {
        status,
        status_text,
        fail_info,
        token,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Vecteur figé : requête pour le digest 00 01 02 … 1f, certReq TRUE,
    /// sans nonce. Toute divergence d'un octet est une régression du
    /// protocole.
    #[test]
    fn la_requete_der_est_conforme_au_vecteur_fige() {
        let mut digest = [0u8; 32];
        for (i, b) in digest.iter_mut().enumerate() {
            *b = i as u8;
        }
        let req = TimeStampRequest {
            digest_sha256: digest,
            nonce: None,
            cert_req: true,
        };
        assert_eq!(
            to_hex(&req.to_der()),
            concat!(
                "3039",                   // TimeStampReq ::= SEQUENCE, 57 octets
                "020101",                 // version 1
                "3031",                   // MessageImprint ::= SEQUENCE, 49 octets
                "300d",                   // AlgorithmIdentifier ::= SEQUENCE
                "0609608648016503040201", // OID 2.16.840.1.101.3.4.2.1 (SHA-256)
                "0500",                   // paramètres NULL
                "0420",                   // hashedMessage ::= OCTET STRING, 32 octets
                "000102030405060708090a0b0c0d0e0f",
                "101112131415161718191a1b1c1d1e1f",
                "0101ff", // certReq TRUE
            )
        );
    }

    #[test]
    fn le_nonce_est_encode_en_entier_minimal() {
        let req = TimeStampRequest {
            digest_sha256: [0u8; 32],
            nonce: Some(0xDEAD_BEEF),
            cert_req: false,
        };
        let der = req.to_der();
        // 0xDEADBEEF a le bit de poids fort à 1 → préfixe 0x00 obligatoire.
        assert!(
            to_hex(&der).contains("020500deadbeef"),
            "nonce mal encodé : {}",
            to_hex(&der)
        );
        // certReq FALSE = valeur par défaut : ne doit PAS être encodé (DER).
        assert!(!der.ends_with(&[0x01, 0x01, 0xFF]));
    }

    #[test]
    fn la_requete_pour_une_racine_hache_la_racine_en_sha256() {
        let root = BlobHash([0xAB; 32]);
        let req = TimeStampRequest::for_root(&root);
        assert_eq!(req.digest_sha256, sha256(&root.0));
        assert!(req.cert_req);
    }

    #[test]
    fn sha256_correspond_au_vecteur_connu() {
        // SHA-256 de la chaîne vide, vecteur NIST.
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Aller-retour : une réponse « jeton délivré » construite avec notre
    /// encodeur se décode en statut + jeton identique à l'octet près.
    #[test]
    fn roundtrip_reponse_avec_jeton() {
        // Jeton factice : SEQUENCE { INTEGER 5 } — opaque pour le décodeur.
        let token = tlv(TAG_SEQUENCE, &integer_u64(5));
        let status_info = tlv(TAG_SEQUENCE, &integer_u64(0)); // granted
        let mut body = status_info;
        body.extend_from_slice(&token);
        let resp_der = tlv(TAG_SEQUENCE, &body);

        let resp = parse_response(&resp_der).unwrap();
        assert_eq!(resp.status, PkiStatus::Granted);
        assert!(resp.status.is_granted());
        assert_eq!(resp.token.as_deref(), Some(token.as_slice()));
        assert!(resp.status_text.is_empty());
        assert!(resp.fail_info.is_none());
    }

    #[test]
    fn une_reponse_de_refus_expose_le_motif() {
        // PKIStatusInfo { status 2, statusString ["horloge indisponible"], failInfo }
        let mut info = integer_u64(2);
        let motif = tlv(TAG_UTF8_STRING, "horloge indisponible".as_bytes());
        info.extend_from_slice(&tlv(TAG_SEQUENCE, &motif));
        info.extend_from_slice(&tlv(TAG_BIT_STRING, &[0x00, 0x40]));
        let resp_der = tlv(TAG_SEQUENCE, &tlv(TAG_SEQUENCE, &info));

        let resp = parse_response(&resp_der).unwrap();
        assert_eq!(resp.status, PkiStatus::Rejection);
        assert!(!resp.status.is_granted());
        assert_eq!(resp.status_text, vec!["horloge indisponible".to_owned()]);
        assert_eq!(resp.fail_info.as_deref(), Some(&[0x00, 0x40][..]));
        assert!(resp.token.is_none());
    }

    #[test]
    fn un_statut_delivre_sans_jeton_est_refuse() {
        let resp_der = tlv(TAG_SEQUENCE, &tlv(TAG_SEQUENCE, &integer_u64(0)));
        assert!(parse_response(&resp_der).is_err());
    }

    #[test]
    fn des_octets_tronques_sont_refuses() {
        let token = tlv(TAG_SEQUENCE, &integer_u64(5));
        let status_info = tlv(TAG_SEQUENCE, &integer_u64(0));
        let mut body = status_info;
        body.extend_from_slice(&token);
        let mut resp_der = tlv(TAG_SEQUENCE, &body);
        resp_der.truncate(resp_der.len() - 3);
        assert!(parse_response(&resp_der).is_err());
    }
}
