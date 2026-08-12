//! Mini-encodeur/décodeur DER — strictement ce qu'exige RFC 3161.
//!
//! Le protocole est simple (§9 de l'architecture) : quelques SEQUENCE, un
//! OID, un OCTET STRING, des INTEGER. Écrire ces cent lignes évite une
//! dépendance ASN.1 lourde dans un crate de preuve.
//!
//! Encodage : longueurs définies uniquement (forme courte < 128, forme
//! longue au-delà), INTEGER en complément à deux minimal — c'est-à-dire du
//! DER, pas du BER laxiste.

/// Étiquettes ASN.1 utilisées par RFC 3161.
pub(crate) const TAG_BOOLEAN: u8 = 0x01;
pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_NULL: u8 = 0x05;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_UTF8_STRING: u8 = 0x0C;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;

/// Encode un TLV (tag, longueur, valeur).
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    encode_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

/// INTEGER non signé, en complément à deux minimal (préfixe 0x00 si le bit
/// de poids fort est à 1).
pub(crate) fn integer_u64(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = Vec::with_capacity(9);
    if bytes[first] & 0x80 != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(&bytes[first..]);
    tlv(TAG_INTEGER, &content)
}

/// BOOLEAN DER : TRUE = 0xFF, FALSE = 0x00.
pub(crate) fn boolean(value: bool) -> Vec<u8> {
    tlv(TAG_BOOLEAN, &[if value { 0xFF } else { 0x00 }])
}

/// Erreur de lecture DER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DerError {
    /// Fin de données prématurée ou longueur incohérente.
    Truncated,
    /// Forme de longueur refusée (indéfinie, ou plus de 4 octets).
    BadLength,
    /// Étiquette inattendue.
    UnexpectedTag { expected: u8, found: u8 },
}

impl std::fmt::Display for DerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DerError::Truncated => write!(f, "données DER tronquées"),
            DerError::BadLength => write!(f, "longueur DER invalide"),
            DerError::UnexpectedTag { expected, found } => write!(
                f,
                "étiquette DER inattendue : attendu 0x{expected:02X}, trouvé 0x{found:02X}"
            ),
        }
    }
}

/// Un TLV lu : étiquette, contenu, et octets bruts complets (tag + longueur
/// + contenu) — les octets bruts servent à conserver un jeton opaque tel quel.
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

/// Lecteur séquentiel de TLV.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Étiquette du prochain TLV, sans avancer.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Lit le prochain TLV.
    pub fn read_tlv(&mut self) -> Result<Tlv<'a>, DerError> {
        let start = self.pos;
        let tag = *self.data.get(self.pos).ok_or(DerError::Truncated)?;
        self.pos += 1;
        let first = *self.data.get(self.pos).ok_or(DerError::Truncated)?;
        self.pos += 1;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 4 {
                // Longueur indéfinie (BER) ou déraisonnable : refusée.
                return Err(DerError::BadLength);
            }
            let mut len = 0usize;
            for _ in 0..n {
                let b = *self.data.get(self.pos).ok_or(DerError::Truncated)?;
                self.pos += 1;
                len = (len << 8) | b as usize;
            }
            len
        };
        let end = self.pos.checked_add(len).ok_or(DerError::BadLength)?;
        if end > self.data.len() {
            return Err(DerError::Truncated);
        }
        let content = &self.data[self.pos..end];
        self.pos = end;
        Ok(Tlv {
            tag,
            content,
            raw: &self.data[start..end],
        })
    }

    /// Lit le prochain TLV en exigeant une étiquette précise.
    pub fn read_expect(&mut self, tag: u8) -> Result<Tlv<'a>, DerError> {
        let tlv = self.read_tlv()?;
        if tlv.tag != tag {
            return Err(DerError::UnexpectedTag {
                expected: tag,
                found: tlv.tag,
            });
        }
        Ok(tlv)
    }
}

/// Décode un INTEGER non négatif tenant sur 64 bits.
pub(crate) fn decode_integer_u64(content: &[u8]) -> Result<u64, DerError> {
    if content.is_empty() {
        return Err(DerError::Truncated);
    }
    if content[0] & 0x80 != 0 {
        // Négatif : jamais attendu dans RFC 3161.
        return Err(DerError::BadLength);
    }
    let significant: &[u8] = if content[0] == 0 {
        &content[1..]
    } else {
        content
    };
    if significant.len() > 8 {
        return Err(DerError::BadLength);
    }
    let mut value = 0u64;
    for &b in significant {
        value = (value << 8) | b as u64;
    }
    Ok(value)
}
