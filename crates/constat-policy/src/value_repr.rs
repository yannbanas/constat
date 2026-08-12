//! Représentation YAML « naturelle » des valeurs de faits (§5.2).
//!
//! Le YAML d'assertions écrit `equals: true`, `equals: "yes"`, `equals: 3` —
//! jamais la forme taguée interne de [`constat_model::Value`]. Ce module fait
//! la conversion dans les deux sens :
//!
//! - booléen ↔ [`Value::Bool`], entier ↔ [`Value::Int`], texte ↔ [`Value::Text`] ;
//! - liste ↔ [`Value::List`], `null` ↔ [`Value::Absent`] ;
//! - `"fingerprint:<64 hexa>"` ↔ [`Value::Fingerprint`] ;
//! - les flottants sont **refusés** avec un message explicite (§15 : aucun
//!   flottant dans une valeur de fait).

use constat_model::Value;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Préfixe textuel d'une empreinte de secret.
const FINGERPRINT_PREFIX: &str = "fingerprint:";

/// Valeur d'un demi-octet hexadécimal, sinon `None`.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Lit `"fingerprint:<64 hexa>"`, sinon `None`.
fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let hexpart = s.strip_prefix(FINGERPRINT_PREFIX)?;
    let bytes = hexpart.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Encode 32 octets en hexadécimal minuscule (64 caractères).
pub(crate) fn fingerprint_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Visiteur : YAML naturel → [`Value`].
struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("un booléen, un entier, du texte, une liste ou null")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Int(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        i64::try_from(v)
            .map(Value::Int)
            .map_err(|_| E::custom(format!("entier trop grand pour un fait : {v}")))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Err(E::custom(format!(
            "flottant interdit dans une valeur de fait ({v}) — utiliser un entier (§15)"
        )))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(match parse_fingerprint(v) {
            Some(fp) => Value::Fingerprint(fp),
            None => Value::Text(v.to_owned()),
        })
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        self.visit_str(&v)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Absent)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Absent)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(ValueVisitor)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(ValueDe(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::List(items))
    }
}

/// Enveloppe de désérialisation (pour les éléments de liste et de table).
pub(crate) struct ValueDe(pub(crate) Value);

impl<'de> Deserialize<'de> for ValueDe {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ValueVisitor).map(ValueDe)
    }
}

/// Enveloppe de sérialisation (forme naturelle, jamais taguée).
pub(crate) struct ValueSer<'a>(pub(crate) &'a Value);

impl Serialize for ValueSer<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Int(i) => s.serialize_i64(*i),
            Value::Text(t) => s.serialize_str(t),
            Value::List(items) => {
                let mut seq = s.serialize_seq(Some(items.len()))?;
                for it in items {
                    seq.serialize_element(&ValueSer(it))?;
                }
                seq.end()
            }
            Value::Fingerprint(fp) => {
                s.serialize_str(&format!("{FINGERPRINT_PREFIX}{}", fingerprint_hex(fp)))
            }
            Value::Absent => s.serialize_unit(),
        }
    }
}

/// Point d'entrée `serde(with = …)` : sérialise une [`Value`] en YAML naturel.
pub(crate) fn serialize<S: Serializer>(v: &Value, s: S) -> Result<S::Ok, S::Error> {
    ValueSer(v).serialize(s)
}

/// Point d'entrée `serde(with = …)` : désérialise une [`Value`] depuis du
/// YAML naturel.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
    d.deserialize_any(ValueVisitor)
}

/// Variante pour les tables `clé → valeur` (filtre `where` des motifs typés).
pub(crate) mod map_repr {
    use super::{ValueDe, ValueSer};
    use constat_model::Value;
    use serde::de::{Deserializer, MapAccess, Visitor};
    use serde::ser::{SerializeMap, Serializer};
    use std::collections::BTreeMap;
    use std::fmt;

    /// Sérialise la table en YAML naturel.
    pub(crate) fn serialize<S: Serializer>(
        m: &BTreeMap<String, Value>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(m.len()))?;
        for (k, v) in m {
            map.serialize_entry(k, &ValueSer(v))?;
        }
        map.end()
    }

    struct MapVisitor;

    impl<'de> Visitor<'de> for MapVisitor {
        type Value = BTreeMap<String, Value>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("une table clé → valeur")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((k, ValueDe(v))) = access.next_entry::<String, ValueDe>()? {
                out.insert(k, v);
            }
            Ok(out)
        }
    }

    /// Désérialise la table depuis du YAML naturel.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<String, Value>, D::Error> {
        d.deserialize_map(MapVisitor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn empreintes() {
        let fp = [0xabu8; 32];
        let hexa = fingerprint_hex(&fp);
        assert_eq!(hexa.len(), 64);
        assert_eq!(parse_fingerprint(&format!("fingerprint:{hexa}")), Some(fp));
        assert_eq!(parse_fingerprint("fingerprint:zz"), None);
        assert_eq!(parse_fingerprint("pas-une-empreinte"), None);
    }
}
