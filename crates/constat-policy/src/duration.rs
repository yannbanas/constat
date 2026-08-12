//! Durées lisibles : « 24h », « 30m », « 7d », « 90s » → [`DurationMs`].
//!
//! Unités reconnues : `ms`, `s`, `m` (ou `min`), `h`, `d` (ou `j`).
//! Les segments peuvent se combiner : « 1h30m » vaut 90 minutes.
//! Aucun flottant, arithmétique vérifiée (le dépassement est une erreur, pas
//! un enroulement).

use crate::error::PolicyError;
use constat_model::DurationMs;

/// Millisecondes par unité.
const MS_PER_SECOND: u64 = 1_000;
const MS_PER_MINUTE: u64 = 60 * MS_PER_SECOND;
const MS_PER_HOUR: u64 = 60 * MS_PER_MINUTE;
const MS_PER_DAY: u64 = 24 * MS_PER_HOUR;

/// Parse une durée lisible (« 24h », « 30m », « 7d », « 90s », « 1h30m »).
///
/// # Erreurs
///
/// [`PolicyError::InvalidDuration`] si le texte est vide, si un nombre est
/// illisible, si une unité est inconnue ou manquante, ou si le total dépasse
/// la capacité d'un `u64` de millisecondes.
pub fn parse_duration(input: &str) -> Result<DurationMs, PolicyError> {
    let fail = |reason: String| PolicyError::InvalidDuration {
        input: input.to_owned(),
        reason,
    };
    let s = input.trim();
    if s.is_empty() {
        return Err(fail("durée vide".to_owned()));
    }
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut total: u64 = 0;
    while i < b.len() {
        // espaces facultatifs entre segments
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        // nombre
        let mut num: u64 = 0;
        let mut ndigits = 0usize;
        while i < b.len() && b[i].is_ascii_digit() {
            num = num
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(b[i] - b'0')))
                .ok_or_else(|| fail("nombre trop grand".to_owned()))?;
            i += 1;
            ndigits += 1;
        }
        if ndigits == 0 {
            return Err(fail(format!(
                "chiffre attendu à la position {} (format : nombre suivi d'une unité, ex. « 24h »)",
                i + 1
            )));
        }
        // unité (l'espace entre nombre et unité est toléré : « 24 h »)
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let unit_start = i;
        while i < b.len() && b[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = &s[unit_start..i];
        let factor: u64 = match unit {
            "ms" => 1,
            "s" => MS_PER_SECOND,
            "m" | "min" => MS_PER_MINUTE,
            "h" => MS_PER_HOUR,
            "d" | "j" => MS_PER_DAY,
            "" => {
                return Err(fail(format!(
                    "unité manquante après « {num} » (unités : ms, s, m, h, d)"
                )))
            }
            other => {
                return Err(fail(format!(
                    "unité inconnue « {other} » (unités : ms, s, m, h, d)"
                )))
            }
        };
        total = num
            .checked_mul(factor)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(|| fail("durée trop grande".to_owned()))?;
    }
    Ok(DurationMs(total))
}

/// Formate une durée pour un humain, en français : « 26 h », « 45 min »,
/// « 7 j », « 1 h 30 min ».
///
/// Deux composantes au plus. Les heures sont préférées aux jours en dessous
/// de 72 h (« 26 h » plutôt que « 1 j 2 h »), pour coller aux formulations
/// d'audit (« écart maximal entre deux collectes : 26 h »).
pub fn format_duration(d: DurationMs) -> String {
    if d.0 == 0 {
        return "0 s".to_owned();
    }
    let use_days = d.0 >= 72 * MS_PER_HOUR;
    let mut units: Vec<(u64, &str)> = Vec::with_capacity(5);
    if use_days {
        units.push((MS_PER_DAY, "j"));
    }
    units.push((MS_PER_HOUR, "h"));
    units.push((MS_PER_MINUTE, "min"));
    units.push((MS_PER_SECOND, "s"));
    units.push((1, "ms"));

    let mut rest = d.0;
    let mut parts: Vec<String> = Vec::with_capacity(2);
    for (factor, name) in units {
        if rest >= factor {
            let n = rest / factor;
            rest %= factor;
            parts.push(format!("{n} {name}"));
            if parts.len() == 2 {
                break;
            }
        }
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn durees_simples() {
        assert_eq!(parse_duration("24h").unwrap(), DurationMs(24 * MS_PER_HOUR));
        assert_eq!(
            parse_duration("30m").unwrap(),
            DurationMs(30 * MS_PER_MINUTE)
        );
        assert_eq!(parse_duration("7d").unwrap(), DurationMs(7 * MS_PER_DAY));
        assert_eq!(
            parse_duration("90s").unwrap(),
            DurationMs(90 * MS_PER_SECOND)
        );
        assert_eq!(parse_duration("250ms").unwrap(), DurationMs(250));
        assert_eq!(parse_duration("2j").unwrap(), DurationMs(2 * MS_PER_DAY));
        assert_eq!(
            parse_duration("15min").unwrap(),
            DurationMs(15 * MS_PER_MINUTE)
        );
    }

    #[test]
    fn durees_composees() {
        assert_eq!(
            parse_duration("1h30m").unwrap(),
            DurationMs(90 * MS_PER_MINUTE)
        );
        assert_eq!(
            parse_duration("1d 12h").unwrap(),
            DurationMs(36 * MS_PER_HOUR)
        );
        assert_eq!(
            parse_duration(" 24h ").unwrap(),
            DurationMs(24 * MS_PER_HOUR)
        );
        assert_eq!(parse_duration("0s").unwrap(), DurationMs(0));
    }

    #[test]
    fn durees_illisibles() {
        for cas in ["", "  ", "h", "24", "24x", "24 h30", "12.5h", "-3h", "24hh"] {
            assert!(
                parse_duration(cas).is_err(),
                "« {cas} » aurait dû être refusé"
            );
        }
        // le message explique
        let err = parse_duration("24x").unwrap_err();
        assert!(err.to_string().contains("unité inconnue"), "{err}");
        let err = parse_duration("24").unwrap_err();
        assert!(err.to_string().contains("unité manquante"), "{err}");
    }

    #[test]
    fn debordement_refuse() {
        assert!(parse_duration("99999999999999999999s").is_err());
        assert!(parse_duration("18446744073709551615d").is_err());
    }

    #[test]
    fn formatage() {
        assert_eq!(format_duration(DurationMs(0)), "0 s");
        assert_eq!(format_duration(DurationMs(26 * MS_PER_HOUR)), "26 h");
        assert_eq!(format_duration(DurationMs(24 * MS_PER_HOUR)), "24 h");
        assert_eq!(format_duration(DurationMs(7 * MS_PER_DAY)), "7 j");
        assert_eq!(
            format_duration(DurationMs(90 * MS_PER_MINUTE)),
            "1 h 30 min"
        );
        assert_eq!(format_duration(DurationMs(45 * MS_PER_MINUTE)), "45 min");
        assert_eq!(
            format_duration(DurationMs(90 * MS_PER_SECOND)),
            "1 min 30 s"
        );
    }

    #[test]
    fn aller_retour_parse_format() {
        for texte in ["24h", "30m", "7d", "90s"] {
            let d = parse_duration(texte).unwrap();
            // re-parser le format humain (sans espaces exotiques) redonne la même durée
            let refait = parse_duration(&format_duration(d)).unwrap();
            assert_eq!(d, refait, "aller-retour raté pour « {texte} »");
        }
    }
}
