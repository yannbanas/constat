//! Dates UTC pures : parsing des dates d'expiration (« 2027-01-01 ») et
//! formats d'affichage français, sans aucune dépendance.
//!
//! Conformément au §15 de la spécification : tout est en UTC, précision fixe
//! à la milliseconde, entier depuis l'époque Unix. Les conversions civiles
//! utilisent l'algorithme des ères de 400 ans (calendrier grégorien
//! proleptique), exact sur tout l'intervalle utile.

use crate::error::PolicyError;
use constat_model::Timestamp;

/// Millisecondes par jour.
const MS_PER_DAY: i64 = 86_400_000;

/// Année bissextile (grégorien).
fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

/// Nombre de jours du mois `m` (1..=12) de l'année `y`.
fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Jours écoulés depuis 1970-01-01 pour la date civile `(y, m, d)`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let m = i64::from(m);
    let d = i64::from(d);
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Date civile `(y, m, d)` pour un nombre de jours depuis 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// Lit une suite de chiffres ASCII, sinon `None`.
fn digits(s: Option<&str>) -> Option<i64> {
    let s = s?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parse une date UTC : « AAAA-MM-JJ », éventuellement suivie de
/// « THH:MM », « THH:MM:SS » (le `T` peut être un espace) et d'un « Z » final.
///
/// Sans partie horaire, la date désigne minuit UTC. C'est le format des
/// champs `expires` des exceptions (§5.2).
///
/// # Erreurs
///
/// [`PolicyError::InvalidDate`] avec la raison précise (mois hors bornes,
/// jour inexistant, heure illisible…).
pub fn parse_date(input: &str) -> Result<Timestamp, PolicyError> {
    let fail = |reason: String| PolicyError::InvalidDate {
        input: input.to_owned(),
        reason,
    };
    let s = input.trim();
    let b = s.as_bytes();
    if b.len() < 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return Err(fail(
            "format attendu : AAAA-MM-JJ, éventuellement suivi de THH:MM[:SS][Z]".to_owned(),
        ));
    }
    let y = digits(s.get(0..4)).ok_or_else(|| fail("année illisible".to_owned()))?;
    let m = digits(s.get(5..7)).ok_or_else(|| fail("mois illisible".to_owned()))?;
    let d = digits(s.get(8..10)).ok_or_else(|| fail("jour illisible".to_owned()))?;
    if !(1..=12).contains(&m) {
        return Err(fail(format!("mois hors bornes : {m}")));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let (m_u, d_u) = (m as u32, d as u32);
    let dim = days_in_month(y, m_u);
    if d < 1 || d_u > dim {
        return Err(fail(format!(
            "jour hors bornes : {d} (le mois {m} de l'année {y} compte {dim} jours)"
        )));
    }

    // Partie horaire optionnelle. Les dix premiers octets sont ASCII
    // (vérifiés ci-dessus), la coupe est donc sûre.
    let mut rest = s.get(10..).unwrap_or_default();
    let (mut hh, mut mi, mut ss) = (0i64, 0i64, 0i64);
    if !rest.is_empty() {
        let sep = rest.as_bytes()[0];
        if sep != b'T' && sep != b' ' {
            return Err(fail(
                "séparateur attendu entre date et heure : « T » ou espace".to_owned(),
            ));
        }
        rest = rest.get(1..).unwrap_or_default();
        let horaire = rest.strip_suffix('Z').unwrap_or(rest);
        let parts: Vec<&str> = horaire.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(fail("heure attendue au format HH:MM[:SS]".to_owned()));
        }
        hh = digits(parts.first().copied()).ok_or_else(|| fail("heures illisibles".to_owned()))?;
        mi = digits(parts.get(1).copied()).ok_or_else(|| fail("minutes illisibles".to_owned()))?;
        ss = match parts.get(2) {
            Some(p) => digits(Some(p)).ok_or_else(|| fail("secondes illisibles".to_owned()))?,
            None => 0,
        };
        if hh > 23 || mi > 59 || ss > 59 {
            return Err(fail(format!("heure hors bornes : {hh:02}:{mi:02}:{ss:02}")));
        }
    }

    let days = days_from_civil(y, m_u, d_u);
    Ok(Timestamp(
        days * MS_PER_DAY + (hh * 3600 + mi * 60 + ss) * 1000,
    ))
}

/// Formate une date seule : « JJ/MM/AAAA » (UTC).
pub fn format_date(ts: Timestamp) -> String {
    let (y, m, d) = civil_from_days(ts.0.div_euclid(MS_PER_DAY));
    format!("{d:02}/{m:02}/{y:04}")
}

/// Formate une date et une heure : « JJ/MM/AAAA HHhMM » (UTC).
pub fn format_datetime(ts: Timestamp) -> String {
    let days = ts.0.div_euclid(MS_PER_DAY);
    let ms = ts.0.rem_euclid(MS_PER_DAY);
    let (y, m, d) = civil_from_days(days);
    let hh = ms / 3_600_000;
    let mi = (ms % 3_600_000) / 60_000;
    format!("{d:02}/{m:02}/{y:04} {hh:02}h{mi:02}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn epoque() {
        assert_eq!(parse_date("1970-01-01").unwrap(), Timestamp(0));
    }

    #[test]
    fn dates_connues() {
        // 2027-01-01 : 20 819 jours après l'époque
        assert_eq!(
            parse_date("2027-01-01").unwrap(),
            Timestamp(20_819 * MS_PER_DAY)
        );
        // avec heure
        assert_eq!(
            parse_date("1970-01-02T03:04").unwrap(),
            Timestamp(MS_PER_DAY + 3 * 3_600_000 + 4 * 60_000)
        );
        assert_eq!(
            parse_date("1970-01-01T00:00:30Z").unwrap(),
            Timestamp(30_000)
        );
        assert_eq!(
            parse_date("1970-01-01 12:00").unwrap(),
            Timestamp(12 * 3_600_000)
        );
    }

    #[test]
    fn bissextiles() {
        assert!(parse_date("2024-02-29").is_ok());
        assert!(parse_date("2026-02-29").is_err());
        assert!(parse_date("2000-02-29").is_ok());
        assert!(parse_date("2100-02-29").is_err());
    }

    #[test]
    fn dates_illisibles() {
        for cas in [
            "",
            "2027",
            "2027-13-01",
            "2027-00-01",
            "2027-01-32",
            "2027-01-00",
            "01/01/2027",
            "2027-01-01X10:00",
            "2027-01-01T25:00",
            "2027-01-01T10:61",
            "2027-01-01T10",
        ] {
            assert!(parse_date(cas).is_err(), "« {cas} » aurait dû être refusé");
        }
    }

    #[test]
    fn aller_retour_civil() {
        // toutes les dates de 1969 à 2101, aller-retour exact
        for z in days_from_civil(1969, 1, 1)..=days_from_civil(2101, 12, 31) {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
    }

    #[test]
    fn formatage() {
        let ts = parse_date("2026-02-12T03:00").unwrap();
        assert_eq!(format_date(ts), "12/02/2026");
        assert_eq!(format_datetime(ts), "12/02/2026 03h00");
        assert_eq!(format_datetime(Timestamp(0)), "01/01/1970 00h00");
        // avant l'époque : division euclidienne, pas de décalage d'un jour
        assert_eq!(format_datetime(Timestamp(-1)), "31/12/1969 23h59");
    }
}
