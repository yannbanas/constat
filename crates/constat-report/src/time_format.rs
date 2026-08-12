//! Formatage des dates et durées, en pur Rust : pas de dépendance calendaire
//! pour trois formules. Dates en UTC uniquement (§15) — un dossier de preuve
//! n'a pas de fuseau local.

use constat_model::{DurationMs, Timestamp};

/// Formate un instant en `AAAA-MM-JJ HH:MM:SS UTC`.
pub fn format_timestamp(at: Timestamp) -> String {
    let ms = at.0;
    let days = ms.div_euclid(86_400_000);
    let ms_of_day = ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let seconds = ms_of_day / 1_000;
    let (h, m, s) = (seconds / 3_600, (seconds / 60) % 60, seconds % 60);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Formate une durée en unités lisibles : `26 h 30 min`, `45 min`, `30 s`.
pub fn format_duration(d: DurationMs) -> String {
    let seconds = d.0 / 1_000;
    let (h, m, s) = (seconds / 3_600, (seconds / 60) % 60, seconds % 60);
    if h > 0 {
        format!("{h} h {m:02} min")
    } else if m > 0 {
        format!("{m} min")
    } else {
        format!("{s} s")
    }
}

/// Jours depuis l'époque Unix → date civile grégorienne (algorithme de
/// Howard Hinnant, « civil_from_days », domaine largement suffisant ici).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_epoque_unix_est_le_premier_janvier_1970() {
        assert_eq!(format_timestamp(Timestamp(0)), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn une_date_de_2026_est_correcte() {
        // 2026-01-01T00:00:00Z = 1 767 225 600 s.
        assert_eq!(
            format_timestamp(Timestamp(1_767_225_600_000)),
            "2026-01-01 00:00:00 UTC"
        );
        // 2026-03-31T23:59:59Z.
        assert_eq!(
            format_timestamp(Timestamp(1_775_001_599_000)),
            "2026-03-31 23:59:59 UTC"
        );
    }

    #[test]
    fn une_annee_bissextile_est_correcte() {
        // 2024-02-29T12:00:00Z = 1 709 208 000 s.
        assert_eq!(
            format_timestamp(Timestamp(1_709_208_000_000)),
            "2024-02-29 12:00:00 UTC"
        );
    }

    #[test]
    fn les_durees_sont_lisibles() {
        assert_eq!(format_duration(DurationMs(26 * 3_600_000)), "26 h 00 min");
        assert_eq!(
            format_duration(DurationMs(3 * 3_600_000 + 25 * 60_000)),
            "3 h 25 min"
        );
        assert_eq!(format_duration(DurationMs(45 * 60_000)), "45 min");
        assert_eq!(format_duration(DurationMs(30_000)), "30 s");
    }
}
