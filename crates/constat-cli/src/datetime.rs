//! Analyse et formatage des dates, durées et périodes (§10).
//!
//! Aucune dépendance externe : les conversions civiles ↔ jours utilisent les
//! algorithmes classiques de Howard Hinnant, exacts sur tout l'intervalle
//! utile. Tout est en UTC, en millisecondes depuis l'époque Unix — la
//! précision fixe imposée par le cœur (§15).
//!
//! ## Dates acceptées
//! - `2026-03-03` (minuit UTC) ;
//! - `2026-03-03T14:00`, `2026-03-03 14:00:30`, `2026-03-03T14:00:30.250` ;
//! - suffixe de fuseau optionnel : `Z`, `+02:00`, `-0530`, `+02`.
//!
//! ## Périodes acceptées
//! - `2026` — l'année civile ;
//! - `2026-Q1` — le trimestre ;
//! - `2026-03` — le mois ;
//! - `2026-03-03` — la journée ;
//! - `2026-01-15..2026-02-20` — intervalle explicite, bornes incluses.

use constat_model::{DurationMs, Timestamp};
use constat_time::Period;

/// Millisecondes par jour.
pub const MS_PER_DAY: i64 = 86_400_000;

/// Erreur d'analyse d'une date, d'une durée ou d'une période.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum ParseError {
    /// La date fournie ne correspond à aucune forme acceptée.
    #[error("date invalide : « {0} »")]
    #[diagnostic(help(
        "formes acceptées : 2026-03-03, 2026-03-03T14:00, 2026-03-03T14:00:30.250Z, avec fuseau ±HH:MM"
    ))]
    Date(String),
    /// La période fournie ne correspond à aucune forme acceptée.
    #[error("période invalide : « {0} »")]
    #[diagnostic(help(
        "formes acceptées : 2026, 2026-Q1, 2026-03, 2026-03-03, 2026-01-15..2026-02-20"
    ))]
    Period(String),
    /// La durée fournie ne correspond à aucune forme acceptée.
    #[error("durée invalide : « {0} »")]
    #[diagnostic(help("formes acceptées : 500ms, 90s, 30min, 24h, 7j (ou 7d)"))]
    Duration(String),
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

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

/// Jours écoulés depuis l'époque Unix pour une date civile (algorithme Hinnant).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Date civile pour un nombre de jours depuis l'époque Unix.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn parse_date_part(s: &str) -> Option<(i64, u32, u32)> {
    let mut it = s.split('-');
    let ys = it.next()?;
    if ys.is_empty() || !ys.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let y: i64 = ys.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    Some((y, m, d))
}

/// Sépare le fuseau éventuel et renvoie (heure locale, décalage en ms).
fn split_offset(t: &str) -> Option<(&str, i64)> {
    if let Some(rest) = t.strip_suffix(['Z', 'z']) {
        return Some((rest, 0));
    }
    if let Some(pos) = t.rfind(['+', '-']) {
        if pos > 0 {
            let (time, off) = t.split_at(pos);
            let sign: i64 = if off.starts_with('+') { 1 } else { -1 };
            let off = &off[1..];
            let (oh, om): (i64, i64) = match off.split_once(':') {
                Some((h, m)) => (h.parse().ok()?, m.parse().ok()?),
                None if off.len() == 4 => (off[..2].parse().ok()?, off[2..].parse().ok()?),
                None => (off.parse().ok()?, 0),
            };
            if oh > 23 || om > 59 {
                return None;
            }
            return Some((time, sign * (oh * 60 + om) * 60_000));
        }
    }
    Some((t, 0))
}

/// Analyse `HH:MM[:SS[.fff]]` et renvoie (h, min, s, ms).
fn parse_time_part(t: &str) -> Option<(i64, i64, i64, i64)> {
    let mut parts = t.split(':');
    let h: i64 = parts.next()?.parse().ok()?;
    let min: i64 = parts.next()?.parse().ok()?;
    let (sec, milli): (i64, i64) = match parts.next() {
        None => (0, 0),
        Some(sp) => match sp.split_once('.') {
            None => (sp.parse().ok()?, 0),
            Some((s, f)) => {
                let padded: String = format!("{f:0<3}").chars().take(3).collect();
                (s.parse().ok()?, padded.parse().ok()?)
            }
        },
    };
    if parts.next().is_some() || h > 23 || min > 59 || sec > 59 {
        return None;
    }
    Some((h, min, sec, milli))
}

/// Analyse une date, en renvoyant aussi si une heure était présente
/// (utile pour interpréter la borne haute d'une période).
fn parse_timestamp_inner(s: &str) -> Option<(i64, bool)> {
    let s = s.trim();
    let (date_s, time_s) = match s.split_once(['T', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    let (y, m, d) = parse_date_part(date_s)?;
    let mut ms = days_from_civil(y, m, d) * MS_PER_DAY;
    let had_time = time_s.is_some();
    if let Some(t) = time_s {
        let (t, offset_ms) = split_offset(t)?;
        let (h, min, sec, milli) = parse_time_part(t)?;
        ms += h * 3_600_000 + min * 60_000 + sec * 1000 + milli;
        ms -= offset_ms;
    }
    Some((ms, had_time))
}

/// Analyse une date (RFC 3339 ou forme courte `AAAA-MM-JJ`) en UTC.
pub fn parse_timestamp(s: &str) -> Result<Timestamp, ParseError> {
    parse_timestamp_inner(s)
        .map(|(ms, _)| Timestamp(ms))
        .ok_or_else(|| ParseError::Date(s.to_string()))
}

fn month_start_ms(mut y: i64, mut m: u32) -> i64 {
    while m > 12 {
        m -= 12;
        y += 1;
    }
    days_from_civil(y, m, 1) * MS_PER_DAY
}

/// Analyse une période : `2026`, `2026-Q1`, `2026-03`, `2026-03-03`,
/// ou `debut..fin` (bornes incluses).
pub fn parse_period(s: &str) -> Result<Period, ParseError> {
    let raw = s;
    let s = s.trim();
    let err = || ParseError::Period(raw.to_string());

    // Intervalle explicite `debut..fin`.
    if let Some((a, b)) = s.split_once("..") {
        let (from, _) = parse_timestamp_inner(a).ok_or_else(err)?;
        let (bms, had_time) = parse_timestamp_inner(b).ok_or_else(err)?;
        let to = if had_time { bms } else { bms + MS_PER_DAY - 1 };
        if to < from {
            return Err(err());
        }
        return Ok(Period {
            from: Timestamp(from),
            to: Timestamp(to),
        });
    }

    // Année : `2026`.
    if s.len() == 4 && s.chars().all(|c| c.is_ascii_digit()) {
        let y: i64 = s.parse().map_err(|_| err())?;
        return Ok(Period {
            from: Timestamp(month_start_ms(y, 1)),
            to: Timestamp(month_start_ms(y + 1, 1) - 1),
        });
    }

    // Trimestre : `2026-Q1`.
    if let Some((ys, qs)) = s.split_once('-') {
        if let Some(qn) = qs.strip_prefix(['Q', 'q']) {
            let y: i64 = ys.parse().map_err(|_| err())?;
            let q: u32 = qn.parse().map_err(|_| err())?;
            if !(1..=4).contains(&q) {
                return Err(err());
            }
            let m0 = (q - 1) * 3 + 1;
            return Ok(Period {
                from: Timestamp(month_start_ms(y, m0)),
                to: Timestamp(month_start_ms(y, m0 + 3) - 1),
            });
        }
    }

    // Mois : `2026-03`.
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() == 2 {
        let y: i64 = parts[0].parse().map_err(|_| err())?;
        let m: u32 = parts[1].parse().map_err(|_| err())?;
        if !(1..=12).contains(&m) {
            return Err(err());
        }
        return Ok(Period {
            from: Timestamp(month_start_ms(y, m)),
            to: Timestamp(month_start_ms(y, m + 1) - 1),
        });
    }

    // Journée : `2026-03-03`.
    if let Some((y, m, d)) = parse_date_part(s) {
        let from = days_from_civil(y, m, d) * MS_PER_DAY;
        return Ok(Period {
            from: Timestamp(from),
            to: Timestamp(from + MS_PER_DAY - 1),
        });
    }

    Err(err())
}

/// Analyse une durée lisible : `500ms`, `90s`, `30min`, `24h`, `7j` (ou `7d`).
pub fn parse_duration(s: &str) -> Result<DurationMs, ParseError> {
    let raw = s;
    let s = s.trim();
    let err = || ParseError::Duration(raw.to_string());
    let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(err)?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| err())?;
    let ms = match unit.trim() {
        "ms" => n,
        "s" | "sec" => n.saturating_mul(1000),
        "m" | "min" => n.saturating_mul(60_000),
        "h" => n.saturating_mul(3_600_000),
        "d" | "j" => n.saturating_mul(86_400_000),
        _ => return Err(err()),
    };
    Ok(DurationMs(ms))
}

/// Formate un instant en `AAAA-MM-JJ HH:MM` (UTC).
pub fn format_timestamp(t: Timestamp) -> String {
    let days = t.0.div_euclid(MS_PER_DAY);
    let rem = t.0.rem_euclid(MS_PER_DAY);
    let (y, m, d) = civil_from_days(days);
    let h = rem / 3_600_000;
    let min = (rem % 3_600_000) / 60_000;
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}")
}

/// Formate un instant en `AAAA-MM-JJ` (UTC).
pub fn format_day(t: Timestamp) -> String {
    let (y, m, d) = civil_from_days(t.0.div_euclid(MS_PER_DAY));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Formate une période en `AAAA-MM-JJ HH:MM → AAAA-MM-JJ HH:MM`.
pub fn format_period(p: Period) -> String {
    format!("{} → {}", format_timestamp(p.from), format_timestamp(p.to))
}

/// Formate une durée de façon lisible : `26 h`, `45 min`, `4 j 12 h`.
///
/// Les durées jusqu'à trois jours restent en heures : « l'écart maximal
/// entre deux collectes : 26 h » (§4.2) se lit mieux que « 1 j 2 h ».
pub fn format_duration(d: DurationMs) -> String {
    let ms = d.0;
    if ms >= 3 * 86_400_000 {
        let j = ms / 86_400_000;
        let h = (ms % 86_400_000) / 3_600_000;
        if h == 0 {
            format!("{j} j")
        } else {
            format!("{j} j {h} h")
        }
    } else if ms >= 3_600_000 {
        let h = ms / 3_600_000;
        let m = (ms % 3_600_000) / 60_000;
        if m == 0 {
            format!("{h} h")
        } else {
            format!("{h} h {m:02} min")
        }
    } else if ms >= 60_000 {
        format!("{} min", ms / 60_000)
    } else if ms >= 1000 {
        format!("{} s", ms / 1000)
    } else {
        format!("{ms} ms")
    }
}

/// Formate un ratio en parties par million comme un pourcentage français
/// à une décimale : `997_000` → `99,7 %`.
pub fn format_ppm(ppm: u32) -> String {
    format!("{},{} %", ppm / 10_000, (ppm % 10_000) / 1_000)
}

/// L'instant présent, en millisecondes UTC depuis l'époque Unix.
pub fn now() -> Timestamp {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp(d.as_millis() as i64)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn date_courte() {
        // 2026-03-03 : vérifié par retour civil.
        let t = parse_timestamp("2026-03-03").unwrap();
        assert_eq!(format_day(t), "2026-03-03");
        assert_eq!(t.0 % MS_PER_DAY, 0);
    }

    #[test]
    fn date_rfc3339() {
        let a = parse_timestamp("2026-03-03T14:00:00Z").unwrap();
        let b = parse_timestamp("2026-03-03 14:00").unwrap();
        assert_eq!(a, b);
        // Décalage : 14:00+02:00 == 12:00Z.
        let c = parse_timestamp("2026-03-03T14:00+02:00").unwrap();
        let d = parse_timestamp("2026-03-03T12:00Z").unwrap();
        assert_eq!(c, d);
        // Fraction de seconde.
        let e = parse_timestamp("2026-03-03T00:00:00.250Z").unwrap();
        assert_eq!(e.0 - parse_timestamp("2026-03-03").unwrap().0, 250);
    }

    #[test]
    fn date_invalide() {
        assert!(parse_timestamp("2026-13-01").is_err());
        assert!(parse_timestamp("2026-02-30").is_err());
        assert!(parse_timestamp("n'importe quoi").is_err());
    }

    #[test]
    fn periode_trimestre() {
        let p = parse_period("2026-Q1").unwrap();
        assert_eq!(format_day(p.from), "2026-01-01");
        assert_eq!(format_day(p.to), "2026-03-31");
        assert_eq!(p.to.0 % MS_PER_DAY, MS_PER_DAY - 1);
    }

    #[test]
    fn periode_mois_annee_jour() {
        let m = parse_period("2026-03").unwrap();
        assert_eq!(format_day(m.from), "2026-03-01");
        assert_eq!(format_day(m.to), "2026-03-31");
        let y = parse_period("2026").unwrap();
        assert_eq!(format_day(y.from), "2026-01-01");
        assert_eq!(format_day(y.to), "2026-12-31");
        let j = parse_period("2026-02-28").unwrap();
        assert_eq!(format_day(j.from), "2026-02-28");
        assert_eq!(format_day(j.to), "2026-02-28");
    }

    #[test]
    fn periode_intervalle() {
        let p = parse_period("2026-01-15..2026-02-20").unwrap();
        assert_eq!(format_day(p.from), "2026-01-15");
        assert_eq!(format_day(p.to), "2026-02-20");
        assert!(parse_period("2026-02-20..2026-01-15").is_err());
    }

    #[test]
    fn durees() {
        assert_eq!(parse_duration("24h").unwrap().0, 24 * 3_600_000);
        assert_eq!(parse_duration("7j").unwrap().0, 7 * 86_400_000);
        assert_eq!(parse_duration("30min").unwrap().0, 30 * 60_000);
        assert!(parse_duration("24 heures et demie").is_err());
    }

    #[test]
    fn formatage() {
        let t = parse_timestamp("2025-11-04T09:12Z").unwrap();
        assert_eq!(format_timestamp(t), "2025-11-04 09:12");
        assert_eq!(format_ppm(997_000), "99,7 %");
        assert_eq!(format_ppm(1_000_000), "100,0 %");
        assert_eq!(format_duration(DurationMs(26 * 3_600_000)), "26 h");
        assert_eq!(format_duration(DurationMs(108 * 3_600_000)), "4 j 12 h");
    }
}
