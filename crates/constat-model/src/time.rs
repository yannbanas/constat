//! Temps pur : instants UTC en millisecondes, durées, conversions RFC 3339.
//!
//! Décisions de la spec (§15) : dates en UTC, précision **fixe** à la
//! milliseconde, sérialisées en entier depuis l'époque Unix. Aucun flottant,
//! aucune dépendance calendaire : le calcul grégorien est implémenté ici
//! (algorithmes de conversion jours ↔ date civile de Howard Hinnant,
//! exacts sur tout le domaine).

use serde::{Deserialize, Serialize};
use std::ops::{Add, Sub};

/// Millisecondes par jour.
const MS_PER_DAY: i64 = 86_400_000;

/// Instant UTC, en millisecondes depuis l'époque Unix. Précision fixe (§15).
///
/// Les secondes intercalaires ne sont pas représentables : comme le temps
/// Unix, cette échelle les ignore. `Timestamp` s'ordonne naturellement
/// (dérive `Ord`) et se sérialise canoniquement comme un entier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

/// Durée en millisecondes. Aucun flottant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DurationMs(pub u64);

/// Erreur de conversion temporelle (RFC 3339).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimestampError {
    /// La chaîne ne respecte pas le profil RFC 3339 attendu, ou décrit une
    /// date invalide (mois 13, 29 février hors année bissextile, …).
    #[error("horodatage RFC 3339 invalide : {0}")]
    Invalid(String),
    /// L'instant ne peut pas s'écrire en RFC 3339 (années 0000 à 9999).
    #[error("instant hors de la plage représentable en RFC 3339 (années 0000 à 9999)")]
    OutOfRange,
}

impl Timestamp {
    /// L'époque Unix : `1970-01-01T00:00:00.000Z`.
    pub const UNIX_EPOCH: Timestamp = Timestamp(0);

    /// Construit depuis un entier de millisecondes depuis l'époque Unix (UTC).
    pub const fn from_unix_millis(ms: i64) -> Self {
        Timestamp(ms)
    }

    /// Millisecondes depuis l'époque Unix (UTC).
    pub const fn as_unix_millis(self) -> i64 {
        self.0
    }

    /// Rend l'instant sous forme RFC 3339 UTC, précision fixe à la
    /// milliseconde : `AAAA-MM-JJTHH:MM:SS.mmmZ`.
    ///
    /// Le format est **stable** : c'est la représentation lisible de
    /// référence dans les dossiers de preuve. Échoue seulement si l'année
    /// sort de la plage 0000–9999 (limite du format RFC 3339 lui-même).
    ///
    /// ```
    /// use constat_model::Timestamp;
    /// assert_eq!(
    ///     Timestamp::UNIX_EPOCH.to_rfc3339().as_deref(),
    ///     Ok("1970-01-01T00:00:00.000Z"),
    /// );
    /// ```
    pub fn to_rfc3339(self) -> Result<String, TimestampError> {
        let days = self.0.div_euclid(MS_PER_DAY);
        let rem = self.0.rem_euclid(MS_PER_DAY); // toujours dans [0, MS_PER_DAY)
        let (year, month, day) = civil_from_days(days);
        if !(0..=9999).contains(&year) {
            return Err(TimestampError::OutOfRange);
        }
        let ms = rem % 1_000;
        let sec = (rem / 1_000) % 60;
        let min = (rem / 60_000) % 60;
        let hour = rem / 3_600_000;
        Ok(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{ms:03}Z"
        ))
    }

    /// Analyse une date-heure RFC 3339 et la normalise en UTC.
    ///
    /// Accepté : `AAAA-MM-JJTHH:MM:SS[.fraction](Z|±HH:MM)`, avec `T`
    /// insensible à la casse (une espace est aussi tolérée, usage courant).
    /// Un décalage horaire est appliqué pour ramener l'instant en UTC.
    ///
    /// Normalisations assumées (précision fixe, §15) :
    /// - la fraction de seconde est tronquée à la milliseconde ;
    /// - la seconde intercalaire (`:60`) est rejetée : elle n'est pas
    ///   représentable sur une échelle Unix.
    ///
    /// ```
    /// use constat_model::Timestamp;
    /// let t = Timestamp::from_rfc3339("1970-01-01T02:00:00+02:00")?;
    /// assert_eq!(t, Timestamp::UNIX_EPOCH);
    /// # Ok::<(), constat_model::TimestampError>(())
    /// ```
    pub fn from_rfc3339(s: &str) -> Result<Self, TimestampError> {
        parse_rfc3339(s).map(Timestamp)
    }

    /// Addition vérifiée : `None` en cas de débordement de `i64`.
    pub const fn checked_add(self, d: DurationMs) -> Option<Self> {
        match self.0.checked_add_unsigned(d.0) {
            Some(ms) => Some(Timestamp(ms)),
            None => None,
        }
    }

    /// Soustraction vérifiée : `None` en cas de débordement de `i64`.
    pub const fn checked_sub(self, d: DurationMs) -> Option<Self> {
        match self.0.checked_sub_unsigned(d.0) {
            Some(ms) => Some(Timestamp(ms)),
            None => None,
        }
    }

    /// Addition saturante (borne à `i64::MAX`). C'est aussi le comportement
    /// de l'opérateur `+`.
    pub const fn saturating_add(self, d: DurationMs) -> Self {
        Timestamp(self.0.saturating_add_unsigned(d.0))
    }

    /// Soustraction saturante (borne à `i64::MIN`). C'est aussi le
    /// comportement de l'opérateur `-`.
    pub const fn saturating_sub(self, d: DurationMs) -> Self {
        Timestamp(self.0.saturating_sub_unsigned(d.0))
    }

    /// Durée écoulée depuis `earlier`. `None` si `earlier` est postérieur
    /// à `self` — l'appelant décide alors quoi faire d'un intervalle
    /// inversé, jamais masqué par un zéro silencieux.
    pub fn duration_since(self, earlier: Timestamp) -> Option<DurationMs> {
        let diff = i128::from(self.0) - i128::from(earlier.0);
        u64::try_from(diff).ok().map(DurationMs)
    }
}

/// `Timestamp + DurationMs`, saturant aux bornes de `i64`.
impl Add<DurationMs> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: DurationMs) -> Timestamp {
        self.saturating_add(rhs)
    }
}

/// `Timestamp - DurationMs`, saturant aux bornes de `i64`.
impl Sub<DurationMs> for Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: DurationMs) -> Timestamp {
        self.saturating_sub(rhs)
    }
}

impl DurationMs {
    /// Durée nulle.
    pub const ZERO: DurationMs = DurationMs(0);

    /// Construit depuis un nombre de millisecondes.
    pub const fn from_millis(ms: u64) -> Self {
        DurationMs(ms)
    }

    /// Construit depuis un nombre de secondes (saturant).
    pub const fn from_secs(s: u64) -> Self {
        DurationMs(s.saturating_mul(1_000))
    }

    /// Construit depuis un nombre de minutes (saturant).
    pub const fn from_mins(m: u64) -> Self {
        DurationMs(m.saturating_mul(60_000))
    }

    /// Construit depuis un nombre d'heures (saturant).
    pub const fn from_hours(h: u64) -> Self {
        DurationMs(h.saturating_mul(3_600_000))
    }

    /// Construit depuis un nombre de jours (saturant).
    pub const fn from_days(d: u64) -> Self {
        DurationMs(d.saturating_mul(MS_PER_DAY as u64))
    }

    /// Nombre de millisecondes.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Nombre de secondes entières (troncature).
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000
    }

    /// Addition vérifiée.
    pub const fn checked_add(self, rhs: DurationMs) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(ms) => Some(DurationMs(ms)),
            None => None,
        }
    }

    /// Addition saturante (comportement de l'opérateur `+`).
    pub const fn saturating_add(self, rhs: DurationMs) -> Self {
        DurationMs(self.0.saturating_add(rhs.0))
    }

    /// Soustraction saturante à zéro (comportement de l'opérateur `-`).
    pub const fn saturating_sub(self, rhs: DurationMs) -> Self {
        DurationMs(self.0.saturating_sub(rhs.0))
    }
}

/// `DurationMs + DurationMs`, saturant à `u64::MAX`.
impl Add for DurationMs {
    type Output = DurationMs;

    fn add(self, rhs: DurationMs) -> DurationMs {
        self.saturating_add(rhs)
    }
}

/// `DurationMs - DurationMs`, saturant à zéro.
impl Sub for DurationMs {
    type Output = DurationMs;

    fn sub(self, rhs: DurationMs) -> DurationMs {
        self.saturating_sub(rhs)
    }
}

// ---------------------------------------------------------------------------
// Calendrier grégorien pur (algorithmes de Howard Hinnant)
// ---------------------------------------------------------------------------

/// Nombre de jours entre l'époque Unix et la date civile `(y, m, d)`.
/// Exact pour toute année représentable ici (le grégorien proleptique).
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 }); // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Date civile `(année, mois, jour)` du jour `z` (jours depuis l'époque Unix).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Analyse RFC 3339
// ---------------------------------------------------------------------------

fn invalid(src: &str, why: &str) -> TimestampError {
    TimestampError::Invalid(format!("« {src} » : {why}"))
}

/// Lit exactement `n` chiffres décimaux à la position `*i`.
fn digits(b: &[u8], i: &mut usize, n: usize, src: &str) -> Result<u32, TimestampError> {
    let end = i.checked_add(n).filter(|&e| e <= b.len());
    let Some(end) = end else {
        return Err(invalid(src, "chaîne trop courte"));
    };
    let mut v: u32 = 0;
    for &c in &b[*i..end] {
        if !c.is_ascii_digit() {
            return Err(invalid(src, "chiffre décimal attendu"));
        }
        v = v * 10 + u32::from(c - b'0');
    }
    *i = end;
    Ok(v)
}

/// Exige le séparateur `sep` à la position `*i`.
fn expect_sep(b: &[u8], i: &mut usize, sep: u8, src: &str) -> Result<(), TimestampError> {
    if b.get(*i).copied() == Some(sep) {
        *i += 1;
        Ok(())
    } else {
        Err(invalid(src, &format!("« {} » attendu", char::from(sep))))
    }
}

fn parse_rfc3339(src: &str) -> Result<i64, TimestampError> {
    let b = src.as_bytes();
    let mut i = 0usize;

    let year = i64::from(digits(b, &mut i, 4, src)?);
    expect_sep(b, &mut i, b'-', src)?;
    let month = digits(b, &mut i, 2, src)?;
    expect_sep(b, &mut i, b'-', src)?;
    let day = digits(b, &mut i, 2, src)?;

    match b.get(i).copied() {
        Some(b'T' | b't' | b' ') => i += 1,
        _ => return Err(invalid(src, "séparateur « T » attendu entre date et heure")),
    }

    let hour = digits(b, &mut i, 2, src)?;
    expect_sep(b, &mut i, b':', src)?;
    let minute = digits(b, &mut i, 2, src)?;
    expect_sep(b, &mut i, b':', src)?;
    let second = digits(b, &mut i, 2, src)?;

    // Fraction de seconde, tronquée à la milliseconde (précision fixe).
    let mut millis: u32 = 0;
    if b.get(i).copied() == Some(b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &b[start..i];
        if frac.is_empty() || frac.len() > 9 {
            return Err(invalid(
                src,
                "fraction de seconde invalide (1 à 9 chiffres)",
            ));
        }
        for (k, &c) in frac.iter().take(3).enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let pow = 10u32.pow(2 - k as u32);
            millis += u32::from(c - b'0') * pow;
        }
    }

    // Décalage horaire, ramené en UTC.
    let offset_minutes: i64 = match b.get(i).copied() {
        Some(b'Z' | b'z') => {
            i += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            i += 1;
            let oh = digits(b, &mut i, 2, src)?;
            expect_sep(b, &mut i, b':', src)?;
            let om = digits(b, &mut i, 2, src)?;
            if oh > 23 || om > 59 {
                return Err(invalid(src, "décalage horaire hors bornes"));
            }
            let total = i64::from(oh) * 60 + i64::from(om);
            if sign == b'+' {
                total
            } else {
                -total
            }
        }
        _ => return Err(invalid(src, "décalage attendu (« Z » ou « ±HH:MM »)")),
    };

    if i != b.len() {
        return Err(invalid(src, "caractères inattendus en fin de chaîne"));
    }

    // Validation calendaire.
    if !(1..=12).contains(&month) {
        return Err(invalid(src, "mois hors bornes (01 à 12)"));
    }
    if day < 1 || day > days_in_month(year, month) {
        return Err(invalid(src, "jour invalide pour ce mois"));
    }
    if hour > 23 || minute > 59 {
        return Err(invalid(src, "heure ou minute hors bornes"));
    }
    if second == 60 {
        return Err(invalid(
            src,
            "seconde intercalaire (:60) non représentable sur l'échelle Unix",
        ));
    }
    if second > 59 {
        return Err(invalid(src, "seconde hors bornes (00 à 59)"));
    }

    // Années 0000–9999 : aucun débordement possible en i64.
    let days = days_from_civil(year, month, day);
    let local = days * MS_PER_DAY
        + i64::from(hour) * 3_600_000
        + i64::from(minute) * 60_000
        + i64::from(second) * 1_000
        + i64::from(millis);
    Ok(local - offset_minutes * 60_000)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn epoch_vers_rfc3339() {
        assert_eq!(
            Timestamp::UNIX_EPOCH.to_rfc3339().unwrap(),
            "1970-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn valeurs_connues() {
        // 2000-01-01T00:00:00Z = 946684800 s — valeur de référence publique.
        assert_eq!(
            Timestamp(946_684_800_000).to_rfc3339().unwrap(),
            "2000-01-01T00:00:00.000Z"
        );
        assert_eq!(
            Timestamp::from_rfc3339("2000-01-01T00:00:00Z").unwrap(),
            Timestamp(946_684_800_000)
        );
        // Avant l'époque : les négatifs fonctionnent.
        assert_eq!(
            Timestamp(-1_000).to_rfc3339().unwrap(),
            "1969-12-31T23:59:59.000Z"
        );
        // Année bissextile.
        assert_eq!(
            Timestamp::from_rfc3339("2024-02-29T12:00:00Z")
                .unwrap()
                .to_rfc3339()
                .unwrap(),
            "2024-02-29T12:00:00.000Z"
        );
    }

    #[test]
    fn decalage_horaire_normalise_en_utc() {
        let t = Timestamp::from_rfc3339("1970-01-01T02:00:00+02:00").unwrap();
        assert_eq!(t, Timestamp::UNIX_EPOCH);
        let t = Timestamp::from_rfc3339("1969-12-31T19:00:00-05:00").unwrap();
        assert_eq!(t, Timestamp::UNIX_EPOCH);
    }

    #[test]
    fn fraction_tronquee_a_la_milliseconde() {
        let t = Timestamp::from_rfc3339("1970-01-01T00:00:00.123456789Z").unwrap();
        assert_eq!(t, Timestamp(123));
        let t = Timestamp::from_rfc3339("1970-01-01T00:00:00.5Z").unwrap();
        assert_eq!(t, Timestamp(500));
    }

    #[test]
    fn entrees_rejetees() {
        for s in [
            "",
            "2026-13-01T00:00:00Z",      // mois 13
            "2023-02-29T00:00:00Z",      // pas bissextile
            "2026-01-01T24:00:00Z",      // heure 24
            "2026-01-01T00:00:60Z",      // seconde intercalaire
            "2026-01-01T00:00:00",       // décalage manquant
            "2026-01-01T00:00:00.Z",     // fraction vide
            "2026-01-01T00:00:00Zx",     // caractères en trop
            "2026-01-01T00:00:00+25:00", // décalage hors bornes
            "not-a-date",
        ] {
            assert!(
                Timestamp::from_rfc3339(s).is_err(),
                "aurait dû échouer : {s}"
            );
        }
    }

    #[test]
    fn hors_plage_rfc3339() {
        assert_eq!(
            Timestamp(i64::MAX).to_rfc3339(),
            Err(TimestampError::OutOfRange)
        );
        assert_eq!(
            Timestamp(i64::MIN).to_rfc3339(),
            Err(TimestampError::OutOfRange)
        );
    }

    #[test]
    fn arithmetique() {
        let t = Timestamp(1_000);
        assert_eq!(t + DurationMs::from_secs(2), Timestamp(3_000));
        assert_eq!(t - DurationMs::from_secs(1), Timestamp(0));
        assert_eq!(Timestamp(i64::MAX) + DurationMs(1), Timestamp(i64::MAX)); // saturant
        assert_eq!(Timestamp(i64::MIN) - DurationMs(1), Timestamp(i64::MIN)); // saturant
        assert_eq!(t.checked_add(DurationMs(u64::MAX)), None);
        assert_eq!(
            Timestamp(3_000).duration_since(Timestamp(1_000)),
            Some(DurationMs(2_000))
        );
        assert_eq!(Timestamp(0).duration_since(Timestamp(1)), None);
        // Écart maximal représentable : tout le domaine i64 tient dans u64.
        assert_eq!(
            Timestamp(i64::MAX).duration_since(Timestamp(i64::MIN)),
            Some(DurationMs(u64::MAX))
        );
    }

    #[test]
    fn constructeurs_de_duree() {
        assert_eq!(DurationMs::from_secs(1), DurationMs(1_000));
        assert_eq!(DurationMs::from_mins(1), DurationMs(60_000));
        assert_eq!(DurationMs::from_hours(24), DurationMs::from_days(1));
        assert_eq!(DurationMs::from_days(u64::MAX), DurationMs(u64::MAX)); // saturant
        assert_eq!(DurationMs(1_500).as_secs(), 1);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// Aller-retour RFC 3339 identitaire sur toute la plage représentable.
        #[test]
        fn rfc3339_aller_retour(ms in rfc3339_range()) {
            let t = Timestamp(ms);
            let s = t.to_rfc3339().unwrap();
            let back = Timestamp::from_rfc3339(&s).unwrap();
            prop_assert_eq!(back, t);
        }

        /// La représentation textuelle préserve l'ordre chronologique
        /// (tri lexicographique = tri temporel, garanti par la largeur fixe).
        #[test]
        fn rfc3339_preserve_l_ordre(a in rfc3339_range(), b in rfc3339_range()) {
            let (ta, tb) = (Timestamp(a), Timestamp(b));
            let (sa, sb) = (ta.to_rfc3339().unwrap(), tb.to_rfc3339().unwrap());
            prop_assert_eq!(ta.cmp(&tb), sa.cmp(&sb));
        }
    }

    /// Plage des instants exprimables en RFC 3339 (années 0000 à 9999).
    fn rfc3339_range() -> std::ops::RangeInclusive<i64> {
        let min = days_from_civil(0, 1, 1) * MS_PER_DAY;
        let max = days_from_civil(9999, 12, 31) * MS_PER_DAY + (MS_PER_DAY - 1);
        min..=max
    }
}
