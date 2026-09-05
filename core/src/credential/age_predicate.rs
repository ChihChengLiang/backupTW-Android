//! Turning a 民國 birthdate into an age predicate that can be shown on its
//! own.
//!
//! Ported from `backupTW-iOS/backupTW/Model/AgePredicate.swift`. See that
//! file for why a predicate is a claim rather than a circuit, and for the
//! caveat this is *not* zero-knowledge: the disclosure still carries the
//! app's subject identifier, so two verifiers can tell they saw the same
//! person. It is minimal disclosure of the field, a weaker property.

use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};

/// A 民國 (Republic of China) calendar date, as MyData writes it.
///
/// Measured against exactly **one** real MyData download (2026-08-09):
/// `民國 083年03月06日`. [`RocDate::parse`] tolerates what that sample
/// implies and nothing beyond it — a string it cannot read yields `None`,
/// and the caller must treat that as "no age claim", never as "under age".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocDate {
    /// 民國 year. Year 1 is 1912 CE.
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

impl RocDate {
    /// 民國 1 is 1912, so the offset is 1911.
    pub const GREGORIAN_OFFSET: i32 = 1911;

    pub fn gregorian_year(&self) -> i32 {
        self.year + Self::GREGORIAN_OFFSET
    }

    /// Parses the form MyData writes, or `None`.
    ///
    /// Deliberately strict about the *shape* and lenient about spacing: a
    /// government export changing 「民國 083年」 to 「民國83年」 is a
    /// formatting difference, while a string with no 年/月/日 markers is a
    /// different format this has not seen and must not guess at.
    pub fn parse(raw: &str) -> Option<RocDate> {
        // Full-width digits and the ideographic space appear in some
        // government exports; folding them to ASCII is a transliteration,
        // not an interpretation. (Narrower than Foundation's general
        // fullwidth-to-halfwidth transform: only the two things this parser
        // actually reads - digits and spacing - are covered, since nothing
        // else in a 民國 date string is affected by width.)
        let normalized: String = raw
            .chars()
            .map(|c| match c {
                '\u{FF10}'..='\u{FF19}' => {
                    char::from_u32(c as u32 - 0xFF10 + '0' as u32).unwrap_or(c)
                }
                '\u{3000}' => ' ',
                other => other,
            })
            .filter(|&c| c != ' ')
            .collect();

        let year_pos = normalized.find('年')?;
        let month_pos = normalized.find('月')?;
        let day_pos = normalized.find('日')?;
        if !(year_pos < month_pos && month_pos < day_pos) {
            return None;
        }

        let year_text = normalized[..year_pos].replace("民國", "");
        let month_text = &normalized[year_pos + '年'.len_utf8()..month_pos];
        let day_text = &normalized[month_pos + '月'.len_utf8()..day_pos];

        let year: i32 = year_text.parse().ok()?;
        let month: u32 = month_text.parse().ok()?;
        let day: u32 = day_text.parse().ok()?;
        if year <= 0 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        Some(RocDate { year, month, day })
    }

    /// The Gregorian civil date this denotes, in the calendar the core
    /// reasons in (Taipei time, not whatever zone the device happens to be
    /// in — a birthdate on a household record is a civil date in Taiwan).
    pub fn to_gregorian(&self) -> Option<NaiveDate> {
        NaiveDate::from_ymd_opt(self.gregorian_year(), self.month, self.day)
    }
}

/// Fixed UTC+8: Taiwan does not observe daylight saving time, so a fixed
/// offset is exact rather than an approximation.
fn taipei_date(instant: DateTime<Utc>) -> NaiveDate {
    (instant.naive_utc() + Duration::hours(8)).date()
}

/// The age of majority the credential carries a claim about.
pub const MAJORITY: i32 = 18;

/// The claim name. Named for *when* it was true, because that is the whole
/// of its meaning — see the module docs on why a bare `isOver18` would be
/// wrong on both the true and false side.
pub const CLAIM_NAME: &str = "over18AtIssuance";

/// Derives the claim, or `None` when the birthdate is not one this build can
/// read.
///
/// `None` rather than `"false"`, and the difference is the whole safety
/// property: an unparseable date means *unknown*, and emitting `false` for
/// unknown would be asserting somebody is a minor because the parser did not
/// recognise their record.
pub fn claim_value(birthdate: Option<&str>, as_of: DateTime<Utc>) -> Option<String> {
    let roc = RocDate::parse(birthdate?)?;
    let born = roc.to_gregorian()?;
    Some(
        if reached(MAJORITY, born, as_of) {
            "true"
        } else {
            "false"
        }
        .to_owned(),
    )
}

/// Whether someone born on `born` had reached `age` by `as_of`.
///
/// Calendar-year arithmetic, not a day count: the boundary is a birthday,
/// and 18 x 365.25 days differs from it on leap years — the day they differ
/// on is somebody's birthday.
pub fn reached(age: i32, born: NaiveDate, as_of: DateTime<Utc>) -> bool {
    match add_years(born, age) {
        // The predicate turns true *on* the birthday, not the day after.
        Some(boundary) => boundary <= taipei_date(as_of),
        None => false,
    }
}

/// Adds `years` to `date`, clamping a 29 February birthday to 28 February in
/// a non-leap target year — matching `Calendar.date(byAdding:.year...)`,
/// and the conventional reading of 民法 §124 (age counted from the day of
/// birth; a 2/29 birthday reaches majority on the last day of February in a
/// common year, not 1 March).
fn add_years(date: NaiveDate, years: i32) -> Option<NaiveDate> {
    let target_year = date.year() + years;
    NaiveDate::from_ymd_opt(target_year, date.month(), date.day()).or_else(|| {
        if date.month() == 2 && date.day() == 29 {
            NaiveDate::from_ymd_opt(target_year, 2, 28)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn taipei(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        // Midnight Taipei time, expressed as the equivalent UTC instant.
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap() - Duration::hours(8)
    }

    /// The Taipei *civil* date itself, for the birth side of `reached` -
    /// distinct from `taipei()`, whose `.date_naive()` would give the UTC
    /// calendar date of that instant (one day earlier, since Taipei
    /// midnight is 16:00 UTC the previous day).
    fn taipei_civil_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    #[test]
    fn parses_the_format_mydata_actually_writes() {
        let date = RocDate::parse("民國 083年03月06日").unwrap();
        assert_eq!(date.year, 83);
        assert_eq!(date.month, 3);
        assert_eq!(date.day, 6);
        assert_eq!(date.gregorian_year(), 1994);
    }

    #[test]
    fn tolerates_spacing_and_an_optional_prefix() {
        for raw in [
            "民國83年3月6日",
            "民國 83 年 3 月 6 日",
            "83年03月06日",
            " 民國083年03月06日 ",
        ] {
            let date = RocDate::parse(raw).unwrap();
            assert_eq!(date.gregorian_year(), 1994, "{raw:?}");
            assert_eq!((date.month, date.day), (3, 6), "{raw:?}");
        }
    }

    #[test]
    fn refuses_anything_it_has_not_seen() {
        for raw in [
            "0700101",
            "",
            "民國",
            "1994-03-06",
            "民國 年 月 日",
            "民國 83年13月06日",
        ] {
            assert_eq!(RocDate::parse(raw), None, "{raw:?} should not parse");
        }
    }

    #[test]
    fn the_epoch_is_fixed_at_1911() {
        let first = RocDate::parse("民國 001年01月01日").unwrap();
        assert_eq!(first.gregorian_year(), 1912);
    }

    #[test]
    fn the_predicate_turns_true_on_the_birthday_itself() {
        let born = taipei_civil_date(1994, 3, 6);
        assert!(!reached(18, born, taipei(2012, 3, 5)));
        assert!(reached(18, born, taipei(2012, 3, 6)));
        assert!(reached(18, born, taipei(2012, 3, 7)));
    }

    #[test]
    fn a_leap_day_birthday_reaches_majority_on_the_last_day_of_february() {
        let born = taipei_civil_date(2000, 2, 29);
        assert!(!reached(18, born, taipei(2018, 2, 27)));
        assert!(reached(18, born, taipei(2018, 2, 28)));
        assert!(reached(18, born, taipei(2018, 3, 1)));
    }

    #[test]
    fn the_answer_does_not_depend_on_the_hour() {
        let born = taipei_civil_date(1994, 3, 6);
        let morning = Utc.with_ymd_and_hms(2012, 3, 6, 0, 1, 0).unwrap() - Duration::hours(8);
        let night = Utc.with_ymd_and_hms(2012, 3, 6, 23, 59, 0).unwrap() - Duration::hours(8);
        assert!(reached(18, born, morning));
        assert!(reached(18, born, night));
    }

    #[test]
    fn an_adults_claim_is_true_and_a_minors_is_false() {
        let now = taipei(2026, 8, 10);
        assert_eq!(
            claim_value(Some("民國 083年03月06日"), now).as_deref(),
            Some("true")
        );
        assert_eq!(
            claim_value(Some("民國 110年03月06日"), now).as_deref(),
            Some("false")
        );
    }

    #[test]
    fn an_unreadable_birthdate_yields_no_claim_rather_than_false() {
        let now = taipei(2026, 8, 10);
        for raw in [None, Some(""), Some("0700101"), Some("not a date")] {
            assert_eq!(claim_value(raw, now), None, "{raw:?}");
        }
    }
}
