//! Five-field cron expressions (`minute hour day-of-month month day-of-week`)
//! plus `@hourly`, `@daily`, `@weekly`, `@monthly`, evaluated in UTC or a
//! fixed offset. Deliberately small: `*`, `n`, `a-b`, `a,b`, `*/s`, `a-b/s`;
//! day-of-week 0–7 (0 and 7 are Sunday). As in Vixie cron, when both
//! day-of-month and day-of-week are restricted either one matching fires.

use chrono::{DateTime, Datelike, Duration, FixedOffset, TimeZone, Timelike, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    minutes: [bool; 60],
    hours: [bool; 24],
    days: [bool; 32],
    months: [bool; 13],
    weekdays: [bool; 7],
    any_day: bool,
    any_weekday: bool,
}

/// Parse `UTC`, `Z`, `+HH:MM` or `-HH:MM`.
pub fn parse_timezone(s: &str) -> Option<FixedOffset> {
    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("utc") || s == "Z" {
        return FixedOffset::east_opt(0);
    }
    let (sign, rest) = match s.as_bytes()[0] {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    let (h, m) = rest.split_once(':')?;
    let (h, m): (i32, i32) = (h.parse().ok()?, m.parse().ok()?);
    if h > 14 || m > 59 {
        return None;
    }
    FixedOffset::east_opt(sign * (h * 3600 + m * 60))
}

fn field(spec: &str, min: u32, max: u32) -> Result<Vec<bool>, String> {
    let mut set = vec![false; (max + 1) as usize];
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("empty list item".into());
        }
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (
                r,
                s.parse::<u32>()
                    .ok()
                    .filter(|s| *s > 0)
                    .ok_or_else(|| format!("bad step `{s}`"))?,
            ),
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (
                a.parse().map_err(|_| format!("bad number `{a}`"))?,
                b.parse().map_err(|_| format!("bad number `{b}`"))?,
            )
        } else {
            let n: u32 = range.parse().map_err(|_| format!("bad number `{range}`"))?;
            // `n/step` means "from n to max every step", as in Vixie cron.
            if step > 1 { (n, max) } else { (n, n) }
        };
        if lo < min || hi > max || lo > hi {
            return Err(format!("`{part}` is outside {min}–{max}"));
        }
        let mut v = lo;
        while v <= hi {
            set[v as usize] = true;
            v += step;
        }
    }
    Ok(set)
}

impl Schedule {
    pub fn parse(expr: &str) -> Result<Self, String> {
        let expr = expr.trim();
        let expanded = match expr {
            "@hourly" => "0 * * * *",
            "@daily" | "@midnight" => "0 0 * * *",
            "@weekly" => "0 0 * * 0",
            "@monthly" => "0 0 1 * *",
            other => other,
        };
        let parts: Vec<&str> = expanded.split_whitespace().collect();
        if parts.len() != 5 {
            return Err("expected 5 fields: minute hour day month weekday".into());
        }
        let minutes = field(parts[0], 0, 59).map_err(|e| format!("minute: {e}"))?;
        let hours = field(parts[1], 0, 23).map_err(|e| format!("hour: {e}"))?;
        let days = field(parts[2], 1, 31).map_err(|e| format!("day: {e}"))?;
        let months = field(parts[3], 1, 12).map_err(|e| format!("month: {e}"))?;
        let mut weekdays7 = field(parts[4], 0, 7).map_err(|e| format!("weekday: {e}"))?;
        if weekdays7[7] {
            weekdays7[0] = true;
        }
        let mut s = Schedule {
            minutes: [false; 60],
            hours: [false; 24],
            days: [false; 32],
            months: [false; 13],
            weekdays: [false; 7],
            any_day: parts[2] == "*",
            any_weekday: parts[4] == "*",
        };
        s.minutes.copy_from_slice(&minutes[..60]);
        s.hours.copy_from_slice(&hours[..24]);
        s.days.copy_from_slice(&days[..32]);
        s.months.copy_from_slice(&months[..13]);
        s.weekdays.copy_from_slice(&weekdays7[..7]);
        Ok(s)
    }

    fn matches<Tz: TimeZone>(&self, t: &DateTime<Tz>) -> bool {
        let day_ok = self.days[t.day() as usize];
        let wd_ok = self.weekdays[t.weekday().num_days_from_sunday() as usize];
        let dom = match (self.any_day, self.any_weekday) {
            (true, true) => true,
            (false, false) => day_ok || wd_ok,
            (false, true) => day_ok,
            (true, false) => wd_ok,
        };
        self.minutes[t.minute() as usize]
            && self.hours[t.hour() as usize]
            && self.months[t.month() as usize]
            && dom
    }

    /// First matching minute strictly after `after`, searching up to five
    /// years ahead (`None` for impossible schedules such as `0 0 31 2 *`).
    pub fn next_after(&self, after: DateTime<Utc>, tz: FixedOffset) -> Option<DateTime<Utc>> {
        let start = after.with_timezone(&tz);
        let mut t = start.with_second(0)?.with_nanosecond(0)? + Duration::minutes(1);
        let limit = start + Duration::days(366 * 5);
        while t <= limit {
            if !self.months[t.month() as usize] {
                // Jump to the first day of the next month.
                let (y, m) = if t.month() == 12 {
                    (t.year() + 1, 1)
                } else {
                    (t.year(), t.month() + 1)
                };
                t = tz.with_ymd_and_hms(y, m, 1, 0, 0, 0).single()?;
                continue;
            }
            if !self.matches(&t) {
                let day_matches = {
                    let day_ok = self.days[t.day() as usize];
                    let wd_ok = self.weekdays[t.weekday().num_days_from_sunday() as usize];
                    match (self.any_day, self.any_weekday) {
                        (true, true) => true,
                        (false, false) => day_ok || wd_ok,
                        (false, true) => day_ok,
                        (true, false) => wd_ok,
                    }
                };
                if !day_matches {
                    t = (t + Duration::days(1)).with_hour(0)?.with_minute(0)?;
                } else if !self.hours[t.hour() as usize] {
                    t = (t + Duration::hours(1)).with_minute(0)?;
                } else {
                    t += Duration::minutes(1);
                }
                continue;
            }
            return Some(t.with_timezone(&Utc));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn parses_and_rejects() {
        assert!(Schedule::parse("*/15 * * * *").is_ok());
        assert!(Schedule::parse("0 3 * * 1-5").is_ok());
        assert!(Schedule::parse("@daily").is_ok());
        assert!(Schedule::parse("5,35 8-18/2 1,15 * *").is_ok());
        for bad in [
            "* * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "a * * * *",
        ] {
            assert!(Schedule::parse(bad).is_err(), "{bad}");
        }
        assert!(parse_timezone("+03:00").is_some());
        assert!(parse_timezone("-05:30").is_some());
        assert!(parse_timezone("UTC").is_some());
        assert!(parse_timezone("Europe/Moscow").is_none());
        assert!(parse_timezone("+15:00").is_none());
    }

    #[test]
    fn next_occurrences() {
        let utc = FixedOffset::east_opt(0).unwrap();
        let s = Schedule::parse("*/15 * * * *").unwrap();
        assert_eq!(
            s.next_after(at("2026-03-01T10:07:30Z"), utc),
            Some(at("2026-03-01T10:15:00Z"))
        );
        assert_eq!(
            s.next_after(at("2026-03-01T10:15:00Z"), utc),
            Some(at("2026-03-01T10:30:00Z"))
        );
        let s = Schedule::parse("0 3 * * 1-5").unwrap();
        // 2026-03-06 is a Friday; next weekday 03:00 after Friday 04:00 is Monday.
        assert_eq!(
            s.next_after(at("2026-03-06T04:00:00Z"), utc),
            Some(at("2026-03-09T03:00:00Z"))
        );
        let s = Schedule::parse("@monthly").unwrap();
        assert_eq!(
            s.next_after(at("2026-01-31T23:59:00Z"), utc),
            Some(at("2026-02-01T00:00:00Z"))
        );
        let s = Schedule::parse("0 0 29 2 *").unwrap();
        assert_eq!(
            s.next_after(at("2026-03-01T00:00:00Z"), utc),
            Some(at("2028-02-29T00:00:00Z"))
        );
        assert_eq!(
            Schedule::parse("0 0 31 2 *")
                .unwrap()
                .next_after(at("2026-01-01T00:00:00Z"), utc),
            None
        );
        // Day-of-month OR day-of-week when both are restricted.
        let s = Schedule::parse("0 0 1 * 1").unwrap();
        assert_eq!(
            s.next_after(at("2026-03-01T00:00:00Z"), utc),
            Some(at("2026-03-02T00:00:00Z"))
        );
    }

    #[test]
    fn fixed_offset() {
        let msk = parse_timezone("+03:00").unwrap();
        let s = Schedule::parse("0 9 * * *").unwrap();
        assert_eq!(
            s.next_after(at("2026-03-01T05:30:00Z"), msk),
            Some(at("2026-03-01T06:00:00Z"))
        );
        assert_eq!(
            s.next_after(at("2026-03-01T06:00:00Z"), msk),
            Some(at("2026-03-02T06:00:00Z"))
        );
    }
}
