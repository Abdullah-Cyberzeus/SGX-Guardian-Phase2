use crate::dusage::errors::{DusageError, DusageResult};
use crate::dusage::model::DusageQuota;
use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};

pub const DEFAULT_PERIOD: &str = "monthly";
pub const QUOTA_BYTES_ENV: &str = "SGX_DUSAGE_QUOTA_BYTES";

pub fn normalize_period(period: &str) -> DusageResult<String> {
    let normalized = period.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "daily" | "weekly" | "monthly" => Ok(normalized),
        _ => Err(DusageError::InvalidPeriod(period.to_string())),
    }
}

pub fn period_start_for(now: DateTime<Utc>, period: &str) -> DusageResult<DateTime<Utc>> {
    match normalize_period(period)?.as_str() {
        "daily" => Ok(Utc
            .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .single()
            .expect("valid utc day start")),
        "weekly" => {
            let date = now.date_naive();
            let monday = date - Duration::days(date.weekday().num_days_from_monday() as i64);
            Ok(Utc.from_utc_datetime(&monday.and_hms_opt(0, 0, 0).expect("valid utc week start")))
        }
        "monthly" => {
            let first =
                NaiveDate::from_ymd_opt(now.year(), now.month(), 1).expect("valid utc month start");
            Ok(Utc.from_utc_datetime(&first.and_hms_opt(0, 0, 0).expect("valid utc month start")))
        }
        _ => unreachable!(),
    }
}

pub fn next_period_start(start: DateTime<Utc>, period: &str) -> DusageResult<DateTime<Utc>> {
    match normalize_period(period)?.as_str() {
        "daily" => Ok(start + Duration::days(1)),
        "weekly" => Ok(start + Duration::weeks(1)),
        "monthly" => {
            let (year, month) = if start.month() == 12 {
                (start.year() + 1, 1)
            } else {
                (start.year(), start.month() + 1)
            };
            let first = NaiveDate::from_ymd_opt(year, month, 1).expect("valid next month start");
            Ok(Utc.from_utc_datetime(&first.and_hms_opt(0, 0, 0).expect("valid next month start")))
        }
        _ => unreachable!(),
    }
}

pub fn period_has_rolled(period_start: &str, period: &str, now: DateTime<Utc>) -> bool {
    let Ok(start) = DateTime::parse_from_rfc3339(period_start).map(|dt| dt.with_timezone(&Utc))
    else {
        return true;
    };
    next_period_start(start, period)
        .map(|next| now >= next)
        .unwrap_or(true)
}

pub fn used_pct(total_bytes: u64, quota_bytes: Option<u64>) -> Option<f64> {
    let quota = quota_bytes?;
    if quota == 0 {
        return None;
    }
    Some((total_bytes as f64 / quota as f64) * 100.0)
}

pub fn usage_band(used_pct: Option<f64>) -> String {
    match used_pct {
        Some(value) if value > 80.0 => "red".to_string(),
        Some(value) if value > 50.0 => "amber".to_string(),
        Some(_) => "green".to_string(),
        None => "none".to_string(),
    }
}

pub fn env_default_quota(period: &str) -> Option<DusageQuota> {
    let quota_bytes = std::env::var(QUOTA_BYTES_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)?;
    Some(DusageQuota::new(quota_bytes, period.to_string(), 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_normalize_period() {
        assert_eq!(normalize_period("daily").unwrap(), "daily");
        assert_eq!(normalize_period("WEEKLY ").unwrap(), "weekly");
        assert_eq!(normalize_period(" Monthly").unwrap(), "monthly");
        assert!(matches!(
            normalize_period("yearly"),
            Err(DusageError::InvalidPeriod(_))
        ));
    }

    #[test]
    fn test_period_start_for_calculations() {
        // Thursday 2026-06-18 15:30:00 UTC
        let now = Utc.with_ymd_and_hms(2026, 6, 18, 15, 30, 0).unwrap();

        let day_start = period_start_for(now, "daily").unwrap();
        assert_eq!(day_start, Utc.with_ymd_and_hms(2026, 6, 18, 0, 0, 0).unwrap());

        let week_start = period_start_for(now, "weekly").unwrap();
        // Monday was June 15, 2026
        assert_eq!(week_start, Utc.with_ymd_and_hms(2026, 6, 15, 0, 0, 0).unwrap());

        let month_start = period_start_for(now, "monthly").unwrap();
        assert_eq!(month_start, Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());
    }

    #[test]
    fn test_next_period_start_and_year_rollover() {
        let dec_start = Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap();
        let next_month = next_period_start(dec_start, "monthly").unwrap();
        assert_eq!(next_month, Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap());

        let day_start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let next_day = next_period_start(day_start, "daily").unwrap();
        assert_eq!(next_day, Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap());
    }

    #[test]
    fn test_period_has_rolled() {
        let period_start = "2026-06-01T00:00:00Z";

        let during_month = Utc.with_ymd_and_hms(2026, 6, 20, 0, 0, 0).unwrap();
        assert!(!period_has_rolled(period_start, "monthly", during_month));

        let next_month = Utc.with_ymd_and_hms(2026, 7, 1, 0, 0, 0).unwrap();
        assert!(period_has_rolled(period_start, "monthly", next_month));

        // Invalid start date triggers rolled fallback
        assert!(period_has_rolled("invalid-date", "monthly", during_month));
    }

    #[test]
    fn test_used_pct_and_usage_band() {
        assert_eq!(used_pct(500, Some(1000)), Some(50.0));
        assert_eq!(used_pct(500, None), None);
        assert_eq!(used_pct(500, Some(0)), None);

        assert_eq!(usage_band(None), "none");
        assert_eq!(usage_band(Some(30.0)), "green");
        assert_eq!(usage_band(Some(50.0)), "green");
        assert_eq!(usage_band(Some(50.1)), "amber");
        assert_eq!(usage_band(Some(80.0)), "amber");
        assert_eq!(usage_band(Some(80.1)), "red");
        assert_eq!(usage_band(Some(120.0)), "red");
    }
}

