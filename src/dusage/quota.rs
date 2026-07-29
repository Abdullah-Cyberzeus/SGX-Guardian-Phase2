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
