use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::discovery::{
    config::{NmapConfig, ScanScheduleProfile, ScheduleDay, ScheduleFrequency, ScheduledScanKind},
    connected_device::DeviceStatus,
    error::DiscoveryResult,
    inventory::Inventory,
    nmap_parser,
    nmap_runner::NmapRunner,
    run_history::{self, ScanRunSource},
    vuln_trigger,
    whitelist::Whitelist,
    ScanIntensity,
};
use chrono::{Datelike, Duration as ChronoDuration, Local, NaiveDate, Timelike, Utc};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration, Instant};

#[derive(Clone)]
pub struct DiscoveryScheduler {
    pub node_id: String,
    pub config_path: PathBuf,
    pub whitelist_path: PathBuf,
    pub inventory_path: PathBuf,
    pub state: Arc<Mutex<Inventory>>,
}

impl DiscoveryScheduler {
    /// Spawns background loops. Returns immediately.
    pub fn start(self) {
        seed_if_missing(&self.config_path, DEFAULT_NMAP_YAML);
        seed_if_missing(&self.whitelist_path, DEFAULT_WHITELIST_YAML);

        if let Ok(inv) = Inventory::load(&self.inventory_path) {
            if let Ok(mut guard) = self.state.try_lock() {
                *guard = inv;
            }
        }

        for kind in [ScheduledScanKind::Hourly, ScheduledScanKind::Daily] {
            let scheduler = self.clone();
            tokio::spawn(async move {
                scheduler.run_schedule_loop(kind).await;
            });
        }

        let scheduler = self.clone();
        tokio::spawn(async move {
            scheduler.run_profile_schedule_loop().await;
        });
    }

    async fn run_schedule_loop(&self, kind: ScheduledScanKind) {
        let period = schedule_period(kind);
        let mut poll = interval(Duration::from_secs(60));
        let mut next_run = Instant::now() + period;
        let mut last_daily_slot: Option<String> = None;
        poll.tick().await;

        loop {
            poll.tick().await;

            let cfg = match NmapConfig::load(&self.config_path) {
                Ok(cfg) => cfg,
                Err(err) => {
                    tracing::warn!("discovery config load failed: {}", err);
                    next_run = Instant::now() + period;
                    continue;
                }
            };

            if !cfg.scan_schedules.is_empty() {
                next_run = Instant::now() + period;
                continue;
            }

            let Some(intensity) = cfg.scheduled_intensity(kind) else {
                next_run = Instant::now() + period;
                continue;
            };

            if !cfg.enabled {
                next_run = Instant::now() + period;
                continue;
            }

            if kind == ScheduledScanKind::Daily {
                let Some(slot) = daily_schedule_slot(&cfg) else {
                    continue;
                };
                if last_daily_slot.as_deref() == Some(&slot) {
                    continue;
                }
                tracing::info!(
                    schedule = %schedule_name(kind),
                    slot = %slot,
                    timezone = %Local::now().format("%Z %:z"),
                    "scheduled discovery scan is due"
                );

                match self.run_one(&cfg, kind, intensity).await {
                    Ok(()) => last_daily_slot = Some(slot),
                    Err(err) => {
                        // Do not consume the slot on failure. The next poll
                        // retries the same scheduled run and records each
                        // attempt in run history for visibility.
                        log_audit(
                            &self.node_id,
                            AuditCategory::Discovery,
                            AuditSeverity::Warning,
                            AuditAction::Failed,
                            &format!(
                                "{} Guardian network scan failed: {}",
                                schedule_name(kind),
                                err
                            ),
                        );
                    }
                }
                continue;
            } else {
                if Instant::now() < next_run {
                    continue;
                }
                next_run = Instant::now() + period;
            }

            if let Err(err) = self.run_one(&cfg, kind, intensity).await {
                log_audit(
                    &self.node_id,
                    AuditCategory::Discovery,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!(
                        "{} Guardian network scan failed: {}",
                        schedule_name(kind),
                        err
                    ),
                );
            }
        }
    }

    async fn run_profile_schedule_loop(&self) {
        let mut poll = interval(Duration::from_secs(60));
        let mut last_slots: HashMap<String, String> = HashMap::new();
        poll.tick().await;

        loop {
            poll.tick().await;

            let cfg = match NmapConfig::load(&self.config_path) {
                Ok(cfg) => cfg,
                Err(err) => {
                    tracing::warn!("discovery config load failed: {}", err);
                    continue;
                }
            };

            let schedules = cfg.active_schedules().to_vec();
            if schedules.is_empty() {
                continue;
            }

            if !cfg.enabled {
                continue;
            }

            for schedule in schedules {
                let Some(slot) = active_schedule_slot(&schedule) else {
                    continue;
                };
                if last_slots
                    .get(&schedule.id)
                    .is_some_and(|last| last == &slot)
                {
                    continue;
                }

                let kind_label = schedule.frequency.as_str();
                tracing::info!(
                    schedule = %kind_label,
                    slot = %slot,
                    timezone = %schedule.timezone,
                    "scheduled discovery scan is due"
                );

                match self
                    .run_one(&cfg, ScheduledScanKind::Daily, schedule.intensity)
                    .await
                {
                    Ok(()) => {
                        last_slots.insert(schedule.id.clone(), slot);
                        if matches!(schedule.frequency, ScheduleFrequency::Once) {
                            if let Err(err) =
                                remove_one_shot_schedule(&self.config_path, &cfg, &schedule.id)
                            {
                                tracing::warn!(
                                    "failed to remove one-shot schedule after run: {}",
                                    err
                                );
                            }
                        }
                    }
                    Err(err) => {
                        log_audit(
                            &self.node_id,
                            AuditCategory::Discovery,
                            AuditSeverity::Warning,
                            AuditAction::Failed,
                            &format!("scheduled Guardian network scan failed: {}", err),
                        );
                    }
                }
            }
        }
    }

    async fn run_one(
        &self,
        cfg: &NmapConfig,
        kind: ScheduledScanKind,
        intensity: ScanIntensity,
    ) -> DiscoveryResult<()> {
        let started_at = Utc::now();
        let target = cfg.resolved_target_cidr();

        log_audit(
            &self.node_id,
            AuditCategory::Discovery,
            AuditSeverity::Info,
            AuditAction::Started,
            &format!(
                "{} Guardian network scan {} intensity={:?}",
                schedule_name(kind),
                target,
                intensity
            ),
        );

        let xml = match NmapRunner::run_with_intensity(cfg, &target, intensity).await {
            Ok(xml) => xml,
            Err(err) => {
                let completed_at = Utc::now();
                let counts = {
                    let inv = self.state.lock().await;
                    run_history::status_counts(&inv)
                };
                let record = run_history::build_record(
                    started_at,
                    completed_at,
                    ScanRunSource::Scheduled,
                    Some(kind),
                    intensity,
                    target.clone(),
                    false,
                    Some(err.to_string()),
                    None,
                    counts,
                    None,
                    &self.inventory_path,
                );
                self.append_history_record(&record);
                return Err(err);
            }
        };

        // Persist raw XML for forensic re-parsing (rotated last 10).
        let mut raw_xml_path = None;
        if let Some(state_dir) = self.inventory_path.parent() {
            match crate::discovery::raw_store::RawXmlStore::persist(state_dir, &xml) {
                Ok(path) => raw_xml_path = Some(path),
                Err(err) => tracing::warn!("raw_store persist failed: {}", err),
            }
        }

        let wl = Whitelist::load(&self.whitelist_path).unwrap_or_default();
        let devices = match nmap_parser::parse(&xml) {
            Ok(devices) => devices,
            Err(err) => {
                let counts = {
                    let inv = self.state.lock().await;
                    run_history::status_counts(&inv)
                };
                let record = run_history::build_record(
                    started_at,
                    Utc::now(),
                    ScanRunSource::Scheduled,
                    Some(kind),
                    intensity,
                    target.clone(),
                    false,
                    Some(err.to_string()),
                    None,
                    counts,
                    raw_xml_path,
                    &self.inventory_path,
                );
                self.append_history_record(&record);
                return Err(err);
            }
        };
        let semantics = cfg.scan_semantics_for_intensity(&target, intensity);

        let intensity_label = match intensity {
            ScanIntensity::Stealth => "stealth",
            ScanIntensity::Standard => "standard",
            ScanIntensity::Aggressive => "aggressive",
        };
        let mut inv = self.state.lock().await;
        let delta = inv.merge(devices, semantics);
        for id in delta.updated.iter().chain(delta.newly_seen.iter()) {
            if let Some(device) = inv.by_id.get_mut(id) {
                device.last_scan_intensity = Some(intensity_label.to_string());
                wl.classify(device);
            }
        }
        let discovered_devices = delta
            .newly_seen
            .iter()
            .filter_map(|id| inv.by_id.get(id).cloned())
            .collect::<Vec<_>>();
        let pending_devices = discovered_devices
            .iter()
            .filter(|device| matches!(device.status, DeviceStatus::Unauthorized))
            .cloned()
            .collect::<Vec<_>>();
        let offline_devices = delta
            .marked_stale
            .iter()
            .filter_map(|id| inv.by_id.get(id).cloned())
            .collect::<Vec<_>>();
        let counts = run_history::status_counts(&inv);
        if let Err(err) = inv.save_atomic(&self.inventory_path) {
            let record = run_history::build_record(
                started_at,
                Utc::now(),
                ScanRunSource::Scheduled,
                Some(kind),
                intensity,
                target.clone(),
                false,
                Some(err.to_string()),
                Some(&delta),
                counts,
                raw_xml_path,
                &self.inventory_path,
            );
            self.append_history_record(&record);
            return Err(err);
        }
        let record = run_history::build_record(
            started_at,
            Utc::now(),
            ScanRunSource::Scheduled,
            Some(kind),
            intensity,
            target.clone(),
            true,
            None,
            Some(&delta),
            counts,
            raw_xml_path,
            &self.inventory_path,
        );
        self.append_history_record(&record);

        if !delta.newly_seen.is_empty() {
            vuln_trigger::queue_for_ai_review(&self.node_id, &delta.newly_seen);
            log_audit(
                &self.node_id,
                AuditCategory::Discovery,
                AuditSeverity::Warning,
                AuditAction::Detected,
                &format!(
                    "{} scan discovered {} new device(s) on subnet",
                    schedule_name(kind),
                    delta.newly_seen.len()
                ),
            );
        }
        drop(inv);

        for device in &discovered_devices {
            crate::rules::publish(crate::rules::RuleEvent::from_device_discovered(
                &self.node_id,
                device,
            ));
            if matches!(
                device.status,
                DeviceStatus::Unauthorized | DeviceStatus::Drifted
            ) {
                crate::rules::publish(crate::rules::RuleEvent::from_device_unauthorized(
                    &self.node_id,
                    device,
                ));
            }
        }
        for device in discovered_devices {
            crate::notify::publish_device_discovered(&device);
        }
        for device in pending_devices {
            crate::notify::publish_device_pending_approval(&device);
        }
        for device in offline_devices {
            crate::notify::publish_guardian_offline(&device);
        }
        Ok(())
    }

    fn append_history_record(&self, record: &run_history::ScanRunRecord) {
        let Some(state_dir) = self.inventory_path.parent() else {
            return;
        };

        let path = run_history::history_path(state_dir);
        if let Err(err) = run_history::append_record(&path, record) {
            tracing::warn!("discovery run history persist failed: {}", err);
        }
    }

    /// Test hook for timeout-bounded integration checks in `tests/`.
    #[doc(hidden)]
    pub async fn run_one_for_test(
        &self,
        cfg: &NmapConfig,
        kind: ScheduledScanKind,
        intensity: ScanIntensity,
    ) -> DiscoveryResult<()> {
        self.run_one(cfg, kind, intensity).await
    }
}

fn schedule_period(kind: ScheduledScanKind) -> Duration {
    match kind {
        ScheduledScanKind::Hourly => Duration::from_secs(3600),
        ScheduledScanKind::Daily => Duration::from_secs(86_400),
    }
}

fn schedule_name(kind: ScheduledScanKind) -> &'static str {
    match kind {
        ScheduledScanKind::Hourly => "hourly",
        ScheduledScanKind::Daily => "daily",
    }
}

fn daily_schedule_slot(cfg: &NmapConfig) -> Option<String> {
    let now = Local::now();
    let profile = &cfg.schedules.daily;
    if !profile
        .days
        .iter()
        .any(|day| schedule_day_matches(*day, now.weekday()))
    {
        return None;
    }

    let (hour, minute) = profile.time.split_once(':')?;
    let hour = hour.parse::<u32>().ok()?;
    let minute = minute.parse::<u32>().ok()?;
    // The scheduler polls periodically and is not guaranteed to wake at the
    // exact second of the configured minute. Once the configured time has
    // passed, the date/time slot uniquely identifies this day's run and
    // `last_daily_slot` prevents duplicate execution.
    if (now.hour(), now.minute()) < (hour, minute) {
        return None;
    }

    Some(format!("{}-{:02}:{:02}", now.date_naive(), hour, minute))
}

fn schedule_day_matches(day: ScheduleDay, weekday: chrono::Weekday) -> bool {
    matches!(
        (day, weekday),
        (ScheduleDay::Monday, chrono::Weekday::Mon)
            | (ScheduleDay::Tuesday, chrono::Weekday::Tue)
            | (ScheduleDay::Wednesday, chrono::Weekday::Wed)
            | (ScheduleDay::Thursday, chrono::Weekday::Thu)
            | (ScheduleDay::Friday, chrono::Weekday::Fri)
            | (ScheduleDay::Saturday, chrono::Weekday::Sat)
            | (ScheduleDay::Sunday, chrono::Weekday::Sun)
    )
}

fn active_schedule_slot(schedule: &ScanScheduleProfile) -> Option<String> {
    let now = schedule_clock(&schedule.timezone)?;
    let (hour, minute) = parse_schedule_time(&schedule.time)?;
    let candidate = match schedule.frequency {
        ScheduleFrequency::Once => {
            let today = NaiveDate::from_ymd_opt(now.year, now.month, now.day)?;
            let scheduled_date = if (now.hour, now.minute) > (hour, minute) {
                today.succ_opt()?
            } else if (now.hour, now.minute) < (hour, minute) {
                return None;
            } else {
                today
            };
            if scheduled_date != today {
                return None;
            }
            format!("{}T{:02}:{:02}", scheduled_date, hour, minute)
        }
        ScheduleFrequency::Daily | ScheduleFrequency::Custom => {
            if !schedule.days.is_empty()
                && !schedule
                    .days
                    .iter()
                    .any(|day| schedule_day_number(*day) == now.weekday)
            {
                return None;
            }
            if (now.hour, now.minute) < (hour, minute) {
                return None;
            }
            format!("{:04}-{:02}-{:02}", now.year, now.month, now.day)
        }
        ScheduleFrequency::Weekly => {
            if schedule.days.is_empty()
                || !schedule
                    .days
                    .iter()
                    .any(|day| schedule_day_number(*day) == now.weekday)
            {
                return None;
            }
            if (now.hour, now.minute) < (hour, minute) {
                return None;
            }
            format!("{:04}-{:02}-{:02}", now.year, now.month, now.day)
        }
        ScheduleFrequency::Monthly => {
            let day_of_month = schedule.day_of_month.unwrap_or(1);
            let last_day = last_day_of_month(now.year, now.month)?;
            if now.day != u32::from(day_of_month).min(last_day)
                || (now.hour, now.minute) < (hour, minute)
            {
                return None;
            }
            format!("{:04}-{:02}", now.year, now.month)
        }
        ScheduleFrequency::Yearly => {
            let month = schedule.month.unwrap_or(1);
            if now.month != u32::from(month) {
                return None;
            }
            let last_day = last_day_of_month(now.year, now.month)?;
            let day = u32::from(schedule.day_of_month.unwrap_or(1)).min(last_day);
            if now.day != day || (now.hour, now.minute) < (hour, minute) {
                return None;
            }
            format!("{:04}", now.year)
        }
    };

    Some(format!("{}-{candidate}", schedule.frequency.as_str()))
}

struct ScheduleClock {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    /// ISO weekday: Monday = 1, Sunday = 7.
    weekday: u8,
}

/// Resolve the configured IANA timezone using the host's zoneinfo database.
/// This keeps scheduler execution aligned with the timezone selected in the UI,
/// including daylight-saving transitions, instead of silently using server time.
fn schedule_clock(timezone: &str) -> Option<ScheduleClock> {
    if timezone.is_empty()
        || !timezone
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '+' | '-'))
    {
        return None;
    }
    let output = std::process::Command::new("date")
        .env("TZ", timezone)
        .arg("+%Y,%m,%d,%H,%M,%u")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let fields = std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .split(',')
        .collect::<Vec<_>>();
    if fields.len() != 6 {
        return None;
    }
    Some(ScheduleClock {
        year: fields[0].parse().ok()?,
        month: fields[1].parse().ok()?,
        day: fields[2].parse().ok()?,
        hour: fields[3].parse().ok()?,
        minute: fields[4].parse().ok()?,
        weekday: fields[5].parse().ok()?,
    })
}

fn schedule_day_number(day: ScheduleDay) -> u8 {
    match day {
        ScheduleDay::Monday => 1,
        ScheduleDay::Tuesday => 2,
        ScheduleDay::Wednesday => 3,
        ScheduleDay::Thursday => 4,
        ScheduleDay::Friday => 5,
        ScheduleDay::Saturday => 6,
        ScheduleDay::Sunday => 7,
    }
}

fn last_day_of_month(year: i32, month: u32) -> Option<u32> {
    let first_of_next = if month == 12 {
        NaiveDate::from_ymd_opt(year.checked_add(1)?, 1, 1)?
    } else {
        NaiveDate::from_ymd_opt(year, month.checked_add(1)?, 1)?
    };
    Some((first_of_next - ChronoDuration::days(1)).day())
}

fn parse_schedule_time(time: &str) -> Option<(u32, u32)> {
    let (hour_text, minute_text) = time.split_once(':')?;
    let hour = hour_text.parse::<u32>().ok()?;
    let minute = minute_text.parse::<u32>().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some((hour, minute))
}

fn remove_one_shot_schedule(
    path: &PathBuf,
    cfg: &NmapConfig,
    schedule_id: &str,
) -> std::io::Result<()> {
    let mut updated = cfg.clone();
    updated
        .scan_schedules
        .retain(|schedule| schedule.id != schedule_id);
    if updated.scan_schedules.is_empty() {
        updated.enabled = false;
    }
    let yaml = serde_yaml::to_string(&updated).map_err(std::io::Error::other)?;
    atomic_write_text(path, &yaml)
}

fn atomic_write_text(path: &PathBuf, content: &str) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    let tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::fs::write(tmp.path(), content)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

impl ScheduleFrequency {
    fn as_str(self) -> &'static str {
        match self {
            ScheduleFrequency::Once => "once",
            ScheduleFrequency::Daily => "daily",
            ScheduleFrequency::Weekly => "weekly",
            ScheduleFrequency::Monthly => "monthly",
            ScheduleFrequency::Yearly => "yearly",
            ScheduleFrequency::Custom => "custom",
        }
    }
}

const DEFAULT_NMAP_YAML: &str = r#"# /etc/sgx-guardian/discovery/nmap.yaml
# Scheduled NMAP discovery - off by default. Admin opts in.
enabled: false
target_cidr: null         # auto-detect active LAN CIDR at runtime if null
timeout_secs: 600
exclude: []
schedules:
  hourly:
    intensity: standard   # stealth | standard | aggressive
  daily:
    intensity: aggressive # stealth | standard | aggressive
    days: [monday, wednesday, friday]
    time: "23:00"         # local HH:MM
"#;

const DEFAULT_WHITELIST_YAML: &str = r#"# /etc/sgx-guardian/discovery/whitelist.yaml
# NMAP whitelist. Empty by default - admin populates after first scan.
version: "1.0"
devices: []
# Example with strict IP binding (recommended on multi-subnet networks):
#  - mac: "AA:BB:CC:11:22:33"
#    label: "Office printer"
#    expected_os: "Linux"
#    expected_ports: [9100]
#    expected_ips: ["10.0.0.50/32"]
"#;

fn seed_if_missing(path: &std::path::Path, contents: &str) {
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let tmp = path.with_extension("yaml.tmp");
    if std::fs::write(&tmp, contents).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}
