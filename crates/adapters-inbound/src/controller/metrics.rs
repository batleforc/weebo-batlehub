//! The instance gauges of the spec's §6.11, observed from what the last
//! pass of each `BatleHubLocalInstance` found:
//!
//! - `weebo_batlehub_instance_ready{instance_namespace,instance_name}`: 1
//!   when `Ready`;
//! - `weebo_batlehub_instance_restart_required{…}`: how many keys wait for
//!   a restart (`status.restartKeys`);
//! - `weebo_batlehub_instance_config_warnings{…,code}`: how many of
//!   BatleHub's warnings on its configuration carry `code`.
//!
//! Not `namespace`/`instance`: Prometheus sets those on every scraped
//! series (the operator's pod), they would be renamed `exported_*`.
//!
//! Observable gauges over one map: a series is reported only while its
//! entry exists, so a warning that goes takes its series with it, and a
//! deleted instance (`forget_instance`) all of its own.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use application::ports::BoundInstance;
use opentelemetry::KeyValue;

use super::FIELD_MANAGER;

pub const INSTANCE_READY: &str = "weebo_batlehub_instance_ready";
pub const INSTANCE_RESTART_REQUIRED: &str = "weebo_batlehub_instance_restart_required";
pub const INSTANCE_CONFIG_WARNINGS: &str = "weebo_batlehub_instance_config_warnings";

/// What the gauges report of one instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstanceSeries {
    pub ready: bool,
    pub restart_keys: usize,
    /// Warnings by code.
    pub warnings: BTreeMap<String, u64>,
}

type Key = (String, String);

fn series() -> &'static Mutex<BTreeMap<Key, InstanceSeries>> {
    static SERIES: OnceLock<Mutex<BTreeMap<Key, InstanceSeries>>> = OnceLock::new();
    SERIES.get_or_init(Default::default)
}

fn key(instance: &BoundInstance) -> Key {
    (
        instance.namespace.clone().unwrap_or_default(),
        instance.name.clone(),
    )
}

fn labels((namespace, name): &Key) -> [KeyValue; 2] {
    [
        KeyValue::new("instance_namespace", namespace.clone()),
        KeyValue::new("instance_name", name.clone()),
    ]
}

/// Registers the gauges once (a no-op meter until the telemetry installs
/// a real provider).
fn register() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        let meter = opentelemetry::global::meter(FIELD_MANAGER);
        // The callbacks live as long as the meter provider: the handles can go.
        let _ = meter
            .u64_observable_gauge(INSTANCE_READY)
            .with_description("1 when the BatleHubLocalInstance is Ready")
            .with_callback(|observer| {
                for (key, s) in series()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                {
                    observer.observe(u64::from(s.ready), &labels(key));
                }
            })
            .build();
        let _ = meter
            .u64_observable_gauge(INSTANCE_RESTART_REQUIRED)
            .with_description("Keys of the instance's configuration waiting for a restart")
            .with_callback(|observer| {
                for (key, s) in series()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                {
                    observer.observe(s.restart_keys as u64, &labels(key));
                }
            })
            .build();
        let _ = meter
            .u64_observable_gauge(INSTANCE_CONFIG_WARNINGS)
            .with_description("BatleHub's warnings on the instance's configuration, by code")
            .with_callback(|observer| {
                for (key, s) in series()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                {
                    for (code, count) in &s.warnings {
                        let [namespace, name] = labels(key);
                        observer.observe(
                            *count,
                            &[namespace, name, KeyValue::new("code", code.clone())],
                        );
                    }
                }
            })
            .build();
    });
}

/// What the last pass of `instance` found.
pub fn record_instance(instance: &BoundInstance, value: InstanceSeries) {
    register();
    series()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key(instance), value);
}

/// The instance is gone: its series too.
pub fn forget_instance(instance: &BoundInstance) {
    series()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&key(instance));
}

/// The series `instance` reports now (tests).
pub fn instance_series(instance: &BoundInstance) -> Option<InstanceSeries> {
    series()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key(instance))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_instance_reports_until_forgotten() {
        let hub = BoundInstance::local("metrics-test", "hub");
        let value = InstanceSeries {
            ready: true,
            restart_keys: 2,
            warnings: BTreeMap::from([("audit.no-retention".into(), 1)]),
        };
        record_instance(&hub, value.clone());
        assert_eq!(instance_series(&hub), Some(value));
        // A warning that goes takes its series with it.
        record_instance(&hub, InstanceSeries::default());
        assert!(instance_series(&hub).unwrap().warnings.is_empty());
        forget_instance(&hub);
        assert_eq!(instance_series(&hub), None);
    }
}
