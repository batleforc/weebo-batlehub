//! Use-cases and the ports they need. No concrete adapter and no
//! Kubernetes client here: adapters implement [`ports`] in
//! `adapters-outbound`, `operator::main` injects them.

pub mod cache_volume;
pub mod cron;
pub mod pod_safety;
pub mod ports;
pub mod redact;
pub mod use_cases;
pub mod workload;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
