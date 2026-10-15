//! What the cache volume of a managed instance can't do, said rather than
//! left to a pod stuck `Pending`: a single-writer claim mounted by more
//! pods than it admits, a size the claim was created with and keeps.
//!
//! Both depend on the storage being a filesystem cache, which lives in the
//! open configuration (its layers included): the CRD's rules can't see it,
//! so these are advisories, not refusals.

use api::managed::{AccessMode, ManagedInstance};
use domain::Advisory;
use domain::error::ReasonCode;

use crate::workload::DocumentFacts;

/// The pods the cache's claim won't let run: several proxy replicas on a
/// single-writer claim (each surge or extra pod lands on another node and
/// waits for the volume), a separate worker on `ReadWriteOncePod` (the
/// worker mounts the proxy's cache; one pod only may).
pub fn single_writer(spec: &ManagedInstance, facts: &DocumentFacts) -> Option<Advisory> {
    if facts.cache_path.is_none() || !spec.persistence.single_writer() {
        return None;
    }
    let mode = spec.persistence.access_mode.as_str();
    let mut causes = Vec::new();
    if spec.replicas > 1 {
        causes.push(format!(
            "{} proxy replicas share it (pods on other nodes wait for the volume)",
            spec.replicas
        ));
    }
    if spec.persistence.access_mode == AccessMode::ReadWriteOncePod && spec.worker.is_some() {
        causes.push("the worker mounts it too (it never starts)".into());
    }
    (!causes.is_empty()).then(|| Advisory {
        reason: ReasonCode::CacheVolumeSingleWriter,
        message: format!(
            "the filesystem cache's claim is {mode}, one writer: {}. Use ReadWriteMany, one \
             replica, or an object store (storage.type)",
            causes.join("; ")
        ),
    })
}

/// `persistence.size` against what the claim the operator created
/// requests (`current`): the claim is created once, never resized.
pub fn not_resized(spec: &ManagedInstance, current: &str) -> Option<Advisory> {
    let wanted = &spec.persistence.size.0;
    let differs = match (bytes(wanted), bytes(current)) {
        (Some(a), Some(b)) => a != b,
        _ => wanted.trim() != current.trim(),
    };
    differs.then(|| Advisory {
        reason: ReasonCode::CacheVolumeNotResized,
        message: format!(
            "persistence.size is {wanted}, the cache's claim requests {current}: the operator \
             creates the claim once and never resizes it. Expand the claim yourself if its \
             StorageClass allows it (kubectl patch pvc), or set persistence.size back"
        ),
    })
}

/// A Kubernetes quantity of bytes (`10Gi`, `500M`, `1.5Gi`, `1e9`), as a
/// number of bytes; `None` when it isn't one.
fn bytes(quantity: &str) -> Option<f64> {
    const SUFFIXES: [(&str, f64); 13] = [
        ("Ki", 1024.0),
        ("Mi", 1_048_576.0),
        ("Gi", 1_073_741_824.0),
        ("Ti", 1_099_511_627_776.0),
        ("Pi", 1_125_899_906_842_624.0),
        ("Ei", 1_152_921_504_606_846_976.0),
        ("k", 1e3),
        ("M", 1e6),
        ("G", 1e9),
        ("T", 1e12),
        ("P", 1e15),
        ("E", 1e18),
        ("", 1.0),
    ];
    let q = quantity.trim();
    SUFFIXES.iter().find_map(|(suffix, factor)| {
        let number: f64 = q.strip_suffix(suffix)?.parse().ok()?;
        Some(number * factor)
    })
}

#[cfg(test)]
mod tests {
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use serde_json::json;

    use super::*;

    fn facts(filesystem: bool) -> DocumentFacts {
        DocumentFacts::of(&if filesystem {
            json!({})
        } else {
            json!({"storage": {"type": "s3"}})
        })
    }

    #[test]
    fn quantities_compare_by_bytes() {
        assert_eq!(bytes("10Gi"), Some(10.0 * 1024f64.powi(3)));
        assert_eq!(bytes("1024Mi"), bytes("1Gi"));
        assert_eq!(bytes("1e9"), bytes("1G"));
        assert_eq!(bytes("1.5k"), Some(1500.0));
        assert_eq!(bytes("ten"), None);
        assert_eq!(bytes("10Xi"), None);
        assert_eq!(bytes("2E"), Some(2e18));
    }

    #[test]
    fn a_size_the_claim_doesn_t_have_is_reported() {
        let mut spec = ManagedInstance::default();
        assert!(not_resized(&spec, "10Gi").is_none());
        assert!(not_resized(&spec, "10240Mi").is_none());
        spec.persistence.size = Quantity("20Gi".into());
        let advisory = not_resized(&spec, "10Gi").unwrap();
        assert_eq!(advisory.reason, ReasonCode::CacheVolumeNotResized);
        assert!(advisory.message.contains("20Gi"), "{}", advisory.message);
        assert!(advisory.message.contains("10Gi"), "{}", advisory.message);
    }

    #[test]
    fn a_single_writer_claim_mounted_by_more_pods_is_reported() {
        let mut spec = ManagedInstance::default();
        assert!(single_writer(&spec, &facts(true)).is_none());
        spec.replicas = 2;
        let advisory = single_writer(&spec, &facts(true)).unwrap();
        assert_eq!(advisory.reason, ReasonCode::CacheVolumeSingleWriter);
        assert!(advisory.message.contains("2 proxy replicas"));
        // An object store mounts no cache.
        assert!(single_writer(&spec, &facts(false)).is_none());
        // Neither does a cache in an emptyDir, nor a ReadWriteMany claim.
        spec.persistence.enabled = false;
        assert!(single_writer(&spec, &facts(true)).is_none());
        spec.persistence.enabled = true;
        spec.persistence.access_mode = AccessMode::ReadWriteMany;
        assert!(single_writer(&spec, &facts(true)).is_none());

        // A worker beside the proxy: fine on ReadWriteOnce (same node),
        // never on ReadWriteOncePod.
        let mut spec: ManagedInstance = serde_json::from_value(json!({"worker": {}})).unwrap();
        assert!(single_writer(&spec, &facts(true)).is_none());
        spec.persistence.access_mode = AccessMode::ReadWriteOncePod;
        let advisory = single_writer(&spec, &facts(true)).unwrap();
        assert!(advisory.message.contains("worker"), "{}", advisory.message);
    }
}
