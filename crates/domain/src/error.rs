//! Single source of truth for every reason the operator surfaces. Status
//! conditions, Kubernetes Events and metrics all carry one of these
//! variants — never an ad-hoc string at the call site. Add a variant here
//! before reporting a new cause anywhere.
//!
//! The doc comments become the "Reason codes" page of the documentation:
//! each says when the code appears and what to do about it. The catalogue
//! is complete from the start (the spec's §5); the kinds that report most
//! of them arrive milestone by milestone.

pub use weebo_kit_domain::{Reason, Severity};

weebo_kit_domain::reason_codes! {
    pub enum ReasonCode {
        /// `Ready: True` — the one success reason every reconciler uses.
        Reconciled,
        /// The spec is inconsistent in a way only a change of the CR fixes
        /// (a rule the CRD's validation can't express, a gate both set and
        /// exempted, `configApplyPending` outside an external instance
        /// without `manageConfig`…).
        InvalidSpec,

        // --- Instance resolution (every kind that targets an instance) ---
        /// `spec.instanceRef` names no `BatleHubLocalInstance` the operator
        /// sees, or, unset, the namespace has none to default to.
        InstanceNotFound,
        /// `spec.instanceRef` is unset and the namespace has several
        /// `BatleHubLocalInstance`s: set `spec.instanceRef`.
        InstanceAmbiguous,
        /// The instance named is out of reach: in another namespace that
        /// doesn't consent to it, or outside the namespace the operator is
        /// limited to.
        InstanceNotAllowed,
        /// `spec.instanceRef` now designates another instance than the one
        /// recorded in `status.instance`: not followed until
        /// `spec.instanceRef` names the instance to use explicitly.
        InstanceBindingChanged,
        /// The instance exists but is not (yet) `Ready`; the message carries
        /// the instance's own reason.
        InstanceNotReady,
        /// The instance is being deleted while CRs are still bound to it
        /// (named in the message): delete them first, or annotate the
        /// instance `batlehub.weebo.io/force-orphan: "true"` to leave them
        /// orphaned.
        InstanceInUse,

        // --- Secrets the operator reads ---
        /// The token Secret of the instance (admin token of an external
        /// instance, operator token supplied to a managed one), or its key,
        /// is missing or not UTF-8.
        TokenSecretMissing,
        /// The token Secret lacks the label
        /// `batlehub.weebo.io/instance-token: "true"`: the operator only
        /// reads a token from a Secret that opts in (it would send it to
        /// the instance's URL).
        TokenSecretNotAllowed,
        /// A Secret of `configLayers`, `credentials` or `configFrom` lacks
        /// the label `batlehub.weebo.io/credential: "true"`: its content
        /// would be sent to BatleHub, so it must opt in (the message gives
        /// the `kubectl label` command).
        SecretNotAllowed,

        // --- Talking to the instance ---
        /// BatleHub did not answer: network error, timeout, 502/504, or
        /// `/livez` silent.
        InstanceUnreachable,
        /// BatleHub refused the operator's token (401/403), or
        /// `GET /api/v1/me` returned a role other than `admin` (the message
        /// says which).
        OperatorUnauthorized,
        /// The configuration no longer declares the operator's token (the
        /// credentials layer of a managed instance, `spec.config` of an
        /// external one): applying it would lock the operator out.
        OperatorTokenShadowed,
        /// BatleHub answered with an error the operator doesn't expect (a
        /// 500, an unknown answer); the message keeps the status and the
        /// start of the body.
        RemoteError,
        /// BatleHub rejected a governance write (400), a version that
        /// doesn't exist included.
        RemoteRejected,
        /// What the CR references doesn't exist in BatleHub (a registry the
        /// instance doesn't serve).
        RemoteNotFound,

        // --- Configuration ---
        /// BatleHub's own parser refuses the rendered configuration
        /// (`reload.validation: Strict`), or a layer is not TOML.
        ConfigInvalid,
        /// A ConfigMap or Secret of `configLayers`, `credentials` or
        /// `configFrom` is missing.
        ConfigLayerMissing,
        /// The instance refused the configuration (dry run or load); it is
        /// re-staged at most every 10 minutes.
        ConfigRejected,
        /// The new configuration is not yet seen by every pod, or a reload
        /// is in progress; the message names the pods behind.
        ConfigPropagating,
        /// No proxy pod is ready to approve a reload.
        NoReadyPod,
        /// The desired replicas are not available or up to date (managed).
        WorkloadNotReady,
        /// The configuration endpoints answer 503 (hot reload disabled), or
        /// a pod reports hot reload disabled while the spec says otherwise.
        HotReloadDisabled,
        /// External instance: the first configuration layer is not
        /// writable.
        ConfigReadOnly,
        /// External instance with `manageConfig`: a key that needs a
        /// restart changed; the push is held back (the operator can't
        /// restart an instance it doesn't deploy).
        RestartForbidden,
        /// A `BatleHubRegistry` on an external instance without
        /// `manageConfig`: the operator renders no configuration there.
        InstanceConfigUnmanaged,
        /// Managed instance: an object the operator must create already
        /// exists and isn't the operator's — never adopted implicitly.
        OwnedObjectConflict,

        // --- Governance ---
        /// BatleHub has no grant storage configured (503).
        GrantStorageUnavailable,
        /// A grant in place on that node was not written by this CR, or
        /// another CR targets the same coordinate and subject.
        GrantConflict,
        /// A policy in place on that node was not written by this CR, or
        /// another CR targets the same coordinate.
        PolicyConflict,
        /// 409: the subject already holds these actions through package
        /// ownership.
        GrantHeldByOwnership,
        /// 403 on an exemption: `gates:exempt` is granted to no role, the
        /// operator's identity needs a grant on the version or its package
        /// (the message gives it).
        ExemptionNotPermitted,
        /// A `BatleHubNamespaceClaim`'s prefix is already claimed on that
        /// registry by something else (the console, the CLI, another CR):
        /// never taken over. The message says for which group and by whom;
        /// release that claim, or delete this CR.
        ClaimConflict,

        // --- Registries ---
        /// Another `BatleHubRegistry` rendered first on the same instance
        /// has the same `name`, or a registry of another namespace would
        /// complete an entry of the instance's own configuration.
        DuplicateRegistryName,
        /// A registry of another namespace contains a `${VAR}` placeholder:
        /// placeholders resolve from the instance's environment, so they
        /// are refused outside its namespace.
        NamespaceNotAllowed,
        /// The instance refused the configuration containing this
        /// registry.
        InstanceRejected,

        // --- Maintenance ---
        /// The maintenance action failed; `status.lastRun` has the details.
        MaintenanceFailed,
        /// The maintenance action exceeded `timeoutSeconds`.
        MaintenanceTimeout,
        /// The operator stopped while the run was in progress: closed as
        /// failed rather than replayed (at most once).
        MaintenanceInterrupted,

        // --- The operator itself ---
        /// An update would take a CR still carrying the finalizer out of
        /// the operator's label selector (`watch.labelSelector`): refused
        /// at admission.
        LeavesWatchScope,
        /// A Kubernetes API call of the operator itself failed (reading a
        /// CR or a Secret, patching a status, the finalizer) — retried.
        KubernetesApiError,

        // --- Advisories (next to `Ready: True`) ---
        /// A key that needs a restart changed and the operator won't roll
        /// the pods (`reload.restart: Never`, or an external instance): the
        /// keys are in the message.
        RestartRequired,
        /// `reload.strategy: Manual`: a validated configuration waits for
        /// the approval of its hash (in the message).
        ConfigHeld,
        /// `GET /admin/config/warnings` is not empty (`status.warnings`).
        ConfigWarnings,
        /// `${VAR}` placeholders the operator couldn't resolve for
        /// validation (names in the message).
        UnresolvedPlaceholders,
        /// The parser refused the configuration but `reload.validation:
        /// Lenient` applied it anyway.
        ConfigInvalidLenient,
        /// `registrySelector.namespaces.from` other than `Same` on an
        /// operator limited to one namespace: registries of other
        /// namespaces are not seen.
        RegistrySelectorIgnored,
        /// `autoTokenReview` asked on an operator limited to one namespace:
        /// no ClusterRoleBinding is created, bind TokenReview yourself.
        TokenReviewUnavailable,
        /// The registry is suspended (`spec.suspend`): kept, not rendered.
        RegistrySuspended,
        /// A maintenance run is in progress.
        MaintenanceRunning,
        /// The maintenance schedule is suspended.
        MaintenanceSuspended,
        /// A grant is legal but probably unintended (`status.warnings`).
        SuspiciousGrant,
        /// Exemptions past their `exemptUntil` (listed in the message):
        /// reported, not rewritten.
        ExemptionExpired,

        // --- Events only ---
        /// The instance reloaded a new configuration (Event only).
        ConfigReloaded,
        /// A new configuration was rolled out by restarting the pods (Event
        /// only).
        ConfigRolledOut,
        /// A rollout interrupts the instance (single replica, `Recreate`)
        /// (Warning Event only).
        RestartInterrupts,
        /// A maintenance run started (Event only).
        MaintenanceStarted,
        /// The finalizer revoked what the CR wrote in BatleHub (Event
        /// only).
        Revoked,
        /// The finalizer finished — cleanup done, or the CR force-orphaned
        /// (Event only).
        Released,
    }
}

impl Reason for ReasonCode {
    const SUCCESS: Self = ReasonCode::Reconciled;

    fn as_str(self) -> &'static str {
        ReasonCode::as_str(self)
    }

    fn severity(self) -> Severity {
        ReasonCode::severity(self)
    }
}

impl ReasonCode {
    /// Advisory codes don't block `Ready` (and count as `success` in the
    /// reconcile metrics); every failure cause is blocking.
    pub const fn severity(self) -> Severity {
        match self {
            ReasonCode::Reconciled
            | ReasonCode::RestartRequired
            | ReasonCode::ConfigHeld
            | ReasonCode::ConfigWarnings
            | ReasonCode::UnresolvedPlaceholders
            | ReasonCode::ConfigInvalidLenient
            | ReasonCode::RegistrySelectorIgnored
            | ReasonCode::TokenReviewUnavailable
            | ReasonCode::RegistrySuspended
            | ReasonCode::MaintenanceRunning
            | ReasonCode::MaintenanceSuspended
            | ReasonCode::SuspiciousGrant
            | ReasonCode::ExemptionExpired
            | ReasonCode::ConfigReloaded
            | ReasonCode::ConfigRolledOut
            | ReasonCode::RestartInterrupts
            | ReasonCode::MaintenanceStarted
            | ReasonCode::Revoked
            | ReasonCode::Released => Severity::Advisory,
            _ => Severity::Blocking,
        }
    }

    /// Failures only a change of the spec (or of what it references) can
    /// clear: retried on the steady interval rather than every 30 s. Each
    /// is retried right away anyway by the change that clears it (the
    /// kit's predicates, the watches).
    pub const fn needs_a_change(self) -> bool {
        matches!(
            self,
            ReasonCode::InvalidSpec
                | ReasonCode::ConfigInvalid
                | ReasonCode::ConfigRejected
                | ReasonCode::RemoteRejected
                | ReasonCode::OperatorTokenShadowed
                | ReasonCode::GrantConflict
                | ReasonCode::PolicyConflict
                | ReasonCode::GrantHeldByOwnership
                | ReasonCode::ExemptionNotPermitted
                | ReasonCode::ClaimConflict
                | ReasonCode::DuplicateRegistryName
                | ReasonCode::NamespaceNotAllowed
                | ReasonCode::InstanceNotAllowed
                | ReasonCode::InstanceBindingChanged
                | ReasonCode::InstanceAmbiguous
                | ReasonCode::ConfigReadOnly
                | ReasonCode::RestartForbidden
                | ReasonCode::InstanceConfigUnmanaged
                | ReasonCode::OwnedObjectConflict
                | ReasonCode::SecretNotAllowed
                | ReasonCode::TokenSecretNotAllowed
                // A failed run is never retried: a new one comes from the
                // schedule, `run-now` or a new spec.
                | ReasonCode::MaintenanceFailed
                | ReasonCode::MaintenanceTimeout
                | ReasonCode::MaintenanceInterrupted
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_is_pascal_case() {
        weebo_kit_domain::reason::assert_pascal_case(ReasonCode::ALL);
    }

    #[test]
    fn only_failures_wait_for_a_change() {
        for code in ReasonCode::ALL {
            if code.needs_a_change() {
                assert_eq!(code.severity(), Severity::Blocking, "{code}");
            }
        }
        assert!(!ReasonCode::InstanceUnreachable.needs_a_change());
        assert!(ReasonCode::TokenSecretNotAllowed.needs_a_change());
    }
}
