// Input of `weebo-crd-docs` (@weebo/operator-docs), run by `task recu` /
// `npm run gen:crds`: what the CRD reference pages say beyond the CRDs
// themselves. Paths default to the expected tree (../deploy/crd →
// content/docs/crds + public/crd-schemas).
import { defineConfig } from "@weebo/operator-docs/crd-docs";

export default defineConfig({
  // `BatleHubLocalInstance` → example named `my-local-instance`.
  kindPrefix: "BatleHub",
  // Sidebar order follows the order you'd create things in, not the alphabet.
  order: [
    "BatleHubLocalInstance",
    "BatleHubRegistry",
    "BatleHubNamespaceClaim",
    "BatleHubPackageGrant",
    "BatleHubPackagePolicy",
    "BatleHubMaintenance",
  ],
  // The guide that explains each kind, linked from its reference page.
  guides: {
    BatleHubLocalInstance: ["Connect a BatleHub instance", "/docs/guides/connect-instance"],
    BatleHubRegistry: ["Manage the configuration", "/docs/guides/manage-config"],
    BatleHubNamespaceClaim: ["Team namespaces", "/docs/guides/team-namespaces"],
    BatleHubPackageGrant: ["Package grants and policies", "/docs/guides/package-governance"],
    BatleHubPackagePolicy: ["Package grants and policies", "/docs/guides/package-governance"],
    BatleHubMaintenance: ["Maintenance", "/docs/guides/maintenance"],
  },
  // A minimal, realistic `spec` per kind, checked against the schema (every
  // required field present, every key a real field): a renamed field fails
  // generation instead of shipping a stale example.
  examples: {
    BatleHubLocalInstance: {
      external: {
        url: "https://batlehub.example.com",
        adminTokenSecretRef: { name: "batlehub-admin", key: "token" },
      },
    },
    BatleHubRegistry: {
      type: "npm",
      config: { upstreams: ["https://registry.npmjs.org"] },
    },
    BatleHubNamespaceClaim: {
      registry: "npm",
      prefix: "@acme/web",
      group: "oidc:web-team",
    },
    BatleHubPackageGrant: {
      registry: "npm",
      package: "@acme/billing",
      grants: [{ subject: "group:oidc:finance", actions: ["releases:read"] }],
    },
    BatleHubPackagePolicy: {
      registry: "npm",
      package: "@acme/billing",
      version: "1.4.2",
      policy: { visibility: "team" },
    },
    BatleHubMaintenance: {
      action: "retentionRun",
      params: { registry: "npm", dryRun: false },
      schedule: "30 3 * * 0",
    },
  },
  // The operator reference pages (content/docs/reference/), generated from
  // the Rust sources: reason codes (crates/domain/src/error.rs), Events,
  // metrics & health, resource budget (measured from M5).
  reference: {
    metricsPrefix: "weebo_batlehub",
    // The operator's own metrics (spec §6.11); each name is checked in
    // crates/.
    extraMetrics: [
      {
        name: "weebo_batlehub_instance_ready",
        type: "gauge",
        labels: "`instance_namespace`, `instance_name`",
        description: "1 when the BatleHubLocalInstance is `Ready`, 0 otherwise; gone with the instance",
      },
      {
        name: "weebo_batlehub_instance_restart_required",
        type: "gauge",
        labels: "`instance_namespace`, `instance_name`",
        description: "Keys waiting for a restart (`status.restartKeys`): `reload.restart: Never`, or a restart key held back on an external instance",
      },
      {
        name: "weebo_batlehub_instance_config_warnings",
        type: "gauge",
        labels: "`instance_namespace`, `instance_name`, `code`",
        description: "BatleHub's warnings on its configuration (`status.warnings`), by code; a warning that goes takes its series with it",
      },
      {
        name: "weebo_batlehub_admin_requests_total",
        type: "counter",
        labels: "`endpoint` (the call: `reload`, `put_grant`…, `maintenance` for an action's), `status` (`ok`, or the error class: `unreachable`, `unauthorized`, `rejected`…)",
        description: "Calls of BatleHub's admin API",
      },
      {
        name: "weebo_batlehub_maintenance_runs_total",
        type: "counter",
        labels: "`action`, `result`",
        description: "BatleHubMaintenance runs",
      },
    ],
    // `task perf`'s report (target/perf/weebo-batlehub.json), copied here.
    perfReport: "perf/weebo-batlehub.json",
    // Refreshed every week by .github/workflows/perf.yml; the report
    // page says so.
    perfScheduled: true,
  },
});
