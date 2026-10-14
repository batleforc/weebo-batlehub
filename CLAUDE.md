# weebo-batlehub

Kubernetes operator driving BatleHub (package registry proxy-cache)
instances as CRDs, on weebo-operator-kit. **`.prompt/plan.md`** is the
authoritative design doc (CRDs, reason codes, reload protocol,
governance, milestones M0–M5 and their "Constats") — read it before any
non-trivial change; this file is only an index.

## Rules

- Hexagonal layering, same as every weebo operator: `domain` depends on
  nothing but the kit's domain; `api` only serde/schemars/kube types;
  `application` has no adapter nor Kubernetes client; adapters, the
  binary and the testkit hold the `kube`/HTTP code. Inbound adapters read
  nothing of the cluster beyond the reconciled CR: everything goes
  through the ports.
- One namespaced instance kind, `BatleHubLocalInstance` (the kit's
  `LocalInstance` role, like ForgejoLocalInstance/AuthentikLocalInstance);
  no cluster-scoped kind in `v1alpha1`. Resolution is the kit's
  (`resolve_bound`, `check_binding`) through `LocalInstanceDirectory`.
- Every cause shown to a user is a `domain::error::ReasonCode` (doc
  comments become the docs' "Reason codes" page; keep braces balanced and
  `severity` arms fully qualified — the generator scans the text).
- Secrets whose content leaves for BatleHub opt in by label: the token
  through the kit's `read_local_instance_token`
  (`batlehub.weebo.io/instance-token`), other Secrets with
  `batlehub.weebo.io/credential` (plan §2.11).
- `crates/batlehub-client` is generated (`task gen:client` from
  `spec/batlehub-v*.json` + `spec/patches/*.jq`): never edit it by hand.
- BatleHub's configuration is validated by BatleHub's own parser
  (`batlehub-config`), never a copy: M2 waits for batlehub v1.5.0
  (`merge_layers`, `validate_layers`, `RESTART_KEYS`, plan D4/D8).
- `kube`/`k8s-openapi` versions are the kit's; the kit is pinned by tag
  everywhere (`task kit:sync TAG=…` moves them all).
- Generated artifacts (`task recu`): the client, `deploy/crd/`, the chart's
  `templates/crds/`, `docs/content/docs/{crds,reference}/`,
  `docs/public/crd-schemas/` — CI fails on drift.

## Commands

```bash
task lint · task lint:helm · task test · task test:all · task e2e
task recu · task audit · task coverage · task docs · task docs:build
task gen:bump BATLEHUB_VERSION=x.y.z · task kit:sync TAG=vX.Y.Z
```

envtest needs Go and `libclang.so` (`LIBCLANG_PATH`, default `/usr/lib64`,
see the Taskfile's `env:`); `task doctor` checks the setup.

Commits follow Conventional Commits (cocogitto, `cog.toml` rendered from
the kit by `task kit:cog` — never edit it by hand); hooks run `recu`,
`lint`, `test`, `audit` before each commit and `audit` + `test:all` before
each tag. Commits are signed by the user.
