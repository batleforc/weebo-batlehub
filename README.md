# weebo-batlehub

Kubernetes operator driving [BatleHub](https://github.com/batlehub/batlehub)
(package registry proxy-cache) instances as CRDs, built on
[weebo-operator-kit](https://github.com/batleforc/weebo-operator-kit).

> **M2 — configuration management.** The operator connects a
> `BatleHubLocalInstance`, checks that it answers and that its token
> carries the admin role, and with `external.manageConfig` pushes the
> configuration rendered from the CR and its `BatleHubRegistry`s (to each
> pod with `external.podSelector`), validated by BatleHub's own parser.
> The first alpha (0.1.0-alpha.1) closes M2. The design and the
> milestones are in [`.prompt/plan.md`](.prompt/plan.md).

| Kind                    | Scope      | What it does                                                    |
| ----------------------- | ---------- | --------------------------------------------------------------- |
| `BatleHubLocalInstance` | Namespaced | A BatleHub instance: its URL and admin token (`external.adminTokenSecretRef`), and its configuration (`config`, `configLayers`, `external.manageConfig`) |
| `BatleHubRegistry`      | Namespaced | One `[[registries]]` entry of an instance, as its own object (possibly from another namespace the instance accepts) |
| `BatleHubNamespaceClaim` | Namespaced | A team namespace of a registry: a package name prefix reserved to a group, claimed through the admin API |
| `BatleHubPackageGrant`  | Namespaced | The grants of a package or a version, one per subject, written through the admin API |
| `BatleHubPackagePolicy` | Namespaced | The policy of a package or a version, and a version's exemptions from its gates |

Planned (see the plan): `BatleHubMaintenance`, and the managed mode (the
operator deploys BatleHub).

The token Secret must be labelled `batlehub.weebo.io/instance-token: "true"`:
the operator reads Secrets with its own rights and sends the token to the
URL the instance names, so a Secret opts in.

## Layout

Hexagonal, one crate per layer, same rules as every weebo operator:

| Crate               | Holds                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------- |
| `domain`            | the reason codes (`reason_codes!`, the plan's §5), no dependency                       |
| `api`               | the CRD types (`#[derive(CustomResource)]`), the kit's shared field types              |
| `application`       | ports (`AdminGateway`, `GatewayFactory`, `ConfigParser`) and the `reconcile_*` use cases |
| `batlehub-client`   | **generated** from BatleHub's OpenAPI (`spec/`, `task gen:client`), never hand-edited  |
| `adapters-outbound` | `HttpAdminGateway` on the generated client, its factory, `LocalInstanceDirectory`, the configuration parser |
| `adapters-inbound`  | the controllers and the HTTPS router (health, scope guard, admission webhook)          |
| `operator`          | the binary: telemetry, leader election, HTTPS server, controllers                      |
| `crdgen`            | writes `deploy/crd/` from `api`                                                        |
| `testkit`           | envtest and fakes for the integration tests                                            |

`deploy/charts/weebo-batlehub` is a thin chart on the kit's library chart:
`templates/_params.tpl` holds what is the operator's own, `values.yaml`
follows the kit's values contract. `docs/` is the documentation site
(`@weebo/operator-docs`), published to
<https://batleforc.github.io/weebo-batlehub>.

## Tasks

```bash
task init        # toolchain (mise), cog.toml from the kit, git hooks
task doctor      # envtest prerequisites
task recu        # the client, the CRDs, their chart copies and the docs' generated pages
task lint        # fmt --check, clippy -D warnings, actionlint, hadolint
task lint:helm   # helm lint + the kit's smoke renders
task test        # unit + contract tests
task test:all    # + envtest integration tests
task e2e         # kind: cert-manager, the chart, the smoke, leader failover
task coverage    # cargo llvm-cov, fails under 85%
task audit       # cargo-deny, trivy, npm audit (docs)
task docs        # the docs site in dev mode
task gen:bump BATLEHUB_VERSION=x.y.z  # another BatleHub release: spec + client
task kit:sync TAG=vX.Y.Z               # another kit release
```

`lint`, `audit`, `coverage`, `doctor` and the chart tasks are the kit's
(`tasks/*.yaml`, included remotely and pinned by checksum); CI calls the
kit's reusable `checks.yml` and `publish.yml`.

## License

Apache-2.0 — see [LICENSE.md](LICENSE.md).
