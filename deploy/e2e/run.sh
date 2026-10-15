#!/usr/bin/env bash
# kind e2e (`task e2e`, .github/workflows/e2e.yml): deploys cert-manager and
# the operator chart into the current kube context, then the smoke — two
# BatleHubLocalInstances whose state the operator decides without a running
# BatleHub (an unlabelled token Secret, an unreachable URL) —, a real
# BatleHub (batlehub.yaml, 2 replicas) with an external instance that must
# end Ready and one pushing its configuration and a registry to each pod,
# and checks leader election on the real deployment.
#
# With a previously published chart, it first installs that release, creates
# the smoke CRs with it, then upgrades to this checkout's chart and checks
# they keep their state (skipped when no release exists yet — none before
# the first alpha).
#
# Env: IMAGE (operator image already loaded in the cluster, default
# weebo-batlehub-operator:e2e), CERT_MANAGER_VERSION (default: the pinned
# release below; its manifest is checksum-verified only for the pinned one),
# UPGRADE_FROM (previous chart version to upgrade from: empty = the latest
# published one, `none` = skip the upgrade test).
# -E: functions inherit the ERR trap that dumps diagnostics.
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CHART="$HERE/../charts/weebo-batlehub"
IMAGE="${IMAGE:-weebo-batlehub-operator:e2e}"
# Pinned: bump both together (sha256 of the release's cert-manager.yaml).
CERT_MANAGER_PINNED=v1.21.2
CERT_MANAGER_SHA256=e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-$CERT_MANAGER_PINNED}"
CHART_OCI=oci://ghcr.io/batleforc/charts/weebo-batlehub
UPGRADE_FROM="${UPGRADE_FROM:-}"
OPERATOR_NS=weebo-batlehub-system
RELEASE=weebo-batlehub
# The chart's default Lease name (leaderElection.leaseName).
LEASE=weebo-batlehub-operator-leader
WAIT=180s

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() {
  printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2
  dump
  exit 1
}

# Diagnostics for whatever failed: operator logs, CR conditions, events.
dump() {
  set +e
  step "diagnostics"
  kubectl -n "$OPERATOR_NS" get pods -o wide
  kubectl -n "$OPERATOR_NS" logs -l app.kubernetes.io/name=weebo-batlehub --tail=200 --prefix --all-containers
  kubectl -n team-a get batlehublocalinstances,batlehubregistries,batlehubnamespaceclaims,batlehubpackagegrants,batlehubpackagepolicies,batlehubmaintenances -o yaml
  kubectl -n team-a get pods -o wide
  kubectl -n team-a logs deploy/batlehub --tail=50
  kubectl -n team-a logs deploy/managed --tail=50
  kubectl get events -A --sort-by=.lastTimestamp | tail -n 50
}
# dump turns errexit off: leave right after it.
trap 'dump; exit 1' ERR

ensure_ns() { kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null; }

# Waits until `Ready` of instance $1 has reason $2.
reason_is() {
  local name="$1" want="$2" got=""
  for _ in $(seq 1 90); do
    got="$(kubectl -n team-a get batlehublocalinstance "$name" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)"
    [ "$got" = "$want" ] && return 0
    sleep 2
  done
  fail "$name: Ready reason is ${got:-<none>}, expected $want"
}

# Waits until `Ready` of registry $1 has reason $2.
registry_is() {
  local name="$1" want="$2" got=""
  for _ in $(seq 1 90); do
    got="$(kubectl -n team-a get batlehubregistry "$name" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)"
    [ "$got" = "$want" ] && return 0
    sleep 2
  done
  fail "registry $name: Ready reason is ${got:-<none>}, expected $want"
}

# The smoke's two instances, each on the reason it must end on.
smoke_state() {
  reason_is unlabelled TokenSecretNotAllowed
  reason_is unreachable InstanceUnreachable
}

# Retried while a webhook of the release comes up.
apply_smoke() {
  for _ in $(seq 1 30); do
    kubectl apply -f "$HERE/smoke.yaml" && return 0
    sleep 2
  done
  fail "the smoke CRs were never applied"
}

step "cert-manager ($CERT_MANAGER_VERSION)"
manifest="$(mktemp)"
curl -fsSLo "$manifest" \
  "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
if [ "$CERT_MANAGER_VERSION" = "$CERT_MANAGER_PINNED" ]; then
  echo "$CERT_MANAGER_SHA256  $manifest" | sha256sum -c - >/dev/null || fail "cert-manager.yaml checksum mismatch"
fi
kubectl apply -f "$manifest"
kubectl -n cert-manager wait --for=condition=Available --timeout="$WAIT" deploy --all

# ── Upgrade test, part 1: the previous release ────────────────────────────
head_version="$(awk '/^version:/ {print $2}' "$CHART/Chart.yaml")"
previous=""
if [ "$UPGRADE_FROM" != none ]; then
  if [ -n "$UPGRADE_FROM" ]; then
    previous="$UPGRADE_FROM"
  else
    # --devel: the alphas are prereleases, which Helm skips otherwise.
    previous="$(helm show chart "$CHART_OCI" --devel 2>/dev/null | awk '/^version:/ {print $2}' || true)"
  fi
  if [ -z "$previous" ]; then
    echo "no published chart at $CHART_OCI: upgrade test skipped"
  elif [ "$previous" = "$head_version" ] \
    && [ "$(git -C "$HERE" describe --exact-match --tags HEAD 2>/dev/null || true)" = "v$previous" ]; then
    # This checkout is that release: nothing to upgrade from. Between two
    # releases the version is the same but the code isn't: tested.
    echo "this checkout is the published release $previous: upgrade test skipped"
    previous=""
  fi
fi

if [ -n "$previous" ]; then
  step "upgrade test: install the published chart $previous"
  # Its own release image, pulled from ghcr.io; the same values as the
  # upgraded release below.
  helm install "$RELEASE" "$CHART_OCI" --version "$previous" \
    --namespace "$OPERATOR_NS" --create-namespace \
    --set extraEnv[0].name=RUST_LOG --set extraEnv[0].value=info \
    --wait --timeout 5m
  ensure_ns team-a
  apply_smoke
  smoke_state
  step "upgrade test: upgrade $previous -> $head_version (this checkout)"
fi

step "operator chart ($IMAGE)"
# The kit's library chart, as Chart.lock pins it.
helm dependency build --skip-refresh "$CHART"
helm upgrade --install "$RELEASE" "$CHART" \
  --namespace "$OPERATOR_NS" --create-namespace \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE##*:}" \
  --set image.pullPolicy=Never \
  --set extraEnv[0].name=RUST_LOG --set extraEnv[0].value=info \
  --wait --timeout 5m
kubectl -n "$OPERATOR_NS" rollout status "deploy/$RELEASE" --timeout="$WAIT"

if [ -n "$previous" ]; then
  step "upgrade test: CRs created by $previous keep their state"
  # The old operator wrote these reasons: clear them, then make the new
  # one reconcile the old CRs (a status patch alone triggers nothing).
  for name in unlabelled unreachable; do
    kubectl -n team-a patch batlehublocalinstance "$name" --subresource=status --type=merge \
      -p '{"status":{"conditions":[]}}'
    kubectl -n team-a annotate batlehublocalinstance "$name" e2e/upgraded="$(date +%s)" --overwrite
  done
  smoke_state
fi

step "smoke: what the operator decides before calling BatleHub"
ensure_ns team-a
apply_smoke
smoke_state

step "a real BatleHub: an external instance ends Ready"
kubectl apply -f "$HERE/batlehub.yaml"
kubectl -n team-a rollout status deploy/postgres --timeout="$WAIT"
kubectl -n team-a rollout status deploy/batlehub --timeout="$WAIT"
reason_is ready Reconciled
version="$(kubectl -n team-a get batlehublocalinstance ready -o jsonpath='{.status.version}')"
[ -n "$version" ] || fail "ready: no status.version"
echo "BatleHub $version"

step "manageConfig on each of 2 replicas (podSelector), with a registry"
reason_is hub Reconciled
registry_is npm Reconciled
hash="$(kubectl -n team-a get batlehublocalinstance hub -o jsonpath='{.status.configHash}')"
applied="$(kubectl -n team-a get batlehublocalinstance hub -o jsonpath='{.status.appliedConfigHash}')"
[ -n "$hash" ] && [ "$hash" = "$applied" ] || fail "hub: configHash $hash, appliedConfigHash $applied"
# Each pod's own file holds the registry (the image has no shell: a
# throwaway curl pod reads them by IP, with the admin token of
# batlehub.yaml).
admin_token="$(kubectl -n team-a get secret batlehub-admin -o jsonpath='{.data.token}' | base64 -d)"
# A pod ready after the push is approved within 15 s: retried a while.
kubectl -n team-a wait pods -l app=batlehub --for=condition=Ready --timeout="$WAIT"
for ip in $(kubectl -n team-a get pods -l app=batlehub -o jsonpath='{.items[*].status.podIP}'); do
  for _ in $(seq 1 12); do
    content="$(kubectl -n team-a run "read-$RANDOM" --rm -i --restart=Never --quiet \
      --image=docker.io/curlimages/curl:8.17.0 -- \
      -fsS -H "Authorization: Bearer $admin_token" "http://$ip:8080/api/v1/admin/config/content")"
    printf '%s' "$content" | grep -q 'name = \\"npm\\"' && break
    sleep 5
  done
  printf '%s' "$content" | grep -q 'name = \\"npm\\"' || fail "pod $ip doesn't serve the registry: $content"
done
# A key read at startup only is held back: the operator can't restart it.
kubectl -n team-a patch batlehublocalinstance hub --type merge \
  -p '{"spec":{"config":{"database":{"max_connections":6}}}}'
reason_is hub RestartForbidden
kubectl -n team-a patch batlehublocalinstance hub --type merge \
  -p '{"spec":{"config":{"database":{"max_connections":5}}}}'
reason_is hub Reconciled

step "a team namespace claimed on the registry, released on deletion"
kubectl apply -f - <<'YAML'
apiVersion: batlehub.weebo.io/v1alpha1
kind: BatleHubNamespaceClaim
metadata:
  name: web
  namespace: team-a
spec:
  instanceRef: { name: hub }
  registry: npm
  prefix: "@acme/web"
  group: oidc:web-team
YAML
for _ in $(seq 1 90); do
  got="$(kubectl -n team-a get batlehubnamespaceclaim web \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)"
  [ "$got" = Reconciled ] && break
  sleep 2
done
[ "$got" = Reconciled ] || fail "claim web: Ready reason is ${got:-<none>}, expected Reconciled"
claimed="$(kubectl -n team-a get batlehubnamespaceclaim web -o jsonpath='{.status.claimedGroup}')"
[ "$claimed" = oidc:web-team ] || fail "claim web: claimedGroup is ${claimed:-<none>}"
kubectl -n team-a delete batlehubnamespaceclaim web --timeout=60s

# `kind` `name`'s Ready reason, waited for (3 minutes).
cr_reason_is() {
  for _ in $(seq 1 90); do
    got="$(kubectl -n team-a get "$1" "$2" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)"
    [ "$got" = "$3" ] && return 0
    sleep 2
  done
  fail "$1 $2: Ready reason is ${got:-<none>}, expected $3"
}

step "a package's grants and policy written, revoked on deletion"
kubectl apply -f - <<'YAML'
apiVersion: batlehub.weebo.io/v1alpha1
kind: BatleHubPackageGrant
metadata:
  name: billing
  namespace: team-a
spec:
  instanceRef: { name: hub }
  registry: npm
  package: "@acme/billing"
  grants:
    - subject: group:oidc:finance
      actions: ["releases:*"]
---
apiVersion: batlehub.weebo.io/v1alpha1
kind: BatleHubPackagePolicy
metadata:
  name: billing
  namespace: team-a
spec:
  instanceRef: { name: hub }
  registry: npm
  package: "@acme/billing"
  policy:
    visibility: team
YAML
cr_reason_is batlehubpackagegrant billing Reconciled
cr_reason_is batlehubpackagepolicy billing Reconciled
stored="$(kubectl -n team-a get batlehubpackagegrant billing -o jsonpath='{.status.applied[0].stored}')"
printf '%s' "$stored" | grep -q 'releases:publish' || fail "grant billing: stored actions $stored"
# A second grant of the same subject on the node: refused by the webhook.
if kubectl apply -f - <<'YAML' 2>/dev/null
apiVersion: batlehub.weebo.io/v1alpha1
kind: BatleHubPackageGrant
metadata:
  name: billing-again
  namespace: team-a
spec:
  instanceRef: { name: hub }
  registry: npm
  package: "@acme/billing"
  grants:
    - subject: group:oidc:finance
      actions: [releases:read]
YAML
then fail "a second grant of one subject on one node was admitted"; fi
kubectl -n team-a delete batlehubpackagegrant,batlehubpackagepolicy billing --timeout=60s

step "a maintenance runs once; the CRD and the webhook refuse what can't run"
kubectl apply -f - <<'YAML'
apiVersion: batlehub.weebo.io/v1alpha1
kind: BatleHubMaintenance
metadata:
  name: health
  namespace: team-a
spec:
  instanceRef: { name: hub }
  action: healthCheck
  ttlSecondsAfterFinished: 20
YAML
cr_reason_is batlehubmaintenance health Reconciled
runs="$(kubectl -n team-a get batlehubmaintenance health -o jsonpath='{.status.runCount}')"
[ "$runs" = 1 ] || fail "maintenance health: runCount $runs"
# Deleted by the operator once its TTL is over (its RBAC allows it).
kubectl -n team-a wait --for=delete batlehubmaintenance/health --timeout=90s \
  || fail "maintenance health: not deleted after its TTL"
for bad in '{"action":"packageBlock","params":{"registry":"npm"}}' \
  '{"action":"healthCheck","schedule":"every night"}'; do
  if kubectl apply -f - 2>/dev/null <<YAML
apiVersion: batlehub.weebo.io/v1alpha1
kind: BatleHubMaintenance
metadata:
  name: refused
  namespace: team-a
spec: $bad
YAML
  then fail "maintenance $bad was admitted"; fi
done

step "a managed instance: deployed, hot-reloaded, rolled out on a startup key"
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: managed-db
  namespace: team-a
stringData:
  url: postgresql://batlehub:batlehub@postgres:5432/batlehub
---
apiVersion: batlehub.weebo.io/v1alpha1
kind: BatleHubLocalInstance
metadata:
  name: managed
  namespace: team-a
spec:
  managed:
    persistence: { enabled: false }
    env:
      - name: DATABASE_URL
        valueFrom: { secretKeyRef: { name: managed-db, key: url } }
  config:
    server: { host: 0.0.0.0, port: 8080 }
    database: { type: postgresql, url: "${DATABASE_URL}", max_connections: 5 }
    storage: { type: filesystem, path: /var/cache/batlehub }
YAML
reason_is managed Reconciled
proxy_pods() {
  kubectl -n team-a get pods -l app.kubernetes.io/instance=managed,app.kubernetes.io/component=proxy \
    --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'
}
first_pod="$(proxy_pods)"
[ -n "$first_pod" ] || fail "managed: no proxy pod"
template_hash() {
  kubectl -n team-a get deploy managed \
    -o jsonpath='{.spec.template.metadata.annotations.batlehub\.weebo\.io/config-hash}'
}
first_template="$(template_hash)"
# A registry: hot-reloaded, the pod kept.
before="$(kubectl -n team-a get batlehublocalinstance managed -o jsonpath='{.status.configHash}')"
kubectl -n team-a patch batlehublocalinstance managed --type merge -p \
  '{"spec":{"config":{"registries":[{"name":"npm-managed","type":"npm","upstreams":["https://registry.npmjs.org"]}]}}}'
for _ in $(seq 1 90); do
  hash="$(kubectl -n team-a get batlehublocalinstance managed -o jsonpath='{.status.configHash}')"
  applied="$(kubectl -n team-a get batlehublocalinstance managed -o jsonpath='{.status.appliedConfigHash}')"
  [ -n "$hash" ] && [ "$hash" != "$before" ] && [ "$hash" = "$applied" ] && break
  sleep 2
done
[ "$hash" != "$before" ] && [ "$hash" = "$applied" ] \
  || fail "managed: configuration $hash never applied (applied: $applied)"
reason_is managed Reconciled
[ "$(template_hash)" = "$first_template" ] || fail "managed: a hot key rolled the pods"
[ "$(proxy_pods)" = "$first_pod" ] || fail "managed: the pod changed on a hot reload"
token="$(kubectl -n team-a get secret managed-operator-token -o jsonpath='{.data.token}' | base64 -d)"
ip="$(kubectl -n team-a get pod "$first_pod" -o jsonpath='{.status.podIP}')"
# One long-lived curl pod, called with `kubectl exec`: `kubectl run -i
# --rm` may attach after a short command exited and print nothing.
kubectl -n team-a run e2e-probe --restart=Never --image=docker.io/curlimages/curl:8.17.0 \
  --command -- sleep 3600 >/dev/null
kubectl -n team-a wait pod/e2e-probe --for=condition=Ready --timeout="$WAIT" >/dev/null
for _ in $(seq 1 12); do
  health="$(kubectl -n team-a exec e2e-probe -- curl -sS -w '\nHTTP %{http_code}' \
    -H "Authorization: Bearer $token" "http://$ip:8080/api/v1/admin/health" 2>&1 || true)"
  printf '%s' "$health" | grep -q '"registry":"npm-managed"' && break
  echo "managed: /api/v1/admin/health on $ip: ${health:-<no output>}" >&2
  sleep 5
done
kubectl -n team-a delete pod e2e-probe --wait=false >/dev/null
printf '%s' "$health" | grep -q '"registry":"npm-managed"' \
  || fail "managed: the registry isn't served on $ip: ${health:-<no output>}"
# A key read at startup: the pods roll.
kubectl -n team-a patch batlehublocalinstance managed --type merge -p \
  '{"spec":{"config":{"database":{"max_connections":6}}}}'
for _ in $(seq 1 90); do
  [ "$(template_hash)" != "$first_template" ] && break
  sleep 2
done
[ "$(template_hash)" != "$first_template" ] || fail "managed: a startup key didn't roll the pods"
kubectl -n team-a rollout status deploy/managed --timeout="$WAIT"
reason_is managed Reconciled
[ "$(proxy_pods)" != "$first_pod" ] || fail "managed: the pod wasn't replaced"
kubectl -n team-a get events --field-selector reason=ConfigRolledOut -o name | grep -q . \
  || fail "managed: no ConfigRolledOut event"

step "leader election"
holder="$(kubectl -n "$OPERATOR_NS" get lease "$LEASE" -o jsonpath='{.spec.holderIdentity}')"
[ -n "$holder" ] || fail "nobody holds the lease $LEASE"
kubectl -n "$OPERATOR_NS" delete pod "$holder" --wait=false
for _ in $(seq 1 60); do
  now="$(kubectl -n "$OPERATOR_NS" get lease "$LEASE" -o jsonpath='{.spec.holderIdentity}')"
  if [ -n "$now" ] && [ "$now" != "$holder" ]; then break; fi
  sleep 2
done
[ "$now" != "$holder" ] || fail "the lease never moved off $holder"
# The new leader reconciles: a fresh instance gets its state.
kubectl -n team-a annotate batlehublocalinstance unreachable e2e/touched="$(date +%s)" --overwrite
reason_is unreachable InstanceUnreachable

step "e2e passed"
