#!/usr/bin/env bash
# kind e2e (`task e2e`, .github/workflows/e2e.yml): deploys cert-manager and
# the operator chart into the current kube context, then the smoke — two
# BatleHubLocalInstances whose state the operator decides without a running
# BatleHub (an unlabelled token Secret, an unreachable URL) —, a real
# BatleHub (batlehub.yaml) with an external instance that must end Ready,
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
  kubectl -n team-a get batlehublocalinstances -o yaml
  kubectl -n team-a get pods -o wide
  kubectl -n team-a logs deploy/batlehub --tail=50
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
    previous="$(helm show chart "$CHART_OCI" 2>/dev/null | awk '/^version:/ {print $2}' || true)"
  fi
  if [ -z "$previous" ]; then
    echo "no published chart at $CHART_OCI: upgrade test skipped"
  elif [ "$previous" = "$head_version" ]; then
    echo "latest published chart is this version ($head_version): upgrade test skipped"
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
  sleep 15
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
