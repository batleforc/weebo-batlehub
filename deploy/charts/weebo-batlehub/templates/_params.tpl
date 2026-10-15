{{/*
This operator's parameters for the kit's library chart (weebo-operator-lib,
see its README): everything templates/operator.yaml renders that is not a
value.
*/}}
{{- define "operator.params" -}}
{{- /* The TokenReview ClusterRole (templates/tokenreview.yaml) and what the
operator needs to bind it, only together: an operator limited to one
namespace, or with no ClusterRole at all, binds nothing
(TokenReviewUnavailable) and never reads a cluster-scoped binding. */ -}}
{{- $tokenReview := include "operator.tokenReview" . -}}
{{- $tokenReviewName := printf "%s-tokenreview" (include "weebo-operator.fullname" .) -}}
{{- /* watch.clusterKinds: false renders no ClusterRole, so none of
clusterRules below: ConfigMap layers, a registry's configFrom ConfigMap
and external.podSelector then fail (KubernetesApiError), only Secret
layers and `url` work. This chart can't refuse the mode (the kit renders
it in its smoke tests): the kit needs rules for the watch Role
(params.watchRules, spec §7.1, D6, §11.2). */ -}}
group: batlehub.weebo.io
versions: [v1alpha1]
# Every kind the operator watches (ClusterRole).
kinds:
  - batlehublocalinstances
  - batlehubregistries
  - batlehubnamespaceclaims
  - batlehubpackagegrants
  - batlehubpackagepolicies
  - batlehubmaintenances
# The namespaced kinds — all of them, BatleHub has no cluster-scoped kind:
# what a team may manage (rbac.namespacedExample), and the watch Role's
# (watch.namespace).
namespacedKinds:
  - batlehublocalinstances
  - batlehubregistries
  - batlehubnamespaceclaims
  - batlehubpackagegrants
  - batlehubpackagepolicies
  - batlehubmaintenances
# The operator reads and writes Secrets in every namespace that has an
# instance, also limited to one namespace: said explicitly.
clusterSecrets: true
# Kinds the admission webhook checks (`/validate`): a configuration
# BatleHub's parser refuses, a fragment that is not TOML, a placeholder in
# a registry of another namespace, two grants of one subject or two
# policies on one node, a gate both set and exempted, a schedule or date a
# maintenance can't read.
admitted:
  - batlehublocalinstances
  - batlehubregistries
  - batlehubpackagegrants
  - batlehubpackagepolicies
  - batlehubmaintenances
# Reads of the configuration's sources: ConfigMap layers (watched by
# metadata), the labels of the namespaces registries come from (watched,
# for registrySelector.namespaces.from: Selector), the proxy pods of
# `external.podSelector` (listed), and the deletion of a finished
# maintenance. No Secret watch (spec D9).
clusterRules:
  - apiGroups: [""]
    resources: [configmaps, namespaces]
    verbs: [get, list, watch]
  - apiGroups: [""]
    resources: [pods]
    verbs: [list]
  # The admin token goes to a pod only when its controller (a ReplicaSet of
  # the instance's Deployment, or for external.podSelector a ReplicaSet or
  # StatefulSet selecting it) is read and checked by UID.
  - apiGroups: [apps]
    resources: [replicasets, statefulsets]
    verbs: [get]
  # Managed instances: the objects the operator deploys (server-side apply,
  # each read first to never take over someone else's), and their
  # Deployments watched (labelled app.kubernetes.io/managed-by) to follow
  # a rollout.
  - apiGroups: [apps]
    resources: [deployments]
    verbs: [get, list, watch, create, patch, delete]
  - apiGroups: [""]
    resources: [services, serviceaccounts, persistentvolumeclaims]
    verbs: [get, create, patch, delete]
  - apiGroups: [policy]
    resources: [poddisruptionbudgets]
    verbs: [get, create, patch, delete]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses, networkpolicies]
    verbs: [get, create, patch, delete]
  - apiGroups: [autoscaling]
    resources: [horizontalpodautoscalers]
    verbs: [get, create, patch, delete]
  {{- if $tokenReview }}
  # The TokenReview binding of managed instances with a kubernetes auth
  # provider: ONE ClusterRoleBinding, named after the chart's tokenreview
  # ClusterRole, whose subjects the operator edits (get/patch on that name
  # only, never delete). `create` can't be limited by name (RBAC): the
  # API server's escalation check still stops any binding of a role the
  # operator neither holds nor may bind — it may bind this one only.
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [clusterrolebindings]
    verbs: [create]
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [clusterrolebindings]
    verbs: [get, patch]
    resourceNames: [{{ $tokenReviewName }}]
  # `get`: the binding is owned by the ClusterRole (gone with the release).
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [clusterroles]
    verbs: [get, bind]
    resourceNames: [{{ $tokenReviewName }}]
  {{- end }}
  # A single maintenance run is deleted ttlSecondsAfterFinished after it
  # finished (the kit grants its kinds no delete).
  - apiGroups: [batlehub.weebo.io]
    resources: [batlehubmaintenances]
    verbs: [delete]
# The operator's own environment variables.
env:
  {{- if $tokenReview }}
  - name: WEEBO_BATLEHUB_TOKENREVIEW_CLUSTERROLE
    value: {{ $tokenReviewName }}
  {{- end }}
  - name: WEEBO_BATLEHUB_ALLOWED_IMAGES
    value: {{ join "," .Values.managedInstances.allowedImages | quote }}
  {{- with .Values.defaults.image }}
  - name: WEEBO_BATLEHUB_DEFAULT_IMAGE
    value: {{ . | quote }}
  {{- end }}
  {{- with .Values.defaults.workerImage }}
  - name: WEEBO_BATLEHUB_DEFAULT_WORKER_IMAGE
    value: {{ . | quote }}
  {{- end }}
  - name: WEEBO_BATLEHUB_ADMIN_TIMEOUT_SECONDS
    value: {{ .Values.defaults.adminTimeoutSeconds | quote }}
egress:
  - comment: BatleHub instances.
    rules: {{ toJson .Values.networkPolicy.egress.batlehub }}
# Alerts on the operator's own metrics, appended to the kit's (only with
# prometheusRule.enabled, which needs metrics.prometheus.enabled). Names
# matched by regex like the kit's: the OTel -> Prometheus translation may
# suffix a gauge `_ratio`, a counter `_total`.
{{- $sel := printf "namespace=%q, job=%q" .Release.Namespace (printf "%s-metrics" (include "weebo-operator.fullname" .)) }}
alerts:
  - alert: BatleHubInstanceNotReady
    expr: |
      max by (instance_namespace, instance_name) ({__name__=~"weebo_batlehub_instance_ready(_ratio)?", {{ $sel }}}) == 0
    for: 15m
    labels:
      severity: warning
    annotations:
      summary: {{`'BatleHubLocalInstance {{ $labels.instance_namespace }}/{{ $labels.instance_name }} not Ready for 15 minutes'`}}
      description: {{`'kubectl -n {{ $labels.instance_namespace }} get bhli {{ $labels.instance_name }}: the Ready condition says why.'`}}
  - alert: BatleHubRestartPending
    expr: |
      max by (instance_namespace, instance_name) ({__name__=~"weebo_batlehub_instance_restart_required(_ratio)?", {{ $sel }}}) > 0
    for: 24h
    labels:
      severity: info
    annotations:
      summary: {{`'BatleHubLocalInstance {{ $labels.instance_namespace }}/{{ $labels.instance_name }} waits for a restart for 24 hours'`}}
      description: {{`'Keys read at startup changed and the pods did not restart (status.restartKeys): run a restart maintenance, or set reload.restart: Rollout.'`}}
  - alert: BatleHubMaintenanceFailing
    expr: |
      sum by (action) (increase({__name__=~"weebo_batlehub_maintenance_runs(_total)?", result="failure", {{ $sel }}}[1h])) > 0
    labels:
      severity: warning
    annotations:
      summary: {{`'BatleHubMaintenance runs of {{ $labels.action }} failed in the last hour'`}}
      description: {{`'kubectl get bhm -A: status.lastRun says what BatleHub answered.'`}}
{{- end -}}

{{/* "true" when the TokenReview ClusterRole is rendered and the operator
may bind it: tokenReview.enabled, cluster-wide, with a ClusterRole. */}}
{{- define "operator.tokenReview" -}}
{{- if and .Values.tokenReview.enabled (include "weebo-operator.watchClusterKinds" .) (not (include "weebo-operator.watchNamespace" .)) -}}
true
{{- end -}}
{{- end -}}
