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
{{- /* What the operator reads and writes in the namespaces of its instances
(operator.namespacedRules): cluster-wide in the ClusterRole, or — with
watch.namespace — only in that namespace, through the kit's watch Role
(params.watchRules), which a watch.clusterKinds: false release renders
too (spec §7.1, D6). */ -}}
{{- $watchNamespace := include "weebo-operator.watchNamespace" . -}}
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
# Cluster-wide only: the namespaced rules below, and the labels of the
# namespaces registries come from (watched, for
# registrySelector.namespaces.from: Selector). Limited to one namespace,
# none of them: they go to watchRules. No Secret watch (spec D9).
clusterRules:
  {{- if not $watchNamespace }}
  - apiGroups: [""]
    resources: [namespaces]
    verbs: [get, list, watch]
  {{- include "operator.namespacedRules" . | nindent 2 }}
  {{- end }}
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
# Limited to one namespace (watch.namespace): the same rules, in the watch
# Role of that namespace only.
watchRules:
  {{- if $watchNamespace }}
  {{- include "operator.namespacedRules" . | nindent 2 }}
  {{- end }}
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


{{/* The rules on the namespaced resources of the instances' namespaces:
the configuration's sources (ConfigMap layers, watched by metadata; the
proxy pods of external.podSelector, listed), the objects of managed
instances, and the deletion of a finished maintenance. */}}
{{- define "operator.namespacedRules" -}}
- apiGroups: [""]
  resources: [configmaps]
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
# Deployments watched (labelled app.kubernetes.io/managed-by) to follow a
# rollout.
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
# A single maintenance run is deleted ttlSecondsAfterFinished after it
# finished (the kit grants its kinds no delete).
- apiGroups: [batlehub.weebo.io]
  resources: [batlehubmaintenances]
  verbs: [delete]
{{- end -}}
