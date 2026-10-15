{{/*
This operator's parameters for the kit's library chart (weebo-operator-lib,
see its README): everything templates/operator.yaml renders that is not a
value.
*/}}
{{- define "operator.params" -}}
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
  # A single maintenance run is deleted ttlSecondsAfterFinished after it
  # finished (the kit grants its kinds no delete).
  - apiGroups: [batlehub.weebo.io]
    resources: [batlehubmaintenances]
    verbs: [delete]
# The operator's own environment variables.
env: []
egress:
  - comment: BatleHub instances.
    rules: {{ toJson .Values.networkPolicy.egress.batlehub }}
# Alerts on the operator's own metrics, appended to the kit's.
alerts: []
{{- end -}}
