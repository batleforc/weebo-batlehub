{{/*
This operator's parameters for the kit's library chart (weebo-operator-lib,
see its README): everything templates/operator.yaml renders that is not a
value.
*/}}
{{- define "operator.params" -}}
{{- /* watch.clusterKinds: false works as long as the operator has no
rules of its own (clusterRules): the managed mode's (Deployments,
Services, PVCs…, M4) need the kit to carry rules for the watch Role, or
this chart to refuse the mode then (spec §7.1, D6). */ -}}
group: batlehub.weebo.io
versions: [v1alpha1]
# Every kind the operator watches (ClusterRole).
kinds:
  - batlehublocalinstances
# The namespaced kinds — all of them, BatleHub has no cluster-scoped kind:
# what a team may manage (rbac.namespacedExample), and the watch Role's
# (watch.namespace).
namespacedKinds:
  - batlehublocalinstances
# The operator reads and writes Secrets in every namespace that has an
# instance, also limited to one namespace: said explicitly.
clusterSecrets: true
# Kinds the admission webhook checks: none until the operator serves
# `/validate` (a namespace allow-list).
admitted: []
# The operator's own environment variables.
env: []
egress:
  - comment: BatleHub instances.
    rules: {{ toJson .Values.networkPolicy.egress.batlehub }}
# Alerts on the operator's own metrics, appended to the kit's.
alerts: []
{{- end -}}
