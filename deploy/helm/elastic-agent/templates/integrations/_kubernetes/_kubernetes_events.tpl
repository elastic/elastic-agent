{{- define "elasticagent.kubernetes.config.kube_event.init" -}}
{{- if eq $.Values.kubernetes.containers.kube_event.enabled true -}}
{{- $preset := $.Values.agent.presets.clusterWide -}}
{{- $inputVal := (include "elasticagent.kubernetes.config.kube_event.input" $ | fromYamlArray) -}}
{{- include "elasticagent.preset.mutate.inputs" (list $ $preset $inputVal) -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ $preset $.Values.kubernetes.output) -}}
{{- end -}}
{{- end -}}

{{/*
Config input for kube_event
*/}}
{{- define "elasticagent.kubernetes.config.kube_event.input" -}}
- id: kubernetes/metrics-kubernetes.event
  type: kubernetes/metrics
  data_stream:
    namespace: {{.Values.kubernetes.namespace}}
  use_output: {{ .Values.kubernetes.output }}
  {{- with $.Values.kubernetes._onboarding_processor }}
  processors:
  - {{ . | toYaml | nindent 4 }}
  {{- end }}
  streams:
  - id: kubernetes/metrics-kubernetes.event
    data_stream:
      type: metrics
      dataset: kubernetes.event
    metricsets:
      - event
{{- $vars := (include "elasticagent.kubernetes.config.kube_event.default_vars" .) | fromYaml -}}
{{- mergeOverwrite $vars .Values.kubernetes.event.vars | toYaml | nindent 4 }}
{{- end -}}


{{/*
Defaults for kube_event input streams
*/}}
{{- define "elasticagent.kubernetes.config.kube_event.default_vars" -}}
period: 10s
add_metadata: true
{{- end -}}

