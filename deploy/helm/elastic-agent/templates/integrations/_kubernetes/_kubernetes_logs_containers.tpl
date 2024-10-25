{{- define "elasticagent.kubernetes.config.container_logs.init" -}}
{{- if eq $.Values.kubernetes.containers.logs.enabled true -}}
{{- $preset := $.Values.agent.presets.perNode -}}
{{- $inputVal := (include "elasticagent.kubernetes.config.container_logs.input" $ | fromYamlArray) -}}
{{- include "elasticagent.preset.mutate.inputs" (list $ $preset $inputVal) -}}
{{- include "elasticagent.preset.applyOnce" (list $ $preset "elasticagent.kubernetes.pernode.preset") -}}
{{- end -}}
{{- end -}}

{{/*
Config input for container logs
*/}}
{{- define "elasticagent.kubernetes.config.container_logs.input" -}}
- id: filestream-container-logs
  type: filestream
  data_stream:
    namespace: {{ .Values.kubernetes.namespace }}
  use_output: {{ .Values.kubernetes.output }}
  streams:
  - id: kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}
    data_stream:
      dataset: kubernetes.container_logs
      type: logs
    paths:
      - '/var/log/containers/*${kubernetes.container.id}.log'
    prospector.scanner.symlinks: {{ dig "vars" "symlinks" true .Values.kubernetes.containers.logs }}
    parsers:
      - container:
          stream: {{ dig "vars" "stream" "all" .Values.kubernetes.containers.logs }}
          format: {{ dig "vars" "format" "auto" .Values.kubernetes.containers.logs }}
      {{- with $.Values.kubernetes.containers.logs.additionalParsersConfig }}
      {{- . | toYaml | nindent 6 }}
      {{- end }}
{{- end -}}
