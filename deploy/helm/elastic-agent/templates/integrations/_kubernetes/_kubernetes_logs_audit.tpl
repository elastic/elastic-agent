{{- define "elasticagent.kubernetes.config.audit_logs.init" -}}
{{- if eq $.Values.kubernetes.containers.audit_logs.enabled true -}}
{{- $preset := $.Values.agent.presets.perNode -}}
{{- $inputVal := (include "elasticagent.kubernetes.config.audit_logs.input" $ | fromYamlArray) -}}
{{- include "elasticagent.preset.mutate.inputs" (list $ $preset $inputVal) -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ $preset $.Values.kubernetes.output) -}}
{{- end -}}
{{- end -}}

{{/*
Config input for kube audit_logs_filestream
*/}}
{{- define "elasticagent.kubernetes.config.audit_logs.input" -}}
- id: filestream-kubernetes.audit_logs
  type: filestream
  data_stream:
    namespace: {{.Values.kubernetes.namespace}}
  use_output: {{ .Values.kubernetes.output }}
  {{- with $.Values.kubernetes._onboarding_processor }}
  processors:
  - {{ . | toYaml | nindent 4 }}
  {{- end }}
  streams:
  - id: filestream-kubernetes.audit_logs
    data_stream:
      type: logs
      dataset: kubernetes.audit_logs
    paths:
      - /var/log/kubernetes/kube-apiserver-audit.log
    exclude_files:
      - .gz$
    parsers:
      - ndjson:
          add_error_key: true
          target: kubernetes.audit
{{- end -}}
