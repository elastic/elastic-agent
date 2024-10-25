{{- define "elasticagent.system.config.logs.init" -}}
{{- if $.Values.system.logs.enabled}}
{{- $preset := $.Values.agent.presets.perNode -}}
{{- $inputVal := (include "elasticagent.system.config.logs.input" $ | fromYamlArray) -}}
{{- include "elasticagent.preset.mutate.inputs" (list $ $preset $inputVal) -}}
{{- include "elasticagent.preset.applyOnce" (list $ $preset "elasticagent.kubernetes.pernode.preset") -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.system.config.logs.input" -}}
- id: system-logs
  type: logfile
  use_output: {{ $.Values.system.output }}
  data_stream:
    namespace: {{ $.Values.system.namespace }}
  streams:
    - data_stream:
        dataset: system.auth
        type: logs
      paths:
        - /var/log/auth.log*
        - /var/log/secure*
      exclude_files:
        - .gz$
      multiline:
        pattern: ^\s
        match: after
      processors:
        - add_locale: null
      ignore_older: 72h
    - data_stream:
        dataset: system.syslog
        type: logs
      paths:
        - /var/log/messages*
        - /var/log/syslog*
      exclude_files:
        - .gz$
      multiline:
        pattern: ^\s
        match: after
      processors:
        - add_locale: null
      ignore_older: 72h
{{- end -}}
