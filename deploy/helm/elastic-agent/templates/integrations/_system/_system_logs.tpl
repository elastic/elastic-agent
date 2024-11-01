{{- define "elasticagent.system.config.logs.init" -}}
{{- if eq $.Values.system.enabled true }}
{{- $preset := $.Values.agent.presets.perNode -}}
{{- $inputVal := (include "elasticagent.system.config.logs.input" $ | fromYaml) -}}
{{- if ($inputVal).streams }}
{{- include "elasticagent.preset.mutate.inputs" (list $ $preset (list $inputVal)) -}}
{{- include "elasticagent.preset.applyOnce" (list $ $preset "elasticagent.kubernetes.pernode.preset") -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.system.config.logs.input" -}}
id: system-logs
type: logfile
use_output: {{ $.Values.system.output }}
data_stream:
  namespace: {{ $.Values.system.namespace }}
streams:
  {{- if eq $.Values.system.authLogs.enabled true }}
  - data_stream:
      dataset: system.auth
      type: logs
    multiline:
      pattern: ^\s
      match: after
  {{- $vars := (include "elasticagent.system.config.auth_logs.default_vars" .) | fromYaml -}}
  {{- mergeOverwrite $vars $.Values.system.authLogs.vars | toYaml | nindent 4 }}
  {{- end }}
  {{- if eq $.Values.system.syslog.enabled true }}
  - data_stream:
      dataset: system.syslog
      type: logs
    multiline:
      pattern: ^\s
      match: after
  {{- $vars := (include "elasticagent.system.config.syslog.default_vars" .) | fromYaml -}}
  {{- mergeOverwrite $vars $.Values.system.syslog.vars | toYaml | nindent 4 }}
  {{- end }}
{{- end -}}

{{/*
Defaults for auth log input stream
*/}}
{{- define "elasticagent.system.config.auth_logs.default_vars" -}}
paths:
  - /var/log/auth.log*
  - /var/log/secure*
exclude_files:
  - \.gz$
processors:
  - add_locale: null
tags:
  - system-auth
ignore_older: 72h
{{- end -}}

{{/*
Defaults for auth log syslog stream
*/}}
{{- define "elasticagent.system.config.syslog.default_vars" -}}
paths:
  - /var/log/messages*
  - /var/log/syslog*
  - /var/log/system*
exclude_files:
  - \.gz$
processors:
  - add_locale: null
tags: null
ignore_older: 72h
{{- end -}}
