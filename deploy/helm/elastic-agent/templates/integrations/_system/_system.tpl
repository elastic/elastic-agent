{{- define "elasticagent.system.init" -}}
{{- if eq $.Values.system.enabled true -}}
{{- include "elasticagent.system.config.logs.init" $ -}}
{{- include "elasticagent.system.config.metrics.init" $ -}}
{{- end -}}
{{- end -}}
