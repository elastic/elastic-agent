{{- define "elasticagent.engine.k8s.podTemplate" }}
{{- $ := index . 0 -}}
{{- $presetVal := index . 1 -}}
{{- $agentName := index . 2 }}
{{- $podTemplateResource := include "elasticagent.engine.k8s.podTemplateResource" (list $ $presetVal $agentName) | fromYaml  -}}
{{- toYaml ($podTemplateResource).template }}
{{- end }}
