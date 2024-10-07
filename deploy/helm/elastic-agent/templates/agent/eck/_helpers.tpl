{{- define "elasticagent.engine.eck.init" -}}
{{- if eq $.Values.agent.fleet.enabled true -}}
{{- fail "fleet mode with eck engine is not supported at the moment"}}
{{- end -}}
{{/* need to add the basic license annotation for ECK */}}
{{- $basicLicenceAnnotations := dict "eck.k8s.elastic.co/license" "basic"}}
{{- range $presetName, $presetVal := $.Values.agent.presets -}}
{{- include "elasticagent.preset.mutate.annotations" (list $ $presetVal $basicLicenceAnnotations)}}
{{- end -}}
{{- end -}}