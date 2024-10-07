{{- define "elasticagent.engine.k8s.podTemplate" }}
{{- $ := index . 0 -}}
{{- $presetVal := index . 1 -}}
{{- $agentName := index . 2 }}
{{- $contextWithArgs := merge $ (dict "presetVal" $presetVal "agentName" $agentName) }}
{{- $podTemplateResource := (tpl ($.Files.Get "conf/pod_template.yaml") $contextWithArgs) | fromYaml -}}
{{- toYaml $podTemplateResource.template -}}
{{- end }}
