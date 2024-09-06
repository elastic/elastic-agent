{{- define "elasticagent.engine.k8s.secretData" -}}
{{- $ := index . 0 -}}
{{- $presetVal := index . 1 -}}
{{- $agentName := index . 2 }}
  agent.yml: |-
    id: {{ $agentName }}
    {{- with ($presetVal).outputs }}
    outputs:
      {{- range $outputName, $outputVal := . -}}
      {{- include (printf "elasticagent.output.%s.preset.config" ($outputVal).type) (list $ $outputName $outputVal) | nindent 6 }}
      {{- end }}
    {{- end }}
    secret_references: []
    {{- with ($presetVal).agent }}
    agent:
      {{- . | toYaml | nindent 6}}
    {{- end }}
    {{- with ($presetVal).providers }}
    providers:
      {{- . | toYaml | nindent 6 }}
    {{- end }}
    inputs:
      {{- with ($presetVal)._inputs -}}
      {{- . | toYaml | nindent 6 }}
      {{- end }}
{{- end }}