{{- define "elasticagent.engine.k8s.secretData" -}}
{{- $ := index . 0 -}}
{{- $presetVal := index . 1 -}}
{{- $agentName := index . 2 }}
  agent.yml: |-
    {{- if eq $.Values.agent.fleet.enabled false }}
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
    inputs:
      {{- with ($presetVal)._inputs }}
      {{- . | toYaml | nindent 6 }}
      {{- end }}
    {{- else }}
    fleet:
      enabled: true
    {{- end }}
    {{- with ($presetVal).providers }}
    providers:
      {{- . | toYaml | nindent 6 }}
    {{- end }}
  {{- if eq $.Values.agent.fleet.enabled true }}
  {{- if $.Values.agent.fleet.ca.value }}
  {{ ($.Values.agent.fleet.ca)._key }} : |-
    {{- ($.Values.agent.fleet.ca).value | nindent 4 }}
  {{- end }}
  {{- if $.Values.agent.fleet.agentCert.value }}
  {{ ($.Values.agent.fleet.agentCert)._key }} : |-
    {{- ($.Values.agent.fleet.agentCert).value | nindent 4 }}
  {{- end }}
  {{- if $.Values.agent.fleet.agentCertKey.value }}
  {{ ($.Values.agent.fleet.agentCertKey)._key }} : |-
    {{- ($.Values.agent.fleet.agentCertKey).value | nindent 4 }}
  {{- end }}
  {{- if $.Values.agent.fleet.kibanaCA.value }}
  {{ ($.Values.agent.fleet.kibanaCA)._key }} : |-
    {{- ($.Values.agent.fleet.kibanaCA).value | nindent 4 }}
  {{- end }}
  {{- else }}
  {{- with ($presetVal).outputs }}
  {{- range $idx, $outputVal := . }}
  {{- with (dig "ssl" "certificateAuthorities" list $outputVal) }}
  {{- range $idx, $certificateAuthoritiy := . }}
  {{- if $certificateAuthoritiy.value }}
  {{ $certificateAuthoritiy._key }} : |-
    {{- $certificateAuthoritiy.value | nindent 4 }}
  {{- end }}
  {{- end }}
  {{- end }}
  {{- end }}
  {{- end }}
  {{- end }}
{{- end }}
