{{- define "elasticagent.output.ESPlainAuthBasic.preset.envvars" -}}
{{/* this is plain text so nothing to be added in the pod env vars */}}
{{- end -}}

{{- define "elasticagent.output.ESPlainAuthBasic.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{- $_ := set $outputVal "type" "elasticsearch" -}}
{{- $_ := set $outputVal "hosts" (list ($outputVal).url) -}}
{{- $_ := unset $outputVal "url" -}}
{{- $_ := unset $outputVal "api_key" -}}
{{- $_ := unset $outputVal "secretName" -}}
{{- $_ := unset $outputVal "name" -}}
{{- $_ := unset $outputVal "namespace" -}}
{{$outputName}}:
  {{- $outputVal | toYaml | nindent 2}}
{{- end -}}

{{- define "elasticagent.output.ESPlainAuthAPI.preset.envvars" -}}
{{/* this is plain text so nothing to be added in the pod env vars */}}
{{- end -}}

{{- define "elasticagent.output.ESPlainAuthAPI.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{- $_ := set $outputVal "type" "elasticsearch" -}}
{{- $_ := set $outputVal "hosts" (list ($outputVal).url) -}}
{{- $_ := unset $outputVal "url" -}}
{{- $_ := unset $outputVal "username" -}}
{{- $_ := unset $outputVal "password" -}}
{{- $_ := unset $outputVal "secretName" -}}
{{- $_ := unset $outputVal "name" -}}
{{- $_ := unset $outputVal "namespace" -}}
{{$outputName}}:
  {{- $outputVal | toYaml | nindent 2}}
{{- end -}}

{{- define "elasticagent.output.ESSecretAuthBasic.preset.envvars" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
- name: OUTPUT_{{upper $outputName}}_URL
  valueFrom:
    secretKeyRef:
      name: {{($outputVal).secretName}}
      key: url
- name: OUTPUT_{{upper $outputName}}_USER
  valueFrom:
    secretKeyRef:
      name: {{($outputVal).secretName}}
      key: username
- name: OUTPUT_{{upper $outputName}}_PASS
  valueFrom:
    secretKeyRef:
      name: {{($outputVal).secretName}}
      key: password
{{- end -}}

{{- define "elasticagent.output.ESSecretAuthBasic.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{- $outputVal = omit $outputVal "secretName" "username" "password" "name" "serviceName" "namespace" "api_key" "url" -}}
{{- $_ := set $outputVal "type" "elasticsearch" -}}
{{- $_ := set $outputVal "hosts" (list (printf "${OUTPUT_%s_URL}" (upper $outputName))) -}}
{{- $_ := set $outputVal "username" (printf "${OUTPUT_%s_USER}" (upper $outputName)) -}}
{{- $_ := set $outputVal "password" (printf "${OUTPUT_%s_PASS}" (upper $outputName)) -}}
{{$outputName}}:
  {{- $outputVal | toYaml | nindent 2}}
{{- end -}}

{{- define "elasticagent.output.ESSecretAuthAPI.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{- $outputVal = omit $outputVal "secretName" "username" "password" "name" "serviceName" "namespace" "api_key" "url" -}}
{{- $_ := set $outputVal "type" "elasticsearch" -}}
{{- $_ := set $outputVal "hosts" (list (printf "${OUTPUT_%s_URL}" (upper $outputName))) -}}
{{- $_ := set $outputVal "api_key" (printf "${OUTPUT_%s_API_KEY}" (upper $outputName)) -}}
{{$outputName}}:
  {{- $outputVal | toYaml | nindent 2}}
{{- end -}}

{{- define "elasticagent.output.ESSecretAuthAPI.preset.envvars" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
- name: OUTPUT_{{upper $outputName}}_URL
  valueFrom:
    secretKeyRef:
      name: {{($outputVal).secretName}}
      key: url
- name: OUTPUT_{{upper $outputName}}_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{($outputVal).secretName}}
      key: api_key
{{- end -}}

{{- define "elasticagent.output.ESECKRef.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{- if ne $.Values.agent.engine "eck" -}}
{{- fail (printf "output \"%s\" of ESECKRef type can be used only when agent.engine = eck" $outputName)}}
{{- end -}}
{{- $outputVal = omit $outputVal "username" "password" "api_key" "url" "type" "secretName" -}}
{{ $outputVal | toYaml }}
{{- end -}}

{{- define "elasticagent.output.ESECKRef.preset.envvars" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- if ne $.Values.agent.engine "eck" -}}
{{- fail (printf "output \"%s\" of ESECKRef type can be used only when agent.engine = eck" $outputName)}}
{{- end -}}
{{/* no preset env vars for ESECKRef output */}}
{{- end -}}
