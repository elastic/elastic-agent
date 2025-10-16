{{- define "elasticagent.output.ESPlainAuthBasic.preset.envvars" -}}
{{/* this is plain text so nothing to be added in the pod env vars */}}
{{- end -}}

{{- define "elasticagent.output.ESPlainAuthBasic.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{$outputName}}:
  hosts:
  - {{($outputVal).url}}
  password: {{($outputVal).password}}
  type: elasticsearch
  username: {{($outputVal).username}}
  {{- $outputSSLConfig := dig "ssl" dict $outputVal -}}
  {{- with (include "elasticagent.output.render.sslconfig" (list $outputSSLConfig $outputName) | fromYaml) }}
  {{- . | toYaml | nindent 2}}
  {{- end }}
{{- end -}}

{{- define "elasticagent.output.ESPlainAuthAPI.preset.envvars" -}}
{{/* this is plain text so nothing to be added in the pod env vars */}}
{{- end -}}

{{- define "elasticagent.output.ESPlainAuthAPI.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{$outputName}}:
  api_key: {{ ($outputVal).api_key }}
  hosts:
  - {{($outputVal).url }}
  type: elasticsearch
  {{- $outputSSLConfig := dig "ssl" dict $outputVal -}}
  {{- with (include "elasticagent.output.render.sslconfig" (list $outputSSLConfig $outputName) | fromYaml) }}
  {{- . | toYaml | nindent 2}}
  {{- end }}
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
{{$outputName}}:
  hosts:
  - {{ printf "${OUTPUT_%s_URL}" (upper $outputName) }}
  type: elasticsearch
  username: {{printf "${OUTPUT_%s_USER}" (upper $outputName)}}
  password: {{printf "${OUTPUT_%s_PASS}" (upper $outputName)}}
  {{- $outputSSLConfig := dig "ssl" dict $outputVal -}}
  {{- with (include "elasticagent.output.render.sslconfig" (list $outputSSLConfig $outputName) | fromYaml) }}
  {{- . | toYaml | nindent 2}}
  {{- end }}
{{- end -}}

{{- define "elasticagent.output.ESSecretAuthAPI.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{$outputName}}:
  api_key: {{printf "${OUTPUT_%s_API_KEY}" (upper $outputName)}}
  hosts:
  - {{ printf "${OUTPUT_%s_URL}" (upper $outputName) }}
  type: elasticsearch
  {{- $outputSSLConfig := dig "ssl" dict $outputVal -}}
  {{- with (include "elasticagent.output.render.sslconfig" (list $outputSSLConfig $outputName) | fromYaml) }}
  {{- . | toYaml | nindent 2}}
  {{- end }}
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
name: {{($outputVal).name}}
{{- with ($outputVal).namespace }}
namespace: {{.}}
{{- end }}
{{- end -}}

{{- define "elasticagent.output.ESECKRef.preset.envvars" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- if ne $.Values.agent.engine "eck" -}}
{{- fail (printf "output \"%s\" of ESECKRef type can be used only when agent.engine = eck" $outputName)}}
{{- end -}}
{{/* no preset env vars for ESECKRef output */}}
{{- end -}}

{{- define "elasticagent.output.Logstash.preset.config" -}}
{{- $ := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $outputVal := deepCopy (index . 2) -}}
{{$outputName}}:
  hosts:
  {{- range $idx, $host := $outputVal.hosts }}
    - {{$host | quote}}
  {{- end }}
  type: logstash
  {{- if hasKey $outputVal "loadbalance" }}
  loadbalance: {{$outputVal.loadbalance}}
  {{- end }}
  {{- with $outputVal.ttl }}
  ttl: {{. | quote}}
  {{- end }}
  {{- if hasKey $outputVal "slow_start" }}
  slow_start: {{ $outputVal.slow_start}}
  {{- end }}
  {{- with $outputVal.pipelining }}
  pipelining: {{.}}
  {{- end }}
  {{- with $outputVal.workers }}
  workers: {{.}}
  {{- end }}
  {{- with $outputVal.timeout }}
  timeout: {{. | quote }}
  {{- end }}

  {{- with index $outputVal "queue.mem.flush.timeout" }}
  queue.mem.flush.timeout: {{. | quote}}
  {{- end }}
  {{- with index $outputVal "queue.mem.flush.min_events" }}
  queue.mem.flush.min_events: {{.}}
  {{- end }}
  {{- with index $outputVal "queue.mem.events" }}
  queue.mem.events: {{.}}
  {{- end }}
  {{- with $outputVal.max_retries}}
  max_retries: {{.}}
  {{- end }}
  {{- with $outputVal.compression_level}}
  compression_level: {{.}}
  {{- end }}
  {{- with $outputVal.bulk_max_size}}
  bulk_max_size: {{.}}
  {{- end }}
  {{- with index $outputVal "backoff.max" }}
  backoff.max: {{. | quote }}
  {{- end }}
  {{- with index $outputVal "backoff.init" }}
  backoff.init: {{. | quote }}
  {{- end }}
  {{- if hasKey $outputVal "allow_older_versions"}}
  allow_older_versions: {{$outputVal.allow_older_versions}}
  {{- end }}
  {{- $outputSSLConfig := dig "ssl" dict $outputVal -}}
  {{- with (include "elasticagent.output.render.sslconfig" (list $outputSSLConfig $outputName) | fromYaml) }}
  {{- . | toYaml | nindent 2}}
  {{- end }}
{{- end -}}

{{- define "elasticagent.output.Logstash.preset.envvars" -}}
{{/* this is plain text so nothing to be added in the pod env vars */}}
{{- end -}}


{{- define "elasticagent.output.render.sslconfig" -}}
{{- $outputSSLConfig := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- with $outputSSLConfig }}
{{- with $outputSSLConfig.certificateAuthorities }}
ssl.certificate_authorities:
{{- range $idx, $certificateAuthority := . }}
  -  {{$certificateAuthority._mountPath  | quote}}
{{- end }}
{{- end }}
{{- with $outputSSLConfig.certificate }}
ssl.certificate: {{ ._mountPath  | quote}}
{{- end }}
{{- with $outputSSLConfig.key }}
ssl.key: {{ ._mountPath  | quote}}
{{- end }}
{{- with $outputSSLConfig.verificationMode }}
ssl.verification_mode: {{.}}
{{- end }}
{{- with $outputSSLConfig.caTrustedFingerprint }}
ssl.ca_trusted_fingerprint: {{.}}
{{- end }}
{{- end }}
{{- end -}}

{{- define "elasticagent.output.preset.volumemounts" -}}
{{- $outputVal := . -}}
{{- $outputSSLConfig := dig "ssl" dict $outputVal -}}
{{- with $outputSSLConfig -}}
{{- $volumeMounts := list -}}
{{- with $outputSSLConfig.certificateAuthorities -}}
{{- range $idx, $certificateAuthority := . -}}
{{- $volumeMounts = append $volumeMounts $certificateAuthority._volumeMount -}}
{{- end -}}
{{- end -}}
{{- with $outputSSLConfig.certificate -}}
{{- $volumeMounts = append $volumeMounts ._volumeMount -}}
{{- end -}}
{{- with $outputSSLConfig.key -}}
{{- $volumeMounts = append $volumeMounts ._volumeMount -}}
{{- end -}}
{{- with $volumeMounts -}}
{{. | toYaml}}
{{- end -}}
{{- end -}}
{{- end -}}


{{- define "elasticagent.output.preset.volumes" -}}
{{- $outputVal := . -}}
{{- $outputSSLConfig := dig "ssl" dict $outputVal -}}
{{- with $outputSSLConfig -}}
{{- $volumes := list -}}
{{- with $outputSSLConfig.certificateAuthorities -}}
{{- range $idx, $certificateAuthority := . -}}
{{- if $certificateAuthority._volume -}}
{{- $volumes = append $volumes $certificateAuthority._volume -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- with $outputSSLConfig.certificate -}}
{{- $volumes = append $volumes ._volume -}}
{{- end -}}
{{- with $outputSSLConfig.key -}}
{{- $volumes = append $volumes ._volume -}}
{{- end -}}
{{- with $volumes -}}
{{. | toYaml}}
{{- end -}}
{{- end -}}
{{- end -}}
