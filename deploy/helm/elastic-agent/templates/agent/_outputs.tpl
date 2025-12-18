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
  {{- if hasKey $outputVal "enabled" }}
  enabled: {{$outputVal.enabled}}
  {{- end }}
  hosts:
  {{- range $idx, $host := $outputVal.hosts }}
    - {{$host | quote}}
  {{- end }}
  type: logstash
  {{- if hasKey $outputVal "escape_html" }}
  escape_html: {{$outputVal.escape_html}}
  {{- end }}
  {{- with $outputVal.proxy_url }}
  proxy_url: {{. | quote}}
  {{- end }}
  {{- if hasKey $outputVal "proxy_use_local_resolver" }}
  proxy_use_local_resolver: {{$outputVal.proxy_use_local_resolver}}
  {{- end }}
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
  {{- if ne (dig "queue" "mem" "flush" "timeout" "not_found" $outputVal ) "not_found" }}
  queue.mem.flush.timeout: {{$outputVal.queue.mem.flush.timeout | quote}}
  {{- end }}
  {{- if ne (int (dig "queue" "mem" "flush" "min_events"  -1 $outputVal )) -1 }}
  queue.mem.flush.min_events: {{$outputVal.queue.mem.flush.min_events}}
  {{- end }}
  {{- if ne (int (dig "queue" "mem" "events" -1 $outputVal )) -1 }}
  queue.mem.events: {{$outputVal.queue.mem.events}}
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
  {{- if ne (dig "backoff" "max" "not_found" $outputVal ) "not_found" }}
  backoff.max: {{$outputVal.backoff.max | quote }}
  {{- end }}
  {{- if ne (dig "backoff" "init" "not_found" $outputVal ) "not_found" }}
  backoff.init: {{$outputVal.backoff.init | quote }}
  {{- end }}
  {{- if hasKey $outputVal "allow_older_versions" }}
  allow_older_versions: {{$outputVal.allow_older_versions}}
  {{- end }}
  {{- $outputSSLConfig := dig "ssl" dict $outputVal -}}
  {{- with (include "elasticagent.output.render.sslconfig" (list $outputSSLConfig $outputName)) -}}
  {{- .| indent 2 -}}
  {{- end }}
{{- end -}}

{{- define "elasticagent.output.Logstash.preset.envvars" -}}
{{/* this is plain text so nothing to be added in the pod env vars */}}
{{- end -}}

{{- define "elasticagent.output.render.sslconfig.envvars" -}}
{{- $outputSSLConfig := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- $agentName := index . 2 -}}
{{- with $outputSSLConfig }}
{{- if (dig "key_passphrase" dict .) }}
- name: OUTPUT_{{upper $outputName}}_KEY_PASSPHRASE
  valueFrom:
    secretKeyRef:
      name: {{ dig "key_passphrase" "valueFromSecret" "name"  $agentName . }}
      key: {{ dig "key_passphrase" "valueFromSecret" "key"  (printf "%s%s" $outputName ".ssl.key_passphrase") . }} 
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.output.render.sslconfig" -}}
{{- $outputSSLConfig := index . 0 -}}
{{- $outputName := index . 1 -}}
{{- with $outputSSLConfig }}
{{- if hasKey $outputSSLConfig "enabled" }}
ssl.enabled: {{ $outputSSLConfig.enabled }}
{{- end }}
{{- with $outputSSLConfig.certificateAuthorities }}
ssl.certificate_authorities:
{{- range $idx, $certificateAuthority := . }}
  -  {{$certificateAuthority._mountPath  | quote }}
{{- end }}
{{- end }}
{{- with $outputSSLConfig.key_passphrase }}
ssl.key_passphrase: {{ printf "${OUTPUT_%s_KEY_PASSPHRASE}" (upper $outputName) }}
{{- end }}
{{- with $outputSSLConfig.certificate }}
ssl.certificate: {{ ._mountPath  | quote }}
{{- end }}
{{- with $outputSSLConfig.key }}
ssl.key: {{ ._mountPath  | quote }}
{{- end }}
{{- with $outputSSLConfig.verificationMode }}
ssl.verification_mode: {{. | quote }}
{{- end }}
{{- with $outputSSLConfig.caTrustedFingerprint }}
ssl.ca_trusted_fingerprint: {{ . | quote }}
{{- end }}
{{- with $outputSSLConfig.ca_sha256 }}
ssl.ca_sha256: {{ $outputSSLConfig.ca_sha256 | quote }}
{{- end }}
{{- with $outputSSLConfig.renegotiation }}
ssl.renegotiation: {{ $outputSSLConfig.renegotiation | quote }}
{{- end }}
{{- with $outputSSLConfig.client_authentication }}
ssl.client_authentication: {{ $outputSSLConfig.client_authentication | quote }}
{{- end }}
{{- with $outputSSLConfig.supported_protocols }}
ssl.supported_protocols:
{{- range $idx, $protocol := . }}
  -  {{ $protocol  | quote }}
{{- end }}
{{- end }}
{{- with $outputSSLConfig.cipher_suites }}
ssl.cipher_suites:
{{- range $idx, $cipherSuite := . }}
  -  {{ $cipherSuite | quote }}
{{- end }}
{{- end }}
{{- with $outputSSLConfig.curve_types }}
ssl.curve_types:
{{- range $idx, $curveType := . }}
  -  {{ $curveType | quote }}
{{- end }}
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
