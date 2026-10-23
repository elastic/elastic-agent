{{- define "elasticagent.kubernetes.config.container_logs.init" -}}
{{- if eq $.Values.kubernetes.containers.logs.enabled true -}}
{{- $preset := $.Values.agent.presets.perNode -}}
{{- $inputVal := (include "elasticagent.kubernetes.config.container_logs.input" $ | fromYamlArray) -}}
{{- include "elasticagent.preset.mutate.inputs" (list $ $preset $inputVal) -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ $preset $.Values.kubernetes.output) -}}
{{- end -}}
{{- end -}}

{{/*
Config input for container logs
*/}}
{{- define "elasticagent.kubernetes.config.container_logs.input" -}}
{{- $singleInput := dig "single_input" true .Values.kubernetes.containers.logs -}}
{{- $rotated := .Values.kubernetes.containers.logs.rotated_logs -}}
{{- if $singleInput -}}
{{- /*
The agent renders an input once per container for each dynamic provider variable it references, but only
renames the outer input id. The stream id of the single input would then be duplicated, which filestream rejects.
*/ -}}
{{- $userValues := dict
      "kubernetes.containers.logs.vars" (toYaml (dig "vars" (dict) .Values.kubernetes.containers.logs))
      "kubernetes.namespace" (toString .Values.kubernetes.namespace)
      "kubernetes.onboardingID" (toString (default "" .Values.kubernetes.onboardingID)) -}}
{{- range $name, $value := $userValues -}}
{{- if regexMatch "\\$\\{[^}]*(kubernetes|docker)\\." $value -}}
{{- fail (printf "%s references a dynamic provider variable (${kubernetes.*} or ${docker.*}), which is not supported with kubernetes.containers.logs.single_input=true. Set kubernetes.containers.logs.single_input=false to use one input per container." $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- /* The kubernetes provider only discovers pods in its configured namespace, scope the glob the same way. */ -}}
{{- $providerNamespace := dig "providers" "kubernetes" "namespace" "" .Values.agent.presets.perNode -}}
- id: filestream-container-logs
  type: filestream
  data_stream:
    namespace: {{ .Values.kubernetes.namespace }}
  use_output: {{ .Values.kubernetes.output }}
  streams:
  {{- if $singleInput }}
  - id: kubernetes-container-logs
    {{- if $rotated }}
    compression: auto
    paths:
      {{- if $providerNamespace }}
      - '/var/log/pods/{{ $providerNamespace }}_*/*/*.log*'
      {{- else }}
      - '/var/log/pods/*/*/*.log*'
      {{- end }}
    {{- else }}
    paths:
      {{- if $providerNamespace }}
      - '/var/log/containers/*_{{ $providerNamespace }}_*.log'
      {{- else }}
      - '/var/log/containers/*.log'
      {{- end }}
    {{- end }}
    take_over:
      enabled: true
      from_any_id: true
  {{ else if $rotated }}
  - id: kubernetes-container-logs-${kubernetes.pod.uid}-${kubernetes.container.name}
    compression: auto
    paths:
      - '/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log*'
  {{ else }}
  - id: kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}
    paths:
      - '/var/log/containers/*${kubernetes.container.id}.log'
  {{ end }}
    data_stream:
      dataset: kubernetes.container_logs
      type: logs
    prospector.scanner.symlinks: {{ dig "vars" "symlinks" true .Values.kubernetes.containers.logs }}
    {{- with (dig "vars" "read_until_eof" dict .Values.kubernetes.containers.logs) }}
    read_until_eof:
      {{- . | toYaml | nindent 6 }}
    {{- end }}
    parsers:
      - container:
          stream: {{ dig "vars" "containerParserStream" "all" .Values.kubernetes.containers.logs }}
          format: {{ dig "vars" "containerParserFormat" "auto" .Values.kubernetes.containers.logs }}
      {{- with (dig "vars" "additionalParsersConfig" list .Values.kubernetes.containers.logs) }}
      {{ . | toYaml | nindent 6 }}
      {{- end }}
    {{- $additionalProcessors := dig "vars" "processors" list $.Values.kubernetes.containers.logs -}}
    {{- $builtInProcessors := dig "vars" "enabledDefaultProcessors" true $.Values.kubernetes.containers.logs -}}
    {{- if compact (list $singleInput $builtInProcessors $additionalProcessors $.Values.kubernetes._onboarding_processor) }}
    processors:
      {{- if $singleInput }}
      - add_kubernetes_metadata:
          wait_for_metadata: true
          append_fields: true
          default_indexers:
            enabled: false
          default_matchers:
            enabled: false
          {{- if $builtInProcessors }}
          include_annotations:
            - elastic.co/dataset
            - elastic.co/namespace
            - elastic.co/preserve_original_event
          {{- end }}
          {{- if $rotated }}
          indexers:
            - pod_uid: null
          matchers:
            - logs_path:
                logs_path: /var/log/pods/
                resource_type: pod
          {{- else }}
          indexers:
            - container: null
          matchers:
            - logs_path:
                logs_path: /var/log/containers/
                resource_type: container
          {{- end }}
      {{- with $builtInProcessors }}
      - add_tags:
          tags:
            - preserve_original_event
          when:
            and:
              - has_fields:
                  - kubernetes.annotations.elastic_co/preserve_original_event
              - regexp:
                  kubernetes.annotations.elastic_co/preserve_original_event: ^(?i)true$
      {{- end }}
      {{- else }}
      {{- with $builtInProcessors }}
      - add_fields:
          target: kubernetes
          fields:
            annotations.elastic_co/dataset: '${kubernetes.annotations.elastic.co/dataset|""}'
            annotations.elastic_co/namespace: '${kubernetes.annotations.elastic.co/namespace|""}'
            annotations.elastic_co/preserve_original_event: '${kubernetes.annotations.elastic.co/preserve_original_event|""}'
      - drop_fields:
          fields:
            - kubernetes.annotations.elastic_co/dataset
          when:
            equals:
              kubernetes.annotations.elastic_co/dataset: ''
          ignore_missing: true
      - drop_fields:
          fields:
            - kubernetes.annotations.elastic_co/namespace
          when:
            equals:
              kubernetes.annotations.elastic_co/namespace: ''
          ignore_missing: true
      - drop_fields:
          fields:
            - kubernetes.annotations.elastic_co/preserve_original_event
          when:
            equals:
              kubernetes.annotations.elastic_co/preserve_original_event: ''
          ignore_missing: true
      - add_tags:
          tags:
            - preserve_original_event
          when:
            and:
              - has_fields:
                  - kubernetes.annotations.elastic_co/preserve_original_event
              - regexp:
                  kubernetes.annotations.elastic_co/preserve_original_event: ^(?i)true$
      {{- end }}
      {{- end }}
      {{- with $.Values.kubernetes._onboarding_processor }}
      - {{ . | toYaml | nindent 8 }}
      {{- end }}
      {{- with $additionalProcessors }}
      {{- . | toYaml | nindent 6 }}
      {{- end }}
   {{- end }}
{{- end -}}
