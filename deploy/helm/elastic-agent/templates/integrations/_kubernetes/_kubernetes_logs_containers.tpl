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
      - '/var/log/pods/*/*/*.log*'
    {{- else }}
    paths:
      - '/var/log/containers/*.log'
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
