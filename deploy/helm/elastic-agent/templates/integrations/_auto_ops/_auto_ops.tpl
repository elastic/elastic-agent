{{- define "elasticagent.autoops.init" -}}
{{- if eq $.Values.autoOps.enabled true -}}
{{- $presetVal := $.Values.agent.presets.autoOps -}}
{{- $autoOpsConfig := ((include "elasticagent.autoops.config" $) | fromYaml) -}}
{{- include "elasticagent.preset.mutate.otelConfig" (list $ $presetVal $autoOpsConfig) -}}
{{- $autoOpsEnvVars := ((include "elasticagent.autoops.envVars" $) | fromYaml) -}}
{{- include "elasticagent.preset.mutate.envs" (list $presetVal $autoOpsEnvVars)}}
{{- end -}}
{{- end -}}
{{- define "elasticagent.autoops.config" -}}
receivers:
  metricbeatreceiver:
    metricbeat:
      modules:
        # Metrics
        - module: autoops_es
          hosts: ${env:AUTOOPS_ES_URL}
          period: 10s
          metricsets:
            - cat_shards
            - cluster_health
            - cluster_settings
            - license
            - node_stats
            - tasks_management
        # Templates
        - module: autoops_es
          hosts: ${env:AUTOOPS_ES_URL}
          period: 24h
          metricsets:
            - cat_template
            - component_template
            - index_template
    processors:
      - add_fields:
          target: autoops_es
          fields:
            temp_resource_id: ${env:AUTOOPS_TEMP_RESOURCE_ID}
            token: ${env:AUTOOPS_TOKEN}
    output:
      otelconsumer:
    telemetry_types: ["logs"]

exporters:
  otlphttp:
    headers:
      Authorization: "AutoOpsToken ${env:AUTOOPS_TOKEN}"
    endpoint: ${env:AUTOOPS_OTEL_URL}

service:
  pipelines:
    logs:
      receivers: [metricbeatreceiver]
      exporters: [otlphttp]
  telemetry:
    logs:
      encoding: json
{{- end -}}

{{- define "elasticagent.autoops.envVars" }}
{{- $presetName := "autoOps" }}
{{- $agentName := include "elasticagent.preset.fullname" (list $ $presetName) }}
extraEnvs:
  - name: AUTOOPS_TOKEN
    valueFrom:
      secretKeyRef:
        name: {{ $agentName }}-autoops
        key: autoops-token
  - name: AUTOOPS_TEMP_RESOURCE_ID
    valueFrom:
      secretKeyRef:
        name: {{ $agentName }}-autoops
        key: temp-resource-id
  - name: AUTOOPS_OTEL_URL
    valueFrom:
      secretKeyRef:
        name: {{ $agentName }}-autoops
        key: otel-url
  - name: AUTOOPS_ES_URL
    valueFrom:
      secretKeyRef:
        name: {{ $agentName }}-autoops
        key: autoops-es-url
  - name: ELASTICSEARCH_READ_API_KEY
    valueFrom:
      secretKeyRef:
        name: {{ $agentName }}-autoops
        key: es-api-key
  - name: ELASTIC_CLOUD_CONNECTED_MODE_API_KEY
    valueFrom:
      secretKeyRef:
        name: {{ $agentName }}-autoops
        key: cloud-connected-mode-api-key
  - name: ELASTIC_CLOUD_CONNECTED_MODE_API_URL
    valueFrom:
      secretKeyRef:
        name: {{ $agentName }}-autoops
        key: cloud-connected-mode-api-url
        optional: true
{{- end }}
