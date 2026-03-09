{{- define "elasticagent.cloudDefend.init" -}}
{{- if eq $.Values.cloudDefend.enabled true -}}
{{- $preset := $.Values.agent.presets.perNode -}}
{{- if eq $.Values.agent.fleet.enabled false -}}
{{- $inputVal := (include "elasticagent.cloudDefend.config.input" $ | fromYamlArray) -}}
{{- include "elasticagent.preset.mutate.inputs" (list $ $preset $inputVal) -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ $preset $.Values.cloudDefend.output) -}}
{{- end -}}
{{- $envVars := (include "elasticagent.cloudDefend.envVars" $ | fromYaml) -}}
{{- include "elasticagent.preset.mutate.envs" (list $preset $envVars) -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.cloudDefend.envVars" -}}
extraEnvs:
  - name: HOSTFS_PROC_PATH
    value: "/hostfs/proc"
{{- end -}}

{{- define "elasticagent.cloudDefend.config.input" -}}
{{- $policyID := default (uuidv4) $.Values.cloudDefend.policy_id -}}
- id: cloud_defend/control-cloud_defend-{{ $policyID }}
  revision: 1
  name: D4C
  type: cloud_defend/control
  use_output: {{ $.Values.cloudDefend.output }}
  package_policy_id: {{ $policyID }}
  meta:
    package:
      name: cloud_defend
      version: 1.0.0
  data_stream:
    namespace: {{ $.Values.cloudDefend.namespace }}
  streams:
    - id: cloud_defend/control-cloud_defend.alerts-{{ $policyID }}
      data_stream:
        dataset: cloud_defend.alerts
        type: logs
      security-policy:
      {{- $.Values.cloudDefend.securityPolicy | toYaml | nindent 8 }}
    - id: cloud_defend/control-cloud_defend.file-{{ $policyID }}
      data_stream:
        dataset: cloud_defend.file
        type: logs
      file-config: null
    - id: cloud_defend/control-cloud_defend.heartbeat-{{ $policyID }}
      data_stream:
        dataset: cloud_defend.heartbeat
        type: metrics
      period: {{ $.Values.cloudDefend.heartbeat.period }}
    - id: cloud_defend/control-cloud_defend.metrics-{{ $policyID }}
      data_stream:
        dataset: cloud_defend.metrics
        type: metrics
      metricsets:
      {{- $.Values.cloudDefend.metrics.metricsets | toYaml | nindent 8 }}
      hosts: null
      period: {{ $.Values.cloudDefend.metrics.period }}
    - id: cloud_defend/control-cloud_defend.process-{{ $policyID }}
      data_stream:
        dataset: cloud_defend.process
        type: logs
      process-config: null
{{- end -}}
