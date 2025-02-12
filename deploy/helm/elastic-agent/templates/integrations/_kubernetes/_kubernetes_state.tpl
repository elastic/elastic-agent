{{- define "elasticagent.kubernetes.config.state.init" -}}
{{- if or (eq (index $.Values "kube-state-metrics" "enabled") false) (eq $.Values.kubernetes.state.agentAsSidecar.enabled false) -}}
{{/* in standablone mode kube-state-metrics will be collected by the clusterWide preset */}}
{{- with (include "elasticagent.kubernetes.config.state.input" $ | fromYamlArray) -}}
{{- include "elasticagent.preset.mutate.inputs" (list $ $.Values.agent.presets.clusterWide .) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.kubernetes.config.state.input" -}}
{{- if and (eq $.Values.agent.fleet.enabled false) (eq $.Values.kubernetes.state.enabled true) -}}
{{- $streams := dict -}}
{{- $_ := set $streams "containers" "state_container" -}}
{{- $_ := set $streams "cronjobs" "state_cronjob" -}}
{{- $_ := set $streams "daemonsets" "state_daemonset" -}}
{{- $_ := set $streams "deployments" "state_deployment" -}}
{{- $_ := set $streams "jobs" "state_job" -}}
{{- $_ := set $streams "namespaces" "state_namespace" -}}
{{- $_ := set $streams "nodes" "state_node" -}}
{{- $_ := set $streams "persistentvolumeclaims" "state_persistentvolumeclaim" -}}
{{- $_ := set $streams "persistentvolumes" "state_persistentvolume" -}}
{{- $_ := set $streams "pods" "state_pod" -}}
{{- $_ := set $streams "replicasets" "state_replicaset" -}}
{{- $_ := set $streams "resourcequotas" "state_resourcequota" -}}
{{- $_ := set $streams "services" "state_service" -}}
{{- $_ := set $streams "statefulsets" "state_statefulset" -}}
{{- $_ := set $streams "storageclasses" "state_storageclass" -}}
{{- $activeStreams := list}}
{{- range $streamKey, $streamMetricset := $streams -}}
{{- with include "elasticagent.kubernetes.config.state.stream" (list $ $streamKey $streamMetricset) | fromYamlArray -}}
{{- $activeStreams = concat $activeStreams . -}}
{{- end -}}
{{- end -}}
{{- with $activeStreams }}
- id: kube-state-metrics-kubernetes/metrics
  type: kubernetes/metrics
  data_stream:
    namespace: {{ $.Values.kubernetes.namespace }}
  use_output: {{ $.Values.kubernetes.output }}
  streams:
  {{- . | toYaml | nindent 4 }}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.kubernetes.config.state.stream" -}}
{{- $ := index . 0 -}}
{{- $streamKey := index . 1 -}}
{{- $streamMetricSet := index . 2 -}}
{{- if eq (dig $streamKey "state" "enabled" false $.Values.kubernetes) true -}}
- id: kubernetes/metrics-kubernetes.{{$streamMetricSet}}
  data_stream:
    type: metrics
    dataset: kubernetes.{{$streamMetricSet}}
  metricsets:
    - {{$streamMetricSet}}
{{- $defaults := (include "elasticagent.kubernetes.config.state.default_vars" $ ) | fromYaml -}}
{{- mergeOverwrite $defaults (dig $streamKey "state" "vars" dict $.Values.kubernetes) | toYaml | nindent 2 }}
{{- end -}}
{{- end -}}

{{- define "elasticagent.kubernetes.config.state.default_vars" -}}
add_metadata: true
hosts:
{{- if eq (index $.Values "kube-state-metrics" "enabled") true -}}
{{- $port := dig "kube-state-metrics" "service" "port" "8080" $.Values.AsMap -}}
{{- if eq $.Values.kubernetes.state.agentAsSidecar.enabled true }}
  - 'localhost:{{ $port }}'
{{- else }}
{{- $kubeStateChart := index $.Subcharts "kube-state-metrics" }}
  - '{{include "kube-state-metrics.fullname" $kubeStateChart }}:{{ $port }}'
{{- end }}
{{- else }}
  - {{ $.Values.kubernetes.state.host }}
{{- end }}
period: 10s
{{- if or (eq (index $.Values "kube-state-metrics" "enabled") false) (eq $.Values.kubernetes.state.agentAsSidecar.enabled false) }}
condition: '${kubernetes_leaderelection.leader} == true'
{{- end }}
bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
{{- end -}}

