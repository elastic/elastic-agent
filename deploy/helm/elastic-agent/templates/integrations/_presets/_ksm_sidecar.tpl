{{- define "elasticagent.presets.ksm.sidecar.init" -}}
{{- if and (eq $.Values.kubernetes.enabled true) (eq $.Values.kubernetes.state.enabled true) -}}
{{- if and (eq (index $.Values "kube-state-metrics" "enabled") true) (eq $.Values.kubernetes.state.agentAsSidecar.enabled true) -}}
{{- $config := print (include "elasticagent.kubernetes.config.state.input" $) | fromYamlArray -}}
{{- if or $config (eq $.Values.agent.fleet.enabled true) -}}
{{/* set up the kube-state-metrics chart values */}}
{{- $agentName := "agent-ksm" -}}
{{- $kubeStateChart := index $.Values "kube-state-metrics" -}}
{{- $fleetMutations := dict}}
{{- if eq $.Values.agent.fleet.enabled true -}}
{{- include "elasticagent.preset.mutate.fleet" (list $ $fleetMutations) -}}
{{- else -}}
{{- $kubernetesOutputVal := get $.Values.outputs $.Values.kubernetes.output -}}
{{- $outputVolumes := include "elasticagent.output.preset.volumes" $kubernetesOutputVal | fromYamlArray -}}
{{- with $outputVolumes -}}
{{- $_ := set $fleetMutations "extraVolumes" . -}}
{{- end -}}
{{- $outputVolumeMounts := include "elasticagent.output.preset.volumemounts" $kubernetesOutputVal | fromYamlArray -}}
{{- with $outputVolumeMounts -}}
{{- $_ := set $fleetMutations "extraVolumeMounts" $outputVolumeMounts -}}
{{- end -}}
{{- end -}}
{{- $agentContainer := print (include "elasticagent.presets.ksm.sidecar.container" (list $ $fleetMutations)) | fromYaml }}
{{- $_ := set $kubeStateChart "containers" (list $agentContainer) -}}
{{- $agentConfigVolume := print (include "elasticagent.presets.ksm.sidecar.volume" (list $ $agentName)) | fromYaml }}
{{- $_ := set $kubeStateChart "volumes" (uniq (concat (dig "volumes" list $kubeStateChart) (list $agentConfigVolume))) -}}
{{- with ($fleetMutations).extraVolumes -}}
{{- $_ := set $kubeStateChart "volumes" (uniq (concat (dig "volumes" list $kubeStateChart) .)) -}}
{{- end -}}
{{- $_ := set $kubeStateChart "autosharding" (dict "enabled" true)  }}
{{- with $.Values.agent.imagePullSecrets -}}
{{- $_ := set $kubeStateChart "imagePullSecrets" . -}}
{{- end -}}
{{- $secret := (include "elasticagent.presets.ksm.sidecar.secret" (list $ $agentName $config)) }}
{{- $_ := set $kubeStateChart "podAnnotations" (dict "checksum/config" ((print $secret) | sha256sum)) }}
{{- $_ := set $.Values.AsMap "kube-state-metrics" $kubeStateChart -}}
---
{{ $secret }}
---
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define  "elasticagent.presets.ksm.sidecar.container" -}}
{{- $ := index . 0 -}}
{{- $fleetMutations := index . 1 -}}
name: "agent"
{{- with $.Values.agent.image.pullPolicy }}
imagePullPolicy: {{ . }}
{{- end }}
{{- if $.Values.agent.image.tag }}
image: "{{ $.Values.agent.image.repository }}:{{ $.Values.agent.image.tag }}"
{{- else }}
image: "{{ $.Values.agent.image.repository }}:{{ $.Values.agent.version }}"
{{- end }}
args: ["-c", "/etc/elastic-agent/agent.yml", "-e"]
{{- if eq $.Values.agent.unprivileged true }}
securityContext:
  capabilities:
    drop:
    - ALL
    add:
    - CHOWN
    - SETPCAP
    - SYS_PTRACE
  privileged: false
  runAsGroup: 1000
  runAsUser: 1000
{{- end }}
{{- with $.Values.kubernetes.state.agentAsSidecar.resources }}
resources:
  {{- . | toYaml | nindent 2 }}
{{- end }}
volumeMounts:
  - name: config
    mountPath: /etc/elastic-agent/agent.yml
    readOnly: true
    subPath: agent.yml
  {{- with ($fleetMutations).extraVolumeMounts }}
  {{- . | toYaml | nindent 2 }}
  {{- end }}
env:
  - name: NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: STATE_PATH
    value: "/usr/share/elastic-agent/state"
{{- if eq $.Values.agent.fleet.enabled false -}}
{{- $outputName := $.Values.kubernetes.output -}}
{{- $ouputVal := get $.Values.outputs $.Values.kubernetes.output }}
{{- (include (printf "elasticagent.output.%s.preset.envvars" ($ouputVal).type) (list $ $outputName $ouputVal)) | nindent 2 }}
{{- else -}}
{{- with ($fleetMutations).extraEnvs -}}
{{- . | toYaml | nindent 2 }}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define  "elasticagent.presets.ksm.sidecar.volume" -}}
{{- $ := index . 0 -}}
{{- $agentName := index . 1 -}}
name: config
secret:
  defaultMode: 0444
  secretName: {{$agentName}}
{{- end -}}

{{- define  "elasticagent.presets.ksm.sidecar.providers" -}}
providers:
  kubernetes:
    enabled: false
  kubernetes_leaderelection:
    enabled: false
    leader_lease: agent-ksm-sharded
{{- end -}}

{{- define  "elasticagent.presets.ksm.sidecar.secret" }}
{{- $ := index . 0 -}}
{{- $agentName := index . 1 -}}
{{- $streams := index . 2 -}}
{{- $outputName := $.Values.kubernetes.output -}}
{{- $ouputVal := get $.Values.outputs $outputName }}
{{- $presetVal := dict }}
{{- $_ := set $presetVal "outputs" (dict $outputName $ouputVal) }}
{{- with (include "elasticagent.presets.ksm.sidecar.providers" $ | fromYaml).providers }}
{{- $_ := set $presetVal "providers" . }}
{{- end }}
{{- $_ := set $presetVal "_inputs" $streams }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ $agentName }}
  namespace: {{ $.Release.Namespace | quote }}
stringData:
{{ include "elasticagent.engine.k8s.secretData" (list $ $presetVal $agentName) }}
{{- end }}
