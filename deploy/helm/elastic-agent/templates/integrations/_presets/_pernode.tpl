{{- define "elasticagent.presets.pernode.init" -}}
{{- with $.Values.agent.presets.perNode -}}
{{- $preset := . -}}
{{- $volumeMounts := (include "elasticagent.presets.pernode.volumemounts" $ | fromYaml) -}}
{{- with ($volumeMounts).extraVolumeMounts -}}
{{- include "elasticagent.preset.mutate.volumemounts" (list $preset $volumeMounts) -}}
{{- end -}}
{{- $volumes := (include "elasticagent.presets.pernode.volumes" $ | fromYaml) -}}
{{- with ($volumes).extraVolumes -}}
{{- include "elasticagent.preset.mutate.volumes" (list $preset $volumes) -}}
{{- end -}}
{{- $tolerations := (include "elasticagent.presets.pernode.tolerations" $ | fromYaml) -}}
{{- with ($tolerations).tolerations -}}
{{- include "elasticagent.preset.mutate.tolerations" (list $preset $tolerations ) -}}
{{- end -}}
{{- $capabilities := (include "elasticagent.presets.pernode.securityContext.capabilities.add" $ | fromYaml) -}}
{{- with ($capabilities).securityContext -}}
{{- include "elasticagent.preset.mutate.securityContext.capabilities.add" (list $preset $capabilities ) -}}
{{- end -}}
{{- if eq $.Values.agent.fleet.enabled false -}}
{{/* hints and outputs are supported only for standalone agents */}}
{{- $providers := (include "elasticagent.presets.pernode.providers.kubernetes.hints" $ | fromYaml) -}}
{{- with ($providers).providers -}}
{{- include "elasticagent.preset.mutate.providers.kubernetes.hints" (list $preset $providers ) -}}
{{- end -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ . $.Values.kubernetes.output)}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.presets.pernode.volumemounts" -}}
extraVolumeMounts:
{{- $k8sIntegrationLogs := and (eq $.Values.kubernetes.enabled true) (has true (pluck "enabled" $.Values.kubernetes.containers.logs $.Values.kubernetes.containers.audit_logs) ) }}
{{- $systemIntegrationLogs := and (eq $.Values.system.enabled true) (has true (pluck "enabled" $.Values.system.syslog $.Values.system.authLogs) ) }}
{{- if or $k8sIntegrationLogs $systemIntegrationLogs }}
- name: varlibdockercontainers
  mountPath: /var/lib/docker/containers
  readOnly: true
- name: varlog
  mountPath: /var/log
  readOnly: true
{{- end }}
{{- if and (eq $.Values.system.enabled true) (eq $.Values.system.metrics.enabled true) }}
- name: proc
  mountPath: /hostfs/proc
  readOnly: true
- name: cgroup
  mountPath: /hostfs/sys/fs/cgroup
  readOnly: true
- name: var-lib
  mountPath: /hostfs/var/lib
  readOnly: true
- name: etc-full
  mountPath: /hostfs/etc
  readOnly: true
{{- end }}
{{- end }}

{{- define "elasticagent.presets.pernode.volumes" -}}
extraVolumes:
{{- $k8sIntegrationLogs := and (eq $.Values.kubernetes.enabled true) (has true (pluck "enabled" $.Values.kubernetes.containers.logs $.Values.kubernetes.containers.audit_logs) ) }}
{{- $systemIntegrationLogs := and (eq $.Values.system.enabled true) (has true (pluck "enabled" $.Values.system.syslog $.Values.system.authLogs) ) }}
{{- if or $k8sIntegrationLogs $systemIntegrationLogs }}
- name: varlibdockercontainers
  hostPath:
    path: /var/lib/docker/containers
- name: varlog
  hostPath:
    path: /var/log
{{- end }}
{{- if and (eq $.Values.system.enabled true) (eq $.Values.system.metrics.enabled true) }}
- name: proc
  hostPath:
    path: /proc
- name: cgroup
  hostPath:
    path: /sys/fs/cgroup
- name: etc-full
  hostPath:
    path: /etc
- name: var-lib
  hostPath:
    path: /var/lib
{{- end }}
{{- end -}}

{{- define "elasticagent.presets.pernode.providers.kubernetes.hints" -}}
providers:
{{- if and (eq $.Values.kubernetes.enabled true) (eq $.Values.kubernetes.hints.enabled true) }}
  kubernetes:
    hints:
      enabled: true
{{- if (eq $.Values.kubernetes.containers.logs.enabled false) }}
      default_container_logs: true
{{- else }}
      default_container_logs: false
{{- end }}
{{- end }}
{{- end -}}

{{- define "elasticagent.presets.pernode.tolerations" -}}
tolerations:
{{- if and (eq $.Values.kubernetes.enabled true) (has true (pluck "enabled" $.Values.kubernetes.scheduler $.Values.kubernetes.controller_manager)) }}
  - key: node-role.kubernetes.io/control-plane
    effect: NoSchedule
  - key: node-role.kubernetes.io/master
    effect: NoSchedule
{{- end }}
{{- end -}}

{{- define "elasticagent.presets.pernode.securityContext.capabilities.add" -}}
securityContext:
{{- if eq $.Values.agent.unprivileged true -}}
{{- $k8sIntegrationRead := and (eq $.Values.kubernetes.enabled true) (has true (pluck "enabled" $.Values.kubernetes.containers.logs $.Values.kubernetes.containers.audit_logs) ) }}
{{- $systemIntegrationRead := and (eq $.Values.system.enabled true) (has true (pluck "enabled" $.Values.system.syslog $.Values.system.authLogs $.Values.system.metrics) ) }}
{{- if or $k8sIntegrationRead $systemIntegrationRead }}
  capabilities:
    add:
      - DAC_READ_SEARCH
{{- end -}}
{{- end -}}
{{- end -}}
