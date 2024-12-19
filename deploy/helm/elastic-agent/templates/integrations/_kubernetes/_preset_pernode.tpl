{{- define "elasticagent.kubernetes.pernode.preset" -}}
{{- include "elasticagent.preset.mutate.volumemounts" (list $ $.Values.agent.presets.perNode "elasticagent.kubernetes.pernode.preset.volumemounts") -}}
{{- include "elasticagent.preset.mutate.volumes" (list $ $.Values.agent.presets.perNode "elasticagent.kubernetes.pernode.preset.volumes") -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ $.Values.agent.presets.perNode $.Values.kubernetes.output)}}
{{- if eq $.Values.kubernetes.hints.enabled true -}}
{{- include "elasticagent.preset.mutate.providers.kubernetes.hints" (list $ $.Values.agent.presets.perNode "elasticagent.kubernetes.pernode.preset.providers.kubernetes.hints") -}}
{{- end -}}
{{- if or (eq $.Values.kubernetes.scheduler.enabled true) (eq $.Values.kubernetes.controller_manager.enabled true) -}}
{{- include "elasticagent.preset.mutate.tolerations" (list $ $.Values.agent.presets.perNode "elasticagent.kubernetes.pernode.preset.tolerations") -}}
{{- end -}}
{{- if eq $.Values.agent.unprivileged true -}}
{{- include "elasticagent.preset.mutate.securityContext.capabilities.add" (list $ $.Values.agent.presets.perNode "elasticagent.kubernetes.pernode.securityContext.capabilities.add") -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.kubernetes.pernode.preset.rules" -}}
{{- end -}}

{{- define "elasticagent.kubernetes.pernode.preset.volumemounts" -}}
extraVolumeMounts:
- name: proc
  mountPath: /hostfs/proc
  readOnly: true
- name: cgroup
  mountPath: /hostfs/sys/fs/cgroup
  readOnly: true
- name: varlibdockercontainers
  mountPath: /var/lib/docker/containers
  readOnly: true
- name: varlog
  mountPath: /var/log
  readOnly: true
- name: etc-full
  mountPath: /hostfs/etc
  readOnly: true
- name: var-lib
  mountPath: /hostfs/var/lib
  readOnly: true
{{- end -}}

{{- define "elasticagent.kubernetes.pernode.preset.volumes" -}}
extraVolumes:
- name: proc
  hostPath:
    path: /proc
- name: cgroup
  hostPath:
    path: /sys/fs/cgroup
- name: varlibdockercontainers
  hostPath:
    path: /var/lib/docker/containers
- name: varlog
  hostPath:
    path: /var/log
- name: etc-full
  hostPath:
    path: /etc
- name: var-lib
  hostPath:
    path: /var/lib
{{- end -}}

{{- define "elasticagent.kubernetes.pernode.preset.providers.kubernetes.hints" -}}
providers:
  kubernetes:
    hints:
      enabled: true
{{- end -}}

{{- define "elasticagent.kubernetes.pernode.preset.tolerations" -}}
tolerations:
  - key: node-role.kubernetes.io/control-plane
    effect: NoSchedule
  - key: node-role.kubernetes.io/master
    effect: NoSchedule
{{- end -}}

{{- define "elasticagent.kubernetes.pernode.securityContext.capabilities.add" -}}
securityContext:
  capabilities:
    add:
      - DAC_READ_SEARCH
{{- end -}}
