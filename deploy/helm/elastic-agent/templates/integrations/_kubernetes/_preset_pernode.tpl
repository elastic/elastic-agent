{{- define "elasticagent.kubernetes.pernode.preset" -}}
{{- include "elasticagent.preset.mutate.volumemounts" (list $ $.Values.agent.presets.perNode "elasticagent.kubernetes.pernode.preset.volumemounts") -}}
{{- include "elasticagent.preset.mutate.volumes" (list $ $.Values.agent.presets.perNode "elasticagent.kubernetes.pernode.preset.volumes") -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ $.Values.agent.presets.perNode $.Values.kubernetes.output)}}
<<<<<<< HEAD
{{- if eq $.Values.kubernetes.hints.enabled true -}}
{{- include "elasticagent.preset.mutate.initcontainers" (list $ $.Values.agent.presets.perNode "elasticagent.kubernetes.pernode.preset.initcontainers") -}}
=======
{{- if and (eq $.Values.kubernetes.hints.enabled true) (eq $.Values.agent.fleet.enabled false) -}}
>>>>>>> 0d94ead04 ([helm] fleet mode fixes (#6345))
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
{{- if eq $.Values.kubernetes.hints.enabled true }}
- name: external-inputs
  mountPath: /usr/share/elastic-agent/state/inputs.d
{{- end }}
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
{{- if eq $.Values.kubernetes.hints.enabled true }}
- name: external-inputs
  emptyDir: {}
{{- end }}
{{- end -}}

{{- define "elasticagent.kubernetes.pernode.preset.initcontainers" -}}
initContainers:
- name: k8s-templates-downloader
  image: busybox:1.36.1
  securityContext:
    allowPrivilegeEscalation: false
    privileged: false
    runAsUser: 1000
    runAsGroup: 1000
    capabilities:
      drop:
        - ALL
  command: [ 'sh' ]
  args:
    - -c
    - >-
      mkdir -p /etc/elastic-agent/inputs.d &&
      mkdir -p /etc/elastic-agent/inputs.d &&
      wget -O - https://github.com/elastic/elastic-agent/archive/v{{$.Values.agent.version}}.tar.gz | tar xz -C /etc/elastic-agent/inputs.d --strip=5 "elastic-agent-{{$.Values.agent.version}}/deploy/kubernetes/elastic-agent-standalone/templates.d"
  volumeMounts:
    - name: external-inputs
      mountPath: /etc/elastic-agent/inputs.d
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
