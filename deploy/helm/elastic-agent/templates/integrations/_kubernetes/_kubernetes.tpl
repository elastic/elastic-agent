{{- define "elasticagent.kubernetes.init" -}}
{{- if eq $.Values.kubernetes.enabled true -}}
{{- include "elasticagent.kubernetes.config.kube_apiserver.init" $ -}}
{{- include "elasticagent.kubernetes.config.kube_controller.init" $ -}}
{{- include "elasticagent.kubernetes.config.state.init" $ -}}
{{- include "elasticagent.kubernetes.config.audit_logs.init" $ -}}
{{- include "elasticagent.kubernetes.config.container_logs.init" $ -}}
{{- include "elasticagent.kubernetes.config.kubelet.containers.init" $ -}}
{{- include "elasticagent.kubernetes.config.kubelet.nodes.init" $ -}}
{{- include "elasticagent.kubernetes.config.kubelet.pods.init" $ -}}
{{- include "elasticagent.kubernetes.config.kubelet.system.init" $ -}}
{{- include "elasticagent.kubernetes.config.kubelet.volumes.init" $ -}}
{{- include "elasticagent.kubernetes.config.kube_proxy.init" $ -}}
{{- include "elasticagent.kubernetes.config.kube_scheduler.init" $ -}}
{{- end -}}
{{- end -}}
