{{/*
Expand the name of the chart.
*/}}
{{- define "elasticagent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified name for an agent preset.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "elasticagent.preset.fullname" -}}
{{- $ := index . 0 -}}
{{- $presetName := index . 1 -}}
{{- printf "agent-%s-%s" $presetName $.Release.Name | lower | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "elasticagent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Entrypoint for chart initialisation
*/}}
{{- define "elasticagent.init" -}}
{{- if not (hasKey $.Values.agent "initialised") -}}
{{/* init order matters */}}
{{- include (printf "elasticagent.engine.%s.init" $.Values.agent.engine) $ -}}
{{- include "elasticagent.init.fleet" $ -}}
{{- include "elasticagent.init.inputs" $ -}}
{{- include "elasticagent.init.presets" $ -}}
{{- $_ := set $.Values.agent "initialised" dict -}}
{{- end -}}
{{- end -}}

{{/*
Validate fleet configuration
*/}}
{{- define "elasticagent.init.fleet" -}}
{{- $ := . -}}
{{/* check if fleet is enabled */}}
{{- if eq $.Values.agent.fleet.enabled true -}}
{{/* check if the preset exists */}}
{{- $fleetPresetName := $.Values.agent.fleet.preset -}}
{{- $fleetPresetVal := get $.Values.agent.presets $fleetPresetName -}}
{{- $_ := required (printf "preset with name \"%s\" of fleet not defined" $fleetPresetName) $fleetPresetVal -}}
{{/* disable all presets except the fleet one */}}
{{- range $presetName, $presetVal := $.Values.agent.presets}}
{{- if ne $presetName $fleetPresetName -}}
{{- $_ := unset $.Values.agent.presets $presetName}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Initialise input templates if we are not deploying as managed
*/}}
{{- define "elasticagent.init.inputs" -}}
{{- $ := . -}}
{{- if eq $.Values.agent.fleet.enabled false -}}
{{/* standalone agent so initialise inputs */}}
{{- include "elasticagent.kubernetes.init" $ -}}
{{- include "elasticagent.system.init" $ -}}
{{- range $customInputName, $customInputVal := $.Values.extraIntegrations -}}
{{- $customInputPresetName := ($customInputVal).preset -}}
{{- $presetVal := get $.Values.agent.presets $customInputPresetName -}}
{{- $_ := required (printf "preset with name \"%s\" of customInput \"%s\" not defined" $customInputPresetName $customInputName) $customInputVal -}}
{{- $customInputOuput := ($customInputVal).use_output -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ $presetVal $customInputOuput) -}}
{{- include "elasticagent.preset.mutate.inputs" (list $ $presetVal (list $customInputVal)) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate and initialise the defined agent presets
*/}}
{{- define "elasticagent.init.presets" -}}
{{- $ := . -}}
{{- range $presetName, $presetVal := $.Values.agent.presets -}}
{{- include "elasticagent.preset.mutate.unprivileged" (list $ $presetVal) -}}
{{- include "elasticagent.preset.mutate.fleet" (list $ $presetVal) -}}
{{- $presetMode := ($presetVal).mode -}}
{{- if eq $.Values.agent.fleet.enabled false -}}
{{- $presetInputs := dig "_inputs" (list) $presetVal -}}
{{- if empty $presetInputs -}}
{{- $_ := unset $.Values.agent.presets $presetName}}
{{- else -}}
{{- $monitoringOutput := dig "agent" "monitoring" "use_output" "" $presetVal -}}
{{- if $monitoringOutput -}}
{{- include "elasticagent.preset.mutate.outputs.byname" (list $ $presetVal $monitoringOutput) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{/* by default we disable leader election but we also set the name of the leader lease in case it is explicitly enabled */}}
{{- if empty ($presetVal).providers -}}
{{- $_ := set $presetVal "providers" dict -}}
{{- end -}}
{{- $presetProviders := get $presetVal "providers" -}}
{{- if empty ($presetProviders).kubernetes_leaderelection -}}
{{- $_ := set $presetProviders "kubernetes_leaderelection" dict -}}
{{- end -}}
{{- $presetLeaderLeaseName := (printf "%s-%s" $.Release.Name $presetName) | lower  -}}
{{- $defaultLeaderElection := dict "enabled" false "leader_lease" $presetLeaderLeaseName -}}
{{- $presetLeaderElection := mergeOverwrite dict $defaultLeaderElection ($presetProviders).kubernetes_leaderelection -}}
{{- $_ := set $presetProviders "kubernetes_leaderelection" $presetLeaderElection -}}
{{- end -}}
{{- end -}}

{{/*
Mutate an agent preset based on agent.unprivileged
*/}}
{{- define "elasticagent.preset.mutate.unprivileged" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- if not (hasKey $preset "securityContext") -}}
{{- $_ := set $preset "securityContext" dict }}
{{- end -}}
{{- $presetSecurityContext := get $preset "securityContext" }}
{{- if eq $.Values.agent.unprivileged true -}}
{{- $_ := set $presetSecurityContext "privileged" false }}
{{- $_ := set $presetSecurityContext "runAsUser" 1000 }}
{{- $_ := set $presetSecurityContext "runAsGroup" 1000 }}
{{- if not (hasKey $presetSecurityContext "capabilities") -}}
{{- $_ := set $presetSecurityContext "capabilities" dict }}
{{- end -}}
{{- $presetSecurityContextCapabilities := get $presetSecurityContext "capabilities" }}
{{- $_ := set $presetSecurityContextCapabilities "drop" (list "ALL") -}}
{{- $presetSecurityContextCapabilitiesAdd := dig "add" list $presetSecurityContextCapabilities }}
{{- $capabilitiesAddToAdd := list "CHOWN" "SETPCAP" "DAC_READ_SEARCH" "SYS_PTRACE" -}}
{{- $presetSecurityContextCapabilitiesAdd = uniq (concat $presetSecurityContextCapabilitiesAdd $capabilitiesAddToAdd) -}}
{{- $_ := set $presetSecurityContextCapabilities "add" $presetSecurityContextCapabilitiesAdd -}}
{{- else -}}
{{- $_ := set $presetSecurityContext "runAsUser" 0 }}
{{- end -}}
{{- end -}}

{{/*
Mutate an agent preset based on agent.fleet
*/}}
{{- define "elasticagent.preset.mutate.fleet" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- if eq $.Values.agent.fleet.enabled true -}}
{{- $fleetEnvVars := list -}}
{{- if $.Values.agent.fleet.url -}}
{{- $fleetURL := dict }}
{{- $_ := set $fleetURL "name" "FLEET_URL" -}}
{{- $_ := set $fleetURL "value" $.Values.agent.fleet.url -}}
{{- $fleetEnvVars = append $fleetEnvVars $fleetURL  -}}
{{- end -}}
{{- if $.Values.agent.fleet.token -}}
{{- $fleetToken := dict }}
{{- $_ := set $fleetToken "name" "FLEET_ENROLLMENT_TOKEN" -}}
{{- $_ := set $fleetToken "value" $.Values.agent.fleet.token -}}
{{- $fleetEnvVars = append $fleetEnvVars $fleetToken  -}}
{{- end -}}
{{- $fleetInsecure := dict }}
{{- $_ := set $fleetInsecure "name" "FLEET_INSECURE" -}}
{{- $_ := set $fleetInsecure "value" (printf "%t" $.Values.agent.fleet.insecure) -}}
{{- $fleetEnvVars = append $fleetEnvVars $fleetInsecure  -}}
{{- if $.Values.agent.fleet.kibanaHost -}}
{{- $fleetKibanaHost := dict }}
{{- $_ := set $fleetKibanaHost "name" "KIBANA_HOST" -}}
{{- $_ := set $fleetKibanaHost "value" $.Values.agent.fleet.kibanaHost -}}
{{- $fleetEnvVars = append $fleetEnvVars $fleetKibanaHost  -}}
{{- end -}}
{{- if $.Values.agent.fleet.kibanaUser -}}
{{- $fleetKibanaUser := dict }}
{{- $_ := set $fleetKibanaUser "name" "KIBANA_FLEET_USERNAME" -}}
{{- $_ := set $fleetKibanaUser "value" $.Values.agent.fleet.kibanaUser -}}
{{- $fleetEnvVars = append $fleetEnvVars $fleetKibanaUser  -}}
{{- end -}}
{{- if $.Values.agent.fleet.kibanaPassword -}}
{{- $fleetKibanaPassword := dict }}
{{- $_ := set $fleetKibanaPassword "name" "KIBANA_FLEET_PASSWORD" -}}
{{- $_ := set $fleetKibanaPassword "value" $.Values.agent.fleet.kibanaPassword -}}
{{- $fleetEnvVars = append $fleetEnvVars $fleetKibanaPassword  -}}
{{- end -}}
{{- if not (empty $fleetEnvVars) -}}
{{- $fleetEnroll := dict -}}
{{- $_ := set $fleetEnroll "name" "FLEET_ENROLL" -}}
{{- $_ := set $fleetEnroll "value" "1" -}}
{{- $fleetEnvVars = append $fleetEnvVars $fleetEnroll -}}
{{- if not (hasKey $preset "extraEnvs") -}}
{{- $_ := set $preset "extraEnvs" list -}}
{{- end -}}
{{- $presetEnvVars := get $preset "extraEnvs" -}}
{{- $presetEnvVars = uniq (concat $presetEnvVars $fleetEnvVars) -}}
{{- $_ := set $preset "extraEnvs" $presetEnvVars -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "elasticagent.labels" -}}
helm.sh/chart: {{ include "elasticagent.chart" . }}
{{ include "elasticagent.selectorLabels" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "elasticagent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "elasticagent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.agent.version}}
{{- end }}

{{- define "elasticagent.preset.applyOnce" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- if not (hasKey $preset "_appliedMutationTemplates") -}}
{{- $_ := set $preset "_appliedMutationTemplates" dict }}
{{- end -}}
{{- $appliedMutationTemplates := get $preset "_appliedMutationTemplates" -}}
{{- if not (hasKey $appliedMutationTemplates $templateName) -}}
{{- include $templateName $ -}}
{{- $_ := set $appliedMutationTemplates $templateName dict}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.inputs" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $inputVal := index . 2 -}}
{{- $presetInputs := dig "_inputs" (list) $preset -}}
{{- $presetInputs = uniq (concat $presetInputs $inputVal) -}}
{{- $_ := set $preset "_inputs" $presetInputs -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.securityContext.capabilities.add" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- if not (hasKey $preset "securityContext") -}}
{{- $_ := set $preset "securityContext" dict }}
{{- end -}}
{{- $presetSecurityContext := get $preset "securityContext" }}
{{- if not (hasKey $presetSecurityContext "capabilities") -}}
{{- $_ := set $presetSecurityContext "capabilities" dict }}
{{- end -}}
{{- $presetSecurityContextCapabilities := get $presetSecurityContext "capabilities" }}
{{- if not (hasKey $presetSecurityContextCapabilities "add") -}}
{{- $_ := set $presetSecurityContextCapabilities "add" list }}
{{- end -}}
{{- $presetSecurityContextCapabilitiesAdd := get $presetSecurityContextCapabilities "add" }}
{{- $capabilitiesAddToAdd := dig "securityContext" "capabilities" "add" (list) (include $templateName $ | fromYaml) -}}
{{- $presetSecurityContextCapabilitiesAdd = uniq (concat $presetSecurityContextCapabilitiesAdd $capabilitiesAddToAdd) -}}
{{- $_ := set $presetSecurityContextCapabilities "add" $presetSecurityContextCapabilitiesAdd -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.providers.kubernetes.hints" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- if not (hasKey $preset "providers") -}}
{{- $_ := set $preset "providers" dict }}
{{- end -}}
{{- $presetProviders := get $preset "providers" }}
{{- if not (hasKey $presetProviders "kubernetes") -}}
{{- $_ := set $presetProviders "kubernetes" dict }}
{{- end -}}
{{- $presetProvidersKubernetes := get $presetProviders "kubernetes" }}
{{- if not (hasKey $presetProvidersKubernetes "hints") -}}
{{- $_ := set $presetProvidersKubernetes "hints" dict }}
{{- end -}}
{{- $presetProvidersKubernetesHints := get $presetProvidersKubernetes "hints" }}
{{- $presetProvidersKubernetesHintsToAdd := dig "providers" "kubernetes" "hints" (dict) (include $templateName $ | fromYaml) -}}
{{- $presetProvidersKubernetesHints = merge $presetProvidersKubernetesHintsToAdd $presetProvidersKubernetesHints -}}
{{- $_ := set $presetProvidersKubernetes "hints" $presetProvidersKubernetesHints -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.rules" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- if eq ($preset).clusterRole.create true -}}
{{- $presetClusterRoleRules := dig "rules" (list) ($preset).clusterRole -}}
{{- $rulesToAdd := get (include $templateName $ | fromYaml) "rules" -}}
{{- $presetClusterRoleRules = uniq (concat $presetClusterRoleRules $rulesToAdd) -}}
{{- $_ := set ($preset).clusterRole "rules" $presetClusterRoleRules -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.annotations" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $annotationsToAdd := index . 2 -}}
{{- $presetAnnotations := dig "annotations" (dict) $preset -}}
{{- $presetAnnotations = merge $presetAnnotations $annotationsToAdd -}}
{{- $_ := set $preset "annotations" $presetAnnotations -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.containers" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- $presetContainers := dig "extraContainers" (list) $preset -}}
{{- $containersToAdd := get (include $templateName $ | fromYaml) "extraContainers"}}
{{- $presetContainers = uniq (concat $presetContainers $containersToAdd) -}}
{{- $_ := set $preset "extraContainers" $presetContainers -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.tolerations" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- $tolerationsToAdd := dig "tolerations" (list) (include $templateName $ | fromYaml) }}
{{- if $tolerationsToAdd -}}
{{- $presetTolerations := dig "tolerations" (list) $preset -}}
{{- $presetTolerations = uniq (concat $presetTolerations $tolerationsToAdd) -}}
{{- $_ := set $preset "tolerations" $tolerationsToAdd -}}
{{- end -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.initcontainers" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- $presetInitContainers := dig "initContainers" (list) $preset -}}
{{- $initContainersToAdd := get (include $templateName $ | fromYaml) "initContainers"}}
{{- $presetInitContainers = uniq (concat $presetInitContainers $initContainersToAdd) -}}
{{- $_ := set $preset "initContainers" $presetInitContainers -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.volumes" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- $presetVolumes := dig "extraVolumes" (list) $preset -}}
{{- $volumesToAdd := get (include $templateName $ | fromYaml) "extraVolumes"}}
{{- $presetVolumes = uniq (concat $presetVolumes $volumesToAdd) -}}
{{- $_ := set $preset "extraVolumes" $presetVolumes -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.volumemounts" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $templateName := index . 2 -}}
{{- $presetVolumeMounts := dig "extraVolumeMounts" (list) $preset -}}
{{- $volumeMountsToAdd := get (include $templateName $ | fromYaml) "extraVolumeMounts"}}
{{- $presetVolumeMounts = uniq (concat $presetVolumeMounts $volumeMountsToAdd) -}}
{{- $_ := set $preset "extraVolumeMounts" $presetVolumeMounts -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.outputs.byname" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $outputName := index . 2 -}}
{{- $ouputVal := get $.Values.outputs $outputName }}
{{- $_ := required (printf "output \"%s\" is not defined" $outputName) $ouputVal -}}
{{- $outputCopy := deepCopy $ouputVal -}}
{{- $presetOutputs := dig "outputs" (dict) $preset -}}
{{- if not (hasKey $presetOutputs $outputName) -}}
{{- $_ := set $presetOutputs $outputName $outputCopy}}
{{- end -}}
{{- $_ := set $preset "outputs" $presetOutputs -}}
{{- end -}}
