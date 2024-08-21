{{/*
Expand the name of the chart.
*/}}
{{- define "elasticagent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "elasticagent.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
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
{{- include "elasticagent.init.engine" $ -}}
{{- include "elasticagent.init.fleet" $ -}}
{{- include "elasticagent.init.outputs" $ -}}
{{- include "elasticagent.init.inputs" $ -}}
{{- include "elasticagent.init.presets" $ -}}
{{- $_ := set $.Values.agent "initialised" dict -}}
{{- end -}}
{{- end -}}

{{/*
Check the agent.engine and fallback to "k8s"
*/}}
{{- define "elasticagent.init.engine" -}}
{{- $ := . -}}
{{- if empty (dig "engine" ("") $.Values.agent) -}}
{{- $_ := set $.Values.agent "engine" "k8s" -}}
{{- end -}}
{{- include (printf "elasticagent.engine.%s.init" $.Values.agent.engine) $ -}}
{{- end -}}

{{/*
Validate fleet configuration
*/}}
{{- define "elasticagent.init.fleet" -}}
{{- $ := . -}}
{{- if eq $.Values.agent.fleet.enabled true -}}
{{- if empty $.Values.agent.fleet.url -}}
{{- fail "url must be defined when fleet mode is enabled" -}}
{{- end -}}
{{- if empty $.Values.agent.fleet.token -}}
{{- if empty $.Values.agent.fleet.kibanaHost -}}
{{- fail "kibana host must be defined when fleet mode is enabled and a token is not supplied" -}}
{{- end -}}
{{- if empty $.Values.agent.fleet.kibanaUser -}}
{{- fail "kibana username must be defined when fleet mode is enabled and a token is not supplied" -}}
{{- end -}}
{{- if empty $.Values.agent.fleet.kibanaPassword -}}
{{- fail "kibana password must be defined when fleet mode is enabled and a token is not supplied" -}}
{{- end -}}
{{- end -}}
{{- if empty $.Values.agent.fleet.preset -}}
{{- fail "preset must be defined when fleet mode is enabled" -}}
{{- end -}}
{{- if not (hasKey $.Values.agent.presets $.Values.agent.fleet.preset)}}
{{- fail (printf "specified preset \"%s\" under fleet is not found" $.Values.agent.fleet.preset) -}}
{{- end -}}
{{- range $presetName, $presetVal := $.Values.agent.presets}}
{{- if ne $presetName $.Values.agent.fleet.preset -}}
{{- $_ := unset $.Values.agent.presets $presetName}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate and initialise outputs
*/}}
{{- define "elasticagent.init.outputs" -}}
{{- $ := . -}}
{{- $supportOutputTypes := dict "ESPlainAuth" "" "ESSecretAuthBasic" "" "ESSecretAuthAPI" "" "ESECKRef" ""}}
{{- range $outputName, $outputVal := $.Values.outputs -}}
{{- if empty ($outputVal).type -}}
{{- $_ := set $outputVal "type" "ESPlainAuth" -}}
{{- end -}}
{{- include (printf "elasticagent.output.%s.validate" ($outputVal).type) (list $ $outputName $outputVal)}}
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
{{- range $customInputName, $customInputVal := $.Values.extraIntegrations -}}
{{- $customInputPresetName := ($customInputVal).preset -}}
{{- $_ := required (printf "customInput \"%s\" is missing required preset field" $customInputName) $customInputPresetName -}}
{{- $presetVal := get $.Values.agent.presets $customInputPresetName -}}
{{- $_ := required (printf "preset with name \"%s\" of customInput \"%s\" not defined" $customInputPresetName $customInputName) $customInputVal -}}
{{- $customInputOuput := dig "use_output" (list) $customInputVal -}}
{{- if empty $customInputOuput -}}
{{- fail (printf "output not defined in custom integration \"%s\"" $customInputName) -}}
{{- end -}}
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
{{- $presetMode := dig "mode" ("") $presetVal -}}
{{- if not $presetMode -}}
{{- fail (printf "mode is missing from preset \"%s\"" $presetName) -}}
{{- else if eq $presetMode "deployment" -}}
{{- else if eq $presetMode "statefulset" -}}
{{- else if eq $presetMode "daemonset" -}}
{{- else -}}
{{- fail (printf "invalid mode \"%s\" in preset \"%s\", must be one of deployment, statefulset, daemonset" $presetMode $presetName) -}}
{{- end -}}
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
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "elasticagent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "elasticagent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
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
{{- $presetRules := dig "rules" (list) $preset -}}
{{- $rulesToAdd := get (include $templateName $ | fromYaml) "rules" -}}
{{- $presetRules = uniq (concat $presetRules $rulesToAdd) -}}
{{- $_ := set $preset "rules" $presetRules -}}
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
{{- if not (hasKey $.Values.outputs $outputName) -}}
{{- fail (printf "output \"%s\" is not defined" $outputName) -}}
{{- end -}}
{{- $outputDict := deepCopy (get $.Values.outputs $outputName) -}}
{{- $presetOutputs := dig "outputs" (dict) $preset -}}
{{- if not (hasKey $presetOutputs $outputName) -}}
{{- $_ := set $presetOutputs $outputName $outputDict}}
{{- end -}}
{{- $_ := set $preset "outputs" $presetOutputs -}}
{{- end -}}
