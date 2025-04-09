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
{{/* !!! init order matters !!! */}}
{{- include (printf "elasticagent.engine.%s.init" $.Values.agent.engine) $ -}}
{{/* initialise inputs to hydrate the correct presets according to what is enabled */}}
{{- include "elasticagent.init.inputs" $ -}}
{{/* initialise fleet to remove any irrelevant preset and load the certificate settings */}}
{{- include "elasticagent.init.fleet" $ -}}
{{/* initialise presets to set correctly default values in them */}}
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
{{- if $fleetPresetName -}}
{{- $fleetPresetVal := get $.Values.agent.presets $fleetPresetName -}}
{{- $_ := required (printf "preset with name \"%s\" of fleet not defined" $fleetPresetName) $fleetPresetVal -}}
{{- end -}}
{{/* disable all presets except the fleet one */}}
{{- range $presetName, $presetVal := $.Values.agent.presets}}
{{- if ne $presetName $fleetPresetName -}}
{{- $_ := unset $.Values.agent.presets $presetName}}
{{- end -}}
{{- end -}}
{{/* init any fleet-related values that derive from valueFrom schema */}}
{{- include "elasticagent.init.valueFrom" (list $ $.Values.agent.fleet.ca "fleet.ca") -}}
{{- include "elasticagent.init.valueFrom" (list $ $.Values.agent.fleet.agentCert "fleet.agentcert") -}}
{{- include "elasticagent.init.valueFrom" (list $ $.Values.agent.fleet.agentCertKey "fleet.agentcert.key") -}}
{{- include "elasticagent.init.valueFrom" (list $ $.Values.agent.fleet.kibanaCA "fleet.kibana.ca") -}}
{{- end -}}
{{- end -}}

{{/*
Initialise input templates if we are not deploying as managed
*/}}
{{- define "elasticagent.init.inputs" -}}
{{- $ := . -}}
{{/* initialise inputs of the built-in integrations, even if fleet is enabled,
 as they change the k8s configuration of presets e.g. necessary volume mounts, etc. */}}
{{- include "elasticagent.kubernetes.init" $ -}}
{{- include "elasticagent.system.init" $ -}}
{{/* initialise inputs the custom integrations only if fleet is disabled */}}
{{- if eq $.Values.agent.fleet.enabled false -}}
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
{{- include "elasticagent.presets.pernode.init" $ -}}
{{- include "elasticagent.presets.ksm.sidecar.init" $ -}}
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
{{- if empty ($presetVal).providers -}}
{{- $_ := set $presetVal "providers" dict -}}
{{- end -}}
{{- $presetProviders := get $presetVal "providers" -}}
{{- if empty ($presetProviders).kubernetes_leaderelection -}}
{{- $_ := set $presetProviders "kubernetes_leaderelection" dict -}}
{{- end -}}
{{- $presetLeaderLeaseName := (printf "%s-%s" $.Release.Name $presetName) | lower  -}}
{{/* by default we disable leader election but we also set the name of the leader lease in case it is explicitly enabled */}}
{{- $defaultLeaderElection := dict "enabled" false "leader_lease" $presetLeaderLeaseName -}}
{{- if eq $.Values.agent.fleet.enabled true -}}
{{/* for fleet mode the leader election is enabled by default */}}
{{- $_ := set $defaultLeaderElection "enabled" true -}}
{{- end -}}
{{/* merge the default leader election with the leader election from the preset giving priority to the one from the preset */}}
{{- $presetLeaderElection := mergeOverwrite dict $defaultLeaderElection ($presetProviders).kubernetes_leaderelection -}}
{{- $_ := set $presetProviders "kubernetes_leaderelection" $presetLeaderElection -}}
{{/* set a sensible default to preset.statePersistence if no value is already present in the preset */}}
{{- if empty ($presetVal).statePersistence -}}
{{- if eq ($presetMode) "daemonset" -}}
{{- $_ := set $presetVal "statePersistence" "HostPath" -}}
{{- else if eq ($presetMode) "deployment" -}}
{{- $_ := set $presetVal "statePersistence" "EmptyDir" -}}
{{- else if eq ($presetMode) "statefulset" -}}
{{- $_ := set $presetVal "statePersistence" "EmptyDir" -}}
{{- else -}}
fail printf "Unsupported mode %v for preset %v" ($presetMode) $($presetName)
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
{{- $extraVolumeMounts := list -}}
{{- $extraVolumes := list -}}
{{- $extraEnvs := list -}}
{{- if ($.Values.agent.fleet.ca)._mountPath -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "FLEET_CA" "value" ($.Values.agent.fleet.ca)._mountPath) -}}
{{- end -}}
{{- if ($.Values.agent.fleet.ca)._volume -}}
{{- $extraVolumes = append $extraVolumes ($.Values.agent.fleet.ca)._volume -}}
{{- end -}}
{{- if ($.Values.agent.fleet.ca)._volumeMount -}}
{{- $extraVolumeMounts = append $extraVolumeMounts ($.Values.agent.fleet.ca)._volumeMount -}}
{{- end -}}
{{- if ($.Values.agent.fleet.agentCert)._mountPath -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "ELASTIC_AGENT_CERT" "value" ($.Values.agent.fleet.agentCert)._mountPath) -}}
{{- end -}}
{{- if ($.Values.agent.fleet.agentCert)._volume -}}
{{- $extraVolumes = append $extraVolumes ($.Values.agent.fleet.agentCert)._volume -}}
{{- end -}}
{{- if ($.Values.agent.fleet.agentCert)._volumeMount -}}
{{- $extraVolumeMounts = append $extraVolumeMounts ($.Values.agent.fleet.agentCert)._volumeMount -}}
{{- end -}}
{{- if ($.Values.agent.fleet.agentCertKey)._mountPath -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "ELASTIC_AGENT_CERT_KEY" "value" ($.Values.agent.fleet.agentCertKey)._mountPath) -}}
{{- end -}}
{{- if ($.Values.agent.fleet.agentCertKey)._volume -}}
{{- $extraVolumes = append $extraVolumes ($.Values.agent.fleet.agentCertKey)._volume -}}
{{- end -}}
{{- if ($.Values.agent.fleet.agentCertKey)._volumeMount -}}
{{- $extraVolumeMounts = append $extraVolumeMounts ($.Values.agent.fleet.agentCertKey)._volumeMount -}}
{{- end -}}
{{- if ($.Values.agent.fleet.kibanaCA)._mountPath -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "KIBANA_FLEET_CA" "value" ($.Values.agent.fleet.kibanaCA)._mountPath) -}}
{{- end -}}
{{- if ($.Values.agent.fleet.kibanaCA)._volume -}}
{{- $extraVolumes = append $extraVolumes ($.Values.agent.fleet.kibanaCA)._volume -}}
{{- end -}}
{{- if ($.Values.agent.fleet.kibanaCA)._volumeMount -}}
{{- $extraVolumeMounts = append $extraVolumeMounts ($.Values.agent.fleet.kibanaCA)._volumeMount -}}
{{- end -}}
{{- if $.Values.agent.fleet.url -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "FLEET_URL" "value" $.Values.agent.fleet.url) -}}
{{- end -}}
{{- if $.Values.agent.fleet.token -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "FLEET_ENROLLMENT_TOKEN" "value" $.Values.agent.fleet.token) -}}
{{- end -}}
{{- if $.Values.agent.fleet.insecure -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "FLEET_INSECURE" "value" (quote $.Values.agent.fleet.insecure)) -}}
{{- end -}}
{{- if $.Values.agent.fleet.force -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "FLEET_FORCE" "value" (quote $.Values.agent.fleet.force)) -}}
{{- end -}}
{{- if $.Values.agent.fleet.tokenName -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "FLEET_TOKEN_NAME" "value" $.Values.agent.fleet.tokenName) -}}
{{- end -}}
{{- if $.Values.agent.fleet.policyName -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "FLEET_TOKEN_POLICY_NAME" "value" $.Values.agent.fleet.policyName) -}}
{{- end -}}
{{- if $.Values.agent.fleet.kibanaHost -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "KIBANA_FLEET_HOST" "value" $.Values.agent.fleet.kibanaHost) -}}
{{- end -}}
{{- if $.Values.agent.fleet.kibanaUser -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "KIBANA_FLEET_USERNAME" "value" $.Values.agent.fleet.kibanaUser) -}}
{{- end -}}
{{- if $.Values.agent.fleet.kibanaPassword -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "KIBANA_FLEET_PASSWORD" "value" $.Values.agent.fleet.kibanaPassword) -}}
{{- end -}}
{{- if $.Values.agent.fleet.kibanaServiceToken -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "KIBANA_FLEET_SERVICE_TOKEN" "value" $.Values.agent.fleet.kibanaServiceToken) -}}
{{- end -}}
{{- if $.Values.agent.fleet.enabled -}}
{{- $extraEnvs = append $extraEnvs (dict "name" "FLEET_ENROLL" "value" "true") -}}
{{- end -}}
{{- with uniq $extraVolumes -}}
{{- include "elasticagent.preset.mutate.volumes" (list $preset (dict "extraVolumes" .)) -}}
{{- end -}}
{{- with uniq $extraVolumeMounts -}}
{{- include "elasticagent.preset.mutate.volumemounts" (list $preset (dict "extraVolumeMounts" .)) -}}
{{- end -}}
{{- with uniq $extraEnvs -}}
{{- include "elasticagent.preset.mutate.envs" (list $preset (dict "extraEnvs" .)) -}}
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

{{- define "elasticagent.init.valueFrom" -}}
{{- $ := index . 0 -}}
{{- $valueFrom := index . 1 -}}
{{- $id := index . 2 -}}
{{- if ($valueFrom).value -}}
{{- $secretKey := $id -}}
{{- $mountPath := (printf "/mnt/secrets/elastic-agent/%s" $secretKey) -}}
{{- $_ := set $valueFrom "_mountPath" $mountPath -}}
{{- $_ := set $valueFrom "_key" $secretKey -}}
{{/* we don't need to define volume, this will be part of the already existing volumemount with name config */}}
{{- $_ := set $valueFrom "_volumeMount" (dict "name" "config" "mountPath" $mountPath "readOnly" true "subPath" $secretKey) -}}
{{- else if (($valueFrom).valueFromSecret).name -}}
{{/* we don't have to check valueFrom.valueFromSecret.key as values.schema.json enforces it */}}
{{- $secretName := (($valueFrom).valueFromSecret).name -}}
{{- $secretKey := (($valueFrom).valueFromSecret).key -}}
{{- $mountPath := (printf "/mnt/secrets/elastic-agent/%s.%s" $secretName $secretKey) -}}
{{- $volumeName := $secretName -}}
{{- $_ := set $valueFrom "_mountPath" $mountPath -}}
{{- $_ := set $valueFrom "_key" $secretKey -}}
{{- $_ := set $valueFrom "_volume" (dict "name" $volumeName "secret" (dict "secretName" $secretName "defaultMode" 0444)) -}}
{{- $_ := set $valueFrom "_volumeMount" (dict "name" $volumeName "mountPath" $mountPath "readOnly" true "subPath" $secretKey) -}}
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
{{- $preset := index . 0 -}}
{{- $capabilities := index . 1 -}}
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
{{- $capabilitiesAddToAdd := dig "securityContext" "capabilities" "add" (list) $capabilities -}}
{{- $presetSecurityContextCapabilitiesAdd = uniq (concat $presetSecurityContextCapabilitiesAdd $capabilitiesAddToAdd) -}}
{{- $_ := set $presetSecurityContextCapabilities "add" $presetSecurityContextCapabilitiesAdd -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.providers.kubernetes.hints" -}}
{{- $preset := index . 0 -}}
{{- $providers := index . 1 -}}
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
{{- $presetProvidersKubernetesHintsToAdd := dig "providers" "kubernetes" "hints" (dict) $providers -}}
{{- $presetProvidersKubernetesHints = merge $presetProvidersKubernetesHintsToAdd $presetProvidersKubernetesHints -}}
{{- $_ := set $presetProvidersKubernetes "hints" $presetProvidersKubernetesHints -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.annotations" -}}
{{- $ := index . 0 -}}
{{- $preset := index . 1 -}}
{{- $annotationsToAdd := index . 2 -}}
{{- $presetAnnotations := dig "annotations" (dict) $preset -}}
{{- $presetAnnotations = merge $presetAnnotations $annotationsToAdd -}}
{{- $_ := set $preset "annotations" $presetAnnotations -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.tolerations" -}}
{{- $preset := index . 0 -}}
{{- $tolerations := index . 1 -}}
{{- $tolerationsToAdd := dig "tolerations" (list) (include $tolerations $ | fromYaml) }}
{{- $presetTolerations := dig "tolerations" (list) $preset -}}
{{- $presetTolerations = uniq (concat $presetTolerations $tolerationsToAdd) -}}
{{- $_ := set $preset "tolerations" $tolerationsToAdd -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.volumes" -}}
{{- $preset := index . 0 -}}
{{- $volumes := index . 1 -}}
{{- $presetVolumes := dig "extraVolumes" (list) $preset -}}
{{- $volumesToAdd := dig "extraVolumes" (list) $volumes -}}
{{- $presetVolumes = uniq (concat $presetVolumes $volumesToAdd) -}}
{{- $_ := set $preset "extraVolumes" $presetVolumes -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.volumemounts" -}}
{{- $preset := index . 0 -}}
{{- $volumeMounts := index . 1 -}}
{{- $presetVolumeMounts := dig "extraVolumeMounts" (list) $preset -}}
{{- $volumeMountsToAdd := dig "extraVolumeMounts" (list) $volumeMounts}}
{{- $presetVolumeMounts = uniq (concat $presetVolumeMounts $volumeMountsToAdd) -}}
{{- $_ := set $preset "extraVolumeMounts" $presetVolumeMounts -}}
{{- end -}}

{{- define "elasticagent.preset.mutate.envs" -}}
{{- $preset := index . 0 -}}
{{- $envVars := index . 1 -}}
{{- $presetEnvVars := dig "extraEnvs" (list) $preset -}}
{{- $envVarsToAdd := dig "extraEnvs" (list) $envVars}}
{{- $presetEnvVars = uniq (concat $presetEnvVars $envVarsToAdd) -}}
{{- $_ := set $preset "extraEnvs" $presetEnvVars -}}
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

{{/*
Render a yaml with volumes and volumeMounts keys, rendering state volumes and extra volumes and their respective mounts
*/}}
{{- define "elasticagent.preset.render.volumes" -}}
{{- $ := index . 0 -}}
{{- $presetVal := index . 1 -}}
{{- $agentName := index . 2 -}}
volumes:
{{- $definedAgentStateVolume := false -}}
  {{- with ($presetVal).extraVolumes }}
  {{- . | toYaml | nindent 2 }}
  {{- range $idx, $volume := . -}}
  {{- if eq $definedAgentStateVolume false -}}
  {{- if eq ($volume).name "agent-data" -}}
  {{- $definedAgentStateVolume = true}}
  {{- end -}}
  {{- end -}}
  {{- end -}}
  {{- end }}
  {{- if ne ($presetVal).statePersistence "None" }}
  {{- if eq $definedAgentStateVolume false }}
  - name: agent-data
    {{- if eq ($presetVal).statePersistence "HostPath" }}
    hostPath:
      {{- if eq $.Values.agent.fleet.enabled true }}
      {{/* different state hostPath for managed agents */}}
      path: /etc/elastic-agent/{{$.Release.Namespace}}/{{$agentName}}-managed/state
      {{- else }}
      {{/* different state hostPath for standalone agents */}}
      path: /etc/elastic-agent/{{$.Release.Namespace}}/{{$agentName}}/state
      {{- end }}
      type: DirectoryOrCreate
    {{- else if eq ($presetVal).statePersistence "EmptyDir" }}
    emptyDir: {}
    {{- end }}
  {{- end }}
  {{- end }}
volumeMounts:
  {{- $definedAgentStateVolumeMount := false -}}
  {{- with ($presetVal).extraVolumeMounts }}
  {{- . | toYaml | nindent 2}}
  {{- range $idx, $volumeMount := . -}}
  {{- if eq $definedAgentStateVolumeMount false -}}
  {{- if eq ($volumeMount).name "agent-data" -}}
  {{- $definedAgentStateVolumeMount = true}}
  {{- end -}}
  {{- end -}}
  {{- end -}}
  {{- end }}
  {{- if ne ($presetVal).statePersistence "None" }}
  {{- if eq $definedAgentStateVolumeMount false }}
  - name: agent-data
    mountPath: /usr/share/elastic-agent/state
  {{- end }}
  {{- end }}
{{- end -}}
