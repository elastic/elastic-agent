{{- define "elasticagent.engine.k8s.podTemplate" }}
{{- $ := index . 0 -}}
{{- $presetVal := index . 1 -}}
{{- $agentName := index . 2 }}
    spec:
      dnsPolicy: ClusterFirstWithHostNet
      {{- if eq $.Values.agent.fleet.enabled true }}
      hostNetwork: true
      {{- end }}
      {{- with ($presetVal).hostPID }}
      hostPID: {{ . }}
      {{- end }}
      automountServiceAccountToken: true
      {{- with ($presetVal).nodeSelector }}
      nodeSelector:
        {{- . | toYaml | nindent 8 }}
      {{- end }}
      serviceAccountName: {{ $agentName }}
      {{- with ($presetVal).affinity }}
      affinity:
        {{- . | toYaml | nindent 8 }}
      {{- end }}
      {{- with ($presetVal).tolerations }}
      tolerations:
        {{- . | toYaml | nindent 8 }}
      {{- end }}
      {{- with ($presetVal).topologySpreadConstraints }}
      topologySpreadConstraints:
        {{- . | toYaml | nindent 8 }}
      {{- end }}
      volumes:
        {{- $definedAgentStateVolume := false -}}
        {{- with ($presetVal).extraVolumes }}
        {{- . | toYaml | nindent 8 }}
        {{- range $idx, $volume := . -}}
        {{- if eq $definedAgentStateVolume false -}}
        {{- if eq ($volume).name "agent-data" -}}
        {{- $definedAgentStateVolume = true}}
        {{- end -}}
        {{- end -}}
        {{- end -}}
        {{- end }}
        {{- if eq $definedAgentStateVolume false }}
        - name: agent-data
          hostPath:
            {{- if eq $.Values.agent.fleet.enabled true }}
            {{/* different state hostPath for managed agents */}}
            path: /etc/elastic-agent/{{$.Release.Namespace}}/{{$agentName}}-managed/state
            {{- else }}
            {{/* different state hostPath for standalone agents */}}
            path: /etc/elastic-agent/{{$.Release.Namespace}}/{{$agentName}}/state
            {{- end }}
            type: DirectoryOrCreate
        {{- end }}
        {{- if eq $.Values.agent.fleet.enabled false }}
        {{/* standalone mode so config is static */}}
        - name: config
          secret:
            defaultMode: 0444
            secretName: {{ $agentName }}
        {{- end }}
      {{- with ($presetVal).initContainers }}
      initContainers:
        {{- . | toYaml | nindent 8 }}
      {{- end }}
      containers:
        {{- with ($presetVal).extraContainers }}
        {{- . | toYaml | nindent 8 }}
        {{- end }}
        - name: agent
          {{- with $.Values.agent.image.pullPolicy }}
          imagePullPolicy: {{ . }}
          {{- end }}
          {{- if $.Values.agent.image.tag }}
          image: "{{ $.Values.agent.image.repository }}:{{ $.Values.agent.image.tag }}"
          {{- else }}
          image: "{{ $.Values.agent.image.repository }}:{{ $.Values.agent.version }}"
          {{- end }}
          {{- if eq $.Values.agent.fleet.enabled false }}
          args: ["-c", "/etc/elastic-agent/agent.yml", "-e"]
          {{- end }}
          {{- with ($presetVal).securityContext }}
          securityContext:
            {{- . | toYaml | nindent 12 }}
          {{- end }}
          {{- with ($presetVal).resources }}
          resources:
            {{- . | toYaml | nindent 12 }}
          {{- end }}
          volumeMounts:
            {{- $definedAgentStateVolumeMount := false -}}
            {{- with ($presetVal).extraVolumeMounts }}
            {{- . | toYaml | nindent 12 }}
            {{- range $idx, $volumeMount := . -}}
            {{- if eq $definedAgentStateVolumeMount false -}}
            {{- if eq ($volumeMount).name "agent-data" -}}
            {{- $definedAgentStateVolumeMount = true}}
            {{- end -}}
            {{- end -}}
            {{- end -}}
            {{- end }}
            {{- if eq $definedAgentStateVolumeMount false }}
            - name: agent-data
              mountPath: /usr/share/elastic-agent/state
            {{- end }}
            {{- if eq $.Values.agent.fleet.enabled false }}
            - name: config
              mountPath: /etc/elastic-agent/agent.yml
              readOnly: true
              subPath: agent.yml
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
            {{- with ($presetVal).extraEnvs }}
            {{- . | toYaml | nindent 12 }}
            {{- end }}
            {{- if eq $.Values.agent.fleet.enabled false }}
            {{- with ($presetVal).outputs }}
            {{- range $outputName, $outputVal := . -}}
            {{- (include (printf "elasticagent.output.%s.preset.envvars" ($outputVal).type) (list $ $outputName $outputVal)) | nindent 12 }}
            {{- end }}
            {{- end }}
            {{- end }}
{{- end }}
