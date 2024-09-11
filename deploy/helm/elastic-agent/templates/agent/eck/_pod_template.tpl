{{- define "elasticagent.engine.eck.podTemplate" }}
{{- $ := index . 0 -}}
{{- $presetVal := index . 1 -}}
{{- $agentName := index . 2 }}
      spec:
        dnsPolicy: ClusterFirstWithHostNet
        {{- with ($presetVal).hostPID }}
        hostPID: {{ . }}
        {{- end }}
        automountServiceAccountToken: true
        {{- with ($presetVal).nodeSelector }}
        nodeSelector:
          {{- . | toYaml | nindent 10 }}
        {{- end }}
        serviceAccountName: {{ $agentName }}
        {{- with ($presetVal).affinity }}
        affinity:
          {{- . | toYaml | nindent 10 }}
        {{- end }}
        {{- with ($presetVal).tolerations }}
        tolerations:
          {{- . | toYaml | nindent 10 }}
        {{- end }}
        {{- with ($presetVal).topologySpreadConstraints }}
        topologySpreadConstraints:
          {{- . | toYaml | nindent 10 }}
        {{- end }}
        volumes:
          {{- with ($presetVal).extraVolumes }}
          {{- . | toYaml | nindent 10 }}
          {{- end }}
        {{- with ($presetVal).initContainers }}
        initContainers:
          {{- . | toYaml | nindent 10 }}
        {{- end }}
        containers:
          {{- with ($presetVal).extraContainers }}
          {{- . | toYaml | nindent 10 }}
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
            {{- with ($presetVal).securityContext }}
            securityContext:
              {{- . | toYaml | nindent 14 }}
            {{- end }}
            {{- with ($presetVal).resources }}
            resources:
              {{- . | toYaml | nindent 14 }}
            {{- end }}
            volumeMounts:
              {{- with ($presetVal).extraVolumeMounts }}
              {{- . | toYaml | nindent 14 }}
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
              {{- . | toYaml | nindent 14 }}
              {{- end }}
              {{- if eq $.Values.agent.fleet.enabled false }}
              {{- with ($presetVal).outputs }}
              {{- range $outputName, $outputVal := . -}}
              {{- (include (printf "elasticagent.output.%s.preset.envvars" ($outputVal).type) (list $ $outputName $outputVal)) | nindent 14 }}
              {{- end }}
              {{- end }}
              {{- end }}
{{- end }}
