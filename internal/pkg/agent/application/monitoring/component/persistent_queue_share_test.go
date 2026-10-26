// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths/pathstest"
	monitoringcfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
)

const sharedQueueSpecPlatforms = "[linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64, container/amd64, container/arm64]"

func sharedQueueSpec(binary string, inputs ...string) string {
	var b strings.Builder
	b.WriteString("version: 2\ninputs:\n")
	for _, in := range inputs {
		fmt.Fprintf(&b, "  - name: %s\n    description: test\n    platforms: %s\n    outputs: [elasticsearch]\n    command:\n      name: %s\n", in, sharedQueueSpecPlatforms, binary)
	}
	return b.String()
}

const sharedQueuePolicy = `
outputs:
  default:
    type: elasticsearch
    hosts: ["localhost:9200"]
    api_key: id:key
    preset: balanced
    queue:
      persistent:
        file_storage:
          max_size: 10485760
  other:
    type: elasticsearch
    hosts: ["localhost:9201"]
    api_key: id:key
    preset: balanced
    queue:
      persistent:
        file_storage:
          max_size: 10485760
inputs:
  - id: logfile-nginx
    type: filestream
    use_output: %s
    streams:
      - id: logfile-nginx.access
        data_stream:
          dataset: nginx.access
          type: logs
        paths: [/var/log/nginx/access.log*]
agent:
  monitoring:
    enabled: true
    use_output: %s
    logs: true
    metrics: true
    namespace: default
`

func queueExtensionsAndExporters(t *testing.T, policyYAML string) (fileStorage map[string]map[string]any, exporters []string) {
	t.Helper()
	pathstest.SetTop(t, t.TempDir())

	specDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(specDir, "filebeat.spec.yml"), []byte(sharedQueueSpec("filebeat", "filestream")), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(specDir, "metricbeat.spec.yml"), []byte(sharedQueueSpec("metricbeat", "beat/metrics", "http/metrics")), 0o600))

	platform, err := component.LoadPlatformDetail()
	require.NoError(t, err)
	specs, err := component.LoadRuntimeSpecs(specDir, platform, component.SkipBinaryCheck())
	require.NoError(t, err)

	var policy map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(policyYAML), &policy))
	require.NoError(t, translate.RejectReservedOutputKeys(policy))

	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err)
	monCfg := monitoringcfg.DefaultConfig()
	monCfg.UseOutput = policy["agent"].(map[string]any)["monitoring"].(map[string]any)["use_output"].(string)
	monCfg.RuntimeManager = monitoringcfg.OtelRuntimeManager
	mon := New(true, platform.OS, monCfg, agentInfo, logp.NewNopLogger())

	forceOtel := func(comps []component.Component, _ map[string]any) ([]component.Component, error) {
		for i := range comps {
			comps[i].RuntimeManager = component.OtelRuntimeManager
		}
		return comps, nil
	}
	comps, err := specs.ToComponents(policy, component.DefaultRuntimeConfig(), []component.ComponentsModifier{forceOtel},
		mon.MonitoringConfig, logp.InfoLevel, nil, map[string]uint64{}, map[string]bool{})
	require.NoError(t, err)

	outputs := map[string]bool{}
	for _, c := range comps {
		require.NoError(t, c.Err, c.ID)
		outputs[c.OutputName] = true
	}
	require.True(t, outputs[MonitoringOutput], "monitoring components expected")

	conf, err := translate.GetOtelConfig(&component.Model{Components: comps}, logp.NewNopLogger())
	require.NoError(t, err)
	require.NotNil(t, conf)

	for id := range conf.ToStringMap()["exporters"].(map[string]any) {
		exporters = append(exporters, id)
	}
	got := map[string]map[string]any{}
	exts, _ := conf.ToStringMap()["extensions"].(map[string]any)
	for id, cfg := range exts {
		if strings.HasPrefix(id, translate.FileStorageExtensionType+"/") {
			got[id] = cfg.(map[string]any)
		}
	}
	return got, exporters
}

func TestMonitoringAndInputShareFileStorageSameUseOutput(t *testing.T) {
	exts, exporters := queueExtensionsAndExporters(t, fmt.Sprintf(sharedQueuePolicy, "default", "default"))
	require.Len(t, exporters, 2)
	require.Len(t, exts, 1)
	for id, cfg := range exts {
		require.True(t, strings.HasSuffix(id, "/_agent-component/default"), id)
		require.Equal(t, filepath.Join(paths.Data(), "exporter-queue", "default"), cfg["directory"])
	}
}

func TestMonitoringAndInputUniqueFileStorageDifferentUseOutput(t *testing.T) {
	exts, exporters := queueExtensionsAndExporters(t, fmt.Sprintf(sharedQueuePolicy, "default", "other"))
	require.Len(t, exporters, 2)
	require.Len(t, exts, 2)
	dirs := map[string]bool{}
	for _, cfg := range exts {
		dirs[cfg["directory"].(string)] = true
	}
	require.Len(t, dirs, 2)
	require.True(t, dirs[filepath.Join(paths.Data(), "exporter-queue", "default")])
	require.True(t, dirs[filepath.Join(paths.Data(), "exporter-queue", "other")])
}
