// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/pkg/component"
)

var testDiagnostics = DiagnosticsInfo{
	AgentInfo: AgentInfo{
		ID:        "test-id",
		Version:   "test-version",
		Commit:    "test-commit",
		BuildTime: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		Snapshot:  false,
	},
	ProcMeta: []client.ProcMeta{client.ProcMeta{
		Process:            "filebeat",
		Name:               "filebeat",
		Hostname:           "test-host",
		ID:                 "filebeat-id",
		EphemeralID:        "filebeat-ephemeral-id",
		Version:            "filebeat-version",
		BuildCommit:        "filebeat-commit",
		BuildTime:          time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		Username:           "test-user",
		UserID:             "1000",
		UserGID:            "1000",
		BinaryArchitecture: "test-architecture",
		RouteKey:           "test",
		ElasticLicensed:    true,
	}, client.ProcMeta{
		Process:            "filebeat",
		Name:               "filebeat_monitoring",
		Hostname:           "test-host",
		ID:                 "filebeat_monitoring-id",
		EphemeralID:        "filebeat_monitoring-ephemeral-id",
		Version:            "filebeat_monitoring-version",
		BuildCommit:        "filebeat_monitoring-commit",
		BuildTime:          time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		Username:           "test-user",
		UserID:             "1000",
		UserGID:            "1000",
		BinaryArchitecture: "test-architecture",
		RouteKey:           "test",
		ElasticLicensed:    true,
	}, client.ProcMeta{
		Name:     "metricbeat",
		RouteKey: "test",
		Error:    "failed to get metricbeat data",
	}},
}

func Example_humanDiagnosticsOutput() {
	_ = humanDiagnosticsOutput(os.Stdout, testDiagnostics)
	// Output:
	// elastic-agent  id: test-id                version: test-version
	//                build_commit: test-commit  build_time: 2021-01-01 00:00:00 +0000 UTC  snapshot_build: false
	// Applications:
	//   *  name: filebeat                        route_key: test
	//      process: filebeat                     id: filebeat-id          ephemeral_id: filebeat-ephemeral-id        elastic_license: true
	//      version: filebeat-version             commit: filebeat-commit  build_time: 2021-01-01 00:00:00 +0000 UTC  binary_arch: test-architecture
	//      hostname: test-host                   username: test-user      user_id: 1000                              user_gid: 1000
	//   *  name: filebeat_monitoring             route_key: test
	//      process: filebeat                     id: filebeat_monitoring-id          ephemeral_id: filebeat_monitoring-ephemeral-id  elastic_license: true
	//      version: filebeat_monitoring-version  commit: filebeat_monitoring-commit  build_time: 2021-01-01 00:00:00 +0000 UTC       binary_arch: test-architecture
	//      hostname: test-host                   username: test-user                 user_id: 1000                                   user_gid: 1000
	//   *  name: metricbeat                      route_key: test
	//      error: failed to get metricbeat data
}

func Test_collectEndpointSecurityLogs(t *testing.T) {
	root := filepath.Join("testdata", "diagnostics", "endpoint-security", "logs")

	specs := component.SupportedMap
	specs["endpoint-security"].ProgramSpec.LogPaths[runtime.GOOS] =
		filepath.Join(root, "endpoint-*.log")

	buff := bytes.Buffer{}

	zw := zip.NewWriter(&buff)
	err := collectEndpointSecurityLogs(zw, specs)
	assert.NoError(t, err)

	err = zw.Close()
	require.NoError(t, err)

	zr, err := zip.NewReader(
		bytes.NewReader(buff.Bytes()), int64(len(buff.Bytes())))
	require.NoError(t, err)

	assert.NotEmpty(t, zr.File, "zip file shouldn't be empty")
	for _, f := range zr.File {
		split := strings.Split(f.Name, "/")
		name := split[len(split)-1]

		wantf, err := os.Open(filepath.Join(root, name))
		require.NoError(t, err)
		want, err := io.ReadAll(wantf)
		require.NoError(t, err)

		r, err := f.Open()
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)

		assert.Equal(t, got, want)
	}
}

func Test_collectEndpointSecurityLogs_noEndpointSecurity(t *testing.T) {
	root := filepath.Join("doesNotExist")

	specs := component.SupportedMap
	specs["endpoint-security"].ProgramSpec.LogPaths["linux"] =
		filepath.Join(root, "endpoint-*.log")

	buff := bytes.Buffer{}

	zw := zip.NewWriter(&buff)
	err := collectEndpointSecurityLogs(zw, specs)
	assert.NoError(t, err, "collectEndpointSecurityLogs should not return an error")
}
