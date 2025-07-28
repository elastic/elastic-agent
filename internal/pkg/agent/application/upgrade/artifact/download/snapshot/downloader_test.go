// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package snapshot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

func TestNonDefaultSourceURI(t *testing.T) {
	version, err := agtversion.ParseVersion("8.12.0-SNAPSHOT")
	require.NoError(t, err)

	config := artifact.Config{
		SourceURI: "localhost:1234",
	}
	sourceURI, err := snapshotURI(context.TODO(), http.DefaultClient, version, &config)
	require.NoError(t, err)
	require.Equal(t, config.SourceURI, sourceURI)

}

var agentSpec = artifact.Artifact{
	Name:     "Elastic Agent",
	Cmd:      "elastic-agent",
	Artifact: "beat/elastic-agent",
}

func readFile(t *testing.T, name string) []byte {
	bytes, err := os.ReadFile(name)
	require.NoError(t, err)

	return bytes
}

func TestDownloadVersion(t *testing.T) {
	files := map[string][]byte{
		// links for the latest snapshot
		"/latest/8.14.0-SNAPSHOT.json": readFile(t, "./testdata/latest-snapshot.json"),
		"/8.14.0-6d69ee76/downloads/beat/elastic-agent/elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz":        {},
		"/8.14.0-6d69ee76/downloads/beat/elastic-agent/elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz.sha512": {},

		// links for a specific build
		"/8.13.3-76ce1a63/downloads/beat/elastic-agent/elastic-agent-8.13.3-SNAPSHOT-linux-x86_64.tar.gz":        {},
		"/8.13.3-76ce1a63/downloads/beat/elastic-agent/elastic-agent-8.13.3-SNAPSHOT-linux-x86_64.tar.gz.sha512": {},
	}
	type fields struct {
		config *artifact.Config
	}
	type args struct {
		a       artifact.Artifact
		version *agtversion.ParsedSemVer
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "happy path snapshot version",
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(8, 14, 0, "SNAPSHOT", "")},
			want:    "elastic-agent-8.14.0-SNAPSHOT-linux-x86_64.tar.gz",
			wantErr: assert.NoError,
		},
		{
			name: "happy path snapshot version with build metadata",
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(8, 13, 3, "SNAPSHOT", "76ce1a63")},
			want:    "elastic-agent-8.13.3-SNAPSHOT-linux-x86_64.tar.gz",
			wantErr: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			targetDirPath := t.TempDir()

			handleDownload := func(rw http.ResponseWriter, req *http.Request) {
				path := req.URL.Path
				t.Logf("incoming request for %s", path)

				file, ok := files[path]
				if !ok {
					rw.WriteHeader(http.StatusNotFound)
					return
				}

				_, err := io.Copy(rw, bytes.NewReader(file))
				assert.NoError(t, err, "error writing out response body")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(handleDownload))
			defer server.Close()

			log, _ := loggertest.New("downloader")
			upgradeDetails := details.NewDetails(tt.args.version.String(), details.StateRequested, "")

			config := tt.fields.config
			config.TargetDirectory = targetDirPath
			config.SourceURI = "https://artifacts.elastic.co/downloads/"

			client := server.Client()
			transport := client.Transport.(*http.Transport)

			transport.TLSClientConfig.InsecureSkipVerify = true
			transport.DialContext = func(_ context.Context, network, s string) (net.Conn, error) {
				_ = s
				return net.Dial(network, server.Listener.Addr().String())
			}
			downloader, err := NewDownloaderWithClient(log, config, tt.args.version, client, upgradeDetails)
			require.NoError(t, err)
			got, err := downloader.Download(context.TODO(), tt.args.a, tt.args.version)

			if !tt.wantErr(t, err, fmt.Sprintf("Download(%v, %v)", tt.args.a, tt.args.version)) {
				return
			}

			assert.Equalf(t, filepath.Join(targetDirPath, tt.want), got, "Download(%v, %v)", tt.args.a, tt.args.version)
		})
	}

}
