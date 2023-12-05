// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package snapshot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

func TestNonDefaultSourceURI(t *testing.T) {
	version, err := agtversion.ParseVersion("8.12.0-SNAPSHOT")
	require.NoError(t, err)

	config := artifact.Config{
		SourceURI: "localhost:1234",
	}
	sourceURI, err := snapshotURI(http.DefaultClient, version, &config)
	require.NoError(t, err)
	require.Equal(t, config.SourceURI, sourceURI)

}

const artifactAPIElasticAgentSearchResponse = `
{
  "packages": {
    "elastic-agent-1.2.3-SNAPSHOT-darwin-aarch64.tar.gz": {
      "url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-darwin-aarch64.tar.gz",
      "sha_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-darwin-aarch64.tar.gz.sha512",
      "asc_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-darwin-aarch64.tar.gz.asc",
      "type": "tar",
      "architecture": "aarch64",
      "os": [
        "darwin"
      ]
    },
    "elastic-agent-1.2.3-SNAPSHOT-windows-x86_64.zip": {
      "url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-windows-x86_64.zip",
      "sha_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-windows-x86_64.zip.sha512",
      "asc_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-windows-x86_64.zip.asc",
      "type": "zip",
      "architecture": "x86_64",
      "os": [
        "windows"
      ]
    },
    "elastic-agent-core-1.2.3-SNAPSHOT-linux-arm64.tar.gz": {
      "url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/elastic-agent-core/elastic-agent-core-1.2.3-SNAPSHOT-linux-arm64.tar.gz",
      "sha_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/elastic-agent-core/elastic-agent-core-1.2.3-SNAPSHOT-linux-arm64.tar.gz.sha512",
      "asc_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/elastic-agent-core/elastic-agent-core-1.2.3-SNAPSHOT-linux-arm64.tar.gz.asc",
      "type": "tar",
      "architecture": "arm64",
      "os": [
        "linux"
      ]
    },
    "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz": {
      "url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz",
      "sha_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.sha512",
      "asc_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.asc",
      "type": "tar",
      "architecture": "x86_64",
      "os": [
        "linux"
      ]
    },
    "elastic-agent-1.2.3-SNAPSHOT-linux-arm64.tar.gz": {
      "url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-arm64.tar.gz",
      "sha_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-arm64.tar.gz.sha512",
      "asc_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-arm64.tar.gz.asc",
      "type": "tar",
      "architecture": "arm64",
      "os": [
        "linux"
      ]
    },
    "elastic-agent-1.2.3-SNAPSHOT-darwin-x86_64.tar.gz": {
      "url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-darwin-x86_64.tar.gz",
      "sha_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-darwin-x86_64.tar.gz.sha512",
      "asc_url": "https://snapshots.elastic.co/1.2.3-33e8d7e1/downloads/beats/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-darwin-x86_64.tar.gz.asc",
      "type": "tar",
      "architecture": "x86_64",
      "os": [
        "darwin"
      ]
    }
  },
  "manifests": {
    "last-update-time": "Tue, 05 Dec 2023 15:47:06 UTC",
    "seconds-since-last-update": 201
  }
}
`

var agentSpec = artifact.Artifact{
	Name:     "Elastic Agent",
	Cmd:      "elastic-agent",
	Artifact: "beat/elastic-agent",
}

type downloadHttpResponse struct {
	statusCode int
	headers    http.Header
	Body       []byte
}

func TestDownloadVersion(t *testing.T) {

	type fields struct {
		config *artifact.Config
	}
	type args struct {
		a       artifact.Artifact
		version *agtversion.ParsedSemVer
	}
	tests := []struct {
		name    string
		files   map[string]downloadHttpResponse
		fields  fields
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "happy path snapshot version",
			files: map[string]downloadHttpResponse{
				"/1.2.3-33e8d7e1/downloads/beat/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz": {
					statusCode: http.StatusOK,
					Body:       []byte("This is a fake linux elastic agent archive"),
				},
				"/1.2.3-33e8d7e1/downloads/beat/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.sha512": {
					statusCode: http.StatusOK,
					Body:       []byte("somesha512 elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz"),
				},
				"/v1/search/1.2.3-SNAPSHOT/elastic-agent": {
					statusCode: http.StatusOK,
					headers:    map[string][]string{"Content-Type": {"application/json"}},
					Body:       []byte(artifactAPIElasticAgentSearchResponse),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")},
			want:    "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz",
			wantErr: assert.NoError,
		},
		{
			name: "happy path snapshot version with build metadata",
			files: map[string]downloadHttpResponse{
				"/1.2.3-buildid/downloads/beat/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz": {
					statusCode: http.StatusOK,
					Body:       []byte("This is a fake linux elastic agent archive"),
				},
				"/1.2.3-buildid/downloads/beat/elastic-agent/elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz.sha512": {
					statusCode: http.StatusOK,
					Body:       []byte("somesha512 elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz"),
				},
			},
			fields: fields{
				config: &artifact.Config{
					OperatingSystem: "linux",
					Architecture:    "64",
				},
			},
			args:    args{a: agentSpec, version: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "buildid")},
			want:    "elastic-agent-1.2.3-SNAPSHOT-linux-x86_64.tar.gz",
			wantErr: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			targetDirPath := t.TempDir()

			handleDownload := func(rw http.ResponseWriter, req *http.Request) {
				path := req.URL.Path

				resp, ok := tt.files[path]
				if !ok {
					rw.WriteHeader(http.StatusNotFound)
					return
				}

				for k, values := range resp.headers {
					for _, v := range values {
						rw.Header().Set(k, v)
					}
				}

				rw.WriteHeader(resp.statusCode)
				_, err := io.Copy(rw, bytes.NewReader(resp.Body))
				assert.NoError(t, err, "error writing out response body")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(handleDownload))
			defer server.Close()

			log, _ := logger.NewTesting("downloader")
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
