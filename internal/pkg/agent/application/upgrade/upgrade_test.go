// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"crypto/tls"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/composed"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/fs"
	httpDownloader "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	version "github.com/elastic/elastic-agent/pkg/version"
	mockinfo "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/application/info"
	currentagtversion "github.com/elastic/elastic-agent/version"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	mocks "github.com/elastic/elastic-agent/testing/mocks/pkg/control/v2/client"
)

func TestShutdownCallback(t *testing.T) {
	type testcase struct {
		name                  string
		agentHomeDirectory    string
		newAgentHomeDirectory string
		agentVersion          string
		newAgentVersion       string
		oldRunFile            string
		newRunFile            string
	}

	testcases := []testcase{
		{
			name:                  "legacy run directories",
			agentHomeDirectory:    fmt.Sprintf("%s-%s", agentName, release.ShortCommit()),
			newAgentHomeDirectory: fmt.Sprintf("%s-%s", agentName, "abc123"),
			agentVersion:          "7.14.0",
			newAgentVersion:       "7.15.0",
			oldRunFile:            filepath.Join("run", "default", "process-7.14.0", "file.test"),
			newRunFile:            filepath.Join("run", "default", "process-7.15.0", "file.test"),
		},
		{
			name:                  "new run directories",
			agentHomeDirectory:    "elastic-agent-abcdef",
			newAgentHomeDirectory: "elastic-agent-ghijkl",
			agentVersion:          "1.2.3",
			newAgentVersion:       "4.5.6",
			oldRunFile:            filepath.Join("run", "component", "unit", "file.test"),
			newRunFile:            filepath.Join("run", "component", "unit", "file.test"),
		},
		{
			name:                  "new run directories, agents with version in path",
			agentHomeDirectory:    "elastic-agent-1.2.3-abcdef",
			newAgentHomeDirectory: "elastic-agent-4.5.6-ghijkl",
			agentVersion:          "1.2.3",
			newAgentVersion:       "4.5.6",
			oldRunFile:            filepath.Join("run", "component", "unit", "file.test"),
			newRunFile:            filepath.Join("run", "component", "unit", "file.test"),
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			l, _ := logger.New(tt.name, false)
			tmpDir := t.TempDir()

			// make homepath agent consistent
			homePath := filepath.Join(tmpDir, tt.agentHomeDirectory)
			newHome := filepath.Join(tmpDir, tt.newAgentHomeDirectory)

			content := []byte("content")
			sourceDir := filepath.Join(homePath, filepath.Dir(tt.oldRunFile))
			targetDir := filepath.Join(newHome, filepath.Dir(tt.newRunFile))

			require.NoError(t, os.MkdirAll(sourceDir, 0755))
			require.NoError(t, os.MkdirAll(targetDir, 0755))

			cb := shutdownCallback(l, homePath, tt.agentVersion, tt.newAgentVersion, newHome)

			oldFilename := filepath.Join(homePath, tt.oldRunFile)
			err := os.WriteFile(oldFilename, content, 0640)
			require.NoError(t, err, "preparing file failed")

			err = cb()
			require.NoError(t, err, "callback failed")

			newFilename := filepath.Join(newHome, tt.newRunFile)
			newContent, err := os.ReadFile(newFilename)
			require.NoError(t, err, "reading file failed")
			require.Equal(t, content, newContent, "contents are not equal")
		})
	}
}

func TestIsInProgress(t *testing.T) {
	tests := map[string]struct {
		state              cproto.State
		stateErr           string
		watcherPIDsFetcher func() ([]int, error)

		expected    bool
		expectedErr string
	}{
		"state_error": {
			state:              cproto.State_STARTING,
			stateErr:           "some error",
			watcherPIDsFetcher: func() ([]int, error) { return nil, nil },

			expected:    false,
			expectedErr: "failed to get agent state: some error",
		},
		"state_upgrading": {
			state:              cproto.State_UPGRADING,
			stateErr:           "",
			watcherPIDsFetcher: func() ([]int, error) { return nil, nil },

			expected:    true,
			expectedErr: "",
		},
		"state_healthy_no_watcher": {
			state:              cproto.State_HEALTHY,
			stateErr:           "",
			watcherPIDsFetcher: func() ([]int, error) { return []int{}, nil },

			expected:    false,
			expectedErr: "",
		},
		"state_healthy_with_watcher": {
			state:              cproto.State_HEALTHY,
			stateErr:           "",
			watcherPIDsFetcher: func() ([]int, error) { return []int{9999}, nil },

			expected:    true,
			expectedErr: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Expect client.State() call to be made only if no Upgrade Watcher PIDs
			// are returned (i.e. no Upgrade Watcher is found to be running).
			mc := mocks.NewClient(t)
			if test.watcherPIDsFetcher != nil {
				pids, _ := test.watcherPIDsFetcher()
				if len(pids) == 0 {
					if test.stateErr != "" {
						mc.EXPECT().State(context.Background()).Return(nil, errors.New(test.stateErr)).Once()
					} else {
						mc.EXPECT().State(context.Background()).Return(&client.AgentState{State: test.state}, nil).Once()
					}
				}
			}

			inProgress, err := IsInProgress(mc, test.watcherPIDsFetcher)
			if test.expectedErr != "" {
				require.Equal(t, test.expectedErr, err.Error())
			} else {
				require.Equal(t, test.expected, inProgress)
			}
		})
	}
}

// TestUpgraderReload ensures the download configs (artifact.Config) are all
// applied. However, as of today, most of them cannot be set through Fleet UI.
func TestUpgraderReload(t *testing.T) {
	// if needed to regenerate the certificates, use the `elasticsearch-certgen`
	// that is included with Elasticsearch. Just run it, and it generates the CA
	// and a certificate from that CA and the keys.
	cfgyaml, want := prepareTestUpgraderReload()

	log, _ := loggertest.New("")
	u := Upgrader{
		log:      log,
		settings: artifact.DefaultConfig(),
	}

	err := u.Reload(config.MustNewConfigFrom(cfgyaml))
	require.NoError(t, err, "error reloading config")

	assert.Equal(t, &want, u.settings)
}

func TestUpgraderAckAction(t *testing.T) {
	log, _ := loggertest.New("")
	u := Upgrader{
		log:      log,
		settings: artifact.DefaultConfig(),
	}

	action := fleetapi.NewAction(fleetapi.ActionTypeUpgrade)
	t.Run("AckAction without acker", func(t *testing.T) {
		require.Nil(t, u.AckAction(t.Context(), nil, action))
	})
	t.Run("AckAction with acker", func(t *testing.T) {
		acker := &fakeAcker{}
		acker.On("Ack", mock.Anything, action).Return(nil)
		acker.On("Commit", mock.Anything).Return(nil)

		require.Nil(t, u.AckAction(t.Context(), acker, action))
		acker.AssertCalled(t, "Ack", mock.Anything, action)
		acker.AssertCalled(t, "Commit", mock.Anything)
	})

	t.Run("AckAction with acker - failing commit", func(t *testing.T) {
		acker := &fakeAcker{}

		errCommit := errors.New("failed commit")
		acker.On("Ack", mock.Anything, action).Return(nil)
		acker.On("Commit", mock.Anything).Return(errCommit)

		require.ErrorIs(t, u.AckAction(t.Context(), acker, action), errCommit)
		acker.AssertCalled(t, "Ack", mock.Anything, action)
		acker.AssertCalled(t, "Commit", mock.Anything)
	})

	t.Run("AckAction with acker - failed ack", func(t *testing.T) {
		acker := &fakeAcker{}

		errAck := errors.New("ack error")
		acker.On("Ack", mock.Anything, action).Return(errAck)
		acker.On("Commit", mock.Anything).Return(nil)

		require.ErrorIs(t, u.AckAction(t.Context(), acker, action), errAck)
		acker.AssertCalled(t, "Ack", mock.Anything, action)
		acker.AssertNotCalled(t, "Commit", mock.Anything)
	})
}

func prepareTestUpgraderReload() (string, artifact.Config) {
	cfgyaml := `
agent.download:
  source_uri: "https://tardis.elastic.co/downloads/"
  target_directory: "/tardis"
  install_path: "/sonic_screwdriver"
  drop_path: "/gallifrey"
  retry_sleep_init_duration: 10s
  timeout: 30s
  proxy_url: "http://trenzalore:1234"
  proxy_headers:
    title: "Doctor"
    name: "The Doctor"
    intention: "fun"
  ssl:
    enabled: true
    verification_mode: full
    supported_protocols:
      - "TLSv1.3"
    cipher_suites:
      - "TLS-AES-128-GCM-SHA256"
    ca_trusted_fingerprint: "TARD1S-R0S3-TR4V3LS-TH3-WH0L3-UN1V3RS3"
    renegotiation: "never"
    ca_sha256: "6effba339778083ddc39c332b6724a0665462439f6419839c9bb8a7b6639b1cd"
    key: |
      -----BEGIN RSA PRIVATE KEY-----
      MIIEpAIBAAKCAQEAsO3dq2k4ovARfgK+xZ18wv3u4u0OjXONL7YoNL0zLxPPp0hY
      uNisNN57KW6Lba1vSiu7Y02lQ4/JbVIlVds/7FOBPaN1n61rJ6KFGK14PpepjuVr
      zNuLxHawUREBi5oeVEzgkmOHDxxABRjmnbYr67PYhUM9xoLykuxiWtBXYU7WIIg/
      C1TS6gq+18jqEF0VhXRbl0lU27Edf7Jv4LJHXF2HRKpwAmk8VEV0y9N7i2MyiQ3H
      luSTMtgAzAbKC3i7iqYvP3inUnQIAR+2DV/NuZub16GvxNjZKUX2TTRbcd8sM+p4
      Z6cG1TtuwVFJyAmx/kV3LipzviDpxZFM+kgAPQIDAQABAoIBADNXApC/uqCFOv4u
      u77KIS7P0qbklOl000459FbBY/3QKNxowN36eZXpzSFLo4fS4M1L/Vcma8M8EP34
      7T6JnXXtET6alQIdp09b+HUduRuolJoTdoF+X4NF0YnkfmdM9GoP2MaBvOokj2sr
      O5geCYaerECXL3DQBKWflDa35/MjGiY7lbtFlv4vqMh5LhfZpDAxnkNzbDw716Iq
      ZYE2+Rq+l2dK3uNB1tnRSG7fUhNCp/JcQy+9I+bZTY3wFDo23vqeYyR+BhB/byt+
      BFe0IR8+1VgIbE00ecXE/tZ8V1SBMQrJ8avkKLcXYdJdWw1hnAtPMuBDNbvTATKe
      5hdSDN0CgYEA6mzW3ISfaDzrCwW3e1oWpYW+SjeYRaRJLfZwy/arbwp0bQGzrOix
      nVk8g1MsVSUMQ5yoL9/xVnLLKaa5qRLp5sfeRrg+0gKDd1fU+jM9a5UTicbZQGOh
      3aOxtmeekmeh4s670KHZx7KKSsVZH+6bIx4J58zF7UjmcEVjDxGmXZ8CgYEAwTZl
      QoC9ptNtSEKig69RrW0yg7rAGa5Fb29h+sYePK4nX8dvrBDc+cHOxao/uZTd20Tq
      8yHzy0g9IqYX/lSGyrmweY1V03KR3e6d6l2l7s/RakSdB75b3iG5SbC+6cD80zPK
      q2jWg3ajLphuf8dNuC1kOaaHzuhzOoTL8uXDHKMCgYEAoNFfqNH2hUzdNaeLUrzf
      sleIzmNLO+NTLIvWn6Wtv7RdYHZ9a04KotYX9EN3s0WCH1P18Tng1xxTEVTGIx3N
      hjtw2fUFa46734BKpAXIyefwCmF2onx3C5SDko2NNASSAwUtxRdzTlLGGjs+Q/Ct
      Tq8JvpI06e5L35NKPIkwJyMCgYBsHsZ3epemfXYQE8nhqwAn7o1wDddmB5GvlELe
      FHPjPQmnnXEudplR4lSVZHoYneewxlY8DGni/d/IPe37Us3DMDpDKwY2N0zNRrRz
      7Efo5b6omxDMvoemPHT1ecS8BlT002y8kwRHuOIENyTOuHcTc8M8R6aD8KxauOlw
      WYbfxQKBgQDUyPtbfRS5Ns87ix7+3LAQ9W0gtVOIoFl3ysk/JzRDZyxzaX+AhWdC
      IBO3yO2fxXIweDJBnL4TOanJK1NRJsXgGJnp0n8SRwECrtI7Jb3nmRgZEiiwNdr7
      FaZ3yM1rwmTiI90woe9kq8jEcP7Ew07naoCTlEDxTSgSqh4lKuUNCw==
      -----END RSA PRIVATE KEY-----
    certificate: |
      -----BEGIN CERTIFICATE-----
      MIIDQzCCAiugAwIBAgIVAJtAaYlLhZ/4qmigwOyX79az1ZZ3MA0GCSqGSIb3DQEB
      CwUAMDQxMjAwBgNVBAMTKUVsYXN0aWMgQ2VydGlmaWNhdGUgVG9vbCBBdXRvZ2Vu
      ZXJhdGVkIENBMB4XDTIzMTIyMDE1MTcwMloXDTI2MTIxOTE1MTcwMlowDzENMAsG
      A1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDt3atp
      OKLwEX4CvsWdfML97uLtDo1zjS+2KDS9My8Tz6dIWLjYrDTeeylui22tb0oru2NN
      pUOPyW1SJVXbP+xTgT2jdZ+tayeihRiteD6XqY7la8zbi8R2sFERAYuaHlRM4JJj
      hw8cQAUY5p22K+uz2IVDPcaC8pLsYlrQV2FO1iCIPwtU0uoKvtfI6hBdFYV0W5dJ
      VNuxHX+yb+CyR1xdh0SqcAJpPFRFdMvTe4tjMokNx5bkkzLYAMwGygt4u4qmLz94
      p1J0CAEftg1fzbmbm9ehr8TY2SlF9k00W3HfLDPqeGenBtU7bsFRScgJsf5Fdy4q
      c74g6cWRTPpIAD0CAwEAAaNxMG8wHQYDVR0OBBYEFNlPsDNseQ9Tg2iyKxPgwAgC
      0gW+MB8GA1UdIwQYMBaAFGxEf+I5mhWGioGsimjMWMWbu4OAMCIGA1UdEQQbMBmH
      BMCoAQCCEXRhcmRpcy5lbGFzdGljLmNvMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEL
      BQADggEBAD7CAOwaJrt0Au6yEZd4LHY03c8N3bq3Gcn+31YFemyvlHJTVHHzmzEG
      i3pU2JJDjefmHtsyXNnlzVwAcLd0lDtmiV5Baiuq/3C8zlwsln5aOAfJy94WDvfr
      ZSjSN6pPCDMRIc55MRGsy1hHNtMml1R3NdH5H6uuEBKaVJIT3GbvdCdS3n6Gy7Go
      supbBlTxw20eOWOW5NVBhQuix+Lul6QtORTqdV+0Ijyd+c5IoXbBMc34N9sjrDY7
      Uoyv095FS6hLVdVFeTy8kO7DgZUItrzjZiXATcXku0H9TAeccX6BGXgtDLPn93gd
      Ef23lo+PtLfG7fz1TF9Yz11A5uEjZds=
      -----END CERTIFICATE-----
    certificate_authorities:
    - |
      -----BEGIN CERTIFICATE-----
      MIIDSTCCAjGgAwIBAgIUMFzXUvzMd/dsDoDjQ7/6nPBPNqEwDQYJKoZIhvcNAQEL
      BQAwNDEyMDAGA1UEAxMpRWxhc3RpYyBDZXJ0aWZpY2F0ZSBUb29sIEF1dG9nZW5l
      cmF0ZWQgQ0EwHhcNMjMxMjIwMTUxNjI5WhcNMjYxMjE5MTUxNjI5WjA0MTIwMAYD
      VQQDEylFbGFzdGljIENlcnRpZmljYXRlIFRvb2wgQXV0b2dlbmVyYXRlZCBDQTCC
      ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOiP+ezLKtkQ2kDSCs/+EDiK
      qjTgLKl+suJUPDhrzpGZdGmbwE0tKCT9H9aq+nHk56gEYRJ+kiFvb5vJPVj9ExaF
      +TbuGBDrUqeVVSxNwkMlwCK7t2h+MmHmcwZqxDvqT56+lEHMHdd9UMEupgwS5c70
      ykidWwg01LS7nAsVpx5NjsP7zFZcd4jYwhibvasMyPeT9Vn5CDFi1vxcJ7ejmqNf
      aR/fYAZfLGMaIo8r1SBBuWpUAx6+VD0JXb5joxGmGy3SLaCyd7lhv8Xdc+B/A7BQ
      Xq/qtrq9OIqSRVkv7CAJZaMJ/4GyY2h8JtqL6SAnbOUIWywAL9Diq5eoy/HuRfUC
      AwEAAaNTMFEwHQYDVR0OBBYEFGxEf+I5mhWGioGsimjMWMWbu4OAMB8GA1UdIwQY
      MBaAFGxEf+I5mhWGioGsimjMWMWbu4OAMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
      hvcNAQELBQADggEBAKiHmVxUSk+y1LwVRQ2YFgzOFX3EbTVMom8QOsXvuU/2weXi
      h3Ij3u1Fw+do5PGbbKcYsGa4OdX263rW/h//VScWHDjxofvbRlIa5s0j1RVY5QvE
      x354x/EcHVrT4gKL4UAqfGNSrF0AmoeQGSTfre7FpxUq/+G7R0/97dyqKmeZd+o2
      CMfYKYerkyTtH2k4wQXVUQCGo3O2dMGpBakUCH0pXR3bOq8Xszcpz9DI86522I3U
      Moylz3f/lBMBLKFUD19ZzS4Z8c31iZPFXkN+KCjW8B7hNv6qKDSvQo74yvA0NYkv
      ncHUVm1hDPg8p7GUVgwd2m6M7uidGjTtSH1wjZ4=
      -----END CERTIFICATE-----
  proxy_disable: false
  idle_connection_timeout: 15s`

	enabled := true
	want := artifact.Config{
		SourceURI:              "https://tardis.elastic.co/downloads/",
		TargetDirectory:        "/tardis",
		InstallPath:            "/sonic_screwdriver",
		DropPath:               "/gallifrey",
		RetrySleepInitDuration: 10 * time.Second,

		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			TLS: &tlscommon.Config{
				Enabled:          &enabled,
				VerificationMode: tlscommon.VerifyFull,
				Versions:         []tlscommon.TLSVersion{tlscommon.TLSVersionMax},
				CipherSuites: []tlscommon.CipherSuite{
					tlscommon.CipherSuite(tls.TLS_AES_128_GCM_SHA256),
				}, // "RSA-AES-256-GCM-SHA384"
				CATrustedFingerprint: "TARD1S-R0S3-TR4V3LS-TH3-WH0L3-UN1V3RS3",
				Renegotiation:        tlscommon.TLSRenegotiationSupport(tls.RenegotiateNever),
				// CurveTypes:           tls.CurveP521, // it's defined as a private type
				CASha256: []string{"6effba339778083ddc39c332b6724a0665462439f6419839c9bb8a7b6639b1cd"},
				CAs: []string{`-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUMFzXUvzMd/dsDoDjQ7/6nPBPNqEwDQYJKoZIhvcNAQEL
BQAwNDEyMDAGA1UEAxMpRWxhc3RpYyBDZXJ0aWZpY2F0ZSBUb29sIEF1dG9nZW5l
cmF0ZWQgQ0EwHhcNMjMxMjIwMTUxNjI5WhcNMjYxMjE5MTUxNjI5WjA0MTIwMAYD
VQQDEylFbGFzdGljIENlcnRpZmljYXRlIFRvb2wgQXV0b2dlbmVyYXRlZCBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOiP+ezLKtkQ2kDSCs/+EDiK
qjTgLKl+suJUPDhrzpGZdGmbwE0tKCT9H9aq+nHk56gEYRJ+kiFvb5vJPVj9ExaF
+TbuGBDrUqeVVSxNwkMlwCK7t2h+MmHmcwZqxDvqT56+lEHMHdd9UMEupgwS5c70
ykidWwg01LS7nAsVpx5NjsP7zFZcd4jYwhibvasMyPeT9Vn5CDFi1vxcJ7ejmqNf
aR/fYAZfLGMaIo8r1SBBuWpUAx6+VD0JXb5joxGmGy3SLaCyd7lhv8Xdc+B/A7BQ
Xq/qtrq9OIqSRVkv7CAJZaMJ/4GyY2h8JtqL6SAnbOUIWywAL9Diq5eoy/HuRfUC
AwEAAaNTMFEwHQYDVR0OBBYEFGxEf+I5mhWGioGsimjMWMWbu4OAMB8GA1UdIwQY
MBaAFGxEf+I5mhWGioGsimjMWMWbu4OAMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAKiHmVxUSk+y1LwVRQ2YFgzOFX3EbTVMom8QOsXvuU/2weXi
h3Ij3u1Fw+do5PGbbKcYsGa4OdX263rW/h//VScWHDjxofvbRlIa5s0j1RVY5QvE
x354x/EcHVrT4gKL4UAqfGNSrF0AmoeQGSTfre7FpxUq/+G7R0/97dyqKmeZd+o2
CMfYKYerkyTtH2k4wQXVUQCGo3O2dMGpBakUCH0pXR3bOq8Xszcpz9DI86522I3U
Moylz3f/lBMBLKFUD19ZzS4Z8c31iZPFXkN+KCjW8B7hNv6qKDSvQo74yvA0NYkv
ncHUVm1hDPg8p7GUVgwd2m6M7uidGjTtSH1wjZ4=
-----END CERTIFICATE-----
`},
				Certificate: tlscommon.CertificateConfig{
					Certificate: `-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIVAJtAaYlLhZ/4qmigwOyX79az1ZZ3MA0GCSqGSIb3DQEB
CwUAMDQxMjAwBgNVBAMTKUVsYXN0aWMgQ2VydGlmaWNhdGUgVG9vbCBBdXRvZ2Vu
ZXJhdGVkIENBMB4XDTIzMTIyMDE1MTcwMloXDTI2MTIxOTE1MTcwMlowDzENMAsG
A1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALDt3atp
OKLwEX4CvsWdfML97uLtDo1zjS+2KDS9My8Tz6dIWLjYrDTeeylui22tb0oru2NN
pUOPyW1SJVXbP+xTgT2jdZ+tayeihRiteD6XqY7la8zbi8R2sFERAYuaHlRM4JJj
hw8cQAUY5p22K+uz2IVDPcaC8pLsYlrQV2FO1iCIPwtU0uoKvtfI6hBdFYV0W5dJ
VNuxHX+yb+CyR1xdh0SqcAJpPFRFdMvTe4tjMokNx5bkkzLYAMwGygt4u4qmLz94
p1J0CAEftg1fzbmbm9ehr8TY2SlF9k00W3HfLDPqeGenBtU7bsFRScgJsf5Fdy4q
c74g6cWRTPpIAD0CAwEAAaNxMG8wHQYDVR0OBBYEFNlPsDNseQ9Tg2iyKxPgwAgC
0gW+MB8GA1UdIwQYMBaAFGxEf+I5mhWGioGsimjMWMWbu4OAMCIGA1UdEQQbMBmH
BMCoAQCCEXRhcmRpcy5lbGFzdGljLmNvMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEL
BQADggEBAD7CAOwaJrt0Au6yEZd4LHY03c8N3bq3Gcn+31YFemyvlHJTVHHzmzEG
i3pU2JJDjefmHtsyXNnlzVwAcLd0lDtmiV5Baiuq/3C8zlwsln5aOAfJy94WDvfr
ZSjSN6pPCDMRIc55MRGsy1hHNtMml1R3NdH5H6uuEBKaVJIT3GbvdCdS3n6Gy7Go
supbBlTxw20eOWOW5NVBhQuix+Lul6QtORTqdV+0Ijyd+c5IoXbBMc34N9sjrDY7
Uoyv095FS6hLVdVFeTy8kO7DgZUItrzjZiXATcXku0H9TAeccX6BGXgtDLPn93gd
Ef23lo+PtLfG7fz1TF9Yz11A5uEjZds=
-----END CERTIFICATE-----
`,
					Key: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsO3dq2k4ovARfgK+xZ18wv3u4u0OjXONL7YoNL0zLxPPp0hY
uNisNN57KW6Lba1vSiu7Y02lQ4/JbVIlVds/7FOBPaN1n61rJ6KFGK14PpepjuVr
zNuLxHawUREBi5oeVEzgkmOHDxxABRjmnbYr67PYhUM9xoLykuxiWtBXYU7WIIg/
C1TS6gq+18jqEF0VhXRbl0lU27Edf7Jv4LJHXF2HRKpwAmk8VEV0y9N7i2MyiQ3H
luSTMtgAzAbKC3i7iqYvP3inUnQIAR+2DV/NuZub16GvxNjZKUX2TTRbcd8sM+p4
Z6cG1TtuwVFJyAmx/kV3LipzviDpxZFM+kgAPQIDAQABAoIBADNXApC/uqCFOv4u
u77KIS7P0qbklOl000459FbBY/3QKNxowN36eZXpzSFLo4fS4M1L/Vcma8M8EP34
7T6JnXXtET6alQIdp09b+HUduRuolJoTdoF+X4NF0YnkfmdM9GoP2MaBvOokj2sr
O5geCYaerECXL3DQBKWflDa35/MjGiY7lbtFlv4vqMh5LhfZpDAxnkNzbDw716Iq
ZYE2+Rq+l2dK3uNB1tnRSG7fUhNCp/JcQy+9I+bZTY3wFDo23vqeYyR+BhB/byt+
BFe0IR8+1VgIbE00ecXE/tZ8V1SBMQrJ8avkKLcXYdJdWw1hnAtPMuBDNbvTATKe
5hdSDN0CgYEA6mzW3ISfaDzrCwW3e1oWpYW+SjeYRaRJLfZwy/arbwp0bQGzrOix
nVk8g1MsVSUMQ5yoL9/xVnLLKaa5qRLp5sfeRrg+0gKDd1fU+jM9a5UTicbZQGOh
3aOxtmeekmeh4s670KHZx7KKSsVZH+6bIx4J58zF7UjmcEVjDxGmXZ8CgYEAwTZl
QoC9ptNtSEKig69RrW0yg7rAGa5Fb29h+sYePK4nX8dvrBDc+cHOxao/uZTd20Tq
8yHzy0g9IqYX/lSGyrmweY1V03KR3e6d6l2l7s/RakSdB75b3iG5SbC+6cD80zPK
q2jWg3ajLphuf8dNuC1kOaaHzuhzOoTL8uXDHKMCgYEAoNFfqNH2hUzdNaeLUrzf
sleIzmNLO+NTLIvWn6Wtv7RdYHZ9a04KotYX9EN3s0WCH1P18Tng1xxTEVTGIx3N
hjtw2fUFa46734BKpAXIyefwCmF2onx3C5SDko2NNASSAwUtxRdzTlLGGjs+Q/Ct
Tq8JvpI06e5L35NKPIkwJyMCgYBsHsZ3epemfXYQE8nhqwAn7o1wDddmB5GvlELe
FHPjPQmnnXEudplR4lSVZHoYneewxlY8DGni/d/IPe37Us3DMDpDKwY2N0zNRrRz
7Efo5b6omxDMvoemPHT1ecS8BlT002y8kwRHuOIENyTOuHcTc8M8R6aD8KxauOlw
WYbfxQKBgQDUyPtbfRS5Ns87ix7+3LAQ9W0gtVOIoFl3ysk/JzRDZyxzaX+AhWdC
IBO3yO2fxXIweDJBnL4TOanJK1NRJsXgGJnp0n8SRwECrtI7Jb3nmRgZEiiwNdr7
FaZ3yM1rwmTiI90woe9kq8jEcP7Ew07naoCTlEDxTSgSqh4lKuUNCw==
-----END RSA PRIVATE KEY-----
`,
				},
			},
			Timeout: 30 * time.Second,
			Proxy: httpcommon.HTTPClientProxySettings{
				URL: &httpcommon.ProxyURI{
					Scheme: "http",
					Host:   "trenzalore:1234",
				},
				Headers: httpcommon.ProxyHeaders{
					"title":     "Doctor",
					"name":      "The Doctor",
					"intention": "fun",
				},
				Disable: false,
			},
			IdleConnTimeout: 15 * time.Second,
		},
	}
	return cfgyaml, want
}

func TestUpgraderReload_sourceURL(t *testing.T) {
	tcs := []struct {
		name      string
		sourceURL string
		proxyURL  string
		cfg       string
	}{
		{
			name:      "source_uri has precedence over sourceURI",
			sourceURL: "https://this.sourceURI.co/downloads/beats/",
			cfg: `
agent.download:
  source_uri: "https://this.sourceURI.co/downloads/beats/"
  sourceURI: "https://NOT.sourceURI.co/downloads/beats/"
`,
		}, {
			name:      "only sourceURI",
			sourceURL: "https://this.sourceURI.co/downloads/beats/",
			cfg: `
agent.download:
  sourceURI: "https://this.sourceURI.co/downloads/beats/"
`,
		}, {
			name:      "only source_uri",
			sourceURL: "https://this.sourceURI.co/downloads/beats/",
			cfg: `
agent.download:
  source_uri: "https://this.sourceURI.co/downloads/beats/"
`,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := loggertest.New("")

			u := Upgrader{
				log:      log,
				settings: artifact.DefaultConfig(),
			}

			cfg, err := config.NewConfigFrom(tc.cfg)
			require.NoError(t, err, "failed to create new config")

			err = u.Reload(cfg)
			require.NoError(t, err, "error reloading config")

			assert.Equal(t, tc.sourceURL, u.settings.SourceURI)
			if tc.proxyURL != "" {
				require.NotNilf(t, u.settings.Proxy.URL,
					"ProxyURI should not be nil, want %s", tc.proxyURL)
				assert.Equal(t, tc.proxyURL, u.settings.Proxy.URL.String())
			}
		})
	}
}

var agentVersion123SNAPSHOTabcdef = agentVersion{
	version:  "1.2.3",
	snapshot: true,
	hash:     "abcdef",
}

var agentVersion123SNAPSHOTabcdefFips = agentVersion{
	version:  "1.2.3",
	snapshot: true,
	hash:     "abcdef",
	fips:     true,
}

var agentVersion123SNAPSHOTabcdefRepackaged = agentVersion{
	version:  "1.2.3-repackaged",
	snapshot: true,
	hash:     "abcdef",
}

var agentVersion123SNAPSHOTabcdefRepackagedFips = agentVersion{
	version:  "1.2.3-repackaged",
	snapshot: true,
	hash:     "abcdef",
	fips:     true,
}

var agentVersion123abcdef = agentVersion{
	version:  "1.2.3",
	snapshot: false,
	hash:     "abcdef",
}

var agentVersion123SNAPSHOTghijkl = agentVersion{
	version:  "1.2.3",
	snapshot: true,
	hash:     "ghijkl",
}

func TestCheckUpgrade(t *testing.T) {
	type args struct {
		current    agentVersion
		newVersion agentVersion
		metadata   packageMetadata
	}
	type want struct {
		err error
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "different version, snapshot flag and hash, fips to fips",
			args: args{
				current:    agentVersion123SNAPSHOTabcdefFips,
				newVersion: agentVersion123SNAPSHOTabcdefRepackagedFips,
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Fips: true,
						},
					},
				},
			},
			want: want{
				err: nil,
			},
		},
		{
			name: "different version, snapshot flag and hash, fips to non-fips",
			args: args{
				current:    agentVersion123SNAPSHOTabcdefFips,
				newVersion: agentVersion123SNAPSHOTabcdefRepackaged,
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Fips: false,
						},
					},
				},
			},
			want: want{
				err: ErrFipsToNonFips,
			},
		},
		{
			name: "different version, snapshot flag and hash, non-fips to fips",
			args: args{
				current:    agentVersion123SNAPSHOTabcdef,
				newVersion: agentVersion123SNAPSHOTabcdefRepackagedFips,
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Fips: true,
						},
					},
				},
			},
			want: want{
				err: ErrNonFipsToFips,
			},
		},
		{
			name: "different version, snapshot flag and hash, non-fips to non-fips",
			args: args{
				current:    agentVersion123SNAPSHOTabcdef,
				newVersion: agentVersion123SNAPSHOTabcdefRepackaged,
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Fips: false,
						},
					},
				},
			},
			want: want{
				err: nil,
			},
		},
		{
			name: "same version, snapshot flag and hash",
			args: args{
				current:    agentVersion123SNAPSHOTabcdef,
				newVersion: agentVersion123SNAPSHOTabcdef,
			},
			want: want{
				err: ErrUpgradeSameVersion,
			},
		},
		{
			name: "same hash, snapshot flag, different version",
			args: args{
				current:    agentVersion123SNAPSHOTabcdef,
				newVersion: agentVersion123SNAPSHOTabcdefRepackaged,
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Fips: false,
						},
					},
				},
			},
			want: want{
				err: nil,
			},
		},
		{
			name: "same version and hash, different snapshot flag (SNAPSHOT promotion to release)",
			args: args{
				current:    agentVersion123SNAPSHOTabcdef,
				newVersion: agentVersion123abcdef,
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Fips: false,
						},
					},
				},
			},
			want: want{
				err: nil,
			},
		},
		{
			name: "same version and snapshot, different hash (SNAPSHOT upgrade)",
			args: args{
				current:    agentVersion123SNAPSHOTabcdef,
				newVersion: agentVersion123SNAPSHOTghijkl,
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Fips: false,
						},
					},
				},
			},
			want: want{
				err: nil,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			log, _ := loggertest.New(test.name)
			err := checkUpgrade(log, test.args.current, test.args.newVersion, test.args.metadata)

			assert.Equal(t, test.want.err, err, "Unextedted upgrade check result: checkUpgrade(%v, %v, %v, %v) should be %v", log, test.args.current, test.args.newVersion, test.args.metadata, test.want.err)
		})
	}
}

func writeState(t *testing.T, path string, state details.State) {
	ms := newMarkerSerializer(&UpdateMarker{
		Version:           "version",
		Hash:              "hash",
		VersionedHome:     "versionedHome",
		UpdatedOn:         time.Now(),
		PrevVersion:       "prev_version",
		PrevHash:          "prev_hash",
		PrevVersionedHome: "prev_versionedhome",
		Acked:             false,
		Action:            nil,
		Details: &details.Details{
			TargetVersion: "version",
			State:         state,
			ActionID:      "",
			Metadata:      details.Metadata{},
		},
	})

	bytes, err := yaml.Marshal(ms)
	if assert.NoError(t, err, "error marshaling the test upgrade marker") {
		err = os.WriteFile(path, bytes, 0770)
		assert.NoError(t, err, "error writing out the test upgrade marker")
	}
}

func Test_selectWatcherExecutable(t *testing.T) {
	type args struct {
		previous agentInstall
		current  agentInstall
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Simple upgrade, we should launch the new (current) watcher",
			args: args{
				previous: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-somehash"),
				},
				current: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(4, 5, 6, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-4.5.6-someotherhash"),
				},
			},
			want: filepath.Join("data", "elastic-agent-4.5.6-someotherhash"),
		},
		{
			name: "Simple downgrade, we should launch the currently installed (previous) watcher",
			args: args{
				previous: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(4, 5, 6, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-4.5.6-someotherhash"),
				},
				current: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-somehash"),
				},
			},
			want: filepath.Join("data", "elastic-agent-4.5.6-someotherhash"),
		},
		{
			name: "Upgrade from snapshot to released version, we should launch the new (current) watcher",
			args: args{
				previous: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-somehash"),
				},
				current: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-someotherhash"),
				},
			},
			want: filepath.Join("data", "elastic-agent-1.2.3-someotherhash"),
		},
		{
			name: "Downgrade from released version to SNAPSHOT, we should launch the currently installed (previous) watcher",
			args: args{
				previous: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-somehash"),
				},
				current: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-someotherhash"),
				},
			},

			want: filepath.Join("data", "elastic-agent-1.2.3-somehash"),
		},
	}
	// Just need a top dir path. This test does not make any operation on the filesystem, so a temp dir path is as good as any
	fakeTopDir := filepath.Join(t.TempDir(), "Elastic", "Agent")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := &upgradeWatcher{}
			assert.Equalf(t, paths.BinaryPath(filepath.Join(fakeTopDir, tt.want), agentName), watcher.selectWatcherExecutable(fakeTopDir, tt.args.previous, tt.args.current), "selectWatcherExecutable(%v, %v)", tt.args.previous, tt.args.current)
		})
	}
}

func TestIsSameReleaseVersion(t *testing.T) {
	tests := []struct {
		name    string
		current agentVersion
		target  string
		expect  bool
	}{
		{
			name: "current version is snapshot",
			current: agentVersion{
				version:  "1.2.3",
				snapshot: true,
			},
			target: "1.2.3",
			expect: false,
		},
		{
			name: "target version is snapshot",
			current: agentVersion{
				version: "1.2.3",
			},
			target: "1.2.3-SNAPSHOT",
			expect: false,
		},
		{
			name: "target version is different version",
			current: agentVersion{
				version: "1.2.3",
			},
			target: "1.2.4",
			expect: false,
		},
		{
			name: "target version has same major.minor.patch, different pre-release",
			current: agentVersion{
				version: "1.2.3",
			},
			target: "1.2.3-custom.info",
			expect: false,
		},
		{
			name: "target version is same with build",
			current: agentVersion{
				version: "1.2.3",
			},
			target: "1.2.3+buildID",
			expect: false,
		},
		{
			name: "target version is same",
			current: agentVersion{
				version: "1.2.3",
			},
			target: "1.2.3",
			expect: true,
		},
		{
			name: "target version is invalid",
			current: agentVersion{
				version: "1.2.3",
			},
			target: "a.b.c",
			expect: false,
		},
		{
			name: "current version is fips",
			current: agentVersion{
				version: "1.2.3",
				fips:    true,
			},
			target: "1.2.3",
			expect: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := loggertest.New(tc.name)
			assert.Equal(t, tc.expect, isSameReleaseVersion(log, tc.current, tc.target))
		})
	}
}

var _ acker.Acker = &fakeAcker{}

type fakeAcker struct {
	mock.Mock
}

func (f *fakeAcker) Ack(ctx context.Context, action fleetapi.Action) error {
	args := f.Called(ctx, action)
	return args.Error(0)
}

func (f *fakeAcker) Commit(ctx context.Context) error {
	args := f.Called(ctx)
	return args.Error(0)
}

type mockDownloaderFactoryProviderTest struct {
}

func (md *mockDownloaderFactoryProviderTest) Download(ctx context.Context, a artifact.Artifact, version *agtversion.ParsedSemVer) (download.DownloadResult, error) {
	return download.DownloadResult{}, nil
}

func TestDownloaderFactoryProvider(t *testing.T) {
	factory := func(ver *agtversion.ParsedSemVer, l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
		return &mockDownloaderFactoryProviderTest{}, nil
	}
	provider := &downloaderFactoryProvider{
		downloaderFactories: map[string]downloaderFactory{
			"mockDownloaderFactory": factory,
		},
	}

	actual, err := provider.GetDownloaderFactory("mockDownloaderFactory")
	require.NoError(t, err)
	require.Equal(t, reflect.ValueOf(factory).Pointer(), reflect.ValueOf(actual).Pointer())

	_, err = provider.GetDownloaderFactory("nonExistentFactory")
	require.Error(t, err)
	require.Equal(t, "downloader factory \"nonExistentFactory\" not found", err.Error())
}

type upgradeTestCase struct {
	targetVersion          string
	parsedTargetVersion    *agtversion.ParsedSemVer
	downloadError          error
	unpackError            error
	replaceOldWithNewError error
	watchNewAgentError     error
	cleanupError           error
	cleanupCalledWith      error
	expectedError          error
	expectCallback         bool
	calledFuncs            []string
	uncalledFuncs          []string
	downloadsDirCleaned    bool
}

func TestUpgrade(t *testing.T) {
	ctx := t.Context()
	log, _ := loggertest.New("test")

	defaultTargetVersion := "1.0.0"
	defaultParsedTargetVersion, err := agtversion.ParseVersion(defaultTargetVersion)
	require.NoError(t, err)

	currentReleaseVersion := release.VersionWithSnapshot()
	parsedCurrentReleaseVersion, err := agtversion.ParseVersion(currentReleaseVersion)
	require.NoError(t, err)

	invalidTargetVersion := "invalidTargetVersion"

	sourceURI := "mockUri"
	action := &fleetapi.ActionUpgrade{}
	details := &details.Details{}
	skipVerify := false
	skipDefaultPgp := false
	pgpBytes := []string{"mockPGPBytes"}
	pgpBytesConverted := make([]interface{}, len(pgpBytes))
	for i, v := range pgpBytes {
		pgpBytesConverted[i] = v
	}
	agentInfo := &info.AgentInfo{}

	topPath := t.TempDir()
	paths.SetTop(topPath)

	markerFilePath := markerFilePath(paths.Data())
	currentVersionedHome, err := filepath.Rel(topPath, paths.Home())
	require.NoError(t, err)
	symlinkPath := filepath.Join(topPath, agentName)

	downloadResult := download.DownloadResult{
		ArtifactPath:     "mockArtifactPath",
		ArtifactHashPath: "mockArtifactHashPath",
	}

	unpackStepResult := unpackStepResult{
		newHome: "mockNewHome",
		unpackResult: unpackResult{
			VersionedHome: "mockVersionedHome",
			Hash:          "mockHash",
		},
	}

	newRunPath := filepath.Join(unpackStepResult.newHome, "run")

	newBinaryPath := paths.BinaryPath(filepath.Join(topPath, unpackStepResult.VersionedHome), agentName)

	currentVersion := agentVersion{
		version:  release.Version(),
		snapshot: release.Snapshot(),
		hash:     release.Commit(),
		fips:     release.FIPSDistribution(),
	}

	defaultCleanupError := errors.New("test cleanup error")

	previousAgentInstall := agentInstall{
		parsedVersion: currentagtversion.GetParsedAgentPackageVersion(),
		version:       release.VersionWithSnapshot(),
		hash:          release.Commit(),
		versionedHome: currentVersionedHome,
	}

	testCases := map[string]upgradeTestCase{
		"should download artifact, unpack it, replace the old agent and watch the new agent": {
			targetVersion:          defaultTargetVersion,
			parsedTargetVersion:    defaultParsedTargetVersion,
			downloadError:          nil,
			unpackError:            nil,
			replaceOldWithNewError: nil,
			watchNewAgentError:     nil,
			cleanupError:           nil,
			cleanupCalledWith:      nil,
			expectCallback:         true,
			calledFuncs:            []string{"downloadArtifact", "unpackArtifact", "replaceOldWithNew", "watchNewAgent"},
			uncalledFuncs:          []string{},
			downloadsDirCleaned:    true,
		},
		"if the target version is the same release version, it should return error": {
			targetVersion:          currentReleaseVersion,
			parsedTargetVersion:    parsedCurrentReleaseVersion,
			downloadError:          nil,
			unpackError:            nil,
			replaceOldWithNewError: nil,
			watchNewAgentError:     nil,
			cleanupError:           defaultCleanupError,
			cleanupCalledWith:      ErrUpgradeSameVersion,
			expectCallback:         false,
			calledFuncs:            []string{},
			uncalledFuncs:          []string{"downloadArtifact", "unpackArtifact", "replaceOldWithNew", "watchNewAgent"},
			expectedError:          goerrors.Join(ErrUpgradeSameVersion, defaultCleanupError),
			downloadsDirCleaned:    false,
		},
		"if the target version cannot be parsed, it should return error": {
			targetVersion:          invalidTargetVersion,
			parsedTargetVersion:    nil,
			downloadError:          nil,
			unpackError:            nil,
			replaceOldWithNewError: nil,
			watchNewAgentError:     nil,
			cleanupError:           defaultCleanupError,
			cleanupCalledWith:      fmt.Errorf("error parsing version %q: %w", "invalidTargetVersion", version.ErrNoMatch),
			expectCallback:         false,
			calledFuncs:            []string{},
			uncalledFuncs:          []string{"downloadArtifact", "unpackArtifact", "replaceOldWithNew", "watchNewAgent"},
			expectedError:          goerrors.Join(fmt.Errorf("error parsing version %q: %w", "invalidTargetVersion", version.ErrNoMatch), defaultCleanupError),
			downloadsDirCleaned:    false,
		},
		"if the download fails, it should return error": {
			targetVersion:          defaultTargetVersion,
			parsedTargetVersion:    defaultParsedTargetVersion,
			downloadError:          errors.New("test download error"),
			unpackError:            nil,
			replaceOldWithNewError: nil,
			watchNewAgentError:     nil,
			cleanupError:           defaultCleanupError,
			cleanupCalledWith:      errors.New("test download error"),
			expectCallback:         false,
			calledFuncs:            []string{"downloadArtifact"},
			uncalledFuncs:          []string{"unpackArtifact", "replaceOldWithNew", "watchNewAgent"},
			expectedError:          goerrors.Join(errors.New("test download error"), defaultCleanupError),
			downloadsDirCleaned:    false,
		},
		"if the unpack fails, it should return error": {
			targetVersion:          defaultTargetVersion,
			parsedTargetVersion:    defaultParsedTargetVersion,
			downloadError:          nil,
			unpackError:            errors.New("test unpack error"),
			replaceOldWithNewError: nil,
			watchNewAgentError:     nil,
			cleanupError:           defaultCleanupError,
			cleanupCalledWith:      errors.New("test unpack error"),
			expectCallback:         false,
			calledFuncs:            []string{"downloadArtifact", "unpackArtifact"},
			uncalledFuncs:          []string{"replaceOldWithNew", "watchNewAgent"},
			expectedError:          goerrors.Join(errors.New("test unpack error"), defaultCleanupError),
			downloadsDirCleaned:    false,
		},
		"if the replace old with new fails, it should return error": {
			targetVersion:          defaultTargetVersion,
			parsedTargetVersion:    defaultParsedTargetVersion,
			downloadError:          nil,
			unpackError:            nil,
			replaceOldWithNewError: errors.New("test replace old with new error"),
			watchNewAgentError:     nil,
			cleanupError:           defaultCleanupError,
			cleanupCalledWith:      errors.New("test replace old with new error"),
			expectCallback:         false,
			calledFuncs:            []string{"downloadArtifact", "unpackArtifact", "replaceOldWithNew"},
			uncalledFuncs:          []string{"watchNewAgent"},
			expectedError:          goerrors.Join(errors.New("test replace old with new error"), defaultCleanupError),
			downloadsDirCleaned:    false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			newAgentInstall := agentInstall{
				parsedVersion: tc.parsedTargetVersion,
				version:       tc.targetVersion,
				hash:          unpackStepResult.Hash,
				versionedHome: unpackStepResult.VersionedHome,
			}

			downloadsPath := t.TempDir()
			paths.SetDownloads(downloadsPath)

			mockCleaner := &mock_upgradeCleaner{}
			mockExecutor := &mock_upgradeExecutor{}

			upgrader := &Upgrader{
				log:             log,
				agentInfo:       agentInfo,
				markerWatcher:   newMarkerFileWatcher(markerFilePath, log),
				upgradeCleaner:  mockCleaner,
				upgradeExecutor: mockExecutor,
			}

			for _, funcName := range tc.calledFuncs {
				switch funcName {
				case "downloadArtifact":
					mockExecutor.EXPECT().downloadArtifact(ctx, tc.parsedTargetVersion, agentInfo, sourceURI, "", details, skipVerify, skipDefaultPgp, pgpBytesConverted...).Return(downloadResult, tc.downloadError)

				case "unpackArtifact":
					mockExecutor.EXPECT().unpackArtifact(downloadResult, tc.targetVersion, downloadResult.ArtifactPath, topPath, "", paths.Data(), paths.HomePath(), details, currentVersion, mock.AnythingOfType("checkUpgradeFn")).Return(unpackStepResult, tc.unpackError)

				case "replaceOldWithNew":
					mockExecutor.EXPECT().replaceOldWithNew(unpackStepResult, currentVersionedHome, topPath, agentName, paths.Run(), newRunPath, symlinkPath, newBinaryPath, details).Return(tc.replaceOldWithNewError)

				case "watchNewAgent":
					mockExecutor.EXPECT().watchNewAgent(ctx, markerFilePath, topPath, paths.Data(), watcherMaxWaitTime, mock.AnythingOfType("createContextWithTimeout"), newAgentInstall, previousAgentInstall, action, details, OUTCOME_UPGRADE).Return(tc.watchNewAgentError)
				}
			}

			mockCleaner.EXPECT().cleanup(tc.cleanupCalledWith).Return(tc.cleanupError)

			cb, err := upgrader.Upgrade(ctx, tc.targetVersion, sourceURI, action, details, skipVerify, skipDefaultPgp, pgpBytes...)

			if len(tc.calledFuncs) > 0 {
				mockExecutor.AssertExpectations(t)
			}

			for _, funcName := range tc.uncalledFuncs {
				mockExecutor.AssertNotCalled(t, funcName, "expected %v to not be called", funcName)
			}

			mockCleaner.AssertExpectations(t)

			if tc.expectCallback {
				require.NotNil(t, cb)
			} else {
				require.Nil(t, cb)
			}

			if tc.downloadsDirCleaned {
				require.NoDirExists(t, downloadsPath, "downloads directory should be cleaned up")
			} else {
				require.DirExists(t, downloadsPath, "downloads directory should not be cleaned up")
			}

			if tc.expectedError != nil {
				require.Equal(t, tc.expectedError.Error(), err.Error(), "expected error to be %v, got %v", tc.expectedError, err)
				return
			}

			require.NoError(t, err, "expected no error, got %v", err)
		})
	}
}

func setupForFileDownloader(sourcePrefix string, expectedFileName string, partialData []byte) setupFunc {
	return func(t *testing.T, config *artifact.Config, basePath string, targetPath string) {
		testDownloadPath := filepath.Join(basePath, "downloads")
		originalDownloadsPath := paths.Downloads()
		t.Cleanup(func() {
			paths.SetDownloads(originalDownloadsPath)
		})
		paths.SetDownloads(targetPath)
		err := os.MkdirAll(testDownloadPath, 0755)
		require.NoError(t, err)
		tempArtifactPath := filepath.Join(testDownloadPath, expectedFileName)
		err = os.WriteFile(tempArtifactPath, partialData, 0644)
		require.NoError(t, err)

		config.SourceURI = sourcePrefix + tempArtifactPath
		config.DropPath = testDownloadPath
	}
}

func setupForHttpDownloader(partialData []byte) (setupFunc, *httptest.Server) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(partialData) //nolint:errcheck //test code
	}))

	return func(t *testing.T, config *artifact.Config, basePath string, targetPath string) {
		config.SourceURI = server.URL
		config.RetrySleepInitDuration = 1 * time.Second
		config.HTTPTransportSettings = httpcommon.HTTPTransportSettings{
			Timeout: 1 * time.Second,
		}
	}, server
}

func fileDownloaderFactoryProvider(config *artifact.Config, copyFunc func(dst io.Writer, src io.Reader) (int64, error)) *downloaderFactoryProvider {
	fileDownloader := fs.NewDownloader(config)
	fileDownloader.CopyFunc = copyFunc

	fileFactory := func(ver *agtversion.ParsedSemVer, l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
		return fileDownloader, nil
	}

	return &downloaderFactoryProvider{
		downloaderFactories: map[string]downloaderFactory{
			fileDownloaderFactory: fileFactory,
		},
	}
}

func composedDownloaderFactoryProvider(config *artifact.Config, copyFunc func(dst io.Writer, src io.Reader) (int64, error), log *logger.Logger, upgradeDetails *details.Details) *downloaderFactoryProvider {
	fileDownloader := fs.NewDownloader(config)
	httpDownloader := httpDownloader.NewDownloaderWithClient(log, config, http.Client{}, upgradeDetails)

	if strings.HasPrefix(config.SourceURI, "http://") || strings.HasPrefix(config.SourceURI, "https://") {
		httpDownloader.CopyFunc = copyFunc
	} else {
		fileDownloader.CopyFunc = copyFunc
	}

	composedDownloader := composed.NewDownloader(fileDownloader, httpDownloader)

	fileFactory := func(ver *agtversion.ParsedSemVer, l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
		return fileDownloader, nil
	}
	composedFactory := func(ver *agtversion.ParsedSemVer, l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
		return composedDownloader, nil
	}

	return &downloaderFactoryProvider{
		downloaderFactories: map[string]downloaderFactory{
			fileDownloaderFactory:     fileFactory,
			composedDownloaderFactory: composedFactory,
		},
	}
}

type setupFunc func(t *testing.T, config *artifact.Config, basePath string, targetPath string)
type factoryProviderFunc func(config *artifact.Config, copyFunc func(dst io.Writer, src io.Reader) (int64, error)) *downloaderFactoryProvider
type mockError struct {
	message string
}

func (e *mockError) Error() string {
	return e.message
}

func (e *mockError) Is(target error) bool {
	return e.message == target.Error()
}

type testError struct {
	copyFuncError error
	expectedError error
}

func TestUpgradeDownloadErrors(t *testing.T) {
	testArtifact := artifact.Artifact{
		Name:     "Elastic Agent",
		Cmd:      "elastic-agent",
		Artifact: "beats/elastic-agent",
	}
	version := agtversion.NewParsedSemVer(8, 15, 0, "", "")
	tempConfig := &artifact.Config{}
	expectedFileName, err := artifact.GetArtifactName(testArtifact, *version, tempConfig.OS(), tempConfig.Arch())
	require.NoError(t, err)
	partialData := []byte("partial content written before error")

	testErrors := []testError{}

	for _, te := range TestErrors {
		testErrors = append(testErrors, testError{
			copyFuncError: te,
			expectedError: upgradeErrors.ErrInsufficientDiskSpace,
		})
	}

	mockTestError := &mockError{message: "test error"}
	fileDownloaderTestErrors := []testError{}
	fileDownloaderTestErrors = append(fileDownloaderTestErrors, testError{
		copyFuncError: mockTestError,
		expectedError: mockTestError,
	})
	fileDownloaderTestErrors = append(fileDownloaderTestErrors, testErrors...)

	composedDownloaderTestErrors := []testError{}
	composedDownloaderTestErrors = append(composedDownloaderTestErrors, testError{
		copyFuncError: mockTestError,
		expectedError: context.DeadlineExceeded,
	})
	composedDownloaderTestErrors = append(composedDownloaderTestErrors, testErrors...)

	log, err := logger.New("test", false)
	require.NoError(t, err)
	upgradeDetails := details.NewDetails(version.String(), details.StateDownloading, "test")

	testCases := map[string]struct {
		setupFunc           setupFunc
		factoryProviderFunc factoryProviderFunc
		cleanupMsg          string
		errors              []testError
	}{
		"file downloader": {
			setupFunc: setupForFileDownloader("file://", expectedFileName, partialData),
			factoryProviderFunc: func(config *artifact.Config, copyFunc func(io.Writer, io.Reader) (int64, error)) *downloaderFactoryProvider {
				return fileDownloaderFactoryProvider(config, copyFunc)
			},
			cleanupMsg: "file downloader should clean up partial files on error",
			errors:     fileDownloaderTestErrors,
		},
		"composed file downloader": {
			setupFunc: setupForFileDownloader("", expectedFileName, partialData),
			factoryProviderFunc: func(config *artifact.Config, copyFunc func(io.Writer, io.Reader) (int64, error)) *downloaderFactoryProvider {
				return composedDownloaderFactoryProvider(config, copyFunc, log, upgradeDetails)
			},
			cleanupMsg: "composed file downloader should clean up partial files on error",
			errors:     composedDownloaderTestErrors,
		},
		"composed http downloader": {
			setupFunc: func() setupFunc {
				setupFunc, server := setupForHttpDownloader(partialData)
				t.Cleanup(server.Close)
				return setupFunc
			}(),
			factoryProviderFunc: func(config *artifact.Config, copyFunc func(io.Writer, io.Reader) (int64, error)) *downloaderFactoryProvider {
				return composedDownloaderFactoryProvider(config, copyFunc, log, upgradeDetails)
			},
			cleanupMsg: "composed http downloader should clean up partial files on error",
			errors:     composedDownloaderTestErrors,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			for _, testError := range tc.errors {
				t.Run(fmt.Sprintf("with error %v", testError.copyFuncError), func(t *testing.T) {
					baseDir := t.TempDir()
					testTargetPath := filepath.Join(baseDir, "target")

					config := artifact.Config{
						TargetDirectory: testTargetPath,
					}

					tc.setupFunc(t, &config, baseDir, testTargetPath)

					expectedDestPath, err := artifact.GetArtifactPath(testArtifact, *version, config.OS(), config.Arch(), config.TargetDirectory)
					require.NoError(t, err)

					copyFunc := func(dst io.Writer, src io.Reader) (int64, error) {
						_, err := io.Copy(dst, src)
						require.NoError(t, err)

						require.FileExists(t, expectedDestPath, "partially written file should exist before cleanup")
						content, err := os.ReadFile(expectedDestPath)
						require.NoError(t, err)
						require.Equal(t, partialData, content)

						return 0, testError.copyFuncError
					}

					downloaderFactoryProvider := tc.factoryProviderFunc(&config, copyFunc)
					artifactDownloader := newUpgradeArtifactDownloader(log, &config, downloaderFactoryProvider)
					executeUpgrade := &executeUpgrade{
						log:                log,
						artifactDownloader: artifactDownloader,
					}

					mockAgentInfo := mockinfo.NewAgent(t)
					mockAgentInfo.On("Version").Return(version.String())

					upgrader, err := NewUpgrader(log, &config, mockAgentInfo)
					require.NoError(t, err)
					upgrader.upgradeExecutor = executeUpgrade

					_, err = upgrader.Upgrade(context.Background(), version.String(), config.SourceURI, nil, upgradeDetails, false, false)
					require.Error(t, err, "expected error got none")
					require.ErrorIs(t, err, testError.expectedError, "expected error mismatch")
					require.NoFileExists(t, expectedDestPath, tc.cleanupMsg)
					require.DirExists(t, testTargetPath, "target directory should not be cleaned up")
				})
			}
		})
	}
}

func archiveFilesWithArchiveDirName(archiveName string) func(file files) files {
	archiveWithoutSuffix := strings.TrimSuffix(archiveName, ".tar.gz")
	archiveWithoutSuffix = strings.TrimSuffix(archiveWithoutSuffix, ".zip")

	return func(file files) files {
		file.path = strings.Replace(file.path, "elastic-agent-1.2.3-SNAPSHOT-someos-x86_64", archiveWithoutSuffix, 1)

		return file
	}
}

func archiveFilesWithVersionedHome(version string, meta string) func(file files) files {
	return func(file files) files {
		if file.content == ea_123_manifest {
			newContent := strings.ReplaceAll(file.content, "1.2.3", version)
			newContent = strings.ReplaceAll(newContent, "abcdef", meta)

			file.content = newContent
		}
		file.path = strings.ReplaceAll(file.path, "abcdef", meta)

		return file
	}
}

func modifyArchiveFiles(archiveFiles []files, modFuncs ...func(file files) files) []files {
	modifiedArchiveFiles := make([]files, len(archiveFiles))
	for i, file := range archiveFiles {
		for _, modFunc := range modFuncs {
			file = modFunc(file)
		}
		modifiedArchiveFiles[i] = file
	}

	return modifiedArchiveFiles
}

func createArchive(t *testing.T, archiveName string, archiveFiles []files) (string, error) {
	if runtime.GOOS == "windows" {
		return createZipArchive(t, archiveName, archiveFiles)
	}
	return createTarArchive(t, archiveName, archiveFiles)
}

func TestUpgradeUnpackErrors(t *testing.T) {
	log, _ := loggertest.New("test")

	tempConfig := &artifact.Config{} // used only to get os and arch, runtime.GOARCH returns amd64 which is not a valid arch when used in GetArtifactName

	testVersion := agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")
	upgradeDetails := details.NewDetails(testVersion.String(), details.StateRequested, "test")

	artifactName, err := artifact.GetArtifactName(agentArtifact, *testVersion, tempConfig.OS(), tempConfig.Arch())
	require.NoError(t, err)

	archive, err := createArchive(t, artifactName, modifyArchiveFiles(archiveFilesWithMoreComponents, archiveFilesWithArchiveDirName(artifactName)))
	require.NoError(t, err)
	t.Logf("Created archive: %s", archive)

	versionedHome := "data/elastic-agent-1.2.3-SNAPSHOT-abcdef"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, archive)
	}))
	t.Cleanup(server.Close)

	tmpCopyFunc := unpackArchiveCopyFunc
	t.Cleanup(func() {
		unpackArchiveCopyFunc = tmpCopyFunc
	})

	testCases := map[string]testError{
		"should cleanup downloaded artifact and partially unpacked archive on generic error": {
			copyFuncError: errors.New("test copy error"),
			expectedError: errors.New("test copy error"),
		},
	}

	for _, te := range TestErrors {
		testCases[fmt.Sprintf("should cleanup downloaded artifact and partially unpacked archive on disk space error: %v and return InsufficientDiskSpace error", te)] = testError{
			copyFuncError: te,
			expectedError: upgradeErrors.ErrInsufficientDiskSpace,
		}
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			mockAgentInfo := mockinfo.NewAgent(t)
			mockAgentInfo.On("Version").Return(testVersion.String())

			baseDir := t.TempDir()
			paths.SetTop(baseDir)
			testTargetPath := filepath.Join(baseDir, "target")
			versionedHomePath := filepath.Join(baseDir, versionedHome)

			config := artifact.Config{
				TargetDirectory:        testTargetPath,
				SourceURI:              server.URL,
				RetrySleepInitDuration: 1 * time.Second,
				HTTPTransportSettings: httpcommon.HTTPTransportSettings{
					Timeout: 1 * time.Second,
				},
			}

			unpackArchiveCopyFunc = func(dst io.Writer, src io.Reader) (int64, error) {
				require.DirExists(t, versionedHomePath, "versionedHomePath should exist before copying")
				entries, err := os.ReadDir(versionedHomePath)
				require.NoError(t, err, "reading versionedHomePath failed")
				require.Len(t, entries, 1, "versionedHomePath should only contain one file before copying")

				fileInfo, err := entries[0].Info()
				require.NoError(t, err, "getting file info failed")
				require.False(t, fileInfo.IsDir(), "the entry in versionedHomePath should be a file")

				filePath := filepath.Join(versionedHomePath, entries[0].Name())
				file, err := os.Open(filePath)
				require.NoError(t, err, fmt.Sprintf("error opening file %s", filePath))

				defer file.Close()

				stat, err := file.Stat()
				require.NoError(t, err, fmt.Sprintf("error getting file info for %s", filePath))
				require.Equal(t, int64(0), stat.Size(), "file in versionedHomePath should be empty")

				_, err = io.Copy(dst, src)
				require.NoError(t, err, fmt.Sprintf("error copying archive to %s", versionedHomePath))

				statAfter, err := file.Stat()
				require.NoError(t, err, fmt.Sprintf("error getting file info for %s", filePath))
				require.NotEqual(t, int64(0), statAfter.Size(), "file in versionedHomePath should not be empty after copying")

				return 0, tc.copyFuncError
			}

			upgrader, err := NewUpgrader(log, &config, mockAgentInfo)
			require.NoError(t, err)

			_, err = upgrader.Upgrade(context.Background(), testVersion.String(), server.URL, nil, upgradeDetails, true, true)
			require.ErrorIs(t, err, tc.expectedError, "expected error mismatch")

			require.NoDirExists(t, versionedHomePath, "partially unpacked archive should be cleaned up")
			require.NoFileExists(t, config.TargetDirectory, "downloaded artifact should be cleaned up")
		})
	}
}

func TestUpgradeDirectoryCopyErrors(t *testing.T) {
	log, _ := loggertest.New("test")

	tempConfig := &artifact.Config{} // used only to get os and arch, runtime.GOARCH returns amd64 which is not a valid arch when used in GetArtifactName

	// Prepare to override HomePath
	tmpHomePath := paths.HomePath
	t.Cleanup(func() {
		paths.HomePath = tmpHomePath
	})

	initialVersion := agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")
	initialArtifactName, err := artifact.GetArtifactName(agentArtifact, *initialVersion, tempConfig.OS(), tempConfig.Arch())
	require.NoError(t, err)

	modFuncs := []func(file files) files{
		archiveFilesWithArchiveDirName(initialArtifactName),
		archiveFilesWithVersionedHome(initialVersion.CoreVersion(), "abcdef"),
	}

	initialArchiveFiles := modifyArchiveFiles(archiveFilesWithMoreComponents, modFuncs...)

	targetVersion := agtversion.NewParsedSemVer(3, 4, 5, "SNAPSHOT", "")
	targetArtifactName, err := artifact.GetArtifactName(agentArtifact, *targetVersion, tempConfig.OS(), tempConfig.Arch())
	require.NoError(t, err)

	targetArchiveFiles := modifyArchiveFiles(archiveFilesWithMoreComponents,
		archiveFilesWithArchiveDirName(targetArtifactName),
		archiveFilesWithVersionedHome(targetVersion.CoreVersion(), "ghijkl"),
	)

	mockAgentInfo := mockinfo.NewAgent(t)
	mockAgentInfo.On("Version").Return(targetVersion.String())

	upgradeDetails := details.NewDetails(targetVersion.String(), details.StateRequested, "test")

	tempUnpacker := &upgradeUnpacker{ // used only to unpack the initial archive
		log: log,
	}

	testCases := map[string]struct {
		mockReturnedError error
		expectedError     error
	}{
		"should return error if run directory copy fails": {
			mockReturnedError: errors.New("test dir copy error"),
			expectedError:     errors.New("test dir copy error"),
		},
	}

	for _, te := range TestErrors {
		testCases[fmt.Sprintf("should return error if run directory copy fails with disk space error: %v", te)] = struct {
			mockReturnedError error
			expectedError     error
		}{
			mockReturnedError: te,
			expectedError:     upgradeErrors.ErrInsufficientDiskSpace,
		}
	}

	for _, copiedDir := range []string{"action_store", "run_directory"} {
		for name, tc := range testCases {
			t.Run(fmt.Sprintf("when copying %s: %s", copiedDir, name), func(t *testing.T) {
				paths.SetTop(t.TempDir())

				initialArchive, err := createArchive(t, initialArtifactName, initialArchiveFiles)
				require.NoError(t, err)

				t.Logf("Created archive: %s", initialArchive)

				initialUnpackRes, err := tempUnpacker.unpack(initialVersion.String(), initialArchive, paths.Data(), "")
				require.NoError(t, err)

				checkExtractedFilesWithManifestAndVersionedHome(t, paths.Data(), filepath.Join(paths.Top(), initialUnpackRes.VersionedHome))

				// Overriding HomePath which is just a var holding paths.Home() because
				// Home() returns "unknow" short commit and returns the release version
				// which is set in init.
				paths.HomePath = func() string {
					actualPath := filepath.Join(paths.Top(), initialUnpackRes.VersionedHome)
					return actualPath
				}

				// The file list does not contain the action store files, so we need to
				// create them
				err = os.WriteFile(paths.AgentActionStoreFile(), []byte("initial agent action store content"), 0o600)
				require.NoError(t, err)
				err = os.WriteFile(paths.AgentStateStoreYmlFile(), []byte("initial agent state yml content"), 0o600)
				require.NoError(t, err)
				err = os.WriteFile(paths.AgentStateStoreFile(), []byte("initial agent state enc content"), 0o600)
				require.NoError(t, err)

				var createdFilePaths []string
				if copiedDir == "run_directory" {
					// Create several files in the initial run path and save their paths in an array.
					initialRunPath := paths.Run()
					require.NoError(t, os.MkdirAll(initialRunPath, 0o755))

					for i := 0; i < 3; i++ {
						filePath := filepath.Join(initialRunPath, fmt.Sprintf("file%d.txt", i))
						err := os.WriteFile(filePath, []byte(fmt.Sprintf("content for file %d", i)), 0o600)
						require.NoError(t, err)
						createdFilePaths = append(createdFilePaths, filePath)
					}
				}

				targetArchive, err := createArchive(t, targetArtifactName, targetArchiveFiles)
				require.NoError(t, err)

				t.Logf("Created archive: %s", targetArchive)

				newVersionedHome := "data/elastic-agent-3.4.5-SNAPSHOT-ghijkl"
				newVersionedHomePath := filepath.Join(paths.Top(), newVersionedHome)
				newRunPath := filepath.Join(newVersionedHomePath, "run")

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.ServeFile(w, r, targetArchive)
				}))
				t.Cleanup(server.Close)

				if copiedDir == "run_directory" {
					tmpDirCopy := dirCopy
					t.Cleanup(func() {
						dirCopy = tmpDirCopy
					})

					dirCopy = func(src string, dest string, opts ...copy.Options) error {
						require.DirExists(t, newRunPath, "new run path should exist before copying")
						runEntries, err := os.ReadDir(newRunPath)
						require.NoError(t, err, "reading new run directory failed")
						require.Len(t, runEntries, 0, "new run directory should be empty before copying")

						err = tmpDirCopy(src, dest, opts...)
						require.NoError(t, err)

						runEntries, err = os.ReadDir(newRunPath)
						require.NoError(t, err, "reading new run directory failed")
						for _, createdFilePath := range createdFilePaths {
							_, fileName := filepath.Split(createdFilePath)
							require.FileExists(t, filepath.Join(newRunPath, fileName), "expected run file %q to exist in new run directory", fileName)
						}

						return tc.mockReturnedError
					}
				} else {
					tmpWriteFile := writeFile
					t.Cleanup(func() {
						writeFile = tmpWriteFile
					})

					writeFile = func(name string, data []byte, perm os.FileMode) error {
						require.DirExists(t, paths.HomePath(), "home path should exist before writing")
						require.NoFileExists(t, name, fmt.Sprintf("file %s should not exist before writing", name))

						err := tmpWriteFile(name, data, perm)
						require.NoError(t, err)

						require.FileExists(t, name, fmt.Sprintf("file %s should exist after writing", name))

						return tc.mockReturnedError
					}
				}

				config := artifact.Config{
					TargetDirectory:        paths.Downloads(),
					SourceURI:              server.URL,
					RetrySleepInitDuration: 1 * time.Second,
					HTTPTransportSettings: httpcommon.HTTPTransportSettings{
						Timeout: 1 * time.Second,
					},
				}

				upgrader, err := NewUpgrader(log, &config, mockAgentInfo)
				require.NoError(t, err)

				_, err = upgrader.Upgrade(context.Background(), targetVersion.String(), server.URL, nil, upgradeDetails, true, true)
				require.ErrorIs(t, err, tc.expectedError, "expected error mismatch")

				require.NoDirExists(t, newVersionedHomePath, fmt.Sprintf("the new agent directory should be cleaned up if %s copy fails", copiedDir))

				entries, err := os.ReadDir(config.TargetDirectory)
				require.NoError(t, err, "reading target directory failed")
				require.Len(t, entries, 0, fmt.Sprintf("the downloaded artifact should be cleaned up if %s copy fails", copiedDir))
			})
		}
	}
}

func TestUpgradeChangeSymlinkErrors(t *testing.T) {
	log, _ := loggertest.New("test")

	tempConfig := &artifact.Config{} // used only to get os and arch, runtime.GOARCH returns amd64 which is not a valid arch when used in GetArtifactName

	// Prepare to override HomePath
	tmpHomePath := paths.HomePath
	t.Cleanup(func() {
		paths.HomePath = tmpHomePath
	})

	initialVersion := agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")
	initialArtifactName, err := artifact.GetArtifactName(agentArtifact, *initialVersion, tempConfig.OS(), tempConfig.Arch())
	require.NoError(t, err)

	initialArchiveFiles := modifyArchiveFiles(archiveFilesWithMoreComponents,
		archiveFilesWithArchiveDirName(initialArtifactName),
		archiveFilesWithVersionedHome(initialVersion.CoreVersion(), "abcdef"),
	)

	targetVersion := agtversion.NewParsedSemVer(3, 4, 5, "SNAPSHOT", "")
	targetArtifactName, err := artifact.GetArtifactName(agentArtifact, *targetVersion, tempConfig.OS(), tempConfig.Arch())
	require.NoError(t, err)

	targetArchiveFiles := modifyArchiveFiles(archiveFilesWithMoreComponents,
		archiveFilesWithArchiveDirName(targetArtifactName),
		archiveFilesWithVersionedHome(targetVersion.CoreVersion(), "ghijkl"),
	)

	mockAgentInfo := mockinfo.NewAgent(t)
	mockAgentInfo.On("Version").Return(targetVersion.String())

	upgradeDetails := details.NewDetails(targetVersion.String(), details.StateRequested, "test")

	tempUnpacker := &upgradeUnpacker{ // used only to unpack the initial archive
		log: log,
	}

	mockReturnedError := errors.New("test symlink error")

	paths.SetTop(t.TempDir())

	initialArchive, err := createArchive(t, initialArtifactName, initialArchiveFiles)
	require.NoError(t, err)

	t.Logf("Created archive: %s", initialArchive)

	initialUnpackRes, err := tempUnpacker.unpack(initialVersion.String(), initialArchive, paths.Data(), "")
	require.NoError(t, err)

	checkExtractedFilesWithManifestAndVersionedHome(t, paths.Data(), filepath.Join(paths.Top(), initialUnpackRes.VersionedHome))

	// Overriding HomePath which is just a var holding paths.Home() because
	// Home() returns "unknow" short commit and returns the release version
	// which is set in init.
	paths.HomePath = func() string {
		actualPath := filepath.Join(paths.Top(), initialUnpackRes.VersionedHome)
		return actualPath
	}

	// The file list does not contain the action store files, so we need to
	// create them
	err = os.WriteFile(paths.AgentActionStoreFile(), []byte("initial agent action store content"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(paths.AgentStateStoreYmlFile(), []byte("initial agent state yml content"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(paths.AgentStateStoreFile(), []byte("initial agent state enc content"), 0o600)
	require.NoError(t, err)

	var createdFilePaths []string
	// Create several files in the initial run path and save their paths in an array.
	initialRunPath := paths.Run()
	require.NoError(t, os.MkdirAll(initialRunPath, 0o755))

	for i := 0; i < 3; i++ {
		filePath := filepath.Join(initialRunPath, fmt.Sprintf("file%d.txt", i))
		err := os.WriteFile(filePath, []byte(fmt.Sprintf("content for file %d", i)), 0o600)
		require.NoError(t, err)
		createdFilePaths = append(createdFilePaths, filePath)
	}

	targetArchive, err := createArchive(t, targetArtifactName, targetArchiveFiles)
	require.NoError(t, err)

	t.Logf("Created archive: %s", targetArchive)

	newVersionedHome := "data/elastic-agent-3.4.5-SNAPSHOT-ghijkl"
	newVersionedHomePath := filepath.Join(paths.Top(), newVersionedHome)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, targetArchive)
	}))
	t.Cleanup(server.Close)

	config := artifact.Config{
		TargetDirectory:        paths.Downloads(),
		SourceURI:              server.URL,
		RetrySleepInitDuration: 1 * time.Second,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: 1 * time.Second,
		},
	}

	tmpSymlinkFunc := symlinkFunc
	t.Cleanup(func() {
		symlinkFunc = tmpSymlinkFunc
	})

	callCount := 0
	symlinkFunc = func(newTarget, prevNewPath string) error {
		callCount++

		err := tmpSymlinkFunc(newTarget, prevNewPath)
		require.NoError(t, err)

		// return error when switching from old to new agent
		if callCount == 1 {
			return mockReturnedError
		}

		// return nil when cleaning up the symlink
		return nil
	}

	upgrader, err := NewUpgrader(log, &config, mockAgentInfo)
	require.NoError(t, err)

	_, err = upgrader.Upgrade(context.Background(), targetVersion.String(), server.URL, nil, upgradeDetails, true, true)
	require.ErrorIs(t, err, mockReturnedError, "expected error mismatch")

	require.NoDirExists(t, newVersionedHomePath, "new versioned home path should be cleaned up")

	entries, err := os.ReadDir(config.TargetDirectory)
	require.NoError(t, err, "reading target directory failed")
	require.Len(t, entries, 0)
}

func TestUpgradeMarkUpgradeError(t *testing.T) {
	log, _ := loggertest.New("test")

	tempConfig := &artifact.Config{} // used only to get os and arch, runtime.GOARCH returns amd64 which is not a valid arch when used in GetArtifactName

	// Prepare to override HomePath
	tmpHomePath := paths.HomePath
	t.Cleanup(func() {
		paths.HomePath = tmpHomePath
	})

	initialVersion := agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", "")
	initialArtifactName, err := artifact.GetArtifactName(agentArtifact, *initialVersion, tempConfig.OS(), tempConfig.Arch())
	require.NoError(t, err)

	initialArchiveFiles := modifyArchiveFiles(archiveFilesWithMoreComponents,
		archiveFilesWithArchiveDirName(initialArtifactName),
		archiveFilesWithVersionedHome(initialVersion.CoreVersion(), "abcdef"),
	)

	targetVersion := agtversion.NewParsedSemVer(3, 4, 5, "SNAPSHOT", "")
	targetArtifactName, err := artifact.GetArtifactName(agentArtifact, *targetVersion, tempConfig.OS(), tempConfig.Arch())
	require.NoError(t, err)

	targetArchiveFiles := modifyArchiveFiles(archiveFilesWithMoreComponents,
		archiveFilesWithArchiveDirName(targetArtifactName),
		archiveFilesWithVersionedHome(targetVersion.CoreVersion(), "ghijkl"),
	)

	mockAgentInfo := mockinfo.NewAgent(t)
	mockAgentInfo.On("Version").Return(targetVersion.String())

	upgradeDetails := details.NewDetails(targetVersion.String(), details.StateRequested, "test")

	tempUnpacker := &upgradeUnpacker{ // used only to unpack the initial archive
		log: log,
	}

	testCases := map[string]testError{
		"should return error and cleanup if mark upgrade fails": {
			copyFuncError: errors.New("test mark upgrade error"),
			expectedError: errors.New("test mark upgrade error"),
		},
	}

	for _, te := range TestErrors {
		testCases[fmt.Sprintf("should return error and cleanup if mark upgrade fails with disk space error: %v", te)] = testError{
			copyFuncError: te,
			expectedError: upgradeErrors.ErrInsufficientDiskSpace,
		}
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			paths.SetTop(t.TempDir())

			initialArchive, err := createArchive(t, initialArtifactName, initialArchiveFiles)
			require.NoError(t, err)

			t.Logf("Created archive: %s", initialArchive)

			initialUnpackRes, err := tempUnpacker.unpack(initialVersion.String(), initialArchive, paths.Data(), "")
			require.NoError(t, err)

			checkExtractedFilesWithManifestAndVersionedHome(t, paths.Data(), filepath.Join(paths.Top(), initialUnpackRes.VersionedHome))

			// Overriding HomePath which is just a var holding paths.Home() because
			// Home() returns "unknow" short commit and returns the release version
			// which is set in init.
			paths.HomePath = func() string {
				actualPath := filepath.Join(paths.Top(), initialUnpackRes.VersionedHome)
				return actualPath
			}

			// The file list does not contain the action store files, so we need to
			// create them
			err = os.WriteFile(paths.AgentActionStoreFile(), []byte("initial agent action store content"), 0o600)
			require.NoError(t, err)
			err = os.WriteFile(paths.AgentStateStoreYmlFile(), []byte("initial agent state yml content"), 0o600)
			require.NoError(t, err)
			err = os.WriteFile(paths.AgentStateStoreFile(), []byte("initial agent state enc content"), 0o600)
			require.NoError(t, err)

			var createdFilePaths []string
			// Create several files in the initial run path and save their paths in an array.
			initialRunPath := paths.Run()
			require.NoError(t, os.MkdirAll(initialRunPath, 0o755))

			for i := 0; i < 3; i++ {
				filePath := filepath.Join(initialRunPath, fmt.Sprintf("file%d.txt", i))
				err := os.WriteFile(filePath, []byte(fmt.Sprintf("content for file %d", i)), 0o600)
				require.NoError(t, err)
				createdFilePaths = append(createdFilePaths, filePath)
			}

			targetArchive, err := createArchive(t, targetArtifactName, targetArchiveFiles)
			require.NoError(t, err)

			t.Logf("Created archive: %s", targetArchive)

			newVersionedHome := "data/elastic-agent-3.4.5-SNAPSHOT-ghijkl"
			newVersionedHomePath := filepath.Join(paths.Top(), newVersionedHome)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, targetArchive)
			}))
			t.Cleanup(server.Close)

			config := artifact.Config{
				TargetDirectory:        paths.Downloads(),
				SourceURI:              server.URL,
				RetrySleepInitDuration: 1 * time.Second,
				HTTPTransportSettings: httpcommon.HTTPTransportSettings{
					Timeout: 1 * time.Second,
				},
			}

			markerFilePath := markerFilePath(paths.Data())

			tmpWriteFile := writeFile
			t.Cleanup(func() {
				writeFile = tmpWriteFile
			})

			writeFile = func(name string, data []byte, perm os.FileMode) error {
				if name != markerFilePath {
					return tmpWriteFile(name, data, perm)
				}

				require.NoFileExists(t, name, fmt.Sprintf("file %s should not exist before writing", name))

				err := tmpWriteFile(name, data, perm)
				require.NoError(t, err)

				require.FileExists(t, name, fmt.Sprintf("file %s should exist after writing", name))

				return tc.copyFuncError
			}

			upgrader, err := NewUpgrader(log, &config, mockAgentInfo)
			require.NoError(t, err)

			_, err = upgrader.Upgrade(context.Background(), targetVersion.String(), server.URL, nil, upgradeDetails, true, true)
			require.ErrorIs(t, err, tc.expectedError, "expected error mismatch")

			require.NoDirExists(t, newVersionedHomePath, "new versioned home path should be cleaned up")

			entries, err := os.ReadDir(config.TargetDirectory)
			require.NoError(t, err, "reading target directory failed")
			require.Len(t, entries, 0)
		})
	}
}
