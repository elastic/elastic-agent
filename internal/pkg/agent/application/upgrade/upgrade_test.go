// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

func Test_CopyFile(t *testing.T) {
	l, _ := logger.New("test", false)
	tt := []struct {
		Name        string
		From        string
		To          string
		IgnoreErr   bool
		KeepOpen    bool
		ExpectedErr bool
	}{
		{
			"Existing, no onerr",
			filepath.Join(".", "test", "case1", "README.md"),
			filepath.Join(".", "test", "case1", "copy", "README.md"),
			false,
			false,
			false,
		},
		{
			"Existing but open",
			filepath.Join(".", "test", "case2", "README.md"),
			filepath.Join(".", "test", "case2", "copy", "README.md"),
			false,
			true,
			runtime.GOOS == "windows", // this fails only on,
		},
		{
			"Existing but open, ignore errors",
			filepath.Join(".", "test", "case3", "README.md"),
			filepath.Join(".", "test", "case3", "copy", "README.md"),
			true,
			true,
			false,
		},
		{
			"Not existing, accept errors",
			filepath.Join(".", "test", "case4", "README.md"),
			filepath.Join(".", "test", "case4", "copy", "README.md"),
			false,
			false,
			true,
		},
		{
			"Not existing, ignore errors",
			filepath.Join(".", "test", "case4", "README.md"),
			filepath.Join(".", "test", "case4", "copy", "README.md"),
			true,
			false,
			false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			defer func() {
				// cleanup
				_ = os.RemoveAll(filepath.Dir(tc.To))
			}()

			var fl *flock.Flock
			if tc.KeepOpen {
				// this uses syscalls to create inter-process lock
				fl = flock.New(tc.From)
				_, err := fl.TryLock()
				require.NoError(t, err)

				defer func() {
					require.NoError(t, fl.Unlock())
				}()

			}

			err := copyDir(l, tc.From, tc.To, tc.IgnoreErr, copy.Copy)
			require.Equal(t, tc.ExpectedErr, err != nil, err)
		})
	}
}

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
			agentHomeDirectory:    fmt.Sprintf("%s-%s", AgentName, release.ShortCommit()),
			newAgentHomeDirectory: fmt.Sprintf("%s-%s", AgentName, "abc123"),
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
			mc := client.NewMockClient(t)
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
		mockAcker := acker.NewMockAcker(t)
		mockAcker.EXPECT().Ack(mock.Anything, action).Return(nil)
		mockAcker.EXPECT().Commit(mock.Anything).Return(nil)

		require.Nil(t, u.AckAction(t.Context(), mockAcker, action))
	})

	t.Run("AckAction with acker - failing commit", func(t *testing.T) {
		mockAcker := acker.NewMockAcker(t)

		errCommit := errors.New("failed commit")
		mockAcker.EXPECT().Ack(mock.Anything, action).Return(nil)
		mockAcker.EXPECT().Commit(mock.Anything).Return(errCommit)

		require.ErrorIs(t, u.AckAction(t.Context(), mockAcker, action), errCommit)
	})

	t.Run("AckAction with acker - failed ack", func(t *testing.T) {
		mockAcker := acker.NewMockAcker(t)

		errAck := errors.New("ack error")
		mockAcker.EXPECT().Ack(mock.Anything, action).Return(errAck)
		// no expectation on Commit() since it shouldn't be called after an error during Ack()

		require.ErrorIs(t, u.AckAction(t.Context(), mockAcker, action), errAck)
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

func TestExtractVersion(t *testing.T) {
	type args struct {
		metadata packageMetadata
		version  string
	}
	type want struct {
		newVersion agentVersion
	}

	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "same version, snapshot flag and hash",
			args: args{
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Version:       "1.2.3",
							Snapshot:      true,
							VersionedHome: "",
							PathMappings:  nil,
						},
					},
					hash: "abcdef",
				},
				version: "unused",
			},
			want: want{
				newVersion: agentVersion123SNAPSHOTabcdef,
			},
		},
		{
			name: "same hash, snapshot flag, different version",
			args: args{
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Version:       "1.2.3-repackaged",
							Snapshot:      true,
							VersionedHome: "",
							PathMappings:  nil,
						},
					},
					hash: "abcdef",
				},
				version: "unused",
			},
			want: want{
				newVersion: agentVersion123SNAPSHOTabcdefRepackaged,
			},
		},
		{
			name: "same version and hash, different snapshot flag (SNAPSHOT promotion to release)",
			args: args{
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Version:       "1.2.3",
							Snapshot:      false,
							VersionedHome: "",
							PathMappings:  nil,
						},
					},
					hash: "abcdef",
				},
				version: "unused",
			},
			want: want{
				newVersion: agentVersion123abcdef,
			},
		},
		{
			name: "same version and snapshot, different hash (SNAPSHOT upgrade)",
			args: args{
				metadata: packageMetadata{
					manifest: &v1.PackageManifest{
						Package: v1.PackageDesc{
							Version:       "1.2.3",
							Snapshot:      true,
							VersionedHome: "",
							PathMappings:  nil,
						},
					},
					hash: "ghijkl",
				},
				version: "unused",
			},
			want: want{
				newVersion: agentVersion123SNAPSHOTghijkl,
			},
		},
		{
			name: "same version, snapshot flag and hash, no manifest",
			args: args{
				metadata: packageMetadata{
					manifest: nil,
					hash:     "abcdef",
				},
				version: "1.2.3-SNAPSHOT",
			},
			want: want{
				newVersion: agentVersion123SNAPSHOTabcdef,
			},
		},
		{
			name: "same hash, snapshot flag, different version, no manifest",
			args: args{
				metadata: packageMetadata{
					manifest: nil,
					hash:     "abcdef",
				},
				version: "1.2.3-SNAPSHOT.repackaged",
			},
			want: want{
				newVersion: agentVersion123SNAPSHOTabcdefRepackaged,
			},
		},
		{
			name: "same version and hash, different snapshot flag, no manifest (SNAPSHOT promotion to release)",
			args: args{
				metadata: packageMetadata{
					manifest: nil,
					hash:     "abcdef",
				},
				version: "1.2.3",
			},
			want: want{
				newVersion: agentVersion123abcdef,
			},
		},
		{
			name: "same version and snapshot, different hash (SNAPSHOT upgrade)",
			args: args{
				metadata: packageMetadata{
					manifest: nil,
					hash:     "ghijkl",
				},
				version: "1.2.3-SNAPSHOT",
			},
			want: want{
				newVersion: agentVersion123SNAPSHOTghijkl,
			},
		},
		{
			name: "same version and snapshot, no hash (SNAPSHOT upgrade before download)",
			args: args{
				metadata: packageMetadata{
					manifest: nil,
				},
				version: "1.2.3-SNAPSHOT",
			},
			want: want{
				newVersion: agentVersion{
					version:  "1.2.3",
					snapshot: true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualNewVersion := extractAgentVersion(test.args.metadata, test.args.version)
			assert.Equal(t, test.want.newVersion, actualNewVersion, "Unexpected new version result: extractAgentVersion(%v, %v) should be %v",
				test.args.metadata, test.args.version, test.want.newVersion)
		})
	}
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

type mockArtifactDownloader struct {
	returnError       error
	returnArchivePath string
	fleetServerURI    string
}

func (m *mockArtifactDownloader) downloadArtifact(ctx context.Context, parsedVersion *agtversion.ParsedSemVer, sourceURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (_ string, err error) {
	return m.returnArchivePath, m.returnError
}

func (m *mockArtifactDownloader) withFleetServerURI(fleetServerURI string) {
	m.fleetServerURI = fleetServerURI
}

type mockUnpacker struct {
	returnPackageMetadata      packageMetadata
	returnPackageMetadataError error
	returnUnpackResult         UnpackResult
	returnUnpackError          error
}

func (m *mockUnpacker) getPackageMetadata(archivePath string) (packageMetadata, error) {
	return m.returnPackageMetadata, m.returnPackageMetadataError
}

func (m *mockUnpacker) unpack(version, archivePath, dataDir string, flavor string) (UnpackResult, error) {
	return m.returnUnpackResult, m.returnUnpackError
}

func TestUpgradeErrorHandling(t *testing.T) {
	log, _ := loggertest.New("test")
	testError := errors.New("test error")

	type upgraderMocker func(upgrader *Upgrader, archivePath string, versionedHome string)

	type testCase struct {
		isDiskSpaceErrorResult    bool
		expectedError             error
		upgraderMocker            upgraderMocker
		checkArchiveCleanup       bool
		checkVersionedHomeCleanup bool
		setupMocks                func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper)
	}

	testCases := map[string]testCase{
		"should return error and cleanup downloaded archive if downloadArtifact fails after download is complete": {
			isDiskSpaceErrorResult: false,
			expectedError:          testError,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnError:       testError,
					returnArchivePath: archivePath,
				}
			},
			checkArchiveCleanup: true,
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
			},
		},
		"should return error if getPackageMetadata fails": {
			isDiskSpaceErrorResult: false,
			expectedError:          testError,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnArchivePath: archivePath,
				}
				upgrader.unpacker = &mockUnpacker{
					returnPackageMetadataError: testError,
				}
			},
			checkArchiveCleanup: true,
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
			},
		},
		"should return error and cleanup downloaded archive if unpack fails before extracting": {
			isDiskSpaceErrorResult: false,
			expectedError:          testError,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnArchivePath: archivePath,
				}
				upgrader.extractAgentVersion = func(metadata packageMetadata, upgradeVersion string) agentVersion {
					return agentVersion{
						version:  upgradeVersion,
						snapshot: false,
						hash:     metadata.hash,
					}
				}
				upgrader.unpacker = &mockUnpacker{
					returnPackageMetadata: packageMetadata{
						manifest: &v1.PackageManifest{},
						hash:     "hash",
					},
					returnUnpackError: testError,
				}
			},
			checkArchiveCleanup: true,
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
			},
		},
		"should return error and cleanup downloaded archive if unpack fails after extracting": {
			isDiskSpaceErrorResult: false,
			expectedError:          testError,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnArchivePath: archivePath,
				}
				upgrader.extractAgentVersion = func(metadata packageMetadata, upgradeVersion string) agentVersion {
					return agentVersion{
						version:  upgradeVersion,
						snapshot: false,
						hash:     metadata.hash,
					}
				}
				upgrader.unpacker = &mockUnpacker{
					returnPackageMetadata: packageMetadata{
						manifest: &v1.PackageManifest{},
						hash:     "hash",
					},
					returnUnpackError: testError,
					returnUnpackResult: UnpackResult{
						Hash:          "hash",
						VersionedHome: versionedHome,
					},
				}
			},
			checkArchiveCleanup:       true,
			checkVersionedHomeCleanup: true,
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
			},
		},
		"should return error and cleanup downloaded artifact and extracted archive if copyActionStore fails": {
			isDiskSpaceErrorResult: false,
			expectedError:          testError,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnArchivePath: archivePath,
				}
				upgrader.extractAgentVersion = func(metadata packageMetadata, upgradeVersion string) agentVersion {
					return agentVersion{
						version:  upgradeVersion,
						snapshot: false,
						hash:     metadata.hash,
					}
				}
				upgrader.unpacker = &mockUnpacker{
					returnPackageMetadata: packageMetadata{
						manifest: &v1.PackageManifest{},
						hash:     "hash",
					},
					returnUnpackResult: UnpackResult{
						Hash:          "hash",
						VersionedHome: versionedHome,
					},
				}
				upgrader.copyActionStore = func(log *logger.Logger, newHome string) error {
					return testError
				}
			},
			checkArchiveCleanup:       true,
			checkVersionedHomeCleanup: true,
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
			},
		},
		"should return error and cleanup downloaded artifact and extracted archive if copyRunDirectory fails": {
			isDiskSpaceErrorResult: false,
			expectedError:          testError,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{}
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnArchivePath: archivePath,
				}
				upgrader.extractAgentVersion = func(metadata packageMetadata, upgradeVersion string) agentVersion {
					return agentVersion{
						version:  upgradeVersion,
						snapshot: false,
						hash:     metadata.hash,
					}
				}
				upgrader.unpacker = &mockUnpacker{
					returnPackageMetadata: packageMetadata{
						manifest: &v1.PackageManifest{},
						hash:     "hash",
					},
					returnUnpackResult: UnpackResult{
						Hash:          "hash",
						VersionedHome: versionedHome,
					},
				}
				upgrader.copyActionStore = func(log *logger.Logger, newHome string) error {
					return nil
				}
				upgrader.copyRunDirectory = func(log *logger.Logger, oldRunPath, newRunPath string) error {
					return testError
				}
			},
			checkArchiveCleanup:       true,
			checkVersionedHomeCleanup: true,
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
			},
		},
		"should return error and cleanup downloaded artifact and extracted archive if changeSymlink fails": {
			isDiskSpaceErrorResult: false,
			expectedError:          testError,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnArchivePath: archivePath,
				}
				upgrader.extractAgentVersion = func(metadata packageMetadata, upgradeVersion string) agentVersion {
					return agentVersion{
						version:  upgradeVersion,
						snapshot: false,
						hash:     metadata.hash,
					}
				}
				upgrader.unpacker = &mockUnpacker{
					returnPackageMetadata: packageMetadata{
						manifest: &v1.PackageManifest{},
						hash:     "hash",
					},
					returnUnpackResult: UnpackResult{
						Hash:          "hash",
						VersionedHome: versionedHome,
					},
				}
				upgrader.copyActionStore = func(log *logger.Logger, newHome string) error {
					return nil
				}
				upgrader.copyRunDirectory = func(log *logger.Logger, oldRunPath, newRunPath string) error {
					return nil
				}
				upgrader.rollbackInstall = func(ctx context.Context, log *logger.Logger, topDirPath, versionedHome, oldVersionedHome string, source availableRollbacksSource) error {
					return nil
				}
				upgrader.changeSymlink = func(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error {
					return testError
				}
			},
			checkArchiveCleanup:       true,
			checkVersionedHomeCleanup: true,
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
			},
		},
		"should return error and cleanup downloaded artifact and extracted archive if markUpgrade fails": {
			isDiskSpaceErrorResult: false,
			expectedError:          testError,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnArchivePath: archivePath,
				}
				upgrader.extractAgentVersion = func(metadata packageMetadata, upgradeVersion string) agentVersion {
					return agentVersion{
						version:  upgradeVersion,
						snapshot: false,
						hash:     metadata.hash,
					}
				}
				upgrader.unpacker = &mockUnpacker{
					returnPackageMetadata: packageMetadata{
						manifest: &v1.PackageManifest{},
						hash:     "hash",
					},
					returnUnpackResult: UnpackResult{
						Hash:          "hash",
						VersionedHome: versionedHome,
					},
				}
				upgrader.copyActionStore = func(log *logger.Logger, newHome string) error {
					return nil
				}
				upgrader.copyRunDirectory = func(log *logger.Logger, oldRunPath, newRunPath string) error {
					return nil
				}
				upgrader.changeSymlink = func(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error {
					return nil
				}
				upgrader.rollbackInstall = func(ctx context.Context, log *logger.Logger, topDirPath, versionedHome, oldVersionedHome string, source availableRollbacksSource) error {
					return nil
				}
				upgrader.markUpgrade = func(log *logger.Logger, dataDirPath string, updatedOn time.Time, agent, previousAgent agentInstall, action *fleetapi.ActionUpgrade, upgradeDetails *details.Details, availableRollbacks map[string]ttl.TTLMarker) error {
					return testError
				}
			},
			checkArchiveCleanup:       true,
			checkVersionedHomeCleanup: true,
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
				mockRollbackSrc.EXPECT().Set(map[string]ttl.TTLMarker(nil)).Return(nil)
			},
		},
		"should add disk space error to the error chain if downloadArtifact fails with disk space error": {
			isDiskSpaceErrorResult: true,
			expectedError:          upgradeErrors.ErrInsufficientDiskSpace,
			upgraderMocker: func(upgrader *Upgrader, archivePath string, versionedHome string) {
				upgrader.artifactDownloader = &mockArtifactDownloader{
					returnError: testError,
				}
			},
			setupMocks: func(t *testing.T, mockAgentInfo *info.MockAgent, mockRollbackSrc *mockAvailableRollbacksSource, mockWatcherHelper *MockWatcherHelper) {
				mockAgentInfo.EXPECT().Version().Return("9.0.0")
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			paths.SetTop(baseDir)

			mockAgentInfo := info.NewMockAgent(t)
			mockRollbackSource := newMockAvailableRollbacksSource(t)
			mockWatcherHelper := NewMockWatcherHelper(t)

			if tc.setupMocks != nil {
				// setup mocks
				tc.setupMocks(t, mockAgentInfo, mockRollbackSource, mockWatcherHelper)
			} else {
				t.Log("skipping mocks setup as the testcase does not define a setupMocks()")
			}

			upgrader, err := NewUpgrader(log, &artifact.Config{}, nil, mockAgentInfo, mockWatcherHelper, mockRollbackSource)
			require.NoError(t, err)

			tc.upgraderMocker(upgrader, filepath.Join(baseDir, "mockArchive"), "versionedHome")

			// Create the test files for all the cases
			err = os.WriteFile(filepath.Join(baseDir, "mockArchive"), []byte("test"), 0o600)
			require.NoError(t, err)

			err = os.WriteFile(filepath.Join(baseDir, "versionedHome"), []byte("test"), 0o600)
			require.NoError(t, err)

			upgrader.isDiskSpaceErrorFunc = func(err error) bool {
				return tc.isDiskSpaceErrorResult
			}

			_, err = upgrader.Upgrade(context.Background(), "9.0.0", false, "", nil, details.NewDetails("9.0.0", details.StateRequested, "test"), true, true)
			require.ErrorIs(t, err, tc.expectedError)

			// If the downloaded archive needs to be cleaned up assert that it is indeed cleaned up, if not assert that it still exists. The downloaded archive is a mock file that is created for all tests cases.
			if tc.checkArchiveCleanup {
				require.NoFileExists(t, filepath.Join(baseDir, "mockArchive"))
			} else {
				require.FileExists(t, filepath.Join(baseDir, "mockArchive"))
			}

			// If the extracted agent needs to be cleaned up assert that it is indeed cleaned up, if not assert that it still exists. Versioned home is a mock file that is created for all test cases.
			if tc.checkVersionedHomeCleanup {
				require.NoFileExists(t, filepath.Join(baseDir, "versionedHome"))
			} else {
				require.FileExists(t, filepath.Join(baseDir, "versionedHome"))
			}
		})
	}
}

func TestCopyActionStore(t *testing.T) {
	log, _ := loggertest.New("TestCopyActionStore")

	actionStoreContent := "initial agent action_store.yml content"
	actionStateStoreYamlContent := "initial agent state.yml content"
	actionStateStoreFileContent := "initial agent state.enc content"

	type testFile struct {
		name    string
		content string
	}

	type testCase struct {
		files           []testFile
		copyActionStore copyActionStoreFunc
		expectedError   error
	}

	testError := errors.New("test error")

	testCases := map[string]testCase{
		"should copy all action store files": {
			files: []testFile{
				{name: "action_store", content: actionStoreContent},
				{name: "state_yaml", content: actionStateStoreYamlContent},
			},
			copyActionStore: copyActionStoreProvider(os.ReadFile, os.WriteFile),
			expectedError:   nil,
		},
		"should skip copying action store file that does not exist": {
			files: []testFile{
				{name: "action_store", content: actionStoreContent},
				{name: "state_yaml", content: actionStateStoreYamlContent},
			},
			copyActionStore: copyActionStoreProvider(os.ReadFile, os.WriteFile),
			expectedError:   nil,
		},
		"should return error if it cannot read the action store files": {
			files: []testFile{
				{name: "action_store", content: actionStoreContent},
				{name: "state_yaml", content: actionStateStoreYamlContent},
				{name: "state_enc", content: actionStateStoreFileContent},
			},
			copyActionStore: copyActionStoreProvider(func(name string) ([]byte, error) {
				return nil, testError
			}, os.WriteFile),
			expectedError: testError,
		},
		"should return error if it cannot write the action store files": {
			files: []testFile{
				{name: "action_store", content: actionStoreContent},
				{name: "state_yaml", content: actionStateStoreYamlContent},
				{name: "state_enc", content: actionStateStoreFileContent},
			},
			copyActionStore: copyActionStoreProvider(os.ReadFile, func(name string, data []byte, perm os.FileMode) error {
				return testError
			}),
			expectedError: testError,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			newHome := filepath.Join(baseDir, "new_home")
			paths.SetTop(baseDir)

			actionStorePath := paths.AgentActionStoreFile()
			actionStateStoreYamlPath := paths.AgentStateStoreYmlFile()
			actionStateStoreFilePath := paths.AgentStateStoreFile()

			newActionStorePaths := []string{}

			for _, file := range testCase.files {
				path := ""

				switch file.name {
				case "action_store":
					path = actionStorePath
				case "state_yaml":
					path = actionStateStoreYamlPath
				case "state_enc":
					path = actionStateStoreFilePath
				}

				// Create the action store directories and files
				dir := filepath.Dir(path)
				err := os.MkdirAll(dir, 0o755)
				require.NoError(t, err, "error creating directory %s", dir)

				err = os.WriteFile(path, []byte(file.content), 0o600)
				require.NoError(t, err, "error writing to %s", path)

				// Create the new action store directories
				newActionStorePath := filepath.Join(newHome, filepath.Base(path))
				newActionStorePaths = append(newActionStorePaths, newActionStorePath)
				err = os.MkdirAll(filepath.Dir(newActionStorePath), 0o755)
				require.NoError(t, err, "error creating directory %s", filepath.Dir(newActionStorePath))
			}

			err := testCase.copyActionStore(log, newHome)
			if testCase.expectedError != nil {
				require.Error(t, err, "copyActionStoreFunc should return error")
				require.ErrorIs(t, err, testCase.expectedError, "copyActionStoreFunc error mismatch")
				return
			}

			require.NoError(t, err, "error copying action store")

			for i, path := range newActionStorePaths {
				require.FileExists(t, path, "file %s does not exist", path)

				content, err := os.ReadFile(path)
				require.NoError(t, err, "error reading from %s", path)
				require.Equal(t, []byte(testCase.files[i].content), content, "content of %s is not as expected", path)
			}
		})
	}
}

func TestCopyRunDirectory(t *testing.T) {
	log, _ := loggertest.New("TestCopyRunDirectory")

	type testCase struct {
		expectedError    error
		copyRunDirectory copyRunDirectoryFunc
	}

	testCases := map[string]testCase{
		"should copy old run directory to new run directory": {
			expectedError:    nil,
			copyRunDirectory: copyRunDirectoryProvider(os.MkdirAll, copy.Copy),
		},
		"should return error if it cannot create the new run directory": {
			expectedError: fs.ErrPermission,
			copyRunDirectory: copyRunDirectoryProvider(func(path string, perm os.FileMode) error {
				return fs.ErrPermission
			}, copy.Copy),
		},
		"should return error if it cannot copy the old run directory": {
			expectedError: errors.New("test error"),
			copyRunDirectory: copyRunDirectoryProvider(os.MkdirAll, func(src, dest string, opts ...copy.Options) error {
				return errors.New("test error")
			}),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			paths.SetTop(baseDir)

			oldRunPath := filepath.Join(baseDir, "old_dir", "run")
			oldRunFile := filepath.Join(oldRunPath, "file.txt")

			err := os.MkdirAll(oldRunPath, 0o700)
			require.NoError(t, err, "error creating old run directory")

			err = os.WriteFile(oldRunFile, []byte("content for old run file"), 0o600)
			require.NoError(t, err, "error writing to %s", oldRunFile)

			newRunPath := filepath.Join(baseDir, "new_dir", "run")

			err = os.MkdirAll(newRunPath, 0o700)
			require.NoError(t, err, "error creating new run directory")

			err = testCase.copyRunDirectory(log, oldRunPath, newRunPath)
			if testCase.expectedError != nil {
				require.Error(t, err, "copyRunDirectoryFunc should return error")
				require.ErrorIs(t, err, testCase.expectedError, "copyRunDirectoryFunc should return test error")
				return
			}

			require.NoError(t, err, "error copying run directory")
			require.DirExists(t, newRunPath, "new run directory does not exist")

			require.FileExists(t, filepath.Join(newRunPath, "file.txt"), "file.txt does not exist in new run directory")

			content, err := os.ReadFile(filepath.Join(newRunPath, "file.txt"))
			require.NoError(t, err, "error reading from %s", filepath.Join(newRunPath, "file.txt"))
			require.Equal(t, []byte("content for old run file"), content, "content of %s is not as expected", filepath.Join(newRunPath, "file.txt"))
		})
	}
}

type mockSender struct{}

func (m *mockSender) Send(ctx context.Context, method, path string, params url.Values, headers http.Header, body io.Reader) (*http.Response, error) {
	return nil, nil
}

func (m *mockSender) URI() string {
	return "mockURI"
}
func TestSetClient(t *testing.T) {
	log, _ := loggertest.New("test")
	upgrader := &Upgrader{
		log:                log,
		artifactDownloader: &mockArtifactDownloader{},
	}

	upgrader.SetClient(&mockSender{})
	require.Equal(t, "mockURI", upgrader.artifactDownloader.(*mockArtifactDownloader).fleetServerURI)
}
