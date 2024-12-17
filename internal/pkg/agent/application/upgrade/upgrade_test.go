// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
	mocks "github.com/elastic/elastic-agent/testing/mocks/pkg/control/v2/client"
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

			err := copyDir(l, tc.From, tc.To, tc.IgnoreErr)
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
      - "RSA-AES-256-GCM-SHA384"
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
					tlscommon.CipherSuite(tls.TLS_RSA_WITH_AES_256_GCM_SHA384),
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
`}, {
			name:      "only sourceURI",
			sourceURL: "https://this.sourceURI.co/downloads/beats/",
			cfg: `
agent.download:
  sourceURI: "https://this.sourceURI.co/downloads/beats/"
`}, {
			name:      "only source_uri",
			sourceURL: "https://this.sourceURI.co/downloads/beats/",
			cfg: `
agent.download:
  source_uri: "https://this.sourceURI.co/downloads/beats/"
`},
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

var agentVersion123SNAPSHOTabcdefRepackaged = agentVersion{
	version:  "1.2.3-repackaged",
	snapshot: true,
	hash:     "abcdef",
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

func TestIsSameVersion(t *testing.T) {
	type args struct {
		current  agentVersion
		metadata packageMetadata
		version  string
	}
	type want struct {
		same       bool
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
				current: agentVersion123SNAPSHOTabcdef,
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
				same:       true,
				newVersion: agentVersion123SNAPSHOTabcdef,
			},
		},
		{
			name: "same hash, snapshot flag, different version",
			args: args{
				current: agentVersion123SNAPSHOTabcdef,
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
				same:       false,
				newVersion: agentVersion123SNAPSHOTabcdefRepackaged,
			},
		},
		{
			name: "same version and hash, different snapshot flag (SNAPSHOT promotion to release)",
			args: args{
				current: agentVersion123SNAPSHOTabcdef,
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
				same:       false,
				newVersion: agentVersion123abcdef,
			},
		},
		{
			name: "same version and snapshot, different hash (SNAPSHOT upgrade)",
			args: args{
				current: agentVersion123SNAPSHOTabcdef,
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
				same:       false,
				newVersion: agentVersion123SNAPSHOTghijkl,
			},
		},
		{
			name: "same version, snapshot flag and hash, no manifest",
			args: args{
				current: agentVersion123SNAPSHOTabcdef,
				metadata: packageMetadata{
					manifest: nil,
					hash:     "abcdef",
				},
				version: "1.2.3-SNAPSHOT",
			},
			want: want{
				same:       true,
				newVersion: agentVersion123SNAPSHOTabcdef,
			},
		},
		{
			name: "same hash, snapshot flag, different version, no manifest",
			args: args{
				current: agentVersion123SNAPSHOTabcdef,
				metadata: packageMetadata{
					manifest: nil,
					hash:     "abcdef",
				},
				version: "1.2.3-SNAPSHOT.repackaged",
			},
			want: want{
				same:       false,
				newVersion: agentVersion123SNAPSHOTabcdefRepackaged,
			},
		},
		{
			name: "same version and hash, different snapshot flag, no manifest (SNAPSHOT promotion to release)",
			args: args{
				current: agentVersion123SNAPSHOTabcdef,
				metadata: packageMetadata{
					manifest: nil,
					hash:     "abcdef",
				},
				version: "1.2.3",
			},
			want: want{
				same:       false,
				newVersion: agentVersion123abcdef,
			},
		},
		{
			name: "same version and snapshot, different hash (SNAPSHOT upgrade)",
			args: args{
				current: agentVersion123SNAPSHOTabcdef,
				metadata: packageMetadata{
					manifest: nil,
					hash:     "ghijkl",
				},
				version: "1.2.3-SNAPSHOT",
			},
			want: want{
				same:       false,
				newVersion: agentVersion123SNAPSHOTghijkl,
			},
		},
		{
			name: "same version and snapshot, no hash (SNAPSHOT upgrade before download)",
			args: args{
				current: agentVersion123SNAPSHOTabcdef,
				metadata: packageMetadata{
					manifest: nil,
				},
				version: "1.2.3-SNAPSHOT",
			},
			want: want{
				same: false,
				newVersion: agentVersion{
					version:  "1.2.3",
					snapshot: true,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			log, _ := loggertest.New(test.name)
			actualSame, actualNewVersion := isSameVersion(log, test.args.current, test.args.metadata, test.args.version)

			assert.Equal(t, test.want.same, actualSame, "Unexpected boolean comparison result: isSameVersion(%v, %v, %v, %v) should be %v",
				log, test.args.current, test.args.metadata, test.args.version, test.want.same)
			assert.Equal(t, test.want.newVersion, actualNewVersion, "Unexpected new version result: isSameVersion(%v, %v, %v, %v) should be %v",
				log, test.args.current, test.args.metadata, test.args.version, test.want.newVersion)
		})
	}
}

func TestWaitForWatcher(t *testing.T) {
	wantErrWatcherNotStarted := func(t assert.TestingT, err error, i ...interface{}) bool {
		return assert.ErrorIs(t, err, ErrWatcherNotStarted, i)
	}

	tests := []struct {
		name                string
		states              []details.State
		stateChangeInterval time.Duration
		cancelWaitContext   bool
		wantErr             assert.ErrorAssertionFunc
	}{
		{
			name:                "Happy path: watcher is watching already",
			states:              []details.State{details.StateWatching},
			stateChangeInterval: 1 * time.Millisecond,
			wantErr:             assert.NoError,
		},
		{
			name:                "Sad path: watcher is never starting",
			states:              []details.State{details.StateReplacing},
			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
		{
			name: "Runaround path: marker is jumping around and landing on watching",
			states: []details.State{
				details.StateRequested,
				details.StateScheduled,
				details.StateDownloading,
				details.StateExtracting,
				details.StateReplacing,
				details.StateRestarting,
				details.StateWatching,
			},
			stateChangeInterval: 1 * time.Millisecond,
			wantErr:             assert.NoError,
		},
		{
			name:                "Timeout: marker is never created",
			states:              nil,
			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
		{
			name: "Timeout2: state doesn't get there in time",
			states: []details.State{
				details.StateRequested,
				details.StateScheduled,
				details.StateDownloading,
				details.StateExtracting,
				details.StateReplacing,
				details.StateRestarting,
			},

			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			deadline, ok := t.Deadline()
			if !ok {
				deadline = time.Now().Add(5 * time.Second)
			}
			testCtx, testCancel := context.WithDeadline(context.Background(), deadline)
			defer testCancel()

			tmpDir := t.TempDir()
			updMarkerFilePath := filepath.Join(tmpDir, markerFilename)

			waitContext, waitCancel := context.WithCancel(testCtx)
			defer waitCancel()

			fakeTimeout := 30 * time.Second

			// in order to take timing out of the equation provide a context that we can cancel manually
			// still assert that the parent context and timeout passed are correct
			var createContextFunc createContextWithTimeout = func(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				assert.Same(t, testCtx, ctx, "parent context should be the same as the waitForWatcherCall")
				assert.Equal(t, fakeTimeout, timeout, "timeout used in new context should be the same as testcase")

				return waitContext, waitCancel
			}

			if len(tt.states) > 0 {
				initialState := tt.states[0]
				writeState(t, updMarkerFilePath, initialState)
			}

			wg := new(sync.WaitGroup)

			var furtherStates []details.State
			if len(tt.states) > 1 {
				// we have more states to produce
				furtherStates = tt.states[1:]
			}

			wg.Add(1)

			// worker goroutine: writes out additional states while the test is blocked on waitOnWatcher() call and expires
			// the wait context if cancelWaitContext is set to true. Timing of the goroutine is driven by stateChangeInterval.
			go func() {
				defer wg.Done()
				tick := time.NewTicker(tt.stateChangeInterval)
				defer tick.Stop()
				for _, state := range furtherStates {
					select {
					case <-testCtx.Done():
						return
					case <-tick.C:
						writeState(t, updMarkerFilePath, state)
					}
				}
				if tt.cancelWaitContext {
					<-tick.C
					waitCancel()
				}
			}()

			log, _ := loggertest.New(tt.name)

			tt.wantErr(t, waitForWatcherWithTimeoutCreationFunc(testCtx, log, updMarkerFilePath, fakeTimeout, createContextFunc), fmt.Sprintf("waitForWatcher %s, %v, %s, %s)", updMarkerFilePath, tt.states, tt.stateChangeInterval, fakeTimeout))

			// wait for goroutines to finish
			wg.Wait()
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
			assert.Equalf(t, paths.BinaryPath(filepath.Join(fakeTopDir, tt.want), agentName), selectWatcherExecutable(fakeTopDir, tt.args.previous, tt.args.current), "selectWatcherExecutable(%v, %v)", tt.args.previous, tt.args.current)
		})
	}
}

func TestIsSameReleaseVersion(t *testing.T) {
	tests := []struct {
		name    string
		current agentVersion
		target  string
		expect  bool
	}{{
		name: "current version is snapshot",
		current: agentVersion{
			version:  "1.2.3",
			snapshot: true,
		},
		target: "1.2.3",
		expect: false,
	}, {
		name: "target version is snapshot",
		current: agentVersion{
			version: "1.2.3",
		},
		target: "1.2.3-SNAPSHOT",
		expect: false,
	}, {
		name: "target version is different version",
		current: agentVersion{
			version: "1.2.3",
		},
		target: "1.2.4",
		expect: false,
	}, {
		name: "target version is same with pre-release",
		current: agentVersion{
			version: "1.2.3",
		},
		target: "1.2.3-custom.info",
		expect: false,
	}, {
		name: "target version is same with build",
		current: agentVersion{
			version: "1.2.3",
		},
		target: "1.2.3+buildID",
		expect: false,
	}, {
		name: "target version is same",
		current: agentVersion{
			version: "1.2.3",
		},
		target: "1.2.3",
		expect: true,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, isSameReleaseVersion(tc.current, tc.target))
		})
	}
}
