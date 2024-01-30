// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/client/mocks"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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
	l, _ := logger.New("test", false)
	tmpDir, err := os.MkdirTemp("", "shutdown-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// make homepath agent consistent (in a form of elastic-agent-hash)
	homePath := filepath.Join(tmpDir, fmt.Sprintf("%s-%s", agentName, release.ShortCommit()))

	filename := "file.test"
	newCommit := "abc123"
	sourceVersion := "7.14.0"
	targetVersion := "7.15.0"

	content := []byte("content")
	newHome := strings.ReplaceAll(homePath, release.ShortCommit(), newCommit)
	sourceDir := filepath.Join(homePath, "run", "default", "process-"+sourceVersion)
	targetDir := filepath.Join(newHome, "run", "default", "process-"+targetVersion)

	require.NoError(t, os.MkdirAll(sourceDir, 0755))
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	cb := shutdownCallback(l, homePath, sourceVersion, targetVersion, newCommit)

	oldFilename := filepath.Join(sourceDir, filename)
	err = os.WriteFile(oldFilename, content, 0640)
	require.NoError(t, err, "preparing file failed")

	err = cb()
	require.NoError(t, err, "callback failed")

	newFilename := filepath.Join(targetDir, filename)
	newContent, err := os.ReadFile(newFilename)
	require.NoError(t, err, "reading file failed")
	require.Equal(t, content, newContent, "contents are not equal")
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

	log, _ := logger.NewTesting("")
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
			log, _ := logger.NewTesting("")

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
