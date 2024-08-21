// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/testing/proxytest"
)

func TestVerify(t *testing.T) {
	targetDir := t.TempDir()

	log, _ := logger.New("", false)
	timeout := 30 * time.Second
	testCases := getRandomTestCases()[0:1]
	server, pub := getElasticCoServer(t)

	config := &artifact.Config{
		SourceURI:       server.URL + "/downloads",
		TargetDirectory: targetDir,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: timeout,
		},
	}

	t.Run("without proxy", func(t *testing.T) {
		runTests(t, testCases, config, log, pub)
	})

	t.Run("with proxy", func(t *testing.T) {
		brokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			t.Log("[brokenServer] wrong server, is the proxy working?")
			_, _ = w.Write([]byte(`wrong server, is the proxy working?`))
		}))
		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err, "could not parse server URL \"%s\"",
			server.URL)

		proxy := proxytest.New(t,
			proxytest.WithRewriteFn(func(u *url.URL) {
				u.Host = serverURL.Host
			}),
			proxytest.WithRequestLog("proxy", func(_ string, _ ...any) {}))
		err = proxy.Start()
		require.NoError(t, err, "error starting proxytest")
		defer proxy.Close()
		proxyURL, err := url.Parse(proxy.LocalhostURL)
		require.NoError(t, err, "could not parse server URL \"%s\"",
			server.URL)

		config := *config
		config.SourceURI = brokenServer.URL + "/downloads"
		config.Proxy = httpcommon.HTTPClientProxySettings{
			URL: (*httpcommon.ProxyURI)(proxyURL),
		}

		runTests(t, testCases, &config, log, pub)
	})
}

func runTests(t *testing.T, testCases []testCase, config *artifact.Config, log *logger.Logger, pub []byte) {
	for _, tc := range testCases {
		testName := fmt.Sprintf("%s-binary-%s", tc.system, tc.arch)
		t.Run(testName, func(t *testing.T) {
			config.OperatingSystem = tc.system
			config.Architecture = tc.arch

			upgradeDetails := details.NewDetails(
				"8.12.0", details.StateRequested, "")
			downloader, err := NewDownloader(log, config, upgradeDetails)
			require.NoError(t, err, "could not create new downloader")

			pkgPath, err := downloader.Download(context.Background(), beatSpec, version)
			require.NoErrorf(t, err, "failed downloading %s v%s",
				beatSpec.Artifact, version)

			_, err = os.Stat(pkgPath)
			if err != nil {
				t.Fatal(err)
			}

			testVerifier, err := NewVerifier(log, config, pub)
			if err != nil {
				t.Fatal(err)
			}

			err = testVerifier.Verify(beatSpec, *version, false)
			require.NoError(t, err)
		})
	}
}

func getRandomTestCases() []testCase {
	tt := getTestCases()

	first := rand.IntN(len(tt))
	second := rand.IntN(len(tt))

	return []testCase{
		tt[first],
		tt[second],
	}
}
