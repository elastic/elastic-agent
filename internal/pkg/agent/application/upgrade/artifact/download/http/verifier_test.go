// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestVerify(t *testing.T) {
	targetDir := t.TempDir()

	log, _ := logger.New("", false)
	timeout := 30 * time.Second
	testCases := getRandomTestCases()
	server, pub := getElasticCoServer(t)
	elasticClient := getElasticCoClient(server)
	// http.Verifier uses http.DefaultClient, thus we need to change it
	http.DefaultClient = &elasticClient

	config := &artifact.Config{
		SourceURI:       source,
		TargetDirectory: targetDir,
		HTTPTransportSettings: httpcommon.HTTPTransportSettings{
			Timeout: timeout,
		},
	}

	for _, testCase := range testCases {
		testName := fmt.Sprintf("%s-binary-%s", testCase.system, testCase.arch)
		t.Run(testName, func(t *testing.T) {
			config.OperatingSystem = testCase.system
			config.Architecture = testCase.arch

			testClient := NewDownloaderWithClient(log, config, elasticClient)
			artifact, err := testClient.Download(context.Background(), beatSpec, version)
			if err != nil {
				t.Fatal(err)
			}

			_, err = os.Stat(artifact)
			if err != nil {
				t.Fatal(err)
			}

			testVerifier, err := NewVerifier(log, config, pub)
			if err != nil {
				t.Fatal(err)
			}

			err = testVerifier.Verify(beatSpec, version, false)
			require.NoError(t, err)

			os.Remove(artifact)
			os.Remove(artifact + ".sha512")
		})
	}
}

func getRandomTestCases() []testCase {
	tt := getTestCases()

	first := rand.Intn(len(tt))
	second := rand.Intn(len(tt))

	return []testCase{
		tt[first],
		tt[second],
	}
}
