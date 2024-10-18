// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	corev1 "k8s.io/api/core/v1"
)

var (
	kubeStackChartURL     = "https://github.com/open-telemetry/opentelemetry-helm-charts/releases/download/opentelemetry-kube-stack-0.3.2/opentelemetry-kube-stack-0.3.2.tgz"
	kubeStackChartVersion = "0.3.2"
)

func TestOtelKubeStackHelm(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			// only test the basic and the wolfi container with otel
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "wolfi"},
		},
		Group: define.Kubernetes,
	})

	client, err := info.KubeClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	testLogsBasePath := os.Getenv("K8S_TESTS_POD_LOGS_BASE")
	require.NotEmpty(t, testLogsBasePath, "K8S_TESTS_POD_LOGS_BASE must be set")

	err = os.MkdirAll(filepath.Join(testLogsBasePath, t.Name()), 0o755)
	require.NoError(t, err, "failed to create test logs directory")

	namespace := info.Namespace

	esHost := os.Getenv("ELASTICSEARCH_HOST")
	require.NotEmpty(t, esHost, "ELASTICSEARCH_HOST must be set")

	esAPIKey, err := generateESAPIKey(info.ESClient, namespace)
	require.NoError(t, err, "failed to generate ES API key")
	require.NotEmpty(t, esAPIKey, "failed to generate ES API key")

	chartOptions := &action.ChartPathOptions{
		RepoURL: "https://github.com/open-telemetry/opentelemetry-helm-charts/releases/download/opentelemetry-kube-stack-0.3.2/opentelemetry-kube-stack-0.3.2.tgz",
		Version: "0.3.0",
	}

	chartLocation, err := action.NewPull().LocateChart(chartOptions.RepoURL, cli.New())
	if err != nil {
		panic(err)
	}

	testCases := []struct {
		name                       string
		valuesFile                 string
		atLeastValidatedPodsNumber int
	}{
		{
			name:       "helm standalone agent default kubernetes privileged",
			valuesFile: "../../deploy/helm/edot-collector/kube-stack/values.yaml",
			// - perNode Daemonset (at least 1 agent pod)
			// - clusterWide Deployment  (1 agent pod)
			// - operator Deployment  (1 agent pod)
			atLeastValidatedPodsNumber: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			hasher := sha256.New()
			hasher.Write([]byte(tc.name))
			testNamespace := strings.ToLower(base64.URLEncoding.EncodeToString(hasher.Sum(nil)))
			testNamespace = noSpecialCharsRegexp.ReplaceAllString(testNamespace, "")

			settings := cli.New()
			settings.SetNamespace(testNamespace)
			actionConfig := &action.Configuration{}

			helmChart, err := loader.Load(chartLocation)
			require.NoError(t, err, "failed to load helm chart")

			err = actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "",
				func(format string, v ...interface{}) {})
			require.NoError(t, err, "failed to init helm action config")

			yamlFile, err := os.ReadFile(tc.valuesFile)
			if err != nil {
				require.NoError(t, err, "failed to read helm chart values file")
			}

			// Initialize a map to hold the parsed data
			helmValues := make(map[string]any)

			// Unmarshal the YAML into the map
			err = yaml.Unmarshal(yamlFile, &helmValues)
			if err != nil {
				log.Fatalf("Error unmarshalling YAML: %v", err)
			}

			t.Cleanup(func() {
				if t.Failed() {
					dumpLogs(t, ctx, client, testNamespace, testLogsBasePath)
				}

				uninstallAction := action.NewUninstall(actionConfig)
				uninstallAction.Wait = true

				_, err = uninstallAction.Run("helm-agent")
				if err != nil {
					require.NoError(t, err, "failed to uninstall helm chart")
				}
			})

			installAction := action.NewInstall(actionConfig)
			installAction.Namespace = testNamespace
			installAction.CreateNamespace = true
			installAction.UseReleaseName = true
			installAction.ReleaseName = "helm-agent"
			installAction.Timeout = 2 * time.Minute
			installAction.Wait = true
			installAction.WaitForJobs = true
			_, err = installAction.Run(helmChart, helmValues)
			require.NoError(t, err, "failed to install helm chart")

			podList := &corev1.PodList{}
			err = client.Resources(testNamespace).List(ctx, podList)
			require.NoError(t, err, fmt.Sprintf("failed to list pods in namespace %s", testNamespace))

			checkedAgentContainers := 0

			for _, pod := range podList.Items {
				if !strings.HasPrefix(pod.GetName(), "kube-stack-") {
					continue
				}

				checkedAgentContainers++
			}

			require.GreaterOrEqual(t, checkedAgentContainers, tc.atLeastValidatedPodsNumber,
				fmt.Sprintf("at least %d agent containers should be checked", tc.atLeastValidatedPodsNumber))
		})
	}
}
