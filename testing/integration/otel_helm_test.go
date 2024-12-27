// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

var (
	kubeStackChartVersion = "0.3.9"
	kubeStackChartURL     = "https://github.com/open-telemetry/opentelemetry-helm-charts/releases/download/opentelemetry-kube-stack-" + kubeStackChartVersion + "/opentelemetry-kube-stack-" + kubeStackChartVersion + ".tgz"
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

	kCtx := k8sGetContext(t, info)

	chartOptions := &action.ChartPathOptions{
		RepoURL: kubeStackChartURL,
		Version: kubeStackChartVersion,
	}

	chartLocation, err := action.NewPull().LocateChart(chartOptions.RepoURL, cli.New())
	if err != nil {
		panic(err)
	}

	testCases := []struct {
		name                       string
		helmReleaseName            string
		valuesFile                 string
		atLeastValidatedPodsNumber int
	}{
		{
			name:            "helm standalone agent default kubernetes privileged",
			helmReleaseName: "kube-stack-otel",
			valuesFile:      "../../deploy/helm/edot-collector/kube-stack/values.yaml",
			// - A Daemonset to collect K8s node's metrics and logs
			// (1 EDOT collector pod per node)
			// - A Cluster wide Deployment to collect K8s metrics and
			// events (1 EDOT collector pod per cluster)
			// - Two Gateway pods to collect, aggregate and forward
			// telemetry.
			// - An OpenTelemetry Operator Deployment (1 pod per
			// cluster)
			atLeastValidatedPodsNumber: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			testNamespace := kCtx.getNamespace(t)

			settings := cli.New()
			settings.SetNamespace(testNamespace)
			actionConfig := &action.Configuration{}

			helmChart, err := loader.Load(chartLocation)
			require.NoError(t, err, "failed to load helm chart")

			err = actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "",
				func(format string, v ...interface{}) {})
			require.NoError(t, err, "failed to init helm action config")

			// Initialize a map to hold the parsed data
			helmValues := make(map[string]any)

			options := values.Options{
				ValueFiles: []string{tc.valuesFile},
				Values:     []string{fmt.Sprintf("defaultCRConfig.image.repository=%s", kCtx.agentImageRepo), fmt.Sprintf("defaultCRConfig.image.tag=%s", kCtx.agentImageTag)},

				// override secrets reference with env variables
				JSONValues: []string{
					fmt.Sprintf(`collectors.cluster.env[1]={"name":"ELASTIC_ENDPOINT","value":"%s"}`, kCtx.esHost),
					fmt.Sprintf(`collectors.cluster.env[2]={"name":"ELASTIC_API_KEY","value":"%s"}`, kCtx.esAPIKey),
					fmt.Sprintf(`collectors.daemon.env[2]={"name":"ELASTIC_ENDPOINT","value":"%s"}`, kCtx.esHost),
					fmt.Sprintf(`collectors.daemon.env[3]={"name":"ELASTIC_API_KEY","value":"%s"}`, kCtx.esAPIKey),
				},
			}
			providers := getter.All(settings)
			helmValues, err = options.MergeValues(providers)
			if err != nil {
				require.NoError(t, err, "failed to helm values")
			}

			t.Cleanup(func() {
				if t.Failed() {
					if err := k8sDumpAllPodLogs(ctx, kCtx.client, testNamespace, testNamespace, kCtx.logsBasePath); err != nil {
						t.Logf("failed to dump logs: %s", err)
					}
				}

				uninstallAction := action.NewUninstall(actionConfig)
				uninstallAction.Wait = true

				_, err = uninstallAction.Run(tc.helmReleaseName)
				if err != nil {
					require.NoError(t, err, "failed to uninstall helm chart")
				}
			})

			installAction := action.NewInstall(actionConfig)
			installAction.Namespace = testNamespace
			installAction.CreateNamespace = true
			installAction.UseReleaseName = true
			installAction.ReleaseName = tc.helmReleaseName
			installAction.Timeout = 2 * time.Minute
			installAction.Wait = true
			installAction.WaitForJobs = true
			_, err = installAction.Run(helmChart, helmValues)
			require.NoError(t, err, "failed to install helm chart")

			// Pods are created by the OpenTelemetry Operator, it
			// takes some time for the OpenTelemetry Operator to be
			// ready
			require.Eventually(t, func() bool {
				podList := &corev1.PodList{}
				err = kCtx.client.Resources(testNamespace).List(ctx, podList)
				require.NoError(t, err, fmt.Sprintf("failed to list pods in namespace %s", testNamespace))

				checkedAgentContainers := 0

				for _, pod := range podList.Items {
					if strings.HasPrefix(pod.GetName(), tc.helmReleaseName) && pod.Status.Phase == corev1.PodRunning {
						checkedAgentContainers++
					}
				}
				return checkedAgentContainers >= tc.atLeastValidatedPodsNumber
			}, 5*time.Minute, 10*time.Second, fmt.Sprintf("at least %d agent containers should be checked", tc.atLeastValidatedPodsNumber))
		})
	}
}
