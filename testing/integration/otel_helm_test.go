// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
		name  string
		steps []k8sTestStep
	}{
		{
			name: "helm kube-stack operator standalone agent kubernetes privileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeployWithValues(chartLocation, "kube-stack-otel",
					values.Options{
						ValueFiles: []string{"../../deploy/helm/edot-collector/kube-stack/values.yaml"},
						Values:     []string{fmt.Sprintf("defaultCRConfig.image.repository=%s", kCtx.agentImageRepo), fmt.Sprintf("defaultCRConfig.image.tag=%s", kCtx.agentImageTag)},

						// override secrets reference with env variables
						JSONValues: []string{
							fmt.Sprintf(`collectors.gateway.env[1]={"name":"ELASTIC_ENDPOINT","value":"%s"}`, kCtx.esHost),
							fmt.Sprintf(`collectors.gateway.env[2]={"name":"ELASTIC_API_KEY","value":"%s"}`, kCtx.esAPIKey),
						},
					},
				),
				// - An OpenTelemetry Operator Deployment (1 pod per
				// cluster)
				k8sStepCheckRunningPods("app.kubernetes.io/name=opentelemetry-operator", 1, "manager"),
				// - A Daemonset to collect K8s node's metrics and logs
				// (1 EDOT collector pod per node)
				// - A Cluster wide Deployment to collect K8s metrics and
				// events (1 EDOT collector pod per cluster)
				// - Two Gateway pods to collect, aggregate and forward
				// telemetry.
				k8sStepCheckRunningPods("app.kubernetes.io/managed-by=opentelemetry-operator", 4, "otc-container"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			testNamespace := kCtx.getNamespace(t)

			for _, step := range tc.steps {
				step(t, ctx, kCtx, testNamespace)
			}
		})
	}
}

func k8sStepHelmDeployWithValues(chartPath string, releaseName string, values values.Options) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		// Initialize a map to hold the parsed data
		helmValues := make(map[string]any)

		settings := cli.New()
		settings.SetNamespace(namespace)
		providers := getter.All(settings)
		helmValues, err := values.MergeValues(providers)
		if err != nil {
			require.NoError(t, err, "failed to helm values")
		}

		k8sStepHelmDeploy(chartPath, releaseName, helmValues)(t, ctx, kCtx, namespace)
	}
}

// k8sStepCheckRunningPods checks the status of the agent inside the pods returned by the selector
func k8sStepCheckRunningPods(podLabelSelector string, expectedPodNumber int, containerName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.Eventually(t, func() bool {
			perNodePodList := &corev1.PodList{}
			err := kCtx.client.Resources(namespace).List(ctx, perNodePodList, func(opt *metav1.ListOptions) {
				opt.LabelSelector = podLabelSelector
			})
			require.NoError(t, err, "failed to list pods with selector ", perNodePodList)
			checkedAgentContainers := 0

			for _, pod := range perNodePodList.Items {
				if pod.Status.Phase != corev1.PodRunning {
					continue
				}

				for _, container := range pod.Status.ContainerStatuses {
					if container.Name != containerName {
						continue
					}

					if container.RestartCount == 0 && container.State.Running != nil {
						checkedAgentContainers++
					}
				}
			}
			return checkedAgentContainers >= expectedPodNumber
		}, 5*time.Minute, 10*time.Second, fmt.Sprintf("at least %d agent containers should be checked", expectedPodNumber))
	}
}
