// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	testK8s "github.com/elastic/elastic-agent/pkg/testing/kubernetes"
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
			// elastic otel collector image
			{Type: define.Kubernetes, DockerVariant: "elastic-otel-collector"},
			{Type: define.Kubernetes, DockerVariant: "elastic-otel-collector-wolfi"},
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
			name: "managed helm kube-stack operator standalone agent kubernetes privileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeployWithValueOptions(chartLocation, "kube-stack-otel",
					values.Options{
						ValueFiles: []string{"../../deploy/helm/edot-collector/kube-stack/values.yaml"},
						Values: []string{
							fmt.Sprintf("defaultCRConfig.image.repository=%s", kCtx.agentImageRepo),
							fmt.Sprintf("defaultCRConfig.image.tag=%s", kCtx.agentImageTag),
							// override cluster wide
							// endpoint for tests
							"instrumentation.exporter.endpoint=http://opentelemetry-kube-stack-daemon-collector:4318",
						},

						// override secrets reference with env variables
						JSONValues: []string{
							fmt.Sprintf(`collectors.gateway.env[1]={"name":"ELASTIC_ENDPOINT","value":"%s"}`, kCtx.esHost),
							fmt.Sprintf(`collectors.gateway.env[2]={"name":"ELASTIC_API_KEY","value":"%s"}`, kCtx.esEncodedAPIKey),
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
				// validate k8s metrics are being pushed
				k8sStepCheckDatastreamsHits(info, "metrics", "kubeletstatsreceiver.otel", "default"),
				k8sStepCheckDatastreamsHits(info, "metrics", "k8sclusterreceiver.otel", "default"),
				// validates auto-instrumentation and traces
				// datastream generation
				func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
					k8sStepDeployJavaApp()(t, ctx, kCtx, namespace)
					k8sStepCheckDatastreamsHits(info, "traces", "generic.otel", "default")(t, ctx, kCtx, namespace)
				},
			},
		},
		{
			name: "mOTel helm kube-stack operator standalone agent kubernetes privileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeployWithValueOptions(chartLocation, "kube-stack-otel",
					values.Options{
						ValueFiles: []string{"../../deploy/helm/edot-collector/kube-stack/managed_otlp/values.yaml"},
						Values:     []string{fmt.Sprintf("defaultCRConfig.image.repository=%s", kCtx.agentImageRepo), fmt.Sprintf("defaultCRConfig.image.tag=%s", kCtx.agentImageTag)},

						// override secrets reference with env variables
						JSONValues: []string{
							// TODO: replace with managed OTLP ingest endpoint/apiKey when available
							fmt.Sprintf(`collectors.gateway.env[1]={"name":"ELASTIC_OTLP_ENDPOINT","value":"%s"}`, "https://otlp.ingest:433"),
							fmt.Sprintf(`collectors.gateway.env[2]={"name":"ELASTIC_API_KEY","value":"%s"}`, "CHANGEME=="),
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
				// - Two Gateway replicas to collect, aggregate and forward
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

func k8sStepHelmDeployWithValueOptions(chartPath string, releaseName string, values values.Options) k8sTestStep {
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

func k8sStepDeployJavaApp() k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		javaApp, err := os.ReadFile(filepath.Join("testdata", "java_app.yaml"))
		require.NoError(t, err)

		objects, err := testK8s.LoadFromYAML(bufio.NewReader(bytes.NewReader(javaApp)))
		require.NoError(t, err, "failed to parse rendered kustomize")

		err = k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: true, namespace: namespace}, objects...)
		require.NoError(t, err, "failed to create objects")
	}
}

// k8sStepCheckDatastreams checks the corresponding Elasticsearch datastreams
// are created and documents being written
func k8sStepCheckDatastreamsHits(info *define.Info, dsType, dataset, datastreamNamespace string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.Eventually(t, func() bool {
			query := queryK8sNamespaceDataStream(dsType, dataset, datastreamNamespace, namespace)
			docs, err := estools.PerformQueryForRawQuery(ctx, query, fmt.Sprintf(".ds-%s*", dsType), info.ESClient)
			require.NoError(t, err, "failed to get %s datastream documents", fmt.Sprintf("%s-%s-%s", dsType, dataset, datastreamNamespace))
			return docs.Hits.Total.Value > 0
		}, 5*time.Minute, 10*time.Second, fmt.Sprintf("at least one document should be available for %s datastream", fmt.Sprintf("%s-%s-%s", dsType, dataset, datastreamNamespace)))
	}
}

func queryK8sNamespaceDataStream(dsType, dataset, datastreamNamespace, k8snamespace string) map[string]any {
	return map[string]any{
		"_source": []string{"message"},
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					map[string]any{
						"term": map[string]any{
							"data_stream.dataset": dataset,
						},
					},
					map[string]any{
						"term": map[string]any{
							"data_stream.namespace": datastreamNamespace,
						},
					},
					map[string]any{
						"term": map[string]any{
							"data_stream.type": dsType,
						},
					},
					map[string]any{
						"term": map[string]any{
							"resource.attributes.k8s.namespace.name": k8snamespace,
						},
					},
				},
			},
		},
	}
}
