// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	testK8s "github.com/elastic/elastic-agent/pkg/testing/kubernetes"
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

	testCases := []struct {
		name  string
		steps []k8sTestStep
	}{
		{
			name: "managed helm kube-stack operator standalone agent kubernetes privileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepCreateOpenShiftInfrastructure(),
				k8sStepHelmDeployWithValueOptions(KubeStackChartPath, "kube-stack-otel",
					values.Options{
						ValueFiles: helmValuesWithOpenShiftOverlay(kCtx,
							"../../../deploy/helm/edot-collector/kube-stack/values.yaml"),
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
				k8sStepCheckNamespaceDatastreamHits(info, "metrics", "kubeletstatsreceiver.otel", "default"),
				k8sStepCheckNamespaceDatastreamHits(info, "metrics", "k8sclusterreceiver.otel", "default"),
				// validate the openshift resource detector reads the cluster name
				k8sStepCheckClusterNameDatastreamHits(info, "metrics", "k8sclusterreceiver.otel", "default"),
				// validates auto-instrumentation and traces
				// datastream generation
				func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
					k8sStepDeployJavaApp()(t, ctx, kCtx, namespace)
					k8sStepCheckNamespaceDatastreamHits(info, "traces", "generic.otel", "default")(t, ctx, kCtx, namespace)
				},
			},
		},
		{
			name: "mOTel helm kube-stack operator standalone agent kubernetes privileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeployWithValueOptions(KubeStackChartPath, "kube-stack-otel",
					values.Options{
						ValueFiles: helmValuesWithOpenShiftOverlay(kCtx,
							"../../../deploy/helm/edot-collector/kube-stack/managed_otlp/values.yaml"),
						Values: []string{fmt.Sprintf("defaultCRConfig.image.repository=%s", kCtx.agentImageRepo), fmt.Sprintf("defaultCRConfig.image.tag=%s", kCtx.agentImageTag)},

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
		{
			name: "mOTel logs only helm kube-stack operator standalone agent kubernetes privileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeployWithValueOptions(KubeStackChartPath, "kube-stack-otel",
					values.Options{
						ValueFiles: helmValuesWithOpenShiftOverlay(kCtx,
							"../../../deploy/helm/edot-collector/kube-stack/managed_otlp/logs-values.yaml"),
						Values: []string{fmt.Sprintf("defaultCRConfig.image.repository=%s", kCtx.agentImageRepo), fmt.Sprintf("defaultCRConfig.image.tag=%s", kCtx.agentImageTag)},

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
				// - A Daemonset to collect K8s node's logs
				// (1 EDOT collector pod per node)
				// - One Gateway replicas to collect, aggregate and forward
				// telemetry.
				k8sStepCheckRunningPods("app.kubernetes.io/managed-by=opentelemetry-operator", 2, "otc-container"),
			},
		},
		// Template+apply path: exercises "helm template | kubectl apply" instead of "helm install".
		// Catches config issues (e.g. missing/invalid debug exporter per #12878) that would
		// cause collector pods to crash at startup.
		{
			name: "mOTel with helm template apply kube-stack on cluster",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmTemplateApplyWithValueOptions(KubeStackChartPath, "kube-stack-otel",
					values.Options{
						ValueFiles: helmValuesWithOpenShiftOverlay(kCtx,
							"../../../deploy/helm/edot-collector/kube-stack/managed_otlp/values.yaml"),
						Values: []string{fmt.Sprintf("defaultCRConfig.image.repository=%s", kCtx.agentImageRepo), fmt.Sprintf("defaultCRConfig.image.tag=%s", kCtx.agentImageTag)},

						JSONValues: []string{
							fmt.Sprintf(`collectors.gateway.env[1]={"name":"ELASTIC_OTLP_ENDPOINT","value":"%s"}`, "https://otlp.ingest:433"),
							fmt.Sprintf(`collectors.gateway.env[2]={"name":"ELASTIC_API_KEY","value":"%s"}`, "CHANGEME=="),
							// Intentionally broken: debug exporter referenced in pipelines but not configured.
							// Uncomment following line to simulate #12878 - gateway collector will crash at startup failing the test
							// `collectors.gateway.config.exporters.debug=null`,
						},
					},
				),
				k8sStepCheckRunningPods("app.kubernetes.io/name=opentelemetry-operator", 1, "manager"),
				k8sStepCheckRunningPods("app.kubernetes.io/managed-by=opentelemetry-operator", 4, "otc-container"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background() //nolint:forbidigo // ctx is captured by t.Cleanup in step functions; must outlive the test
			testNamespace := kCtx.getNamespace(t)

			for _, step := range tc.steps {
				step(t, ctx, kCtx, testNamespace)
			}
		})
	}
}

func k8sStepHelmDeployWithValueOptions(chartPath string, releaseName string, values values.Options) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		helmValues := mergeValues(t, namespace, values)

		k8sStepHelmDeploy(chartPath, releaseName, helmValues)(t, ctx, kCtx, namespace)
	}
}

// k8sStepHelmTemplateApplyWithValueOptions is like k8sStepHelmDeployWithValueOptions but
// uses "helm template | kubectl apply" instead of "helm install". Exercises the
// template+apply path on the cluster; any config issues cause pods to fail and the
// test fails (e.g. #12878 - missing debug exporter).
func k8sStepHelmTemplateApplyWithValueOptions(chartPath string, releaseName string, values values.Options) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		helmValues := mergeValues(t, namespace, values)

		k8sStepHelmTemplateApply(chartPath, releaseName, helmValues)(t, ctx, kCtx, namespace)
	}
}

func mergeValues(t *testing.T, namespace string, values values.Options) map[string]any {
	settings := cli.New()
	settings.SetNamespace(namespace)
	providers := getter.All(settings)
	helmValues, err := values.MergeValues(providers)
	if err != nil {
		require.NoError(t, err, "failed to helm values")
	}
	return helmValues
}

// k8sStepCheckRunningPods checks the status of the agent inside the pods returned by the selector
func k8sStepCheckRunningPods(podLabelSelector string, expectedPodNumber int, containerName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.EventuallyWithTf(t, func(collectT *assert.CollectT) {
			perNodePodList := &corev1.PodList{}
			err := kCtx.client.Resources(namespace).List(ctx, perNodePodList, func(opt *metav1.ListOptions) {
				opt.LabelSelector = podLabelSelector
			})
			require.NoError(collectT,
				err, "failed to list pods with selector ", perNodePodList)

			require.Greaterf(collectT, len(perNodePodList.Items), 0,
				"no pod found for label selector %q", podLabelSelector)

			checkedAgentContainers := 0
			for _, pod := range perNodePodList.Items {
				if pod.Status.Phase != corev1.PodRunning {
					continue
				}

				for _, container := range pod.Status.ContainerStatuses {
					if container.Name != containerName {
						continue
					}

					if container.Ready {
						checkedAgentContainers++
					}
				}
			}

			require.GreaterOrEqualf(collectT,
				checkedAgentContainers, expectedPodNumber,
				"at least %d agent containers with name %q should be checked",
				expectedPodNumber, containerName)
		}, 5*time.Minute, 10*time.Second, fmt.Sprintf(
			"at least %d agent containers with name %q should be checked",
			expectedPodNumber, containerName))
	}
}

// k8sCreateOpenShiftInfrastructure creates the object that the openshift resource detector reads.
func k8sStepCreateOpenShiftInfrastructure() k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		if !kCtx.openshift {
			return
		}

		const infrastructureCrd = "infrastructures.config.openshift.io"

		// Only MicroShift needs this CRD. A real OpenShift cluster ships it and owns the
		// Infrastructure object, which holds the real cluster name.
		err := kCtx.client.Resources().Get(ctx, infrastructureCrd, "", &apiextensionsv1.CustomResourceDefinition{})
		if err == nil {
			t.Logf("the %q CRD already exists", infrastructureCrd)
			return
		}

		crd := &apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: infrastructureCrd},
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Group: configv1.GroupName,
				Scope: apiextensionsv1.ClusterScoped,
				Names: apiextensionsv1.CustomResourceDefinitionNames{
					Plural:   "infrastructures",
					Singular: "infrastructure",
					Kind:     "Infrastructure",
				},
				Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
					Name:    "v1",
					Served:  true,
					Storage: true,
					// The detector reads the status subresource.
					Subresources: &apiextensionsv1.CustomResourceSubresources{Status: &apiextensionsv1.CustomResourceSubresourceStatus{}},
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]apiextensionsv1.JSONSchemaProps{
								"spec":   {Type: "object", XPreserveUnknownFields: new(true)},
								"status": {Type: "object", XPreserveUnknownFields: new(true)},
							},
						},
					},
				}},
			},
		}

		err = k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: true}, crd)
		require.NoErrorf(t, err, "failed to create the %q CRD", infrastructureCrd)

		// Delete the CRD on test completion to also remove the Infrastructure object with it.
		t.Cleanup(func() {
			if err := kCtx.client.Resources().Delete(ctx, crd); err != nil {
				t.Logf("failed to delete the %q CRD: %s", infrastructureCrd, err)
			}
		})

		infra := &configv1.Infrastructure{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}
		err = k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{}, infra)
		require.NoErrorf(t, err, "failed to create the %q object", infrastructureCrd)

		// Use the test namespace as the cluster name since it is unique.
		infra.Status = configv1.InfrastructureStatus{InfrastructureName: namespace}
		err = kCtx.client.Resources().UpdateStatus(ctx, infra)
		require.NoErrorf(t, err, "failed to update the %q object status", infrastructureCrd)
	}
}

func k8sStepDeployJavaApp() k8sTestStep {
	return k8sStepDeployApp("java_app.yaml")
}

func k8sStepDeployApp(manifest string) func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		javaApp, err := os.ReadFile(filepath.Join("testdata", manifest))
		require.NoError(t, err)

		objects, err := testK8s.LoadFromYAML(bufio.NewReader(bytes.NewReader(javaApp)))
		require.NoError(t, err, "failed to parse rendered kustomize")

		err = k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: true, namespace: namespace}, objects...)
		require.NoError(t, err, "failed to create objects")
	}
}

func k8sStepCheckNamespaceDatastreamHits(info *define.Info, dsType, dataset, datastreamNamespace string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		k8sCheckDatastreamHits(t, ctx, info, dsType, dataset, datastreamNamespace, "k8s.namespace.name", namespace)
	}
}

func k8sStepCheckClusterNameDatastreamHits(info *define.Info, dsType, dataset, datastreamNamespace string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, _ string) {
		if !kCtx.openshift {
			return
		}
		infra := &configv1.Infrastructure{}
		err := kCtx.client.Resources().Get(ctx, "cluster", "", infra)
		require.NoError(t, err)
		require.NotEmpty(t, infra.Status.InfrastructureName)
		k8sCheckDatastreamHits(t, ctx, info, dsType, dataset, datastreamNamespace, "k8s.cluster.name", infra.Status.InfrastructureName)
	}
}

// k8sCheckDatastreamHits waits until the datastream has at least one document carrying the given resource attribute.
func k8sCheckDatastreamHits(t *testing.T, ctx context.Context, info *define.Info, dsType, dataset, datastreamNamespace, attribute, value string) {
	dsName := fmt.Sprintf("%s-%s-%s", dsType, dataset, datastreamNamespace)
	// Check errors against the CollectT so a transient query failure is
	// retried on the next tick instead of aborting the test.
	require.EventuallyWithT(t, func(collectT *assert.CollectT) {
		query := queryDataStreamResourceAttribute(dsType, dataset, datastreamNamespace, attribute, value)
		docs, err := estools.PerformQueryForRawQuery(ctx, query, fmt.Sprintf(".ds-%s*", dsType), info.ESClient)
		require.NoError(collectT, err, "failed to get %s datastream documents", dsName)
		require.Greater(collectT, docs.Hits.Total.Value, 0)
	}, 5*time.Minute, 10*time.Second, fmt.Sprintf(
		"at least one document with the %s %q should be available for %s datastream",
		attribute, value, dsName))
}

// helmValuesWithOpenShiftOverlay appends OpenShift-specific helm value files to base when on OpenShift.
func helmValuesWithOpenShiftOverlay(kCtx k8sContext, base ...string) []string {
	if kCtx.openshift {
		return append(base,
			"../../../deploy/helm/edot-collector/kube-stack/openshift/values.yaml",
		)
	}
	return base
}
