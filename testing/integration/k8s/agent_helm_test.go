// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"context"
	"fmt"
	"testing"

	"helm.sh/helm/v3/pkg/cli/values"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestAgentKubeStackHelm(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: true,
		Sudo:  false,
		OS: []define.OS{
			// only test the basic and the wolfi container
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "wolfi"},
		},
		Group: define.Default,
	})

	kCtx := k8sGetContext(t, info)

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepHelmDeployWithValueOptions(KubeStackChartPath, "elastic-agent",
			values.Options{
				ValueFiles: []string{"../../../deploy/helm/elastic-agent/values.yaml"},
				Values: []string{
					fmt.Sprintf("defaultCRConfig.image.repository=%s", kCtx.agentImageRepo),
					fmt.Sprintf("defaultCRConfig.image.tag=%s", kCtx.agentImageTag),
					// // override cluster wide
					// // endpoint for tests
					// "instrumentation.exporter.endpoint=http://opentelemetry-kube-stack-daemon-collector:4318",
				},

				// override secrets reference with env variables
				JSONValues: []string{
					fmt.Sprintf(`collectors.gateway.env[1]={"name":"ELASTIC_ENDPOINT","value":"%s"}`, kCtx.esHost),
					fmt.Sprintf(`collectors.gateway.env[2]={"name":"ELASTIC_API_KEY","value":"%s"}`, kCtx.esEncodedAPIKey),
				},
			},
		),
		// - TODO
		k8sStepCheckRunningPods("app.kubernetes.io/name=agent-clusterwide-elastic-agent", 1, "agent"),
		// - A Daemonset to collect K8s node's metrics and logs
		// (1 EDOT collector pod per node)
		// - A Cluster wide Deployment to collect K8s metrics and
		// events (1 EDOT collector pod per cluster)
		// - Two Gateway pods to collect, aggregate and forward
		// telemetry.
		k8sStepCheckRunningPods("app.kubernetes.io/managed-by=agent-pernode-elastic-agent", 1, "agent"),
		// // validate k8s metrics are being pushed
		// k8sStepCheckDatastreamsHits(info, "metrics", "kubeletstatsreceiver.otel", "default"),
		// k8sStepCheckDatastreamsHits(info, "metrics", "k8sclusterreceiver.otel", "default"),
		// validates auto-instrumentation and traces
		// datastream generation
		func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
			k8sStepDeployJavaApp()(t, ctx, kCtx, namespace)
			k8sStepCheckDatastreamsHits(info, "log", "kubernetes.container_logs", "default")(t, ctx, kCtx, namespace)
		},
	}

	ctx := context.Background()
	testNamespace := kCtx.getNamespace(t)

	for _, step := range steps {
		step(t, ctx, kCtx, testNamespace)
	}
}
