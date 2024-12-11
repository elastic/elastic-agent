// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestKubernetesAgentService(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			// only test the service container
			{Type: define.Kubernetes, DockerVariant: "service"},
		},
		Group: define.Kubernetes,
	})

	// read the service agent config
	serviceAgentYAML, err := os.ReadFile(filepath.Join("testdata", "connectors.agent.yml"))
	require.NoError(t, err, "failed to read service agent config")

	ctx := context.Background()
	kCtx := k8sGetContext(t, info)

	nodeList := corev1.NodeList{}
	err = kCtx.client.Resources().List(ctx, &nodeList)
	require.NoError(t, err)

	totalK8SNodes := len(nodeList.Items)
	require.NotZero(t, totalK8SNodes, "No Kubernetes nodes found")

	testSteps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepDeployKustomize(agentK8SKustomize, "elastic-agent-standalone", k8sKustomizeOverrides{
			agentContainerMemoryLimit: "800Mi",
		}, func(obj k8s.Object) {
			// update the configmap to only run the connectors input
			switch objWithType := obj.(type) {
			case *corev1.ConfigMap:
				_, ok := objWithType.Data["agent.yml"]
				if ok {
					objWithType.Data["agent.yml"] = string(serviceAgentYAML)
				}
			}
		}),
		k8sStepCheckAgentStatus("app=elastic-agent-standalone", totalK8SNodes, "elastic-agent-standalone", map[string]bool{
			"connectors-py": true,
		}),
	}

	testNamespace := kCtx.getNamespace(t)
	for _, step := range testSteps {
		step(t, ctx, kCtx, testNamespace)
	}
}
