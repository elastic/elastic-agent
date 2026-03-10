// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestKubernetesAgentHelmCloudDefend(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "wolfi"},
			{Type: define.Kubernetes, DockerVariant: "complete"},
			{Type: define.Kubernetes, DockerVariant: "complete-wolfi"},
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background()
	kCtx := k8sGetContext(t, info)

	schedulableNodeCount, err := k8sSchedulableNodeCount(ctx, kCtx)
	require.NoError(t, err, "error at getting schedulable node count")
	require.NotZero(t, schedulableNodeCount, "no schedulable Kubernetes nodes found")

	testCases := []struct {
		name       string
		skipReason string
		steps      []k8sTestStep
	}{
		{
			name: "helm standalone agent cloud-defend",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"kubernetes": map[string]any{
						"enabled": false,
					},
					"cloudDefend": map[string]any{
						"enabled": true,
					},
					"agent": map[string]any{
						"unprivileged": false,
						"image": map[string]any{
							"repository": kCtx.agentImageRepo,
							"tag":        kCtx.agentImageTag,
							"pullPolicy": "Never",
						},
					},
					"outputs": map[string]any{
						"default": map[string]any{
							"type":    "ESPlainAuthAPI",
							"url":     kCtx.esHost,
							"api_key": kCtx.esAPIKey,
						},
					},
				}),
				k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", map[string]bool{
					"cloud_defend/control-default": true,
				}),
			},
		},
		{
			name: "helm managed agent cloud-defend",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"cloudDefend": map[string]any{
						"enabled": true,
					},
					"agent": map[string]any{
						"unprivileged": false,
						"image": map[string]any{
							"repository": kCtx.agentImageRepo,
							"tag":        kCtx.agentImageTag,
							"pullPolicy": "Never",
						},
						"fleet": map[string]any{
							"enabled": true,
							"url":     kCtx.enrollParams.FleetURL,
							"token":   kCtx.enrollParams.EnrollmentToken,
							"preset":  "perNode",
						},
					},
				}),
				k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil),
				k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipReason != "" {
				t.Skip(tc.skipReason)
			}

			ctx := context.Background()
			testNamespace := kCtx.getNamespace(t)

			for _, step := range tc.steps {
				step(t, ctx, kCtx, testNamespace)
			}
		})
	}
}
