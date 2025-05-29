// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestKubernetesJournaldInput(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "complete"},
			{Type: define.Kubernetes, DockerVariant: "elastic-otel-collector"},
		},
		Group: define.Kubernetes,
	})

	agentConfigYAML, err := os.ReadFile(filepath.Join("testdata", "journald-input.yml"))
	require.NoError(t, err, "failed to read journald input template")

	ctx := context.Background()
	kCtx := k8sGetContext(t, info)

	schedulableNodeCount, err := k8sSchedulableNodeCount(ctx, kCtx)
	require.NoError(t, err, "error at getting schedulable node count")
	require.NotZero(t, schedulableNodeCount, "no schedulable Kubernetes nodes found")

	namespace := kCtx.getNamespace(t)
	hostPathType := corev1.HostPathDirectory

	testCases := []struct {
		name       string
		skipReason string
		steps      []k8sTestStep
	}{
		{
			name: "happy path",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize(
					agentK8SKustomize,
					"elastic-agent-standalone",
					k8sKustomizeOverrides{
						agentContainerExtraEnv: []corev1.EnvVar{
							{
								Name:  "ELASTICSEARCH_USERNAME",
								Value: os.Getenv("ELASTICSEARCH_USERNAME"),
							},
							{
								Name:  "ELASTICSEARCH_PASSWORD",
								Value: os.Getenv("ELASTICSEARCH_PASSWORD"),
							},
							{
								Name:  "EA_POLICY_NAMESPACE",
								Value: namespace,
							},
						},
						agentContainerVolumeMounts: []corev1.VolumeMount{
							{
								Name:      "journald-mount",
								MountPath: "/opt/journald",
								ReadOnly:  true,
							},
						},
						agentPodVolumes: []corev1.Volume{
							{
								Name: "journald-mount",
								VolumeSource: corev1.VolumeSource{
									HostPath: &corev1.HostPathVolumeSource{
										Path: "/run/log/journal",
										Type: &hostPathType,
									},
								},
							},
						},
					},
					func(obj k8s.Object) {
						// update the configmap to use the journald input
						switch objWithType := obj.(type) {
						case *corev1.ConfigMap:
							_, ok := objWithType.Data["agent.yml"]
							if ok {
								objWithType.Data["agent.yml"] = string(agentConfigYAML)
							}
						}

					}),
				k8sStepCheckAgentStatus(
					"app=elastic-agent-standalone",
					schedulableNodeCount,
					"elastic-agent-standalone",
					map[string]bool{
						"journald": true,
					}),
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

			// Check if the context was cancelled or timed out
			if ctx.Err() != nil {
				t.Errorf("context error: %v", ctx.Err())
			}

			// Query the index and filter by the input type
			docs := findESDocs(t, func() (estools.Documents, error) {
				return estools.GetLogsForIndexWithContext(
					ctx,
					info.ESClient, fmt.Sprintf("logs-%s-default", namespace),
					map[string]any{
						"input.type": "journald",
					},
				)
			})

			require.NotEmpty(t, docs, "expected logs to be found in Elasticsearch")
		})
	}
}
