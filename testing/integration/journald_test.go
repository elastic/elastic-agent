// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

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
	"github.com/elastic/go-elasticsearch/v8"
)

func TestKubernetesJournaldInput(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "complete"},
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

	steps := []k8sTestStep{
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
	}

	journaldTest(
		t,
		info.ESClient,
		kCtx,
		steps,
		fmt.Sprintf("logs-%s-default", namespace),
		"input.type",
		"journald")
}

func TestKubernetesJournaldInputOtel(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes, DockerVariant: "elastic-otel-collector"},
		},
		Group: define.Kubernetes,
	})

	otelConfigYAML, err := os.ReadFile(filepath.Join("testdata", "journald-otel.yml"))
	require.NoError(t, err, "failed to read journald input template")

	kCtx := k8sGetContext(t, info)
	namespace := kCtx.getNamespace(t)
	hostPathType := corev1.HostPathDirectory

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepDeployKustomize(
			agentK8SKustomize,
			"elastic-agent-standalone",
			k8sKustomizeOverrides{
				agentContainerArgs: []string{"--config", "/etc/elastic-agent/agent.yml"},
				agentContainerExtraEnv: []corev1.EnvVar{
					{
						Name:  "EA_POLICY_NAMESPACE",
						Value: namespace,
					},
					{
						Name:  "ES_API_KEY_ENCODED",
						Value: kCtx.esEncodedAPIKey,
					},
				},
				agentContainerVolumeMounts: []corev1.VolumeMount{
					{
						Name:      "journald-mount",
						MountPath: "/opt/journal",
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
						objWithType.Data["agent.yml"] = string(otelConfigYAML)
					}
				}
			}),
	}

	journaldTest(
		t,
		info.ESClient,
		kCtx,
		steps,
		fmt.Sprintf("logs-generic.otel-%s", namespace),
		"body.structured.input.type",
		"journald")
}

func journaldTest(
	t *testing.T,
	esClient *elasticsearch.Client,
	kCtx k8sContext,
	steps []k8sTestStep,
	index, field, value string) {
	t.Helper()

	ctx := context.Background()
	testNamespace := kCtx.getNamespace(t)

	for _, step := range steps {
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
			esClient,
			index,
			map[string]any{
				field: value,
			},
		)
	})
	require.NotEmpty(t, docs, "expected logs to be found in Elasticsearch")
}
