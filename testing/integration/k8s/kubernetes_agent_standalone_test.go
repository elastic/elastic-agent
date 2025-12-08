// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/cli/values"

	"github.com/elastic/elastic-agent-libs/kibana"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	testK8s "github.com/elastic/elastic-agent/pkg/testing/kubernetes"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

func TestKubernetesAgentStandaloneKustomize(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			// test all produced images
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "wolfi"},
			{Type: define.Kubernetes, DockerVariant: "complete"},
			{Type: define.Kubernetes, DockerVariant: "complete-wolfi"},
			{Type: define.Kubernetes, DockerVariant: "slim"},
			{Type: define.Kubernetes, DockerVariant: "slim-wolfi"},
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
			name: "default deployment - rootful agent",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize("elastic-agent-standalone", k8sKustomizeOverrides{}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
			},
		},
		{
			name: "drop ALL capabilities - rootful agent",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize("elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerRunUser:          int64Ptr(0),
					agentContainerCapabilitiesAdd:  []corev1.Capability{},
					agentContainerCapabilitiesDrop: []corev1.Capability{"ALL"},
				}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
			},
		},
		{
			name: "drop ALL add CHOWN, SETPCAP capabilities - rootful agent",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize("elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerRunUser:          int64Ptr(0),
					agentContainerCapabilitiesAdd:  []corev1.Capability{"CHOWN", "SETPCAP"},
					agentContainerCapabilitiesDrop: []corev1.Capability{"ALL"},
				}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
				k8sStepRunInnerTests("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone"),
			},
		},
		{
			name: "drop ALL add CHOWN, SETPCAP, DAC_READ_SEARCH, SYS_PTRACE capabilities - rootless agent",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize("elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerRunUser:          int64Ptr(1000),
					agentContainerRunGroup:         int64Ptr(1000),
					agentContainerCapabilitiesAdd:  []corev1.Capability{"CHOWN", "SETPCAP", "DAC_READ_SEARCH", "SYS_PTRACE"},
					agentContainerCapabilitiesDrop: []corev1.Capability{"ALL"},
				}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
				k8sStepRunInnerTests("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone"),
			},
		},
		{
			name: "drop ALL add CHOWN, SETPCAP, DAC_READ_SEARCH, SYS_PTRACE capabilities - rootless agent random uid:gid",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize("elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerRunUser:          int64Ptr(500),
					agentContainerRunGroup:         int64Ptr(500),
					agentContainerCapabilitiesAdd:  []corev1.Capability{"CHOWN", "SETPCAP", "DAC_READ_SEARCH", "SYS_PTRACE"},
					agentContainerCapabilitiesDrop: []corev1.Capability{"ALL"},
				}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
				k8sStepRunInnerTests("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone"),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipReason != "" {
				t.Skip(tc.skipReason)
			}

			testNamespace := kCtx.getNamespace(t)

			for _, step := range tc.steps {
				step(t, ctx, kCtx, testNamespace)
			}
		})
	}
}

func TestKubernetesAgentOtel(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			// only test the basic and the wolfi container with otel
			{Type: define.Kubernetes, DockerVariant: "elastic-otel-collector"},
			{Type: define.Kubernetes, DockerVariant: "elastic-otel-collector-wolfi"},
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background()
	kCtx := k8sGetContext(t, info)

	nodeList := corev1.NodeList{}
	err := kCtx.client.Resources().List(ctx, &nodeList)
	require.NoError(t, err)

	schedulableNodeCount, err := k8sSchedulableNodeCount(ctx, kCtx)
	require.NoError(t, err, "error at getting schedulable node count")
	require.NotZero(t, schedulableNodeCount, "no schedulable Kubernetes nodes found")

	testCases := []struct {
		name       string
		skipReason string
		steps      []k8sTestStep
	}{
		{
			name: "run agent in otel mode",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize("elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerExtraEnv: []corev1.EnvVar{},
					agentContainerArgs:     []string{}, // clear default args
				}, nil),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipReason != "" {
				t.Skip(tc.skipReason)
			}

			testNamespace := kCtx.getNamespace(t)

			for _, step := range tc.steps {
				step(t, ctx, kCtx, testNamespace)
			}
		})
	}
}

func TestKubernetesAgentHelm(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			// only test the basic and the wolfi container with otel
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "wolfi"},
			{Type: define.Kubernetes, DockerVariant: "slim"},
			{Type: define.Kubernetes, DockerVariant: "slim-wolfi"},
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background()
	kCtx := k8sGetContext(t, info)

	nodeList := corev1.NodeList{}
	err := kCtx.client.Resources().List(ctx, &nodeList)
	require.NoError(t, err)

	schedulableNodeCount, err := k8sSchedulableNodeCount(ctx, kCtx)
	require.NoError(t, err, "error at getting schedulable node count")
	require.NotZero(t, schedulableNodeCount, "no schedulable Kubernetes nodes found")

	testCases := []struct {
		name       string
		skipReason string
		steps      []k8sTestStep
	}{
		{
			// Configure the perNode and clusterWide agents to both use host networking. On the node that
			// runs the clusterWide agent, this tests that two agents do not try to bind to the same
			// gRPC control protocol port by default preventing one from starting.
			name: "helm standalone agent default kubernetes privileged without host network port collision",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"kubernetes": map[string]any{
						"enabled": true,
					},
					"agent": map[string]any{
						"unprivileged": false,
						"image": map[string]any{
							"repository": kCtx.agentImageRepo,
							"tag":        kCtx.agentImageTag,
							"pullPolicy": "Never",
						},
						"presets": map[string]any{
							"clusterWide": map[string]any{
								"hostNetwork": true,
							},
							"perNode": map[string]any{
								"hostNetwork": true,
							},
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
				k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil),
				k8sStepCheckAgentStatus("name=agent-clusterwide-helm-agent", 1, "agent", nil),
				k8sStepCheckRestrictUpgrade("name=agent-pernode-helm-agent", schedulableNodeCount, "agent"),
				k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent"),
				k8sStepRunInnerTests("name=agent-clusterwide-helm-agent", 1, "agent"),
			},
		},
		{
			name: "helm standalone agent default kubernetes unprivileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"kubernetes": map[string]any{
						"enabled": true,
						"state": map[string]any{
							"agentAsSidecar": map[string]any{
								"enabled": true,
							},
						},
					},
					"agent": map[string]any{
						"unprivileged": true,
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
				k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil),
				k8sStepCheckAgentStatus("name=agent-clusterwide-helm-agent", 1, "agent", nil),
				k8sStepCheckAgentStatus("app.kubernetes.io/name=kube-state-metrics", 1, "agent", nil),
				k8sStepCheckRestrictUpgrade("name=agent-pernode-helm-agent", schedulableNodeCount, "agent"),
				k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent"),
				k8sStepRunInnerTests("name=agent-clusterwide-helm-agent", 1, "agent"),
				k8sStepRunInnerTests("app.kubernetes.io/name=kube-state-metrics", 1, "agent"),
			},
		},
		{
			name: "helm managed agent default kubernetes privileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
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
		{
			name: "helm managed agent unenrolled with different enrollment token",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
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
				func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
					// unenroll all agents from fleet and keep track of their ids
					unEnrolledIDs := map[string]struct{}{}
					k8sStepForEachAgentID("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", func(ctx context.Context, id string) error {
						unEnrolledIDs[id] = struct{}{}
						_, err = info.KibanaClient.UnEnrollAgent(ctx, kibana.UnEnrollAgentRequest{
							ID:     id,
							Revoke: true,
						})
						return err
					})(t, ctx, kCtx, namespace)
					k8sStepHelmUninstall("helm-agent")(t, ctx, kCtx, namespace)

					// generate a new enrollment token and re-deploy, the helm chart since it is
					// under the same release name and same namespace will have the same state
					// as the previous deployment
					enrollParams, err := fleettools.NewEnrollParams(ctx, info.KibanaClient)
					require.NoError(t, err, "failed to create fleet enroll params")
					require.NotEqual(t, kCtx.enrollParams.EnrollmentToken, enrollParams.EnrollmentToken, "enrollment token did not change")
					k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
						"agent": map[string]any{
							"unprivileged": false,
							"image": map[string]any{
								"repository": kCtx.agentImageRepo,
								"tag":        kCtx.agentImageTag,
								"pullPolicy": "Never",
							},
							"fleet": map[string]any{
								"enabled": true,
								"url":     enrollParams.FleetURL,
								"token":   enrollParams.EnrollmentToken,
								"preset":  "perNode",
							},
						},
					})(t, ctx, kCtx, namespace)
					k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil)(t, ctx, kCtx, namespace)
					k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent")(t, ctx, kCtx, namespace)
					enrolledIDs := map[string]time.Time{}
					k8sStepForEachAgentID("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", func(ctx context.Context, id string) error {
						resp, err := kibanaGetAgent(ctx, info.KibanaClient, id)
						if err != nil {
							return err
						}
						// no ID should match the ones from the unenrolled ones
						if _, exists := unEnrolledIDs[id]; exists {
							return fmt.Errorf("agent with id %s found in unEnrolledIDs", id)
						}
						// keep track of the new enrolled ids and their enrollment time as reported by fleet
						enrolledIDs[id] = resp.EnrolledAt
						return nil
					})(t, ctx, kCtx, namespace)

					// uninstall and reinstall but this time check that the elastic-agent is not re-enrolling
					k8sStepHelmUninstall("helm-agent")(t, ctx, kCtx, namespace)
					k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
						"agent": map[string]any{
							"unprivileged": false,
							"image": map[string]any{
								"repository": kCtx.agentImageRepo,
								"tag":        kCtx.agentImageTag,
								"pullPolicy": "Never",
							},
							"fleet": map[string]any{
								"enabled": true,
								"url":     enrollParams.FleetURL,
								"token":   enrollParams.EnrollmentToken,
								"preset":  "perNode",
							},
						},
					})(t, ctx, kCtx, namespace)
					k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil)(t, ctx, kCtx, namespace)
					k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent")(t, ctx, kCtx, namespace)
					k8sStepForEachAgentID("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", func(ctx context.Context, id string) error {
						resp, err := kibanaGetAgent(ctx, info.KibanaClient, id)
						if err != nil {
							return err
						}
						// no ID should match the ones from the unenrolled ones
						enrolledAt, exists := enrolledIDs[id]
						if !exists {
							return fmt.Errorf("agent with id %s not found in enrolledIDs", id)
						}

						if !resp.EnrolledAt.Equal(enrolledAt) {
							return fmt.Errorf("agent enrollment time is updated")
						}
						return nil
					})(t, ctx, kCtx, namespace)
				},
			},
		},
		{
			name: "helm managed agent unenrolled",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
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
				func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
					// unenroll all agents from fleet and keep track of their ids
					unEnrolledIDs := map[string]struct{}{}
					k8sStepForEachAgentID("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", func(ctx context.Context, id string) error {
						unEnrolledIDs[id] = struct{}{}
						_, err = info.KibanaClient.UnEnrollAgent(ctx, kibana.UnEnrollAgentRequest{
							ID:     id,
							Revoke: true,
						})
						return err
					})(t, ctx, kCtx, namespace)

					// re-deploy with the same enrollment token, the helm chart since it is
					// under the same release name and same namespace will have the same state
					// as the previous deployment
					k8sStepHelmUninstall("helm-agent")(t, ctx, kCtx, namespace)
					k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
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
					})(t, ctx, kCtx, namespace)
					k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil)(t, ctx, kCtx, namespace)
					k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent")(t, ctx, kCtx, namespace)
					enrolledIDs := map[string]time.Time{}
					k8sStepForEachAgentID("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", func(ctx context.Context, id string) error {
						resp, err := kibanaGetAgent(ctx, info.KibanaClient, id)
						if err != nil {
							return err
						}
						// no ID should match the ones from the unenrolled ones
						if _, exists := unEnrolledIDs[id]; exists {
							return fmt.Errorf("agent with id %s found in unEnrolledIDs", id)
						}
						// keep track of the new enrolled ids and their enrollment time as reported by fleet
						enrolledIDs[id] = resp.EnrolledAt
						return nil
					})(t, ctx, kCtx, namespace)

					// uninstall and reinstall but this time check that the elastic-agent is not re-enrolling
					k8sStepHelmUninstall("helm-agent")(t, ctx, kCtx, namespace)
					k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
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
					})(t, ctx, kCtx, namespace)
					k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil)(t, ctx, kCtx, namespace)
					k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent")(t, ctx, kCtx, namespace)
					k8sStepForEachAgentID("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", func(ctx context.Context, id string) error {
						resp, err := kibanaGetAgent(ctx, info.KibanaClient, id)
						if err != nil {
							return err
						}
						// no ID should match the ones from the unenrolled ones
						enrolledAt, exists := enrolledIDs[id]
						if !exists {
							return fmt.Errorf("agent with id %s not found in enrolledIDs", id)
						}

						if !resp.EnrolledAt.Equal(enrolledAt) {
							return fmt.Errorf("agent enrollment time is updated")
						}
						return nil
					})(t, ctx, kCtx, namespace)
				},
			},
		},
		{
			name: "helm managed agent upgrade older version",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"agent": map[string]any{
						"unprivileged": false,
						"image": map[string]any{
							"repository": "docker.elastic.co/elastic-agent/elastic-agent",
							"tag":        "8.17.0",
							"pullPolicy": "IfNotPresent",
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
				func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
					enrolledIDs := map[string]time.Time{}
					k8sStepForEachAgentID("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", func(ctx context.Context, id string) error {
						resp, err := kibanaGetAgent(ctx, info.KibanaClient, id)
						if err != nil {
							return err
						}
						// keep track of the new enrolled ids and their enrollment time as reported by fleet
						enrolledIDs[id] = resp.EnrolledAt
						return nil
					})(t, ctx, kCtx, namespace)
					k8sStepHelmUninstall("helm-agent")(t, ctx, kCtx, namespace)
					k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
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
					})(t, ctx, kCtx, namespace)
					k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil)(t, ctx, kCtx, namespace)
					k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent")(t, ctx, kCtx, namespace)
					k8sStepForEachAgentID("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", func(ctx context.Context, id string) error {
						resp, err := kibanaGetAgent(ctx, info.KibanaClient, id)
						if err != nil {
							return err
						}
						enrolledAt, exists := enrolledIDs[id]
						if !exists {
							return fmt.Errorf("agent with id %s not found in enrolledIDs", id)
						}
						if !resp.EnrolledAt.Equal(enrolledAt) {
							return fmt.Errorf("agent enrollment time is updated")
						}
						return nil
					})(t, ctx, kCtx, namespace)
				},
			},
		},
		{
			name: "helm managed agent default kubernetes unprivileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"agent": map[string]any{
						"unprivileged": true,
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
		{
			name: "helm standalone agent unprivileged kubernetes hints",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"agent": map[string]any{
						"unprivileged": true,
						"image": map[string]any{
							"repository": kCtx.agentImageRepo,
							"tag":        kCtx.agentImageTag,
							"pullPolicy": "Never",
						},
					},
					"kubernetes": map[string]any{
						"enabled": true,
						"hints": map[string]any{
							"enabled": true,
						},
						"state": map[string]any{
							"agentAsSidecar": map[string]any{
								"enabled": true,
							},
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
				k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil),
				k8sStepCheckAgentStatus("name=agent-clusterwide-helm-agent", 1, "agent", nil),
				k8sStepCheckAgentStatus("app.kubernetes.io/name=kube-state-metrics", 1, "agent", nil),
				k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent"),
				k8sStepRunInnerTests("name=agent-clusterwide-helm-agent", 1, "agent"),
				k8sStepRunInnerTests("app.kubernetes.io/name=kube-state-metrics", 1, "agent"),
				k8sStepHintsRedisCreate(),
				k8sStepHintsRedisCheckAgentStatus("name=agent-pernode-helm-agent", true),
				k8sStepHintsRedisDelete(),
				k8sStepHintsRedisCheckAgentStatus("name=agent-pernode-helm-agent", false),
			},
		},
		{
			name: "helm standalone agent unprivileged kubernetes hints pre-deployed",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHintsRedisCreate(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"agent": map[string]any{
						"unprivileged": true,
						"image": map[string]any{
							"repository": kCtx.agentImageRepo,
							"tag":        kCtx.agentImageTag,
							"pullPolicy": "Never",
						},
					},
					"kubernetes": map[string]any{
						"enabled": true,
						"hints": map[string]any{
							"enabled": true,
						},
						"state": map[string]any{
							"agentAsSidecar": map[string]any{
								"enabled": true,
							},
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
				k8sStepCheckAgentStatus("name=agent-pernode-helm-agent", schedulableNodeCount, "agent", nil),
				k8sStepCheckAgentStatus("name=agent-clusterwide-helm-agent", 1, "agent", nil),
				k8sStepCheckAgentStatus("app.kubernetes.io/name=kube-state-metrics", 1, "agent", nil),
				k8sStepRunInnerTests("name=agent-pernode-helm-agent", schedulableNodeCount, "agent"),
				k8sStepRunInnerTests("name=agent-clusterwide-helm-agent", 1, "agent"),
				k8sStepRunInnerTests("app.kubernetes.io/name=kube-state-metrics", 1, "agent"),
				k8sStepHintsRedisCheckAgentStatus("name=agent-pernode-helm-agent", true),
				k8sStepHintsRedisDelete(),
				k8sStepHintsRedisCheckAgentStatus("name=agent-pernode-helm-agent", false),
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

// k8sDumpPods creates an archive that contains logs of all pods in the given namespace and kube-system to the given target directory
func k8sDumpPods(t *testing.T, ctx context.Context, client klient.Client, testName string, namespace string, targetDir string, testStartTime time.Time) {
	// Create the tar file
	archivePath := filepath.Join(targetDir, fmt.Sprintf("%s.tar", namespace))
	tarFile, err := os.Create(archivePath)
	if err != nil {
		t.Logf("failed to create archive at path %q", archivePath)
		return
	}
	defer tarFile.Close()

	t.Logf("archive %q contains the dump info for %q test", archivePath, testName)

	// Create a new tar writer
	tarWriter := tar.NewWriter(tarFile)
	defer tarWriter.Close()

	clientSet, err := kubernetes.NewForConfig(client.RESTConfig())
	if err != nil {
		t.Logf("error creating clientset: %s", err)
		return
	}

	podList := &corev1.PodList{}
	err = client.Resources("").List(ctx, podList)
	if err != nil {
		t.Logf("error listing pods: %s", err)
		return
	}

	type containerPodState struct {
		corev1.ContainerStatus `json:",inline"`
		Namespace              string `json:"namespace"`
		PodName                string `json:"podName"`
	}

	var statesDump []containerPodState

	for _, pod := range podList.Items {
		podNamespace := pod.GetNamespace()
		if podNamespace != namespace && podNamespace != "kube-system" {
			continue
		}

		for _, container := range pod.Spec.Containers {
			previous := false

			for _, containerStatus := range pod.Status.ContainerStatuses {
				if container.Name != containerStatus.Name {
					continue
				}

				statesDump = append(statesDump, containerPodState{
					containerStatus,
					podNamespace,
					pod.GetName(),
				})
				if containerStatus.RestartCount == 0 {
					break
				}
				// since we dump logs from pods that are expected to constantly run,
				// namely kube-apiserver in kube-system namespace, we need to identify
				// if a restart of such pod happened during the test to correctly if we
				// want previous log
				containerTerminated := containerStatus.LastTerminationState.Terminated
				if containerTerminated != nil && containerTerminated.FinishedAt.After(testStartTime) {
					previous = true
				}
				break
			}

			var logFileName string
			if previous {
				logFileName = fmt.Sprintf("%s-%s-%s-previous.log", podNamespace, pod.Name, container.Name)
			} else {
				logFileName = fmt.Sprintf("%s-%s-%s.log", podNamespace, pod.Name, container.Name)
			}

			req := clientSet.CoreV1().Pods(podNamespace).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container: container.Name,
				Previous:  previous,
				SinceTime: &metav1.Time{Time: testStartTime},
			})

			streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			podLogsStream, err := req.Stream(streamCtx)
			if err != nil {
				cancel()
				t.Logf("error getting container %q of pod %q logs: %s", container.Name, pod.Name, err)
				continue
			}

			b, err := io.ReadAll(podLogsStream)
			_ = podLogsStream.Close()
			cancel()
			if err != nil {
				t.Logf("error reading container %q logs of pod %q: %s", container.Name, pod.Name, err)
				continue
			}

			header := &tar.Header{
				Name:       logFileName,
				Size:       int64(len(b)),
				Mode:       0o600,
				ModTime:    time.Now(),
				AccessTime: time.Now(),
				ChangeTime: time.Now(),
			}

			if err := tarWriter.WriteHeader(header); err != nil {
				t.Logf("error writing header of file %q in archive: %s", logFileName, err)
				continue
			}

			if _, err := tarWriter.Write(b); err != nil {
				t.Logf("error writing data of file %q in archive: %s", logFileName, err)
			}
		}
	}

	b, err := json.Marshal(statesDump)
	if err != nil {
		t.Logf("error marshalling pod states: %s", err)
		return
	}

	statesDumpFile := "containerPodsStates.json"
	header := &tar.Header{
		Name:       statesDumpFile,
		Size:       int64(len(b)),
		Mode:       0o600,
		ModTime:    time.Now(),
		AccessTime: time.Now(),
		ChangeTime: time.Now(),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		t.Logf("error writing header of file %q in archive: %s", statesDumpFile, err)
		return
	}

	if _, err := tarWriter.Write(b); err != nil {
		t.Logf("error writing data of file %q in archive: %s", statesDumpFile, err)
	}
}

// k8sTestStep is a function that performs a single step in a k8s integration test
type k8sTestStep func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string)

// k8sStepCreateNamespace creates a namespace for the current test and adds a test cleanup that
// deletes it
func k8sStepCreateNamespace() k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		k8sNamespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		}

		t.Cleanup(func() {
			err := k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: true}, k8sNamespace)
			if err != nil {
				t.Logf("failed to delete namespace: %v", err)
			}
		})

		err := k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: true}, k8sNamespace)
		require.NoError(t, err, "failed to create namespace")
	}
}

// k8sKustomizeOverrides is futile attempt to make kustomize somewhat flexible and
// contains certain handpicked overrides to apply to the k8s objects created from
// kustomize rendering
type k8sKustomizeOverrides struct {
	agentContainerRunUser          *int64
	agentContainerRunGroup         *int64
	agentContainerCapabilitiesDrop []corev1.Capability
	agentContainerCapabilitiesAdd  []corev1.Capability
	agentContainerExtraEnv         []corev1.EnvVar
	agentContainerArgs             []string
	agentContainerMemoryLimit      string
	agentContainerVolumeMounts     []corev1.VolumeMount
	agentPodVolumes                []corev1.Volume
}

// k8sStepDeployKustomize renders a kustomize manifest and deploys it. Also, it tries to
// adjust the k8s objects created from the rendering to match the needs of the current test with k8sKustomizeOverrides.
// However, this is not that as flexible as we would like it to be. As a last resort somebody can use forEachObject callback
// to further adjust the k8s objects
func k8sStepDeployKustomize(containerName string, overrides k8sKustomizeOverrides, forEachObject func(object k8s.Object)) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		kustomizeYaml, err := os.ReadFile(AgentKustomizePath)
		require.NoError(t, err, "failed to read kustomize manifest")

		objects, err := testK8s.LoadFromYAML(bufio.NewReader(bytes.NewReader(kustomizeYaml)))
		require.NoError(t, err, "failed to parse rendered kustomize")

		if forEachObject != nil {
			for _, object := range objects {
				forEachObject(object)
			}
		}

		k8sKustomizeAdjustObjects(objects, namespace, containerName,
			func(container *corev1.Container) {
				container.VolumeMounts = append(container.VolumeMounts, overrides.agentContainerVolumeMounts...)

				// set agent image
				container.Image = kCtx.agentImage
				// set ImagePullPolicy to "Never" to avoid pulling the image
				// as the image is already loaded by the kubernetes provisioner
				container.ImagePullPolicy = "Never"

				if overrides.agentContainerMemoryLimit != "" {
					container.Resources.Limits = corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse(overrides.agentContainerMemoryLimit),
					}
				}

				// if security context overrides are set then set security context
				if overrides.agentContainerCapabilitiesDrop != nil || overrides.agentContainerCapabilitiesAdd != nil ||
					overrides.agentContainerRunUser != nil || overrides.agentContainerRunGroup != nil {
					// set security context
					container.SecurityContext = &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Drop: overrides.agentContainerCapabilitiesDrop,
							Add:  overrides.agentContainerCapabilitiesAdd,
						},
						RunAsUser:  overrides.agentContainerRunUser,
						RunAsGroup: overrides.agentContainerRunGroup,
					}
				}

				// set Elasticsearch host and API key
				for idx, env := range container.Env {
					if env.Name == "ES_HOST" {
						container.Env[idx].Value = kCtx.esHost
						container.Env[idx].ValueFrom = nil
					}
					if env.Name == "API_KEY" {
						container.Env[idx].Value = kCtx.esAPIKey
						container.Env[idx].ValueFrom = nil
					}
					if env.Name == "CA_TRUSTED" {
						// empty this otherwise it defaults to %CA_TRUSTED% and causes issues
						container.Env[idx].Value = ""
						container.Env[idx].ValueFrom = nil
					}
				}

				if len(overrides.agentContainerExtraEnv) > 0 {
					container.Env = append(container.Env, overrides.agentContainerExtraEnv...)
				}

				if overrides.agentContainerArgs != nil {
					container.Args = overrides.agentContainerArgs
				}
			},
			func(pod *corev1.PodSpec) {
				for volumeIdx, volume := range pod.Volumes {
					// need to update the volume path of the state directory
					// to match the test namespace
					if volume.Name == "elastic-agent-state" {
						hostPathType := corev1.HostPathDirectoryOrCreate
						pod.Volumes[volumeIdx].VolumeSource.HostPath = &corev1.HostPathVolumeSource{
							Type: &hostPathType,
							Path: fmt.Sprintf("/var/lib/elastic-agent-standalone/%s/state", namespace),
						}
					}
				}
				pod.Volumes = append(pod.Volumes, overrides.agentPodVolumes...)
			})

		t.Cleanup(func() {
			if t.Failed() {
				k8sDumpPods(t, ctx, kCtx.client, t.Name(), namespace, kCtx.logsBasePath, kCtx.createdAt)
			}

			err := k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: true}, objects...)
			if err != nil {
				t.Logf("failed to delete objects: %v", err)
			}
		})

		err = k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: true, namespace: namespace}, objects...)
		require.NoError(t, err, "failed to create objects")
	}
}

// k8sStepCheckAgentStatus checks the status of the agent inside the pods returned by the selector
func k8sStepCheckAgentStatus(agentPodLabelSelector string, expectedPodNumber int, containerName string, componentPresence map[string]bool) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		perNodePodList := &corev1.PodList{}
		err := kCtx.client.Resources(namespace).List(ctx, perNodePodList, func(opt *metav1.ListOptions) {
			opt.LabelSelector = agentPodLabelSelector
		})
		require.NoError(t, err, "failed to list pods with selector ", perNodePodList)
		require.NotEmpty(t, perNodePodList.Items, "no pods found with selector ", perNodePodList)
		require.Equal(t, expectedPodNumber, len(perNodePodList.Items), "unexpected number of pods found with selector ", perNodePodList)

		for _, pod := range perNodePodList.Items {
			var stdout, stderr bytes.Buffer
			err = k8sCheckAgentStatus(ctx, kCtx.client, &stdout, &stderr, namespace, pod.Name, containerName, componentPresence)
			if err != nil {
				t.Errorf("failed to check agent status %s: %v", pod.Name, err)
				t.Logf("stdout: %s\n", stdout.String())
				t.Logf("stderr: %s\n", stderr.String())
				t.FailNow()
			}
		}
	}
}

func k8sStepForEachAgentID(agentPodLabelSelector string, expectedPodNumber int, containerName string, cb func(ctx context.Context, id string) error) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		perNodePodList := &corev1.PodList{}
		err := kCtx.client.Resources(namespace).List(ctx, perNodePodList, func(opt *metav1.ListOptions) {
			opt.LabelSelector = agentPodLabelSelector
		})
		require.NoError(t, err, "failed to list pods with selector ", perNodePodList)
		require.NotEmpty(t, perNodePodList.Items, "no pods found with selector ", perNodePodList)
		require.Equal(t, expectedPodNumber, len(perNodePodList.Items), "unexpected number of pods found with selector ", perNodePodList)
		var stdout, stderr bytes.Buffer
		for _, pod := range perNodePodList.Items {
			id, err := k8sGetAgentID(ctx, kCtx.client, &stdout, &stderr, namespace, pod.Name, containerName)
			require.NoError(t, err, "failed to unenroll agent %s", pod.Name)
			require.NotEmpty(t, id, "agent id should not be empty")
			require.NoError(t, cb(ctx, id), "callback for each agent id failed")
		}
	}
}

// k8sStepRunInnerTests invokes the k8s inner tests inside the pods returned by the selector. Note that this
// step requires the agent image to be built with the testing framework as there is the point where the binary
// for the inner tests is copied
func k8sStepRunInnerTests(agentPodLabelSelector string, expectedPodNumber int, containerName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		perNodePodList := &corev1.PodList{}
		err := kCtx.client.Resources(namespace).List(ctx, perNodePodList, func(opt *metav1.ListOptions) {
			opt.LabelSelector = agentPodLabelSelector
		})
		require.NoError(t, err, "failed to list pods with selector ", perNodePodList)
		require.NotEmpty(t, perNodePodList.Items, "no pods found with selector ", perNodePodList)
		require.Equal(t, expectedPodNumber, len(perNodePodList.Items), "unexpected number of pods found with selector ", perNodePodList)

		for _, pod := range perNodePodList.Items {
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err = kCtx.client.Resources().ExecInPod(ctx, namespace, pod.Name, containerName,
				[]string{"/usr/share/elastic-agent/k8s-inner-tests", "-test.v"}, &stdout, &stderr)
			cancel()
			t.Logf("%s k8s-inner-tests output:", pod.Name)
			t.Log(stdout.String())
			if err != nil {
				t.Log(stderr.String())
			}
			require.NoError(t, err, "error at k8s inner tests execution")
		}
	}
}

// k8sStepHelmUninstall uninstalls the helm chart with the given release name
func k8sStepHelmUninstall(releaseName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		settings := cli.New()
		settings.SetNamespace(namespace)
		actionConfig := &action.Configuration{}

		err := actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "",
			func(format string, v ...interface{}) {})
		require.NoError(t, err, "failed to init helm action config")

		uninstallAction := action.NewUninstall(actionConfig)
		uninstallAction.Wait = true
		_, err = uninstallAction.Run(releaseName)
		require.NoError(t, err, "failed to uninstall helm chart")
	}
}

// k8sStepHelmDeploy deploys a helm chart with the given values and the release name
func k8sStepHelmDeploy(chartPath string, releaseName string, values map[string]any) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		settings := cli.New()
		settings.SetNamespace(namespace)
		actionConfig := &action.Configuration{}

		helmChart, err := loader.Load(chartPath)
		require.NoError(t, err, "failed to load helm chart")

		err = actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "",
			func(format string, v ...interface{}) {})
		require.NoError(t, err, "failed to init helm action config")

		t.Cleanup(func() {
			if t.Failed() {
				k8sDumpPods(t, ctx, kCtx.client, t.Name(), namespace, kCtx.logsBasePath, kCtx.createdAt)
			}

			uninstallAction := action.NewUninstall(actionConfig)
			uninstallAction.Wait = true
			_, _ = uninstallAction.Run(releaseName)
		})

		installAction := action.NewInstall(actionConfig)
		installAction.Namespace = namespace
		installAction.CreateNamespace = true
		installAction.UseReleaseName = true
		installAction.ReleaseName = releaseName
		installAction.Timeout = 2 * time.Minute
		installAction.Wait = true
		installAction.WaitForJobs = true
		_, err = installAction.Run(helmChart, values)
		require.NoError(t, err, "failed to install helm chart")
	}
}

// k8sStepHelmUpgrade upgrades a helm release with the given values and the release name
func k8sStepHelmUpgrade(chartPath string, releaseName string, values values.Options) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		settings := cli.New()
		settings.SetNamespace(namespace)
		actionConfig := &action.Configuration{}

		helmChart, err := loader.Load(chartPath)
		require.NoError(t, err, "failed to load helm chart")

		err = actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "",
			func(format string, v ...interface{}) {})
		require.NoError(t, err, "failed to init helm action config")

		t.Cleanup(func() {
			if t.Failed() {
				k8sDumpPods(t, ctx, kCtx.client, t.Name(), namespace, kCtx.logsBasePath, kCtx.createdAt)
			}

			uninstallAction := action.NewUninstall(actionConfig)
			uninstallAction.Wait = true
			_, _ = uninstallAction.Run(releaseName)
		})

		upgradeAction := action.NewUpgrade(actionConfig)
		upgradeAction.Namespace = namespace
		upgradeAction.Timeout = 2 * time.Minute
		upgradeAction.Wait = true
		upgradeAction.WaitForJobs = true
		_, err = upgradeAction.Run(
			releaseName, helmChart, mergeValues(t, namespace, values))
		require.NoError(t, err, "failed to upgrade helm chart")
	}
}

func k8sStepHintsRedisCreate() k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		r, err := os.Open("testdata/k8s.hints.redis.yaml")
		require.NoError(t, err, "failed to open redis k8s test data")

		redisObjs, err := testK8s.LoadFromYAML(bufio.NewReader(r))
		require.NoError(t, err, "failed to convert redis yaml to k8s objects")

		t.Cleanup(func() {
			err = k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: true}, redisObjs...)
			require.NoError(t, err, "failed to delete redis k8s objects")
		})

		err = k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: true, waitTimeout: 120 * time.Second, namespace: namespace}, redisObjs...)
		require.NoError(t, err, "failed to create redis k8s objects")
	}
}

func k8sStepHintsRedisCheckAgentStatus(agentPodLabelSelector string, hintDeployed bool) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		agentPodList := &corev1.PodList{}
		err := kCtx.client.Resources(namespace).List(ctx, agentPodList, func(opt *metav1.ListOptions) {
			opt.LabelSelector = agentPodLabelSelector
		})
		require.NoError(t, err, "failed to list agent pods with selector ", agentPodLabelSelector)
		require.NotEmpty(t, agentPodList.Items, "no agent pods found with selector ", agentPodLabelSelector)

		redisPodSelector := "app.kubernetes.io/name=redis"
		redisPodList := &corev1.PodList{}
		err = kCtx.client.Resources(namespace).List(ctx, redisPodList, func(opt *metav1.ListOptions) {
			opt.LabelSelector = redisPodSelector
		})
		require.NoError(t, err, "failed to list redis pods with selector ", redisPodSelector)
		if hintDeployed {
			require.NotEmpty(t, redisPodList.Items, "no redis pods found with selector ", redisPodSelector)
			// check that redis pods have the correct annotations
			for _, redisPod := range redisPodList.Items {
				hintPackage, ok := redisPod.ObjectMeta.Annotations["co.elastic.hints/package"]
				require.True(t, ok, "missing hints annotation")
				require.Equal(t, "redis", hintPackage, "hints annotation package wrong value")
			}
		} else {
			require.Empty(t, redisPodList.Items, "redis pods should not exist ", redisPodSelector)
		}

		for _, pod := range agentPodList.Items {
			shouldExist := hintDeployed
			if shouldExist {
				redisPodOnSameNode := false
				for _, redisPod := range redisPodList.Items {
					redisPodOnSameNode = redisPod.Spec.NodeName == pod.Spec.NodeName
					if redisPodOnSameNode {
						break
					}
				}
				shouldExist = shouldExist && redisPodOnSameNode
			}

			var stdout, stderr bytes.Buffer
			err = k8sCheckAgentStatus(ctx, kCtx.client, &stdout, &stderr, namespace, pod.Name, "agent", map[string]bool{
				"redis/metrics": shouldExist,
			})
			if err != nil {
				t.Errorf("failed to check agent status %s: %v", pod.Name, err)
				t.Logf("stdout: %s\n", stdout.String())
				t.Logf("stderr: %s\n", stderr.String())
				t.FailNow()
			}
		}
	}
}

func k8sStepHintsRedisDelete() k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		redisPod := &corev1.Pod{}
		err := kCtx.client.Resources(namespace).Get(ctx, "redis", namespace, redisPod)
		require.NoError(t, err, "failed to get redis pod")

		err = k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: true}, redisPod)
		require.NoError(t, err, "failed to delete redis k8s objects")
	}
}

func k8sStepCheckRestrictUpgrade(agentPodLabelSelector string, expectedPodNumber int, containerName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		perNodePodList := &corev1.PodList{}
		err := kCtx.client.Resources(namespace).List(ctx, perNodePodList, func(opt *metav1.ListOptions) {
			opt.LabelSelector = agentPodLabelSelector
		})
		require.NoError(t, err, "failed to list pods with selector ", perNodePodList)
		require.NotEmpty(t, perNodePodList.Items, "no pods found with selector ", perNodePodList)
		require.Equal(t, expectedPodNumber, len(perNodePodList.Items), "unexpected number of pods found with selector ", perNodePodList)
		for _, pod := range perNodePodList.Items {
			var stdout, stderr bytes.Buffer

			command := []string{"elastic-agent", "upgrade", "1.0.0"}
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err := kCtx.client.Resources().ExecInPod(ctx, namespace, pod.Name, containerName, command, &stdout, &stderr)
			cancel()
			require.Error(t, err)
			require.Contains(t, stderr.String(), coordinator.ErrNotUpgradable.Error())
		}
	}
}
