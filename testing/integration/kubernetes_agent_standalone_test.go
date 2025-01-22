// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/go-elasticsearch/v8"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	cliResource "k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	helmKube "helm.sh/helm/v3/pkg/kube"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	aclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/helm"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

const (
	agentK8SKustomize = "../../deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone"
	agentK8SHelm      = "../../deploy/helm/elastic-agent"
)

var noSpecialCharsRegexp = regexp.MustCompile("[^a-zA-Z0-9]+")

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
				k8sStepDeployKustomize(agentK8SKustomize, "elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerMemoryLimit: "800Mi",
				}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
			},
		},
		{
			name: "drop ALL capabilities - rootful agent",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize(agentK8SKustomize, "elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerRunUser:          int64Ptr(0),
					agentContainerCapabilitiesAdd:  []corev1.Capability{},
					agentContainerCapabilitiesDrop: []corev1.Capability{"ALL"},
					agentContainerMemoryLimit:      "800Mi",
				}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
			},
		},
		{
			name: "drop ALL add CHOWN, SETPCAP capabilities - rootful agent",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize(agentK8SKustomize, "elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerRunUser:          int64Ptr(0),
					agentContainerCapabilitiesAdd:  []corev1.Capability{"CHOWN", "SETPCAP"},
					agentContainerCapabilitiesDrop: []corev1.Capability{"ALL"},
					agentContainerMemoryLimit:      "800Mi",
				}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
				k8sStepRunInnerTests("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone"),
			},
		},
		{
			name: "drop ALL add CHOWN, SETPCAP, DAC_READ_SEARCH, SYS_PTRACE capabilities - rootless agent",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize(agentK8SKustomize, "elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerRunUser:          int64Ptr(1000),
					agentContainerRunGroup:         int64Ptr(1000),
					agentContainerCapabilitiesAdd:  []corev1.Capability{"CHOWN", "SETPCAP", "DAC_READ_SEARCH", "SYS_PTRACE"},
					agentContainerCapabilitiesDrop: []corev1.Capability{"ALL"},
					agentContainerMemoryLimit:      "800Mi",
				}, nil),
				k8sStepCheckAgentStatus("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone", nil),
				k8sStepRunInnerTests("app=elastic-agent-standalone", schedulableNodeCount, "elastic-agent-standalone"),
			},
		},
		{
			name: "drop ALL add CHOWN, SETPCAP, DAC_READ_SEARCH, SYS_PTRACE capabilities - rootless agent random uid:gid",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepDeployKustomize(agentK8SKustomize, "elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerRunUser:          int64Ptr(500),
					agentContainerRunGroup:         int64Ptr(500),
					agentContainerCapabilitiesAdd:  []corev1.Capability{"CHOWN", "SETPCAP", "DAC_READ_SEARCH", "SYS_PTRACE"},
					agentContainerCapabilitiesDrop: []corev1.Capability{"ALL"},
					agentContainerMemoryLimit:      "800Mi",
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
			{Type: define.Kubernetes, DockerVariant: "basic"},
			{Type: define.Kubernetes, DockerVariant: "wolfi"},
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
				k8sStepDeployKustomize(agentK8SKustomize, "elastic-agent-standalone", k8sKustomizeOverrides{
					agentContainerMemoryLimit: "800Mi",
					agentContainerExtraEnv:    []corev1.EnvVar{{Name: "ELASTIC_AGENT_OTEL", Value: "true"}},
					agentContainerArgs:        []string{}, // clear default args
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
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background()
	kCtx := k8sGetContext(t, info)

	err := helm.BuildChartDependencies(agentK8SHelm)
	require.NoError(t, err, "failed to build helm dependencies")

	nodeList := corev1.NodeList{}
	err = kCtx.client.Resources().List(ctx, &nodeList)
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
			name: "helm standalone agent default kubernetes privileged",
			steps: []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
					k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
					k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
					k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
					k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
					"agent": map[string]any{
						"unprivileged": false,
						"image": map[string]any{
							"repository": kCtx.agentImageRepo,
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
					k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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
				k8sStepHelmDeploy(agentK8SHelm, "helm-agent", map[string]any{
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

// k8sCheckAgentStatus checks that the agent reports healthy.
func k8sCheckAgentStatus(ctx context.Context, client klient.Client, stdout *bytes.Buffer, stderr *bytes.Buffer,
	namespace string, agentPodName string, containerName string, componentPresence map[string]bool,
) error {
	command := []string{"elastic-agent", "status", "--output=json"}

	checkStatus := func() error {
		status := atesting.AgentStatusOutput{} // clear status output
		stdout.Reset()
		stderr.Reset()
		if err := client.Resources().ExecInPod(ctx, namespace, agentPodName, containerName, command, stdout, stderr); err != nil {
			return err
		}

		if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
			return err
		}

		var err error
		// validate that the components defined are also healthy if they should exist
		for component, shouldBePresent := range componentPresence {
			compState, ok := getAgentComponentState(status, component)
			if shouldBePresent {
				if !ok {
					// doesn't exist
					err = errors.Join(err, fmt.Errorf("required component %s not found", component))
				} else if compState != int(aclient.Healthy) {
					// not healthy
					err = errors.Join(err, fmt.Errorf("required component %s is not healthy", component))
				}
			} else if ok {
				// should not be present
				err = errors.Join(err, fmt.Errorf("component %s should not be present", component))
			}
		}
		return err
	}

	// we will wait maximum 120 seconds for the agent to report healthy
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, 120*time.Second)
	defer timeoutCancel()
	for {
		err := checkStatus()
		if err == nil {
			return nil
		}
		if timeoutCtx.Err() != nil {
			// timeout waiting for agent to become healthy
			return errors.Join(err, errors.New("timeout waiting for agent to become healthy"))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// k8sGetAgentID returns the agent ID for the given agent pod
func k8sGetAgentID(ctx context.Context, client klient.Client, stdout *bytes.Buffer, stderr *bytes.Buffer,
	namespace string, agentPodName string, containerName string) (string, error) {
	command := []string{"elastic-agent", "status", "--output=json"}

	status := atesting.AgentStatusOutput{} // clear status output
	stdout.Reset()
	stderr.Reset()
	if err := client.Resources().ExecInPod(ctx, namespace, agentPodName, containerName, command, stdout, stderr); err != nil {
		return "", err
	}

	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		return "", err
	}

	return status.Info.ID, nil
}

// getAgentComponentState returns the component state for the given component name and a bool indicating if it exists.
func getAgentComponentState(status atesting.AgentStatusOutput, componentName string) (int, bool) {
	for _, comp := range status.Components {
		if comp.Name == componentName {
			return comp.State, true
		}
	}
	return -1, false
}

// k8sDumpAllPodLogs dumps the logs of all pods in the given namespace to the given target directory
func k8sDumpAllPodLogs(ctx context.Context, client klient.Client, testName string, namespace string, targetDir string) error {
	podList := &corev1.PodList{}

	clientSet, err := kubernetes.NewForConfig(client.RESTConfig())
	if err != nil {
		return fmt.Errorf("error creating clientset: %w", err)
	}

	err = client.Resources(namespace).List(ctx, podList)
	if err != nil {
		return fmt.Errorf("error listing pods: %w", err)
	}

	var errs error
	for _, pod := range podList.Items {
		previous := false
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.RestartCount > 0 {
				previous = true
				break
			}
		}

		for _, container := range pod.Spec.Containers {
			logFilePath := filepath.Join(targetDir, fmt.Sprintf("%s-%s-%s.log", testName, pod.Name, container.Name))
			logFile, err := os.Create(logFilePath)
			if err != nil {
				errs = errors.Join(fmt.Errorf("error creating log file: %w", err), errs)
				continue
			}

			req := clientSet.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container: container.Name,
				Previous:  previous,
			})
			podLogsStream, err := req.Stream(context.TODO())
			if err != nil {
				errs = errors.Join(fmt.Errorf("error getting container %s of pod %s logs: %w", container.Name, pod.Name, err), errs)
				continue
			}

			_, err = io.Copy(logFile, podLogsStream)
			if err != nil {
				errs = errors.Join(fmt.Errorf("error writing container %s of pod %s logs: %w", container.Name, pod.Name, err), errs)
			}

			_ = podLogsStream.Close()
		}
	}

	return errs
}

// k8sKustomizeAdjustObjects adjusts the namespace of given k8s objects and calls the given callbacks for the containers and the pod
func k8sKustomizeAdjustObjects(objects []k8s.Object, namespace string, containerName string, cbContainer func(container *corev1.Container), cbPod func(pod *corev1.PodSpec)) {
	// Update the agent image and image pull policy as it is already loaded in kind cluster
	for _, obj := range objects {
		obj.SetNamespace(namespace)
		var podSpec *corev1.PodSpec
		switch objWithType := obj.(type) {
		case *appsv1.DaemonSet:
			podSpec = &objWithType.Spec.Template.Spec
		case *appsv1.StatefulSet:
			podSpec = &objWithType.Spec.Template.Spec
		case *appsv1.Deployment:
			podSpec = &objWithType.Spec.Template.Spec
		case *appsv1.ReplicaSet:
			podSpec = &objWithType.Spec.Template.Spec
		case *batchv1.Job:
			podSpec = &objWithType.Spec.Template.Spec
		case *batchv1.CronJob:
			podSpec = &objWithType.Spec.JobTemplate.Spec.Template.Spec
		default:
			continue
		}

		if cbPod != nil {
			cbPod(podSpec)
		}

		for idx, container := range podSpec.Containers {
			if container.Name != containerName {
				continue
			}
			if cbContainer != nil {
				cbContainer(&podSpec.Containers[idx])
			}
		}
	}
}

// k8sYAMLToObjects converts the given YAML reader to a list of k8s objects
func k8sYAMLToObjects(reader *bufio.Reader) ([]k8s.Object, error) {
	// if we need to encode/decode more k8s object types in our tests, add them here
	k8sScheme := runtime.NewScheme()
	k8sScheme.AddKnownTypes(rbacv1.SchemeGroupVersion, &rbacv1.ClusterRoleBinding{}, &rbacv1.ClusterRoleBindingList{})
	k8sScheme.AddKnownTypes(rbacv1.SchemeGroupVersion, &rbacv1.ClusterRole{}, &rbacv1.ClusterRoleList{})
	k8sScheme.AddKnownTypes(rbacv1.SchemeGroupVersion, &rbacv1.RoleBinding{}, &rbacv1.RoleBindingList{})
	k8sScheme.AddKnownTypes(rbacv1.SchemeGroupVersion, &rbacv1.Role{}, &rbacv1.RoleList{})
	k8sScheme.AddKnownTypes(corev1.SchemeGroupVersion, &corev1.ServiceAccount{}, &corev1.ServiceAccountList{})
	k8sScheme.AddKnownTypes(corev1.SchemeGroupVersion, &corev1.Pod{}, &corev1.PodList{})
	k8sScheme.AddKnownTypes(corev1.SchemeGroupVersion, &corev1.Service{}, &corev1.ServiceList{})
	k8sScheme.AddKnownTypes(appsv1.SchemeGroupVersion, &appsv1.DaemonSet{})
	k8sScheme.AddKnownTypes(appsv1.SchemeGroupVersion, &appsv1.StatefulSet{})
	k8sScheme.AddKnownTypes(appsv1.SchemeGroupVersion, &appsv1.Deployment{})
	k8sScheme.AddKnownTypes(corev1.SchemeGroupVersion, &corev1.Secret{}, &corev1.ConfigMap{})

	var objects []k8s.Object
	decoder := serializer.NewCodecFactory(k8sScheme).UniversalDeserializer()
	yamlReader := yaml.NewYAMLReader(reader)
	for {
		yamlBytes, err := yamlReader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to read YAML: %w", err)
		}
		obj, _, err := decoder.Decode(yamlBytes, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decode YAML: %w", err)
		}

		k8sObj, ok := obj.(k8s.Object)
		if !ok {
			return nil, fmt.Errorf("failed to cast object to k8s.Object: %v", obj)
		}

		objects = append(objects, k8sObj)
	}

	return objects, nil
}

// k8sRenderKustomize renders the given kustomize directory to YAML
func k8sRenderKustomize(kustomizePath string) ([]byte, error) {
	// Create a file system pointing to the kustomize directory
	fSys := filesys.MakeFsOnDisk()

	// Create a kustomizer
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())

	// Run the kustomizer on the given directory
	resMap, err := k.Run(fSys, kustomizePath)
	if err != nil {
		return nil, err
	}

	// Convert the result to YAML
	renderedManifest, err := resMap.AsYaml()
	if err != nil {
		return nil, err
	}

	return renderedManifest, nil
}

// generateESAPIKey generates an API key for the given Elasticsearch.
func generateESAPIKey(esClient *elasticsearch.Client, keyName string) (string, error) {
	apiKeyReqBody := fmt.Sprintf(`{
		"name": "%s",
		"expiration": "1d"
	}`, keyName)

	resp, err := esClient.Security.CreateAPIKey(strings.NewReader(apiKeyReqBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	response := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return "", err
	}

	keyToken := response["api_key"].(string)
	if keyToken == "" {
		return "", fmt.Errorf("key token is empty")
	}

	keyID := response["id"].(string)
	if keyID == "" {
		return "", fmt.Errorf("key ID is empty")
	}

	return fmt.Sprintf("%s:%s", keyID, keyToken), nil
}

// k8sDeleteOpts contains options for deleting k8s objects
type k8sDeleteOpts struct {
	// wait for the objects to be deleted
	wait bool
	// timeout for waiting for the objects to be deleted
	waitTimeout time.Duration
}

// k8sDeleteObjects deletes the given k8s objects and waits for them to be deleted if wait is true.
func k8sDeleteObjects(ctx context.Context, client klient.Client, opts k8sDeleteOpts, objects ...k8s.Object) error {
	if len(objects) == 0 {
		return nil
	}

	// Delete the objects
	for _, obj := range objects {
		_ = client.Resources(obj.GetNamespace()).Delete(ctx, obj)
	}

	if !opts.wait {
		// no need to wait
		return nil
	}

	if opts.waitTimeout == 0 {
		// default to 20 seconds
		opts.waitTimeout = 20 * time.Second
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, opts.waitTimeout)
	defer timeoutCancel()
	for _, obj := range objects {
		for {
			if timeoutCtx.Err() != nil {
				return errors.New("timeout waiting for k8s objects to be deleted")
			}

			err := client.Resources().Get(timeoutCtx, obj.GetName(), obj.GetNamespace(), obj)
			if err != nil {
				// object has been deleted
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil
}

// int64Ptr returns a pointer to the given int64
func int64Ptr(val int64) *int64 {
	valPtr := val
	return &valPtr
}

// k8sCreateOpts contains options for k8sCreateObjects
type k8sCreateOpts struct {
	// namespace is the namespace to create the objects in
	namespace string
	// wait specifies whether to wait for the objects to be ready
	wait bool
	// waitTimeout is the timeout for waiting for the objects to be ready if wait is true
	waitTimeout time.Duration
}

// k8sCreateObjects creates k8s objects and waits for them to be ready if specified in opts.
// Note that if opts.namespace is not empty, all objects will be created and updated to reference
// the given namespace.
func k8sCreateObjects(ctx context.Context, client klient.Client, opts k8sCreateOpts, objects ...k8s.Object) error {
	// Create the objects
	for _, obj := range objects {
		if opts.namespace != "" {
			// update the namespace
			obj.SetNamespace(opts.namespace)

			// special case for ClusterRoleBinding and RoleBinding
			// update the subjects to reference the given namespace
			switch objWithType := obj.(type) {
			case *rbacv1.ClusterRoleBinding:
				for idx := range objWithType.Subjects {
					objWithType.Subjects[idx].Namespace = opts.namespace
				}
				continue
			case *rbacv1.RoleBinding:
				for idx := range objWithType.Subjects {
					objWithType.Subjects[idx].Namespace = opts.namespace
				}
				continue
			}
		}
		if err := client.Resources().Create(ctx, obj); err != nil {
			return fmt.Errorf("failed to create object %s: %w", obj.GetName(), err)
		}
	}

	if !opts.wait {
		// no need to wait
		return nil
	}

	if opts.waitTimeout == 0 {
		// default to 120 seconds
		opts.waitTimeout = 120 * time.Second
	}

	return k8sWaitForReady(ctx, client, opts.waitTimeout, objects...)
}

// k8sWaitForReady waits for the given k8s objects to be ready
func k8sWaitForReady(ctx context.Context, client klient.Client, waitDuration time.Duration, objects ...k8s.Object) error {
	// use ready checker from helm kube
	clientSet, err := kubernetes.NewForConfig(client.RESTConfig())
	if err != nil {
		return fmt.Errorf("error creating clientset: %w", err)
	}
	readyChecker := helmKube.NewReadyChecker(clientSet, func(s string, i ...interface{}) {})

	ctxTimeout, cancel := context.WithTimeout(ctx, waitDuration)
	defer cancel()

	waitFn := func(ri *cliResource.Info) error {
		// here we wait for the k8s object (e.g. deployment, daemonset, pod) to be ready
		for {
			ready, readyErr := readyChecker.IsReady(ctxTimeout, ri)
			if ready {
				// k8s object is ready
				return nil
			}
			// k8s object is not ready yet
			readyErr = errors.Join(fmt.Errorf("k8s object %s is not ready", ri.Name), readyErr)

			if ctxTimeout.Err() != nil {
				// timeout
				return errors.Join(fmt.Errorf("timeout waiting for k8s object %s to be ready", ri.Name), readyErr)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	for _, o := range objects {
		// convert k8s.Object to resource.Info for ready checker
		runtimeObj, ok := o.(runtime.Object)
		if !ok {
			return fmt.Errorf("unable to convert k8s.Object %s to runtime.Object", o.GetName())
		}

		if err := waitFn(&cliResource.Info{
			Object:    runtimeObj,
			Name:      o.GetName(),
			Namespace: o.GetNamespace(),
		}); err != nil {
			return err
		}
		// extract pod label selector for all k8s objects that have underlying pods
		oPodsLabelSelector, err := helmKube.SelectorsForObject(runtimeObj)
		if err != nil {
			// k8s object does not have pods
			continue
		}

		podList, err := clientSet.CoreV1().Pods(o.GetNamespace()).List(ctx, metav1.ListOptions{
			LabelSelector: oPodsLabelSelector.String(),
		})
		if err != nil {
			return fmt.Errorf("error listing pods: %w", err)
		}

		// here we wait for the all pods to be ready
		for _, pod := range podList.Items {
			if err := waitFn(&cliResource.Info{
				Object:    &pod,
				Name:      pod.Name,
				Namespace: pod.Namespace,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

// k8sContext contains all the information needed to run a k8s test
type k8sContext struct {
	client    klient.Client
	clientSet *kubernetes.Clientset
	// logsBasePath is the path that will be used to store the pod logs in a case a test fails
	logsBasePath string
	// agentImage is the full image of elastic-agent to use in the test
	agentImage string
	// agentImageRepo is the repository of elastic-agent image to use in the test
	agentImageRepo string
	// agentImageTag is the tag of elastic-agent image to use in the test
	agentImageTag string
	// esHost is the host of the elasticsearch to use in the test
	esHost string
	// esAPIKey is the API key of the elasticsearch to use in the test
	esAPIKey string
	// enrollParams contains the information needed to enroll an agent with Fleet in the test
	enrollParams *fleettools.EnrollParams
}

// getNamespace returns a unique namespace for the current test
func (k8sContext) getNamespace(t *testing.T) string {
	hasher := sha256.New()
	hasher.Write([]byte(t.Name()))
	testNamespace := strings.ToLower(base64.URLEncoding.EncodeToString(hasher.Sum(nil)))
	return noSpecialCharsRegexp.ReplaceAllString(testNamespace, "")
}

func k8sSchedulableNodeCount(ctx context.Context, kCtx k8sContext) (int, error) {
	nodeList := corev1.NodeList{}
	err := kCtx.client.Resources().List(ctx, &nodeList)
	if err != nil {
		return 0, err
	}

	totalSchedulableNodes := 0

	for _, node := range nodeList.Items {
		if node.Spec.Unschedulable {
			continue
		}

		hasNoScheduleTaint := false
		for _, taint := range node.Spec.Taints {
			if taint.Effect == corev1.TaintEffectNoSchedule {
				hasNoScheduleTaint = true
				break
			}
		}

		if hasNoScheduleTaint {
			continue
		}

		totalSchedulableNodes++
	}

	return totalSchedulableNodes, err
}

// k8sGetContext performs all the necessary checks to get a k8sContext for the current test
func k8sGetContext(t *testing.T, info *define.Info) k8sContext {
	agentImage := os.Getenv("AGENT_IMAGE")
	require.NotEmpty(t, agentImage, "AGENT_IMAGE must be set")

	agentImageParts := strings.SplitN(agentImage, ":", 2)
	require.Len(t, agentImageParts, 2, "AGENT_IMAGE must be in the form '<repository>:<version>'")
	agentImageRepo := agentImageParts[0]
	agentImageTag := agentImageParts[1]

	client, err := info.KubeClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	clientSet, err := kubernetes.NewForConfig(client.RESTConfig())
	require.NoError(t, err)
	require.NotNil(t, clientSet)

	testLogsBasePath := os.Getenv("K8S_TESTS_POD_LOGS_BASE")
	require.NotEmpty(t, testLogsBasePath, "K8S_TESTS_POD_LOGS_BASE must be set")

	err = os.MkdirAll(filepath.Join(testLogsBasePath, t.Name()), 0o755)
	require.NoError(t, err, "failed to create test logs directory")

	esHost := os.Getenv("ELASTICSEARCH_HOST")
	require.NotEmpty(t, esHost, "ELASTICSEARCH_HOST must be set")

	esAPIKey, err := generateESAPIKey(info.ESClient, info.Namespace)
	require.NoError(t, err, "failed to generate ES API key")
	require.NotEmpty(t, esAPIKey, "failed to generate ES API key")

	enrollParams, err := fleettools.NewEnrollParams(context.Background(), info.KibanaClient)
	require.NoError(t, err, "failed to create fleet enroll params")

	return k8sContext{
		client:         client,
		clientSet:      clientSet,
		agentImage:     agentImage,
		agentImageRepo: agentImageRepo,
		agentImageTag:  agentImageTag,
		logsBasePath:   testLogsBasePath,
		esHost:         esHost,
		esAPIKey:       esAPIKey,
		enrollParams:   enrollParams,
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
}

// k8sStepDeployKustomize renders a kustomize manifest and deploys it. Also, it tries to
// adjust the k8s objects created from the rendering to match the needs of the current test with k8sKustomizeOverrides.
// However, this is not that as flexible as we would like it to be. As a last resort somebody can use forEachObject callback
// to further adjust the k8s objects
func k8sStepDeployKustomize(kustomizePath string, containerName string, overrides k8sKustomizeOverrides, forEachObject func(object k8s.Object)) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		renderedManifest, err := k8sRenderKustomize(kustomizePath)
		require.NoError(t, err, "failed to render kustomize")

		objects, err := k8sYAMLToObjects(bufio.NewReader(bytes.NewReader(renderedManifest)))
		require.NoError(t, err, "failed to parse rendered kustomize")

		if forEachObject != nil {
			for _, object := range objects {
				forEachObject(object)
			}
		}

		k8sKustomizeAdjustObjects(objects, namespace, containerName,
			func(container *corev1.Container) {
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
				}

				if len(overrides.agentContainerExtraEnv) > 0 {
					container.Env = append(container.Env, overrides.agentContainerExtraEnv...)
				}

				if overrides.agentContainerArgs != nil {
					// drop arguments overriding default config
					container.Args = []string{}
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
			})

		t.Cleanup(func() {
			if t.Failed() {
				if err := k8sDumpAllPodLogs(ctx, kCtx.client, namespace, namespace, kCtx.logsBasePath); err != nil {
					t.Logf("failed to dump logs: %v", err)
				}
			}

			err := k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: true}, objects...)
			if err != nil {
				t.Logf("failed to delete objects: %v", err)
			}
		})

		err = k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: true}, objects...)
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
			err = kCtx.client.Resources().ExecInPod(ctx, namespace, pod.Name, containerName,
				[]string{"/usr/share/elastic-agent/k8s-inner-tests", "-test.v"}, &stdout, &stderr)
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
				if err := k8sDumpAllPodLogs(ctx, kCtx.client, namespace, namespace, kCtx.logsBasePath); err != nil {
					t.Logf("failed to dump logs: %v", err)
				}
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

func k8sStepHintsRedisCreate() k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		r, err := os.Open("testdata/k8s.hints.redis.yaml")
		require.NoError(t, err, "failed to open redis k8s test data")

		redisObjs, err := k8sYAMLToObjects(bufio.NewReader(r))
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
			err := kCtx.client.Resources().ExecInPod(ctx, namespace, pod.Name, containerName, command, &stdout, &stderr)
			require.Error(t, err)
			require.Contains(t, stderr.String(), coordinator.ErrNotUpgradable.Error())
		}
	}
}

// GetAgentResponse extends kibana.GetAgentResponse and includes the EnrolledAt field
type GetAgentResponse struct {
	kibana.GetAgentResponse `json:",inline"`
	EnrolledAt              time.Time `json:"enrolled_at"`
}

// kibanaGetAgent essentially re-implements kibana.GetAgent to extract also GetAgentResponse.EnrolledAt
func kibanaGetAgent(ctx context.Context, kc *kibana.Client, id string) (*GetAgentResponse, error) {
	apiURL := fmt.Sprintf("/api/fleet/agents/%s", id)
	r, err := kc.Connection.SendWithContext(ctx, http.MethodGet, apiURL, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error calling get agent API: %w", err)
	}
	defer r.Body.Close()
	var agentResp struct {
		Item GetAgentResponse `json:"item"`
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error calling get agent API: %s", string(b))
	}
	err = json.Unmarshal(b, &agentResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling response json: %w", err)
	}
	return &agentResp.Item, nil
}
