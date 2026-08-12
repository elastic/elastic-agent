// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

// Regression test for https://github.com/elastic/elastic-agent/issues/15666.
//
// By default, elastic-agent routes all metricbeat-based inputs (including
// system/metrics and kubernetes/metrics) to the OtelRuntimeManager. Both
// integrations therefore run as OTel receivers inside a single
// elastic-otel-collector subprocess managed by elastic-agent.
//
// When Fleet pushes a policy update (e.g. system integration removed),
// the coordinator calls applyOTelUpdate, which shuts down ALL OTel-managed
// receivers and rebuilds the pipeline. During Shutdown() of the
// kubernetes/metrics receiver, enricher.Stop() tries to acquire
// resourceWatchers.lock. That lock is permanently held by enricher.Start()
// blocked inside watcher.Start() → cache.WaitForCacheSync(), which retries
// forever when the service account lacks LIST permission for deployments.apps.
// The elastic-otel-collector subprocess is still alive but internally
// deadlocked, so elastic-agent never applies a kill timeout — the component
// stays in STOPPING permanently.
//
// Fix (beats): release resourceWatchers.lock before calling watcher.Start(),
// so enricher.Stop() can acquire the lock, cancel the watcher context, and
// unblock WaitForCacheSync.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/elastic/elastic-agent-libs/kibana"
	aclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const (
	rbacDeadlockAgentPodSelector        = "name=agent-pernode-helm-agent"
	rbacDeadlockAgentContainer          = "agent"
	rbacDeadlockKubernetesComponentName = "kubernetes/metrics"
	rbacDeadlockSystemComponentName     = "system/metrics"
)

// TestKubernetesAgentHelmRBACDeadlock replicates the scenario from
// https://github.com/elastic/elastic-agent/issues/15666.
//
// Both integrations are installed before enrollment so the agent starts with
// both as OTel-managed receivers in one elastic-otel-collector subprocess.
// Removing system triggers applyOTelUpdate, which shuts down all receivers
// including kubernetes/metrics while its deployment watcher holds the lock.
func TestKubernetesAgentHelmRBACDeadlock(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes, DockerVariant: "basic"},
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background() //nolint:forbidigo // ctx is captured by t.Cleanup in step functions; must outlive the test
	kCtx := k8sGetContext(t, info)

	schedulableNodeCount, err := k8sSchedulableNodeCount(ctx, kCtx)
	require.NoError(t, err, "error getting schedulable node count")
	require.NotZero(t, schedulableNodeCount, "no schedulable kubernetes nodes found")

	testNamespace := kCtx.getNamespace(t)

	// ClusterRole is cluster-scoped; embed the namespace to keep names unique
	// across parallel runs.
	restrictedRoleName := "test-restricted-k8s-" + testNamespace

	var kubernetesPackagePolicyID string
	var systemPackagePolicyID string

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepCreateRestrictedK8sClusterRole(restrictedRoleName),
		// Populate the full policy before enrolling so the agent starts with
		// both integrations and elastic-otel-collector loads both receivers.
		k8sStepInstallSystemIntegration(info.KibanaClient, kCtx.enrollParams.PolicyID, &systemPackagePolicyID),
		k8sStepInstallKubernetesIntegration(info.KibanaClient, kCtx.enrollParams.PolicyID, &kubernetesPackagePolicyID),
		k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
			"agent": map[string]any{
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
				"presets": map[string]any{
					"perNode": map[string]any{
						"clusterRole": map[string]any{
							// Disable chart-managed ClusterRole creation and
							// bind to our restricted role instead.
							"create": false,
							"name":   restrictedRoleName,
						},
					},
				},
			},
		}),
		// Both components must be healthy before changing the policy.
		k8sStepWaitForComponentState(rbacDeadlockAgentPodSelector, schedulableNodeCount, rbacDeadlockAgentContainer,
			rbacDeadlockKubernetesComponentName, aclient.Healthy, 3*time.Minute),
		k8sStepWaitForComponentState(rbacDeadlockAgentPodSelector, schedulableNodeCount, rbacDeadlockAgentContainer,
			rbacDeadlockSystemComponentName, aclient.Healthy, 3*time.Minute),
		// Removing system triggers applyOTelUpdate, which calls Shutdown() on
		// all receivers including kubernetes/metrics. Fleet takes ~30 s to
		// propagate; the collection interval is 10 s, so the deployment watcher
		// is guaranteed to be running (and holding the lock) by then.
		k8sStepDeleteFleetPackage(info.KibanaClient, &systemPackagePolicyID),
		k8sStepWaitForReload(rbacDeadlockAgentPodSelector, schedulableNodeCount, rbacDeadlockAgentContainer,
			rbacDeadlockSystemComponentName, rbacDeadlockKubernetesComponentName, 2*time.Minute),
	}

	for _, step := range steps {
		step(t, ctx, kCtx, testNamespace)
		if t.Failed() {
			return
		}
	}
}

// k8sStepCreateRestrictedK8sClusterRole creates a ClusterRole that grants
// pod/node/event and namespace collection permissions but intentionally omits
// deployments.apps.
//
// The state_deployment metricset starts a deployment watcher. When it cannot
// list deployments, WaitForCacheSync blocks inside watcher.Start(), and
// enricher.Start() holds resourceWatchers.lock the entire time. That is the
// exact precondition for a concurrent enricher.Stop() to deadlock on that lock.
func k8sStepCreateRestrictedK8sClusterRole(roleName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: roleName,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{
						"namespaces",
						"pods",
						"nodes",
						"nodes/metrics",
						"nodes/proxy",
						"nodes/stats",
						"events",
					},
					Verbs: []string{"get", "watch", "list"},
				},
				{
					APIGroups: []string{"coordination.k8s.io"},
					Resources: []string{"leases"},
					Verbs:     []string{"get", "create", "update"},
				},
				{
					APIGroups: []string{"apps"},
					Resources: []string{"replicasets"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					NonResourceURLs: []string{"/metrics", "/healthz", "/healthz/*", "/livez", "/livez/*", "/readyz", "/readyz/*"},
					Verbs:           []string{"get"},
				},
			},
		}

		t.Cleanup(func() {
			if err := k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: false}, cr); err != nil {
				t.Logf("failed to delete restricted ClusterRole %s: %v", roleName, err)
			}
		})

		require.NoError(t, k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: false}, cr),
			"failed to create restricted ClusterRole")
	}
}

// k8sStepInstallKubernetesIntegration enables only the state_deployment stream —
// the metricset that starts the deployment watcher responsible for the deadlock.
// leaderelection is disabled so every pod exercises the deadlock path.
func k8sStepInstallKubernetesIntegration(kc *kibana.Client, agentPolicyID string, policyIDOut *string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		version, err := getFleetPackageVersion(ctx, kc, "kubernetes")
		require.NoError(t, err, "failed to resolve kubernetes package version")

		policyUUID := uuid.Must(uuid.NewV4()).String()
		resp, err := kc.InstallFleetPackage(ctx, kibana.PackagePolicyRequest{
			Name:      "kubernetes-" + policyUUID,
			Namespace: "default",
			PolicyID:  agentPolicyID,
			Package: kibana.PackagePolicyRequestPackage{
				Name:    "kubernetes",
				Version: version,
			},
			Vars: map[string]interface{}{},
			Inputs: []map[string]interface{}{
				{
					"type":            "kubernetes/metrics",
					"policy_template": "kube-state-metrics",
					"enabled":         true,
					"vars":            map[string]interface{}{},
					"streams": []map[string]interface{}{
						{
							"enabled": true,
							"data_stream": map[string]interface{}{
								"type":    "metrics",
								"dataset": "kubernetes.state_deployment",
							},
							"vars": map[string]interface{}{
								"add_metadata": map[string]interface{}{"type": "bool", "value": true},
								"hosts": map[string]interface{}{
									"type":  "text",
									"value": []string{"kube-state-metrics:8080"},
								},
								"leaderelection":    map[string]interface{}{"type": "bool", "value": false},
								"period":            map[string]interface{}{"type": "text", "value": "10s"},
								"bearer_token_file": map[string]interface{}{"type": "text", "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
							},
						},
					},
				},
			},
		})
		require.NoError(t, err, "failed to install kubernetes Fleet package")
		*policyIDOut = resp.Item.ID
		t.Cleanup(func() {
			if *policyIDOut == "" {
				return
			}
			if _, err := kc.DeleteFleetPackage(ctx, *policyIDOut); err != nil {
				t.Logf("failed to delete Fleet package policy %s: %v", *policyIDOut, err)
			}
		})
	}
}

// k8sStepInstallSystemIntegration installs a minimal system/cpu policy; removing
// it later triggers applyOTelUpdate, which shuts down all receivers including
// kubernetes/metrics.
func k8sStepInstallSystemIntegration(kc *kibana.Client, agentPolicyID string, policyIDOut *string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		version, err := getFleetPackageVersion(ctx, kc, "system")
		require.NoError(t, err, "failed to resolve system package version")

		policyUUID := uuid.Must(uuid.NewV4()).String()
		resp, err := kc.InstallFleetPackage(ctx, kibana.PackagePolicyRequest{
			Name:      "system-" + policyUUID,
			Namespace: "default",
			PolicyID:  agentPolicyID,
			Package: kibana.PackagePolicyRequestPackage{
				Name:    "system",
				Version: version,
			},
			Vars: map[string]interface{}{},
			Inputs: []map[string]interface{}{
				{
					"type":            "system/metrics",
					"policy_template": "system",
					"enabled":         true,
					"vars":            map[string]interface{}{},
					"streams": []map[string]interface{}{
						{
							"enabled": true,
							"data_stream": map[string]interface{}{
								"type":    "metrics",
								"dataset": "system.cpu",
							},
							"vars": map[string]interface{}{
								"period": map[string]interface{}{"type": "text", "value": "10s"},
								"cpu.metrics": map[string]interface{}{
									"type":  "text",
									"value": []string{"percentages", "normalized_percentages"},
								},
							},
						},
					},
				},
			},
		})
		require.NoError(t, err, "failed to install system Fleet package")
		*policyIDOut = resp.Item.ID
		t.Cleanup(func() {
			if *policyIDOut == "" {
				return
			}
			if _, err := kc.DeleteFleetPackage(ctx, *policyIDOut); err != nil {
				t.Logf("failed to delete Fleet package policy %s: %v", *policyIDOut, err)
			}
		})
	}
}

// k8sStepDeleteFleetPackage deletes the package policy stored in *policyID,
// triggering a policy reload on enrolled agents.
func k8sStepDeleteFleetPackage(kc *kibana.Client, policyID *string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.NotEmpty(t, *policyID, "package policy ID must be set before deletion")
		_, err := kc.DeleteFleetPackage(ctx, *policyID)
		require.NoError(t, err, "failed to delete Fleet package policy %s", *policyID)
		*policyID = ""
	}
}

func k8sStepWaitForComponentState(
	agentPodLabelSelector string, expectedPodNumber int, containerName string,
	componentName string, expectedState aclient.State, timeout time.Duration,
) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		podList := listAgentPods(t, ctx, kCtx, namespace, agentPodLabelSelector, expectedPodNumber)

		for _, pod := range podList.Items {
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				status, err := execAgentStatus(ctx, kCtx, namespace, pod.Name, containerName)
				if !assert.NoError(c, err, "failed to get agent status in pod %s", pod.Name) {
					return
				}
				state, found := getAgentComponentState(status, componentName)
				if assert.True(c, found, "component %s not yet present in pod %s", componentName, pod.Name) {
					assert.Equal(c, int(expectedState), state,
						"component %s in pod %s has state %d, want %s",
						componentName, pod.Name, state, expectedState)
				}
			}, timeout, 2*time.Second,
				"component %s did not reach %s in pod %s within %s",
				componentName, expectedState, pod.Name, timeout)
		}
	}
}

// k8sStepWaitForReload waits until the removed component disappears and the
// retained component returns to HEALTHY.
func k8sStepWaitForReload(
	agentPodLabelSelector string, expectedPodNumber int, containerName string,
	removedComponentName, retainedComponentName string, timeout time.Duration,
) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		podList := listAgentPods(t, ctx, kCtx, namespace, agentPodLabelSelector, expectedPodNumber)

		for _, pod := range podList.Items {
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				status, err := execAgentStatus(ctx, kCtx, namespace, pod.Name, containerName)
				if !assert.NoError(c, err, "failed to get agent status in pod %s", pod.Name) {
					return
				}
				_, removedFound := getAgentComponentState(status, removedComponentName)
				assert.False(c, removedFound,
					"removed component %s is still present in pod %s", removedComponentName, pod.Name)

				retainedState, retainedFound := getAgentComponentState(status, retainedComponentName)
				if assert.True(c, retainedFound,
					"retained component %s is missing from pod %s", retainedComponentName, pod.Name) {
					assert.Equal(c, int(aclient.Healthy), retainedState,
						"retained component %s in pod %s has state %d, want HEALTHY",
						retainedComponentName, pod.Name, retainedState)
				}
			}, timeout, 2*time.Second,
				"reload did not complete in pod %s within %s — %s likely deadlocked in STOPPING",
				pod.Name, timeout, retainedComponentName)
		}
	}
}

func getFleetPackageVersion(ctx context.Context, kc *kibana.Client, packageName string) (string, error) {
	resp, err := kc.SendWithContext(ctx, http.MethodGet,
		"/api/fleet/epm/packages/"+packageName, nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("querying EPM for %s: %w", packageName, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading EPM response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("EPM returned %d for %s: %s", resp.StatusCode, packageName, body)
	}

	var result struct {
		Item struct {
			Version string `json:"version"`
		} `json:"item"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing EPM response: %w", err)
	}
	if result.Item.Version == "" {
		return "", fmt.Errorf("EPM response for %s has no version field: %s", packageName, body)
	}
	return result.Item.Version, nil
}

func listAgentPods(
	t *testing.T, ctx context.Context, kCtx k8sContext,
	namespace, selector string, expected int,
) *corev1.PodList {
	t.Helper()
	podList := &corev1.PodList{}
	err := kCtx.client.Resources(namespace).List(ctx, podList, func(opt *metav1.ListOptions) {
		opt.LabelSelector = selector
	})
	require.NoError(t, err, "failed to list pods with selector %s", selector)
	require.Len(t, podList.Items, expected,
		"unexpected number of pods with selector %s", selector)
	return podList
}

// execAgentStatus runs `elastic-agent status --output=json` inside the
// container and returns the parsed output. The command exits non-zero when the
// agent is unhealthy, so valid JSON takes precedence over the exit status.
func execAgentStatus(
	ctx context.Context, kCtx k8sContext,
	namespace, podName, containerName string,
) (atesting.AgentStatusOutput, error) {
	var stdout, stderr bytes.Buffer
	execCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	execErr := kCtx.client.Resources().ExecInPod(execCtx, namespace, podName, containerName,
		[]string{"elastic-agent", "status", "--output=json"}, &stdout, &stderr)

	var status atesting.AgentStatusOutput
	parseErr := json.Unmarshal(stdout.Bytes(), &status)
	if parseErr == nil {
		return status, nil
	}
	if execErr != nil {
		return status, fmt.Errorf(
			"executing elastic-agent status: %w (stdout: %s; stderr: %s; JSON error: %w)",
			execErr, stdout.String(), stderr.String(), parseErr)
	}
	return status, fmt.Errorf("parsing elastic-agent status: %w (stdout: %s; stderr: %s)",
		parseErr, stdout.String(), stderr.String())
}
