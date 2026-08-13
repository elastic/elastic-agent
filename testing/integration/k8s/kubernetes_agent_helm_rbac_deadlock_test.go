// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

// Regression test for https://github.com/elastic/elastic-agent/issues/15666.
//
// The kubernetes integration is installed with a restricted ClusterRole that
// omits deployments.apps. The state_deployment metricset starts a deployment
// watcher; because LIST deployments.apps is denied, WaitForCacheSync blocks
// indefinitely inside watcher.Start(). enricher.Start() holds
// resourceWatchers.lock for the entire duration of that call.
//
// Updating the kubernetes Fleet policy (period change) triggers the
// elastic-otel-collector partial reload, which calls Shutdown() on the
// kubernetes/metrics receiver. Shutdown() → enricher.Stop() tries to acquire
// resourceWatchers.lock — which is permanently held by the blocked
// enricher.Start() → deadlock → component stays in STOPPING permanently.
//
// Fix (beats): release resourceWatchers.lock before calling watcher.Start(),
// so a concurrent enricher.Stop() can acquire the lock, cancel the watcher
// context, and unblock WaitForCacheSync.

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
	"github.com/elastic/elastic-agent/pkg/testing/tools"
)

const (
	rbacDeadlockAgentPodSelector        = "name=agent-pernode-helm-agent"
	rbacDeadlockAgentContainer          = "agent"
	rbacDeadlockKubernetesComponentName = "kubernetes/metrics"
)

// TestKubernetesAgentHelmRBACDeadlock replicates the scenario from
// https://github.com/elastic/elastic-agent/issues/15666.
//
// The kubernetes integration is installed with a restricted ClusterRole that
// omits deployments.apps. Once the agent is healthy, a Fleet policy update
// (period change) triggers the partial OTel reload that calls Shutdown() on
// the kubernetes/metrics receiver — the exact path where the deadlock lives.
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

	var (
		kubernetesPackagePolicyID string
		fleetAgentID              string
		fleetAgentPolicyRevision  int
	)

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepCreateRestrictedK8sClusterRole(restrictedRoleName),
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
		k8sStepWaitForComponentState(rbacDeadlockAgentPodSelector, schedulableNodeCount, rbacDeadlockAgentContainer,
			rbacDeadlockKubernetesComponentName, aclient.Healthy, 3*time.Minute),
		// Snapshot the Fleet agent ID and current policy revision before the
		// update so we can wait deterministically for the agent to acknowledge
		// the new policy (rather than sleeping a fixed amount of time).
		k8sStepSnapshotFleetAgent(info.KibanaClient, kCtx.enrollParams.PolicyID, &fleetAgentID, &fleetAgentPolicyRevision),
		// Changing the period triggers a partial OTel reload that calls
		// Shutdown() on kubernetes/metrics.
		k8sStepUpdateKubernetesIntegration(info.KibanaClient, kCtx.enrollParams.PolicyID, &kubernetesPackagePolicyID),
		// Wait until Fleet confirms the agent has acknowledged the new policy
		// revision. At that point the new config has been sent to the OTel
		// subprocess and the partial reload is in progress.
		k8sStepWaitForPolicyRevision(info.KibanaClient, &fleetAgentID, &fleetAgentPolicyRevision),
		// kubernetes/metrics must return to HEALTHY after the reload.
		// Without the fix: enricher.Stop() deadlocks on resourceWatchers.lock
		// and the component stays STOPPING permanently.
		k8sStepWaitForComponentState(rbacDeadlockAgentPodSelector, schedulableNodeCount, rbacDeadlockAgentContainer,
			rbacDeadlockKubernetesComponentName, aclient.Healthy, 2*time.Minute),
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

// k8sStepUpdateKubernetesIntegration updates the kubernetes package policy to
// change the collection period. This triggers a partial OTel reload that calls
// Shutdown() on the kubernetes/metrics receiver while the deployment watcher
// goroutine holds resourceWatchers.lock inside watcher.Start().
func k8sStepUpdateKubernetesIntegration(kc *kibana.Client, agentPolicyID string, policyID *string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.NotEmpty(t, *policyID, "package policy ID must be set before update")

		version, err := getFleetPackageVersion(ctx, kc, "kubernetes")
		require.NoError(t, err, "failed to resolve kubernetes package version")

		reqBody := map[string]interface{}{
			"name":      "kubernetes-" + uuid.Must(uuid.NewV4()).String(),
			"namespace": "default",
			"policy_id": agentPolicyID,
			"package": map[string]interface{}{
				"name":    "kubernetes",
				"version": version,
			},
			"vars": map[string]interface{}{},
			"inputs": []map[string]interface{}{
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
								"period":            map[string]interface{}{"type": "text", "value": "20s"},
								"bearer_token_file": map[string]interface{}{"type": "text", "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
							},
						},
					},
				},
			},
		}

		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err, "failed to marshal update request body")

		resp, err := kc.SendWithContext(ctx, http.MethodPut,
			"/api/fleet/package_policies/"+*policyID,
			nil, http.Header{"Content-Type": []string{"application/json"}}, bytes.NewReader(bodyBytes))
		require.NoError(t, err, "failed to send kubernetes Fleet package policy update")
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"Fleet package policy update returned unexpected status: %s", respBody)
	}
}

// k8sStepSnapshotFleetAgent finds the agent enrolled in agentPolicyID and
// records its Fleet ID and current policy revision. Call this before making a
// Fleet policy change so that k8sStepWaitForPolicyRevision can detect when the
// agent has acknowledged the update.
func k8sStepSnapshotFleetAgent(kc *kibana.Client, agentPolicyID string, agentIDOut *string, revisionOut *int) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		resp, err := kc.ListAgents(ctx, kibana.ListAgentsRequest{})
		require.NoError(t, err, "failed to list Fleet agents")

		for _, agent := range resp.Items {
			if agent.PolicyID == agentPolicyID {
				*agentIDOut = agent.ID
				*revisionOut = agent.PolicyRevision
				return
			}
		}
		require.Failf(t, "fleet agent not found", "no agent enrolled in policy %s", agentPolicyID)
	}
}

// k8sStepWaitForPolicyRevision waits until the Fleet agent has acknowledged a
// policy revision strictly greater than the snapshot captured by
// k8sStepSnapshotFleetAgent. This is the deterministic signal that the agent
// has received the updated policy and sent the new config to the OTel
// subprocess, triggering the partial reload.
func k8sStepWaitForPolicyRevision(kc *kibana.Client, agentID *string, snapshotRevision *int) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		require.NotEmpty(t, *agentID, "agent ID must be set before waiting for policy revision")
		require.Eventually(t,
			tools.IsMinPolicyRevision(ctx, t, kc, *agentID, *snapshotRevision+1),
			3*time.Minute, 5*time.Second,
			"agent %s did not acknowledge policy revision > %d within 3 minutes",
			*agentID, *snapshotRevision)
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
