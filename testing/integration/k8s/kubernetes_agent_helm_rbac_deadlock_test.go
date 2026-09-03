// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const (
	rbacDeadlockAgentPodSelector          = "name=agent-pernode-helm-agent"
	rbacDeadlockAgentContainer            = "agent"
	rbacDeadlockDeniedLogMessage          = "deployments.apps is forbidden"
	rbacDeadlockReloadStartedLogMessage   = "Config updated, performing partial receiver reload"
	rbacDeadlockReloadCompleteLogMessage  = "Partial receiver reload completed successfully"
	rbacDeadlockInitialPeriod             = "10s"
	rbacDeadlockUpdatedPeriod             = "20s"
	rbacDeadlockUpdatedPeriodMilliseconds = 20000
)

type rbacTestAgent struct {
	podName      string
	podUID       types.UID
	restartCount int32
	agentID      string
}

type podLogEvents struct {
	stream    io.ReadCloser
	scanner   *bufio.Scanner
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// TestKubernetesAgentHelmRBACDeadlock verifies that a policy reload completes
// while deployment access is denied and that collection starts after access is
// granted, without restarting the agent.
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

	ctx := context.Background() //nolint:forbidigo // cleanup functions use this context after the test body returns
	kCtx := k8sGetContext(t, info)
	namespace := kCtx.getNamespace(t)
	roleName := "test-restricted-k8s-" + namespace
	probeDeploymentName := "rbac-recovery-probe-" + uuid.Must(uuid.NewV4()).String()

	runStep := func(step k8sTestStep) {
		step(t, ctx, kCtx, namespace)
	}

	runStep(k8sStepCreateNamespace())
	createRBACRecoveryProbe(t, ctx, kCtx, namespace, probeDeploymentName)
	createRestrictedK8sClusterRole(t, ctx, kCtx, roleName)
	packagePolicyID, packagePolicy := installKubernetesIntegration(t, ctx, info.KibanaClient, kCtx.enrollParams.PolicyID)
	runStep(k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
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
						"create": false,
						"name":   roleName,
					},
				},
			},
		},
	}))

	agent := selectRBACAgent(t, ctx, kCtx, namespace)
	initialEvents := openPodLogEvents(t, ctx, kCtx, namespace, agent.podName, false)
	initialEvents.waitFor(t, rbacDeadlockDeniedLogMessage)
	initialEvents.close()
	agent.agentID = readAgentID(t, ctx, kCtx, namespace, agent.podName)

	reloadEvents := openPodLogEvents(t, ctx, kCtx, namespace, agent.podName, true)
	updateKubernetesIntegration(t, ctx, info.KibanaClient, packagePolicyID, packagePolicy)
	reloadEvents.waitFor(t, rbacDeadlockReloadStartedLogMessage)
	reloadEvents.waitFor(t, rbacDeadlockReloadCompleteLogMessage)
	reloadEvents.waitFor(t, rbacDeadlockDeniedLogMessage)
	reloadEvents.close()

	grantDeploymentRBAC(t, ctx, kCtx, roleName)
	waitForRecoveredDeploymentMetrics(t, ctx, info, namespace, probeDeploymentName, agent.agentID)
	assertAgentDidNotRestart(t, ctx, kCtx, namespace, agent)
}

func createRBACRecoveryProbe(
	t *testing.T,
	ctx context.Context,
	kCtx k8sContext,
	namespace string,
	deploymentName string,
) {
	t.Helper()
	replicas := int32(0)
	labels := map[string]string{"app": deploymentName}
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    "probe",
						Image:   "unused",
						Command: []string{"true"},
					}},
				},
			},
		},
	}

	require.NoError(t,
		k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: false}, deployment),
		"failed to create RBAC recovery probe deployment")
}

func createRestrictedK8sClusterRole(t *testing.T, ctx context.Context, kCtx k8sContext, roleName string) {
	t.Helper()
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: roleName},
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
		if err := k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: false}, role); err != nil {
			t.Logf("failed to delete restricted ClusterRole %s: %v", roleName, err)
		}
	})

	require.NoError(t, k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: false}, role),
		"failed to create restricted ClusterRole")
}

func installKubernetesIntegration(
	t *testing.T,
	ctx context.Context,
	kc *kibana.Client,
	agentPolicyID string,
) (string, kibana.PackagePolicyRequest) {
	t.Helper()
	version, err := getFleetPackageVersion(ctx, kc, "kubernetes")
	require.NoError(t, err, "failed to resolve kubernetes package version")

	request := kubernetesPackagePolicyRequest(agentPolicyID, version, rbacDeadlockInitialPeriod)
	response, err := kc.InstallFleetPackage(ctx, request)
	require.NoError(t, err, "failed to install kubernetes Fleet package")

	policyID := response.Item.ID
	t.Cleanup(func() {
		if _, err := kc.DeleteFleetPackage(ctx, policyID); err != nil {
			t.Logf("failed to delete Fleet package policy %s: %v", policyID, err)
		}
	})
	return policyID, request
}

func updateKubernetesIntegration(
	t *testing.T,
	ctx context.Context,
	kc *kibana.Client,
	packagePolicyID string,
	request kibana.PackagePolicyRequest,
) {
	t.Helper()
	request.Inputs = kubernetesPackagePolicyInputs(rbacDeadlockUpdatedPeriod)

	body, err := json.Marshal(request)
	require.NoError(t, err, "failed to marshal kubernetes Fleet package policy update")

	response, err := kc.SendWithContext(ctx, http.MethodPut,
		"/api/fleet/package_policies/"+packagePolicyID,
		nil, http.Header{"Content-Type": []string{"application/json"}}, bytes.NewReader(body))
	require.NoError(t, err, "failed to update kubernetes Fleet package policy")
	defer response.Body.Close()

	responseBody, _ := io.ReadAll(response.Body)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"Fleet package policy update returned unexpected status: %s", responseBody)
}

func kubernetesPackagePolicyRequest(agentPolicyID, version, period string) kibana.PackagePolicyRequest {
	return kibana.PackagePolicyRequest{
		Name:      "kubernetes-" + uuid.Must(uuid.NewV4()).String(),
		Namespace: "default",
		PolicyID:  agentPolicyID,
		Package: kibana.PackagePolicyRequestPackage{
			Name:    "kubernetes",
			Version: version,
		},
		Vars:   map[string]interface{}{},
		Inputs: kubernetesPackagePolicyInputs(period),
	}
}

func kubernetesPackagePolicyInputs(period string) []map[string]interface{} {
	return []map[string]interface{}{
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
						"period":            map[string]interface{}{"type": "text", "value": period},
						"bearer_token_file": map[string]interface{}{"type": "text", "value": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
					},
				},
			},
		},
	}
}

func selectRBACAgent(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) rbacTestAgent {
	t.Helper()
	pods := &corev1.PodList{}
	err := kCtx.client.Resources(namespace).List(ctx, pods, func(options *metav1.ListOptions) {
		options.LabelSelector = rbacDeadlockAgentPodSelector
	})
	require.NoError(t, err, "failed to list Elastic Agent pods")
	require.NotEmpty(t, pods.Items, "no Elastic Agent pods found")

	sort.Slice(pods.Items, func(i, j int) bool {
		return pods.Items[i].Name < pods.Items[j].Name
	})
	pod := &pods.Items[0]

	return rbacTestAgent{
		podName:      pod.Name,
		podUID:       pod.UID,
		restartCount: containerRestartCount(t, pod, rbacDeadlockAgentContainer),
	}
}

func openPodLogEvents(
	t *testing.T,
	ctx context.Context,
	kCtx k8sContext,
	namespace string,
	podName string,
	onlyNew bool,
) *podLogEvents {
	t.Helper()
	eventsCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	options := &corev1.PodLogOptions{
		Container: rbacDeadlockAgentContainer,
		Follow:    true,
	}
	if onlyNew {
		tailLines := int64(0)
		options.TailLines = &tailLines
	}

	stream, err := kCtx.clientSet.CoreV1().Pods(namespace).GetLogs(podName, options).Stream(eventsCtx)
	if err != nil {
		cancel()
		require.NoError(t, err, "failed to follow logs for pod %s", podName)
	}

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	events := &podLogEvents{
		stream:  stream,
		scanner: scanner,
		cancel:  cancel,
	}
	t.Cleanup(events.close)
	return events
}

func (events *podLogEvents) waitFor(t *testing.T, message string) {
	t.Helper()
	for events.scanner.Scan() {
		if strings.Contains(events.scanner.Text(), message) {
			return
		}
	}
	if err := events.scanner.Err(); err != nil {
		require.NoError(t, err, "log stream ended before event %q", message)
	}
	require.Failf(t, "log event not found", "log stream ended before event %q", message)
}

func (events *podLogEvents) close() {
	events.closeOnce.Do(func() {
		events.cancel()
		_ = events.stream.Close()
	})
}

func readAgentID(
	t *testing.T,
	ctx context.Context,
	kCtx k8sContext,
	namespace string,
	podName string,
) string {
	t.Helper()
	status, err := execAgentStatus(ctx, kCtx, namespace, podName, rbacDeadlockAgentContainer)
	require.NoError(t, err, "failed to read Elastic Agent status")
	require.NotEmpty(t, status.Info.ID, "Elastic Agent status has no agent ID")
	return status.Info.ID
}

func grantDeploymentRBAC(t *testing.T, ctx context.Context, kCtx k8sContext, roleName string) {
	t.Helper()
	role := &rbacv1.ClusterRole{}
	require.NoError(t, kCtx.client.Resources().Get(ctx, roleName, "", role),
		"failed to get restricted ClusterRole")

	role.Rules = append(role.Rules, rbacv1.PolicyRule{
		APIGroups: []string{"apps"},
		Resources: []string{"deployments"},
		Verbs:     []string{"get", "list", "watch"},
	})
	require.NoError(t, kCtx.client.Resources().Update(ctx, role),
		"failed to grant deployment access to restricted ClusterRole")
}

func waitForRecoveredDeploymentMetrics(
	t *testing.T,
	ctx context.Context,
	info *define.Info,
	namespace string,
	deploymentName string,
	agentID string,
) {
	t.Helper()
	query := map[string]any{
		"size":             0,
		"track_total_hits": true,
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					map[string]any{"term": map[string]any{"data_stream.type": "metrics"}},
					map[string]any{"term": map[string]any{"data_stream.dataset": "kubernetes.state_deployment"}},
					map[string]any{"term": map[string]any{"data_stream.namespace": "default"}},
					map[string]any{"term": map[string]any{"agent.id": agentID}},
					map[string]any{"term": map[string]any{"kubernetes.deployment.name": deploymentName}},
					map[string]any{"term": map[string]any{"kubernetes.namespace": namespace}},
					map[string]any{"term": map[string]any{"metricset.period": rbacDeadlockUpdatedPeriodMilliseconds}},
				},
			},
		},
	}

	require.EventuallyWithT(t, func(collectT *assert.CollectT) {
		queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		docs, err := estools.PerformQueryForRawQuery(queryCtx, query,
			".ds-metrics-kubernetes.state_deployment-default*", info.ESClient)
		if !assert.NoError(collectT, err, "failed to query recovered deployment metrics") {
			return
		}
		assert.Positive(collectT, docs.Hits.Total.Value,
			"no deployment metric received from agent %s", agentID)
	}, 3*time.Minute, 10*time.Second,
		"state_deployment collection did not recover after deployment access was granted")
}

func assertAgentDidNotRestart(
	t *testing.T,
	ctx context.Context,
	kCtx k8sContext,
	namespace string,
	agent rbacTestAgent,
) {
	t.Helper()
	pod := &corev1.Pod{}
	require.NoError(t, kCtx.client.Resources(namespace).Get(ctx, agent.podName, namespace, pod),
		"Elastic Agent pod was replaced")
	require.Equal(t, agent.podUID, pod.UID, "Elastic Agent pod was replaced")
	require.Equal(t, agent.restartCount, containerRestartCount(t, pod, rbacDeadlockAgentContainer),
		"Elastic Agent container restarted")
}

func containerRestartCount(t *testing.T, pod *corev1.Pod, containerName string) int32 {
	t.Helper()
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == containerName {
			return status.RestartCount
		}
	}
	require.Failf(t, "container status not found", "pod %s has no status for container %s", pod.Name, containerName)
	return 0
}

func getFleetPackageVersion(ctx context.Context, kc *kibana.Client, packageName string) (string, error) {
	response, err := kc.SendWithContext(ctx, http.MethodGet,
		"/api/fleet/epm/packages/"+packageName, nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("querying EPM for %s: %w", packageName, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("reading EPM response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("EPM returned %d for %s: %s", response.StatusCode, packageName, body)
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

func execAgentStatus(
	ctx context.Context,
	kCtx k8sContext,
	namespace string,
	podName string,
	containerName string,
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
