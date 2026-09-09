// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestKubernetesFleetServerStatePersistence deploys an Elastic Agent that bootstraps its own
// Fleet Server (FLEET_SERVER_ENABLE=1) with its state directory persisted on a volume,
// restarts the pod and asserts that the agent reuses the persisted enrollment instead of
// enrolling again.
//
// A re-enrollment on every restart leaves the previous agent record behind as an offline
// ghost in Fleet, which is what this test guards against.
//
// The restart also covers the API key validation performed by the enrollment check: it runs
// before Fleet Server is started, so the check cannot reach the internal endpoint and must
// keep the existing enrollment instead of failing the startup.
func TestKubernetesFleetServerStatePersistence(t *testing.T) {
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
	namespace := kCtx.getNamespace(t)

	const (
		agentName        = "fleet-server"
		containerName    = "elastic-agent"
		podLabelSelector = "name=" + agentName
	)

	policyID := createFleetServerPolicy(t, ctx, info)
	serviceToken, err := estools.CreateServiceToken(ctx, info.ESClient, "fleet-server")
	require.NoError(t, err, "failed to create the fleet-server service token")

	statefulSet := fleetServerStatefulSet(kCtx, agentName, namespace, policyID, serviceToken)
	// StatefulSet pods are named "<statefulset name>-<ordinal>".
	podName := statefulSet.Name + "-0"

	// agent ID to the enrollment time reported by Fleet, as observed before the restart.
	enrolledIDs := map[string]time.Time{}

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepDeployStatefulSet(statefulSet),
		k8sStepCheckAgentStatus(podLabelSelector, 1, containerName, map[string]bool{"fleet-server": true}),
		k8sStepForEachAgentID(podLabelSelector, 1, containerName, func(ctx context.Context, id string) error {
			agent, err := kibanaGetAgent(ctx, info.KibanaClient, id)
			if err != nil {
				return err
			}
			enrolledIDs[id] = agent.EnrolledAt
			t.Cleanup(func() {
				if err := fleettools.UnEnrollAgent(ctx, info.KibanaClient, id); err != nil {
					t.Logf("failed to unenroll the agent %q: %v", id, err)
				}
			})
			return nil
		}),
		k8sStepCheckPolicyAgentCount(info, policyID, 1),

		k8sStepRestartPod(podName),

		k8sStepCheckAgentStatus(podLabelSelector, 1, containerName, map[string]bool{"fleet-server": true}),
		k8sStepForEachAgentID(podLabelSelector, 1, containerName, func(ctx context.Context, id string) error {
			// A re-enrollment allocates a new agent ID and updates the enrollment time,
			// and leaves the previous record behind in Fleet.
			enrolledAt, exists := enrolledIDs[id]
			if !exists {
				return fmt.Errorf("agent %s re-enrolled after the restart, the persisted state was not reused", id)
			}
			agent, err := kibanaGetAgent(ctx, info.KibanaClient, id)
			if err != nil {
				return err
			}
			if !agent.EnrolledAt.Equal(enrolledAt) {
				return fmt.Errorf("agent enrollment time is updated: %s != %s", agent.EnrolledAt, enrolledAt)
			}
			return nil
		}),
		k8sStepCheckPolicyAgentCount(info, policyID, 1),
	}

	for _, step := range steps {
		step(t, ctx, kCtx, namespace)
	}
}

// k8sStepDeployStatefulSet deploys the given statefulset and waits for it to be ready.
func k8sStepDeployStatefulSet(statefulSet *appsv1.StatefulSet) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		t.Cleanup(func() {
			if t.Failed() {
				k8sDumpPods(t, ctx, kCtx.client, t.Name(), namespace, kCtx.logsBasePath, kCtx.createdAt)
			}
		})

		err := k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{
			namespace:   namespace,
			wait:        true,
			waitTimeout: 5 * time.Minute,
		}, statefulSet)
		require.NoError(t, err, "failed to create statefulset %q", statefulSet.Name)
	}
}

// k8sStepRestartPod deletes the given pod and waits for its controller to recreate it and
// for the new pod to become ready.
func k8sStepRestartPod(podName string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		pod := &corev1.Pod{}
		require.NoError(t, kCtx.client.Resources(namespace).Get(ctx, podName, namespace, pod),
			"failed to get pod %q", podName)
		previousUID := pod.GetUID()

		require.NoError(t, kCtx.client.Resources(namespace).Delete(ctx, pod), "failed to delete pod %q", podName)

		// the controller recreates the pod under the same name, so wait for a new instance
		// of it to show up before handing it over to the ready check
		require.Eventuallyf(t, func() bool {
			pod = &corev1.Pod{}
			err := kCtx.client.Resources(namespace).Get(ctx, podName, namespace, pod)
			return err == nil && pod.GetUID() != previousUID
		}, time.Minute, time.Second, "pod %q was not recreated", podName)

		require.NoError(t, k8sWaitForReady(ctx, kCtx.client, 5*time.Minute, pod),
			"pod %q did not become ready after the restart", podName)
	}
}

// k8sStepCheckPolicyAgentCount asserts the number of agents, including the inactive ones,
// that Fleet has enrolled into the given policy.
func k8sStepCheckPolicyAgentCount(info *define.Info, policyID string, expected int) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		agents, err := kibanaListAgentsByPolicy(ctx, info.KibanaClient, policyID)
		require.NoError(t, err, "failed to list the agents of policy %q", policyID)
		assert.Lenf(t, agents, expected, "unexpected number of agents enrolled into policy %q", policyID)
	}
}

// createFleetServerPolicy creates an agent policy that holds the fleet-server integration and
// returns its ID.
func createFleetServerPolicy(t *testing.T, ctx context.Context, info *define.Info) string {
	t.Helper()

	policyUUID := uuid.Must(uuid.NewV4()).String()
	policyResp, err := info.KibanaClient.CreatePolicy(ctx, kibana.AgentPolicy{
		ID:          "test-fleet-server-policy-" + policyUUID,
		Name:        "test-fleet-server-policy-" + policyUUID,
		Namespace:   "default",
		Description: "Test fleet-server policy " + policyUUID,
	})
	require.NoError(t, err, "failed to create the fleet-server policy")

	t.Cleanup(func() {
		// the agents enrolled into the policy have to be gone before the policy can be
		// deleted, which is not guaranteed here, so this is best effort only.
		if err := info.KibanaClient.DeletePolicy(ctx, policyResp.ID); err != nil {
			t.Logf("failed to delete the fleet-server policy %q: %v", policyResp.ID, err)
		}
	})

	_, err = tools.InstallPackageFromDefaultFile(ctx, info.KibanaClient, "fleet-server",
		integration.PreinstalledPackages["fleet_server"], filepath.Join("testdata", "fleet-server.json"),
		uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(t, err, "failed to add the fleet-server integration to the policy")

	return policyResp.ID
}

// fleetServerStatefulSet returns a StatefulSet that runs an Elastic Agent bootstrapping its
// own Fleet Server, with its state directory on a host volume so that it survives the pod
// being recreated, mimicking a container deployment with the state directory on a volume.
func fleetServerStatefulSet(kCtx k8sContext, name string, namespace string, policyID string, serviceToken string) *appsv1.StatefulSet {
	replicas := int32(1)
	labels := map[string]string{"name": name}
	hostPathType := corev1.HostPathDirectoryOrCreate
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: appsv1.StatefulSetSpec{
			ServiceName: name,
			Replicas:    &replicas,
			Selector:    &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "elastic-agent",
							Image:           kCtx.agentImage,
							ImagePullPolicy: corev1.PullNever,
							SecurityContext: &corev1.SecurityContext{
								// the state directory is created owned by root
								RunAsUser: int64Ptr(0),
							},
							Env: []corev1.EnvVar{
								// FLEET_URL is intentionally not set: the agent enrolls
								// through the internal endpoint of its own Fleet Server.
								{Name: "FLEET_SERVER_ENABLE", Value: "1"},
								{Name: "FLEET_SERVER_ELASTICSEARCH_HOST", Value: kCtx.esHost},
								{Name: "FLEET_SERVER_SERVICE_TOKEN", Value: serviceToken},
								{Name: "FLEET_SERVER_POLICY_ID", Value: policyID},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "elastic-agent-state", MountPath: "/usr/share/elastic-agent/state"},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "elastic-agent-state",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Type: &hostPathType,
									Path: fmt.Sprintf("/var/lib/elastic-agent-fleet-server/%s/state", namespace),
								},
							},
						},
					},
				},
			},
		},
	}
}

// kibanaListAgentsByPolicy returns all the agents, including the inactive ones, that are
// enrolled into the given policy. kibana.ListAgents cannot filter, and the shared stack
// holds agents of other tests, so the query is made directly.
func kibanaListAgentsByPolicy(ctx context.Context, kc *kibana.Client, policyID string) ([]GetAgentResponse, error) {
	params := url.Values{}
	params.Set("kuery", fmt.Sprintf("policy_id:%q", policyID))
	params.Set("showInactive", "true")
	params.Set("perPage", "100")

	r, err := kc.SendWithContext(ctx, http.MethodGet, "/api/fleet/agents", params, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error calling list agents API: %w", err)
	}
	defer r.Body.Close()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error calling list agents API: %s", string(b))
	}

	var agentsResp struct {
		Items []GetAgentResponse `json:"items"`
	}
	if err := json.Unmarshal(b, &agentsResp); err != nil {
		return nil, fmt.Errorf("unmarshalling response json: %w", err)
	}
	return agentsResp.Items, nil
}
