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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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

	aclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
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
			{Type: define.Kubernetes, DockerVariant: "ubi"},
			{Type: define.Kubernetes, DockerVariant: "complete"},
			{Type: define.Kubernetes, DockerVariant: "complete-wolfi"},
		},
		Group: define.Kubernetes,
	})

	kCtx := k8sGetContext(t, info)

	renderedManifest, err := renderKustomize(agentK8SKustomize)
	require.NoError(t, err, "failed to render kustomize")

	testCases := []struct {
		name             string
		runUser          *int64
		runGroup         *int64
		capabilitiesDrop []corev1.Capability
		capabilitiesAdd  []corev1.Capability
		runK8SInnerTests bool
		skipReason       string
	}{
		{
			"default deployment - rootful agent",
			nil,
			nil,
			nil,
			nil,
			false,
			"",
		},
		{
			"drop ALL capabilities - rootful agent",
			int64Ptr(0),
			nil,
			[]corev1.Capability{"ALL"},
			[]corev1.Capability{},
			false,
			"",
		},
		{
			"drop ALL add CHOWN, SETPCAP capabilities - rootful agent",
			int64Ptr(0),
			nil,
			[]corev1.Capability{"ALL"},
			[]corev1.Capability{"CHOWN", "SETPCAP"},
			true,
			"",
		},
		{
			"drop ALL add CHOWN, SETPCAP capabilities - rootless agent",
			int64Ptr(1000), // elastic-agent uid
			nil,
			[]corev1.Capability{"ALL"},
			[]corev1.Capability{"CHOWN", "SETPCAP", "DAC_READ_SEARCH", "SYS_PTRACE"},
			true,
			"",
		},
		{
			"drop ALL add CHOWN, SETPCAP capabilities - rootless agent random uid:gid",
			int64Ptr(500),
			int64Ptr(500),
			[]corev1.Capability{"ALL"},
			[]corev1.Capability{"CHOWN", "SETPCAP", "DAC_READ_SEARCH", "SYS_PTRACE"},
			true,
			"",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipReason != "" {
				t.Skip(tc.skipReason)
			}

			ctx := context.Background()

			testNamespace := kCtx.getNamespace(t)

			k8sObjects, err := k8sYAMLToObjects(bufio.NewReader(bytes.NewReader(renderedManifest)))
			require.NoError(t, err, "failed to convert yaml to k8s objects")

			// add the testNamespace in the beginning of k8sObjects to be created first
			k8sObjects = append([]k8s.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}}, k8sObjects...)

			t.Cleanup(func() {
				err = k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: true}, k8sObjects...)
				require.NoError(t, err, "failed to delete k8s namespace")
			})

			k8sKustomizeAdjustObjects(k8sObjects, testNamespace, "elastic-agent-standalone",
				func(container *corev1.Container) {
					// set agent image
					container.Image = kCtx.agentImage
					// set ImagePullPolicy to "Never" to avoid pulling the image
					// as the image is already loaded by the kubernetes provisioner
					container.ImagePullPolicy = "Never"

					container.Resources.Limits = corev1.ResourceList{
						corev1.ResourceMemory: resource.MustParse("800Mi"),
					}

					if tc.capabilitiesDrop != nil || tc.capabilitiesAdd != nil || tc.runUser != nil || tc.runGroup != nil {
						// set security context
						container.SecurityContext = &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Drop: tc.capabilitiesDrop,
								Add:  tc.capabilitiesAdd,
							},
							RunAsUser:  tc.runUser,
							RunAsGroup: tc.runGroup,
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
				},
				func(pod *corev1.PodSpec) {
					for volumeIdx, volume := range pod.Volumes {
						// need to update the volume path of the state directory
						// to match the test namespace
						if volume.Name == "elastic-agent-state" {
							hostPathType := corev1.HostPathDirectoryOrCreate
							pod.Volumes[volumeIdx].VolumeSource.HostPath = &corev1.HostPathVolumeSource{
								Type: &hostPathType,
								Path: fmt.Sprintf("/var/lib/elastic-agent-standalone/%s/state", testNamespace),
							}
						}
					}
				})

			k8sKustomizeDeployAgent(t, ctx, kCtx.client, k8sObjects, testNamespace, tc.runK8SInnerTests,
				kCtx.logsBasePath, true, nil)
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

	kCtx := k8sGetContext(t, info)

	renderedManifest, err := renderKustomize(agentK8SKustomize)
	require.NoError(t, err, "failed to render kustomize")

	testCases := []struct {
		name             string
		envAdd           []corev1.EnvVar
		runK8SInnerTests bool
	}{
		{
			"run agent in otel mode",
			[]corev1.EnvVar{
				{Name: "ELASTIC_AGENT_OTEL", Value: "true"},
			},
			false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			testNamespace := kCtx.getNamespace(t)

			k8sObjects, err := k8sYAMLToObjects(bufio.NewReader(bytes.NewReader(renderedManifest)))
			require.NoError(t, err, "failed to convert yaml to k8s objects")

			// add the testNamespace in the k8sObjects
			k8sObjects = append([]k8s.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}}, k8sObjects...)

			t.Cleanup(func() {
				err = k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: true}, k8sObjects...)
				require.NoError(t, err, "failed to delete k8s namespace")
			})

			k8sKustomizeAdjustObjects(k8sObjects, testNamespace, "elastic-agent-standalone",
				func(container *corev1.Container) {
					// set agent image
					container.Image = kCtx.agentImage
					// set ImagePullPolicy to "Never" to avoid pulling the image
					// as the image is already loaded by the kubernetes provisioner
					container.ImagePullPolicy = "Never"

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

					if len(tc.envAdd) > 0 {
						container.Env = append(container.Env, tc.envAdd...)
					}

					// drop arguments overriding default config
					container.Args = []string{}
				},
				func(pod *corev1.PodSpec) {
					for volumeIdx, volume := range pod.Volumes {
						// need to update the volume path of the state directory
						// to match the test namespace
						if volume.Name == "elastic-agent-state" {
							hostPathType := corev1.HostPathDirectoryOrCreate
							pod.Volumes[volumeIdx].VolumeSource.HostPath = &corev1.HostPathVolumeSource{
								Type: &hostPathType,
								Path: fmt.Sprintf("/var/lib/elastic-agent-standalone/%s/state", testNamespace),
							}
						}
					}
				})

			k8sKustomizeDeployAgent(t, ctx, kCtx.client, k8sObjects, testNamespace,
				false, kCtx.logsBasePath, false, nil)
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

	nodeList := corev1.NodeList{}
	err := kCtx.client.Resources().List(ctx, &nodeList)
	require.NoError(t, err)

	totalK8SNodes := len(nodeList.Items)
	require.NotZero(t, totalK8SNodes, "No Kubernetes nodes found")

	testCases := []struct {
		name                   string
		values                 map[string]any
		atLeastAgentPods       int
		runK8SInnerTests       bool
		agentPodLabelSelectors []string
	}{
		{
			name: "helm standalone agent default kubernetes privileged",
			values: map[string]any{
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
			},
			runK8SInnerTests: true,
			// - perNode Daemonset (totalK8SNodes pods)
			// - clusterWide Deployment  (1 agent pod)
			// - ksmSharded Statefulset  (1 agent pod)
			atLeastAgentPods: totalK8SNodes + 1 + 1,
			agentPodLabelSelectors: []string{
				// name=agent-{preset}-{release}
				"name=agent-pernode-helm-agent",
				"name=agent-clusterwide-helm-agent",
				"name=agent-ksmsharded-helm-agent",
			},
		},
		{
			name: "helm standalone agent default kubernetes unprivileged",
			values: map[string]any{
				"kubernetes": map[string]any{
					"enabled": true,
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
			},
			runK8SInnerTests: true,
			// - perNode Daemonset (totalK8SNodes pods)
			// - clusterWide Deployment  (1 agent pod)
			// - ksmSharded Statefulset  (1 agent pod)
			atLeastAgentPods: totalK8SNodes + 1 + 1,
			agentPodLabelSelectors: []string{
				// name=agent-{preset}-{release}
				"name=agent-pernode-helm-agent",
				"name=agent-clusterwide-helm-agent",
				"name=agent-ksmsharded-helm-agent",
			},
		},
		{
			name: "helm managed agent default kubernetes privileged",
			values: map[string]any{
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
			},
			runK8SInnerTests: true,
			// - perNode Daemonset (totalK8SNodes pods)
			atLeastAgentPods: totalK8SNodes,
			agentPodLabelSelectors: []string{
				// name=agent-{preset}-{release}
				"name=agent-pernode-helm-agent",
			},
		},
		{
			name: "helm managed agent default kubernetes unprivileged",
			values: map[string]any{
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
			},
			runK8SInnerTests: true,
			// - perNode Daemonset (totalK8SNodes pods)
			atLeastAgentPods: totalK8SNodes,
			agentPodLabelSelectors: []string{
				// name=agent-{preset}-{release}
				"name=agent-pernode-helm-agent",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			testNamespace := kCtx.getNamespace(t)

			settings := cli.New()
			settings.SetNamespace(testNamespace)
			actionConfig := &action.Configuration{}

			helmChart, err := loader.Load(agentK8SHelm)
			require.NoError(t, err, "failed to load helm chart")

			err = actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "",
				func(format string, v ...interface{}) {})
			require.NoError(t, err, "failed to init helm action config")

			helmValues := tc.values

			k8sNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}

			t.Cleanup(func() {
				if t.Failed() {
					if err := k8sDumpAllPodLogs(ctx, kCtx.client, testNamespace, testNamespace, kCtx.logsBasePath); err != nil {
						t.Logf("failed to dump logs: %s", err)
					}
				}

				uninstallAction := action.NewUninstall(actionConfig)
				uninstallAction.Wait = true
				_, err = uninstallAction.Run("helm-agent")
				if err != nil {
					t.Logf("failed to uninstall helm chart: %s", err)
				}

				err = k8sDeleteObjects(ctx, kCtx.client, k8sDeleteOpts{wait: true}, k8sNamespace)
				if err != nil {
					t.Logf("failed to delete k8s namespace: %s", err)
				}
			})

			installAction := action.NewInstall(actionConfig)
			installAction.Namespace = testNamespace
			installAction.CreateNamespace = true
			installAction.UseReleaseName = true
			installAction.ReleaseName = "helm-agent"
			installAction.Timeout = 2 * time.Minute
			installAction.Wait = true
			installAction.WaitForJobs = true
			_, err = installAction.Run(helmChart, helmValues)
			require.NoError(t, err, "failed to install helm chart")

			healthyAgentPods := 0
			for _, podSelector := range tc.agentPodLabelSelectors {
				pods := &corev1.PodList{}
				err = kCtx.client.Resources(testNamespace).List(ctx, pods, func(opt *metav1.ListOptions) {
					opt.LabelSelector = podSelector
				})
				require.NoError(t, err, "failed to list pods with selector ", podSelector)

				for _, pod := range pods.Items {
					var stdout, stderr bytes.Buffer
					err = k8sCheckAgentStatus(ctx, kCtx.client, &stdout, &stderr, testNamespace, pod.Name, "agent", map[string]bool{})
					if err != nil {
						t.Errorf("failed to check agent status: %v", err)
						t.Logf("stdout: %s\n", stdout.String())
						t.Logf("stderr: %s\n", stderr.String())
						t.FailNow()
					}
					healthyAgentPods++

					if !tc.runK8SInnerTests {
						continue
					}

					stdout.Reset()
					stderr.Reset()
					err := kCtx.client.Resources().ExecInPod(ctx, testNamespace, pod.Name, "agent",
						[]string{"/usr/share/elastic-agent/k8s-inner-tests", "-test.v"}, &stdout, &stderr)
					t.Logf("%s k8s-inner-tests output:", pod.Name)
					t.Log(stdout.String())
					if err != nil {
						t.Log(stderr.String())
					}
					require.NoError(t, err, "error at k8s inner tests execution")
				}
			}

			require.GreaterOrEqual(t, healthyAgentPods, tc.atLeastAgentPods,
				fmt.Sprintf("at least %d agent containers should be checked", tc.atLeastAgentPods))
		})
	}
}

func k8sKustomizeDeployAgent(t *testing.T, ctx context.Context, client klient.Client, objects []k8s.Object,
	namespace string, runK8SInnerTests bool, testlogsBasePath string, checkStatus bool, componentPresence map[string]bool,
) {
	err := k8sCreateObjects(ctx, client, k8sCreateOpts{namespace: namespace, wait: true}, objects...)
	require.NoError(t, err, "failed to create k8s objects")

	t.Cleanup(func() {
		if t.Failed() {
			if err := k8sDumpAllPodLogs(ctx, client, namespace, namespace, testlogsBasePath); err != nil {
				t.Logf("failed to dump logs: %s", err)
			}
		}
	})

	pods := &corev1.PodList{}
	podsLabelSelector := fmt.Sprintf("app=elastic-agent-standalone")
	err = client.Resources(namespace).List(ctx, pods, func(opt *metav1.ListOptions) {
		opt.LabelSelector = podsLabelSelector
	})
	require.NoError(t, err, "failed to list pods with selector ", podsLabelSelector)
	require.NotEmpty(t, pods.Items, "no pods found with selector ", podsLabelSelector)

	for _, pod := range pods.Items {
		var stdout, stderr bytes.Buffer

		if checkStatus {
			err = k8sCheckAgentStatus(ctx, client, &stdout, &stderr, namespace, pod.Name, "elastic-agent-standalone", componentPresence)
			if err != nil {
				t.Errorf("failed to check agent status: %v", err)
				t.Logf("stdout: %s\n", stdout.String())
				t.Logf("stderr: %s\n", stderr.String())
				t.FailNow()
			}
		}

		stdout.Reset()
		stderr.Reset()

		if runK8SInnerTests {
			err := client.Resources().ExecInPod(ctx, namespace, pod.Name, "elastic-agent-standalone",
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

// renderKustomize renders the given kustomize directory to YAML
func renderKustomize(kustomizePath string) ([]byte, error) {
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
