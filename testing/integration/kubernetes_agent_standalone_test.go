// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/go-elasticsearch/v8"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

const agentK8SKustomize = "../../deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone"

var noSpecialCharsRegexp = regexp.MustCompile("[^a-zA-Z0-9]+")

func TestKubernetesAgentStandalone(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes},
		},
		Group: define.Kubernetes,
	})

	agentImage := os.Getenv("AGENT_IMAGE")
	require.NotEmpty(t, agentImage)

	client, err := info.KubeClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	testLogsBasePath := os.Getenv("K8S_TESTS_POD_LOGS_BASE")
	require.NotEmpty(t, testLogsBasePath)

	namespace := info.Namespace

	esHost := os.Getenv("ELASTICSEARCH_HOST")
	require.NotEmpty(t, esHost)

	esAPIKey, err := generateESAPIKey(info.ESClient, namespace)
	require.NoError(t, err)
	require.NotEmpty(t, esAPIKey)

	renderedManifest, err := renderKustomize(agentK8SKustomize)
	require.NoError(t, err)

	testCases := []struct {
		name             string
		runUser          int64
		runGroup         int64
		capabilitiesDrop []corev1.Capability
		capabilitiesAdd  []corev1.Capability
		runK8SInnerTests bool
	}{
		{
			"default deployment - rootful agent",
			0,
			0,
			nil,
			nil,
			false,
		},
		{
			"drop ALL capabilities - rootful agent",
			0,
			0,
			[]corev1.Capability{"ALL"},
			[]corev1.Capability{},
			false,
		},
		{
			"drop ALL add CHOWN, SETPCAP capabilities - rootful agent",
			0,
			0,
			[]corev1.Capability{"ALL"},
			[]corev1.Capability{"CHOWN", "SETPCAP"},
			true,
		},
		{
			"drop ALL add CHOWN, SETPCAP capabilities - rootless agent",
			500,
			500,
			[]corev1.Capability{"ALL"},
			[]corev1.Capability{"CHOWN", "SETPCAP"},
			true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hasher := sha256.New()
			hasher.Write([]byte(tc.name))
			testNamespace := strings.ToLower(base64.URLEncoding.EncodeToString(hasher.Sum(nil)))
			testNamespace = noSpecialCharsRegexp.ReplaceAllString(testNamespace, "")

			k8sObjects, err := yamlToK8SObjects(bufio.NewReader(bytes.NewReader(renderedManifest)))
			require.NoError(t, err)

			adjustK8SAgentManifests(k8sObjects, testNamespace,
				func(container *corev1.Container) {
					container.Image = agentImage
					// set ImagePullPolicy to "Never" to avoid pulling the image
					// as the image is already loaded by the kubernetes provisioner
					container.ImagePullPolicy = "Never"

					// set capabilities
					container.SecurityContext = &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Drop: tc.capabilitiesDrop,
							Add:  tc.capabilitiesAdd,
						},
						RunAsUser:  &tc.runUser,
						RunAsGroup: &tc.runGroup,
					}
					// set Elasticsearch host and API key
					for idx, env := range container.Env {
						if env.Name == "ES_HOST" {
							container.Env[idx].Value = esHost
							container.Env[idx].ValueFrom = nil
						}
						if env.Name == "API_KEY" {
							container.Env[idx].Value = esAPIKey
							container.Env[idx].ValueFrom = nil
						}
					}
				},
				func(pod *corev1.PodSpec) {
					for volumeIdx, volume := range pod.Volumes {
						if volume.Name == "elastic-agent-state" {
							hostPathType := corev1.HostPathDirectoryOrCreate
							pod.Volumes[volumeIdx].VolumeSource.HostPath = &corev1.HostPathVolumeSource{
								Type: &hostPathType,
								Path: fmt.Sprintf("/var/lib/elastic-agent-standalone/%s/state", testNamespace),
							}
						}
					}
				})

			ctx := context.Background()

			deployK8SAgent(t, ctx, client, k8sObjects, testNamespace, tc.runK8SInnerTests, testLogsBasePath)
		})
	}

}

func deployK8SAgent(t *testing.T, ctx context.Context, client klient.Client, objects []k8s.Object, namespace string,
	runInnerK8STests bool, testLogsBasePath string) {
	k8sNamespaceObj := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	t.Cleanup(func() {
		if t.Failed() {
			dumpLogs(t, ctx, client, namespace, testLogsBasePath)
		}
		_ = client.Resources().Delete(ctx, k8sNamespaceObj)
		for _, obj := range objects {
			_ = client.Resources(namespace).Delete(ctx, obj)
		}
	})

	err := client.Resources().Create(ctx, k8sNamespaceObj)
	require.NoError(t, err)

	// Create the objects
	for _, obj := range objects {
		obj.SetNamespace(namespace)
		err = client.Resources(namespace).Create(ctx, obj)
		require.NoError(t, err)
	}

	var agentPodName string
	// Wait for pods to be ready
	require.Eventually(t, func() bool {
		podList := &corev1.PodList{}
		err := client.Resources(namespace).List(ctx, podList)
		require.NoError(t, err)

		for _, pod := range podList.Items {
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if containerStatus.RestartCount > 0 {
					return false
				}
			}

			for _, cond := range pod.Status.Conditions {
				if cond.Type != corev1.PodReady {
					continue
				}

				if cond.Status != corev1.ConditionTrue {
					return false
				}
			}
		}

		return true
	}, time.Second*100, time.Second*1)

	require.NotEmpty(t, agentPodName)

	var stdout, stderr bytes.Buffer
	command := []string{"elastic-agent", "status"}
	success := assert.Eventually(t, func() bool {
		err = client.Resources().ExecInPod(ctx, namespace, agentPodName, "elastic-agent-standalone", command, &stdout, &stderr)
		if err != nil {
			stdout.Reset()
			stderr.Reset()
			return false
		}
		return true
	}, time.Second*100, time.Second*1, "elastic-agent never reported healthy")

	if !success {
		t.Log(stdout.String())
		t.Log(stderr.String())
		return
	}
	stdout.Reset()
	stderr.Reset()

	if runInnerK8STests {
		err = client.Resources().ExecInPod(ctx, namespace, agentPodName, "elastic-agent-standalone",
			[]string{"/usr/share/elastic-agent/k8s-inner-tests", "-test.v"}, &stdout, &stderr)
		t.Log(stdout.String())
		require.NoError(t, err)
	}
}

func dumpLogs(t *testing.T, ctx context.Context, client klient.Client, namespace string, targetDir string) {

	podList := &corev1.PodList{}

	clientset, err := kubernetes.NewForConfig(client.RESTConfig())
	if err != nil {
		t.Logf("Error creating clientset: %v\n", err)
		return
	}

	err = client.Resources(namespace).List(ctx, podList)
	if err != nil {
		t.Logf("Error listing pods: %v\n", err)
		return
	}

	for _, pod := range podList.Items {

		previous := false
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.RestartCount > 0 {
				previous = true
				break
			}
		}

		for _, container := range pod.Spec.Containers {
			logFilePath := filepath.Join(targetDir, fmt.Sprintf("%s-%s-%s.log", t.Name(), pod.Name, container.Name))
			logFile, err := os.Create(logFilePath)
			if err != nil {
				t.Logf("Error creating log file: %v\n", err)
				continue
			}

			req := clientset.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container: container.Name,
				Previous:  previous,
			})
			podLogsStream, err := req.Stream(context.TODO())
			if err != nil {
				t.Logf("Error getting container %s of pod %s logs: %v\n", container.Name, pod.Name, err)
				continue
			}

			_, err = io.Copy(logFile, podLogsStream)
			if err != nil {
				t.Logf("Error writing container %s of pod %s logs: %v\n", container.Name, pod.Name, err)
			} else {
				t.Logf("Wrote container %s of pod %s logs to %s\n", container.Name, pod.Name, logFilePath)
			}

			_ = podLogsStream.Close()
		}
	}
}

func adjustK8SAgentManifests(objects []k8s.Object, namespace string, cbContainer func(container *corev1.Container), cbPod func(pod *corev1.PodSpec)) {
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

		if podSpec == nil {
			continue
		}

		for idx, container := range podSpec.Containers {
			if container.Name != "elastic-agent-standalone" {
				continue
			}
			if cbContainer != nil {
				cbContainer(&podSpec.Containers[idx])
			}

			if cbPod != nil {
				cbPod(podSpec)
			}
		}

	}
}

func yamlToK8SObjects(reader *bufio.Reader) ([]k8s.Object, error) {
	var objects []k8s.Object

	scheme := runtime.NewScheme()
	scheme.AddKnownTypes(rbacv1.SchemeGroupVersion, &rbacv1.ClusterRoleBinding{}, &rbacv1.ClusterRoleBindingList{})
	scheme.AddKnownTypes(rbacv1.SchemeGroupVersion, &rbacv1.ClusterRole{}, &rbacv1.ClusterRoleList{})
	scheme.AddKnownTypes(rbacv1.SchemeGroupVersion, &rbacv1.RoleBinding{}, &rbacv1.RoleBindingList{})
	scheme.AddKnownTypes(rbacv1.SchemeGroupVersion, &rbacv1.Role{}, &rbacv1.RoleList{})
	scheme.AddKnownTypes(corev1.SchemeGroupVersion, &corev1.ServiceAccount{}, &corev1.ServiceAccountList{})
	scheme.AddKnownTypes(corev1.SchemeGroupVersion, &corev1.Service{}, &corev1.ServiceList{})
	scheme.AddKnownTypes(appsv1.SchemeGroupVersion, &appsv1.DaemonSet{})
	scheme.AddKnownTypes(appsv1.SchemeGroupVersion, &appsv1.StatefulSet{})
	scheme.AddKnownTypes(appsv1.SchemeGroupVersion, &appsv1.Deployment{})
	scheme.AddKnownTypes(corev1.SchemeGroupVersion, &corev1.Secret{}, &corev1.ConfigMap{})
	decoder := serializer.NewCodecFactory(scheme).UniversalDeserializer()

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
