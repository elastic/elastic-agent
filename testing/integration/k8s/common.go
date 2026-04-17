// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	helmKube "helm.sh/helm/v3/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	cliResource "k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	aclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

var noSpecialCharsRegexp = regexp.MustCompile("[^a-zA-Z0-9]+")

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
	// esEncodedAPIKey is the encoded API key of the elasticsearch to use in the test
	esEncodedAPIKey string
	// enrollParams contains the information needed to enroll an agent with Fleet in the test
	enrollParams *fleettools.EnrollParams
	// createdAt is the time when the k8sContext was created
	createdAt time.Time
}

// getNamespace returns a unique namespace for the current test
func (k k8sContext) getNamespace(t *testing.T) string {
	if ns := os.Getenv("K8S_TESTS_NAMESPACE"); ns != "" {
		return ns
	}

	nsUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("error generating namespace UUID: %v", err)
	}
	hasher := sha256.New()
	hasher.Write([]byte(nsUUID.String()))
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

	err = os.MkdirAll(testLogsBasePath, 0o755)
	require.NoError(t, err, "failed to create test logs directory")

	esHost, err := integration.GetESHost()
	require.NoError(t, err, "cannot parse ELASTICSEARCH_HOST")

	esAPIKey, err := generateESAPIKey(info.ESClient, info.Namespace)
	require.NoError(t, err, "failed to generate ES API key")
	require.NotEmpty(t, esAPIKey, "failed to generate ES API key")

	beatsStyleAPIKey, err := base64.StdEncoding.DecodeString(esAPIKey.Encoded)
	require.NoError(t, err, "failed to decode ES API key")

	enrollParams, err := fleettools.NewEnrollParams(context.Background(), info.KibanaClient)
	require.NoError(t, err, "failed to create fleet enroll params")

	return k8sContext{
		client:          client,
		clientSet:       clientSet,
		agentImage:      agentImage,
		agentImageRepo:  agentImageRepo,
		agentImageTag:   agentImageTag,
		logsBasePath:    testLogsBasePath,
		esHost:          esHost,
		esAPIKey:        string(beatsStyleAPIKey),
		esEncodedAPIKey: esAPIKey.Encoded,
		enrollParams:    enrollParams,
		createdAt:       time.Now(),
	}
}

// generateESAPIKey generates an API key for the given Elasticsearch.
func generateESAPIKey(esClient *elasticsearch.Client, keyName string) (estools.APIKeyResponse, error) {
	return estools.CreateAPIKey(context.Background(), esClient, estools.APIKeyRequest{Name: keyName, Expiration: "1d"})
}

// int64Ptr returns a pointer to the given int64
func int64Ptr(val int64) *int64 {
	valPtr := val
	return &valPtr
}

// k8sCheckAgentStatus checks that the agent reports healthy.
func k8sCheckAgentStatus(ctx context.Context, client klient.Client, stdout *bytes.Buffer, stderr *bytes.Buffer,
	namespace string, agentPodName string, containerName string, componentPresence map[string]bool,
) error {
	command := []string{"elastic-agent", "status", "--output=json"}
	stopCheck := errors.New("stop check")

	// we will wait maximum 120 seconds for the agent to report healthy
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	checkStatus := func() error {
		pod := corev1.Pod{}
		if err := client.Resources(namespace).Get(ctx, agentPodName, namespace, &pod); err != nil {
			return err
		}

		for _, container := range pod.Status.ContainerStatuses {
			if container.Name != containerName {
				continue
			}

			if restarts := container.RestartCount; restarts != 0 {
				return fmt.Errorf("container %q of pod %q has restarted %d times: %w", containerName, agentPodName, restarts, stopCheck)
			}
		}

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
	for {
		err := checkStatus()
		if err == nil {
			return nil
		} else if errors.Is(err, stopCheck) {
			return err
		}
		if ctx.Err() != nil {
			// timeout waiting for agent to become healthy
			return errors.Join(err, errors.New("timeout waiting for agent to become healthy"))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// k8sGetAgentID returns the agent ID for the given agent pod
func k8sGetAgentID(ctx context.Context, client klient.Client, stdout *bytes.Buffer, stderr *bytes.Buffer,
	namespace string, agentPodName string, containerName string,
) (string, error) {
	command := []string{"elastic-agent", "status", "--output=json"}

	status := atesting.AgentStatusOutput{} // clear status output
	stdout.Reset()
	stderr.Reset()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	err := client.Resources().ExecInPod(ctx, namespace, agentPodName, containerName, command, stdout, stderr)
	cancel()
	if err != nil {
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
			case *rbacv1.RoleBinding:
				for idx := range objWithType.Subjects {
					objWithType.Subjects[idx].Namespace = opts.namespace
				}
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

func queryK8sNamespaceDataStream(dsType, dataset, datastreamNamespace, k8snamespace string) map[string]any {
	return map[string]any{
		"_source": []string{"message"},
		"query": map[string]any{
			"bool": map[string]any{
				"filter": []any{
					map[string]any{
						"term": map[string]any{
							"data_stream.dataset": dataset,
						},
					},
					map[string]any{
						"term": map[string]any{
							"data_stream.namespace": datastreamNamespace,
						},
					},
					map[string]any{
						"term": map[string]any{
							"data_stream.type": dsType,
						},
					},
					map[string]any{
						"term": map[string]any{
							"resource.attributes.k8s.namespace.name": k8snamespace,
						},
					},
				},
			},
		},
	}
}

// PerformQuery performs an Elasticsearch search query using the provided client.
// TODO: add it to elastic-agent-libs/testing/estools
func PerformQuery(ctx context.Context, queryRaw map[string]interface{}, index string, client elastictransport.Interface) (ESResponse, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(queryRaw)
	if err != nil {
		return ESResponse{}, fmt.Errorf("error creating ES query: %w", err)
	}

	es := esapi.New(client)
	res, err := es.Search(
		es.Search.WithIndex(index),
		es.Search.WithExpandWildcards("all"),
		es.Search.WithBody(&buf),
		es.Search.WithTrackTotalHits(true),
		es.Search.WithPretty(),
		es.Search.WithContext(ctx),
		es.Search.WithSize(300),
	)

	if err != nil {
		return ESResponse{}, fmt.Errorf("error performing ES search: %w", err)
	}

	if res.StatusCode >= 300 || res.StatusCode < 200 {
		return ESResponse{}, fmt.Errorf("non-200 return code: %v, response: '%s'", res.StatusCode, res.String())
	}

	resp := ESResponse{}
	err = json.NewDecoder(res.Body).Decode(&resp)
	if err != nil {
		return ESResponse{}, fmt.Errorf("error reading response body: %w", err)
	}

	return resp, nil
}

// ESResponse represents a Elasticsearch search response.
// TODO: add it to elastic-agent-libs/testing/estools
type ESResponse struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore any   `json:"max_score"`
		Hits     []any `json:"hits"`
	} `json:"hits"`
	Aggregations struct {
		FilesCount struct {
			DocCountErrorUpperBound int `json:"doc_count_error_upper_bound"`
			SumOtherDocCount        int `json:"sum_other_doc_count"`
			Buckets                 []struct {
				Key      string `json:"key"`
				DocCount int    `json:"doc_count"`
			} `json:"buckets"`
		} `json:"files_count"`
	} `json:"aggregations"`
}

func k8sReadPodLogLines(ctx context.Context, clientSet *kubernetes.Clientset, namespace string, podName string, opts *corev1.PodLogOptions, maxLines int) ([]string, error) {
	req := clientSet.CoreV1().Pods(namespace).GetLogs(podName, opts)
	logs, err := req.Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer logs.Close()

	return readPodLogLines(logs, maxLines)
}

func readPodLogLines(r io.Reader, maxLines int) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lines := []string{}
	index := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		index++
		lines = append(lines, line)
		if maxLines > 0 && index >= maxLines {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
