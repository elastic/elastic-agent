// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/release"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientk8s "k8s.io/client-go/kubernetes"
	yamlk8s "sigs.k8s.io/yaml"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	k8sSubdir    = "k8s"
	cgroupSubDir = "cgroup"
	logsSubDir   = "logs"
)

func k8sDiagnostics(l *logp.Logger) func(ctx context.Context) []byte {
	return func(ctx context.Context) []byte {
		if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); !ok {
			return nil
		}

		kubernetesClient, err := kubernetes.GetKubernetesClient("", kubernetes.KubeClientOptions{})
		if err != nil {
			err = fmt.Errorf("error instantiating k8s client: %w", err)
			errorOnlyZip, zipCreateErr := createErrorOnlyZip(err)
			if zipCreateErr != nil {
				l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, err)
			}
			return errorOnlyZip
		}

		tokenPayload, err := readServiceAccountToken("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			err = fmt.Errorf("error reading service account token: %w", err)
			errorOnlyZip, zipCreateErr := createErrorOnlyZip(err)
			if zipCreateErr != nil {
				l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, err)
			}
			return errorOnlyZip
		}
		return collectK8sDiagnosticsWithClientAndToken(ctx, l, kubernetesClient, tokenPayload.Namespace, tokenPayload.Pod.Name)
	}
}
func collectK8sDiagnosticsWithClientAndToken(ctx context.Context, l *logp.Logger, k8sClient clientk8s.Interface, namespace string, podName string) []byte {

	tmpDir, err := os.MkdirTemp("", "elastic-agent-k8s-diag-*")
	if err != nil {
		err = fmt.Errorf("error creating k8s diag temp directory: %w", err)
		errorOnlyZip, zipCreateErr := createErrorOnlyZip(err)
		if zipCreateErr != nil {
			l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, err)
		}
		return errorOnlyZip
	}
	defer os.RemoveAll(tmpDir)

	k8sDir := filepath.Join(tmpDir, k8sSubdir)
	err = os.MkdirAll(k8sDir, 0755)
	if err != nil {
		err = fmt.Errorf("error creating k8s diag subdirectory %q: %w", k8sDir, err)
		errorOnlyZip, zipCreateErr := createErrorOnlyZip(err)
		if zipCreateErr != nil {
			l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, err)
		}
		return errorOnlyZip
	}

	var diagnosticsAccumulatedError error

	pod, err := k8sClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, fmt.Errorf("error getting pod %s/%s: %w", namespace, podName, err))
		errorOnlyZip, zipCreateErr := createErrorOnlyZip(diagnosticsAccumulatedError)
		if zipCreateErr != nil {
			l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, diagnosticsAccumulatedError)
		}
		return errorOnlyZip
	}

	diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, dumpK8sManifests(ctx, k8sClient, pod, k8sDir))
	diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, writeNamespaceLeases(ctx, k8sClient, namespace, filepath.Join(k8sDir, "leases.yaml")))

	// Collect logs for this pod
	podLogsDir := filepath.Join(k8sDir, logsSubDir)
	diagnosticsAccumulatedError = errors.Join(os.MkdirAll(podLogsDir, 0755))
	diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, collectLogsFromPod(ctx, k8sClient, pod, podLogsDir))
	diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, dumpHelmChartValues(ctx, k8sClient, pod, k8sDir, filepath.Join(k8sDir, "values.yaml")))

	// Collect cgroup stats
	cgroupOutputDir := filepath.Join(tmpDir, cgroupSubDir)
	diagnosticsAccumulatedError = errors.Join(os.MkdirAll(cgroupOutputDir, 0755))
	diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, collectCgroup(ctx, "/sys/fs/cgroup/", cgroupOutputDir))
	buf := new(bytes.Buffer)
	err = writeZipFileFromDir(buf, tmpDir, diagnosticsAccumulatedError)
	if err != nil {
		l.Errorf("error creating k8s diagnostics zip: %s. Diagnostics errors: %s", err, diagnosticsAccumulatedError)
		return nil
	}

	return buf.Bytes()
}

func collectCgroup(ctx context.Context, cgroupBaseDir string, outputDir string) error {
	cgroupFiles := []string{
		"memory.events",
		"memory.stat",
		"memory.low",
		"memory.high",
		"memory.min",
		"memory.max",
	}

	var accumulatedError error

	for _, cgroupFile := range cgroupFiles {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		inputFileName := filepath.Join(cgroupBaseDir, cgroupFile)
		outputFileName := filepath.Join(outputDir, cgroupFile)

		accumulatedError = errors.Join(accumulatedError, copyFile(inputFileName, outputFileName))
	}
	return accumulatedError
}

func copyFile(inputFileName string, outputFileName string) error {
	inputFile, err := os.Open(inputFileName)
	if err != nil {
		return fmt.Errorf("error opening %q: %w", inputFileName, err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputFileName)
	if err != nil {
		return fmt.Errorf("error creating outputfile %q: %w", outputFileName, err)
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, inputFile)
	if err != nil {
		return fmt.Errorf("error copying %q into %q: %w", inputFileName, outputFileName, err)
	}

	return nil
}

func dumpK8sManifests(ctx context.Context, k8sClient clientk8s.Interface, pod *v1.Pod, k8sDir string) error {
	var diagnosticsAccumulatedError error

	podMashalledBytes, err := yamlk8s.Marshal(pod)
	if err != nil {
		diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, fmt.Errorf("error marshalling pod %s/%s: %w", pod.Namespace, pod.Name, err))
	}

	if podMashalledBytes != nil {
		err = os.WriteFile(filepath.Join(k8sDir, fmt.Sprintf("pod-%s.yaml", pod.Name)), podMashalledBytes, 0644)
		if err != nil {
			diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, fmt.Errorf("error writing pod.yaml for %s/%s: %w", pod.Namespace, pod.Name, err))
		}
	}

	// Follow OwnerRefs to get to the deployment/statefulset/daemonset that spawned this agent
	diagnosticsAccumulatedError = errors.Join(diagnosticsAccumulatedError, dumpOwnerReferences(ctx, k8sClient, pod.Namespace, pod.OwnerReferences, k8sDir))
	return diagnosticsAccumulatedError
}

func collectLogsFromPod(ctx context.Context, client clientk8s.Interface, pod *v1.Pod, dir string) error {

	var retrieveLogsErr error

	for _, container := range pod.Spec.InitContainers {
		retrieveLogsErr = errors.Join(retrieveLogsErr, retrieveContainerLogs(ctx, client, pod, container, false, dir))
	}

	for _, container := range pod.Spec.Containers {
		retrieveLogsErr = errors.Join(retrieveLogsErr, retrieveContainerLogs(ctx, client, pod, container, false, dir))

		// Find container state to check if there has been a restart
		containerStatusIdx := slices.IndexFunc(pod.Status.ContainerStatuses, func(status v1.ContainerStatus) bool {
			return status.Name == container.Name
		})
		if containerStatusIdx != -1 {
			containerStatus := pod.Status.ContainerStatuses[containerStatusIdx]
			if containerStatus.RestartCount > 0 {
				// collect the previous container logs as well
				retrieveLogsErr = errors.Join(retrieveLogsErr, retrieveContainerLogs(ctx, client, pod, container, true, dir))
			}
		}
	}

	return retrieveLogsErr
}

func retrieveContainerLogs(ctx context.Context, client clientk8s.Interface, pod *v1.Pod, container v1.Container, previous bool, outputDir string) error {
	logsReq := client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &v1.PodLogOptions{
		Container: container.Name,
		Previous:  previous,
	})

	streamCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	podLogsStream, err := logsReq.Stream(streamCtx)
	if err != nil {
		return fmt.Errorf("retrieving (previous=%v) logs for %s/%s container %s: %w", previous, pod.Namespace, pod.Name, container.Name, err)
	}

	outputFileName := fmt.Sprintf("%s-%s-current.log", pod.Name, container.Name)
	if previous {
		outputFileName = fmt.Sprintf("%s-%s-previous.log", pod.Name, container.Name)
	}

	oFile, err := os.Create(filepath.Join(outputDir, outputFileName))
	if err != nil {
		return fmt.Errorf("creating error creating output file %s: %w", outputFileName, err)
	}
	defer oFile.Close()
	_, err = io.Copy(oFile, podLogsStream)
	if err != nil {
		return fmt.Errorf("writing (previous=%v) pod logs for %s/%s container %s: %w", previous, pod.Namespace, pod.Name, container.Name, err)
	}
	return nil
}

func createErrorOnlyZip(diagErr error) ([]byte, error) {
	if diagErr == nil {
		return nil, nil
	}

	buf := new(bytes.Buffer)
	writeErr := writeErrorOnlyZip(buf, diagErr)
	if writeErr != nil {
		return nil, writeErr
	}
	return buf.Bytes(), nil
}

func writeErrorOnlyZip(w io.Writer, diagErr error) error {
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	err := addDiagnosticsErrorFileToZip(zipWriter, diagErr)
	if err != nil {
		return fmt.Errorf("adding error file to diagnostics zip writer: %w", err)
	}
	return nil
}

func addDiagnosticsErrorFileToZip(zipWriter *zip.Writer, diagErr error) error {
	errWriter, err := zipWriter.Create(path.Join("k8s-diag-errors.txt"))
	if err != nil {
		return fmt.Errorf("error creating zip writer: %w", err)
	}
	_, err = errWriter.Write([]byte(diagErr.Error()))
	if err != nil {
		return fmt.Errorf("error writing diagnostics error file: %w", err)
	}
	return nil
}

type PodInfoToken struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type ServiceAccountInfoToken struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type TokenPayload struct {
	Namespace      string                  `json:"namespace"`
	Pod            PodInfoToken            `json:"pod"`
	ServiceAccount ServiceAccountInfoToken `json:"serviceaccount"`
}

func readServiceAccountToken(tokenPath string) (*TokenPayload, error) {
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, err
	}

	// token is of the form: <header>.<payload>.<signature>
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid service account token")
	}
	// we care only about the payload (the middle part)
	payloadSeg := parts[1]

	// decode the payload
	decodedPayload, err := base64.RawURLEncoding.DecodeString(string(payloadSeg))
	if err != nil {
		return nil, fmt.Errorf("failed to decode service account token payload: %w", err)
	}

	// unmarshal the payload
	k8sIO := struct {
		Payload TokenPayload `json:"kubernetes.io"`
	}{}
	err = json.Unmarshal(decodedPayload, &k8sIO)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal service account token payload: %w", err)
	}

	return &k8sIO.Payload, nil
}

func dumpOwnerReferences(ctx context.Context, kubernetesClient clientk8s.Interface, namespace string, references []metav1.OwnerReference, outputdir string) error {

	var k8sError error

	for _, ownerRef := range references {

		var k8sObject runtime.Object
		var err error

		switch ownerRef.Kind {
		case "DaemonSet":
			k8sObject, err = kubernetesClient.AppsV1().DaemonSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error getting daemonset %q: %w", ownerRef.Name, err))
				continue
			}

		case "StatefulSet":
			k8sObject, err = kubernetesClient.AppsV1().StatefulSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error getting statefulset %q: %w", ownerRef.Name, err))
				continue
			}

		case "Deployment":
			k8sObject, err = kubernetesClient.AppsV1().Deployments(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error getting deployment %q: %w", ownerRef.Name, err))
				continue
			}

		case "ReplicaSet":
			replicaSet, err := kubernetesClient.AppsV1().ReplicaSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error getting replicaset %q: %w", ownerRef.Name, err))
				continue
			}
			// recursively search for owners of replicasets
			k8sError = errors.Join(k8sError, dumpOwnerReferences(ctx, kubernetesClient, namespace, replicaSet.OwnerReferences, outputdir))
			k8sObject = replicaSet

		default:
			k8sError = errors.Join(k8sError, fmt.Errorf("unsupported owner ref %s/%s, skipping", ownerRef.Kind, ownerRef.Name))
			continue
		}

		if k8sObject != nil {
			outputFile := fmt.Sprintf("%s-%s.yaml", strings.ToLower(ownerRef.Kind), ownerRef.Name)
			err = dumpK8sObject(k8sObject, ownerRef.Name, filepath.Join(outputdir, outputFile))
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error dumping %s: %w", outputFile, err))
			}
		}
	}
	return k8sError
}

func dumpK8sObject(obj runtime.Object, objName string, outputfile string) error {
	marshalledBytes, err := yamlk8s.Marshal(obj)
	if err != nil {
		return fmt.Errorf("error marshalling %s %s: %w", obj.GetObjectKind().GroupVersionKind().Kind, objName, err)
	}
	err = os.WriteFile(outputfile, marshalledBytes, 0644)
	if err != nil {
		return fmt.Errorf("error writing output file %s: %w", outputfile, err)
	}
	return nil
}

func dumpHelmChartValues(ctx context.Context, kubernetesClient clientk8s.Interface, agentPod *v1.Pod, chartOutputDir, valuesOutputFilePath string) error {
	if agentPod == nil {
		return nil
	}

	agentPodLabels := agentPod.GetObjectMeta().GetLabels()
	agentHelmChart, ok := agentPodLabels["helm.sh/chart"]
	if !ok || !strings.HasPrefix(agentHelmChart, "elastic-agent-") {
		return nil
	}

	agentHelmRelease, ok := agentPodLabels["app.kubernetes.io/instance"]
	if !ok || agentHelmRelease == "" {
		return nil
	}

	namespace := agentPod.GetObjectMeta().GetNamespace()

	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"owner":  "helm",
			"name":   agentHelmRelease,
			"status": "deployed",
		},
	}
	helmReleaseSecrets, err := kubernetesClient.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
		Limit:         1,
	})
	if err != nil {
		return fmt.Errorf("failed to list helm release secrets: %w", err)
	}
	if len(helmReleaseSecrets.Items) == 0 {
		return fmt.Errorf("no helm release secrets found for release %s", agentHelmRelease)
	}

	r, err := decodeHelmRelease(string(helmReleaseSecrets.Items[0].Data["release"]))
	if err != nil {
		return fmt.Errorf("failed to decode helm release: %w", err)
	}

	if _, err = chartutil.Save(r.Chart, chartOutputDir); err != nil {
		return fmt.Errorf("failed to save helm chart: %w", err)
	}

	yamlBytes, err := yaml.Marshal(r.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal helm values from release: %w", err)
	}

	if err = os.WriteFile(valuesOutputFilePath, yamlBytes, 0644); err != nil {
		return fmt.Errorf("failed to write helm values to file: %w", err)
	}

	return nil
}

// decodeHelmRelease decodes the bytes of data into a release
// type. Data must contain a base64 encoded gzipped string of a
// valid release, otherwise an error is returned.
func decodeHelmRelease(data string) (*release.Release, error) {
	var b64 = base64.StdEncoding
	var magicGzip = []byte{0x1f, 0x8b, 0x08}

	// base64 decode string
	b, err := b64.DecodeString(data)
	if err != nil {
		return nil, err
	}

	// For backwards compatibility with releases that were stored before
	// compression was introduced we skip decompression if the
	// gzip magic header is not found
	if len(b) > 3 && bytes.Equal(b[0:3], magicGzip) {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		b2, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		b = b2
	}

	var rls release.Release
	// unmarshal release object bytes
	if err := json.Unmarshal(b, &rls); err != nil {
		return nil, err
	}
	return &rls, nil
}

func writeNamespaceLeases(ctx context.Context, kubernetesClient clientk8s.Interface, namespace string, outputFile string) error {
	leases, err := kubernetesClient.CoordinationV1().Leases(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	if len(leases.Items) == 0 {
		return nil
	}

	leasesMarshalledBytes, err := yamlk8s.Marshal(leases.Items)
	if err != nil {
		return fmt.Errorf("error marshalling leases for %q: %w", namespace, err)
	}
	err = os.WriteFile(outputFile, leasesMarshalledBytes, 0644)
	if err != nil {
		return fmt.Errorf("error writing pod.yaml: %w", err)
	}
	return nil
}

func writeZipFileFromDir(baseWriter io.Writer, dir string, diagErr error) error {
	writer := zip.NewWriter(baseWriter)
	defer writer.Close()
	err := writer.AddFS(os.DirFS(dir))
	if err != nil {
		diagErr = errors.Join(diagErr, fmt.Errorf("error adding diagnostics dir %s to zip: %w", dir, err))
	}

	if diagErr != nil {
		return addDiagnosticsErrorFileToZip(writer, diagErr)
	}

	return nil
}
