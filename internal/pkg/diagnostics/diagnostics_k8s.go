// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientk8s "k8s.io/client-go/kubernetes"
	yamlk8s "sigs.k8s.io/yaml"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/logp"
)

func k8sDiagnostics(l *logp.Logger) func(ctx context.Context) []byte {
	return func(ctx context.Context) []byte {
		if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); !ok {
			return nil
		}

		var k8sError error

		const zipSubdir = "k8s"
		tmpDir, err := os.MkdirTemp("", "elastic-agent-k8s-diag-*")
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error creating k8s diag temp directory: %w", err))
			errorOnlyZip, zipCreateErr := createErrorOnlyZip(k8sError)
			if zipCreateErr != nil {
				l.Errorf("error creating error-only k8s diag zip: %s", zipCreateErr)
			}
			return errorOnlyZip
		}
		defer os.RemoveAll(tmpDir)

		k8sDir := filepath.Join(tmpDir, zipSubdir)
		err = os.MkdirAll(k8sDir, 0755)
		if err != nil {
			k8sError = errors.Join(fmt.Errorf("error creating k8s diag subdirectory %q: %w", k8sDir, err))
			errorOnlyZip, zipCreateErr := createErrorOnlyZip(k8sError)
			if zipCreateErr != nil {
				l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, k8sError)
			}
			return errorOnlyZip
		}

		kubernetesClient, err := kubernetes.GetKubernetesClient("", kubernetes.KubeClientOptions{})
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error instantiating k8s client: %w", err))
			errorOnlyZip, zipCreateErr := createErrorOnlyZip(k8sError)
			if zipCreateErr != nil {
				l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, k8sError)
			}
			return errorOnlyZip
		}

		tokenPayload, err := readServiceAccountToken("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error reading service account token: %w", err))
			errorOnlyZip, zipCreateErr := createErrorOnlyZip(k8sError)
			if zipCreateErr != nil {
				l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, k8sError)
			}
			return errorOnlyZip
		}

		pod, err := kubernetesClient.CoreV1().Pods(tokenPayload.Namespace).Get(ctx, tokenPayload.Pod.Name, metav1.GetOptions{})
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error getting pod %s/%s: %w", tokenPayload.Namespace, tokenPayload.Pod.Name, err))
			errorOnlyZip, zipCreateErr := createErrorOnlyZip(k8sError)
			if zipCreateErr != nil {
				l.Errorf("error creating error-only k8s diag zip: %s. Diagnostics errors: %s", zipCreateErr, k8sError)
			}
			return errorOnlyZip
		}

		podMashalledBytes, err := yamlk8s.Marshal(pod)
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error marshalling pod %s/%s: %w", tokenPayload.Namespace, tokenPayload.Pod.Name, err))
		}

		if podMashalledBytes != nil {
			err = os.WriteFile(filepath.Join(k8sDir, fmt.Sprintf("pod-%s.yaml", tokenPayload.Pod.Name)), podMashalledBytes, 0644)
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error writing pod.yaml for %s/%s: %w", tokenPayload.Namespace, tokenPayload.Pod.Name, err))
			}
		}

		k8sError = errors.Join(k8sError, dumpOwnerReferences(ctx, kubernetesClient, tokenPayload.Namespace, pod.OwnerReferences, k8sDir))

		buf := new(bytes.Buffer)
		err = writeZipFileFromDir(buf, tmpDir, k8sError)
		if err != nil {
			l.Errorf("error creating k8s diagnostics zip: %s. Diagnostics errors: %s", err, k8sError)
			return nil
		}

		return buf.Bytes()
	}
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
			err = dumpOwnerReferences(ctx, kubernetesClient, namespace, replicaSet.OwnerReferences, outputdir)
			if err != nil {
				k8sError = errors.Join(k8sError, err)
			}
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
