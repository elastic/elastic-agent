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
	"path/filepath"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientk8s "k8s.io/client-go/kubernetes"
	yamlk8s "sigs.k8s.io/yaml"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
)

func k8sDiagnostics() func(ctx context.Context) []byte {
	return func(ctx context.Context) []byte {
		if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); !ok {
			return nil
		}

		// TODO create a temp dir here and an errors file where to dump all the errors ?

		var k8sError error

		kubernetesClient, err := kubernetes.GetKubernetesClient("", kubernetes.KubeClientOptions{})
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error instantiating k8s client: %w", err))
			//return createErrorFile(k8sErrors)
		}

		tokenPayload, err := readServiceAccountToken("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error reading service account token: %w", err))
		}

		pod, err := kubernetesClient.CoreV1().Pods(tokenPayload.Namespace).Get(ctx, tokenPayload.Pod.Name, metav1.GetOptions{})
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error getting pod %s/%s: %w", tokenPayload.Namespace, tokenPayload.Pod.Name, err))
		}

		tmpDir, err := os.MkdirTemp("", "elastic-agent-k8s-diag-*")
		if err != nil {
			k8sError = errors.Join(k8sError, fmt.Errorf("error creating k8s diag temp directory: %w", err))
		}
		defer os.RemoveAll(tmpDir)

		k8sDir := filepath.Join(tmpDir, "k8s")
		err = os.MkdirAll(k8sDir, 0755)

		podMashalledBytes, err := yamlk8s.Marshal(pod)
		if err != nil {
			return []byte(fmt.Sprintf("error marshalling pod: %q", err))
		}

		err = os.WriteFile(filepath.Join(k8sDir, fmt.Sprintf("pod-%s.yaml", tokenPayload.Pod.Name)), podMashalledBytes, 0644)
		if err != nil {
			return []byte(fmt.Sprintf("error writing pod.yaml: %q", err))
		}

		k8sError = errors.Join(k8sError, dumpOwnerReferences(ctx, kubernetesClient, tokenPayload.Namespace, pod.OwnerReferences, k8sDir))

		buf := new(bytes.Buffer)
		err = writeZipFileFromDir(buf, tmpDir)
		if err != nil {
			return []byte(fmt.Sprintf("error creating zipped elastic-agent-k8s-*.zip: %q", err))
		}

		return buf.Bytes()
	}
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
		switch ownerRef.Kind {
		case "DaemonSet":
			daemonset, err := kubernetesClient.AppsV1().DaemonSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error getting daemonset %q: %w", ownerRef.Name, err))
				continue
			}
			dsMarshalledBytes, err := yaml.Marshal(daemonset)
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error marshalling daemonset %q: %w", ownerRef.Name, err))
				continue
			}
			err = os.WriteFile(filepath.Join(outputdir, fmt.Sprintf("daemonset-%s.yaml", ownerRef.Name)), dsMarshalledBytes, 0644)
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error writing pod.yaml: %w", err))
				continue
			}
		case "StatefulSet", "Deployment":
			k8sError = errors.Join(k8sError, fmt.Errorf("support for %s not implemented", ownerRef.Kind))
			continue
		case "ReplicaSet":
			replicaSet, err := kubernetesClient.AppsV1().ReplicaSets(namespace).Get(ctx, ownerRef.Name, metav1.GetOptions{})
			if err != nil {
				k8sError = errors.Join(k8sError, fmt.Errorf("error getting replicaset %q: %w", ownerRef.Name, err))
				continue
			}
			return dumpOwnerReferences(ctx, kubernetesClient, namespace, replicaSet.OwnerReferences, outputdir)
		default:
			// recursively go to the owner of the object
		}
	}
	return k8sError
}

func writeZipFileFromDir(baseWriter io.Writer, dir string) error {
	writer := zip.NewWriter(baseWriter)
	defer writer.Close()
	return writer.AddFS(os.DirFS(dir))
}
