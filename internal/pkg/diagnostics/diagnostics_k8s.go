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
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
)

func k8sDiagnostics() func(ctx context.Context) []byte {
	return func(ctx context.Context) []byte {
		if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); !ok {
			return nil
		}

		// TODO create a temp dir here and an errors file where to dump all the errors ?
		kubernetesClient, err := kubernetes.GetKubernetesClient("", kubernetes.KubeClientOptions{})
		if err != nil {
			return []byte(fmt.Sprintf("error instantiating k8s client: %q", err))
		}

		tokenPayload, err := readServiceAccountToken("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			return []byte(fmt.Sprintf("error reading service account token: %q", err))
		}

		pod, err := kubernetesClient.CoreV1().Pods(tokenPayload.Namespace).Get(ctx, tokenPayload.Pod.Name, metav1.GetOptions{})
		if err != nil {
			return []byte(fmt.Sprintf("error reading podName from %q: %q", tokenPayload.Pod.Name, err))
		}

		tmpDir, err := os.MkdirTemp("", "elastic-agent-k8s-diag-*")
		if err != nil {
			return []byte(fmt.Sprintf("error creating k8s diag temp directory: %q", err))
		}
		defer os.RemoveAll(tmpDir)

		podMashalledBytes, err := yaml.Marshal(pod)
		if err != nil {
			return []byte(fmt.Sprintf("error marshalling pod: %q", err))
		}

		err = os.WriteFile(filepath.Join(tmpDir, "pod.yaml"), podMashalledBytes, 0644)
		if err != nil {
			return []byte(fmt.Sprintf("error writing pod.yaml: %q", err))
		}

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

func writeZipFileFromDir(baseWriter io.Writer, dir string) error {
	writer := zip.NewWriter(baseWriter)
	defer writer.Close()
	return writer.AddFS(os.DirFS(dir))
}
