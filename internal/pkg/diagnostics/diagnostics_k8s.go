// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
		const namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
		namespaceBytes, err := os.ReadFile(namespaceFile)
		if err != nil {
			return []byte(fmt.Sprintf("error reading namespace from %q: %q", namespaceFile, err))
		}

		const podNameFile = "/etc/podinfo/name"
		podName, err := os.ReadFile(podNameFile)
		if err != nil {
			return []byte(fmt.Sprintf("error reading podName from %q: %q", podNameFile, err))
		}

		namespace := strings.TrimSpace(string(namespaceBytes))
		pod, err := kubernetesClient.CoreV1().Pods(namespace).Get(ctx, string(podName), metav1.GetOptions{})
		if err != nil {
			return []byte(fmt.Sprintf("error reading podName from %q: %q", podNameFile, err))
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

func writeZipFileFromDir(baseWriter io.Writer, dir string) error {
	writer := zip.NewWriter(baseWriter)
	defer writer.Close()
	return writer.AddFS(os.DirFS(dir))
}
