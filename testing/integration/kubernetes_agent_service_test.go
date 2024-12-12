// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestKubernetesAgentService(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			// only test the service container
			{Type: define.Kubernetes, DockerVariant: "service"},
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background()
	kCtx := k8sGetContext(t, info)
	testNamespace := kCtx.getNamespace(t)

	renderedManifest, err := renderKustomize(agentK8SKustomize)
	require.NoError(t, err, "failed to render kustomize")

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

	// update the configmap to only run the connectors input
	serviceAgentYAML, err := os.ReadFile(filepath.Join("testdata", "connectors.agent.yml"))
	require.NoError(t, err)
	for _, obj := range k8sObjects {
		switch objWithType := obj.(type) {
		case *corev1.ConfigMap:
			_, ok := objWithType.Data["agent.yml"]
			if ok {
				objWithType.Data["agent.yml"] = string(serviceAgentYAML)
			}
		}
	}

	k8sKustomizeDeployAgent(t, ctx, kCtx.client, k8sObjects, testNamespace, false, kCtx.logsBasePath,
		true, map[string]bool{
			"connectors-py": true,
		})
}
