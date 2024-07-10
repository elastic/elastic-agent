// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package integration

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

const agentK8SKustomize = "../../deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone"

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

	ctx := context.Background()

	namespace := info.Namespace

	// Create a file system pointing to the kustomize directory
	fSys := filesys.MakeFsOnDisk()

	// Create a kustomizer
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())

	// Run the kustomizer on the given directory
	resMap, err := k.Run(fSys, agentK8SKustomize)
	require.NoError(t, err)

	// Convert the result to YAML
	renderedManifest, err := resMap.AsYaml()
	require.NoError(t, err)

	decoder := newYamlReader()
	objects, err := decoder.ToObjects(bufio.NewReader(bytes.NewReader(renderedManifest)))
	require.NoError(t, err)

	k8sNamespaceObj := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	t.Cleanup(func() {
		_ = client.Resources().Delete(ctx, k8sNamespaceObj)
		for _, obj := range objects {
			_ = client.Resources(namespace).Delete(ctx, obj)
		}
	})

	err = client.Resources().Create(ctx, k8sNamespaceObj)
	require.NoError(t, err)

	// Update the agent image and image pull policy as it is already loaded in kind cluster
	for _, obj := range objects {
		switch objWithType := obj.(type) {
		case *appsv1.DaemonSet:
			for idx, container := range objWithType.Spec.Template.Spec.Containers {
				if container.Name == "elastic-agent-standalone" {
					objWithType.Spec.Template.Spec.Containers[idx].Image = agentImage
					objWithType.Spec.Template.Spec.Containers[idx].ImagePullPolicy = "Never"
				}
			}
		case *appsv1.StatefulSet:
			for idx, container := range objWithType.Spec.Template.Spec.Containers {
				if container.Name == "elastic-agent-standalone" {
					objWithType.Spec.Template.Spec.Containers[idx].Image = agentImage
					objWithType.Spec.Template.Spec.Containers[idx].ImagePullPolicy = "Never"
				}
			}
		case *appsv1.Deployment:
			for idx, container := range objWithType.Spec.Template.Spec.Containers {
				if container.Name == "elastic-agent-standalone" {
					objWithType.Spec.Template.Spec.Containers[idx].Image = agentImage
					objWithType.Spec.Template.Spec.Containers[idx].ImagePullPolicy = "Never"
				}
			}
		}
	}

	// Create the objects
	for _, obj := range objects {
		obj.SetNamespace(namespace)
		err = client.Resources(namespace).Create(ctx, obj)
		require.NoError(t, err)
	}

	// Wait for pods to be ready
	require.Eventually(t, func() bool {
		podList := &corev1.PodList{}
		err := client.Resources(namespace).List(ctx, podList)
		require.NoError(t, err)

		for _, pod := range podList.Items {
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
	require.NoError(t, err)
}

// YAMLDecoder converts YAML bytes into test.Builder instances.
type YAMLDecoder struct {
	decoder runtime.Decoder
}

func newYamlReader() *YAMLDecoder {
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

	return &YAMLDecoder{decoder: decoder}
}

func (yd *YAMLDecoder) ToObjects(reader *bufio.Reader) ([]k8s.Object, error) {
	var objects []k8s.Object

	yamlReader := yaml.NewYAMLReader(reader)
	for {
		yamlBytes, err := yamlReader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to read YAML: %w", err)
		}
		obj, _, err := yd.decoder.Decode(yamlBytes, nil, nil)
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
