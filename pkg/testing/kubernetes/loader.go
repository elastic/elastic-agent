// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"github.com/elastic/cloud-on-k8s/v2/pkg/apis/agent/v1alpha1"
)

// LoadFromYAML converts the given YAML reader to a list of k8s objects
func LoadFromYAML(reader *bufio.Reader) ([]k8s.Object, error) {
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
	k8sScheme.AddKnownTypes(schedulingv1.SchemeGroupVersion, &schedulingv1.PriorityClass{})
	k8sScheme.AddKnownTypes(schema.GroupVersion{Group: "agent.k8s.elastic.co", Version: "v1alpha1"}, &v1alpha1.Agent{})

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
