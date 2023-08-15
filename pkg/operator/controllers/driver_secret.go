// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package controllers

import (
	"context"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func reconcileSecret(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	name, content string,
	scheme *runtime.Scheme,
	namespace string,
) (bool, error) {
	// TODO: get, compare hash and skip if existing
	expected := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		StringData: map[string]string{
			ConfigFileName: content,
		},
	}
	gvk, err := apiutil.GVKForObject(expected, scheme)
	if err != nil {
		return false, err
	}
	kind := gvk.Kind

	if err := controllerutil.SetControllerReference(c, expected, scheme); err != nil {
		return false, err
	}

	var reconciled corev1.Secret
	return false, reconcileResource(ctx, log, compStart, client, expected, &reconciled, name, namespace, kind, true)
}
