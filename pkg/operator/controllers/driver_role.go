// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package controllers

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
)

func reconcileRoles(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	roles []*rbacv1.Role,
	scheme *runtime.Scheme,
	namespace string,
) (bool, error) {
	var err error
	var rn bool
	for _, role := range roles {
		roleRn, roleErr := reconcileRole(ctx, log, client, c, role, scheme, namespace)
		if roleErr != nil {
			err = roleErr
			continue
		}
		rn = rn || roleRn
	}

	return rn, err
}

func reconcileRole(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	expected *rbacv1.Role,
	scheme *runtime.Scheme,
	namespace string,
) (bool, error) {
	// TODO: get, compare hash and skip if existing
	gvk, err := apiutil.GVKForObject(expected, scheme)
	if err != nil {
		return false, err
	}
	kind := gvk.Kind

	if err := controllerutil.SetControllerReference(c, expected, scheme); err != nil {
		return false, err
	}

	var reconciled rbacv1.Role
	return false, reconcileResource(ctx, log, compStart, client, expected, &reconciled, expected.Name, namespace, kind, true)
}

func defaultAgentRoles(base string, namespace string) []*rbacv1.Role {
	var roles []*rbacv1.Role
	kubeAdmConfigRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      escapeK8sName(base + "-kubeadm-config"),
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{"kubeadm-config"},
				Verbs:         []string{"get"},
			},
		},
	}

	leasesRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      escapeK8sName(base + "-leases"),
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"get", "create", "update"},
			},
		},
	}

	roles = append(roles, kubeAdmConfigRole)
	roles = append(roles, leasesRole)

	return roles
}
