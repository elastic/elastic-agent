// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package controllers

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
)

func reconcileClusterRoleBindings(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	serviceAccountName string,
	roles []*rbacv1.ClusterRole,
	scheme *runtime.Scheme,
	namespace string,
) (bool, error) {
	var err error
	var rn bool
	for _, role := range roles {
		log.Debugf("creating role binding %s", role.Name)
		roleRn, roleErr := reconcileClusterRoleBinding(ctx, log, client, c, serviceAccountName, role, scheme, namespace)
		if roleErr != nil {
			err = roleErr
			continue
		}
		rn = rn || roleRn
	}

	return rn, err
}

func reconcileClusterRoleBinding(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	serviceAccountName string,
	role *rbacv1.ClusterRole,
	scheme *runtime.Scheme,
	namespace string,
) (bool, error) {
	roleBindingName := ClusterRoleBindingName(role.Name, serviceAccountName)
	// TODO: get, compare hash and skip if existing
	expected := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName,
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     role.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
	gvk, err := apiutil.GVKForObject(expected, scheme)
	if err != nil {
		return false, err
	}
	kind := gvk.Kind

	log.Debugf("reconciling cluster role binding %s(%s)", expected.Name, expected.Namespace)
	var reconciled rbacv1.ClusterRoleBinding
	return false, reconcileResource(ctx, log, compStart, client, expected, &reconciled, expected.Name, expected.Namespace, kind, false)
}

func ClusterRoleBindingName(roleName, serviceAccountName string) string {
	return escapeK8sName(fmt.Sprintf("%s-%s-%s", roleName, serviceAccountName, "RoleBindC"))
}
