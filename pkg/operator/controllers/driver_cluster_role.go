// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package controllers

import (
	"context"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

func reconcileClusterRoles(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	roles []*rbacv1.ClusterRole,
	scheme *runtime.Scheme,
	namespace string,
) (bool, error) {
	var err error
	var rn bool
	for _, role := range roles {
		roleRn, roleErr := reconcileClusterRole(ctx, log, client, c, role, scheme, namespace)
		if roleErr != nil {
			err = roleErr
			continue
		}
		rn = rn || roleRn
	}

	return rn, err
}

func reconcileClusterRole(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	expected *rbacv1.ClusterRole,
	scheme *runtime.Scheme,
	namespace string,
) (bool, error) {
	// TODO: get, compare hash and skip if existing
	gvk, err := apiutil.GVKForObject(expected, scheme)
	if err != nil {
		return false, err
	}
	kind := gvk.Kind

	// if err := controllerutil.SetControllerReference(c, expected, scheme); err != nil {
	// 	return false, err
	// }

	var reconciled rbacv1.ClusterRole
	return false, reconcileResource(ctx, log, compStart, client, expected, &reconciled, expected.Name, namespace, kind, true)
}

func defaultAgentClusterRoles(base, namespace string) []*rbacv1.ClusterRole {
	var roles []*rbacv1.ClusterRole

	defaultRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      escapeK8sName(base + "-default-role"),
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{
					"nodes", "namespaces", "events", "pods", "services",
					"configmaps", "serviceaccounts",
					"persistentvolumes", "persistentvolumeclaims",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"extensions"},
				Resources: []string{
					"replicasets",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{
					"statefulsets", "deployments", "replicasets", "daemonsets",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{
					"jobs", "cronjobs",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{
					"nodes/stats",
				},
				Verbs: []string{"get"},
			},
			{
				NonResourceURLs: []string{"/metrics"},
				Verbs:           []string{"get"},
			},
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{
					"clusterrolebindings", "clusterroles", "rolebindings", "roles",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"policy"},
				Resources: []string{
					"podsecuritypolicies",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"storage.k8s.io"},
				Resources: []string{
					"storageclasses",
				},
				Verbs: []string{"get", "list", "watch"},
			},
		},
	}
	roles = append(roles, defaultRole)

	return roles
}
