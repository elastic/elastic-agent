/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	observabilityv1alpha1 "github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
)

// ElasticAgentComponentReconciler reconciles a ElasticAgentComponent object
type ElasticAgentComponentReconciler struct {
	client.Client
	Scheme *k8sRuntime.Scheme
	log    *logger.Logger
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ElasticAgentComponent object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *ElasticAgentComponentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	r.log.Debugf("Reconciling component", req.NamespacedName.String())
	component := &observabilityv1alpha1.ElasticAgentComponent{}
	if err := r.Client.Get(ctx, req.NamespacedName, component); err != nil {
		if apierrors.IsNotFound(err) {
			r.log.Debugf("Operator: not found")
			//r.onDelete(req.NamespacedName)
			return reconcile.Result{}, nil
		}
		r.log.Debugf("Operator: err %v", err)
		return reconcile.Result{}, err
	}

	// create config
	secretName := NameSecret(req.Name)
	r.log.Debugf("Component: reconciling secret")
	if rn, err := reconcileSecret(ctx, r.log, r.Client, component, secretName, component.Spec.Policy, r.Scheme, req.Namespace); err != nil {
		r.log.Debugf("Component: reconciling secret failed: %v", err)
		return ctrl.Result{}, err
	} else if rn {
		r.log.Debugf("Component: reconciling secret requeue needed")
		return ctrl.Result{Requeue: true}, nil
	}

	// setup rbac
	serviceAccountName := ServiceAccountName(req.Name)
	if rn, err := reconcileServiceAccount(ctx, r.log, r.Client, component, serviceAccountName, r.Scheme, req.Namespace); err != nil {
		r.log.Debugf("Component: reconciling service account failed: %v", err)
		return ctrl.Result{}, err
	} else if rn {
		r.log.Debugf("Component: reconciling service account requeue needed")
		return ctrl.Result{Requeue: true}, nil
	}

	roles := defaultAgentRoles(req.Name, req.Namespace)
	if rn, err := reconcileRoles(ctx, r.log, r.Client, component, roles, r.Scheme, req.Namespace); err != nil {
		r.log.Debugf("Component: reconciling roles failed: %v", err)
		return ctrl.Result{}, err
	} else if rn {
		r.log.Debugf("Component: reconciling roles requeue needed")
		return ctrl.Result{Requeue: true}, nil
	}

	clusterRoles := defaultAgentClusterRoles(req.Name, req.Namespace)
	r.log.Debugf("CLuster roles before %d", len(clusterRoles))
	if rn, err := reconcileClusterRoles(ctx, r.log, r.Client, component, clusterRoles, r.Scheme, req.Namespace); err != nil {
		r.log.Debugf("Component: reconciling cluster roles failed: %v", err)
		return ctrl.Result{}, err
	} else if rn {
		r.log.Debugf("Component: reconciling cluster roles requeue needed")
		return ctrl.Result{Requeue: true}, nil
	}
	r.log.Debugf("CLuster roles after %d", len(clusterRoles))

	if rn, err := reconcileClusterRoleBindings(ctx, r.log, r.Client, component, serviceAccountName, clusterRoles, r.Scheme, req.Namespace); err != nil {
		r.log.Debugf("Component: reconciling cluster role bindings failed: %v", err)
		return ctrl.Result{}, err
	} else if rn {
		r.log.Debugf("Component: reconciling cluster role bindings requeue needed")
		return ctrl.Result{Requeue: true}, nil
	}

	if rn, err := reconcileRoleBindings(ctx, r.log, r.Client, component, serviceAccountName, roles, r.Scheme, req.Namespace); err != nil {
		r.log.Debugf("Component: reconciling roles binding failed: %v", err)
		return ctrl.Result{}, err
	} else if rn {
		r.log.Debugf("Component: reconciling roles binding requeue needed")
		return ctrl.Result{Requeue: true}, nil
	}

	// setup pod vehicle
	if component.Spec.UpdateNeeded {
		r.log.Debugf("Component: updating")
		// no need to recreate on update
		return ctrl.Result{}, nil
	}
	r.log.Debugf("Component: reconciling pod")
	rn, err := reconcilePodVehicle(ctx, r.log, r.Client, component, secretName, r.Scheme, req.Namespace, serviceAccountName)
	if err != nil {
		r.log.Errorf("Failed reconciling pod vehicle: %v", err)
	}
	r.log.Debugf("Component: reconciling pod done rn: %v", rn)
	return ctrl.Result{Requeue: rn}, nil

}

func NewElasticComponentController(log *logger.Logger, client client.Client, scheme *k8sRuntime.Scheme) *ElasticAgentComponentReconciler {
	return &ElasticAgentComponentReconciler{
		log:    log,
		Client: client,
		Scheme: scheme,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticAgentComponentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&observabilityv1alpha1.ElasticAgentComponent{}).
		Complete(r)
}
