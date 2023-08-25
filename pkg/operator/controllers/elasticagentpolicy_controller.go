// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package controllers

import (
	"context"
	"fmt"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	observabilityv1alpha1 "github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
)

var (
	defaultConfigTimeout      = 300 * time.Second
	defaultErrorReportTimeout = 5 * time.Second
)

const (
	compStart  = 1 << 0
	compUpdate = 1 << 1
	compStop   = 1 << 2
)

type Watcher interface {
	Watch() runtime.WatchChan
}

// ElasticAgentPolicyReconciler reconciles a ElasticAgentPolicy object
type ElasticAgentPolicyReconciler struct {
	k8sClient.Client
	Scheme *k8sRuntime.Scheme

	cm *k8sConfigManager
}

func NewElasticPolicyController(log *logger.Logger, client k8sClient.Client, scheme *k8sRuntime.Scheme, rw Watcher) *ElasticAgentPolicyReconciler {
	cfgMng := &k8sConfigManager{
		log:            log,
		ch:             make(chan coordinator.ConfigChange),
		errCh:          make(chan error),
		runtimeWatcher: rw,
		client:         client,
		scheme:         scheme,
	}
	return &ElasticAgentPolicyReconciler{
		cm:     cfgMng,
		Client: client,
		Scheme: scheme,
	}
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ElasticAgentPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *ElasticAgentPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	return r.cm.handleReconcile(ctx, r.Client, req, r.Scheme)
}

func (r *ElasticAgentPolicyReconciler) ConfigManager() coordinator.ConfigManager {
	return r.cm
}

// SetupWithManager sets up the controller with the Manager.
func (r *ElasticAgentPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&observabilityv1alpha1.ElasticAgentPolicy{}).
		Complete(r)
}

// config manager implementation
type k8sConfigManager struct {
	log            *logger.Logger
	client         k8sClient.Client
	scheme         *k8sRuntime.Scheme
	ch             chan coordinator.ConfigChange
	errCh          chan error
	runtimeWatcher Watcher
	cfgHash        string
	currPolicy     *observabilityv1alpha1.ElasticAgentPolicy
	currNamespace  string
	currCfg        map[string]interface{}
	newHash        string
	cfgLock        sync.Mutex
}

func (r *k8sConfigManager) Run(ctx context.Context) error {
	go r.run(ctx)
	<-ctx.Done()
	return nil
}

func (r *k8sConfigManager) handleReconcile(ctx context.Context, client k8sClient.Client, req ctrl.Request, scheme *k8sRuntime.Scheme) (ctrl.Result, error) {
	r.cfgLock.Lock()
	defer r.cfgLock.Unlock()

	policy := &observabilityv1alpha1.ElasticAgentPolicy{}
	if err := client.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			r.log.Debugf("Operator: not found")
			return reconcile.Result{}, nil
		}
		r.log.Errorf("Operator: err %v", err)
		return reconcile.Result{}, err
	}

	newHash, err := policy.Spec.Policy.Hash()
	if err != nil {
		return reconcile.Result{}, err
	}

	if r.cfgHash == string(newHash) {
		return reconcile.Result{}, nil
	}

	cfg, err := config.NewConfigFrom(policy.Spec.Policy.Data)
	if err != nil {
		err = fmt.Errorf("failed to parse policy: %w", err)
		r.reportError(err)
		return reconcile.Result{}, err
	}

	r.currCfg, err = cfg.ToMapStr()
	if err != nil {
		return ctrl.Result{}, err
	}
	r.currNamespace = req.Namespace
	r.currPolicy = policy
	r.newHash = newHash

	// pass config to config Manager
	select {
	case r.ch <- &crConfigChange{
		cfg: cfg,
	}:
		r.log.Debugf("Operator:sent config change")
	case <-time.After(defaultConfigTimeout):
		r.log.Errorf("failed to process configuration, coordinator sleeping")
		r.reportError(fmt.Errorf("failed to process configuration, coordinator sleeping"))
	}

	return ctrl.Result{}, err
}
func (r *k8sConfigManager) run(ctx context.Context) {
	for recCh := range r.runtimeWatcher.Watch() {
		r.cfgLock.Lock()
		r.log.Debugf("Operator: retrieved components")
		for wr := range recCh {
			if wr.Err != nil {
				r.log.Errorf("Operator: retrieved component with an error: %v", wr.Err)
			}

			mode := compStart
			if wr.Stop {
				mode = compStop
			} else if wr.Update {
				mode = compUpdate
			}
			r.log.Debugf("Operator: reconciling component %s", wr.Comp.ID)
			owner := wr.Comp
			_, compErr := reconcileComponent(ctx, r.log, mode, r.currCfg, owner, r.client, r.currPolicy, r.scheme, r.currNamespace)
			if compErr != nil {
				r.log.Errorf("Operator: reconciled with error %v", compErr)
			}
		}

		r.log.Debugf("Operator: finished with components")
		r.cfgHash = r.newHash
		r.newHash = ""
		r.cfgLock.Unlock()
	}
}

func (r *k8sConfigManager) Errors() <-chan error {
	return r.errCh
}

// ActionErrors returns the error channel for actions.
// Returns nil channel.
func (r *k8sConfigManager) ActionErrors() <-chan error {
	// TODO: implement properly
	actionErrCh := make(chan error)
	return actionErrCh
}

func (r *k8sConfigManager) Watch() <-chan coordinator.ConfigChange {
	return r.ch
}

func (r *k8sConfigManager) reportError(err error) {
	select {
	case r.errCh <- err:
	case <-time.After(defaultErrorReportTimeout):
		r.log.Warnf("Timed out: failed to report error %v.", err)
	}
}

type crConfigChange struct {
	cfg *config.Config
}

func (l *crConfigChange) Config() *config.Config {
	return l.cfg
}

func (l *crConfigChange) Ack() error {
	// do nothing
	return nil
}

func (l *crConfigChange) Fail(_ error) {
	// do nothing
}
