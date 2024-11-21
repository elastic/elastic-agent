// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetesleaderelection

import (
	"context"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const leaderElectorPrefix = "elastic-agent-leader-"

func init() {
	composable.Providers.MustAddContextProvider("kubernetes_leaderelection", ContextProviderBuilder)
}

type contextProvider struct {
	logger         *logger.Logger
	config         *Config
	leaderElection *leaderelection.LeaderElectionConfig
}

// ContextProviderBuilder builds the provider.
func ContextProviderBuilder(logger *logger.Logger, c *config.Config, managed bool) (corecomp.ContextProvider, error) {
	var cfg Config
	if c == nil {
		c = config.New()
	}
	err := c.UnpackTo(&cfg)
	if err != nil {
		return nil, errors.New(err, "failed to unpack configuration")
	}
	return &contextProvider{logger, &cfg, nil}, nil
}

// This is needed to overwrite the Kubernetes client for the tests
var getK8sClientFunc = func(kubeconfig string, opt kubernetes.KubeClientOptions) (k8sclient.Interface, error) {
	return kubernetes.GetKubernetesClient(kubeconfig, opt)
}

// Run runs the leaderelection provider.
func (p *contextProvider) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	client, err := getK8sClientFunc(p.config.KubeConfig, p.config.KubeClientOptions)
	if err != nil {
		p.logger.Debugf("Kubernetes leaderelection provider skipped, unable to connect: %s", err)
		return nil
	}

	agentInfo, err := info.NewAgentInfo(ctx, false)
	if err != nil {
		return err
	}
	var id string
	podName, found := os.LookupEnv("POD_NAME")
	if found {
		id = leaderElectorPrefix + podName
	} else {
		id = leaderElectorPrefix + agentInfo.AgentID()
	}

	ns, err := kubernetes.InClusterNamespace()
	if err != nil {
		ns = "default"
	}
	lease := metav1.ObjectMeta{
		Name:      p.config.LeaderLease,
		Namespace: ns,
	}
	p.leaderElection = &leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta: lease,
			Client:    client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: id,
			},
		},
		ReleaseOnCancel: true,
		LeaseDuration:   time.Duration(p.config.LeaseDuration) * time.Second,
		RenewDeadline:   time.Duration(p.config.RenewDeadline) * time.Second,
		RetryPeriod:     time.Duration(p.config.RetryPeriod) * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				p.logger.Debugf("leader election lock GAINED, id %v", id)
				p.logger.Debugf("leader configuration timings: LeaseDuration: %v , RenewDeadline: %v, RetryPeriod: %v", p.leaderElection.LeaseDuration, p.leaderElection.RenewDeadline, p.leaderElection.RetryPeriod)
				p.startLeading(comm)
			},
			OnStoppedLeading: func() {
				p.logger.Debugf("leader election lock LOST, id %v", id)
				p.stopLeading(comm)
			},
		},
	}

	le, err := leaderelection.NewLeaderElector(*p.leaderElection)
	if err != nil {
		p.logger.Errorf("error while creating Leader Elector: %v", err)
	}
	p.logger.Debugf("Starting Leader Elector")

	for {
		le.Run(ctx)
		if ctx.Err() != nil {
			p.logger.Debugf("Stopped Leader Elector")
			return comm.Err()
		}
	}
}

func (p *contextProvider) startLeading(comm corecomp.ContextProviderComm) {
	mapping := map[string]interface{}{
		"leader": true,
	}

	err := comm.Set(mapping)
	if err != nil {
		p.logger.Errorf("Failed updating leaderelection status to leader TRUE: %s", err)
	}
}

func (p *contextProvider) stopLeading(comm corecomp.ContextProviderComm) {
	mapping := map[string]interface{}{
		"leader": false,
	}

	err := comm.Set(mapping)
	if err != nil {
		p.logger.Errorf("Failed updating leaderelection status to leader FALSE: %s", err)
	}
}
