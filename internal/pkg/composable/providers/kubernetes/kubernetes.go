// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetes

import (
	"fmt"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"

	k8s "k8s.io/client-go/kubernetes"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	// NodePriority is the priority that node mappings are added to the provider.
	NodePriority = 0
	// PodPriority is the priority that pod mappings are added to the provider.
	PodPriority = 1
	// ContainerPriority is the priority that container mappings are added to the provider.
	ContainerPriority = 2
	// ServicePriority is the priority that service mappings are added to the provider.
	ServicePriority = 3
)

const nodeScope = "node"

func init() {
	composable.Providers.MustAddDynamicProvider("kubernetes", DynamicProviderBuilder)
}

type dynamicProvider struct {
	logger  *logger.Logger
	config  *Config
	managed bool
}

// DynamicProviderBuilder builds the dynamic provider.
func DynamicProviderBuilder(logger *logger.Logger, c *config.Config, managed bool) (composable.DynamicProvider, error) {
	var cfg Config
	if c == nil {
		c = config.New()
	}
	err := c.Unpack(&cfg)
	if err != nil {
		return nil, errors.New(err, "failed to unpack configuration")
	}

	return &dynamicProvider{logger, &cfg, managed}, nil
}

// Run runs the kubernetes context provider.
func (p *dynamicProvider) Run(comm composable.DynamicProviderComm) error {
	if p.config.Hints.Enabled {
		betalogger := p.logger.Named("cfgwarn")
		betalogger.Warnf("BETA: Hints' feature is beta.")
	}
	eventers := make([]Eventer, 0, 3)
	if p.config.Resources.Pod.Enabled {
		eventer, err := p.watchResource(comm, "pod")
		if err != nil {
			return err
		}
		if eventer != nil {
			eventers = append(eventers, eventer)
		}
	}
	if p.config.Resources.Node.Enabled {
		eventer, err := p.watchResource(comm, nodeScope)
		if err != nil {
			return err
		}
		if eventer != nil {
			eventers = append(eventers, eventer)
		}
	}
	if p.config.Resources.Service.Enabled {
		eventer, err := p.watchResource(comm, "service")
		if err != nil {
			return err
		}
		if eventer != nil {
			eventers = append(eventers, eventer)
		}
	}
	<-comm.Done()
	for _, eventer := range eventers {
		eventer.Stop()
	}
	return comm.Err()
}

// watchResource initializes the proper watcher according to the given resource (pod, node, service)
// and starts watching for such resource's events.
func (p *dynamicProvider) watchResource(
	comm composable.DynamicProviderComm,
	resourceType string) (Eventer, error) {
	client, err := kubernetes.GetKubernetesClient(p.config.KubeConfig, p.config.KubeClientOptions)
	if err != nil {
		// info only; return nil (do nothing)
		p.logger.Debugf("Kubernetes provider for resource %s skipped, unable to connect: %s", resourceType, err)
		return nil, nil
	}

	// Ensure that node is set correctly whenever the scope is set to "node". Make sure that node is empty
	// when cluster scope is enforced.
	p.logger.Infof("Kubernetes provider started for resource %s with %s scope", resourceType, p.config.Scope)
	if p.config.Scope == nodeScope {

		p.logger.Debugf(
			"Initializing Kubernetes watcher for resource %s using node: %v",
			resourceType,
			p.config.Node)
		nd := &kubernetes.DiscoverKubernetesNodeParams{
			ConfigHost:  p.config.Node,
			Client:      client,
			IsInCluster: kubernetes.IsInCluster(p.config.KubeConfig),
			HostUtils:   &kubernetes.DefaultDiscoveryUtils{},
		}
		p.config.Node, err = kubernetes.DiscoverKubernetesNode(p.logger, nd)
		if err != nil {
			p.logger.Debugf("Kubernetes provider skipped, unable to discover node: %w", err)
			return nil, nil
		}

	} else {
		p.config.Node = ""
	}

	eventer, err := p.newEventer(resourceType, comm, client)
	if err != nil {
		return nil, errors.New(err, "couldn't create kubernetes watcher for resource %s", resourceType)
	}

	err = eventer.Start()
	if err != nil {
		return nil, errors.New(err, "couldn't start kubernetes eventer for resource %s", resourceType)
	}

	return eventer, nil
}

// Eventer allows defining ways in which kubernetes resource events are observed and processed
type Eventer interface {
	kubernetes.ResourceEventHandler
	Start() error
	Stop()
}

// newEventer initializes the proper eventer according to the given resource (pod, node, service).
func (p *dynamicProvider) newEventer(
	resourceType string,
	comm composable.DynamicProviderComm,
	client k8s.Interface) (Eventer, error) {
	switch resourceType {
	case "pod":
		eventer, err := NewPodEventer(comm, p.config, p.logger, client, p.config.Scope, p.managed)
		if err != nil {
			return nil, err
		}
		return eventer, nil
	case nodeScope:
		eventer, err := NewNodeEventer(comm, p.config, p.logger, client, p.config.Scope, p.managed)
		if err != nil {
			return nil, err
		}
		return eventer, nil
	case "service":
		eventer, err := NewServiceEventer(comm, p.config, p.logger, client, p.config.Scope, p.managed)
		if err != nil {
			return nil, err
		}
		return eventer, nil
	default:
		return nil, fmt.Errorf("unsupported autodiscover resource %s", resourceType)
	}
}
