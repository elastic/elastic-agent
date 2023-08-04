// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetes

import (
	"fmt"
	"time"

	k8s "k8s.io/client-go/kubernetes"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/safemapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
)

type service struct {
	logger           *logp.Logger
	cleanupTimeout   time.Duration
	comm             composable.DynamicProviderComm
	scope            string
	config           *Config
	metagen          metadata.MetaGen
	watcher          kubernetes.Watcher
	namespaceWatcher kubernetes.Watcher
}

type serviceData struct {
	service    *kubernetes.Service
	mapping    map[string]interface{}
	processors []map[string]interface{}
}

// NewServiceEventer creates an eventer that can discover and process service objects
func NewServiceEventer(
	comm composable.DynamicProviderComm,
	cfg *Config,
	logger *logp.Logger,
	client k8s.Interface,
	scope string,
	managed bool) (Eventer, error) {
	watcher, err := kubernetes.NewNamedWatcher("agent-service", client, &kubernetes.Service{}, kubernetes.WatchOptions{
		SyncTimeout:  cfg.SyncPeriod,
		Node:         cfg.Node,
		HonorReSyncs: true,
	}, nil)
	if err != nil {
		return nil, errors.New(err, "couldn't create kubernetes watcher")
	}

	metaConf := metadata.GetDefaultResourceMetadataConfig()
	namespaceWatcher, err := kubernetes.NewNamedWatcher("agent-namespace", client, &kubernetes.Namespace{}, kubernetes.WatchOptions{
		SyncTimeout: cfg.SyncPeriod,
		Namespace:   cfg.Namespace,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't create watcher for %T due to error %w", &kubernetes.Namespace{}, err)
	}
	namespaceMeta := metadata.NewNamespaceMetadataGenerator(metaConf.Namespace, namespaceWatcher.Store(), client)

	rawConfig, err := config.NewConfigFrom(cfg)
	if err != nil {
		return nil, errors.New(err, "failed to unpack configuration")
	}

	metaGen := metadata.NewServiceMetadataGenerator(rawConfig, watcher.Store(), namespaceMeta, client)
	s := &service{
		logger,
		cfg.CleanupTimeout,
		comm,
		scope,
		cfg,
		metaGen,
		watcher,
		namespaceWatcher,
	}
	watcher.AddEventHandler(s)

	return s, nil
}

// Start starts the eventer
func (s *service) Start() error {
	if s.namespaceWatcher != nil {
		if err := s.namespaceWatcher.Start(); err != nil {
			return err
		}
	}
	return s.watcher.Start()
}

// Stop stops the eventer
func (s *service) Stop() {
	s.watcher.Stop()

	if s.namespaceWatcher != nil {
		s.namespaceWatcher.Stop()
	}
}

func (s *service) emitRunning(service *kubernetes.Service) {
	namespaceAnnotations := svcNamespaceAnnotations(service, s.namespaceWatcher)
	data := generateServiceData(service, s.metagen, namespaceAnnotations)
	if data == nil {
		return
	}
	data.mapping["scope"] = s.scope

	// Emit the service
	_ = s.comm.AddOrUpdate(string(service.GetUID()), ServicePriority, data.mapping, data.processors, nil)
}

// svcNamespaceAnnotations returns the annotations of the namespace of the service
func svcNamespaceAnnotations(svc *kubernetes.Service, watcher kubernetes.Watcher) mapstr.M {
	if watcher == nil {
		return nil
	}

	rawNs, ok, err := watcher.Store().GetByKey(svc.Namespace)
	if !ok || err != nil {
		return nil
	}

	namespace, ok := rawNs.(*kubernetes.Namespace)
	if !ok {
		return nil
	}

	annotations := mapstr.M{}
	for k, v := range namespace.GetAnnotations() {
		_ = safemapstr.Put(annotations, k, v)
	}
	return annotations
}

func (s *service) emitStopped(service *kubernetes.Service) {
	s.comm.Remove(string(service.GetUID()))
}

// OnAdd ensures processing of service objects that are newly created
func (s *service) OnAdd(obj interface{}) {
	s.logger.Debugf("Watcher Service add: %+v", obj)
	s.emitRunning(obj.(*kubernetes.Service))
}

// OnUpdate ensures processing of service objects that are updated
func (s *service) OnUpdate(obj interface{}) {
	service, _ := obj.(*kubernetes.Service)
	// Once service is in terminated state, mark it for deletion
	if service.GetObjectMeta().GetDeletionTimestamp() != nil {
		s.logger.Debugf("Watcher Service update (terminating): %+v", obj)
		time.AfterFunc(s.cleanupTimeout, func() { s.emitStopped(service) })
	} else {
		s.logger.Debugf("Watcher Node update: %+v", obj)
		s.emitRunning(service)
	}
}

// OnDelete ensures processing of service objects that are deleted
func (s *service) OnDelete(obj interface{}) {
	s.logger.Debugf("Watcher Service delete: %+v", obj)
	service, _ := obj.(*kubernetes.Service)
	time.AfterFunc(s.cleanupTimeout, func() { s.emitStopped(service) })
}

func generateServiceData(
	service *kubernetes.Service,
	kubeMetaGen metadata.MetaGen,
	namespaceAnnotations mapstr.M) *serviceData {
	host := service.Spec.ClusterIP

	// If a service doesn't have an IP then dont monitor it
	if host == "" {
		return nil
	}

	meta := kubeMetaGen.Generate(service)
	kubemetaMap, err := meta.GetValue("kubernetes")
	if err != nil {
		return &serviceData{}
	}

	// k8sMapping includes only the metadata that fall under kubernetes.*
	// and these are available as dynamic vars through the provider
	k8sMapping := map[string]interface{}(kubemetaMap.(mapstr.M).Clone())

	if len(namespaceAnnotations) != 0 {
		k8sMapping["namespace_annotations"] = namespaceAnnotations
	}
	// Pass annotations to all events so that it can be used in templating and by annotation builders.
	annotations := mapstr.M{}
	for k, v := range service.GetObjectMeta().GetAnnotations() {
		_ = safemapstr.Put(annotations, k, v)
	}

	// add annotations to be discoverable by templates
	k8sMapping["annotations"] = annotations

	processors := []map[string]interface{}{}
	// meta map includes metadata that go under kubernetes.*
	// but also other ECS fields like orchestrator.*
	for field, metaMap := range meta {
		processor := map[string]interface{}{
			"add_fields": map[string]interface{}{
				"fields": metaMap,
				"target": field,
			},
		}
		processors = append(processors, processor)
	}

	return &serviceData{
		service:    service,
		mapping:    k8sMapping,
		processors: processors,
	}
}
