// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetes

import (
	"fmt"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-autodiscover/utils"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	c "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/safemapstr"

	k8s "k8s.io/client-go/kubernetes"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
)

const (
	processorhints = "hints/processors"
)

type pod struct {
	watcher           kubernetes.Watcher
	nodeWatcher       kubernetes.Watcher
	comm              composable.DynamicProviderComm
	metagen           metadata.MetaGen
	namespaceWatcher  kubernetes.Watcher
	replicasetWatcher kubernetes.Watcher
	jobWatcher        kubernetes.Watcher
	config            *Config
	logger            *logp.Logger
	scope             string
	managed           bool
	cleanupTimeout    time.Duration

	// Mutex used by configuration updates not triggered by the main watcher,
	// to avoid race conditions between cross updates and deletions.
	// Other updaters must use a write lock.
	crossUpdate sync.RWMutex
}

type providerData struct {
	uid        string
	mapping    map[string]interface{}
	processors []map[string]interface{}
}

// Will hold the generated mapping data needed for hints based autodsicovery
type hintsData struct {
	composableMapping mapstr.M
	processors        []mapstr.M
}

// NewPodEventer creates an eventer that can discover and process pod objects
func NewPodEventer(
	comm composable.DynamicProviderComm,
	cfg *Config,
	logger *logp.Logger,
	client k8s.Interface,
	scope string,
	managed bool) (Eventer, error) {
	watcher, err := kubernetes.NewNamedWatcher("agent-pod", client, &kubernetes.Pod{}, kubernetes.WatchOptions{
		SyncTimeout:  cfg.SyncPeriod,
		Node:         cfg.Node,
		Namespace:    cfg.Namespace,
		HonorReSyncs: true,
	}, nil)
	if err != nil {
		return nil, errors.New(err, "couldn't create kubernetes watcher")
	}

	var replicaSetWatcher, jobWatcher kubernetes.Watcher

	options := kubernetes.WatchOptions{
		SyncTimeout: cfg.SyncPeriod,
		Node:        cfg.Node,
	}
	metaConf := cfg.AddResourceMetadata

	nodeWatcher, err := kubernetes.NewNamedWatcher("agent-node", client, &kubernetes.Node{}, options, nil)
	if err != nil {
		logger.Errorf("couldn't create watcher for %T due to error %+v", &kubernetes.Node{}, err)
	}
	namespaceWatcher, err := kubernetes.NewNamedWatcher("agent-namespace", client, &kubernetes.Namespace{}, kubernetes.WatchOptions{
		SyncTimeout: cfg.SyncPeriod,
	}, nil)
	if err != nil {
		logger.Errorf("couldn't create watcher for %T due to error %+v", &kubernetes.Namespace{}, err)
	}

	// Resource is Pod so we need to create watchers for Replicasets and Jobs that it might belong to
	// in order to be able to retrieve 2nd layer Owner metadata like in case of:
	// Deployment -> Replicaset -> Pod
	// CronJob -> job -> Pod
	if metaConf.Deployment {
		replicaSetWatcher, err = kubernetes.NewNamedWatcher("resource_metadata_enricher_rs", client, &kubernetes.ReplicaSet{}, kubernetes.WatchOptions{
			SyncTimeout: cfg.SyncPeriod,
		}, nil)
		if err != nil {
			logger.Errorf("Error creating watcher for %T due to error %+v", &kubernetes.Namespace{}, err)
		}
	}
	if metaConf.CronJob {
		jobWatcher, err = kubernetes.NewNamedWatcher("resource_metadata_enricher_job", client, &kubernetes.Job{}, kubernetes.WatchOptions{
			SyncTimeout: cfg.SyncPeriod,
		}, nil)
		if err != nil {
			logger.Errorf("Error creating watcher for %T due to error %+v", &kubernetes.Job{}, err)
		}
	}

	rawConfig, err := c.NewConfigFrom(cfg)
	if err != nil {
		return nil, errors.New(err, "failed to unpack configuration")
	}
	metaGen := metadata.GetPodMetaGen(rawConfig, watcher, nodeWatcher, namespaceWatcher, replicaSetWatcher, jobWatcher, metaConf)

	p := &pod{
		logger:            logger,
		cleanupTimeout:    cfg.CleanupTimeout,
		comm:              comm,
		scope:             scope,
		config:            cfg,
		metagen:           metaGen,
		watcher:           watcher,
		nodeWatcher:       nodeWatcher,
		namespaceWatcher:  namespaceWatcher,
		replicasetWatcher: replicaSetWatcher,
		jobWatcher:        jobWatcher,
		managed:           managed,
	}

	watcher.AddEventHandler(p)

	if nodeWatcher != nil && metaConf.Node.Enabled() {
		updater := kubernetes.NewNodePodUpdater(p.unlockedUpdate, watcher.Store(), &p.crossUpdate)
		nodeWatcher.AddEventHandler(updater)
	}

	if namespaceWatcher != nil && metaConf.Namespace.Enabled() {
		updater := kubernetes.NewNamespacePodUpdater(p.unlockedUpdate, watcher.Store(), &p.crossUpdate)
		namespaceWatcher.AddEventHandler(updater)
	}

	return p, nil
}

// Start starts the eventer
func (p *pod) Start() error {
	if p.nodeWatcher != nil {
		err := p.nodeWatcher.Start()
		if err != nil {
			return err
		}
	}

	if p.namespaceWatcher != nil {
		if err := p.namespaceWatcher.Start(); err != nil {
			return err
		}
	}

	if p.replicasetWatcher != nil {
		if err := p.replicasetWatcher.Start(); err != nil {
			return err
		}
	}

	if p.jobWatcher != nil {
		if err := p.jobWatcher.Start(); err != nil {
			return err
		}
	}

	return p.watcher.Start()
}

// Stop stops the eventer
func (p *pod) Stop() {
	p.watcher.Stop()

	if p.namespaceWatcher != nil {
		p.namespaceWatcher.Stop()
	}

	if p.nodeWatcher != nil {
		p.nodeWatcher.Stop()
	}

	if p.replicasetWatcher != nil {
		p.replicasetWatcher.Stop()
	}

	if p.jobWatcher != nil {
		p.jobWatcher.Stop()
	}
}

func (p *pod) emitRunning(pod *kubernetes.Pod) {

	namespaceAnnotations := kubernetes.PodNamespaceAnnotations(pod, p.namespaceWatcher)

	data := generatePodData(pod, p.metagen, namespaceAnnotations)
	data.mapping["scope"] = p.scope

	if p.config.Hints.Enabled { // This is "hints based autodiscovery flow"
		if !p.managed {
			if ann, ok := data.mapping["annotations"]; ok {
				annotations, _ := ann.(mapstr.M)
				hints := utils.GenerateHints(annotations, "", p.config.Prefix)
				if len(hints) > 0 {
					p.logger.Debugf("Extracted hints are :%v", hints)
					hintsMapping := GenerateHintsMapping(hints, data.mapping, p.logger, "")
					p.logger.Debugf("Generated Pods' hints mappings are :%v", hintsMapping)
					_ = p.comm.AddOrUpdate(
						data.uid,
						PodPriority,
						map[string]interface{}{"hints": hintsMapping},
						data.processors,
					)
				}
			}
		}
	} else { // This is the "template-based autodiscovery" flow
		// emit normal mapping to be used in dynamic variable resolution
		// Emit the pod
		// We emit Pod + containers to ensure that configs matching Pod only
		// get Pod metadata (not specific to any container)
		_ = p.comm.AddOrUpdate(data.uid, PodPriority, data.mapping, data.processors)
	}

	// Emit all containers in the pod
	// We should deal with init containers stopping after initialization
	p.emitContainers(pod, namespaceAnnotations)
}

func (p *pod) emitContainers(pod *kubernetes.Pod, namespaceAnnotations mapstr.M) {
	generateContainerData(p.comm, pod, p.metagen, namespaceAnnotations, p.logger, p.managed, p.config)
}

func (p *pod) emitStopped(pod *kubernetes.Pod) {
	p.comm.Remove(string(pod.GetUID()))

	for _, c := range pod.Spec.Containers {
		// ID is the combination of pod UID + container name
		eventID := fmt.Sprintf("%s.%s", pod.GetObjectMeta().GetUID(), c.Name)
		p.comm.Remove(eventID)
	}

	for _, c := range pod.Spec.InitContainers {
		// ID is the combination of pod UID + container name
		eventID := fmt.Sprintf("%s.%s", pod.GetObjectMeta().GetUID(), c.Name)
		p.comm.Remove(eventID)
	}
}

// OnAdd ensures processing of pod objects that are newly added
func (p *pod) OnAdd(obj interface{}) {
	p.crossUpdate.RLock()
	defer p.crossUpdate.RUnlock()

	p.logger.Debugf("pod add: %+v", obj)
	p.emitRunning(obj.(*kubernetes.Pod))
}

// OnUpdate emits events for a given pod depending on the state of the pod,
// if it is terminating, a stop event is scheduled, if not, a stop and a start
// events are sent sequentially to recreate the resources assotiated to the pod.
func (p *pod) OnUpdate(obj interface{}) {
	p.crossUpdate.RLock()
	defer p.crossUpdate.RUnlock()

	p.unlockedUpdate(obj)
}

func (p *pod) unlockedUpdate(obj interface{}) {
	p.logger.Debugf("Watcher Pod update: %+v", obj)
	pod, _ := obj.(*kubernetes.Pod)
	p.emitRunning(pod)
}

// OnDelete stops pod objects that are deleted
func (p *pod) OnDelete(obj interface{}) {
	p.crossUpdate.RLock()
	defer p.crossUpdate.RUnlock()

	p.logger.Debugf("pod delete: %+v", obj)
	pod, _ := obj.(*kubernetes.Pod)
	time.AfterFunc(p.cleanupTimeout, func() {
		p.emitStopped(pod)
	})
}

func generatePodData(
	pod *kubernetes.Pod,
	kubeMetaGen metadata.MetaGen,
	namespaceAnnotations mapstr.M) providerData {

	meta := kubeMetaGen.Generate(pod)
	kubemetaMap, err := meta.GetValue("kubernetes")
	if err != nil {
		return providerData{}
	}

	// k8sMapping includes only the metadata that fall under kubernetes.*
	// and these are available as dynamic vars through the provider
	k8sMapping := map[string]interface{}(kubemetaMap.(mapstr.M).Clone())

	if len(namespaceAnnotations) != 0 {
		k8sMapping["namespace_annotations"] = namespaceAnnotations
	}
	// Pass annotations to all events so that it can be used in templating and by annotation builders.
	annotations := mapstr.M{}
	for k, v := range pod.GetObjectMeta().GetAnnotations() {
		_ = safemapstr.Put(annotations, k, v)
	}
	k8sMapping["annotations"] = annotations
	// Pass labels(not dedoted) to all events so that they can be used in templating.
	labels := mapstr.M{}
	for k, v := range pod.GetObjectMeta().GetLabels() {
		_ = safemapstr.Put(labels, k, v)
	}
	k8sMapping["labels"] = labels

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

	return providerData{
		uid:        string(pod.GetUID()),
		mapping:    k8sMapping,
		processors: processors,
	}
}

func generateContainerData(
	comm composable.DynamicProviderComm,
	pod *kubernetes.Pod,
	kubeMetaGen metadata.MetaGen,
	namespaceAnnotations mapstr.M,
	logger *logp.Logger,
	managed bool,
	config *Config) {

	containers := kubernetes.GetContainersInPod(pod)

	// Pass annotations to all events so that it can be used in templating and by annotation builders.
	annotations := mapstr.M{}
	for k, v := range pod.GetObjectMeta().GetAnnotations() {
		_ = safemapstr.Put(annotations, k, v)
	}

	// Pass labels to all events so that it can be used in templating.
	labels := mapstr.M{}
	for k, v := range pod.GetObjectMeta().GetLabels() {
		_ = safemapstr.Put(labels, k, v)
	}

	for _, c := range containers {
		// If it doesn't have an ID, container doesn't exist in
		// the runtime, emit only an event if we are stopping, so
		// we are sure of cleaning up configurations.
		if c.ID == "" {
			continue
		}

		// ID is the combination of pod UID + container name
		eventID := fmt.Sprintf("%s.%s", pod.GetObjectMeta().GetUID(), c.Spec.Name)

		meta := kubeMetaGen.Generate(pod, metadata.WithFields("container.name", c.Spec.Name))
		kubemetaMap, err := meta.GetValue("kubernetes")
		if err != nil {
			continue
		}

		// k8sMapping includes only the metadata that fall under kubernetes.*
		// and these are available as dynamic vars through the provider
		k8sMapping := map[string]interface{}(kubemetaMap.(mapstr.M).Clone())

		if len(namespaceAnnotations) != 0 {
			k8sMapping["namespace_annotations"] = namespaceAnnotations
		}
		// add annotations and labels to be discoverable by templates
		k8sMapping["annotations"] = annotations
		k8sMapping["labels"] = labels

		//container ECS fields
		cmeta := mapstr.M{
			"id":      c.ID,
			"runtime": c.Runtime,
			"image": mapstr.M{
				"name": c.Spec.Image,
			},
		}

		processors := []map[string]interface{}{
			{
				"add_fields": map[string]interface{}{
					"fields": cmeta,
					"target": "container",
				},
			},
		}
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

		// add container metadata under kubernetes.container.* to
		// make them available to dynamic var resolution

		containerMeta := mapstr.M{
			"id":      c.ID,
			"name":    c.Spec.Name,
			"image":   c.Spec.Image,
			"runtime": c.Runtime,
		}

		if len(c.Spec.Ports) > 0 {
			for _, port := range c.Spec.Ports {
				_, _ = containerMeta.Put("port", fmt.Sprintf("%v", port.ContainerPort))
				_, _ = containerMeta.Put("port_name", port.Name)
				k8sMapping["container"] = containerMeta

				if config.Hints.Enabled { // This is "hints based autodiscovery flow"
					if !managed {
						hintData := GetHintsMapping(k8sMapping, logger, config.Prefix, c.ID)
						if len(hintData.composableMapping) > 0 {
							if len(hintData.processors) > 0 {
								processors = updateProcessors(hintData.processors, processors)
							}
							_ = comm.AddOrUpdate(
								eventID,
								PodPriority,
								map[string]interface{}{"hints": hintData.composableMapping},
								processors,
							)
						} else if config.Hints.DefaultContainerLogs {
							// in case of no package detected in the hints fallback to the generic log collection
							_, _ = hintData.composableMapping.Put("container_logs.enabled", true)
							_, _ = hintData.composableMapping.Put("container_id", c.ID)
							if len(hintData.processors) > 0 {
								processors = updateProcessors(hintData.processors, processors)
							}
							_ = comm.AddOrUpdate(
								eventID,
								PodPriority,
								map[string]interface{}{"hints": hintData.composableMapping},
								processors,
							)
						}
					}
				} else { // This is the "template-based autodiscovery" flow
					_ = comm.AddOrUpdate(eventID, ContainerPriority, k8sMapping, processors)
				}
			}
		} else {
			k8sMapping["container"] = containerMeta
			if config.Hints.Enabled { // This is "hints based autodiscovery flow"
				if !managed {
					hintData := GetHintsMapping(k8sMapping, logger, config.Prefix, c.ID)
					if len(hintData.composableMapping) > 0 {
						if len(hintData.processors) > 0 {
							processors = updateProcessors(hintData.processors, processors)
						}
						_ = comm.AddOrUpdate(
							eventID,
							PodPriority,
							map[string]interface{}{"hints": hintData.composableMapping},
							processors,
						)
					} else if config.Hints.DefaultContainerLogs {
						// in case of no package detected in the hints fallback to the generic log collection
						_, _ = hintData.composableMapping.Put("container_logs.enabled", true)
						_, _ = hintData.composableMapping.Put("container_id", c.ID)
						if len(hintData.processors) > 0 {
							processors = updateProcessors(hintData.processors, processors)
						}
						_ = comm.AddOrUpdate(
							eventID,
							PodPriority,
							map[string]interface{}{"hints": hintData.composableMapping},
							processors,
						)
					}
				}
			} else { // This is the "template-based autodiscovery" flow
				_ = comm.AddOrUpdate(eventID, ContainerPriority, k8sMapping, processors)
			}
		}
	}
}

// Updates processors map with any additional processors identfied from annotations
func updateProcessors(newprocessors []mapstr.M, processors []map[string]interface{}) []map[string]interface{} {
	for _, processor := range newprocessors {
		processors = append(processors, processor)
	}

	return processors
}
