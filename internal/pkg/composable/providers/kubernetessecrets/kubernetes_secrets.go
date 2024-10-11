// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetessecrets

import (
	"context"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var _ corecomp.FetchContextProvider = (*contextProviderK8sSecrets)(nil)
var getK8sClientFunc = getK8sClient

func init() {
	composable.Providers.MustAddContextProvider("kubernetes_secrets", ContextProviderBuilder)
}

type contextProviderK8sSecrets struct {
	logger *logger.Logger
	config *Config

	clientMx sync.Mutex
	client   k8sclient.Interface

	secretsCacheMx sync.RWMutex
	secretsCache   map[string]*secretsData
}

type secretsData struct {
	value      string
	lastAccess time.Time
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(logger *logger.Logger, c *config.Config, _ bool) (corecomp.ContextProvider, error) {
	var cfg Config
	if c == nil {
		c = config.New()
	}
	err := c.Unpack(&cfg)
	if err != nil {
		return nil, errors.New(err, "failed to unpack configuration")
	}
	return &contextProviderK8sSecrets{
		logger:       logger,
		config:       &cfg,
		secretsCache: make(map[string]*secretsData),
	}, nil
}

func (p *contextProviderK8sSecrets) Fetch(key string) (string, bool) {
	if p.config.DisableCache {
		valid := p.validateKey(key)
		if valid {
			return p.fetchSecretWithTimeout(key)
		} else {
			return "", false
		}
	} else {
		return p.getFromCache(key)
	}
}

// Run initializes the k8s secrets context provider.
func (p *contextProviderK8sSecrets) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	client, err := getK8sClientFunc(p.config.KubeConfig, p.config.KubeClientOptions)
	if err != nil {
		p.logger.Debugf("kubernetes_secrets provider skipped, unable to connect: %s", err)
		return nil
	}
	p.clientMx.Lock()
	p.client = client
	p.clientMx.Unlock()

	if !p.config.DisableCache {
		go p.updateSecrets(ctx, comm)
	}

	<-comm.Done()

	p.clientMx.Lock()
	p.client = nil
	p.clientMx.Unlock()
	return comm.Err()
}

func getK8sClient(kubeconfig string, opt kubernetes.KubeClientOptions) (k8sclient.Interface, error) {
	return kubernetes.GetKubernetesClient(kubeconfig, opt)
}

// Update the secrets in the cache every RefreshInterval
func (p *contextProviderK8sSecrets) updateSecrets(ctx context.Context, comm corecomp.ContextProviderComm) {
	timer := time.NewTimer(p.config.RefreshInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			updatedCache := p.updateCache()
			if updatedCache {
				p.logger.Info("Secrets cache was updated, the agent will be notified.")
				comm.Signal()
			}
			timer.Reset(p.config.RefreshInterval)
		}
	}
}

// mergeWithCurrent merges the updated map with the cache map.
// This function needs to be called between the mutex lock for the map.
func (p *contextProviderK8sSecrets) mergeWithCurrent(updatedMap map[string]*secretsData) (map[string]*secretsData, bool) {
	merged := make(map[string]*secretsData)
	updatedCache := false

	for name, data := range p.secretsCache {
		diff := time.Since(data.lastAccess)
		if diff < p.config.TTLDelete {
			merged[name] = data
			// Check if this key is part of the updatedMap. If it is not, we know the secrets cache was updated,
			// and we need to signal that.
			_, ok := updatedMap[name]
			if !ok {
				updatedCache = true
			}
		}
	}

	for name, data := range updatedMap {
		// We need to check if the key is already in the new map. If it is, lastAccess cannot be overwritten since
		// it could have been updated when trying to fetch the secret at the same time we are running update cache.
		// In that case, we only update the value.
		if _, ok := merged[name]; ok {
			if merged[name].value != data.value {
				merged[name].value = data.value
				updatedCache = true
			}
		}
	}

	return merged, updatedCache
}

func (p *contextProviderK8sSecrets) updateCache() bool {
	// Keep track whether the cache had values changing, so we can notify the agent
	updatedCache := false

	// deleting entries does not free the memory, so we need to create a new map
	// to place the secrets we want to keep
	cacheTmp := make(map[string]*secretsData)

	// to not hold the lock for long, we copy the current state of the cache map
	copyMap := make(map[string]secretsData)
	p.secretsCacheMx.RLock()
	for name, data := range p.secretsCache {
		copyMap[name] = *data
	}
	p.secretsCacheMx.RUnlock()

	// The only way to update an entry in the cache is through the last access time (to delete the key)
	// or if the value gets updated.
	for name, data := range copyMap {
		diff := time.Since(data.lastAccess)
		if diff < p.config.TTLDelete {
			value, ok := p.fetchSecretWithTimeout(name)
			if ok {
				newData := &secretsData{
					value:      value,
					lastAccess: data.lastAccess,
				}
				cacheTmp[name] = newData
				if value != data.value {
					updatedCache = true
				}
			}
		} else {
			updatedCache = true
		}
	}

	// While the cache was updated, it is possible that some secret was added through another go routine.
	// We need to merge the updated map with the current cache map to catch the new entries and avoid
	// loss of data.
	var updated bool
	p.secretsCacheMx.Lock()
	p.secretsCache, updated = p.mergeWithCurrent(cacheTmp)
	p.secretsCacheMx.Unlock()

	return updatedCache || updated
}

func (p *contextProviderK8sSecrets) getFromCache(key string) (string, bool) {
	p.secretsCacheMx.RLock()
	_, ok := p.secretsCache[key]
	p.secretsCacheMx.RUnlock()

	// if value is still not present in cache, it is possible we haven't tried to fetch it yet
	if !ok {
		value, ok := p.addToCache(key)
		// if it was not possible to fetch the secret, return
		if !ok {
			return value, ok
		}
	}

	p.secretsCacheMx.Lock()
	data, ok := p.secretsCache[key]
	data.lastAccess = time.Now()
	pass := data.value
	p.secretsCacheMx.Unlock()

	return pass, ok
}

func (p *contextProviderK8sSecrets) validateKey(key string) bool {
	// Make sure the key has the expected format "kubernetes_secrets.somenamespace.somesecret.value"
	tokens := strings.Split(key, ".")
	if len(tokens) > 0 && tokens[0] != "kubernetes_secrets" {
		return false
	}
	if len(tokens) != 4 {
		p.logger.Debugf(
			"not valid secret key: %v. Secrets should be of the following format %v",
			key,
			"kubernetes_secrets.somenamespace.somesecret.value",
		)
		return false
	}
	return true
}

func (p *contextProviderK8sSecrets) addToCache(key string) (string, bool) {
	valid := p.validateKey(key)
	if !valid {
		return "", false
	}

	value, ok := p.fetchSecretWithTimeout(key)
	if ok {
		p.secretsCacheMx.Lock()
		p.secretsCache[key] = &secretsData{value: value}
		p.secretsCacheMx.Unlock()
	}
	return value, ok
}

type Result struct {
	value string
	ok    bool
}

func (p *contextProviderK8sSecrets) fetchSecretWithTimeout(key string) (string, bool) {
	ctxTimeout, cancel := context.WithTimeout(context.Background(), p.config.RequestTimeout)
	defer cancel()

	resultCh := make(chan Result, 1)
	p.fetchSecret(ctxTimeout, key, resultCh)

	select {
	case <-ctxTimeout.Done():
		p.logger.Errorf("Could not retrieve value for key %v: %v", key, ctxTimeout.Err())
		return "", false
	case result := <-resultCh:
		return result.value, result.ok
	}
}

func (p *contextProviderK8sSecrets) fetchSecret(context context.Context, key string, resultCh chan Result) {
	p.clientMx.Lock()
	client := p.client
	p.clientMx.Unlock()
	if client == nil {
		resultCh <- Result{value: "", ok: false}
		return
	}

	tokens := strings.Split(key, ".")
	// key has the format "kubernetes_secrets.somenamespace.somesecret.value"
	// This function is only called from:
	// - addToCache, where we already validated that the key has the right format.
	// - updateCache, where the results are only added to the cache through addToCache
	// Because of this we no longer need to validate the key
	ns := tokens[1]
	secretName := tokens[2]
	secretVar := tokens[3]

	secretInterface := client.CoreV1().Secrets(ns)
	secret, err := secretInterface.Get(context, secretName, metav1.GetOptions{})

	if err != nil {
		p.logger.Errorf("Could not retrieve secret from k8s API: %v", err)
		resultCh <- Result{value: "", ok: false}
		return
	}
	if _, ok := secret.Data[secretVar]; !ok {
		p.logger.Errorf("Could not retrieve value %v for secret %v", secretVar, secretName)
		resultCh <- Result{value: "", ok: false}
		return
	}

	secretString := secret.Data[secretVar]
	resultCh <- Result{value: string(secretString), ok: true}
}
