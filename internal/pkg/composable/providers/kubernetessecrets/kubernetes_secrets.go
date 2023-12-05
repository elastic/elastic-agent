// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
func ContextProviderBuilder(logger *logger.Logger, c *config.Config, managed bool) (corecomp.ContextProvider, error) {
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
	return p.getFromCache(key)
}

// Run initializes the k8s secrets context provider.
func (p *contextProviderK8sSecrets) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	client, err := getK8sClientFunc(p.config.KubeConfig, p.config.KubeClientOptions)
	if err != nil {
		p.logger.Debugf("Kubernetes_secrets provider skipped, unable to connect: %s", err)
		return nil
	}
	p.clientMx.Lock()
	p.client = client
	p.clientMx.Unlock()
	go p.updateSecrets(ctx)

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
func (p *contextProviderK8sSecrets) updateSecrets(ctx context.Context) {
	timer := time.NewTimer(p.config.RefreshInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			p.updateCache()
			timer.Reset(p.config.RefreshInterval)
		}
	}
}

func (p *contextProviderK8sSecrets) updateCache() {
	// deleting entries does not free the memory, so we need to create a new map
	// to place the secrets we want to keep
	cacheTmp := make(map[string]*secretsData)

	p.secretsCacheMx.RLock()
	for name, data := range p.secretsCache {
		diff := time.Since(data.lastAccess)
		if diff < p.config.TTLDelete {
			value, ok := p.fetchSecretWithTimeout(name)
			if ok {
				newData := &secretsData{
					value:      value,
					lastAccess: data.lastAccess,
				}
				cacheTmp[name] = newData
			}

		}
	}
	p.secretsCacheMx.RUnlock()

	p.secretsCacheMx.Lock()
	p.secretsCache = cacheTmp
	p.secretsCacheMx.Unlock()
}

func (p *contextProviderK8sSecrets) getFromCache(key string) (string, bool) {
	p.secretsCacheMx.RLock()
	_, ok := p.secretsCache[key]
	p.secretsCacheMx.RUnlock()

	// if value is still not present in cache, it is possible we haven't tried to fetch it yet
	if !ok {
		data, ok := p.addToCache(key)
		// if it was not possible to fetch the secret, return
		if !ok {
			return data.value, ok
		}
	}

	var pass string
	p.secretsCacheMx.Lock()
	data, ok := p.secretsCache[key]
	data.lastAccess = time.Now()
	pass = data.value
	p.secretsCacheMx.Unlock()
	return pass, ok
}

func (p *contextProviderK8sSecrets) addToCache(key string) (secretsData, bool) {
	// Make sure the key has the expected format "kubernetes_secrets.somenamespace.somesecret.value"
	tokens := strings.Split(key, ".")
	if len(tokens) > 0 && tokens[0] != "kubernetes_secrets" {
		return secretsData{
			value: "",
		}, false
	}
	if len(tokens) != 4 {
		p.logger.Debugf(
			"not valid secret key: %v. Secrets should be of the following format %v",
			key,
			"kubernetes_secrets.somenamespace.somesecret.value",
		)
		return secretsData{
			value: "",
		}, false
	}

	value, ok := p.fetchSecretWithTimeout(key)
	data := secretsData{
		value: value,
	}
	if ok {
		p.secretsCacheMx.Lock()
		p.secretsCache[key] = &data
		p.secretsCacheMx.Unlock()
	}
	return data, ok
}

type Result struct {
	value string
	ok    bool
}

func (p *contextProviderK8sSecrets) fetchSecretWithTimeout(key string) (string, bool) {
	ctxTimeout, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()

	resultCh := make(chan Result, 1)
	go p.fetchSecret(ctxTimeout, key, resultCh)

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
