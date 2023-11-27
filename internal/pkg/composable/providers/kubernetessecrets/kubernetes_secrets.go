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

	secretsCacheMx sync.Mutex
	secretsCache   map[string]secretsData
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
		secretsCache: make(map[string]secretsData),
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

// Update the secrets in the cache every TTL minutes
func (p *contextProviderK8sSecrets) updateSecrets(ctx context.Context) {
	timer := time.NewTimer(p.config.TTLUpdate)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			p.updateCache()
			timer.Reset(p.config.TTLUpdate)
		}
	}
}

func (p *contextProviderK8sSecrets) updateCache() {
	p.secretsCacheMx.Lock()
	for name, data := range p.secretsCache {
		diff := time.Since(data.lastAccess)
		if diff > p.config.TTLDelete {
			delete(p.secretsCache, name)
		} else {
			newValue, ok := p.fetchSecret(name)
			if !ok {
				delete(p.secretsCache, name)
			} else {
				data.value = newValue
			}
		}
	}
	p.secretsCacheMx.Unlock()
}

func (p *contextProviderK8sSecrets) getFromCache(key string) (string, bool) {
	p.secretsCacheMx.Lock()
	_, ok := p.secretsCache[key]
	p.secretsCacheMx.Unlock()

	// if value is still not present in cache, it is possible we haven't tried to fetch it yet
	if !ok {
		data, ok := p.addToCache(key)
		// if it was not possible to fetch the secret, return
		if !ok {
			return data.value, ok
		}
	}

	p.secretsCacheMx.Lock()
	data, ok := p.secretsCache[key]
	data.lastAccess = time.Now()
	p.secretsCacheMx.Unlock()

	return data.value, ok
}

func (p *contextProviderK8sSecrets) addToCache(key string) (secretsData, bool) {
	value, ok := p.fetchSecret(key)
	data := secretsData{
		value: value,
	}
	if ok {
		p.secretsCacheMx.Lock()
		p.secretsCache[key] = data
		p.secretsCacheMx.Unlock()
	}
	return data, ok
}

func (p *contextProviderK8sSecrets) fetchSecret(key string) (string, bool) {
	p.clientMx.Lock()
	client := p.client
	p.clientMx.Unlock()
	if client == nil {
		return "", false
	}

	// key = "kubernetes_secrets.somenamespace.somesecret.value"
	tokens := strings.Split(key, ".")
	if len(tokens) > 0 && tokens[0] != "kubernetes_secrets" {
		return "", false
	}
	if len(tokens) != 4 {
		p.logger.Debugf(
			"not valid secret key: %v. Secrets should be of the following format %v",
			key,
			"kubernetes_secrets.somenamespace.somesecret.value",
		)
		return "", false
	}
	ns := tokens[1]
	secretName := tokens[2]
	secretVar := tokens[3]

	secretIntefrace := client.CoreV1().Secrets(ns)
	ctx := context.TODO()
	secret, err := secretIntefrace.Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		p.logger.Errorf("Could not retrieve secret from k8s API: %v", err)
		return "", false
	}
	if _, ok := secret.Data[secretVar]; !ok {
		p.logger.Errorf("Could not retrieve value %v for secret %v", secretVar, secretName)
		return "", false
	}
	secretString := secret.Data[secretVar]

	return string(secretString), true
}
