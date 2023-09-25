// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetessecrets

import (
	"context"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var _ corecomp.FetchContextProvider = (*contextProviderK8sSecrets)(nil)

func init() {
	composable.Providers.MustAddContextProvider("kubernetes_secrets", ContextProviderBuilder)
}

type contextProviderK8sSecrets struct {
	logger *logger.Logger
	config *Config

	clientMx sync.Mutex

	k8sCacheProvider cacheProvider

	// readers holds a set of cached K8S reader per namespace.
	// We restrict each cache to watch only 1 namespace. Watching all the namespaces would consume a lot of memory
	// when we probably want to watch a very limited set of Secrets.
	readers map[string]client.Reader

	// ctx is the context used to start the informers. Informers will be stopped once the context is done.
	ctx context.Context
}

type cacheProvider interface {
	new(cfg *Config, namespace string) (cache.Cache, error)
}

type defaultCacheProvider struct{}

func (dcp defaultCacheProvider) new(cfg *Config, namespace string) (cache.Cache, error) {
	restConfig, err := kubernetes.BuildConfig(cfg.KubeConfig)
	if err != nil {
		return nil, err
	}
	if cfg.KubeClientOptions.QPS > 0 {
		restConfig.QPS = cfg.KubeClientOptions.QPS
	}
	if cfg.KubeClientOptions.Burst > 0 {
		restConfig.Burst = cfg.KubeClientOptions.Burst
	}
	return cache.New(restConfig, cache.Options{
		DefaultNamespaces: map[string]cache.Config{namespace: {}},
	})
}

// getReader returns a cached client associated to a given Kubernetes namespace.
func (p *contextProviderK8sSecrets) getReader(namespace string) (client.Reader, error) {
	p.clientMx.Lock()
	defer p.clientMx.Unlock()
	reader, exist := p.readers[namespace]
	if !exist {
		p.logger.Infof(
			"Create new cached reader for namespace %s",
			namespace,
		)
		newReader, err := p.k8sCacheProvider.new(p.config, namespace)
		if err != nil {
			return nil, err
		}
		p.readers[namespace] = newReader
		reader = newReader
		go func() {
			if err := newReader.Start(p.ctx); err != nil {
				p.logger.Errorf("Could not start K8S client: %v", err)
			}
		}()
		// Wait for the cache to be initialized.
		newReader.WaitForCacheSync(p.ctx)
	}
	return reader, nil
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(logger *logger.Logger, c *config.Config, _ bool) (corecomp.ContextProvider, error) {
	var cfg Config
	if c == nil {
		c = config.New()
	}
	if err := c.Unpack(&cfg); err != nil {
		return nil, errors.New(err, "failed to unpack configuration")
	}
	contextProviderK8sSecrets := &contextProviderK8sSecrets{
		readers:          make(map[string]client.Reader),
		k8sCacheProvider: &defaultCacheProvider{},
		logger:           logger,
		config:           &cfg,
	}
	return contextProviderK8sSecrets, nil
}

func (p *contextProviderK8sSecrets) Fetch(key string) (string, bool) {
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
	reader, err := p.getReader(ns)
	if err != nil {
		p.logger.Errorf("Could not create K8S client: %v", err)
		return "", false
	}
	secretName := tokens[2]
	secretVar := tokens[3]

	secret := corev1.Secret{}
	if err := reader.Get(context.TODO(), client.ObjectKey{Namespace: ns, Name: secretName}, &secret); err != nil {
		if k8serrors.IsNotFound(err) {
			p.logger.Errorf("Secret %s/%s not found: %v", ns, secretName, err)
			return "", false
		}
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

// Run initializes the k8s secrets context provider.
func (p *contextProviderK8sSecrets) Run(_ context.Context, comm corecomp.ContextProviderComm) error {
	p.ctx = comm
	<-comm.Done()
	return comm.Err()
}
