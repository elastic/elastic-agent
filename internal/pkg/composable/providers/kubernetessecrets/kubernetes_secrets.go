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

var (
	_                corecomp.FetchContextProvider = (*contextProviderK8SSecrets)(nil)
	getK8sClientFunc                               = kubernetes.GetKubernetesClient
)

func init() {
	composable.Providers.MustAddContextProvider("kubernetes_secrets", ContextProviderBuilder)
}

type store interface {
	// AddConditionally adds the given secret to the store if the given condition returns true. If there is no existing
	// secret, the condition will be called with an empty secret and false. If updateAccess is true and the secret already exists,
	// then the lastAccess timestamp is updated to time.Now() independently of the condition result.
	AddConditionally(key string, sd secret, updateAccess bool, cond conditionFn)
	// ListKeys returns a list of all the keys of the secrets in the store without checking for expiration
	ListKeys() []string
	// List returns a list of all the secrets in the store that are not expired
	List() []secret
	// Get returns the secret associated with the given key from the store if it exists and is not expired. If updateAccess is true
	// and the secret exists, essentially the expiration check is skipped and the lastAccess timestamp is updated to time.Now().
	Get(key string, updateAccess bool) (secret, bool)
}

// secret represents the data of a kubernetes secret that is stored in the cache
type secret struct {
	// name is the name of the secret, and it derives from key
	name string
	// namespace is the name of the namespace, and it derives from key
	namespace string
	// key is the key inside the secret, and it derives from key
	key string
	// value is the value of key inside the secret
	value string
	// apiExists is true if the secret was fetched from the API with no errors
	apiExists bool
	// apiFetchTime is the time the secret was fetched from the API
	apiFetchTime time.Time
}

type conditionFn func(existing secret, exists bool) bool

type contextProviderK8SSecrets struct {
	logger    *logger.Logger
	config    *Config
	client    k8sclient.Interface
	clientMtx sync.RWMutex
	running   chan struct{}
	store     store
}

// ContextProviderBuilder builds the kubernetes_secrets context provider. By default, this provider employs a cache
// to reduce the number of requests to the API server. The cache refreshes the secrets referenced during each Fetch call
// every Config.RefreshInterval. To maintain only secrets that are actually needed by the agent, each secret reference
// expires based on the Config.TTLDelete. During expiration of secret references or actual changes of secret values,
// the kubernetes_secrets provider calls the ContextProviderComm.Signal() to notify the agent. The cache mechanism
// can be disabled by setting Config.DisableCache to true.
func ContextProviderBuilder(logger *logger.Logger, c *config.Config, _ bool) (corecomp.ContextProvider, error) {
	cfg := defaultConfig()

	if c == nil {
		c = config.New()
	}

	err := c.UnpackTo(cfg)
	if err != nil {
		return nil, errors.New(err, "failed to unpack configuration")
	}
	return &contextProviderK8SSecrets{
		logger:  logger,
		config:  cfg,
		client:  nil,
		running: make(chan struct{}),
		store:   newExpirationCache(cfg.TTLDelete),
	}, nil
}

// Run initializes the k8s secrets context provider.
func (p *contextProviderK8SSecrets) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	client, err := getK8sClientFunc(p.config.KubeConfig, p.config.KubeClientOptions)
	if err != nil {
		// signal that the provider has initialized
		close(p.running)
		p.logger.Debug("kubernetes_secrets provider skipped, unable to connect: ", err.Error())
		return err
	}
	p.clientMtx.Lock()
	p.client = client
	p.clientMtx.Unlock()

	if !p.config.DisableCache {
		go p.refreshCache(ctx, comm)
	}

	// signal that the provider has initialized
	close(p.running)
	<-comm.Done()

	p.clientMtx.Lock()
	p.client = nil
	p.clientMtx.Unlock()

	return comm.Err()
}

// Fetch returns the secret value for the given key
func (p *contextProviderK8SSecrets) Fetch(key string) (string, bool) {
	// Make sure the key has the expected format "kubernetes_secrets.somenamespace.somesecret.value"
	tokens := strings.Split(key, ".")
	if len(tokens) > 0 && tokens[0] != "kubernetes_secrets" {
		return "", false
	}
	if len(tokens) != 4 {
		p.logger.Warn("Invalid secret key format: ", key, ". Secrets should be of the format kubernetes_secrets.namespace.secret_name.value")
		return "", false
	}

	ctx := context.Background()

	secretNamespace := tokens[1]
	secretName := tokens[2]
	secretKey := tokens[3]

	// Wait for the provider to be initialized
	<-p.running

	if p.config.DisableCache {
		// cache disabled - fetch secret from the API
		return p.fetchFromAPI(ctx, secretName, secretNamespace, secretKey)
	}

	// cache enabled
	sd, exists := p.store.Get(key, true)
	if exists {
		// cache hit
		return sd.value, sd.apiExists
	}

	// cache miss - fetch secret from the API
	apiSecretValue, apiExists := p.fetchFromAPI(ctx, secretName, secretNamespace, secretKey)
	now := time.Now()
	sd = secret{
		name:         secretName,
		namespace:    secretNamespace,
		key:          secretKey,
		value:        apiSecretValue,
		apiExists:    apiExists,
		apiFetchTime: now,
	}
	p.store.AddConditionally(key, sd, true, func(existing secret, exists bool) bool {
		if !exists {
			// no existing secret in the cache thus add it
			return true
		}
		if existing.value != apiSecretValue && !existing.apiFetchTime.After(now) {
			// there is an existing secret in the cache but its value has changed since the last time
			// it was fetched from the API thus update it
			return true
		}
		// there is an existing secret in the cache, and it points already to the latest value
		// thus do not update it and derive the value and apiExists from the existing secret
		apiSecretValue = existing.value
		apiExists = existing.apiExists
		return false
	})
	return apiSecretValue, apiExists
}

// refreshCache refreshes the secrets in the cache every p.config.RefreshInterval
func (p *contextProviderK8SSecrets) refreshCache(ctx context.Context, comm corecomp.ContextProviderComm) {
	timer := time.NewTimer(p.config.RefreshInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			hasUpdate := p.updateSecrets(ctx)
			if hasUpdate {
				p.logger.Info("Secrets cache was updated, the agent will be notified.")
				comm.Signal()
			}
			timer.Reset(p.config.RefreshInterval)
		}
	}
}

// updateSecrets causes all the non-expired secrets to be re-fetched from the API server and returns true if
// any of the secrets an updated value or has expired
func (p *contextProviderK8SSecrets) updateSecrets(ctx context.Context) bool {
	// Keep track whether the cache had updates
	hasUpdates := false

	secretKeys := p.store.ListKeys()
	for _, key := range secretKeys {
		sd, exists := p.store.Get(key, false)
		if !exists {
			// this item has expired thus mark that the cache has updates and continue
			hasUpdates = true
			continue
		}

		apiSecretValue, apiExists := p.fetchFromAPI(ctx, sd.name, sd.namespace, sd.key)
		now := time.Now()
		sd = secret{
			name:         sd.name,
			namespace:    sd.namespace,
			key:          sd.key,
			value:        apiSecretValue,
			apiExists:    apiExists,
			apiFetchTime: now,
		}

		p.store.AddConditionally(key, sd, false, func(existing secret, exists bool) bool {
			if !exists {
				// no existing secret which means it has been removed until we fetched it
				// from the API. In this case we do not want to update the cache, but we
				// mark that the cache has updates
				hasUpdates = true
				return false
			}
			if existing.value != apiSecretValue && !existing.apiFetchTime.After(now) {
				// the secret value has changed and the above fetchFromAPI is more recent thus
				// add it and mark that the cache has updates
				hasUpdates = true
				return true
			}
			// the secret value has not changed
			return false
		})
	}

	return hasUpdates
}

// fetchFromAPI fetches the secret value from the API
func (p *contextProviderK8SSecrets) fetchFromAPI(ctx context.Context, secretName string, secretNamespace string, secretKey string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, p.config.RequestTimeout)
	defer cancel()

	p.clientMtx.RLock()
	if p.client == nil {
		// k8s client is nil most probably due to an error at p.Run
		p.clientMtx.RUnlock()
		return "", false
	}
	c := p.client
	p.clientMtx.RUnlock()

	si := c.CoreV1().Secrets(secretNamespace)
	secret, err := si.Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		p.logger.Warn("Could not retrieve secret ", secretName, " at namespace ", secretNamespace, ": ", err.Error())
		return "", false
	}

	if _, ok := secret.Data[secretKey]; !ok {
		p.logger.Warn("Could not retrieve value of key ", secretKey, " for secret ", secretName, " at namespace ", secretNamespace)
		return "", false
	}

	return string(secret.Data[secretKey]), true
}
