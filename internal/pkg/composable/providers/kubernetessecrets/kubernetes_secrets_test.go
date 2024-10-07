// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetessecrets

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

const (
	ns   = "test_namespace"
	pass = "testing_passpass"
)

func Test_K8sSecretsProvider_FetchWrongSecret(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "apps/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing_secret",
			Namespace: ns,
		},
		Data: map[string][]byte{
			"secret_value": []byte(pass),
		},
	}
	_, err := client.CoreV1().Secrets(ns).Create(context.Background(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	logger := logp.NewLogger("test_k8s_secrets")
	cfg, err := config.NewConfigFrom(map[string]string{"a": "b"})
	require.NoError(t, err)

	p, err := ContextProviderBuilder(logger, cfg, true)
	require.NoError(t, err)

	fp, _ := p.(*contextProviderK8sSecrets)

	getK8sClientFunc = func(kubeconfig string, opt kubernetes.KubeClientOptions) (k8sclient.Interface, error) {
		return client, nil
	}
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)

	go func() {
		_ = fp.Run(ctx, comm)
	}()

	for {
		fp.clientMx.Lock()
		client := fp.client
		fp.clientMx.Unlock()
		if client != nil {
			break
		}
		<-time.After(10 * time.Millisecond)
	}

	val, found := fp.Fetch("kubernetes_secrets.test_namespace.testing_secretHACK.secret_value")
	assert.False(t, found)
	assert.EqualValues(t, val, "")
}

func Test_K8sSecretsProvider_Fetch_Cache_Enabled(t *testing.T) {
	client := k8sfake.NewSimpleClientset()

	ttlDelete, err := time.ParseDuration("1s")
	require.NoError(t, err)

	refreshInterval, err := time.ParseDuration("100ms")
	require.NoError(t, err)

	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "apps/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing_secret",
			Namespace: ns,
		},
		Data: map[string][]byte{
			"secret_value": []byte(pass),
		},
	}
	_, err = client.CoreV1().Secrets(ns).Create(context.Background(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	logger := logp.NewLogger("test_k8s_secrets")

	c := map[string]interface{}{
		"cache_refresh_interval": refreshInterval,
		"cache_ttl":              ttlDelete,
		"cache_disable":          false,
	}
	cfg, err := config.NewConfigFrom(c)
	require.NoError(t, err)

	p, err := ContextProviderBuilder(logger, cfg, true)
	require.NoError(t, err)

	fp, _ := p.(*contextProviderK8sSecrets)

	getK8sClientFunc = func(kubeconfig string, opt kubernetes.KubeClientOptions) (k8sclient.Interface, error) {
		return client, nil
	}
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)

	go func() {
		_ = fp.Run(ctx, comm)
	}()

	for {
		fp.clientMx.Lock()
		client := fp.client
		fp.clientMx.Unlock()
		if client != nil {
			break
		}
		<-time.After(10 * time.Millisecond)
	}

	// Secret cache should be empty at start
	fp.secretsCacheMx.Lock()
	assert.Equal(t, 0, len(fp.secretsCache))
	fp.secretsCacheMx.Unlock()

	key := "kubernetes_secrets.test_namespace.testing_secret.secret_value"

	// Secret should be in the cache after this call
	val, found := fp.Fetch(key)
	assert.True(t, found)
	assert.Equal(t, val, pass)
	fp.secretsCacheMx.RLock()
	assert.Equal(t, len(fp.secretsCache), 1)
	assert.NotNil(t, fp.secretsCache[key])
	assert.NotZero(t, fp.secretsCache[key].lastAccess)
	fp.secretsCacheMx.RUnlock()

	// Update the secret and check after TTL time, the secret value is correct
	newPass := "new-pass"
	secret = &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "apps/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing_secret",
			Namespace: ns,
		},
		Data: map[string][]byte{
			"secret_value": []byte(newPass),
		},
	}
	_, err = client.CoreV1().Secrets(ns).Update(context.Background(), secret, metav1.UpdateOptions{})
	require.NoError(t, err)

	// wait for ttl update
	<-time.After(refreshInterval)
	status := &strings.Builder{}
	duration := refreshInterval * 3
	assert.Eventuallyf(t, func() bool {
		val, found = fp.Fetch(key)
		isNewPass := val == newPass
		if found && isNewPass {
			return true
		}

		fmt.Fprintf(status, "found: %t, isNewPass: %t", found, isNewPass)
		return false
	}, duration, refreshInterval,
		"Failed to update the secret value after TTL update has passed. Tried fetching for %d. Last status: %s",
		duration, status)

	// After TTL delete, secret should no longer be found in cache since it was never
	// fetched during that time
	<-time.After(ttlDelete)
	assert.Eventuallyf(t, func() bool {
		fp.secretsCacheMx.RLock()
		size := len(fp.secretsCache)
		fp.secretsCacheMx.RUnlock()
		return size == 0
	}, ttlDelete*3, ttlDelete, "Failed to delete the secret after TTL delete has passed.")

}

func Test_K8sSecretsProvider_Fetch_Cache_Disabled(t *testing.T) {
	client := k8sfake.NewSimpleClientset()

	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "apps/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing_secret",
			Namespace: ns,
		},
		Data: map[string][]byte{
			"secret_value": []byte(pass),
		},
	}
	_, err := client.CoreV1().Secrets(ns).Create(context.Background(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	logger := logp.NewLogger("test_k8s_secrets")

	c := map[string]interface{}{
		"cache_disable": true,
	}
	cfg, err := config.NewConfigFrom(c)
	require.NoError(t, err)

	p, err := ContextProviderBuilder(logger, cfg, true)
	require.NoError(t, err)

	fp, _ := p.(*contextProviderK8sSecrets)

	getK8sClientFunc = func(kubeconfig string, opt kubernetes.KubeClientOptions) (k8sclient.Interface, error) {
		return client, nil
	}
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)

	go func() {
		_ = fp.Run(ctx, comm)
	}()

	for {
		fp.clientMx.Lock()
		client := fp.client
		fp.clientMx.Unlock()
		if client != nil {
			break
		}
		<-time.After(10 * time.Millisecond)
	}

	key := "kubernetes_secrets.test_namespace.testing_secret.secret_value"

	// Secret should be in the cache after this call
	val, found := fp.Fetch(key)
	assert.True(t, found)
	assert.Equal(t, val, pass)

	// Update the secret and check the result
	newPass := "new-pass"
	secret = &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "apps/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing_secret",
			Namespace: ns,
		},
		Data: map[string][]byte{
			"secret_value": []byte(newPass),
		},
	}
	_, err = client.CoreV1().Secrets(ns).Update(context.Background(), secret, metav1.UpdateOptions{})
	require.NoError(t, err)

	val, found = fp.Fetch(key)
	assert.True(t, found)
	assert.Equal(t, val, newPass)

	// Check key that does not exist
	val, found = fp.Fetch(key + "doesnotexist")
	assert.False(t, found)
	assert.Equal(t, "", val)
}

func Test_MergeWitchCurrent(t *testing.T) {
	logger := logp.NewLogger("test_k8s_secrets")

	c := map[string]interface{}{}
	cfg, err := config.NewConfigFrom(c)
	require.NoError(t, err)

	p, err := ContextProviderBuilder(logger, cfg, true)
	require.NoError(t, err)

	fp, _ := p.(*contextProviderK8sSecrets)

	ts := time.Now()
	var tests = []struct {
		secretsCache map[string]*secretsData
		updatedMap   map[string]*secretsData
		mergedMap    map[string]*secretsData
		updatedCache bool
		message      string
	}{
		{
			secretsCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
			},
			updatedMap: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one-updated",
					lastAccess: ts,
				},
			},
			mergedMap: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one-updated",
					lastAccess: ts,
				},
			},
			updatedCache: true,
			message:      "When the value of one of the keys in the map gets updated, updatedCache should be true.",
		},
		{
			secretsCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
			},
			updatedMap: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
			},
			mergedMap: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
			},
			updatedCache: false,
			message:      "When nothing changes in the cache, updatedCache should be false.",
		},
		{
			secretsCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
				"kubernetes_secrets.default.secret_two.secret_value": {
					value:      "value-two",
					lastAccess: ts,
				},
			},
			updatedMap: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
			},
			mergedMap: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
				"kubernetes_secrets.default.secret_two.secret_value": {
					value:      "value-two",
					lastAccess: ts,
				},
			},
			updatedCache: true,
			message: "When secretsCache gets updated at the same time we create updatedMap, then merging the two should" +
				"detect the change on updatedCache.",
		},
	}

	for _, test := range tests {
		fp.secretsCache = test.secretsCache
		merged, updated := fp.mergeWithCurrent(test.updatedMap)

		require.Equalf(t, len(test.mergedMap), len(merged), "Resulting merged map does not have the expected length.")
		for key, data1 := range test.mergedMap {
			data2, ok := merged[key]
			if ok {
				require.Equalf(t, data1.value, data2.value, "Resulting merged map values do not equal the expected ones.")
				require.Equalf(t, data1.lastAccess, data2.lastAccess, "Resulting merged map values do not equal the expected ones.")
			} else {
				t.Fatalf("Resulting merged map does not have expecting keys.")
			}
		}

		require.Equalf(t, test.updatedCache, updated, test.message)
	}
}

func Test_UpdateCache(t *testing.T) {
	logger := logp.NewLogger("test_k8s_secrets")

	c := map[string]interface{}{}
	cfg, err := config.NewConfigFrom(c)
	require.NoError(t, err)

	p, err := ContextProviderBuilder(logger, cfg, true)
	require.NoError(t, err)

	fp, _ := p.(*contextProviderK8sSecrets)

	ts := time.Now()

	client := k8sfake.NewSimpleClientset()
	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "apps/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret_one",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"secret_value": []byte(pass),
		},
	}
	_, err = client.CoreV1().Secrets("default").Create(context.Background(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	fp.client = client

	var tests = []struct {
		secretsCache  map[string]*secretsData
		expectedCache map[string]*secretsData
		updatedCache  bool
		message       string
	}{
		{
			secretsCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
			},
			expectedCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      pass,
					lastAccess: ts,
				},
			},
			updatedCache: true,
			message:      "When last access is still within the limits, values should be updated.",
		},
		{
			secretsCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts.Add(-fp.config.TTLDelete - time.Minute),
				},
			},
			expectedCache: map[string]*secretsData{},
			updatedCache:  true,
			message:       "When last access is no longer within the limits, the data should be deleted.",
		},
		{
			secretsCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      pass,
					lastAccess: ts,
				},
			},
			expectedCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      pass,
					lastAccess: ts,
				},
			},
			updatedCache: false,
			message:      "When the values did not change and last access is still within limits, no update happens.",
		},
	}

	for _, test := range tests {
		fp.secretsCache = test.secretsCache
		updated := fp.updateCache()

		require.Equalf(t, len(test.expectedCache), len(fp.secretsCache), "Resulting updated map does not have the expected length.")
		for key, data1 := range test.expectedCache {
			data2, ok := fp.secretsCache[key]
			if ok {
				require.Equalf(t, data1.value, data2.value, "Resulting updating map values do not equal the expected ones.")
				require.Equalf(t, data1.lastAccess, data2.lastAccess, "Resulting updated map values do not equal the expected ones.")
			} else {
				t.Fatalf("Resulting updated map does not have expecting keys.")
			}
		}

		require.Equalf(t, test.updatedCache, updated, test.message)
	}

}

func Test_Signal(t *testing.T) {
	// The signal should get triggered every time there is an update on the cache
	logger := logp.NewLogger("test_k8s_secrets")

	client := k8sfake.NewSimpleClientset()

	secret := &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "apps/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret_one",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"secret_value": []byte(pass),
		},
	}
	_, err := client.CoreV1().Secrets("default").Create(context.Background(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	refreshInterval, err := time.ParseDuration("100ms")
	require.NoError(t, err)

	c := map[string]interface{}{
		"cache_refresh_interval": refreshInterval,
	}
	cfg, err := config.NewConfigFrom(c)
	require.NoError(t, err)

	p, err := ContextProviderBuilder(logger, cfg, true)
	require.NoError(t, err)

	fp, _ := p.(*contextProviderK8sSecrets)
	fp.client = client

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)

	signalTriggered := new(bool)
	*signalTriggered = false
	var lock sync.RWMutex

	comm.CallOnSignal(func() {
		lock.Lock()
		*signalTriggered = true
		lock.Unlock()
	})

	go fp.updateSecrets(ctx, comm)

	ts := time.Now()

	var tests = []struct {
		secretsCache map[string]*secretsData
		updated      bool
		message      string
	}{
		{
			secretsCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      "value-one",
					lastAccess: ts,
				},
			},
			updated: true,
			message: "Value of secret should be updated and signal should be triggered.",
		},
		{
			secretsCache: map[string]*secretsData{
				"kubernetes_secrets.default.secret_one.secret_value": {
					value:      pass,
					lastAccess: ts,
				},
			},
			updated: false,
			message: "Value of secret should not be updated and signal should not be triggered.",
		},
	}

	for _, test := range tests {
		fp.secretsCacheMx.Lock()
		fp.secretsCache = test.secretsCache
		fp.secretsCacheMx.Unlock()

		// wait for cache to be updated
		<-time.After(fp.config.RefreshInterval)

		assert.Eventuallyf(t, func() bool {
			lock.RLock()
			defer lock.RUnlock()
			return *signalTriggered == test.updated
		}, fp.config.RefreshInterval*3, fp.config.RefreshInterval, test.message)

		lock.Lock()
		*signalTriggered = false
		lock.Unlock()
	}

}
