// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetessecrets

import (
	"context"
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

func Test_K8sSecretsProvider_Fetch(t *testing.T) {
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

	val, found := fp.Fetch("kubernetes_secrets.test_namespace.testing_secret.secret_value")
	assert.True(t, found)
	assert.Equal(t, val, pass)
}

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

func Test_K8sSecretsProvider_Check_TTL(t *testing.T) {
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
		"refresh_interval": refreshInterval,
		"ttl_delete":       ttlDelete,
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
	assert.Eventuallyf(t, func() bool {
		val, found = fp.Fetch(key)
		return found && val == newPass
	}, refreshInterval*3, refreshInterval, "Failed to update the secret value after TTL update has passed.")

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
