// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetessecrets

import (
	"context"
	"fmt"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

const (
	ns   = "test_namespace"
	pass = "testing_passpass"
)

func Test_K8sSecretsProvider_Fetch(t *testing.T) {
	logger := logp.NewLogger("test_k8s_secrets")
	cfg, err := config.NewConfigFrom(map[string]string{"a": "b"})
	require.NoError(t, err)

	p, err := ContextProviderBuilder(logger, cfg, true)
	require.NoError(t, err)

	fp, ok := p.(*contextProviderK8sSecrets)
	require.True(t, ok, "cannot cast ContextProvider into contextProviderK8sSecrets")

	// Use a fake reader provider that will handle requests for the fake ns
	fp.k8sReaderProvider = newFakeReaderProvider().WithReader(
		ns,
		fake.NewFakeClient(
			&v1.Secret{
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
			},
		),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)

	go func() {
		_ = fp.Run(ctx, comm)
	}()

	val, found := fp.Fetch("kubernetes_secrets.test_namespace.testing_secret.secret_value")
	assert.True(t, found)
	assert.Equal(t, val, pass)
}

func Test_K8sSecretsProvider_FetchWrongSecret(t *testing.T) {
	logger := logp.NewLogger("test_k8s_secrets")
	cfg, err := config.NewConfigFrom(map[string]string{"a": "b"})
	require.NoError(t, err)

	p, err := ContextProviderBuilder(logger, cfg, true)
	require.NoError(t, err)

	fp, _ := p.(*contextProviderK8sSecrets)

	// Use a fake reader provider that will handle requests for the fake ns
	fp.k8sReaderProvider = newFakeReaderProvider().WithReader(
		ns,
		fake.NewFakeClient(
			&v1.Secret{
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
			},
		),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	comm := ctesting.NewContextComm(ctx)

	go func() {
		_ = fp.Run(ctx, comm)
	}()

	val, found := fp.Fetch("kubernetes_secrets.test_namespace.testing_secretHACK.secret_value")
	assert.False(t, found)
	assert.EqualValues(t, val, "")
}

// -- Fixtures

type fakeReaderProvider struct {
	readers map[string]client.Reader
}

var _ k8sReaderProvider = &fakeReaderProvider{}

func newFakeReaderProvider() *fakeReaderProvider {
	return &fakeReaderProvider{
		readers: make(map[string]client.Reader),
	}
}

func (f *fakeReaderProvider) WithReader(namespace string, r client.Reader) *fakeReaderProvider {
	f.readers[namespace] = r
	return f
}

func (f *fakeReaderProvider) getReader(namespace string) (client.Reader, error) {
	reader, exists := f.readers[namespace]
	if !exists {
		return nil, fmt.Errorf("no reader for namespace %s", namespace)
	}
	return reader, nil
}
