// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetessecrets

import (
	"context"
	"fmt"
<<<<<<< HEAD
	"strings"
=======
	"runtime"
>>>>>>> 45e3abf15 (fix: disable kubernetes_secrets unit-test that relies on timing for windows platform (#6805))
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

<<<<<<< HEAD
func Test_K8sSecretsProvider_FetchWrongSecret(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	secret := &v1.Secret{
=======
	for _, tc := range []struct {
		name          string
		providerCfg   Config
		k8sClient     k8sclient.Interface
		storeInit     func(t *testing.T) store
		keyToFetch    string
		expectedValue string
		expectedFound bool
		expectedCache map[string]*cacheEntry
	}{
		{
			name: "invalid key format",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			storeInit:     func(t *testing.T) store { return newExpirationCache(time.Minute) },
			keyToFetch:    "secret_name",
			expectedValue: "",
			expectedFound: false,
			expectedCache: nil,
		},
		{
			name: "invalid key format missing tokens",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			storeInit:     func(t *testing.T) store { return newExpirationCache(time.Minute) },
			keyToFetch:    fmt.Sprintf("%s.default.secret_name", k8sSecretsProviderName),
			expectedValue: "",
			expectedFound: false,
			expectedCache: nil,
		},
		{
			name: "invalid key inside secret",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			storeInit:     func(t *testing.T) store { return newExpirationCache(time.Minute) },
			keyToFetch:    fmt.Sprintf("%s.default.secret_name.wrong", k8sSecretsProviderName),
			expectedValue: "",
			expectedFound: false,
			expectedCache: buildCacheMap(
				buildCacheEntry("default", "secret_name", "wrong", "", false, time.Now(), time.Now()),
			),
		},
		{
			name: "k8s client nil",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient:     nil,
			storeInit:     func(t *testing.T) store { return newExpirationCache(time.Minute) },
			keyToFetch:    testDataBuilder.getFetchKey(),
			expectedValue: "",
			expectedFound: false,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("", false, time.Now(), time.Now()),
			),
		},
		{
			name: "cache-disabled API-hit",
			providerCfg: Config{
				RequestTimeout: time.Second,
				DisableCache:   true,
			},
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			keyToFetch:    testDataBuilder.getFetchKey(),
			storeInit:     func(t *testing.T) store { return newExpirationCache(time.Minute) },
			expectedValue: "secret_value",
			expectedFound: true,
		},
		{
			name: "cache-disabled API-miss",
			providerCfg: Config{
				RequestTimeout: time.Second,
				DisableCache:   true,
			},
			k8sClient:     k8sfake.NewClientset(),
			keyToFetch:    testDataBuilder.getFetchKey(),
			storeInit:     func(t *testing.T) store { return newExpirationCache(time.Minute) },
			expectedValue: "",
			expectedFound: false,
		},
		{
			name: "cache-hit",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			keyToFetch: testDataBuilder.getFetchKey(),
			storeInit: func(t *testing.T) store {
				s := newExpirationCache(time.Minute)
				s.Lock()
				s.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
				)
				s.Unlock()
				return s
			},
			expectedValue: "secret_value",
			expectedFound: true,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
		{
			name: "cache-miss API-hit",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			keyToFetch:    testDataBuilder.getFetchKey(),
			storeInit:     func(t *testing.T) store { return newExpirationCache(time.Minute) },
			expectedValue: "secret_value",
			expectedFound: true,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
		{
			name: "cache-miss API-miss",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient:     k8sfake.NewClientset(),
			keyToFetch:    testDataBuilder.getFetchKey(),
			storeInit:     func(t *testing.T) store { return newExpirationCache(time.Minute) },
			expectedValue: "",
			expectedFound: false,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("", false, time.Now(), time.Now()),
			),
		},
		{
			name: "cache-miss contention with newer fetch",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient:  k8sfake.NewClientset(),
			keyToFetch: testDataBuilder.getFetchKey(),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				ms := newMockStore(t)
				ms.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					// when Fetch calls Get, we silently insert another secret with the same key
					// to simulate another fetch/cache update happening in parallel and thus test
					// that the AddConditionally in Fetch works as expected. We also mark it's last
					// access to one hour ago to check that Fetch always updates the lastAccess of
					// an existing item.
					key := args.Get(0).(string)
					exps.Lock()
					exps.items[key] = testDataBuilder.buildCacheEntry("value_from_cache", true, time.Now().Add(1*time.Hour), time.Now().Add(-time.Hour))
					exps.Unlock()
				}).Return(secret{}, false).Once()
				ms.On("AddConditionally", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					obj := args.Get(1).(secret)
					updateAccess := args.Get(2).(bool)
					condition := args.Get(3).(conditionFn)
					exps.AddConditionally(key, obj, updateAccess, condition)
				}).Once()
				listMock := ms.On("List")
				listMock.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listMock.Return(exps.List())
				}).Once()
				return ms
			},
			expectedValue: "value_from_cache",
			expectedFound: true,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("value_from_cache", true, time.Now(), time.Now()),
			),
		},
		{
			name: "cache-miss contention same value",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient:  k8sfake.NewClientset(),
			keyToFetch: testDataBuilder.getFetchKey(),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				ms := newMockStore(t)
				ms.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					// when Fetch calls Get, we silently insert another secret with the same key
					// to simulate another fetch/cache update happening in parallel and thus test
					// that the AddConditionally in Fetch works as expected. We also mark it's last
					// access to one hour ago to check that Fetch always updates the lastAccess of
					// an existing item.
					key := args.Get(0).(string)
					exps.Lock()
					exps.items[key] = testDataBuilder.buildCacheEntry("secret_value", true, time.Now().Add(1*time.Hour), time.Now().Add(-time.Hour))
					exps.Unlock()
				}).Return(secret{}, false).Once()
				ms.On("AddConditionally", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					obj := args.Get(1).(secret)
					updateAccess := args.Get(2).(bool)
					condition := args.Get(3).(conditionFn)
					exps.AddConditionally(key, obj, updateAccess, condition)
				}).Once()

				listMock := ms.On("List")
				listMock.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listMock.Return(exps.List())
				}).Once()
				return ms
			},
			expectedValue: "secret_value",
			expectedFound: true,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
		{
			name: "cache-miss contention with older fetch",
			providerCfg: Config{
				RequestTimeout: time.Second,
			},
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			keyToFetch: testDataBuilder.getFetchKey(),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				ms := newMockStore(t)
				ms.On("Get", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					// when Fetch calls Get, we silently insert another secret with the same key
					// to simulate another fetch/cache update happening in parallel and thus test
					// that the AddConditionally in Fetch works as expected. We also mark it's last
					// access to one hour ago to check that Fetch always updates the lastAccess of
					// an existing item.
					key := args.Get(0).(string)
					exps.Lock()
					exps.items[key] = testDataBuilder.buildCacheEntry("value_from_cache", true, time.Now(), time.Now().Add(-time.Hour))
					exps.Unlock()
				}).Return(secret{}, false).Once()
				ms.On("AddConditionally", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					obj := args.Get(1).(secret)
					updateAccess := args.Get(2).(bool)
					condition := args.Get(3).(conditionFn)
					exps.AddConditionally(key, obj, updateAccess, condition)
				}).Once()

				listMock := ms.On("List")
				listMock.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listMock.Return(exps.List())
				}).Once()
				return ms
			},
			expectedValue: "secret_value",
			expectedFound: true,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			running := make(chan struct{})
			close(running)
			p := contextProviderK8SSecrets{
				logger:  logp.NewLogger("test_k8s_secrets"),
				config:  &tc.providerCfg,
				client:  tc.k8sClient,
				running: running,
				store:   tc.storeInit(t),
			}

			val, found := p.Fetch(tc.keyToFetch)
			require.Equal(t, tc.expectedFound, found)
			require.Equal(t, tc.expectedValue, val)

			list := p.store.List()
			require.Equal(t, len(tc.expectedCache), len(list))

			cacheMap := make(map[string]secret)
			for _, s := range list {
				cacheMap[fmt.Sprintf("%s.%s.%s.%s", k8sSecretsProviderName, s.namespace, s.name, s.key)] = s
			}
			for k, v := range tc.expectedCache {
				inCache, exists := cacheMap[k]
				require.True(t, exists)
				require.Equal(t, v.s.key, inCache.key)
				require.Equal(t, v.s.name, inCache.name)
				require.Equal(t, v.s.namespace, inCache.namespace)
				require.Equal(t, v.s.key, inCache.key)
				require.Equal(t, v.s.value, inCache.value)
				require.Equal(t, v.s.apiExists, inCache.apiExists)
			}
		})
	}
}

func Test_UpdateCache(t *testing.T) {
	testDataBuilder := secretTestDataBuilder{
		namespace: "default",
		name:      "secret_name",
		key:       "secret_key",
	}

	for _, tc := range []struct {
		name           string
		providerCfg    Config
		k8sClient      k8sclient.Interface
		storeInit      func(t *testing.T) store
		expectedUpdate bool
		expectedCache  map[string]*cacheEntry
	}{
		{
			// check that cache returns true if a secret is expired
			name: "secret-expired",
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				exps.Lock()
				exps.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now().Add(-time.Hour)),
				)
				exps.Unlock()
				return exps
			},
			expectedUpdate: true,
		},
		{
			// check that cache returns false if there is no change in the secret
			name: "secret-no-change API-hit",
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				exps.Lock()
				exps.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
				)
				exps.Unlock()
				return exps
			},
			expectedUpdate: false,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
		{
			// check that cache returns true if there is a change in the secret
			name: "secret-change API-hit",
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value_new"),
			),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				exps.Lock()
				exps.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
				)
				exps.Unlock()
				return exps
			},
			expectedUpdate: true,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value_new", true, time.Now(), time.Now()),
			),
		},
		{
			// check that cache returns true if the API returns an error at refreshing of an existing secret
			name:      "secret-change API-miss",
			k8sClient: k8sfake.NewClientset(),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				exps.Lock()
				exps.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
				)
				exps.Unlock()
				return exps
			},
			expectedUpdate: true,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("", false, time.Now(), time.Now()),
			),
		},
		{
			// check that lastAccess is updated for expired secrets if they are updated
			name: "secret-expired with update",
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				exps.Lock()
				exps.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value_old", true, time.Now(), time.Now()),
				)
				exps.Unlock()
				ms := newMockStore(t)
				getMockCall := ms.On("Get", mock.Anything, mock.Anything)
				getMockCall.Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					ret, exists := exps.Get(key, args.Get(1).(bool))
					// when updateSecrets calls Get, we silently shift one hour back the lastAccess of an existing secret to test
					// that the AddConditionally in updateCache works as expected and that the lastAccess is updated
					exps.Lock()
					exps.items[key].lastAccess = time.Now().Add(-time.Hour)
					exps.Unlock()
					getMockCall.Return(ret, exists)
				}).Once()
				ms.On("AddConditionally", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					obj := args.Get(1).(secret)
					updateAccess := args.Get(2).(bool)
					condition := args.Get(3).(conditionFn)
					exps.AddConditionally(key, obj, updateAccess, condition)
				}).Once()
				listKeys := ms.On("ListKeys")
				listKeys.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listKeys.Return(exps.ListKeys())
				}).Once()
				listMock := ms.On("List")
				listMock.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listMock.Return(exps.List())
				}).Once()
				return ms
			},
			expectedUpdate: true,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
		{
			// check that lastAccess is not updated for expired secrets if they are not updated
			name: "secret-expired with no update",
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				exps.Lock()
				exps.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
				)
				exps.Unlock()
				ms := newMockStore(t)
				getMockCall := ms.On("Get", mock.Anything, mock.Anything)
				getMockCall.Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					ret, exists := exps.Get(key, args.Get(1).(bool))
					// when updateSecrets calls Get, we silently shift one hour back the lastAccess of an existing secret to test
					// that the AddConditionally in updateCache works as expected and that the lastAccess is not updated
					// if there is no update
					exps.Lock()
					exps.items[key].lastAccess = time.Now().Add(-time.Hour)
					exps.Unlock()
					getMockCall.Return(ret, exists)
				}).Once()
				ms.On("AddConditionally", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					obj := args.Get(1).(secret)
					updateAccess := args.Get(2).(bool)
					condition := args.Get(3).(conditionFn)
					exps.AddConditionally(key, obj, updateAccess, condition)
				}).Once()
				listKeys := ms.On("ListKeys")
				listKeys.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listKeys.Return(exps.ListKeys())
				}).Once()
				listMock := ms.On("List")
				listMock.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listMock.Return(exps.List())
				}).Once()
				return ms
			},
			expectedUpdate: false,
			expectedCache:  map[string]*cacheEntry{},
		},
		{
			// check that cache returns true if a secret is removed (aka expired) while it was being fetched from the API
			name:      "secret-change contention secret removed",
			k8sClient: k8sfake.NewClientset(),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				exps.Lock()
				exps.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
				)
				exps.Unlock()
				ms := newMockStore(t)
				getMockCall := ms.On("Get", mock.Anything, mock.Anything)
				getMockCall.Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					ret, exists := exps.Get(key, args.Get(1).(bool))
					// when updateSecrets calls Get, we silently remove an existing secret to test
					// that the AddConditionally in updateCache works as expected when the secret is removed
					exps.Lock()
					delete(exps.items, key)
					exps.Unlock()
					getMockCall.Return(ret, exists)
				}).Once()
				ms.On("AddConditionally", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					obj := args.Get(1).(secret)
					updateAccess := args.Get(2).(bool)
					condition := args.Get(3).(conditionFn)
					exps.AddConditionally(key, obj, updateAccess, condition)
				}).Once()
				listKeys := ms.On("ListKeys")
				listKeys.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listKeys.Return(exps.ListKeys())
				}).Once()
				listMock := ms.On("List")
				listMock.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listMock.Return(exps.List())
				}).Once()
				return ms
			},
			expectedUpdate: true,
			expectedCache:  nil,
		},
		{
			// check that cache returns false if a secret is more recently fetched from the API
			name: "secret-change contention with newer fetched item",
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			storeInit: func(t *testing.T) store {
				exps := newExpirationCache(time.Minute)
				exps.Lock()
				exps.items = buildCacheMap(
					testDataBuilder.buildCacheEntry("secret_value_cached", true, time.Now(), time.Now()),
				)
				exps.Unlock()
				ms := newMockStore(t)
				getMock := ms.On("Get", mock.Anything, mock.Anything)
				getMock.Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					ret, exists := exps.Get(key, args.Get(1).(bool))
					// when updateSecrets calls Get, we silently mark the existing secret to a newer fetch from API time
					// to test that the AddConditionally in updateCache works as expected
					exps.Lock()
					exps.items[key].s.apiFetchTime = time.Now().Add(time.Hour)
					exps.Unlock()
					getMock.Return(ret, exists)
				}).Once()
				ms.On("AddConditionally", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
					key := args.Get(0).(string)
					obj := args.Get(1).(secret)
					updateAccess := args.Get(2).(bool)
					condition := args.Get(3).(conditionFn)
					exps.AddConditionally(key, obj, updateAccess, condition)
				}).Once()
				listKeys := ms.On("ListKeys")
				listKeys.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listKeys.Return(exps.ListKeys())
				}).Once()
				listMock := ms.On("List")
				listMock.Run(func(args mock.Arguments) {
					// need to evaluate this at runtime
					listMock.Return(exps.List())
				}).Once()
				return ms
			},
			expectedUpdate: false,
			expectedCache: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value_cached", true, time.Now(), time.Now()),
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			running := make(chan struct{})
			close(running)
			p := contextProviderK8SSecrets{
				logger:  logp.NewLogger("test_k8s_secrets"),
				config:  &tc.providerCfg,
				client:  tc.k8sClient,
				running: running,
				store:   tc.storeInit(t),
			}

			hasUpdates := p.updateSecrets(context.Background())
			require.Equal(t, tc.expectedUpdate, hasUpdates)

			list := p.store.List()
			require.Equal(t, len(tc.expectedCache), len(list))

			cacheMap := make(map[string]secret)
			for _, s := range list {
				cacheMap[fmt.Sprintf("%s.%s.%s.%s", k8sSecretsProviderName, s.namespace, s.name, s.key)] = s
			}
			for k, v := range tc.expectedCache {
				inCache, exists := cacheMap[k]
				require.True(t, exists)
				require.Equal(t, v.s.key, inCache.key)
				require.Equal(t, v.s.name, inCache.name)
				require.Equal(t, v.s.namespace, inCache.namespace)
				require.Equal(t, v.s.key, inCache.key)
				require.Equal(t, v.s.value, inCache.value)
				require.Equal(t, v.s.apiExists, inCache.apiExists)
			}
		})
	}
}

func Test_Run(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Flaky timing on Windows")
	}

	testDataBuilder := secretTestDataBuilder{
		namespace: "default",
		name:      "secret_name",
		key:       "secret_key",
	}

	tests := []struct {
		name           string
		providerCfg    Config
		expectedSignal bool
		waitForSignal  time.Duration
		k8sClient      k8sclient.Interface
		k8sClientErr   error
		preCacheState  map[string]*cacheEntry
		postCacheState map[string]*cacheEntry
		secretToFetch  string
	}{
		{
			// check that the cache signals ContextComm when the secret is updated
			name: "secret-update-value and signal",
			providerCfg: Config{
				RefreshInterval: 100 * time.Millisecond,
				RequestTimeout:  100 * time.Millisecond,
				TTLDelete:       2 * time.Second,
				DisableCache:    false,
			},
			expectedSignal: true,
			waitForSignal:  time.Second,
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			k8sClientErr: nil,
			preCacheState: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value_old", true, time.Now(), time.Now()),
			),
			postCacheState: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
		{
			// check that the cache does not signal ContextComm when the secret is not updated
			name: "secret no-update and no-signal",
			providerCfg: Config{
				RefreshInterval: 100 * time.Millisecond,
				RequestTimeout:  100 * time.Millisecond,
				TTLDelete:       2 * time.Second,
				DisableCache:    false,
			},
			expectedSignal: false,
			waitForSignal:  time.Second,
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			k8sClientErr: nil,
			preCacheState: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
			postCacheState: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
		{
			// check that the cache signals ContextComm when a secret expires
			name: "secret-expired and signal",
			providerCfg: Config{
				RefreshInterval: 100 * time.Millisecond,
				RequestTimeout:  100 * time.Millisecond,
				TTLDelete:       500 * time.Millisecond,
				DisableCache:    false,
			},
			expectedSignal: true,
			waitForSignal:  time.Second,
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			k8sClientErr: nil,
			preCacheState: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
			postCacheState: nil,
		},
		{
			// check that the cache is populated when a fetch of a non-existing secret runs
			name: "fetch populates cache",
			providerCfg: Config{
				RefreshInterval: 100 * time.Millisecond,
				RequestTimeout:  100 * time.Millisecond,
				TTLDelete:       2 * time.Second,
				DisableCache:    false,
			},
			expectedSignal: false,
			waitForSignal:  time.Second,
			k8sClient: k8sfake.NewClientset(
				testDataBuilder.buildK8SSecret("secret_value"),
			),
			k8sClientErr:  nil,
			secretToFetch: fmt.Sprintf("%s.default.secret_name.secret_key", k8sSecretsProviderName),
			preCacheState: map[string]*cacheEntry{},
			postCacheState: buildCacheMap(
				testDataBuilder.buildCacheEntry("secret_value", true, time.Now(), time.Now()),
			),
		},
		{
			// check that Run returns an error when the k8s client fails to initialize
			name: "k8s client error",
			providerCfg: Config{
				RefreshInterval: 100 * time.Millisecond,
				RequestTimeout:  100 * time.Millisecond,
				TTLDelete:       2 * time.Second,
				DisableCache:    false,
			},
			k8sClient:    nil,
			k8sClientErr: errors.New("k8s client error"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getK8sClientFunc = func(kubeconfig string, opt kubernetes.KubeClientOptions) (k8sclient.Interface, error) {
				return tc.k8sClient, tc.k8sClientErr
			}
			t.Cleanup(func() {
				getK8sClientFunc = kubernetes.GetKubernetesClient
			})

			cfg, err := config.NewConfigFrom(tc.providerCfg)
			require.NoError(t, err)

			log := logp.NewLogger("test_k8s_secrets")
			provider, err := ContextProviderBuilder(log, cfg, true)
			require.NoError(t, err)

			p, is := provider.(*contextProviderK8SSecrets)
			require.True(t, is)

			ec, is := p.store.(*expirationCache)
			require.True(t, is)

			if tc.k8sClientErr != nil {
				require.Error(t, p.Run(context.Background(), ctesting.NewContextComm(context.Background())))
				return
			}

			ec.Lock()
			ec.items = tc.preCacheState
			ec.Unlock()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			comm := ctesting.NewContextComm(ctx)
			signal := make(chan struct{}, 10)
			comm.CallOnSignal(func() {
				select {
				case <-comm.Done():
				case signal <- struct{}{}:
				}
			})

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = p.Run(ctx, comm)
			}()

			<-p.running

			if tc.secretToFetch != "" {
				p.Fetch(tc.secretToFetch)
			}

			receivedSignal := false
			select {
			case <-signal:
				receivedSignal = true
			case <-time.After(tc.waitForSignal):
			}
			cancel()

			wg.Wait()

			require.Equal(t, tc.expectedSignal, receivedSignal)

			list := p.store.List()
			require.Equal(t, len(tc.postCacheState), len(list))

			cacheMap := make(map[string]secret)
			for _, s := range list {
				cacheMap[fmt.Sprintf("%s.%s.%s.%s", k8sSecretsProviderName, s.namespace, s.name, s.key)] = s
			}
			for k, v := range tc.postCacheState {
				inCache, exists := cacheMap[k]
				require.True(t, exists)
				require.Equal(t, v.s.key, inCache.key)
				require.Equal(t, v.s.name, inCache.name)
				require.Equal(t, v.s.namespace, inCache.namespace)
				require.Equal(t, v.s.key, inCache.key)
				require.Equal(t, v.s.value, inCache.value)
				require.Equal(t, v.s.apiExists, inCache.apiExists)
			}
		})
	}
}

func Test_Config(t *testing.T) {
	for _, tc := range []struct {
		name           string
		inConfig       map[string]interface{}
		expectedConfig *Config
		expectErr      bool
	}{
		{
			name:           "default config",
			inConfig:       nil,
			expectedConfig: defaultConfig(),
		},
		{
			name: "invalid config negative refresh interval",
			inConfig: map[string]interface{}{
				"cache_refresh_interval": -1,
			},
			expectErr: true,
		},
		{
			name: "invalid config zero refresh interval",
			inConfig: map[string]interface{}{
				"cache_refresh_interval": 0,
			},
			expectErr: true,
		},
		{
			name: "invalid config negative cache_request_timeout",
			inConfig: map[string]interface{}{
				"cache_request_timeout": -1,
			},
			expectErr: true,
		},
		{
			name: "invalid config zero cache_request_timeout",
			inConfig: map[string]interface{}{
				"cache_request_timeout": 0,
			},
			expectErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *config.Config
			var err error

			if tc.inConfig != nil {
				cfg, err = config.NewConfigFrom(tc.inConfig)
				require.NoError(t, err)
			}

			log := logp.NewLogger("test_k8s_secrets")
			provider, err := ContextProviderBuilder(log, cfg, true)
			if tc.expectErr {
				require.Error(t, err)
				return
			}

			p, is := provider.(*contextProviderK8SSecrets)
			require.True(t, is)
			require.Equal(t, tc.expectedConfig, p.config)
		})
	}
}

type secretTestDataBuilder struct {
	namespace string
	name      string
	key       string
}

func (b secretTestDataBuilder) buildCacheEntry(value string, exists bool, apiFetchTime time.Time, lastAccess time.Time) *cacheEntry {
	return buildCacheEntry(b.namespace, b.name, b.key, value, exists, apiFetchTime, lastAccess)
}

func (b secretTestDataBuilder) buildK8SSecret(value string) *v1.Secret {
	return buildK8SSecret(b.namespace, b.name, b.key, value)
}

func (b secretTestDataBuilder) getFetchKey() string {
	return fmt.Sprintf("%s.%s.%s.%s", k8sSecretsProviderName, b.namespace, b.name, b.key)
}

func buildSecret(namespace string, name string, key string, value string, exists bool, apiFetchTime time.Time) secret {
	return secret{
		name:         name,
		namespace:    namespace,
		key:          key,
		value:        value,
		apiExists:    exists,
		apiFetchTime: apiFetchTime,
	}
}

func buildCacheEntry(namespace string, name string, key string, value string, exists bool, apiFetchTime time.Time, lastAccess time.Time) *cacheEntry {
	return &cacheEntry{
		s:          buildSecret(namespace, name, key, value, exists, apiFetchTime),
		lastAccess: lastAccess,
	}
}

func buildCacheEntryKey(e *cacheEntry) string {
	return fmt.Sprintf("%s.%s.%s.%s", k8sSecretsProviderName, e.s.namespace, e.s.name, e.s.key)
}

func buildK8SSecret(namespace string, name string, key string, value string) *v1.Secret {
	return &v1.Secret{
>>>>>>> 45e3abf15 (fix: disable kubernetes_secrets unit-test that relies on timing for windows platform (#6805))
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
