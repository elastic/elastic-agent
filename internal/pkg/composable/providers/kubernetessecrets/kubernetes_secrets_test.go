// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetessecrets

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/logp"
	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func Test_Fetch(t *testing.T) {
	testDataBuilder := secretTestDataBuilder{
		namespace: "default",
		name:      "secret_name",
		key:       "secret_key",
	}

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
			keyToFetch:    "kubernetes_secrets.default.secret_name",
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
			keyToFetch:    "kubernetes_secrets.default.secret_name.wrong",
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
				cacheMap[fmt.Sprintf("kubernetes_secrets.%s.%s.%s", s.namespace, s.name, s.key)] = s
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
				cacheMap[fmt.Sprintf("kubernetes_secrets.%s.%s.%s", s.namespace, s.name, s.key)] = s
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
			secretToFetch: "kubernetes_secrets.default.secret_name.secret_key",
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
				cacheMap[fmt.Sprintf("kubernetes_secrets.%s.%s.%s", s.namespace, s.name, s.key)] = s
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
	return fmt.Sprintf("kubernetes_secrets.%s.%s.%s", b.namespace, b.name, b.key)
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
	return fmt.Sprintf("kubernetes_secrets.%s.%s.%s", e.s.namespace, e.s.name, e.s.key)
}

func buildK8SSecret(namespace string, name string, key string, value string) *v1.Secret {
	return &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "apps/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			key: []byte(value),
		},
	}
}

func buildCacheMap(entry ...*cacheEntry) map[string]*cacheEntry {
	cache := make(map[string]*cacheEntry)

	for _, e := range entry {
		cache[buildCacheEntryKey(e)] = e
	}

	return cache
}
