// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package util

import (
	"context"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/go-sysinfo"
	"github.com/elastic/go-sysinfo/types"
)

// GetHostName returns the host's FQDN if the FDQN feature flag is enabled; otherwise, it
// returns the OS-provided hostname.
func GetHostName(isFqdnFeatureEnabled bool, hostInfo types.HostInfo, host types.Host, log *logger.Logger) string {
	if !isFqdnFeatureEnabled {
		return hostInfo.Hostname
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	fqdn, err := host.FQDNWithContext(ctx)
	if err != nil {
		// If we are unable to lookup the FQDN, we fallback to the OS-provided hostname
		log.Debugf("unable to lookup FQDN: %s, using hostname = %s", err.Error(), hostInfo.Hostname)
		return hostInfo.Hostname
	}

	return fqdn
}

var _ types.Host = &threadSafeHost{}

// threadSafeHost is a thread-safe wrapper around types.Host.
// It exists so we can only create it once, as some of the setup it does is relatively expensive.
type threadSafeHost struct {
	sync.Mutex
	inner types.Host
}

func newThreadSafeHost(inner types.Host) *threadSafeHost {
	return &threadSafeHost{inner: inner}
}

func (s *threadSafeHost) CPUTime() (types.CPUTimes, error) {
	s.Lock()
	defer s.Unlock()
	return s.inner.CPUTime()
}

func (s *threadSafeHost) Info() types.HostInfo {
	s.Lock()
	defer s.Unlock()
	return s.inner.Info()
}

func (s *threadSafeHost) Memory() (*types.HostMemoryInfo, error) {
	s.Lock()
	defer s.Unlock()
	return s.inner.Memory()
}

func (s *threadSafeHost) FQDNWithContext(ctx context.Context) (string, error) {
	s.Lock()
	defer s.Unlock()
	return s.inner.FQDNWithContext(ctx)
}

func (s *threadSafeHost) FQDN() (string, error) {
	s.Lock()
	defer s.Unlock()
	return s.inner.FQDN()
}

var (
	sharedHost types.Host
	once       sync.Once
	hostErr    error
)

func GetHost() (types.Host, error) {
	once.Do(func() {
		var innerHost types.Host
		innerHost, hostErr = sysinfo.Host()
		sharedHost = newThreadSafeHost(innerHost)
	})
	return sharedHost, hostErr
}
