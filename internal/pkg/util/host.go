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

var sharedHost types.Host = &SharedHost{}

func init() {
	sharedHost, _ = NewSharedHost()
}

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

// SharedHost is a thread-safe wrapper around types.Host.
// It exists so we can only create it once, as some of the setup it does is relatively expensive.
type SharedHost struct {
	sync.Mutex
	inner types.Host
}

func NewSharedHost() (*SharedHost, error) {
	inner, err := sysinfo.Host()
	if err != nil {
		return nil, err
	}
	return &SharedHost{inner: inner}, nil
}

func (s *SharedHost) CPUTime() (types.CPUTimes, error) {
	s.Lock()
	defer s.Unlock()
	return s.inner.CPUTime()
}

func (s *SharedHost) Info() types.HostInfo {
	s.Lock()
	defer s.Unlock()
	return s.inner.Info()
}

func (s *SharedHost) Memory() (*types.HostMemoryInfo, error) {
	s.Lock()
	defer s.Unlock()
	return s.inner.Memory()
}

func (s *SharedHost) FQDNWithContext(ctx context.Context) (string, error) {
	s.Lock()
	defer s.Unlock()
	return s.inner.FQDNWithContext(ctx)
}

func (s *SharedHost) FQDN() (string, error) {
	s.Lock()
	defer s.Unlock()
	return s.inner.FQDN()
}

func GetHost() (types.Host, error) {
	if sharedHost != nil {
		return sharedHost, nil
	}
	return NewSharedHost()
}
