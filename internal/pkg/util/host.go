// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package util

import (
	"context"
	"time"

	"github.com/elastic/elastic-agent/pkg/core/logger"
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
