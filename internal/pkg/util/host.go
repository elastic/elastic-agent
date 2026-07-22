// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package util

import (
	"context"
	"os"
	"time"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/go-sysinfo/types"
)

// EnvHostName overrides the hostname reported by Elastic Agent when set.
const EnvHostName = "ELASTIC_AGENT_HOSTNAME"

// GetHostName returns the hostname for this agent. ELASTIC_AGENT_HOSTNAME takes precedence;
// otherwise falls back to FQDN (when enabled) or the OS hostname.
func GetHostName(isFqdnFeatureEnabled bool, hostInfo types.HostInfo, host types.Host, log *logger.Logger) string {
	if override := os.Getenv(EnvHostName); override != "" {
		return override
	}

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
