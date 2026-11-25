// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package hostinfo gathers the information Elastic Agent reports about the host it runs on, including its hostname,
// and watches it for changes. Gathering it does a fair amount of I/O, so long-running code should share a Watcher
// instead of calling Fetch repeatedly. The check interval and FQDN lookup timeout match the defaults of the
// add_host_metadata processor in Beats.
//
// Known inconsistency with Beats: Elastic Agent reports the lowercased hostname as host.name, including when it
// comes from ELASTIC_AGENT_HOSTNAME. add_host_metadata lowercases the FQDN or OS hostname too, but uses
// ELASTIC_AGENT_HOSTNAME as is. So if the override contains uppercase letters, host.name differs between the agent
// (Fleet metadata and the host provider) and the events Beats publish.
package hostinfo

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/elastic/go-sysinfo/types"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
)

const (
	// EnvOverride overrides the hostname reported by Elastic Agent when set.
	EnvOverride = "ELASTIC_AGENT_HOSTNAME"

	// DefaultCheckInterval is how often a Watcher fetches the host information again by default. It matches the
	// default cache.ttl of add_host_metadata.
	DefaultCheckInterval = 5 * time.Minute

	// fqdnLookupTimeout matches the FQDN lookup timeout in add_host_metadata.
	fqdnLookupTimeout = time.Minute
)

// Override returns the trimmed value of ELASTIC_AGENT_HOSTNAME, or "" if the variable is unset or contains only
// whitespace.
func Override() string {
	return strings.TrimSpace(os.Getenv(EnvOverride))
}

// Info is the information Elastic Agent reports about the host. It only contains fields that don't change on their
// own, so two Infos can be compared to tell whether the host changed.
type Info struct {
	// Hostname is ELASTIC_AGENT_HOSTNAME if set, otherwise the FQDN if the FQDN feature is enabled and the lookup
	// succeeds, otherwise the OS hostname. Its case is preserved, as Fleet expects for host.hostname and Beats for
	// agent.name.
	Hostname string
	// ID is the unique ID of the host, if available.
	ID            string
	Architecture  string
	KernelVersion string
	IPs           []string
	MACs          []string
	OS            types.OSInfo
	// MemoryTotal is the total physical memory in bytes, or 0 if it isn't available.
	MemoryTotal uint64
}

// Name returns the host.name Elastic Agent reports: Hostname lowercased. See the package documentation for how that
// differs from Beats.
func (i Info) Name() string {
	return strings.ToLower(i.Hostname)
}

// Fetch gathers the host information. It does a fair amount of I/O, and the FQDN lookup can take up to a minute.
func Fetch(ctx context.Context, log *logger.Logger) (Info, error) {
	host, err := sysinfo.Host()
	if err != nil {
		return Info{}, fmt.Errorf("failed to get host information: %w", err)
	}
	return fromHost(ctx, host, features.FQDN(), log), nil
}

func fromHost(ctx context.Context, host types.Host, useFQDN bool, log *logger.Logger) Info {
	hostInfo := host.Info()
	info := Info{
		Hostname:      lookupHostname(ctx, hostInfo, host, useFQDN, log),
		ID:            hostInfo.UniqueID,
		Architecture:  hostInfo.Architecture,
		KernelVersion: hostInfo.KernelVersion,
		IPs:           hostInfo.IPs,
		MACs:          hostInfo.MACs,
	}
	if hostInfo.OS != nil {
		info.OS = *hostInfo.OS
	}

	// Total physical memory is best-effort: some platforms/providers don't
	// report it, in which case we leave it at 0.
	if memInfo, err := host.Memory(); err != nil {
		log.Warnf("failed to gather host memory info: %v", err)
	} else if memInfo != nil {
		info.MemoryTotal = memInfo.Total
	}

	return info
}

func lookupHostname(ctx context.Context, info types.HostInfo, host types.Host, useFQDN bool, log *logger.Logger) string {
	if override := Override(); override != "" {
		return override
	}

	if !useFQDN {
		return info.Hostname
	}

	ctx, cancel := context.WithTimeout(ctx, fqdnLookupTimeout)
	defer cancel()

	fqdn, err := host.FQDNWithContext(ctx)
	if err != nil {
		// If we are unable to lookup the FQDN, we fallback to the OS-provided hostname
		log.Debugf("unable to lookup FQDN: %s, using hostname = %s", err.Error(), info.Hostname)
		return info.Hostname
	}

	return fqdn
}
