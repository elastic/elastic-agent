// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package hostinfo gathers the information Elastic Agent reports about the host it runs on, including its hostname,
// and watches it for changes. Gathering it does a fair amount of I/O, so long-running code should use a Watcher
// instead of calling Fetch repeatedly. The default check interval matches the default cache.ttl of the
// add_host_metadata processor in Beats.
//
// Known inconsistency with Beats: Elastic Agent reports the lowercased hostname as host.name, including when it
// comes from ELASTIC_AGENT_HOSTNAME. add_host_metadata lowercases the FQDN or OS hostname too, but uses
// ELASTIC_AGENT_HOSTNAME as is. So if the override contains uppercase letters, host.name differs between the agent
// (Fleet metadata and the host provider) and the events Beats publish.
package hostinfo

import (
	"fmt"
	"strings"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/elastic/go-sysinfo/types"

	"github.com/elastic/elastic-agent/internal/pkg/util"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
)

// DefaultCheckInterval is how often a Watcher fetches the host information again by default. It matches the default
// cache.ttl of add_host_metadata.
const DefaultCheckInterval = 5 * time.Minute

// Info is the information Elastic Agent reports about the host. It only contains fields that don't change on their
// own, so two Infos can be compared to tell whether the host changed.
type Info struct {
	// Hostname is ELASTIC_AGENT_HOSTNAME if set, otherwise the FQDN if the FQDN feature is enabled and the lookup
	// succeeds, otherwise the OS hostname. Its case is preserved.
	Hostname string
	// ID is the unique ID of the host, if available.
	ID            string
	Architecture  string
	KernelVersion string
	IPs           []string
	MACs          []string
	OS            types.OSInfo
}

// Name returns the host.name Elastic Agent reports: Hostname lowercased. See the package documentation for how that
// differs from Beats.
func (i Info) Name() string {
	return strings.ToLower(i.Hostname)
}

// Fetch gathers the host information. It does a fair amount of I/O, and the FQDN lookup can take up to a minute.
func Fetch(log *logger.Logger) (Info, error) {
	host, err := sysinfo.Host()
	if err != nil {
		return Info{}, fmt.Errorf("failed to get host information: %w", err)
	}
	return fromHost(host, features.FQDN(), log), nil
}

func fromHost(host types.Host, useFQDN bool, log *logger.Logger) Info {
	hostInfo := host.Info()
	info := Info{
		Hostname:      util.GetHostName(useFQDN, hostInfo, host, log),
		ID:            hostInfo.UniqueID,
		Architecture:  hostInfo.Architecture,
		KernelVersion: hostInfo.KernelVersion,
		IPs:           hostInfo.IPs,
		MACs:          hostInfo.MACs,
	}
	if hostInfo.OS != nil {
		info.OS = *hostInfo.OS
	}
	return info
}
