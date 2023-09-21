// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package utils

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent-system-metrics/metric/system/process"
)

// GetWatcherPIDs returns the PID's of any running `elastic-agent watch` process.
func GetWatcherPIDs() ([]int, error) {
	procStats := process.Stats{
		// filtering with '.*elastic-agent' or '^.*elastic-agent$' doesn't
		// seem to work as expected, filtering is done in the for loop below
		Procs: []string{".*"},
	}
	err := procStats.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize process.Stats: %w", err)
	}
	pidMap, _, err := procStats.FetchPids()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch pids: %w", err)
	}
	var pids []int
	for pid, state := range pidMap {
		if len(state.Args) < 2 {
			// must have at least 2 args "elastic-agent[.exe] watch"
			continue
		}
		// instead of matching on Windows using the specific '.exe' suffix, this ensures
		// that even if the watcher is spawned without the '.exe' suffix (which Windows will allow and supports)
		// it always results in the watch process being killed
		if strings.TrimSuffix(filepath.Base(state.Args[0]), ".exe") == "elastic-agent" && state.Args[1] == "watch" {
			// it is a watch subprocess
			pids = append(pids, pid)
		}
	}
	return pids, nil
}
