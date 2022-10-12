// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/kardianos/service"
)

const (
	darwin  = "darwin"
	unknown = "unknown"
	running = "running"
)

// Useful test to keep the code around.
// Marked as skipped, because can't really use as unit test with CI since it relies on actual endpoint service to be present
func TestStatusWatcher(t *testing.T) {
	t.Skip()
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	name := "ElasticEndpoint"
	if runtime.GOOS == darwin {
		name = "co.elastic.endpoint"
	}
	sw, err := newServiceWatcher(name)
	if err != nil {
		t.Fatal(err)
	}

	sw.checkDuration = 2 * time.Minute
	sw.checkInterval = 2 * time.Second
	sw.stopOnError = false

	go func() {
		sw.run(ctx)
	}()

	for r := range sw.status() {
		if r.Err != nil {
			//nolint:forbidigo // ok for interractive test code
			fmt.Println("watch err:", r.Err)
		} else {
			var s string
			switch r.Status {
			case service.StatusUnknown:
				s = unknown
			case service.StatusRunning:
				s = running
			case service.StatusStopped:
				s = "Stopped"
			}
			//nolint:forbidigo // ok for interractive test code
			fmt.Println("status:", s)
		}
	}
	//nolint:forbidigo // ok for interractive test code
	fmt.Println("watch done")
}
