// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kardianos/service"
)

func TestStatusWatcher(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	sw, err := newServiceWatcher("co.elastic.endpoint")
	if err != nil {
		t.Fatal(err)
	}

	sw.checkDuration = time.Minute
	sw.checkInterval = 2 * time.Second

	go func() {
		sw.run(ctx)
	}()

	for r := range sw.status() {
		if r.err != nil {
			fmt.Println("watch err:")
		} else {
			var s string
			switch r.status {
			case service.StatusUnknown:
				s = "Unknown"
			case service.StatusRunning:
				s = "Running"
			case service.StatusStopped:
				s = "Stopped"
			}
			fmt.Println("status:", s)
		}
	}
	fmt.Println("watch done")
}
