// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/component"
	"golang.org/x/sync/errgroup"
)

func TestServiceStart(t *testing.T) {
	// Skipping this test, since it requires proper endpoint service binaries. Leaving the test in because it is useful for local interractive testing with Endpoint service
	t.Skip()
	log := logp.NewLogger("test_service")
	comp := component.Component{
		Spec: component.InputRuntimeSpec{
			// BinaryName: "endpoint-security.exe",
			// BinaryPath: `C:\work\elastic-agent-8.5.0-SNAPSHOT-windows-x86_64\data\elastic-agent-b6521b\components\endpoint-security.exe`,
			BinaryName: "endpoint-security",
			//BinaryPath: "/home/amaus/elastic/elastic-agent/build/distributions/elastic-agent-8.5.0-SNAPSHOT-linux-x86_64/data/elastic-agent-b6521b/components/endpoint-security",
			BinaryPath: "/Users/amaus/elastic/elastic-agent/build/distributions/elastic-agent-8.5.0-SNAPSHOT-darwin-x86_64/data/elastic-agent-2099aa/components/endpoint-security",
			Spec: component.InputSpec{
				Service: &component.ServiceSpec{
					Name:  "ElasticEndpoint",
					Label: "co.elastic.endpoint",
					Operations: component.ServiceOperationsSpec{
						Check: &component.ServiceOperationsCommandSpec{
							Args: []string{"verify", "--log", "stderr"}, Env: []component.CommandEnvSpec(nil), Timeout: 30000000000,
						},
						Install: &component.ServiceOperationsCommandSpec{
							Args: []string{"install", "--log", "stderr", "--upgrade", "--resources", "endpoint-security-resources.zip"}, Env: []component.CommandEnvSpec(nil), Timeout: 600000000000,
						},
						Uninstall: &component.ServiceOperationsCommandSpec{
							Args: []string{"uninstall", "--log", "stderr"}, Env: []component.CommandEnvSpec(nil), Timeout: 600000000000,
						},
					},
				},
			},
		},
	}

	service, err := NewServiceRuntime(comp, log)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	g, ctx := errgroup.WithContext(ctx)

	comm := newMockCommunicator()

	// Run main loop
	g.Go(func() error {
		return service.Run(ctx, comm)
	})

	//err = service.Start()
	err = service.Stop()
	//err = service.Teardown()
	if err != nil {
		t.Fatal(err)
	}

	g.Go(func() error {
		for {
			select {
			case state := <-service.Watch():
				fmt.Printf("Got State: %#v\n", state)
				switch state.State {
				case client.UnitStateHealthy, client.UnitStateStopped:
					cn()
					return nil
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	err = g.Wait()
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}
