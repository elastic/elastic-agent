// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package stack

import (
	"context"
	"fmt"
	"github.com/elastic/e2e-testing/cli/config"
	"github.com/elastic/e2e-testing/dev-tools/deploy"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"path/filepath"
)

// Up teardown docker environment
func Up(ctx context.Context, version string, dockerImage string) error {
	fmt.Println("Load elastic agent image")
	directory, _ := filepath.Abs("build/distributions/elastic-agent-8.3.0-SNAPSHOT-linux-amd64.docker.tar.gz")
	fmt.Println(directory)
	err := deploy.LoadImage(directory)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Tag elastic agent image")
	version = version + "-SNAPSHOT"
	// we need to tag the loaded image because its tag relates to the target branch
	err = deploy.TagImage(
		fmt.Sprintf("docker.elastic.co/beats/%s:%s", "elastic-agent", version),
		fmt.Sprintf("docker.elastic.co/observability-ci/%s:%s-%s", "elastic-agent", version, "amd64"),
		// tagging including git commit and snapshot
		fmt.Sprintf("docker.elastic.co/observability-ci/%s:%s-%s", "elastic-agent", version, "amd64"),
	)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Deploy stack")
	provider := deploy.New("elastic-package")

	service, ok := provider.(*deploy.EPServiceManager)
	if !ok {
		return errors.New("error")
	}
	profile := deploy.NewServiceRequest("fleet")
	env := map[string]string{}
	env["ELASTIC_AGENT_IMAGE_REF_OVERRIDE"] = "docker.elastic.co/observability-ci/elastic-agent:8.3.0-SNAPSHOT-amd64"
	config.Init()
	err = service.Bootstrap(ctx, profile, env, func() error {
		fmt.Println("stack has been deployed")
		return nil
	})
	fmt.Println("stack has been deployed", err)
	return err
}

// Down teardown docker environment
func Down(ctx context.Context) error {
	provider := deploy.New("elastic-package")
	profile := deploy.NewServiceRequest("fleet")
	service, ok := provider.(*deploy.EPServiceManager)
	if !ok {
		return errors.New("error")
	}
	service.Destroy(ctx, profile)
	return nil
}
