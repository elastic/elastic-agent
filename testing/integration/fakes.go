// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent/pkg/component"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

const fakeShipperName = "fake-shipper"

var fakeComponentPltfs = []string{
	"container/amd64",
	"container/arm64",
	"darwin/amd64",
	"darwin/arm64",
	"linux/amd64",
	"linux/arm64",
	"windows/amd64",
}

var fakeComponent = atesting.UsableComponent{
	Name:       "fake",
	BinaryPath: mustAbs(filepath.Join("..", "..", "pkg", "component", "fake", "component", osExt("component"))),
	Spec: &component.Spec{
		Version: 2,
		Inputs: []component.InputSpec{
			{
				Name:        "fake",
				Description: "A fake input",
				Platforms:   fakeComponentPltfs,
				Shippers: []string{
					fakeShipperName,
				},
				Command: &component.CommandSpec{},
			},
			{
				Name:        "fake-apm",
				Description: "Fake component apm traces generator",
				Platforms:   fakeComponentPltfs,
				Shippers: []string{
					fakeShipperName,
				},
				Command: &component.CommandSpec{
					Env: []component.CommandEnvSpec{
						{
							Name:  "ELASTIC_APM_LOG_FILE",
							Value: "stderr",
						},
						{
							Name:  "ELASTIC_APM_LOG_LEVEL",
							Value: "debug",
						},
					},
				},
			},
		},
	},
}

var fakeShipper = atesting.UsableComponent{
	Name:       fakeShipperName,
	BinaryPath: mustAbs(filepath.Join("..", "..", "pkg", "component", "fake", "shipper", osExt("shipper"))),
	Spec: &component.Spec{
		Version: 2,
		Shippers: []component.ShipperSpec{
			{
				Name:        fakeShipperName,
				Description: "A fake shipper",
				Platforms: []string{
					"container/amd64",
					"container/arm64",
					"darwin/amd64",
					"darwin/arm64",
					"linux/amd64",
					"linux/arm64",
					"windows/amd64",
				},
				Outputs: []string{
					"fake-action-output",
				},
				Command: &component.CommandSpec{},
			},
		},
	},
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return abs
}

func osExt(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
