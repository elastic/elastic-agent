// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build local && !define

package define

import (
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/elastic/go-sysinfo"
	"github.com/elastic/go-sysinfo/types"

	"github.com/elastic/elastic-agent/pkg/utils"
)

var osInfo *types.OSInfo
var osInfoErr error
var osInfoOnce sync.Once

func defineAction(t *testing.T, req Requirements) *Info {
	// always validate requirement is valid
	if err := req.Validate(); err != nil {
		panic(fmt.Sprintf("test %s has invalid requirements: %s", t.Name(), err))
	}
	if !req.Local {
		t.Skip("running local only tests and this test doesn't support local")
		return nil
	}
	if req.Sudo {
		// we can run sudo tests if we are being executed as root
		root, err := utils.HasRoot()
		if err != nil {
			panic(fmt.Sprintf("test %s failed to determine if running as root: %s", t.Name(), err))
		}
		if !root {
			t.Skip("not running as root and test requires root")
			return nil
		}
	}
	// need OS info to determine if the test can run
	osInfo, err := getOSInfo()
	if err != nil {
		panic("failed to get OS information")
	}
	if !req.runtimeAllowed(runtime.GOOS, runtime.GOARCH, osInfo.Version, osInfo.Platform) {
		t.Skip("platform, architecture, version, and distro not supported by test")
		return nil
	}
	// use a default local namespace
	namespace, err := getNamespace(t, "local")
	if err != nil {
		panic(err)
	}
	info := &Info{
		Namespace: namespace,
	}
	if req.Stack != nil {
		info.ESClient, err = getESClient()
		if err != nil {
			t.Skipf("test requires a stack but failed to create a valid client to elasticsearch: %s", err)
			return nil
		}
		info.KibanaClient, err = getKibanaClient()
		if err != nil {
			t.Skipf("test requires a stack but failed to create a valid client to kibana: %s", err)
			return nil
		}
	}
	return nil
}

func getOSInfo() (*types.OSInfo, error) {
	osInfoOnce.Do(func() {
		sysInfo, err := sysinfo.Host()
		if err != nil {
			osInfoErr = err
		} else {
			osInfo = sysInfo.Info().OS
		}
	})
	return osInfo, osInfoErr
}
