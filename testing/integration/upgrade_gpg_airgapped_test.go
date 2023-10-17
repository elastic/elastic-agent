// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/testing/upgradetest"
)

func AirGap() {

	// 	tmpDir := t.TempDir()
	//	httptest.NewServer(http.FileServer(http.Dir(tmpDir)))

	host := "artifacts.elastic.co"
	ips, err := net.LookupIP(host)
	if err != nil {
		panic(err)
	}

	// iptables -A OUTPUT -j DROP -d IP

	const iptables = "iptables"
	const ip6tables = "ip6tables"
	var cmd string
	for _, ip := range ips {
		cmd = iptables
		if ip.To4() == nil {
			cmd = ip6tables
		}
		toExec := []string{"-A", "OUTPUT", "-j", "DROP", "-d", ip.String()}

		fmt.Println(cmd, toExec)
		out, err := exec.Command(
			cmd, toExec...).
			// cmd, "-A", "OUTPUT", "-j", "DROP", "-d", ip.String()).
			CombinedOutput()
		fmt.Println("=================================================")
		fmt.Println(cmd, toExec)
		if err != nil {
			fmt.Println("FAILED:", cmd, toExec)
			fmt.Println(string(out))
		}
		fmt.Println("=================================================")
		// fmt.Println(ip)
	}
}

func newArtefactsServer(t *testing.T, version string) *httptest.Server {
	// https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.10.2-linux-x86_64.tar.gz
	tmpDir := t.TempDir()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(tmpDir)).ServeHTTP(w, r)
	}))

}

func TestAirgappedStandaloneUpgradeFailingGPGFallbackButUpgradeSucceed(t *testing.T) {
	define.Require(t, define.Requirements{
		Isolate: true,
		Local:   false, // requires Agent installation
		Sudo:    true,  // requires Agent installation
	})

	minVersion := upgradetest.Version_8_10_0_SNAPSHOT
	fromVersion, err := version.ParseVersion(define.Version())
	require.NoError(t, err)

	if fromVersion.Less(*minVersion) {
		t.Skipf("Version %s is lower than min version %s", define.Version(), minVersion)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start at the build version
	startFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	downgradeToVersion, err := upgradetest.PreviousMinor(ctx, define.Version())
	require.NoError(t, err)
	endFixture, err := atesting.NewFixture(
		t,
		downgradeToVersion,
		atesting.WithFetcher(atesting.ArtifactFetcher()),
	)
	require.NoError(t, err)

	artefactsServer := newArtefactsServer(t, downgradeToVersion)

	t.Logf("Testing Elastic Agent upgrade from %s to %s...", define.Version(), downgradeToVersion)

	err = upgradetest.PerformUpgrade(
		ctx, startFixture, endFixture, t,
		upgradetest.WithSourceURI(artefactsServer.URL),
		upgradetest.WithSkipVerify(false))
	require.NoError(t, err, "perform upgrade failed")
}
