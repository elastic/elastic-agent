// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/proxytest"
)

type ProxyURL struct {
	suite.Suite
	fixture *integrationtest.Fixture

	fleet *fleetservertest.Server
	proxy *proxytest.Proxy

	proxyURL string
}

func TestProxyURL(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		// Isolate: true,
		Local: true,
		Sudo:  true,
		OS: []define.OS{{
			Type: define.Linux,
			Arch: define.AMD64,
			// Version: "22.04",
			Distro: "ubuntu",
		}},
	})

	suite.Run(t, &ProxyURL{})
}

func (p *ProxyURL) SetupSuite() {
	fleetHost := "fleet.elastic.co"

	agentVersion := "8.10.0-SNAPSHOT"
	p.setupFleet("http://" + fleetHost)

	p.proxy = proxytest.New(p.T(),
		proxytest.WithRewrite(fleetHost, p.fleet.LocalhostURL))

	f, err := define.NewFixture(p.T(),
		agentVersion,
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	p.Require().NoError(err, "SetupSuite: NewFixture failed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = f.Prepare(ctx)
	p.Require().NoError(err, "SetupSuite: fixture.Prepare failed")

	p.fixture = f
}

func (p *ProxyURL) TestNoProxyInThePolicy() {
	t := p.T()
	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			ProxyURL:       p.proxy.LocalhostURL,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleet.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			}})
	if err != nil {
		t.Log(string(out))
		require.NoError(t, err, "failed to install agent")
	}

	var status integrationtest.AgentStatusOutput
	if !assert.Eventually(t, func() bool {
		status, err = p.fixture.ExecStatus(context.Background())
		return status.FleetState == int(cproto.State_HEALTHY)
	}, 30*time.Second, 5*time.Second) {
		t.Errorf("want fleet state %d, got %d",
			cproto.State_HEALTHY, status.FleetState)
		t.Logf("agent status: %v", status)
	}
}

func (p *ProxyURL) setupFleet(fleetHost string) {
	agentID := "proxy-url-agent-id"
	actionID := "ActionID"
	policyID := "bedf2f42-a252-40bb-ab2b-8a7e1b874c7a"
	enrollmentToken := "enrollmentToken"
	ackToken := "ackToken"
	apiKey := fleetservertest.APIKey{
		ID:  "apiKeyID",
		Key: "apiKeyKey",
	}

	var actionsIdx int

	tmpl := fleetservertest.TmplPolicy{
		AckToken:   ackToken,
		AgentID:    agentID,
		ActionID:   actionID,
		PolicyID:   policyID,
		FleetHosts: fmt.Sprintf("%q", fleetHost),
		SourceURI:  "http://source.uri",
		CreatedAt:  time.Now().Format(time.RFC3339),
		Output: struct {
			APIKey string
			Hosts  string
			Type   string
		}{
			APIKey: apiKey.String(),
			Hosts:  `"https://my.clould.elstc.co:443"`,
			Type:   "elasticsearch"},
	}

	nextAction := func() (fleetservertest.CheckinAction, *fleetservertest.HTTPError) {
		defer func() { actionsIdx++ }()
		actions, err := fleetservertest.NewActionPolicyChangeEmptyPolicy(tmpl)
		if err != nil {
			panic(fmt.Sprintf("failed to get new actions: %v", err))
		}

		switch actionsIdx {
		case 0:
			return fleetservertest.CheckinAction{
					AckToken: tmpl.AckToken, Actions: []string{actions}},
				nil
		}

		return fleetservertest.CheckinAction{}, nil
	}

	acker := func(id string) (fleetservertest.AckResponseItem, bool) {
		return fleetservertest.AckResponseItem{
			Status:  http.StatusOK,
			Message: http.StatusText(http.StatusOK),
		}, false
	}

	fleet := fleetservertest.NewServerWithFakeComponent(
		apiKey,
		enrollmentToken,
		agentID,
		policyID,
		nextAction,
		acker,
		// fleetservertest.WithRequestLog(log.Printf),
	)
	p.fleet = fleet
	tmpl.FleetHosts = fmt.Sprintf("%q", fleet.LocalhostURL)

	return
}

func (p *ProxyURL) setupSquidProxy(urlRewriter string) {
	t := p.T()
	t.Helper()

	t.Log("installing squid")
	cmd := []string{"apt", "install", "-y", "squid=5.2-1ubuntu4.3"}
	out, err := exec.Command(cmd[0], cmd[1:]...).Output()
	if err != nil {
		var eerr *exec.ExitError
		if errors.As(err, &eerr) {
			t.Logf("failed running: %q", strings.Join(cmd, " "))
			t.Log("stdout:", string(out))
			t.Log("stderr:", string(eerr.Stderr))
		}

		t.Fatalf("could install squid service")
	}

	t.Log("reading config")
	conf, err := os.ReadFile("testdata/squid.conf")
	require.NoError(t, err, "could not open squid config")

	extraConf := "\n" +
		"url_rewrite_program " + urlRewriter + "\n" +
		"url_rewrite_extras " + p.fleet.LocalhostURL + "\n"
	conf = append(conf, []byte(extraConf)...)
	t.Log("saving config")
	err = os.WriteFile("/etc/squid/squid.conf", conf, 0644)
	require.NoError(p.T(), err, "could not save squid config")

	t.Log("restarting squid")
	cmd = []string{"systemctl", "restart", "squid.service"}
	out, err = exec.Command(cmd[0], cmd[1:]...).Output()
	if err != nil {
		var eerr *exec.ExitError
		if errors.As(err, &eerr) {
			t.Logf("failed running: %q", strings.Join(cmd, " "))
			t.Log("stdout:", string(out))
			t.Log("stderr:", string(eerr.Stderr))
		}

		t.Fatalf("could restart squid service")
	}

	p.proxyURL = "http://localhost:3128" // default squid address
}

// type logWriter func(args ...any)
//
// func (w logWriter) Write(p []byte) (n int, err error) {
// 	w(string(p))
// 	return len(p), nil
// }
