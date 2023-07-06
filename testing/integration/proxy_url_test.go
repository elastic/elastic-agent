// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
)

type ProxyURL struct {
	suite.Suite
	fixture *integrationtest.Fixture

	fleet *fleetservertest.Server

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

type logWriter func(args ...any)

func (w logWriter) Write(p []byte) (n int, err error) {
	w(string(p))
	return len(p), nil
}

func (p *ProxyURL) SetupSuite() {
	t := p.T()

	pwd, err := os.Getwd()
	require.NoError(t, err, "could not get current working directory")
	urlRewriter := path.Join(pwd, "testdata", "squid_url_rewrite")

	agentVersion := "8.10.0-SNAPSHOT"
	t.Log("setting up fleet-server mock")
	p.setupFleet()
	t.Log("done setting up fleet-server mock")

	t.Log("starting url rewrite program")
	go func() {
		cmd := exec.Command(urlRewriter)
		cmd.Stderr = logWriter(t.Log)
		cmd.Stdout = logWriter(t.Log)

		err := cmd.Run()
		if err != nil {
			t.Logf("failed running: %q: %#v", urlRewriter, err)
			os.Exit(1) // cannot FailNow a test on a goroutine
		}
	}()

	t.Log("setting up squid proxy")
	p.setupSquidProxy(urlRewriter)
	t.Log("done setting up squid proxy")

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

func (p *ProxyURL) setupMockProxy() {

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

	testfleetURL, err := url.Parse(p.fleet.URL)
	require.NoError(t, err, "could parse fleet-server URL")

	extraConf := "\n" +
		"url_rewrite_program " + urlRewriter + "\n" +
		"url_rewrite_extras " + "http://localhost:" + testfleetURL.Port() + "\n"
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

func (p *ProxyURL) setupFleet() {
	// this value is hard coded on the squid URL rewrite program.
	// See testdata/squid_url_rewrite.go
	fleetHost := "http://fleet.elastic.co"
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
		actions, err := fleetservertest.NewActionPolicyChangeWithFakeComponent(tmpl)
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
		fleetservertest.WithRequestLog(log.Printf))
	p.fleet = fleet

	return
}

func (p *ProxyURL) Test1() {
	out, err := p.fixture.Install(
		context.Background(),
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			ProxyURL:       p.proxyURL,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             p.fleet.URL,
				EnrollmentToken: "anythingWillDO",
			}})

	fmt.Println("========================================== Agent output ==========================================")
	fmt.Println(string(out))
	if err != nil {
		fmt.Println("========================================== Agent ERROR ==========================================")
		fmt.Printf("%v\n", err)
	}
}
