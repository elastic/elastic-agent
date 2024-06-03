// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/proxytest"
)

func TestProxyURL(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: Fleet,
		Local: false,
		Sudo:  true,
	})

	// Setup proxies and fake fleet server host we are gonna rewrite
	unreachableFleetHost := "fleet.elastic.co"
	unreachableFleetHttpURL := "http://" + unreachableFleetHost

	// setupFunc is a hook used by testcases to set up proxies and add data/behaviors to fleet policy and checkinAcker
	// the test will use one of the returned proxies if a proxy key is set in args.enrollProxyName
	type setupFunc func(ctx context.Context, t *testing.T, fleet *fleetservertest.Server, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) (proxies map[string]*proxytest.Proxy)

	// enrollmentURLFunc is a getter for the enrollmentURL so that each testcase can control what is used at install time
	type enrollmentURLFunc func(fleet *fleetservertest.Server) string

	// testFunc is the hook the main test loop calls for performing assertions after the agent has been installed and is healthy
	type testFunc func(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, proxies map[string]*proxytest.Proxy, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker)

	type args struct {
		enrollProxyName string
	}

	type testcase struct {
		name          string
		args          args
		setupF        setupFunc
		enrollmentURL enrollmentURLFunc
		testF         testFunc
	}

	testcases := []testcase{
		{
			name: "EnrollWithProxy-NoProxyInPolicy",
			args: args{enrollProxyName: "proxy"},
			setupF: func(ctx context.Context, t *testing.T, fleet *fleetservertest.Server, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) (proxies map[string]*proxytest.Proxy) {

				// Create and start fake proxy
				proxy := proxytest.New(t,
					proxytest.WithRewrite(unreachableFleetHost, "localhost:"+fleet.Port),
					proxytest.WithRequestLog("proxy", t.Logf),
					proxytest.WithVerboseLog())
				err := proxy.Start()
				require.NoError(t, err, "error starting proxy")
				t.Cleanup(proxy.Close)

				// now that we have fleet and the proxy running, we can add actions which
				// depend on them.
				action, err := fleetservertest.NewActionWithEmptyPolicyChange(
					"actionID-TestNoProxyInThePolicyActionID", *policyData)
				require.NoError(t, err, "could not generate action with policy")

				// Create checkin action with respective ack token
				ackToken := "ackToken-AckTokenTestNoProxyInThePolicy"
				checkinWithAcker.AddCheckin(
					ackToken,
					0,
					action,
				)

				return map[string]*proxytest.Proxy{"proxy": proxy}
			},
			enrollmentURL: func(_ *fleetservertest.Server) string {
				// returning a non-existing URL we make sure Fleet is only reachable through proxy
				return unreachableFleetHttpURL
			},
			testF: func(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, proxies map[string]*proxytest.Proxy, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) {
				check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)
			},
		},
		{
			name: "EnrollWithProxy-EmptyProxyInPolicy",
			args: args{enrollProxyName: "proxy"},
			setupF: func(ctx context.Context, t *testing.T, fleet *fleetservertest.Server, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) (proxies map[string]*proxytest.Proxy) {

				// set FleetProxyURL to empty string in the policy
				policyData.FleetProxyURL = new(string)
				// FIXME: this reassignment is pointless ?
				*policyData.FleetProxyURL = ""

				// Create and start fake proxy
				proxy := proxytest.New(t,
					proxytest.WithRewrite(unreachableFleetHost, "localhost:"+fleet.Port),
					proxytest.WithRequestLog("proxy", t.Logf),
					proxytest.WithVerboseLog())
				err := proxy.Start()
				require.NoError(t, err, "error starting proxy")
				t.Cleanup(proxy.Close)

				// now that we have fleet and the proxy running, we can add actions which
				// depend on them.
				ackToken := "ackToken-AckTokenTestNoProxyInThePolicy"
				action, err := fleetservertest.NewActionWithEmptyPolicyChange(
					"actionID-TestNoProxyInThePolicyActionID", *policyData)
				require.NoError(t, err, "could not generate action with policy")
				checkinWithAcker.AddCheckin(
					ackToken,
					0,
					action,
				)

				return map[string]*proxytest.Proxy{"proxy": proxy}
			},
			enrollmentURL: func(_ *fleetservertest.Server) string {
				// returning a non-existing URL we make sure Fleet is only reachable through proxy
				return unreachableFleetHttpURL
			},
			testF: func(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, proxies map[string]*proxytest.Proxy, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) {
				check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)
			},
		},
		{
			name: "EnrollWithProxy-PolicyProxyTakesPrecedence",
			args: args{enrollProxyName: "enroll"},
			setupF: func(ctx context.Context, t *testing.T, fleet *fleetservertest.Server, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) (proxies map[string]*proxytest.Proxy) {

				// We need 2 proxies: one for the initial enroll and another to specify in the policy
				proxyEnroll := proxytest.New(t,
					proxytest.WithRewrite(unreachableFleetHost, "localhost:"+fleet.Port),
					proxytest.WithRequestLog("proxy-enroll", t.Logf),
					proxytest.WithVerboseLog())
				proxyEnroll.Start()
				t.Cleanup(proxyEnroll.Close)
				proxyFleetPolicy := proxytest.New(t,
					proxytest.WithRewrite(unreachableFleetHost, "localhost:"+fleet.Port),
					proxytest.WithRequestLog("proxy-fleet-policy", t.Logf),
					proxytest.WithVerboseLog())
				proxyFleetPolicy.Start()
				t.Cleanup(proxyFleetPolicy.Close)

				// set the proxy URL in policy to proxyFleetPolicy
				policyData.FleetProxyURL = new(string)
				*policyData.FleetProxyURL = proxyFleetPolicy.LocalhostURL

				// now that we have fleet and the proxy running, we can add actions which
				// depend on them.
				action, err := fleetservertest.NewActionWithEmptyPolicyChange(
					"actionID-TestValidProxyInThePolicy", *policyData)
				require.NoError(t, err, "could not generate action with policy")

				ackToken := "AckToken-TestValidProxyInThePolicy"
				checkinWithAcker.AddCheckin(
					ackToken,
					0,
					action,
				)

				return map[string]*proxytest.Proxy{"enroll": proxyEnroll, "policy": proxyFleetPolicy}
			},
			enrollmentURL: func(_ *fleetservertest.Server) string {
				// returning a non-existing URL we make sure Fleet is only reachable through proxy
				return unreachableFleetHttpURL
			},
			testF: func(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, proxies map[string]*proxytest.Proxy, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) {
				check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

				// ensure the agent is communicating through the proxy set in the policy
				want := fleetservertest.NewPathCheckin(policyData.AgentID)
				assert.Eventually(t, func() bool {
					for _, r := range proxies["policy"].ProxiedRequests() {
						if strings.Contains(r, want) {
							return true
						}
					}

					return false
				}, 5*time.Minute, 5*time.Second,
					"did not find requests to the proxy defined in the policy. Want [%s] on %v",
					proxies["policy"].LocalhostURL, proxies["policy"].ProxiedRequests())
			},
		},
		{
			name: "NoEnrollProxy-ProxyInThePolicy",
			args: args{
				// no proxy at enroll
				enrollProxyName: "",
			},
			setupF: func(ctx context.Context, t *testing.T, fleet *fleetservertest.Server, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) (proxies map[string]*proxytest.Proxy) {
				// Create a fake proxy to be used in fleet policy
				proxyFleetPolicy := proxytest.New(t,
					proxytest.WithRewrite(unreachableFleetHost, "localhost:"+fleet.Port),
					proxytest.WithRequestLog("proxy-fleet-policy", t.Logf),
					proxytest.WithVerboseLog())
				proxyFleetPolicy.Start()
				t.Cleanup(proxyFleetPolicy.Close)

				policyData.FleetProxyURL = new(string)
				*policyData.FleetProxyURL = proxyFleetPolicy.LocalhostURL
				// now that we have fleet and the proxy running, we can add actions which
				// depend on them.
				action, err := fleetservertest.NewActionWithEmptyPolicyChange(
					"actionID-TestValidProxyInThePolicy", *policyData)
				require.NoError(t, err, "could not generate action with policy")

				ackToken := "AckToken-TestValidProxyInThePolicy"
				checkinWithAcker.AddCheckin(
					ackToken,
					0,
					action,
				)
				return map[string]*proxytest.Proxy{"proxyFleetPolicy": proxyFleetPolicy}
			},
			enrollmentURL: func(fleet *fleetservertest.Server) string {
				return fleet.LocalhostURL
			},
			testF: func(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, proxies map[string]*proxytest.Proxy, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) {
				check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

				// ensure the agent is communicating through the new proxy
				if !assert.Eventually(t, func() bool {
					proxy := proxies["proxyFleetPolicy"]
					for _, r := range proxy.ProxiedRequests() {
						if strings.Contains(
							r,
							fleetservertest.NewPathCheckin(policyData.AgentID)) {
							return true
						}
					}

					return false
				}, 5*time.Minute, 5*time.Second) {
					t.Errorf("did not find requests to the proxy defined in the policy")
				}
			},
		},
		{
			name: "NoEnrollProxy-RemoveProxyFromThePolicy",
			args: args{
				// no proxy at enroll
				enrollProxyName: "",
			},
			setupF: func(ctx context.Context, t *testing.T, fleet *fleetservertest.Server, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) (proxies map[string]*proxytest.Proxy) {

				// Create a fake proxy to use in initial fleet policy
				proxyFleetPolicy := proxytest.New(t,
					proxytest.WithRewrite(unreachableFleetHost, "localhost:"+fleet.Port),
					proxytest.WithRequestLog("proxy-fleet-policy", t.Logf),
					proxytest.WithVerboseLog())
				proxyFleetPolicy.Start()
				t.Cleanup(proxyFleetPolicy.Close)

				policyData.FleetProxyURL = new(string)
				*policyData.FleetProxyURL = proxyFleetPolicy.LocalhostURL

				// now that we have fleet and the proxy running, we can add actions which
				// depend on them.
				action, err := fleetservertest.NewActionWithEmptyPolicyChange(
					"actionID-TestRemoveProxyFromThePolicy", *policyData)
				require.NoError(t, err, "could not generate action with policy")

				ackToken := "AckToken-TestRemoveProxyFromThePolicy"
				checkinWithAcker.AddCheckin(
					ackToken,
					0,
					action,
				)

				return map[string]*proxytest.Proxy{"fleetProxy": proxyFleetPolicy}
			},
			enrollmentURL: func(fleet *fleetservertest.Server) string {
				return fleet.LocalhostURL
			},
			testF: func(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, proxies map[string]*proxytest.Proxy, policyData *fleetservertest.TmplPolicy, checkinWithAcker *fleetservertest.CheckinActionsWithAcker) {
				// assert the agent is actually connected to fleet.
				check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

				// ensure the agent is communicating through the proxy set in the policy
				if !assert.Eventually(t, func() bool {
					for _, r := range proxies["fleetProxy"].ProxiedRequests() {
						if strings.Contains(
							r,
							fleetservertest.NewPathCheckin(policyData.AgentID)) {
							return true
						}
					}

					return false
				}, 5*time.Minute, 5*time.Second) {
					t.Errorf("did not find requests to the proxy defined in the policy")
				}

				// Assert the proxy is set on the agent
				inspect, err := fixture.ExecInspect(ctx)
				require.NoError(t, err)
				assert.Equal(t, *policyData.FleetProxyURL, inspect.Fleet.ProxyURL)

				// remove proxy from the policy
				want := *policyData.FleetProxyURL
				policyData.FleetProxyURL = nil
				actionIDRemoveProxyFromPolicy := "actionIDRemoveProxyFromPolicy-actionID-TestRemoveProxyFromThePolicy"
				action, err := fleetservertest.NewActionWithEmptyPolicyChange(
					actionIDRemoveProxyFromPolicy, *policyData)
				require.NoError(t, err, "could not generate action with policy")

				ackToken := "AckToken-TestRemovedProxyFromThePolicy"
				checkinWithAcker.AddCheckin(
					ackToken,
					0,
					action,
				)

				// ensures the agent acked the action sending a policy without proxy
				require.Eventually(t, func() bool {
					return checkinWithAcker.Acked(actionIDRemoveProxyFromPolicy)
				},
					30*time.Second, 5*time.Second)
				inspect, err = fixture.ExecInspect(ctx)
				require.NoError(t, err)
				assert.Equal(t, inspect.Fleet.ProxyURL, want)

				// assert, again, the agent is actually connected to fleet.
				check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)
			},
		},
	}

	for _, tt := range testcases {

		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
			defer cancel()

			// create API Key and basic Fleet Policy
			apiKey, policyData := createBasicFleetPolicyData(t, unreachableFleetHost)

			// Create a checkin and ack handler
			checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()

			// Start fake fleet server
			enrollmentToken := "enrollmentToken"
			fleet := fleetservertest.NewServerWithHandlers(
				apiKey,
				enrollmentToken,
				policyData.AgentID,
				policyData.PolicyID,
				checkinWithAcker.ActionsGenerator(),
				checkinWithAcker.Acker(),
				fleetservertest.WithRequestLog(t.Logf),
			)
			t.Cleanup(fleet.Close)

			// Specific testcase setup and map of created proxies
			proxies := tt.setupF(ctx, t, fleet, &policyData, &checkinWithAcker)

			fixture, err := define.NewFixtureFromLocalBuild(t,
				define.Version(),
				integrationtest.WithAllowErrors(),
				integrationtest.WithLogOutput())
			require.NoError(t, err, "SetupTest: NewFixtureFromLocalBuild failed")

			err = fixture.EnsurePrepared(ctx)
			require.NoError(t, err, "SetupTest: fixture.Prepare failed")

			installProxyURL := ""
			if tt.args.enrollProxyName != "" {
				require.Containsf(t, proxies, tt.args.enrollProxyName, "Proxy %q to be used for enrolling is missing from the map of proxies", tt.args.enrollProxyName)
				installProxyURL = proxies[tt.args.enrollProxyName].LocalhostURL
			}

			require.NotNil(t, tt.enrollmentURL, "testcase must define an enrollmentURL getter")
			enrollmentURL := tt.enrollmentURL(fleet)

			out, err := fixture.Install(
				ctx,
				&integrationtest.InstallOpts{
					Force:          true,
					NonInteractive: true,
					Insecure:       true,
					ProxyURL:       installProxyURL,
					EnrollOpts: integrationtest.EnrollOpts{
						URL:             enrollmentURL,
						EnrollmentToken: "anythingWillDO",
					}})
			t.Logf("elastic-agent install output: \n%s\n", string(out))
			require.NoError(t, err, "failed to install agent")
			t.Cleanup(func() {
				uninstallCtx, uninstallCtxCancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer uninstallCtxCancel()
				uninstallOutput, uninstallErr := fixture.Uninstall(uninstallCtx, &integrationtest.UninstallOpts{Force: true})
				t.Logf("uninstall output:\n%s\n", string(uninstallOutput))
				assert.NoError(t, uninstallErr, "error during uninstall")
			})

			tt.testF(ctx, t, fixture, proxies, &policyData, &checkinWithAcker)
		})
	}

}

func createBasicFleetPolicyData(t *testing.T, fleetHost string) (fleetservertest.APIKey, fleetservertest.TmplPolicy) {
	apiKey := fleetservertest.APIKey{
		ID:  "apiKeyID",
		Key: "apiKeyKey",
	}

	agentID := strings.Replace(t.Name(), "/", "-", -1) + "-agent-id"
	policyUUID, err := uuid.NewUUID()
	require.NoError(t, err, "error generating UUID for policy")

	policyID := policyUUID.String()
	policyData := fleetservertest.TmplPolicy{
		AgentID:    agentID,
		PolicyID:   t.Name() + policyID,
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
	return apiKey, policyData
}
