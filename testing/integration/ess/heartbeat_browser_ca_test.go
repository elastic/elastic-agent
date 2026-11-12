// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/pkg/kibana"
	"github.com/elastic/beats/v7/pkg/mapstr"
	"github.com/elastic/beats/v7/pkg/testing/estools"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/testing/integration"
)

const (
	completeWolfiImageEnv = "ELASTIC_AGENT_COMPLETE_WOLFI_IMAGE"

	// browserCADir is where the agent containers mount the CA directory, which
	// ELASTIC_AGENT_BROWSER_CA points at.
	browserCADir = "/etc/elastic-agent/browser-cas"
	// browserCAServerImage serves HTTPS as any non-root user.
	browserCAServerImage = "docker.io/nginxinc/nginx-unprivileged:1.27-alpine"
	// browserCAErr is how Chromium rejects a certificate signed by an unknown CA.
	browserCAErr = "ERR_CERT_AUTHORITY_INVALID"
)

// browserCAAgent is an Elastic Agent container that runs the browser monitor.
type browserCAAgent struct {
	name     string // e.g. "complete-root"
	root     bool
	policyID string
	runner   *HeartbeatRunner
}

// TestHeartbeatBrowserTrustsMountedCA runs a Fleet browser monitor from a private
// location against an HTTPS server signed by a test CA, on the complete and the
// complete-wolfi images, each as the image's non-root user and as root (Heartbeat
// then runs the browser as BEAT_SETUID_AS). Every agent mounts the same CA directory,
// set with ELASTIC_AGENT_BROWSER_CA: the monitor must be down with a certificate
// error without the CA, up once the CA is added and down again once it is removed,
// without restarting the agents.
func TestHeartbeatBrowserTrustsMountedCA(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.HeartbeatComplete,
		Stack: &define.Stack{},
		Local: false, // requires the elastic-agent-complete Docker images
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux, Arch: define.AMD64},
		},
	})

	images := map[string]string{
		"complete":       strings.TrimSpace(os.Getenv(completeImageEnv)),
		"complete-wolfi": strings.TrimSpace(os.Getenv(completeWolfiImageEnv)),
	}
	require.NotEmpty(t, images["complete"], "%s must be set", completeImageEnv)
	require.NotEmpty(t, images["complete-wolfi"], "%s must be set", completeWolfiImageEnv)

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Minute)
	defer cancel()

	testID := uuid.Must(uuid.NewV4()).String()
	shortID := testID[:8]

	// The agents share a network with the HTTPS server rather than the host network,
	// so that several can run at once without their ports colliding.
	network := "browser-ca-" + shortID
	out, err := dockerOutput(ctx, "network", "create", network)
	require.NoError(t, err, "creating Docker network: %s", out)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
		defer cleanupCancel()
		if out, err := dockerOutput(cleanupCtx, "network", "rm", network); err != nil {
			t.Logf("failed removing network %s: %v\n%s", network, err, out)
		}
	})

	server := "browser-ca-server-" + shortID
	caPEM := startBrowserCAServer(ctx, t, network, server)
	caDir := t.TempDir()
	require.NoError(t, os.Chmod(caDir, 0o755), "making the CA directory readable by the agents")

	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err, "getting default Fleet Server URL")

	// Each agent gets its own policy, and below its own private location: Synthetics
	// runs a monitor on only one agent of a location's policy.
	var agents []*browserCAAgent
	for _, variant := range []string{"complete", "complete-wolfi"} {
		for _, root := range []bool{false, true} {
			name := variant
			if root {
				name += "-root"
			}
			policy, err := info.KibanaClient.CreatePolicy(ctx, kibana.AgentPolicy{
				Name:        "browser-ca-" + name + "-" + testID,
				Namespace:   info.Namespace,
				Description: "Browser CA test policy " + testID,
				MonitoringEnabled: []kibana.MonitoringEnabledOption{
					kibana.MonitoringEnabledLogs,
				},
			})
			require.NoError(t, err, "creating the %s agent's Fleet policy", name)
			enrollmentToken, err := tools.CreateEnrollmentToken(t, ctx, info.KibanaClient, policy.ID)
			require.NoError(t, err, "creating the %s agent's enrollment token", name)
			a := &browserCAAgent{
				name:     name,
				root:     root,
				policyID: policy.ID,
				runner:   &HeartbeatRunner{info: info, containerName: "browser-ca-" + name + "-" + shortID},
			}
			startBrowserCAAgent(ctx, t, a, images[variant], network, caDir, fleetServerURL, enrollmentToken.APIKey)
			agents = append(agents, a)
		}
	}
	waitBrowserCAAgentsEnrolled(ctx, t, agents)

	// Kibana only sends browser monitors to agents reporting the complete image.
	var locations []string
	for _, a := range agents {
		location, err := createSyntheticsPrivateLocation(ctx, info.KibanaClient, "browser-ca-"+a.name+"-"+testID, a.policyID)
		require.NoError(t, err, "creating the %s agent's Synthetics private location", a.name)
		locations = append(locations, location)
	}
	require.NoError(t, createSyntheticsUIMonitor(ctx, info.KibanaClient, map[string]any{
		"type":              "browser",
		"name":              "browser-ca-monitor-" + testID,
		"enabled":           true,
		"private_locations": locations,
		"schedule":          1,
		"inline_script":     fmt.Sprintf(`step("load", async () => { await page.goto("https://%s:8443"); });`, server),
	}), "creating browser monitor")

	// Each phase depends on the previous one, so the first that fails stops the test.
	phases := []struct {
		name   string
		status string
		change func() error
	}{
		{name: "rejects the server without the CA", status: "down"},
		{name: "trusts the server once the CA is added", status: "up", change: func() error {
			return os.WriteFile(filepath.Join(caDir, "ca.crt"), caPEM, 0o644)
		}},
		{name: "rejects the server once the CA is removed", status: "down", change: func() error {
			return os.Remove(filepath.Join(caDir, "ca.crt"))
		}},
	}
	for _, phase := range phases {
		since := time.Now()
		if phase.change != nil {
			require.NoError(t, phase.change(), "%s: changing the CA directory", phase.name)
		}
		waitBrowserCAMonitors(ctx, t, info, agents, since, phase.status, phase.name)
		if phase.status != "up" {
			continue
		}
		for _, a := range agents {
			if !a.root {
				continue
			}
			// Heartbeat runs the browser as BEAT_SETUID_AS, which must read the store.
			out, err := dockerOutput(ctx, "exec", a.runner.containerName,
				"stat", "-c", "%U", "/usr/share/elastic-agent/.pki/nssdb/cert9.db")
			require.NoError(t, err, "checking the %s agent's browser trust store owner: %s", a.name, out)
			require.Equal(t, "elastic-agent", strings.TrimSpace(string(out)), "%s agent's trust store owner", a.name)
		}
	}
}

// budget returns d, or what is left of ctx when that is less, so that waits end
// with the test's deadline.
func budget(ctx context.Context, d time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		return max(min(d, time.Until(deadline)), 0)
	}
	return d
}

// startBrowserCAServer starts an HTTPS server on port 8443 of the network, named
// name, whose certificate a new CA signed. It returns that CA in PEM form.
func startBrowserCAServer(ctx context.Context, t *testing.T, network, name string) []byte {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating CA key")
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "elastic-agent browser CA test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err, "creating CA")
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err, "parsing CA")

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating server key")
	srvDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{name},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err, "creating server certificate")
	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	require.NoError(t, err, "encoding server key")

	// The server runs as a non-root user: everything it reads must be world-readable.
	confDir, tlsDir := t.TempDir(), t.TempDir()
	for path, content := range map[string][]byte{
		filepath.Join(confDir, "default.conf"): []byte(`server {
  listen 8443 ssl;
  ssl_certificate /etc/nginx/tls/tls.crt;
  ssl_certificate_key /etc/nginx/tls/tls.key;
  location / {
    default_type text/html;
    return 200 '<html><title>ok</title></html>';
  }
}
`),
		filepath.Join(tlsDir, "tls.crt"): pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		filepath.Join(tlsDir, "tls.key"): pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	} {
		require.NoError(t, os.WriteFile(path, content, 0o644), "writing %s", path)
		require.NoError(t, os.Chmod(path, 0o644), "making %s readable", path)
	}
	for _, dir := range []string{confDir, tlsDir} {
		require.NoError(t, os.Chmod(dir, 0o755), "making %s readable", dir)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
		defer cleanupCancel()
		if t.Failed() {
			out, _ := dockerOutput(cleanupCtx, "logs", name)
			t.Logf("HTTPS server logs:\n%s", out)
		}
		_, _ = dockerOutput(cleanupCtx, "rm", "-f", name)
	})
	out, err := dockerOutput(ctx, "run", "--detach", "--name", name, "--network", network,
		"-v", confDir+":/etc/nginx/conf.d:ro",
		"-v", tlsDir+":/etc/nginx/tls:ro",
		browserCAServerImage,
	)
	require.NoError(t, err, "starting the HTTPS server: %s", out)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// startBrowserCAAgent starts an agent container that enrolls in Fleet and trusts the
// CAs in caDir, checked for changes every 5 seconds.
func startBrowserCAAgent(ctx context.Context, t *testing.T, a *browserCAAgent, image, network, caDir, fleetServerURL, enrollmentToken string) {
	t.Helper()
	name := a.runner.containerName

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Minute)
		defer cleanupCancel()
		if t.Failed() {
			a.runner.collectContainerDiagnostics(cleanupCtx, t)
		}
		if out, err := dockerOutput(cleanupCtx, "rm", "-f", "-v", name); err != nil {
			t.Logf("failed removing container %s: %v\n%s", name, err, out)
		}
		if a.runner.agentID != "" {
			if err := fleettools.UnEnrollAgent(cleanupCtx, a.runner.info.KibanaClient, a.runner.agentID); err != nil {
				t.Logf("failed unenrolling agent %s: %v", a.runner.agentID, err)
			}
		}
	})

	args := []string{
		"run", "--detach",
		"--name", name,
		"--network", network,
		"-e", "FLEET_ENROLL=1",
		"-e", "FLEET_URL=" + fleetServerURL,
		"-e", "FLEET_ENROLLMENT_TOKEN=" + enrollmentToken,
		"-e", "ELASTIC_AGENT_BROWSER_CA=" + browserCADir,
		"-e", "ELASTIC_AGENT_BROWSER_CA_RELOAD_INTERVAL=5s",
		"-v", caDir + ":" + browserCADir + ":ro",
	}
	if a.root {
		args = append(args, "--user", "0")
	}
	out, err := dockerOutput(ctx, append(args, image)...)
	require.NoError(t, err, "starting %s agent container: %s", a.name, out)
}

// waitBrowserCAAgentsEnrolled waits until the agents are healthy, enrolled, and seen
// by Fleet as running the complete image, with one time budget for all of them.
func waitBrowserCAAgentsEnrolled(ctx context.Context, t *testing.T, agents []*browserCAAgent) {
	t.Helper()
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		for _, a := range agents {
			if a.runner.agentID != "" {
				continue
			}
			status, err := a.runner.execStatus(ctx)
			if !assert.NoError(collect, err, "getting %s agent status", a.name) {
				continue
			}
			if !assert.Equal(collect, cproto.State_HEALTHY, cproto.State(status.FleetState), //nolint:gosec // G115 always under 32-bit
				"expected the %s agent's Fleet state to be HEALTHY, got %s (message=%q)", a.name, cproto.State(status.FleetState), status.FleetMessage) || //nolint:gosec // G115 always under 32-bit
				!assert.Equal(collect, cproto.State_HEALTHY, cproto.State(status.State), //nolint:gosec // G115 always under 32-bit
					"expected the %s agent's state to be HEALTHY, got %s (message=%q)", a.name, cproto.State(status.State), status.Message) || //nolint:gosec // G115 always under 32-bit
				!assert.NotEmpty(collect, status.Info.ID, "expected the %s agent's ID to be non-empty", a.name) {
				continue
			}
			a.runner.agentID = status.Info.ID
		}
	}, budget(ctx, 6*time.Minute), 5*time.Second, "timed out waiting for the agents to enroll and become healthy")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		for _, a := range agents {
			agent, err := getFleetAgent(ctx, a.runner.info.KibanaClient, a.runner.agentID)
			if !assert.NoError(collect, err, "getting %s agent from Fleet", a.name) {
				continue
			}
			assert.True(collect, agent.Active, "expected the %s agent to be active in Fleet", a.name)
			assert.True(collect, agent.LocalMetadata.Elastic.Agent.Complete,
				"expected the %s agent's local_metadata.elastic.agent.complete to be true", a.name)
		}
	}, budget(ctx, 6*time.Minute), 5*time.Second, "Fleet did not observe complete metadata for every agent")
	for _, a := range agents {
		t.Logf("%s agent %s enrolled (container %s)", a.name, a.runner.agentID, a.runner.containerName)
	}
}

// waitBrowserCAMonitors waits until every agent's browser monitor reported status
// after since, with one time budget for all of them.
func waitBrowserCAMonitors(ctx context.Context, t *testing.T, info *define.Info, agents []*browserCAAgent, since time.Time, status, phase string) {
	t.Helper()
	pending := agents
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var still []*browserCAAgent
		for _, a := range pending {
			if err := browserCAMonitorResult(ctx, info, a, since, status); err != nil {
				assert.NoError(collect, err, "%s agent", a.name)
				still = append(still, a)
			}
		}
		pending = still
	}, budget(ctx, 10*time.Minute), 10*time.Second, "%s: not every agent's browser monitor reported %s", phase, status)
}

// browserCAMonitorResult checks for a browser monitor result of the agent, after
// since, with the given status. A "down" result must come from the browser rejecting
// the server's certificate, so that a server that isn't up yet can't pass for it.
func browserCAMonitorResult(ctx context.Context, info *define.Info, a *browserCAAgent, since time.Time, status string) error {
	after := map[string]any{"range": map[string]any{
		"@timestamp": map[string]any{"gte": since.UTC().Format("2006-01-02T15:04:05.000Z")},
	}}
	query := func(must ...map[string]any) map[string]any {
		return map[string]any{
			"query": map[string]any{"bool": map[string]any{
				"must":   append(must, map[string]any{"match": map[string]any{"agent.id": a.runner.agentID}}),
				"filter": after,
			}},
			"sort": []any{map[string]any{"@timestamp": map[string]any{"order": "desc"}}},
			"size": 50,
		}
	}

	res, err := estools.PerformQueryForRawQuery(ctx, query(
		map[string]any{"exists": map[string]any{"field": "summary"}},
		map[string]any{"term": map[string]any{"monitor.status": status}},
	), "synthetics-browser-*", info.ESClient)
	if err != nil {
		return fmt.Errorf("querying browser monitor results: %w", err)
	}
	if len(res.Hits.Hits) == 0 {
		return fmt.Errorf("no %s browser monitor result yet", status)
	}
	if status != "down" {
		return nil
	}

	res, err = estools.PerformQueryForRawQuery(ctx, query(
		map[string]any{"exists": map[string]any{"field": "error.message"}},
	), "synthetics-browser-*", info.ESClient)
	if err != nil {
		return fmt.Errorf("querying browser monitor errors: %w", err)
	}
	var messages []string
	for _, hit := range res.Hits.Hits {
		if msg, err := mapstr.M(hit.Source).GetValue("error.message"); err == nil {
			messages = append(messages, fmt.Sprint(msg))
		}
	}
	if !strings.Contains(strings.Join(messages, "\n"), browserCAErr) {
		return fmt.Errorf("expected the browser to reject the certificate with %s, got errors: %q", browserCAErr, messages)
	}
	return nil
}
