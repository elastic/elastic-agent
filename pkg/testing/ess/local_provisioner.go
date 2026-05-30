// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/pkg/testing/common"
)

// ProvisionerLocal is the name of the local stack provisioner. It brings up a
// fully local Elastic Stack with the `elastic-package stack up` command instead of
// a cloud ESS deployment, so integration tests can run without cloud credentials.
const ProvisionerLocal = "local"

const (
	// localDefaultProfile is the dedicated elastic-package profile used for the
	// local integration-test stack, kept separate from the user's "default"
	// profile so this does not clobber a stack they may be running themselves.
	localDefaultProfile = "elastic-agent-integration"

	// localComposeProjectBase is the base docker compose project name
	// elastic-package uses for the stack (see internal/stack/boot.go in
	// elastic/elastic-package). The compose network is "<project>_default".
	localComposeProjectBase = "elastic-package-stack"
)

// The stack is reached from a test instance that has joined the stack's compose
// network, so it addresses the services by their compose service names. Those names
// are present in each service certificate's SANs (alongside localhost/127.0.0.1),
// so TLS hostname verification succeeds once the CA is trusted.
const (
	localElasticsearchURL = "https://elasticsearch:9200"
	localKibanaURL        = "https://kibana:5601"
	localFleetServerURL   = "https://fleet-server:8220"
)

// elastic-package shellinit environment variable names (see internal/stack/shellinit.go).
const (
	// epElasticsearchHostEnv is the host-published Elasticsearch URL (e.g.
	// https://127.0.0.1:9200). The Stack's Elasticsearch field uses the in-network
	// service name instead, so this is kept separately for host-side admin calls
	// the provisioner makes (e.g. relaxing cluster settings).
	epElasticsearchHostEnv     = "ELASTIC_PACKAGE_ELASTICSEARCH_HOST"
	epElasticsearchUsernameEnv = "ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME"
	epElasticsearchPasswordEnv = "ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD"
	epCACertEnv                = "ELASTIC_PACKAGE_CA_CERT"

	// epProfileEnv selects the elastic-package profile for every subcommand. It is
	// used instead of the --profile/-p flag because that flag is registered only on
	// some subcommands (e.g. it is absent on `profiles create`), and there is no
	// global -p flag.
	epProfileEnv = "ELASTIC_PACKAGE_PROFILE"
)

// LocalProvisioner provisions a local Elastic Stack using the elastic-package CLI.
type LocalProvisioner struct {
	logger  common.Logger
	bin     string
	profile string
}

// NewLocalProvisioner creates the local stack provisioner. It requires the
// elastic-package binary to be available (on PATH or via the ELASTIC_PACKAGE_BIN
// environment variable); the profile can be overridden with ELASTIC_PACKAGE_PROFILE.
func NewLocalProvisioner() (common.StackProvisioner, error) {
	bin := os.Getenv("ELASTIC_PACKAGE_BIN")
	if bin == "" {
		found, err := exec.LookPath("elastic-package")
		if err != nil {
			return nil, fmt.Errorf("the %q stack provisioner requires the elastic-package binary "+
				"(install it with `go install github.com/elastic/elastic-package@latest` or set ELASTIC_PACKAGE_BIN): %w",
				ProvisionerLocal, err)
		}
		bin = found
	}
	profile := os.Getenv("ELASTIC_PACKAGE_PROFILE")
	if profile == "" {
		profile = localDefaultProfile
	}
	return &LocalProvisioner{
		bin:     bin,
		profile: profile,
	}, nil
}

func (p *LocalProvisioner) Name() string {
	return ProvisionerLocal
}

func (p *LocalProvisioner) SetLogger(l common.Logger) {
	p.logger = l
}

// Create brings up the local stack and returns its connection details.
func (p *LocalProvisioner) Create(ctx context.Context, request common.StackRequest) (common.Stack, error) {
	if err := p.ensureProfile(ctx); err != nil {
		return common.Stack{}, err
	}

	p.logger.Logf("Bringing up local elastic-package stack %s (profile %q); this can take several minutes...",
		request.Version, p.profile)
	// `stack up` waits for all services to be healthy before returning, so a
	// generous timeout covers the initial image pulls on a cold machine.
	upCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if _, err := p.run(upCtx, "stack", "up", "-d", "--version", request.Version); err != nil {
		return common.Stack{}, fmt.Errorf("failed to bring up local stack: %w", err)
	}

	env, err := p.shellinit(ctx)
	if err != nil {
		return common.Stack{}, err
	}

	caCert, err := readCACert(env[epCACertEnv])
	if err != nil {
		return common.Stack{}, err
	}

	// The integration suites create a large number of data streams/indices, which
	// quickly trips a single-node cluster's defaults (disk watermarks leaving shards
	// unassigned, and the per-node shard cap), surfacing as 503
	// no_shard_available_action_exception during searches. Relax those for this
	// throwaway local stack. Best-effort: a failure here doesn't block the stack.
	if esHost := env[epElasticsearchHostEnv]; esHost != "" {
		p.logger.Logf("Relaxing local stack cluster settings (disk watermarks, max shards per node)")
		if err := applyLocalClusterSettings(ctx, esHost, env[epElasticsearchUsernameEnv], env[epElasticsearchPasswordEnv], caCert); err != nil {
			p.logger.Logf("WARNING: failed to relax local stack cluster settings; shard-heavy tests may fail: %s", err)
		}
	}

	return common.Stack{
		ID:                 request.ID,
		Provisioner:        p.Name(),
		Version:            request.Version,
		Elasticsearch:      localElasticsearchURL,
		Kibana:             localKibanaURL,
		IntegrationsServer: localFleetServerURL,
		Username:           env[epElasticsearchUsernameEnv],
		Password:           env[epElasticsearchPasswordEnv],
		CACert:             caCert,
		Internal: map[string]interface{}{
			// Consumed by the runner to join the test instance to the stack's
			// network (see common.InstanceNetworkAttacher).
			"network": p.networkName(),
			"profile": p.profile,
		},
		Ready: true,
	}, nil
}

// WaitForReady verifies the stack is healthy. `stack up` already blocks until the
// services are ready, so this is a lightweight confirmation via `stack status`.
func (p *LocalProvisioner) WaitForReady(ctx context.Context, stack common.Stack) (common.Stack, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := p.run(ctx, "stack", "status"); err != nil {
		return stack, fmt.Errorf("local stack is not healthy: %w", err)
	}
	stack.Ready = true
	return stack, nil
}

// Delete tears the local stack down.
func (p *LocalProvisioner) Delete(ctx context.Context, stack common.Stack) error {
	p.logger.Logf("Destroying local elastic-package stack (profile %q)", p.profile)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := p.run(ctx, "stack", "down"); err != nil {
		return fmt.Errorf("failed to destroy local stack: %w", err)
	}
	return nil
}

// Upgrade re-runs `stack up` at the new version.
func (p *LocalProvisioner) Upgrade(ctx context.Context, stack common.Stack, newVersion string) error {
	p.logger.Logf("Upgrading local elastic-package stack (profile %q) to %s", p.profile, newVersion)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if _, err := p.run(ctx, "stack", "up", "-d", "--version", newVersion); err != nil {
		return fmt.Errorf("failed to upgrade local stack: %w", err)
	}
	return nil
}

// networkName returns the docker compose network name backing the stack. The
// project name is "elastic-package-stack" for the default profile, or
// "elastic-package-stack-<profile>" otherwise; the network is "<project>_default".
func (p *LocalProvisioner) networkName() string {
	project := localComposeProjectBase
	if p.profile != "" && p.profile != "default" {
		project = localComposeProjectBase + "-" + p.profile
	}
	return project + "_default"
}

// ensureProfile creates the dedicated elastic-package profile if it does not
// already exist. Creating an existing profile is treated as success.
func (p *LocalProvisioner) ensureProfile(ctx context.Context) error {
	if p.profile == "default" {
		return nil // always exists
	}
	out, err := p.run(ctx, "profiles", "create", p.profile)
	if err != nil {
		if strings.Contains(out, "already exists") {
			return nil
		}
		return fmt.Errorf("failed to create elastic-package profile %q: %w", p.profile, err)
	}
	return nil
}

// shellinit runs `elastic-package stack shellinit` and parses the exported
// environment variables (lines of the form `export NAME=value`).
func (p *LocalProvisioner) shellinit(ctx context.Context) (map[string]string, error) {
	out, err := p.run(ctx, "stack", "shellinit", "--shell", "bash")
	if err != nil {
		return nil, fmt.Errorf("failed to read stack shellinit: %w", err)
	}
	return parseShellinit(out), nil
}

// parseShellinit parses `elastic-package stack shellinit` output, which is a list of
// `export NAME=value` lines (POSIX shell format), into a name→value map.
func parseShellinit(out string) map[string]string {
	env := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimPrefix(line, "export ")
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[strings.TrimSpace(name)] = strings.Trim(value, `"'`)
	}
	return env
}

// command builds the elastic-package command for the given arguments, selecting the
// configured profile via the ELASTIC_PACKAGE_PROFILE environment variable.
func (p *LocalProvisioner) command(ctx context.Context, args ...string) *exec.Cmd {
	//nolint:gosec // G204: p.bin is the elastic-package binary resolved by the test framework and args are framework-controlled, not external input.
	cmd := exec.CommandContext(ctx, p.bin, args...)
	cmd.Env = append(os.Environ(), epProfileEnv+"="+p.profile)
	return cmd
}

// run executes the elastic-package binary with the configured profile, streaming
// its output to the logger and also returning it (for parsing/error inspection).
func (p *LocalProvisioner) run(ctx context.Context, args ...string) (string, error) {
	cmd := p.command(ctx, args...)

	var buf bytes.Buffer
	ll := &lineLogger{logger: p.logger}
	w := io.MultiWriter(&buf, ll)
	cmd.Stdout = w
	cmd.Stderr = w

	err := cmd.Run()
	ll.flush()
	if err != nil {
		return buf.String(), fmt.Errorf("elastic-package %s failed: %w (output: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(buf.String()))
	}
	return buf.String(), nil
}

// localClusterSettings is the persistent cluster settings body applied to the
// local stack. It disables disk-based shard allocation thresholds (a single-node
// dev cluster easily crosses the watermarks, leaving shards unassigned) and raises
// the per-node shard cap (the suites create many data streams).
const localClusterSettings = `{"persistent":{` +
	`"cluster.routing.allocation.disk.threshold_enabled":false,` +
	`"cluster.max_shards_per_node":3000}}`

// applyLocalClusterSettings PUTs localClusterSettings to the stack's Elasticsearch.
// The CA (PEM) is trusted for the request; if it cannot be parsed the request falls
// back to skipping verification, which is acceptable for a local stack on loopback.
func applyLocalClusterSettings(ctx context.Context, esURL, username, password, caPEM string) error {
	pool := x509.NewCertPool()
	insecure := !pool.AppendCertsFromPEM([]byte(caPEM))
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            pool,
				InsecureSkipVerify: insecure, //nolint:gosec // local self-signed stack reached over loopback
			},
		},
	}

	url := strings.TrimRight(esURL, "/") + "/_cluster/settings"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(localClusterSettings))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// readCACert reads the PEM contents of the CA certificate at the given path.
func readCACert(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("elastic-package shellinit did not report a CA certificate path (%s)", epCACertEnv)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read elastic-package CA certificate %q: %w", path, err)
	}
	return string(b), nil
}

// lineLogger buffers bytes written to it and emits whole lines to the logger, so
// the streamed elastic-package output appears as tidy per-line log entries.
type lineLogger struct {
	logger common.Logger
	buf    bytes.Buffer
}

func (l *lineLogger) Write(p []byte) (int, error) {
	l.buf.Write(p)
	for {
		line, err := l.buf.ReadString('\n')
		if err != nil {
			// no full line yet; put the partial back for the next write
			l.buf.WriteString(line)
			break
		}
		if s := strings.TrimRight(line, "\r\n"); s != "" && l.logger != nil {
			l.logger.Logf("%s", s)
		}
	}
	//nolint:nilerr // a non-nil ReadString error just means no complete line yet; all bytes were buffered, so the write succeeded.
	return len(p), nil
}

func (l *lineLogger) flush() {
	if s := strings.TrimSpace(l.buf.String()); s != "" && l.logger != nil {
		l.logger.Logf("%s", s)
	}
	l.buf.Reset()
}
