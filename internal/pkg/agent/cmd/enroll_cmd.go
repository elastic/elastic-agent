// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"go.elastic.co/apm/v2"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/enroll"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/client/wait"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	maxRetriesstoreAgentInfo       = 5
	waitingForAgent                = "Waiting for Elastic Agent to start"
	waitingForFleetServer          = "Waiting for Elastic Agent to start Fleet Server"
	defaultFleetServerHost         = "0.0.0.0"
	defaultFleetServerPort         = 8220
	defaultFleetServerInternalHost = "localhost"
	defaultFleetServerInternalPort = 8221
)

var (
	enrollDelay   = 1 * time.Second  // max delay to start enrollment
	daemonTimeout = 30 * time.Second // max amount of for communication to running Agent daemon
)

type saver interface {
	Save(io.Reader) error
}

// enrollCmd is an enroll subcommand that interacts between the Kibana API and the Agent.
type enrollCmd struct {
	log            *logger.Logger
	options        *enroll.EnrollOptions
	configStore    saver
	remoteConfig   remote.Config
	agentProc      *process.Info
	configPath     string
	backoffFactory func(done <-chan struct{}) backoff.Backoff

	// For testability
	daemonReloadFunc func(context.Context) error
}

// newEnrollCmd creates a new enrollment with the given store.
func newEnrollCmd(
	log *logger.Logger,
	options *enroll.EnrollOptions,
	configPath string,
	store saver,
	backoffFactory func(done <-chan struct{}) backoff.Backoff,
) (*enrollCmd, error) {
	if backoffFactory == nil {
		backoffFactory = func(done <-chan struct{}) backoff.Backoff {
			return backoff.NewEqualJitterBackoff(done, enroll.EnrollBackoffInit, enroll.EnrollBackoffMax)
		}
	}
	return &enrollCmd{
		log:              log,
		options:          options,
		configStore:      store,
		configPath:       configPath,
		daemonReloadFunc: daemonReload,
		backoffFactory:   backoffFactory,
	}, nil
}

// Execute enrolls the agent into Fleet.
func (c *enrollCmd) Execute(ctx context.Context, streams *cli.IOStreams) error {
	var err error
	defer c.stopAgent() // ensure its stopped no matter what

	span, ctx := apm.StartSpan(ctx, "enroll", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	hasRoot, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("checking if running with root/Administrator privileges: %w", err)
	}

	// Create encryption key from the agent before touching configuration
	if !c.options.SkipCreateSecret {
		opts := []vault.OptionFunc{vault.WithUnprivileged(!hasRoot)}
		if c.options.FixPermissions != nil {
			opts = append(opts, vault.WithVaultOwnership(*c.options.FixPermissions))
		}
		err = secret.CreateAgentSecret(ctx, opts...)
		if err != nil {
			return err
		}
	}

	persistentConfig, err := enroll.LoadPersistentConfig(c.configPath)
	if err != nil {
		return err
	}

	// localFleetServer indicates that we start our internal fleet server. Agent
	// will communicate to the internal fleet server on localhost only.
	// Connection setup should disable proxies in that case.
	localFleetServer := c.options.FleetServer.ConnStr != ""
	if localFleetServer && !c.options.DelayEnroll {
		token, err := c.fleetServerBootstrap(ctx, persistentConfig)
		if err != nil {
			return err
		}
		if c.options.EnrollAPIKey == "" && token != "" {
			c.options.EnrollAPIKey = token
		}
	}

	c.remoteConfig, err = c.options.RemoteConfig(true)
	if err != nil {
		return errors.New(
			err, "Error",
			errors.TypeConfig,
			errors.M(errors.MetaKeyURI, c.options.URL))
	}
	if localFleetServer {
		// Ensure that the agent does not use a proxy configuration
		// when connecting to the local fleet server.
		// Note that when running fleet-server the enroll request will be sent to :8220,
		// however when the agent is running afterward requests will be sent to :8221
		c.remoteConfig.Transport.Proxy.Disable = true
	}

	if c.options.DelayEnroll {
		if c.options.FleetServer.Host != "" {
			return errors.New("--delay-enroll cannot be used with --fleet-server-es", errors.TypeConfig)
		}
		err = c.writeDelayEnroll(streams)
		if err != nil {
			// context for error already provided in writeDelayEnroll
			return err
		}
		if c.options.FixPermissions != nil {
			err = perms.FixPermissions(paths.Top(), perms.WithOwnership(*c.options.FixPermissions))
			if err != nil {
				return errors.New(err, "failed to fix permissions")
			}
		}
		return nil
	}

	err = enroll.EnrollWithBackoff(ctx, c.log,
		persistentConfig,
		enrollDelay,
		*c.options,
		c.configStore,
		c.backoffFactory)
	if err != nil {
		return fmt.Errorf("fail to enroll: %w", err)
	}

	if c.options.FixPermissions != nil {
		err = perms.FixPermissions(paths.Top(), perms.WithOwnership(*c.options.FixPermissions))
		if err != nil {
			return errors.New(err, "failed to fix permissions")
		}
	}

	defer func() {
		if err != nil {
			fmt.Fprintf(streams.Err, "Something went wrong while enrolling the Elastic Agent: %v\n", err)
		} else {
			fmt.Fprintln(streams.Out, "Successfully enrolled the Elastic Agent.")
		}
	}()

	if c.agentProc == nil && !c.options.SkipDaemonRestart {
		if err = c.daemonReloadWithBackoff(ctx); err != nil {
			c.log.Errorf("Elastic Agent might not be running; unable to trigger restart: %v", err)
			return fmt.Errorf("could not reload agent daemon, unable to trigger restart: %w", err)
		}

		c.log.Info("Successfully triggered restart on running Elastic Agent.")
		return nil
	}

	c.log.Info("Elastic Agent has been enrolled; start Elastic Agent")
	return nil
}

func (c *enrollCmd) writeDelayEnroll(streams *cli.IOStreams) error {
	enrollPath := paths.AgentEnrollFile()
	data, err := yaml.Marshal(c.options)
	if err != nil {
		return errors.New(
			err,
			"failed to marshall enrollment options",
			errors.TypeConfig,
			errors.M("path", enrollPath))
	}
	err = os.WriteFile(enrollPath, data, 0600)
	if err != nil {
		return errors.New(
			err,
			"failed to write enrollment options file",
			errors.TypeFilesystem,
			errors.M("path", enrollPath))
	}
	fmt.Fprintf(streams.Out, "Successfully wrote %s for delayed enrollment of the Elastic Agent.\n", enrollPath)
	return nil
}

func (c *enrollCmd) fleetServerBootstrap(ctx context.Context, persistentConfig map[string]interface{}) (string, error) {
	c.log.Debug("verifying communication with running Elastic Agent daemon")
	agentRunning := true
	if c.options.FleetServer.InternalPort == 0 {
		c.options.FleetServer.InternalPort = defaultFleetServerInternalPort
	}
	_, err := getDaemonState(ctx)
	if err != nil {
		if !c.options.FleetServer.SpawnAgent {
			// wait longer to try and communicate with the Elastic Agent
			err = wait.ForAgent(ctx, c.options.DaemonTimeout)
			if err != nil {
				return "", errors.New("failed to communicate with elastic-agent daemon; is elastic-agent running?")
			}
		} else {
			agentRunning = false
		}
	}

	err = c.prepareFleetTLS()
	if err != nil {
		return "", err
	}

	agentConfig := enroll.CreateAgentConfig("", persistentConfig, c.options.FleetServer.Headers, c.options.Staging)

	//nolint:dupl // duplicate because same params are passed
	fleetConfig, err := enroll.CreateFleetServerBootstrapConfig(
		c.options.FleetServer.ConnStr, c.options.FleetServer.ServiceToken, c.options.FleetServer.ServiceTokenPath,
		c.options.FleetServer.PolicyID,
		c.options.FleetServer.Host, c.options.FleetServer.Port, c.options.FleetServer.InternalPort,
		c.options.FleetServer.Cert, c.options.FleetServer.CertKey, c.options.FleetServer.CertKeyPassphrasePath, c.options.FleetServer.ElasticsearchCA, c.options.FleetServer.ElasticsearchCASHA256,
		c.options.CAs, c.options.FleetServer.ClientAuth,
		c.options.FleetServer.ElasticsearchCert, c.options.FleetServer.ElasticsearchCertKey,
		c.options.FleetServer.Headers,
		c.options.ProxyURL,
		c.options.ProxyDisabled,
		c.options.ProxyHeaders,
		c.options.FleetServer.ElasticsearchInsecure,
	)
	if err != nil {
		return "", err
	}
	c.options.FleetServer.InternalPort = fleetConfig.Server.InternalPort

	configToStore := map[string]interface{}{
		"agent": agentConfig,
		"fleet": fleetConfig,
	}
	reader, err := yamlToReader(configToStore)
	if err != nil {
		return "", err
	}

	if err := enroll.SafelyStoreAgentInfo(c.configStore, reader); err != nil {
		return "", err
	}

	var agentSubproc <-chan *os.ProcessState
	if agentRunning {
		// reload the already running agent
		err = c.daemonReloadWithBackoff(ctx)
		if err != nil {
			return "", errors.New(err, "failed to trigger elastic-agent daemon reload", errors.TypeApplication)
		}
	} else {
		// spawn `run` as a subprocess so enroll can perform the bootstrap process of Fleet Server
		agentSubproc, err = c.startAgent(ctx)
		if err != nil {
			return "", err
		}
	}

	token, err := waitForFleetServer(ctx, agentSubproc, c.log, c.options.FleetServer.Timeout)
	if err != nil {
		return "", errors.New(err, "fleet-server failed", errors.TypeApplication)
	}
	return token, nil
}

func (c *enrollCmd) prepareFleetTLS() error {
	host := c.options.FleetServer.Host
	if host == "" {
		host = defaultFleetServerInternalHost
	}
	port := c.options.FleetServer.Port
	if port == 0 {
		port = defaultFleetServerPort
	}
	if c.options.FleetServer.Cert != "" && c.options.FleetServer.CertKey == "" {
		return errors.New("certificate private key is required when certificate provided")
	}
	if c.options.FleetServer.CertKey != "" && c.options.FleetServer.Cert == "" {
		return errors.New("certificate is required when certificate private key is provided")
	}
	if c.options.FleetServer.Cert == "" && c.options.FleetServer.CertKey == "" {
		if c.options.FleetServer.Insecure {
			// running insecure, force the binding to localhost (unless specified)
			if c.options.FleetServer.Host == "" {
				c.options.FleetServer.Host = defaultFleetServerInternalHost
			}
			c.options.URL = "http://" + net.JoinHostPort(host, strconv.Itoa(int(port)))
			c.options.Insecure = true
			return nil
		}

		c.log.Info("Generating self-signed certificate for Fleet Server")
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		ca, err := authority.NewCA()
		if err != nil {
			return err
		}
		pair, err := ca.GeneratePairWithName(hostname)
		if err != nil {
			return err
		}
		c.options.FleetServer.Cert = string(pair.Crt)
		c.options.FleetServer.CertKey = string(pair.Key)
		c.options.URL = "https://" + net.JoinHostPort(hostname, strconv.Itoa(int(port)))
		c.options.CAs = []string{string(ca.Crt())}
	}
	// running with custom Cert and CertKey; URL is required to be set
	if c.options.URL == "" {
		return errors.New("url is required when a certificate is provided")
	}

	if c.options.FleetServer.InternalPort > 0 {
		if c.options.FleetServer.InternalPort != defaultFleetServerInternalPort {
			c.log.Warnf("Internal endpoint configured to: %d. Changing this value is not supported.", c.options.FleetServer.InternalPort)
		}
		c.options.InternalURL = net.JoinHostPort(defaultFleetServerInternalHost, strconv.Itoa(int(c.options.FleetServer.InternalPort)))
	}

	return nil
}

const (
	daemonReloadInitBackoff = time.Second
	daemonReloadMaxBackoff  = time.Minute
	daemonReloadRetries     = 5
)

func (c *enrollCmd) daemonReloadWithBackoff(ctx context.Context) error {
	backExp := backoff.NewExpBackoff(ctx.Done(), daemonReloadInitBackoff, daemonReloadMaxBackoff)

	var lastErr error
	for i := 0; i < daemonReloadRetries; i++ {
		attempt := i

		c.log.Infof("Restarting agent daemon, attempt %d", attempt)
		err := c.daemonReloadFunc(ctx)
		if err == nil {
			return nil
		}

		// If the context was cancelled, return early
		if errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, context.Canceled) {
			return fmt.Errorf("could not reload daemon after %d retries: %w",
				attempt, err)
		}
		lastErr = err

		c.log.Errorf("Restart attempt %d failed: '%s'. Waiting for %s", attempt, err, backExp.NextWait().String())
		// backoff Wait returns false if context.Done()
		if !backExp.Wait() {
			return ctx.Err()
		}
	}

	return fmt.Errorf("could not reload agent's daemon, all retries failed. Last error: %w", lastErr)
}

func daemonReload(ctx context.Context) error {
	daemon := client.New()
	err := daemon.Connect(ctx)
	if err != nil {
		return err
	}
	defer daemon.Disconnect()
	return daemon.Restart(ctx)
}

func (c *enrollCmd) startAgent(ctx context.Context) (<-chan *os.ProcessState, error) {
	cmd, err := os.Executable()
	if err != nil {
		return nil, err
	}
	c.log.Info("Spawning Elastic Agent daemon as a subprocess to complete bootstrap process.")
	args := []string{
		"run", "-e", "-c", paths.ConfigFile(),
		"--path.home", paths.Top(), "--path.config", paths.Config(),
		"--path.logs", paths.Logs(), "--path.socket", paths.ControlSocket(),
	}
	if paths.Downloads() != "" {
		args = append(args, "--path.downloads", paths.Downloads())
	}
	if !paths.IsVersionHome() {
		args = append(args, "--path.home.unversioned")
	}
	proc, err := process.Start(
		cmd,
		process.WithContext(ctx),
		process.WithArgs(args),
		process.WithCmdOptions(func(c *exec.Cmd) error {
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			return nil
		}))
	if err != nil {
		return nil, err
	}
	resChan := make(chan *os.ProcessState)
	go func() {
		procState, _ := proc.Process.Wait()
		resChan <- procState
	}()
	c.agentProc = proc
	return resChan, nil
}

func (c *enrollCmd) stopAgent() {
	if c.agentProc != nil {
		_ = c.agentProc.StopWait()
		c.agentProc = nil
	}
}

func yamlToReader(in interface{}) (io.Reader, error) {
	data, err := yaml.Marshal(in)
	if err != nil {
		return nil, errors.New(err, "could not marshal to YAML")
	}
	return bytes.NewReader(data), nil
}

func getDaemonState(ctx context.Context) (*client.AgentState, error) {
	ctx, cancel := context.WithTimeout(ctx, daemonTimeout)
	defer cancel()
	daemon := client.New()
	err := daemon.Connect(ctx)
	if err != nil {
		return nil, err
	}
	defer daemon.Disconnect()
	return daemon.State(ctx)
}

type waitResult struct {
	enrollmentToken string
	err             error
}

func waitForFleetServer(ctx context.Context, agentSubproc <-chan *os.ProcessState, log *logger.Logger, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	maxBackoff := timeout
	if maxBackoff <= 0 {
		// indefinite timeout
		maxBackoff = 10 * time.Minute
	}

	resChan := make(chan waitResult)
	innerCtx, innerCancel := context.WithCancel(context.Background())
	defer innerCancel()
	go func() {
		msg := ""
		msgCount := 0
		backExp := expBackoffWithContext(innerCtx, 1*time.Second, maxBackoff)

		for {
			// if the timeout is reached, no response was sent on `res`, therefore
			// send an error
			if !backExp.Wait() {
				resChan <- waitResult{err: fmt.Errorf(
					"timed out waiting for Fleet Server to start after %s",
					timeout)}
			}

			state, err := getDaemonState(innerCtx)
			if errors.Is(err, context.Canceled) {
				resChan <- waitResult{err: err}
				return
			}
			if err != nil {
				log.Debugf("%s: %s", waitingForAgent, err)
				if msg != waitingForAgent {
					msg = waitingForAgent
					msgCount = 0
					log.Info(waitingForAgent)
				} else {
					msgCount++
					if msgCount > 5 {
						msgCount = 0
						log.Infof("%s: %s", waitingForAgent, err)
					}
				}
				continue
			}
			unit := getCompUnitFromStatus(state, "fleet-server")
			if unit == nil {
				err = errors.New("no fleet-server application running")
				log.Debugf("%s: %s", waitingForFleetServer, err)
				if msg != waitingForFleetServer {
					msg = waitingForFleetServer
					msgCount = 0
					log.Info(waitingForFleetServer)
				} else {
					msgCount++
					if msgCount > 5 {
						msgCount = 0
						log.Infof("%s: %s", waitingForFleetServer, err)
					}
				}
				continue
			}
			log.Debugf("%s: %s - %s", waitingForFleetServer, unit.State, unit.Message)
			if unit.State == client.Degraded || unit.State == client.Healthy {
				// app has started and is running
				if unit.Message != "" {
					log.Infof("Fleet Server - %s", unit.Message)
				}
				// extract the enrollment token from the status payload
				token := ""
				if unit.Payload != nil {
					if enrollToken, ok := unit.Payload["enrollment_token"]; ok {
						if tokenStr, ok := enrollToken.(string); ok {
							token = tokenStr
						}
					}
				}
				resChan <- waitResult{enrollmentToken: token}
				break
			}
			if unit.Message != "" {
				appMsg := fmt.Sprintf("Fleet Server - %s", unit.Message)
				if msg != appMsg {
					msg = appMsg
					msgCount = 0
					log.Info(appMsg)
				} else {
					msgCount++
					if msgCount > 5 {
						msgCount = 0
						log.Info(appMsg)
					}
				}
			}
		}
	}()

	var res waitResult
	if agentSubproc == nil {
		select {
		case <-ctx.Done():
			innerCancel()
			res = <-resChan
		case res = <-resChan:
		}
	} else {
		select {
		case ps := <-agentSubproc:
			res = waitResult{err: fmt.Errorf("spawned Elastic Agent exited unexpectedly: %s", ps)}
		case <-ctx.Done():
			innerCancel()
			res = <-resChan
		case res = <-resChan:
		}
	}

	if res.err != nil {
		return "", res.err
	}
	return res.enrollmentToken, nil
}

func getCompUnitFromStatus(state *client.AgentState, name string) *client.ComponentUnitState {
	for _, comp := range state.Components {
		if comp.Name == name {
			for _, unit := range comp.Units {
				if unit.UnitType == client.UnitTypeInput {
					return &unit
				}
			}
		}
	}
	return nil
}

func expBackoffWithContext(ctx context.Context, init, max time.Duration) backoff.Backoff {
	signal := make(chan struct{})
	bo := backoff.NewExpBackoff(signal, init, max)
	go func() {
		<-ctx.Done()
		close(signal)
	}()
	return bo
}
