// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package comp

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"go.elastic.co/apm"
	apmtransport "go.elastic.co/apm/transport"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

var SenderAlreadyRunningError = errors.New("apm sender is already running")

type apmTracesSender struct {
	cfgUpd      chan *proto.APMConfig
	updateErrCh chan error
	ctx         context.Context
	ctxCancelF  context.CancelFunc
}

func (ats *apmTracesSender) Start(ctx context.Context, cfg *proto.APMConfig) error {
	if ats.ctx != nil && ats.ctx.Err() == nil {
		// the context is still running, we cannot start another
		return SenderAlreadyRunningError
	}

	ats.init(ctx)

	go ats.sendTracesLoop(cfg, time.Second, 100*time.Millisecond)
	return nil
}

func (ats *apmTracesSender) init(outerCtx context.Context) {
	ats.ctx, ats.ctxCancelF = context.WithCancel(outerCtx)
	ats.cfgUpd = make(chan *proto.APMConfig)
	ats.updateErrCh = make(chan error)
}

func (ats *apmTracesSender) cleanup() {
	if ats.ctxCancelF != nil {
		ats.ctxCancelF()
		ats.ctxCancelF = nil
	}

	ats.ctx = nil
	close(ats.cfgUpd)
	ats.cfgUpd = nil
	close(ats.updateErrCh)
	ats.updateErrCh = nil
}

func (ats *apmTracesSender) sendTracesLoop(initialCfg *proto.APMConfig, sendInterval time.Duration, traceDuration time.Duration) {
	tracer, err := ats.createNewTracer(initialCfg)
	if err != nil {
		ats.updateErrCh <- fmt.Errorf("error creating tracer from initial config: %w", err)
	}

	ticker := time.NewTicker(sendInterval)
	for {
		select {
		case <-ats.ctx.Done():
			return
		case <-ticker.C:
			ats.sendTrace(tracer, traceDuration)
		case updatedCfg := <-ats.cfgUpd:
			newTracer, err := ats.createNewTracer(updatedCfg)
			if err != nil {
				ats.updateErrCh <- fmt.Errorf("error creating tracer from config: %w", err)
				continue
			}
			if tracer != nil {
				tracer.Close()
			}
			tracer = newTracer
			ats.updateErrCh <- nil
		}
	}
}

func (ats *apmTracesSender) Update(cfg *proto.APMConfig, timeout time.Duration) error {
	select {
	case ats.cfgUpd <- cfg:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("config update timed out")
	}
}

func (ats *apmTracesSender) Stop() error {
	ats.cleanup()
	return nil
}

func (ats *apmTracesSender) createNewTracer(cfg *proto.APMConfig) (*apm.Tracer, error) {
	if cfg == nil {
		return nil, nil
	}

	const (
		envVerifyServerCert = "ELASTIC_APM_VERIFY_SERVER_CERT"
		envServerCert       = "ELASTIC_APM_SERVER_CERT"
		envCACert           = "ELASTIC_APM_SERVER_CA_CERT_FILE"
		envGlobalLabels     = "ELASTIC_APM_GLOBAL_LABELS"
	)
	if cfg.Elastic.Tls.SkipVerify {
		os.Setenv(envVerifyServerCert, "false")
		defer os.Unsetenv(envVerifyServerCert)
	}
	if cfg.Elastic.Tls.ServerCert != "" {
		os.Setenv(envServerCert, cfg.Elastic.Tls.ServerCert)
		defer os.Unsetenv(envServerCert)
	}
	if cfg.Elastic.Tls.ServerCa != "" {
		os.Setenv(envCACert, cfg.Elastic.Tls.ServerCa)
		defer os.Unsetenv(envCACert)
	}

	ts, err := apmtransport.NewHTTPTransport()
	if err != nil {
		return nil, err
	}

	if len(cfg.Elastic.Hosts) > 0 {
		hosts := make([]*url.URL, 0, len(cfg.Elastic.Hosts))
		for _, host := range cfg.Elastic.Hosts {
			u, err := url.Parse(host)
			if err != nil {
				return nil, fmt.Errorf("failed parsing %s: %w", host, err)
			}
			hosts = append(hosts, u)
		}
		ts.SetServerURL(hosts...)
	}
	if cfg.Elastic.ApiKey != "" {
		ts.SetAPIKey(cfg.Elastic.ApiKey)
	} else if cfg.Elastic.SecretToken != "" {
		ts.SetSecretToken(cfg.Elastic.SecretToken)
	}
	return apm.NewTracerOptions(apm.TracerOptions{
		ServiceName:        "fake-apm",
		ServiceVersion:     "0.1",
		ServiceEnvironment: cfg.Elastic.Environment,
		Transport:          ts,
	})
}

func (ats *apmTracesSender) sendTrace(tracer *apm.Tracer, duration time.Duration) {
	if tracer == nil {
		// no tracer configured, skip
		return
	}
	tx := tracer.StartTransaction("faketransaction", "request")
	defer tx.End()
	span := tx.StartSpan("spanName", "spanType", nil)
	defer span.End()
	time.Sleep(duration)
}

type fakeAPMInput struct {
	logger zerolog.Logger
	unit   *client.Unit
	sender *apmTracesSender
}

func (fai *fakeAPMInput) Unit() *client.Unit {
	return fai.unit
}
func (fai *fakeAPMInput) Update(u *client.Unit, triggers client.Trigger) error {
	if u.Expected().State == client.UnitStateStopped {
		fai.logger.Info().Msg("fakeAPMInput stopping APM sender")
		// stop apm trace sender
		return fai.sender.Stop()
	}

	if triggers&client.TriggeredAPMChange != client.TriggeredAPMChange {
		// no apm change, nothing to do
		return nil
	}

	fai.logger.Info().Msgf("Updating sender config with %+v", u.Expected().APMConfig)

	return fai.sender.Update(u.Expected().APMConfig, time.Second)
}

func newFakeAPMInput(logger zerolog.Logger, logLevel client.UnitLogLevel, unit *client.Unit) (*fakeAPMInput, error) {
	logger = logger.Level(toZerologLevel(logLevel))
	apmInput := &fakeAPMInput{
		logger: logger,
		unit:   unit,
		sender: new(apmTracesSender),
	}
	err := unit.UpdateState(client.UnitStateStarting, "Starting fake APM traces sender", nil)
	if err != nil {
		return apmInput, fmt.Errorf("error while setting starting state: %w", err)
	}
	err = apmInput.sender.Start(context.Background(), unit.Expected().APMConfig)
	if err != nil {
		return apmInput, fmt.Errorf("error starting apm tracer sender: %w", err)
	}
	go senderErrorLogger(apmInput.sender.ctx, logger, apmInput.sender.updateErrCh, unit)
	err = unit.UpdateState(client.UnitStateHealthy, "Fake APM traces sender has started", nil)
	if err != nil {
		return apmInput, fmt.Errorf("error while setting healthy state: %w", err)
	}
	return apmInput, err
}

func senderErrorLogger(ctx context.Context, logger zerolog.Logger, errCh <-chan error, unit *client.Unit) {
	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("context expired: senderErrorLogger exiting")
			return
		case err, ok := <-errCh:
			if !ok {
				logger.Info().Msg("error channel closed: senderErrorLogger exiting")
			}
			if err != nil {
				logger.Err(err).Msg("sender error")
				_ = unit.UpdateState(client.UnitStateDegraded, fmt.Sprintf("sender error: %s", err), nil)
			}
			_ = unit.UpdateState(client.UnitStateHealthy, fmt.Sprintf("sender error: %s", err), nil)
		}
	}
}
