// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleet

import (
	"context"
	stderrors "errors"
	"sync"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"

	eaclient "github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/internal/pkg/scheduler"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Max number of times an invalid API Key is checked
const maxUnauthCounter int = 6

// Consts for states at fleet checkin
const (
	fleetStateDegraded = "DEGRADED"
	fleetStateOnline   = "online"
	fleetStateError    = "error"
	fleetStateStarting = "starting"
)

// Default backoff settings for connecting to Fleet
var defaultFleetBackoffSettings = backoffSettings{
	Init: 60 * time.Second,
	Max:  10 * time.Minute,
}

// Default Configuration for the Fleet Gateway.
var defaultGatewaySettings = &fleetGatewaySettings{
	Duration:                     1 * time.Second,        // time between successful calls
	Jitter:                       500 * time.Millisecond, // used as a jitter for duration
	ErrConsecutiveUnauthDuration: 1 * time.Hour,          // time between calls when the agent exceeds unauthorized response limit
	Backoff:                      &defaultFleetBackoffSettings,
}

type fleetGatewaySettings struct {
	Duration                     time.Duration    `config:"checkin_frequency"`
	Jitter                       time.Duration    `config:"jitter"`
	Backoff                      *backoffSettings `config:"backoff"`
	ErrConsecutiveUnauthDuration time.Duration
}

type backoffSettings struct {
	Init time.Duration `config:"init"`
	Max  time.Duration `config:"max"`
}

type agentInfo interface {
	AgentID() string
}

type stateStore interface {
	AckToken() string
	SetAckToken(ackToken string)
	Save() error
	Action() fleetapi.Action
}

type rollbacksSource interface {
	Get() (map[string]ttl.TTLMarker, error)
}

type FleetGateway struct {
	log                *logger.Logger
	client             client.Sender
	scheduler          scheduler.Scheduler
	settings           *fleetGatewaySettings
	agentInfo          agentInfo
	acker              acker.Acker
	unauthCounter      int
	checkinFailCounter int
	stateStore         stateStore
	stateFetcher       StateFetcher
	errCh              chan error
	actionCh           chan []fleetapi.Action
	rollbackSource     rollbacksSource
}

// New creates a new fleet gateway
func New(
	log *logger.Logger,
	agentInfo agentInfo,
	client client.Sender,
	acker acker.Acker,
	stateStore stateStore,
	stateFetcher StateFetcher,
	cfg *configuration.FleetCheckin,
	source rollbacksSource,
) (*FleetGateway, error) {
	scheduler := scheduler.NewPeriodicJitter(defaultGatewaySettings.Duration, defaultGatewaySettings.Jitter)
	st := defaultGatewaySettings
	st.Backoff = getBackoffSettings(cfg)
	return newFleetGatewayWithScheduler(
		log,
		st,
		agentInfo,
		client,
		scheduler,
		acker,
		stateStore,
		stateFetcher,
		source,
	)
}

func newFleetGatewayWithScheduler(
	log *logger.Logger,
	settings *fleetGatewaySettings,
	agentInfo agentInfo,
	client client.Sender,
	scheduler scheduler.Scheduler,
	acker acker.Acker,
	stateStore stateStore,
	stateFetcher StateFetcher,
	source rollbacksSource,
) (*FleetGateway, error) {
	return &FleetGateway{
		log:            log,
		client:         client,
		settings:       settings,
		agentInfo:      agentInfo,
		scheduler:      scheduler,
		acker:          acker,
		stateFetcher:   stateFetcher,
		stateStore:     stateStore,
		errCh:          make(chan error),
		actionCh:       make(chan []fleetapi.Action, 1),
		rollbackSource: source,
	}, nil
}

func (f *FleetGateway) Actions() <-chan []fleetapi.Action {
	return f.actionCh
}

func (f *FleetGateway) Run(ctx context.Context) error {
	var requestBackoff backoff.Backoff
	if f.settings.Backoff == nil {
		requestBackoff = RequestBackoff(ctx.Done())
	} else {
		requestBackoff = backoff.NewEqualJitterBackoff(
			ctx.Done(),
			f.settings.Backoff.Init,
			f.settings.Backoff.Max,
		)
	}

	f.log.Info("Fleet gateway started")
	for {
		select {
		case <-ctx.Done():
			f.scheduler.Stop()
			f.log.Info("Fleet gateway stopped")
			return ctx.Err()
		case <-f.scheduler.WaitTick():
			f.log.Debug("FleetGateway calling Checkin API")

			// Execute the checkin call and for any errors returned by the fleet-server API
			// the function will retry to communicate with fleet-server with an exponential delay and some
			// jitter to help better distribute the load from a fleet of agents.
			resp, err := f.doExecute(ctx, requestBackoff)
			if err != nil {
				continue
			}

			actions := make([]fleetapi.Action, len(resp.Actions))
			copy(actions, resp.Actions)
			if len(actions) > 0 {
				f.actionCh <- actions
			}
		}
	}
}

// Errors returns the channel to watch for reported errors.
func (f *FleetGateway) Errors() <-chan error {
	return f.errCh
}

func (f *FleetGateway) doExecute(ctx context.Context, bo backoff.Backoff) (*fleetapi.CheckinResponse, error) {
	bo.Reset()

	// Guard if the context is stopped by a out of bound call,
	// this mean we are rebooting to change the log level or the system is shutting us down.
	for ctx.Err() == nil {
		f.log.Debugf("Checking started")
		resp, took, err := f.execute(ctx)
		if err != nil {
			becauseOfStateChanged := errors.Is(err, errComponentStateChanged)

			// don't count that as failed attempt
			if !becauseOfStateChanged {
				f.checkinFailCounter++
			}

			warnMsg := "Possible transient error during checkin with fleet-server, retrying"
			if becauseOfStateChanged {
				warnMsg = "Check in cancelled because of state change, retrying"
			}
			// Report the first two failures at warn level as they may be recoverable with retries.
			if f.checkinFailCounter <= 2 {
				f.log.Warnw(warnMsg,
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter,
					"retry_after_ns", bo.NextWait())
			} else {
				f.log.Errorw("Cannot checkin in with fleet-server, retrying",
					"error.message", err, "request_duration_ns", took, "failed_checkins", f.checkinFailCounter,
					"retry_after_ns", bo.NextWait())
			}

			if !bo.Wait() {
				if ctx.Err() != nil {
					// if the context is cancelled, break out of the loop
					break
				}

				// This should not really happen, but just in-case this error is used to show that
				// something strange occurred and we want to log it and report it.
				err := errors.New(
					"checkin retry loop was stopped",
					errors.TypeNetwork,
					errors.M(errors.MetaKeyURI, f.client.URI()),
				)

				f.log.Error(err)
				f.errCh <- err
				return nil, err
			}
			f.errCh <- err
			continue
		}

		if f.checkinFailCounter > 0 {
			// Log at same level as error logs above so subsequent successes are visible when log level is set to 'error'.
			f.log.Warnf("Checkin request to fleet-server succeeded after %d failures", f.checkinFailCounter)
		}

		f.checkinFailCounter = 0
		if resp.FleetWarning != "" {
			f.errCh <- coordinator.NewWarningError(resp.FleetWarning)
		} else {
			f.errCh <- nil
		}

		// Request was successful, return the collected actions.
		return resp, nil
	}

	// This mean that the next loop was cancelled because of the context, we should return the error
	// but we should not log it, because we are in the process of shutting down.
	return nil, ctx.Err()
}

func convertToCheckinComponents(logger *logp.Logger, components []runtime.ComponentComponentState, collector *status.AggregateStatus) []fleetapi.CheckinComponent {
	if components == nil && (collector == nil || len(collector.ComponentStatusMap) == 0) {
		return nil
	}
	stateString := func(s eaclient.UnitState) string {
		if state := s.String(); state != "UNKNOWN" {
			return state
		}
		return ""
	}

	unitTypeString := func(t eaclient.UnitType) string {
		if typ := t.String(); typ != "unknown" {
			return typ
		}
		return ""
	}

	otelComponentTypeString := func(componentStatusId string) string {
		kind, _, err := translate.ParseEntityStatusId(componentStatusId)
		if err != nil {
			logger.Warnf("failed to parse component status id '%s': %v", componentStatusId, err)
			return ""
		}
		switch kind {
		case "receiver":
			return "input"
		case "exporter":
			return "output"
		}
		return ""
	}

	size := len(components)
	if collector != nil {
		size += len(collector.ComponentStatusMap)
	}
	checkinComponents := make([]fleetapi.CheckinComponent, 0, size)

	for _, item := range components {
		component := item.Component
		state := item.State

		checkinComponent := fleetapi.CheckinComponent{
			ID:      component.ID,
			Type:    component.Type(),
			Status:  stateString(state.State),
			Message: state.Message,
		}

		if state.Units != nil {
			units := make([]fleetapi.CheckinUnit, 0, len(state.Units))

			for unitKey, unitState := range state.Units {
				units = append(units, fleetapi.CheckinUnit{
					ID:      unitKey.UnitID,
					Type:    unitTypeString(unitKey.UnitType),
					Status:  stateString(unitState.State),
					Message: unitState.Message,
					Payload: unitState.Payload,
				})
			}
			checkinComponent.Units = units
		}
		checkinComponents = append(checkinComponents, checkinComponent)
	}

	// OTel status is placed as a component for each top-level component in OTel
	// and each subcomponent is a unit.
	if collector != nil {
		for id, item := range collector.ComponentStatusMap {
			state, msg := translate.StateWithMessage(item)

			checkinComponent := fleetapi.CheckinComponent{
				ID:      id,
				Type:    "otel",
				Status:  stateString(state),
				Message: msg,
			}

			if len(item.ComponentStatusMap) > 0 {
				units := make([]fleetapi.CheckinUnit, 0, len(item.ComponentStatusMap))
				for unitId, unitItem := range item.ComponentStatusMap {
					unitState, unitMsg := translate.StateWithMessage(unitItem)
					units = append(units, fleetapi.CheckinUnit{
						ID:      unitId,
						Status:  stateString(unitState),
						Message: unitMsg,
						Type:    otelComponentTypeString(unitId),
					})
				}
				checkinComponent.Units = units
			}

			checkinComponents = append(checkinComponents, checkinComponent)
		}
	}

	return checkinComponents
}

func (f *FleetGateway) execute(ctx context.Context) (*fleetapi.CheckinResponse, time.Duration, error) {
	ecsMeta, err := info.Metadata(ctx, f.log)
	if err != nil {
		f.log.Error(errors.New("failed to load metadata", err))
		return nil, 0, err
	}

	// retrieve ack token from the store
	ackToken := f.stateStore.AckToken()
	if ackToken != "" {
		f.log.Debugf("using previously saved ack token: %v", ackToken)
	}

	// get current state
	state, stateCtx := f.stateFetcher.FetchState(ctx)

	// convert components into checkin components structure
	components := convertToCheckinComponents(f.log, state.Components, state.Collector)

	f.log.Debugf("correcting agent loglevel from %s to %s using coordinator state", ecsMeta.Elastic.Agent.LogLevel, state.LogLevel.String())
	// Fix loglevel with the current log level used by coordinator
	ecsMeta.Elastic.Agent.LogLevel = state.LogLevel.String()

	action := f.stateStore.Action()
	agentPolicyID := getPolicyID(action)
	policyRevisionIDX := getPolicyRevisionIDX(action)

	// get available rollbacks
	rollbacks, err := f.rollbackSource.Get()
	if err != nil {
		f.log.Warnf("error getting available rollbacks: %s", err.Error())
		// this should already be nil but let's make sure that we don't include rollbacks in checkin body when encountering errors
		rollbacks = nil
	}

	var validRollbacks []fleetapi.CheckinRollback
	if len(rollbacks) > 0 {
		now := time.Now()
		validRollbacks = make([]fleetapi.CheckinRollback, 0, len(rollbacks))
		for _, rollback := range rollbacks {
			if rollback.ValidUntil.After(now) {
				// map the `ttl.Marker` to the `fleetapi.CheckinRollback`
				validRollbacks = append(validRollbacks, fleetapi.CheckinRollback{
					Version:    rollback.Version,
					ValidUntil: rollback.ValidUntil,
				})
			}
		}
	}

	// checkin
	cmd := fleetapi.NewCheckinCmd(f.agentInfo, f.client)
	req := &fleetapi.CheckinRequest{
		AckToken:          ackToken,
		Metadata:          ecsMeta,
		Status:            agentStateToString(state.State),
		Message:           state.Message,
		Components:        components,
		UpgradeDetails:    state.UpgradeDetails,
		AgentPolicyID:     agentPolicyID,
		PolicyRevisionIDX: policyRevisionIDX,
	}
	if len(validRollbacks) > 0 {
		req.Upgrade.Rollbacks = validRollbacks
	}

	resp, took, err := cmd.Execute(stateCtx, req)
	f.stateFetcher.Done()
	if isUnauth(err) {
		f.unauthCounter++
		if f.shouldUseLongSched() {
			f.log.Warnf("retrieved an invalid api key error '%d' times. will use long scheduler", f.unauthCounter)
			f.scheduler.SetDuration(defaultGatewaySettings.ErrConsecutiveUnauthDuration)
			return &fleetapi.CheckinResponse{}, took, nil
		}

		return nil, took, err
	}

	f.scheduler.SetDuration(defaultGatewaySettings.Duration)

	f.unauthCounter = 0
	if err != nil {
		if errors.Is(err, context.Canceled) && errors.Is(context.Cause(stateCtx), errComponentStateChanged) {
			return nil, took, stderrors.Join(err, errComponentStateChanged)
		}
		return nil, took, err
	}

	// Save the latest ackToken
	if resp.AckToken != "" {
		f.stateStore.SetAckToken(resp.AckToken)
		serr := f.stateStore.Save()
		if serr != nil {
			f.log.Errorf("failed to save the ack token, err: %v", serr)
		}
	}

	return resp, took, nil
}

// shouldUseLongSched checks if the max number of trying an invalid key is reached
func (f *FleetGateway) shouldUseLongSched() bool {
	return f.unauthCounter > maxUnauthCounter
}

func isUnauth(err error) bool {
	return errors.Is(err, client.ErrInvalidAPIKey)
}

func (f *FleetGateway) SetClient(c client.Sender) {
	f.client = c
}

func agentStateToString(state agentclient.State) string {
	switch state {
	case agentclient.Healthy:
		return fleetStateOnline
	case agentclient.Failed:
		return fleetStateError
	case agentclient.Starting:
		return fleetStateStarting
	case agentclient.Configuring:
		return fleetStateOnline
	case agentclient.Upgrading:
		return fleetStateOnline
	case agentclient.Rollback:
		return fleetStateDegraded
	case agentclient.Degraded:
		return fleetStateDegraded
	// Report Stopping and Stopped as online since Fleet doesn't understand these states yet.
	// Usually Stopping and Stopped mean the agent is going to stop checking in at which point Fleet
	// will update the state to offline. Use the online state here since there isn't anything better
	// at the moment, and the agent will end up in the expected offline state eventually.
	case agentclient.Stopping:
		return fleetStateOnline
	case agentclient.Stopped:
		return fleetStateOnline
	}
	// Unknown states map to degraded.
	return fleetStateDegraded
}

func RequestBackoff(done <-chan struct{}) backoff.Backoff {
	return backoff.NewEqualJitterBackoff(
		done,
		defaultFleetBackoffSettings.Init,
		defaultFleetBackoffSettings.Max,
	)
}

// getPolicyID will check that the passed action is a POLICY_CHANGE action and return the policy_id attribute of the policy as a string.
func getPolicyID(action fleetapi.Action) string {
	policyChange, ok := action.(*fleetapi.ActionPolicyChange)
	if !ok {
		return ""
	}
	v, ok := policyChange.Data.Policy["policy_id"]
	if !ok {
		return ""
	}
	vv, ok := v.(string)
	if !ok {
		return ""
	}
	return vv
}

// getPolicyRevisionIDX will check that the passed action is a POLICY_CHANGE action and return the policy_revision_idx attribute of the policy as an int64.
// The function will attempt to convert the attribute to int64 if int or float64 is used in order to prevent issues from serialization.
func getPolicyRevisionIDX(action fleetapi.Action) int64 {
	policyChange, ok := action.(*fleetapi.ActionPolicyChange)
	if !ok {
		return 0
	}
	v, ok := policyChange.Data.Policy["policy_revision_idx"]
	if !ok {
		return 0
	}
	switch vv := v.(type) {
	case int64:
		return vv
	case int:
		return int64(vv)
	case float64:
		return int64(vv)
	default:
		return 0
	}
}

var errComponentStateChanged = errors.New("error component state changed")

type StateFetcher interface {
	// FetchState returns the current state and a context that is valid as long as the returned state is valid to use.
	FetchState(ctx context.Context) (coordinator.State, context.Context)
	// Done should be called once the checkin call is complete.
	Done()
	StartStateWatch(ctx context.Context) error
}

type FastCheckinStateFetcher struct {
	log       *logger.Logger
	fetcher   func() coordinator.State
	stateChan chan coordinator.State

	cancel context.CancelCauseFunc
	mutex  sync.Mutex
}

func NewFastCheckinStateFetcher(log *logger.Logger, fetcher func() coordinator.State, stateChan chan coordinator.State) *FastCheckinStateFetcher {
	return &FastCheckinStateFetcher{
		log:       log,
		fetcher:   fetcher,
		stateChan: stateChan,
		cancel:    nil,
		mutex:     sync.Mutex{},
	}
}

// Fetch wraps the state fetching to send in the check-in request under the checkin state mutex.
// After the state is fetched the checkin cancellation function has be initialized and the new context
// is returned.
func (s *FastCheckinStateFetcher) FetchState(ctx context.Context) (coordinator.State, context.Context) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.cancel != nil {
		s.cancel(nil) // ensure ctx cleanup
	}

	ctx2, ctxCancel := context.WithCancelCause(ctx)
	state := s.fetcher()
	s.cancel = ctxCancel
	return state, ctx2
}

func (s *FastCheckinStateFetcher) Done() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.cancel != nil {
		s.cancel(nil) // ensure ctx cleanup
		s.cancel = nil
	}
}

func (s *FastCheckinStateFetcher) invalidateState() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.cancel != nil {
		s.cancel(errComponentStateChanged)
		s.cancel = nil
	}
}

func (s *FastCheckinStateFetcher) StartStateWatch(ctx context.Context) error {
	s.log.Info("FleetGateway state watching started")
	for {
		select {
		case <-ctx.Done():
			s.log.Info("FleetGateway state watching stopped")
			return ctx.Err()
		case _, isOpen := <-s.stateChan:
			if !isOpen {
				s.log.Info("FleetGateway state watching channel closed, stopping loop.")
				return nil
			}
			// TODO: consider check for specific changes e.g. degraded?
			s.invalidateState()
		}
	}
}

// CheckinStateFetcher implements the simple state fetching without any invalidation or fast checkin logic.
type CheckinStateFetcher struct {
	fetcher func() coordinator.State
}

func NewCheckinStateFetcher(fetcher func() coordinator.State) *CheckinStateFetcher {
	return &CheckinStateFetcher{fetcher: fetcher}
}

// FetchState returns the current state and the given ctx because the current state is always valid to use.
func (s *CheckinStateFetcher) FetchState(ctx context.Context) (coordinator.State, context.Context) {
	state := s.fetcher()
	return state, ctx
}

func (s *CheckinStateFetcher) Done()                                     {}
func (s *CheckinStateFetcher) StartStateWatch(ctx context.Context) error { return nil }

func getBackoffSettings(cfg *configuration.FleetCheckin) *backoffSettings {
	bo := defaultFleetBackoffSettings

	if cfg == nil {
		return &defaultFleetBackoffSettings
	}

	if cfg.RequestBackoffInit > 0 {
		bo.Init = cfg.RequestBackoffInit
	}
	if cfg.RequestBackoffMax > 0 {
		bo.Max = cfg.RequestBackoffMax
	}

	return &bo
}
