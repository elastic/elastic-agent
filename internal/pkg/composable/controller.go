// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package composable

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	defaultRetryInterval   = 30 * time.Second
	defaultDefaultProvider = "env"
)

// Controller manages the state of the providers current context.
type Controller interface {
	// Run runs the controller.
	//
	// Cancelling the context stops the controller.
	Run(ctx context.Context) error

	// Errors returns the channel to watch for reported errors.
	Errors() <-chan error

	// Watch returns the channel to watch for variable changes.
	Watch() <-chan []*transpiler.Vars

	// Observe instructs the controller to enable the observed providers.
	//
	// This is a blocking call until the observation is handled and the most recent
	// set of variables are returned the caller in the case a change occurred. If no change occurred then
	// it will return with a nil array. If changed the current observed state of variables
	// that is returned is not sent over the Watch channel, the caller should coordinate this fact.
	//
	// Only error that is returned from this function is the result of the passed context.
	Observe(context.Context, []string) ([]*transpiler.Vars, error)

	// DefaultProvider returns the default provider used by the controller.
	//
	// This is used by any variable reference that doesn't add a provider prefix.
	DefaultProvider() string
}

type observer struct {
	vars   map[string]bool
	result chan []*transpiler.Vars
}

// controller manages the state of the providers current context.
type controller struct {
	logger          *logger.Logger
	ch              chan []*transpiler.Vars
	observedCh      chan observer
	errCh           chan error
	restartInterval time.Duration
	defaultProvider string

	managed                 bool
	contextProviderBuilders map[string]contextProvider
	dynamicProviderBuilders map[string]dynamicProvider

	contextProviderStates map[string]*contextProviderState
	dynamicProviderStates map[string]*dynamicProviderState
}

// New creates a new controller.
func New(log *logger.Logger, c *config.Config, managed bool) (Controller, error) {
	l := log.Named("composable")

	var providersCfg Config
	if c != nil {
		err := c.UnpackTo(&providersCfg)
		if err != nil {
			return nil, errors.New(err, "failed to unpack providers config", errors.TypeConfig)
		}
	}

	//  Unless explicitly configured otherwise, All registered providers are enabled by default
	providersInitialDefault := true
	if providersCfg.ProvidersInitialDefault != nil {
		providersInitialDefault = *providersCfg.ProvidersInitialDefault
	}

	restartInterval := defaultRetryInterval
	if providersCfg.ProvidersRestartInterval != nil {
		restartInterval = *providersCfg.ProvidersRestartInterval
	}

	defaultProvider := defaultDefaultProvider
	if providersCfg.ProvidersDefaultProvider != nil {
		defaultProvider = *providersCfg.ProvidersDefaultProvider
	}

	// build all the context providers
	contextProviders := map[string]contextProvider{}
	for name, builder := range Providers.contextProviders {
		pCfg, ok := providersCfg.Providers[name]
		if (ok && !pCfg.Enabled()) || (!ok && !providersInitialDefault) {
			// explicitly disabled; skipping
			continue
		}
		contextProviders[name] = contextProvider{
			builder: builder,
			cfg:     pCfg,
		}
	}

	// build all the dynamic providers
	dynamicProviders := map[string]dynamicProvider{}
	for name, builder := range Providers.dynamicProviders {
		pCfg, ok := providersCfg.Providers[name]
		if (ok && !pCfg.Enabled()) || (!ok && !providersInitialDefault) {
			// explicitly disabled; skipping
			continue
		}
		dynamicProviders[name] = dynamicProvider{
			builder: builder,
			cfg:     pCfg,
		}
	}

	return &controller{
		logger:                  l,
		ch:                      make(chan []*transpiler.Vars, 1),
		observedCh:              make(chan observer),
		errCh:                   make(chan error),
		managed:                 managed,
		restartInterval:         restartInterval,
		defaultProvider:         defaultProvider,
		contextProviderBuilders: contextProviders,
		dynamicProviderBuilders: dynamicProviders,
		contextProviderStates:   make(map[string]*contextProviderState),
		dynamicProviderStates:   make(map[string]*dynamicProviderState),
	}, nil
}

// Run runs the controller.
func (c *controller) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	c.logger.Debugf("Starting controller for composable inputs")
	defer c.logger.Debugf("Stopped controller for composable inputs")

	stateChangedChan := make(chan bool, 1) // sized so we can store 1 notification or proceed
	localCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	c.logger.Debugf("Started controller for composable inputs")

	t := time.NewTimer(100 * time.Millisecond)
	defer func() {
		c.logger.Debugf("Stopping controller for composable inputs")
		t.Stop()
		cancel() // this cancel will stop all running providers

		// wait for all providers to stop (but its possible they still send notifications over notify
		// channel, and we cannot block them sending)
		emptyChan, emptyCancel := context.WithCancel(context.Background())
		defer emptyCancel()
		go func() {
			for {
				select {
				case <-emptyChan.Done():
					return
				case <-stateChangedChan:
				}
			}
		}()

		close(c.ch)
		wg.Wait()
	}()

	// synchronize the fetch providers through a channel
	var fetchProvidersLock sync.RWMutex
	var fetchProviders mapstr.M
	fetchCh := make(chan fetchProvider)
	go func() {
		for {
			select {
			case <-localCtx.Done():
				return
			case msg := <-fetchCh:
				fetchProvidersLock.Lock()
				if msg.fetchProvider == nil {
					_ = fetchProviders.Delete(msg.name)
				} else {
					_, _ = fetchProviders.Put(msg.name, msg.fetchProvider)
				}
				fetchProvidersLock.Unlock()
			}
		}
	}()

	// send initial vars state
	fetchProvidersLock.RLock()
	err := c.sendVars(ctx, nil, fetchProviders)
	if err != nil {
		fetchProvidersLock.RUnlock()
		// only error is context cancel, no need to add error message context
		return err
	}
	fetchProvidersLock.RUnlock()

	// performs debounce of notifies; accumulates them into 100 millisecond chunks
	var observedResult chan []*transpiler.Vars
	for {
	DEBOUNCE:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case observed := <-c.observedCh:
				observedResult = observed.result
				changed := c.handleObserved(localCtx, &wg, fetchCh, stateChangedChan, observed.vars)
				if changed {
					t.Reset(100 * time.Millisecond)
					c.logger.Debugf("Observed state changed for composable inputs; debounce started")
					drainChan(stateChangedChan)
					break DEBOUNCE
				} else {
					observedResult <- nil
					observedResult = nil
				}
			case <-stateChangedChan:
				t.Reset(100 * time.Millisecond)
				c.logger.Debugf("Variable state changed for composable inputs; debounce started")
				drainChan(stateChangedChan)
				break DEBOUNCE
			}
		}

		// notification received, wait for batch
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			drainChan(stateChangedChan)
			// batching done, gather results
		}

		// send the vars to the watcher or the observer caller
		fetchProvidersLock.RLock()
		err := c.sendVars(ctx, observedResult, fetchProviders)
		observedResult = nil
		if err != nil {
			fetchProvidersLock.RUnlock()
			// only error is context cancel, no need to add error message context
			return err
		}
		fetchProvidersLock.RUnlock()
	}
}

func (c *controller) sendVars(ctx context.Context, observedResult chan []*transpiler.Vars, fetchContextProviders mapstr.M) error {
	c.logger.Debugf("Computing new variable state for composable inputs")
	vars := c.generateVars(fetchContextProviders, c.defaultProvider)
	if observedResult != nil {
		// drain any vars sitting on the watch channel
		// this new set of vars replaces that set if that current
		// value has not been read then it will result in vars state being incorrect
		select {
		case <-c.ch:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case observedResult <- vars:
			return nil
		}
	}
	for {
		select {
		case c.ch <- vars:
			return nil
		case <-ctx.Done():
			// coordinator is handling cancellation it won't drain the channel
			return ctx.Err()
		default:
			// c.ch is size of 1, nothing is reading and there's already a signal
			select {
			case <-c.ch:
				// Vars not pushed, cleaning channel
			default:
				// already read
			}
		}
	}
}

// Errors returns the channel to watch for reported errors.
func (c *controller) Errors() <-chan error {
	return c.errCh
}

// Watch returns the channel for variable changes.
func (c *controller) Watch() <-chan []*transpiler.Vars {
	return c.ch
}

// Observe instructs the controller to enable the observed providers.
//
// This is a blocking call until the observation is handled and the most recent
// set of variables are returned the caller in the case a change occurred. If no change occurred then
// it will return with a nil array. If changed the current observed state of variables
// that is returned is not sent over the Watch channel, the caller should coordinate this fact.
//
// Only error that is returned from this function is the result of the passed context.
func (c *controller) Observe(ctx context.Context, vars []string) ([]*transpiler.Vars, error) {
	// only need the top-level variables to determine which providers to run
	//
	// future: possible that all vars could be organized and then passed to each provider to
	// inform the provider on which variables it needs to provide values for.
	topLevel := make(map[string]bool)
	for _, v := range vars {
		vs := strings.SplitN(v, ".", 2)
		topLevel[vs[0]] = true
	}
	// blocks waiting for an updated set of variables
	ch := make(chan []*transpiler.Vars)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case c.observedCh <- observer{topLevel, ch}:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case vars := <-ch:
		return vars, nil
	}
}

// DefaultProvider returns the default provider being used by the controller.
func (c *controller) DefaultProvider() string {
	return c.defaultProvider
}

func (c *controller) handleObserved(ctx context.Context, wg *sync.WaitGroup, fetchCh chan fetchProvider, stateChangedChan chan bool, observed map[string]bool) bool {
	changed := false

	// get the list of already running, so we can determine a list that needs to be stopped
	runningCtx := make(map[string]*contextProviderState, len(c.contextProviderStates))
	runningDyn := make(map[string]*dynamicProviderState, len(c.dynamicProviderStates))
	for name, state := range c.contextProviderStates {
		runningCtx[name] = state
	}
	for name, state := range c.dynamicProviderStates {
		runningDyn[name] = state
	}

	// loop through the top-level observed variables and start the providers that are current off
	for name, enabled := range observed {
		if !enabled {
			// should always be true, but just in-case
			continue
		}
		_, ok := runningCtx[name]
		if ok {
			// already running
			delete(runningCtx, name)
			continue
		}
		_, ok = runningDyn[name]
		if ok {
			// already running
			delete(runningDyn, name)
			continue
		}

		found := false
		contextInfo, ok := c.contextProviderBuilders[name]
		if ok {
			found = true
			state := c.startContextProvider(ctx, wg, fetchCh, stateChangedChan, name, contextInfo)
			if state != nil {
				changed = true
				c.contextProviderStates[name] = state
			}
		}
		dynamicInfo, ok := c.dynamicProviderBuilders[name]
		if ok {
			found = true
			state := c.startDynamicProvider(ctx, wg, stateChangedChan, name, dynamicInfo)
			if state != nil {
				changed = true
				c.dynamicProviderStates[name] = state
			}
		}
		if !found {
			c.logger.Warnf("provider %q referenced in policy but no provider exists or was explicitly disabled", name)
		}
	}

	// running remaining need to be stopped
	for name, state := range runningCtx {
		changed = true
		state.logger.Infof("Stopping provider %q", name)
		state.canceller()
		delete(c.contextProviderStates, name)
	}
	for name, state := range runningDyn {
		changed = true
		state.logger.Infof("Stopping dynamic provider %q", name)
		state.canceller()
		delete(c.dynamicProviderStates, name)
	}

	return changed
}

func (c *controller) startContextProvider(ctx context.Context, wg *sync.WaitGroup, fetchCh chan fetchProvider, stateChangedChan chan bool, name string, info contextProvider) *contextProviderState {
	wg.Add(1)
	l := c.logger.Named(strings.Join([]string{"providers", name}, "."))

	ctx, cancel := context.WithCancel(ctx)
	emptyMapping, _ := transpiler.NewAST(nil)
	state := &contextProviderState{
		Context:   ctx,
		mapping:   emptyMapping,
		signal:    stateChangedChan,
		logger:    l,
		canceller: cancel,
	}
	go func() {
		defer wg.Done()
		for {
			l.Infof("Starting context provider %q", name)

			provider, err := info.builder(l, info.cfg, c.managed)
			if err != nil {
				l.Errorf("provider %q failed to build (will retry in %s): %s", name, c.restartInterval.String(), err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(c.restartInterval):
					// wait restart interval and then try again
				}
				continue
			}

			fp, fpok := provider.(corecomp.FetchContextProvider)
			if fpok {
				sendFetchProvider(ctx, fetchCh, name, fp)
			}

			err = provider.Run(ctx, state)
			closeProvider(l, name, provider)
			if errors.Is(err, context.Canceled) {
				// valid exit
				if fpok {
					// turn off fetch provider
					sendFetchProvider(ctx, fetchCh, name, nil)
				}
				return
			}
			// all other exits are bad, even a nil error
			l.Errorf("provider %q failed to run (will retry in %s): %s", name, c.restartInterval.String(), err)
			if fpok {
				// turn off fetch provider
				sendFetchProvider(ctx, fetchCh, name, nil)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(c.restartInterval):
				// wait restart interval and then try again
			}
		}
	}()
	return state
}

func sendFetchProvider(ctx context.Context, fetchCh chan fetchProvider, name string, fp corecomp.FetchContextProvider) {
	select {
	case <-ctx.Done():
	case fetchCh <- fetchProvider{name: name, fetchProvider: fp}:
	}
}

func (c *controller) startDynamicProvider(ctx context.Context, wg *sync.WaitGroup, stateChangedChan chan bool, name string, info dynamicProvider) *dynamicProviderState {
	wg.Add(1)
	l := c.logger.Named(strings.Join([]string{"providers", name}, "."))

	ctx, cancel := context.WithCancel(ctx)
	state := &dynamicProviderState{
		Context:   ctx,
		mappings:  map[string]dynamicProviderMapping{},
		signal:    stateChangedChan,
		logger:    l,
		canceller: cancel,
	}
	go func() {
		defer wg.Done()
		for {
			l.Infof("Starting dynamic provider %q", name)

			provider, err := info.builder(l, info.cfg, c.managed)
			if err != nil {
				l.Errorf("provider %q failed to build (will retry in %s): %s", name, c.restartInterval.String(), err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(c.restartInterval):
					// wait restart interval and then try again
				}
				continue
			}

			err = provider.Run(state)
			closeProvider(l, name, provider)
			if errors.Is(err, context.Canceled) {
				return
			}
			// all other exits are bad, even a nil error
			l.Errorf("provider %q failed to run (will restart in %s): %s", name, c.restartInterval.String(), err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(c.restartInterval):
				// wait restart interval and then try again
			}
		}
	}()
	return state
}

func (c *controller) generateVars(fetchContextProviders mapstr.M, defaultProvider string) []*transpiler.Vars {
	// build the vars list of mappings
	vars := make([]*transpiler.Vars, 1)
	mapping, _ := transpiler.NewAST(map[string]any{})
	for name, state := range c.contextProviderStates {
		_ = mapping.Insert(state.Current(), name)
	}
	vars[0] = transpiler.NewVarsFromAst("", mapping, fetchContextProviders, defaultProvider)

	// add to the vars list for each dynamic providers mappings
	for name, state := range c.dynamicProviderStates {
		for _, mappings := range state.Mappings() {
			local := mapping.ShallowClone()
			_ = local.Insert(mappings.mapping, name)
			id := fmt.Sprintf("%s-%s", name, mappings.id)
			v := transpiler.NewVarsWithProcessorsFromAst(id, local, name, mappings.processors, fetchContextProviders, defaultProvider)
			vars = append(vars, v)
		}
	}
	return vars
}

func closeProvider(l *logger.Logger, name string, provider interface{}) {
	cp, ok := provider.(corecomp.CloseableProvider)
	if !ok {
		// doesn't implement Close
		return
	}
	if err := cp.Close(); err != nil {
		l.Errorf("unable to close context provider %q: %s", name, err)
	}
}

type contextProvider struct {
	builder ContextProviderBuilder
	cfg     *config.Config
}

type dynamicProvider struct {
	builder DynamicProviderBuilder
	cfg     *config.Config
}

type fetchProvider struct {
	name          string
	fetchProvider corecomp.FetchContextProvider
}

type contextProviderState struct {
	context.Context

	lock    sync.RWMutex
	mapping *transpiler.AST
	signal  chan bool

	logger    *logger.Logger
	canceller context.CancelFunc
}

// Signal signals that something has changed in the provider.
//
// Note: This should only be used by fetch context providers, standard context
// providers should use Set to update the overall state.
func (c *contextProviderState) Signal() {
	// Notify the controller Run loop that a state has changed. The notification
	// channel has buffer size 1 so this ensures that an update will always
	// happen after this change, while coalescing multiple simultaneous changes
	// into a single controller update.
	select {
	case c.signal <- true:
	default:
	}
}

// Set sets the current mapping.
func (c *contextProviderState) Set(mapping map[string]interface{}) error {
	var err error
	ast, err := transpiler.NewAST(mapping)
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.mapping != nil && c.mapping.Equal(ast) {
		// same mapping; no need to update and signal
		return nil
	}
	c.mapping = ast
	c.Signal()
	return nil
}

// Current returns the current mapping.
func (c *contextProviderState) Current() *transpiler.AST {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.mapping
}

type dynamicProviderMapping struct {
	id         string
	priority   int
	mapping    *transpiler.AST
	processors transpiler.Processors
}

type dynamicProviderState struct {
	context.Context

	lock     sync.Mutex
	mappings map[string]dynamicProviderMapping
	signal   chan bool

	logger    *logger.Logger
	canceller context.CancelFunc
}

// AddOrUpdate adds or updates the current mapping for the dynamic provider.
//
// `priority` ensures that order is maintained when adding the mapping to the current state
// for the processor. Lower priority mappings will always be sorted before higher priority mappings
// to ensure that matching of variables occurs on the lower priority mappings first.
func (c *dynamicProviderState) AddOrUpdate(id string, priority int, mapping map[string]interface{}, processors []map[string]interface{}) error {
	var err error
	processors, err = cloneMapArray(processors)
	if err != nil {
		return err
	}
	ast, err := transpiler.NewAST(mapping)
	if err != nil {
		return err
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	curr, ok := c.mappings[id]
	if ok && curr.mapping.Equal(ast) && reflect.DeepEqual(curr.processors, processors) {
		// same mapping; no need to update and signal
		return nil
	}
	c.mappings[id] = dynamicProviderMapping{
		id:         id,
		priority:   priority,
		mapping:    ast,
		processors: processors,
	}

	select {
	case c.signal <- true:
	default:
	}
	return nil
}

// Remove removes the current mapping for the dynamic provider.
func (c *dynamicProviderState) Remove(id string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	_, exists := c.mappings[id]
	if exists {
		// existed; remove and signal
		delete(c.mappings, id)

		select {
		case c.signal <- true:
		default:
		}
	}
}

// Mappings returns the current mappings.
func (c *dynamicProviderState) Mappings() []dynamicProviderMapping {
	c.lock.Lock()
	originalMapping := make(map[string]dynamicProviderMapping)
	for k, v := range c.mappings {
		originalMapping[k] = v
	}
	c.lock.Unlock()

	// add the mappings sorted by (priority,id)
	mappings := make([]dynamicProviderMapping, 0)
	priorities := make([]int, 0)
	for _, mapping := range originalMapping {
		priorities = addToSet(priorities, mapping.priority)
	}
	sort.Ints(priorities)
	for _, priority := range priorities {
		ids := make([]string, 0)
		for name, mapping := range originalMapping {
			if mapping.priority == priority {
				ids = append(ids, name)
			}
		}
		sort.Strings(ids)
		for _, name := range ids {
			mappings = append(mappings, originalMapping[name])
		}
	}
	return mappings
}

func cloneMapArray(source []map[string]interface{}) ([]map[string]interface{}, error) {
	if source == nil {
		return nil, nil
	}
	bytes, err := json.Marshal(source)
	if err != nil {
		return nil, fmt.Errorf("failed to clone: %w", err)
	}
	var dest []map[string]interface{}
	err = json.Unmarshal(bytes, &dest)
	if err != nil {
		return nil, fmt.Errorf("failed to clone: %w", err)
	}
	return dest, nil
}

func addToSet(set []int, i int) []int {
	for _, j := range set {
		if j == i {
			return set
		}
	}
	return append(set, i)
}

func drainChan[T any](ch chan T) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
