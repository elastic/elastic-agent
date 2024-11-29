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

	// Observe instructs the variables to observe.
	Observe([]string)
}

// controller manages the state of the providers current context.
type controller struct {
	logger          *logger.Logger
	ch              chan []*transpiler.Vars
	observedCh      chan map[string]bool
	errCh           chan error
	restartInterval time.Duration

	managed          bool
	contextProviders map[string]contextProvider
	dynamicProviders map[string]dynamicProvider

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

	restartInterval := 5 * time.Second
	if providersCfg.ProvidersRestartInterval != nil {
		restartInterval = *providersCfg.ProvidersRestartInterval
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
		logger:                l,
		ch:                    make(chan []*transpiler.Vars, 1),
		observedCh:            make(chan map[string]bool, 1),
		errCh:                 make(chan error),
		managed:               managed,
		restartInterval:       restartInterval,
		contextProviders:      contextProviders,
		dynamicProviders:      dynamicProviders,
		contextProviderStates: make(map[string]*contextProviderState),
		dynamicProviderStates: make(map[string]*dynamicProviderState),
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

	fetchContextProviders := mapstr.M{}

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

	// send initial vars state
	err := c.sendVars(ctx, fetchContextProviders)
	if err != nil {
		// only error is context cancel, no need to add error message context
		return err
	}

	// performs debounce of notifies; accumulates them into 100 millisecond chunks
	for {
	DEBOUNCE:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case observed := <-c.observedCh:
				c.handleObserved(localCtx, &wg, stateChangedChan, fetchContextProviders, observed)
				t.Reset(100 * time.Millisecond)
				c.logger.Debugf("Observed state changed for composable inputs; debounce started")
				drainChan(stateChangedChan)
				break DEBOUNCE
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

		// send the vars to the watcher
		err = c.sendVars(ctx, fetchContextProviders)
		if err != nil {
			// only error is context cancel, no need to add error message context
			return err
		}
	}
}

func (c *controller) sendVars(ctx context.Context, fetchContextProviders mapstr.M) error {
	c.logger.Debugf("Computing new variable state for composable inputs")
	vars := c.generateVars(fetchContextProviders)
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

// Observe sends the observed variables from the AST to the controller.
//
// Based on this information it will determine which providers should even be running.
func (c *controller) Observe(vars []string) {
	// only need the top-level variables to determine which providers to run
	//
	// future: possible that all vars could be organized and then passed to each provider to
	// inform the provider on which variables it needs to provide values for.
	topLevel := make(map[string]bool)
	for _, v := range vars {
		vs := strings.SplitN(v, ".", 2)
		topLevel[vs[0]] = true
	}
	// drain the channel first, if the previous vars had not been used yet the new list should be used instead
	drainChan(c.observedCh)
	c.observedCh <- topLevel
}

func (c *controller) handleObserved(ctx context.Context, wg *sync.WaitGroup, stateChangedChan chan bool, fetchContextProviders mapstr.M, observed map[string]bool) {
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

		contextInfo, ok := c.contextProviders[name]
		if ok {
			state := c.startContextProvider(ctx, wg, stateChangedChan, name, contextInfo)
			if state != nil {
				c.contextProviderStates[name] = state
				if p, ok := state.provider.(corecomp.FetchContextProvider); ok {
					_, _ = fetchContextProviders.Put(name, p)
				}
			}
		}
		dynamicInfo, ok := c.dynamicProviders[name]
		if ok {
			state := c.startDynamicProvider(ctx, wg, stateChangedChan, name, dynamicInfo)
			if state != nil {
				c.dynamicProviderStates[name] = state
			}
		}
		c.logger.Warnf("provider %q referenced in policy but no provider exists or was explicitly disabled", name)
	}

	// running remaining need to be stopped
	for name, state := range runningCtx {
		state.logger.Infof("Stopping provider %q", name)
		state.canceller()
		delete(c.contextProviderStates, name)
	}
	for name, state := range runningDyn {
		state.logger.Infof("Stopping dynamic provider %q", name)
		state.canceller()
		delete(c.dynamicProviderStates, name)
	}
}

func (c *controller) startContextProvider(ctx context.Context, wg *sync.WaitGroup, stateChangedChan chan bool, name string, info contextProvider) *contextProviderState {
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
			}

			state.provider = provider
			err = provider.Run(ctx, state)
			closeProvider(l, name, provider)
			if errors.Is(err, context.Canceled) {
				// valid exit
				return
			}
			// all other exits are bad, even a nil error
			l.Errorf("provider %q failed to run (will retry in %s): %s", name, c.restartInterval.String(), err)
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
			}

			err = state.provider.Run(state)
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

func (c *controller) generateVars(fetchContextProviders mapstr.M) []*transpiler.Vars {
	// build the vars list of mappings
	vars := make([]*transpiler.Vars, 1)
	mapping, _ := transpiler.NewAST(map[string]any{})
	for name, state := range c.contextProviderStates {
		_ = mapping.Insert(state.Current(), name)
	}
	vars[0] = transpiler.NewVarsFromAst("", mapping, fetchContextProviders)

	// add to the vars list for each dynamic providers mappings
	for name, state := range c.dynamicProviderStates {
		for _, mappings := range state.Mappings() {
			local := mapping.ShallowClone()
			_ = local.Insert(mappings.mapping, name)
			id := fmt.Sprintf("%s-%s", name, mappings.id)
			v := transpiler.NewVarsWithProcessorsFromAst(id, local, name, mappings.processors, fetchContextProviders)
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

type contextProviderState struct {
	context.Context

	provider corecomp.ContextProvider
	lock     sync.RWMutex
	mapping  *transpiler.AST
	signal   chan bool

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

	provider DynamicProvider
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
