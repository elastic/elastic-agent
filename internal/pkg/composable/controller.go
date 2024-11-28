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

	// Close closes the controller, allowing for any resource
	// cleanup and such.
	Close()
}

// controller manages the state of the providers current context.
type controller struct {
	logger           *logger.Logger
	ch               chan []*transpiler.Vars
	errCh            chan error
	contextProviders map[string]*contextProviderState
	dynamicProviders map[string]*dynamicProviderState
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

	// build all the context providers
	contextProviders := map[string]*contextProviderState{}
	for name, builder := range Providers.contextProviders {
		pCfg, ok := providersCfg.Providers[name]
		if (ok && !pCfg.Enabled()) || (!ok && !providersInitialDefault) {
			// explicitly disabled; skipping
			continue
		}
		provider, err := builder(l, pCfg, managed)
		if err != nil {
			return nil, errors.New(err, fmt.Sprintf("failed to build provider '%s'", name), errors.TypeConfig, errors.M("provider", name))
		}
		emptyMapping, _ := transpiler.NewAST(nil)
		contextProviders[name] = &contextProviderState{
			// Safe for Context to be nil here because it will be filled in
			// by (*controller).Run before the provider is started.
			provider: provider,
			mapping:  emptyMapping,
		}
	}

	// build all the dynamic providers
	dynamicProviders := map[string]*dynamicProviderState{}
	for name, builder := range Providers.dynamicProviders {
		pCfg, ok := providersCfg.Providers[name]
		if (ok && !pCfg.Enabled()) || (!ok && !providersInitialDefault) {
			// explicitly disabled; skipping
			continue
		}
		provider, err := builder(l.Named(strings.Join([]string{"providers", name}, ".")), pCfg, managed)
		if err != nil {
			return nil, errors.New(err, fmt.Sprintf("failed to build provider '%s'", name), errors.TypeConfig, errors.M("provider", name))
		}
		dynamicProviders[name] = &dynamicProviderState{
			provider: provider,
			mappings: map[string]dynamicProviderMapping{},
		}
	}

	return &controller{
		logger:           l,
		ch:               make(chan []*transpiler.Vars, 1),
		errCh:            make(chan error),
		contextProviders: contextProviders,
		dynamicProviders: dynamicProviders,
	}, nil
}

// Run runs the controller.
func (c *controller) Run(ctx context.Context) error {
	c.logger.Debugf("Starting controller for composable inputs")
	defer c.logger.Debugf("Stopped controller for composable inputs")

	stateChangedChan := make(chan bool, 1) // sized so we can store 1 notification or proceed
	localCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	fetchContextProviders := mapstr.M{}

	var wg sync.WaitGroup
	wg.Add(len(c.contextProviders) + len(c.dynamicProviders))

	// run all the enabled context providers
	for name, state := range c.contextProviders {
		state.Context = localCtx
		state.signal = stateChangedChan
		go func(name string, state *contextProviderState) {
			defer wg.Done()
			err := state.provider.Run(ctx, state)
			if err != nil && !errors.Is(err, context.Canceled) {
				err = errors.New(err, fmt.Sprintf("failed to run provider '%s'", name), errors.TypeConfig, errors.M("provider", name))
				c.logger.Errorf("%s", err)
			}
		}(name, state)
		if p, ok := state.provider.(corecomp.FetchContextProvider); ok {
			_, _ = fetchContextProviders.Put(name, p)
		}
	}

	// run all the enabled dynamic providers
	for name, state := range c.dynamicProviders {
		state.Context = localCtx
		state.signal = stateChangedChan
		go func(name string, state *dynamicProviderState) {
			defer wg.Done()
			err := state.provider.Run(state)
			if err != nil && !errors.Is(err, context.Canceled) {
				err = errors.New(err, fmt.Sprintf("failed to run provider '%s'", name), errors.TypeConfig, errors.M("provider", name))
				c.logger.Errorf("%s", err)
			}
		}(name, state)
	}

	c.logger.Debugf("Started controller for composable inputs")

	t := time.NewTimer(100 * time.Millisecond)
	cleanupFn := func() {
		c.logger.Debugf("Stopping controller for composable inputs")
		t.Stop()
		cancel()

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
	}

	// performs debounce of notifies; accumulates them into 100 millisecond chunks
	for {
	DEBOUNCE:
		for {
			select {
			case <-ctx.Done():
				cleanupFn()
				return ctx.Err()
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
			cleanupFn()
			return ctx.Err()
		case <-t.C:
			drainChan(stateChangedChan)
			// batching done, gather results
		}

		c.logger.Debugf("Computing new variable state for composable inputs")

		vars := c.generateVars(fetchContextProviders)

	UPDATEVARS:
		for {
			select {
			case c.ch <- vars:
				break UPDATEVARS
			case <-ctx.Done():
				// coordinator is handling cancellation it won't drain the channel
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
}

// Errors returns the channel to watch for reported errors.
func (c *controller) Errors() <-chan error {
	return c.errCh
}

// Watch returns the channel for variable changes.
func (c *controller) Watch() <-chan []*transpiler.Vars {
	return c.ch
}

// Close closes the controller, allowing for any resource
// cleanup and such.
func (c *controller) Close() {
	// Attempt to close all closeable context providers.
	for name, state := range c.contextProviders {
		cp, ok := state.provider.(corecomp.CloseableProvider)
		if !ok {
			continue
		}

		if err := cp.Close(); err != nil {
			c.logger.Errorf("unable to close context provider %q: %s", name, err.Error())
		}
	}

	// Attempt to close all closeable dynamic providers.
	for name, state := range c.dynamicProviders {
		cp, ok := state.provider.(corecomp.CloseableProvider)
		if !ok {
			continue
		}

		if err := cp.Close(); err != nil {
			c.logger.Errorf("unable to close dynamic provider %q: %s", name, err.Error())
		}
	}
}

func (c *controller) generateVars(fetchContextProviders mapstr.M) []*transpiler.Vars {
	// build the vars list of mappings
	vars := make([]*transpiler.Vars, 1)
	mapping, _ := transpiler.NewAST(map[string]any{})
	for name, state := range c.contextProviders {
		_ = mapping.Insert(state.Current(), name)
	}
	vars[0] = transpiler.NewVarsFromAst("", mapping, fetchContextProviders)

	// add to the vars list for each dynamic providers mappings
	for name, state := range c.dynamicProviders {
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

type contextProviderState struct {
	context.Context

	provider corecomp.ContextProvider
	lock     sync.RWMutex
	mapping  *transpiler.AST
	signal   chan bool
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

func drainChan(ch chan bool) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
