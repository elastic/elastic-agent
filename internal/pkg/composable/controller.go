// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
		err := c.Unpack(&providersCfg)
		if err != nil {
			return nil, errors.New(err, "failed to unpack providers config", errors.TypeConfig)
		}
	}

	// build all the context providers
	contextProviders := map[string]*contextProviderState{}
	for name, builder := range Providers.contextProviders {
		pCfg, ok := providersCfg.Providers[name]
		if ok && !pCfg.Enabled() {
			// explicitly disabled; skipping
			continue
		}
		provider, err := builder(l, pCfg, managed)
		if err != nil {
			return nil, errors.New(err, fmt.Sprintf("failed to build provider '%s'", name), errors.TypeConfig, errors.M("provider", name))
		}
		contextProviders[name] = &contextProviderState{
			provider: provider,
		}
	}

	// build all the dynamic providers
	dynamicProviders := map[string]*dynamicProviderState{}
	for name, builder := range Providers.dynamicProviders {
		pCfg, ok := providersCfg.Providers[name]
		if ok && !pCfg.Enabled() {
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

	notify := make(chan bool, 1) // sized so we can store 1 notification or proceed
	localCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	fetchContextProviders := mapstr.M{}

	var wg sync.WaitGroup
	wg.Add(len(c.contextProviders) + len(c.dynamicProviders))

	// run all the enabled context providers
	for name, state := range c.contextProviders {
		state.Context = localCtx
		state.signal = notify
		go func(name string, state *contextProviderState) {
			defer wg.Done()
			err := state.provider.Run(state)
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
		state.signal = notify
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
				case <-notify:
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
			case <-notify:
				t.Reset(100 * time.Millisecond)
				c.logger.Debugf("Variable state changed for composable inputs; debounce started")
				drainChan(notify)
				break DEBOUNCE
			}
		}

		// notification received, wait for batch
		select {
		case <-ctx.Done():
			cleanupFn()
			return ctx.Err()
		case <-t.C:
			drainChan(notify)
			// batching done, gather results
		}

		c.logger.Debugf("Computing new variable state for composable inputs")

		// build the vars list of mappings
		vars := make([]*transpiler.Vars, 1)
		mapping := map[string]interface{}{}
		for name, state := range c.contextProviders {
			mapping[name] = state.Current()
		}
		// this is ensured not to error, by how the mappings states are verified
		vars[0], _ = transpiler.NewVars("", mapping, fetchContextProviders)

		// add to the vars list for each dynamic providers mappings
		for name, state := range c.dynamicProviders {
			for _, mappings := range state.Mappings() {
				local, _ := cloneMap(mapping) // will not fail; already been successfully cloned once
				local[name] = mappings.mapping
				id := fmt.Sprintf("%s-%s", name, mappings.id)
				// this is ensured not to error, by how the mappings states are verified
				v, _ := transpiler.NewVarsWithProcessors(id, local, name, mappings.processors, fetchContextProviders)
				vars = append(vars, v)
			}
		}

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

type contextProviderState struct {
	context.Context

	provider corecomp.ContextProvider
	lock     sync.RWMutex
	mapping  map[string]interface{}
	signal   chan bool
}

// Set sets the current mapping.
func (c *contextProviderState) Set(mapping map[string]interface{}) error {
	var err error
	mapping, err = cloneMap(mapping)
	if err != nil {
		return err
	}
	// ensure creating vars will not error
	_, err = transpiler.NewVars("", mapping, nil)
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if reflect.DeepEqual(c.mapping, mapping) {
		// same mapping; no need to update and signal
		return nil
	}
	c.mapping = mapping

	select {
	case c.signal <- true:
	default:
	}
	return nil
}

// Current returns the current mapping.
func (c *contextProviderState) Current() map[string]interface{} {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.mapping
}

type dynamicProviderMapping struct {
	id         string
	priority   int
	mapping    map[string]interface{}
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
	mapping, err = cloneMap(mapping)
	if err != nil {
		return err
	}
	processors, err = cloneMapArray(processors)
	if err != nil {
		return err
	}
	// ensure creating vars will not error
	_, err = transpiler.NewVars("", mapping, nil)
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	curr, ok := c.mappings[id]
	if ok && reflect.DeepEqual(curr.mapping, mapping) && reflect.DeepEqual(curr.processors, processors) {
		// same mapping; no need to update and signal
		return nil
	}
	c.mappings[id] = dynamicProviderMapping{
		id:         id,
		priority:   priority,
		mapping:    mapping,
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

func cloneMap(source map[string]interface{}) (map[string]interface{}, error) {
	if source == nil {
		return nil, nil
	}
	bytes, err := json.Marshal(source)
	if err != nil {
		return nil, fmt.Errorf("failed to clone: %w", err)
	}
	var dest map[string]interface{}
	err = json.Unmarshal(bytes, &dest)
	if err != nil {
		return nil, fmt.Errorf("failed to clone: %w", err)
	}
	return dest, nil
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
