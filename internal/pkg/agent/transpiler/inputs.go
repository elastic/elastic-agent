// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cespare/xxhash/v2"
)

const (
	// streamsKey is the name of the dictionary key for streams that an input can have. In the case that
	// an input defines a set of streams and after conditions are applied all the streams are removed then
	// the entire input is removed.
	streamsKey = "streams"
	idKey      = "id"
)

// RenderedInputInfo describes how a rendered input was produced from a set of variables.
type RenderedInputInfo struct {
	// DynamicProvider is the name of the dynamic provider whose mapping produced the variable
	// set the input was rendered from.
	DynamicProvider string
	// ProviderVars are the variables owned by DynamicProvider (that is, namespaced under its
	// name) which were actually resolved while rendering the input. It is sorted and
	// deduplicated.
	ProviderVars []string
}

// RenderedInputs is the result of rendering the inputs of a policy against a set of vars.
type RenderedInputs struct {
	// Info maps the id of each input rendered from a dynamic provider to information about
	// how it was rendered.
	Info    map[string]RenderedInputInfo
	entries []*renderEntry
}

// Node returns the rendered inputs as a list node.
func (r *RenderedInputs) Node() Node {
	nodes := make([]Node, 0, len(r.entries))
	for _, entry := range r.entries {
		nodes = append(nodes, entry.rendered)
	}
	return NewList(nodes)
}

// Maps returns the rendered inputs in their native form, as AST.Map would.
//
// The maps are shared with the RenderCache the inputs were rendered with (if any) and with
// every previous and future caller, so they must be treated as read-only.
func (r *RenderedInputs) Maps() []interface{} {
	maps := make([]interface{}, 0, len(r.entries))
	for _, entry := range r.entries {
		maps = append(maps, entry.mapped)
	}
	return maps
}

// RenderInputs renders dynamic inputs section. It also returns a map of input id to information about the dynamic
// provider used when rendering that input, including which of the provider's variables the input resolved.
func RenderInputs(inputs Node, varsArray []*Vars) (Node, map[string]RenderedInputInfo, error) {
	rendered, err := RenderInputsCached(inputs, varsArray, nil)
	if err != nil {
		return nil, nil, err
	}
	return rendered.Node(), rendered.Info, nil
}

// RenderInputsCached is RenderInputs with a cache of previously rendered inputs.
//
// The cache may be nil, in which case every input is rendered. See RenderCache for the rules
// the caller must follow.
func RenderInputsCached(inputs Node, varsArray []*Vars, cache *RenderCache) (*RenderedInputs, error) {
	l, ok := inputs.Value().(*List)
	if !ok {
		return nil, fmt.Errorf("inputs must be an array")
	}
	inputNodes := l.Value().([]Node)
	// the below allocation doesn't account for nodes filtered out by conditions, but it's still preferable to
	// overallocate once compared to dynamically growing the map
	inputIdToRenderInfo := make(map[string]RenderedInputInfo, len(varsArray)-1)
	// rendered inputs deduplicated by their hash; an input that renders identically for
	// multiple vars sets is only included once
	seen := map[uint64]struct{}{}
	var entries []*renderEntry
	hasher := xxhash.New()

	defaultProvider := ""
	if len(varsArray) > 0 {
		defaultProvider = varsArray[0].defaultProvider
	}
	// providers referenced by each input, so that an input that doesn't reference a dynamic
	// provider is only rendered against the context vars instead of once per dynamic mapping
	inputProviders := make([]map[string]struct{}, len(inputNodes))
	for i, node := range inputNodes {
		dict, ok := node.(*Dict)
		if !ok {
			continue
		}
		if cache != nil {
			inputProviders[i] = cache.inputProviders(i, dict, defaultProvider)
		} else {
			inputProviders[i] = referencedProviders(dict, defaultProvider)
		}
	}

	for _, vars := range varsArray {
		for i, node := range inputNodes {
			dict, ok := node.(*Dict)
			if !ok {
				continue
			}
			if vars.dynamicProvider != "" {
				if _, referenced := inputProviders[i][vars.dynamicProvider]; !referenced {
					// input doesn't reference this dynamic provider; rendering it against this
					// mapping produces the same result as the context vars (already rendered)
					continue
				}
			}
			var entry *renderEntry
			key := renderKey{input: i, varsKey: vars.cacheKey}
			// values from fetch context providers are resolved at lookup time and can change
			// without the vars changing, so inputs using them are always rendered
			cacheable := cache != nil && vars.cacheKey != "" && !vars.referencesFetchProvider(inputProviders[i])
			if cacheable {
				entry = cache.get(key)
			}
			if entry == nil {
				var err error
				entry, err = renderInput(dict, vars, hasher)
				if err != nil {
					return nil, err
				}
				if cacheable {
					cache.put(key, entry)
				}
			}
			if entry.rendered == nil {
				// removed by an unresolved variable or a condition
				continue
			}
			if _, exists := seen[entry.hash]; exists {
				continue
			}
			seen[entry.hash] = struct{}{}
			entries = append(entries, entry)
			if vars.dynamicProvider != "" {
				inputIdToRenderInfo[entry.id] = RenderedInputInfo{
					DynamicProvider: vars.dynamicProvider,
					ProviderVars:    entry.providerVars,
				}
			}
		}
	}
	if cache != nil {
		cache.sweep()
	}
	return &RenderedInputs{Info: inputIdToRenderInfo, entries: entries}, nil
}

// renderInput renders a single input against a set of vars and returns the final form of the
// rendered input (unique id, promoted processors), ready to be included in the rendered policy.
func renderInput(dict *Dict, vars *Vars, hasher *xxhash.Digest) (*renderEntry, error) {
	hadStreams := getStreams(dict) != nil
	// Only variable sets coming from a dynamic provider need introspection, the
	// variables of context providers can't make an input dynamic.
	applyVars := vars
	var observed map[string]struct{}
	if vars.dynamicProvider != "" {
		observed = make(map[string]struct{})
		applyVars = vars.WithVarObserver(func(name string) {
			observed[name] = struct{}{}
		})
	}
	n, err := dict.Apply(applyVars)
	if errors.Is(err, ErrNoMatch) {
		// has a variable that didn't exist, so we ignore it
		return &renderEntry{}, nil
	}
	if err != nil {
		// another error that needs to be reported
		return nil, err
	}
	if n == nil {
		// condition removed it
		return &renderEntry{}, nil
	}
	rendered := n.(*Dict)
	if hadStreams && getStreams(rendered) == nil {
		// conditions removed all streams (input is removed)
		return &renderEntry{}, nil
	}
	hasher.Reset()
	_ = rendered.Hash64With(hasher)
	entry := &renderEntry{
		hash:         hasher.Sum64(),
		providerVars: providerOwnedVars(vars.dynamicProvider, observed),
	}
	if rendered == dict {
		// nothing in the input was affected by the vars, so Apply returned the original;
		// it must not be modified below
		rendered = dict.ShallowClone().(*Dict)
	}
	if vars.ID() != "" {
		// vars has unique ID, concat ID onto existing ID
		idIdx := -1
		for i, node := range rendered.value {
			if k, ok := node.(*Key); ok && k.name == idKey {
				idIdx = i
				break
			}
		}
		if idIdx >= 0 {
			// the key and its value may be shared with the original input, so a new key is
			// put in place of the existing one rather than modifying it
			existing := rendered.value[idIdx].(*Key)
			var id string
			switch idVal := existing.value.(type) {
			case *StrVal:
				id = fmt.Sprintf("%s-%s", idVal.value, vars.ID())
			case *IntVal:
				id = fmt.Sprintf("%d-%s", idVal.value, vars.ID())
			case *UIntVal:
				id = fmt.Sprintf("%d-%s", idVal.value, vars.ID())
			case *FloatVal:
				id = fmt.Sprintf("%f-%s", idVal.value, vars.ID())
			default:
				return nil, fmt.Errorf("id field type invalid, expected string, int, uint, or float got: %T", existing.value)
			}
			rendered.value[idIdx] = NewKey(idKey, NewStrVal(id))
			// keep the original id under 'original_id'
			origKey, _ := existing.Clone().(*Key) // always a Key
			origKey.name = "original_id"
			rendered.Insert(origKey)
			entry.id = id
		} else {
			rendered.Insert(NewKey(idKey, NewStrVal(vars.ID())))
			entry.id = vars.ID()
		}
	}
	entry.rendered = promoteProcessors(rendered)
	entry.mapped = toInterface(entry.rendered).(map[string]interface{})
	return entry, nil
}

// referencedProviders returns the names of the providers referenced by the variables of the input.
func referencedProviders(dict *Dict, defaultProvider string) map[string]struct{} {
	providers := map[string]struct{}{}
	for _, name := range dict.Vars(nil, defaultProvider) {
		providers[strings.SplitN(name, varsSeparator, 2)[0]] = struct{}{}
	}
	return providers
}

// providerOwnedVars returns the sorted subset of observed variable names that are namespaced
// under the given provider, that is, whose first '.'-separated segment is the provider name.
func providerOwnedVars(provider string, observed map[string]struct{}) []string {
	if provider == "" || len(observed) == 0 {
		return nil
	}
	var vars []string
	for name := range observed {
		if varPrefixMatched(name, provider) {
			vars = append(vars, name)
		}
	}
	// sort to keep the result stable, it ends up in logs and diagnostics
	slices.Sort(vars)
	return vars
}

func getStreams(dict *Dict) *List {
	node, ok := dict.Find(streamsKey)
	if !ok {
		return nil
	}
	key, ok := node.(*Key)
	if !ok {
		return nil
	}
	if key.value == nil {
		return nil
	}
	list, ok := key.value.(*List)
	if !ok {
		return nil
	}
	if len(list.value) == 0 {
		// didn't have any streams defined in the list (so no removal should be done)
		return nil
	}
	return list
}

// promoteProcessors adds the processors attached to the rendered input (by variable substitution)
// to the input's "processors" list. The dictionary is modified in place, so it must be owned by
// the caller.
func promoteProcessors(dict *Dict) *Dict {
	p := dict.Processors()
	if p == nil {
		return dict
	}
	var currentList *List
	current, ok := dict.Find("processors")
	if ok {
		currentList, ok = current.Value().(*List)
		if !ok {
			return dict
		}
	}
	ast, _ := NewAST(map[string]interface{}{
		"processors": p,
	})
	procs, _ := Lookup(ast, "processors")
	nodes := nodesFromList(procs.Value().(*List))
	if ok && currentList != nil {
		nodes = append(nodes, nodesFromList(currentList)...)
	}
	dictNodes := dict.Value().([]Node)
	set := false
	for i, node := range dictNodes {
		switch n := node.(type) {
		case *Key:
			if n.Name() == "processors" {
				dictNodes[i] = NewKey("processors", NewList(nodes))
				set = true
			}
		}
		if set {
			break
		}
	}
	if !set {
		dictNodes = append(dictNodes, NewKey("processors", NewList(nodes)))
	}
	return NewDict(dictNodes)
}

func nodesFromList(list *List) []Node {
	return list.Value().([]Node)
}
