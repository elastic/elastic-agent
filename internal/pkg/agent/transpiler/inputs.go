// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"errors"
	"fmt"
	"slices"

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

// RenderInputs renders dynamic inputs section. It also returns a map of input id to information about the dynamic
// provider used when rendering that input, including which of the provider's variables the input resolved.
func RenderInputs(inputs Node, varsArray []*Vars) (Node, map[string]RenderedInputInfo, error) {
	l, ok := inputs.Value().(*List)
	if !ok {
		return nil, nil, fmt.Errorf("inputs must be an array")
	}
	var nodes []varIDMap
	// the below allocation doesn't account for nodes filtered out by conditions, but it's still preferable to
	// overallocate once compared to dynamically growing the map
	inputIdToRenderInfo := make(map[string]RenderedInputInfo, len(varsArray)-1)
	nodesMap := map[uint64]*Dict{}
	hasher := xxhash.New()
	for _, vars := range varsArray {
		for _, node := range l.Value().([]Node) {
			dict, ok := node.(*Dict)
			if !ok {
				continue
			}
			hadStreams := false
			if streams := getStreams(dict); streams != nil {
				hadStreams = true
			}
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
			// Apply creates a new Node with a deep copy of all the values
			n, err := dict.Apply(applyVars)
			if errors.Is(err, ErrNoMatch) {
				// has a variable that didn't exist, so we ignore it
				continue
			}
			if err != nil {
				// another error that needs to be reported
				return nil, nil, err
			}
			if n == nil {
				// condition removed it
				continue
			}
			dict = n.(*Dict)
			if hadStreams {
				streams := getStreams(dict)
				if streams == nil {
					// conditions removed all streams (input is removed)
					continue
				}
			}
			hasher.Reset()
			_ = dict.Hash64With(hasher)
			hash := hasher.Sum64()
			_, exists := nodesMap[hash]
			if !exists {
				nodesMap[hash] = dict
				nodes = append(nodes, varIDMap{
					id:              vars.ID(),
					dynamicProvider: vars.dynamicProvider,
					providerVars:    providerOwnedVars(vars.dynamicProvider, observed),
					d:               dict,
				})
			}
		}
	}
	var nInputs []Node
	for _, node := range nodes {
		if node.id != "" {
			// vars has unique ID, concat ID onto existing ID
			idNode, ok := node.d.Find(idKey)
			if ok {
				idKey, _ := idNode.(*Key) // always a Key

				// clone original and update its key to 'original_id'
				origKey, _ := idKey.Clone().(*Key) // always a Key
				origKey.name = "original_id"
				node.d.Insert(origKey)

				// update id field to concat the id of the variable context set
				switch idVal := idKey.value.(type) {
				case *StrVal:
					idVal.value = fmt.Sprintf("%s-%s", idVal.value, node.id)
				case *IntVal:
					idKey.value = NewStrVal(fmt.Sprintf("%d-%s", idVal.value, node.id))
				case *UIntVal:
					idKey.value = NewStrVal(fmt.Sprintf("%d-%s", idVal.value, node.id))
				case *FloatVal:
					idKey.value = NewStrVal(fmt.Sprintf("%f-%s", idVal.value, node.id))
				default:
					return nil, nil, fmt.Errorf("id field type invalid, expected string, int, uint, or float got: %T", idKey.value)
				}
				if node.dynamicProvider != "" {
					inputIdToRenderInfo[idKey.value.String()] = node.renderedInputInfo()
				}
			} else {
				node.d.Insert(NewKey("id", NewStrVal(node.id)))
				if node.dynamicProvider != "" {
					inputIdToRenderInfo[node.id] = node.renderedInputInfo()
				}
			}
		}
		nInputs = append(nInputs, promoteProcessors(node.d))
	}
	return NewList(nInputs), inputIdToRenderInfo, nil
}

type varIDMap struct {
	id              string
	dynamicProvider string
	providerVars    []string
	d               *Dict
}

func (v varIDMap) renderedInputInfo() RenderedInputInfo {
	return RenderedInputInfo{
		DynamicProvider: v.dynamicProvider,
		ProviderVars:    v.providerVars,
	}
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
