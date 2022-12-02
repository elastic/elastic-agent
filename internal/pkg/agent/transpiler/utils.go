// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package transpiler

import (
	"errors"
	"fmt"
)

const (
	// streamsKey is the name of the dictionary key for streams that an input can have. In the case that
	// an input defines a set of streams and after conditions are applied all the streams are removed then
	// the entire input is removed.
	streamsKey = "streams"
)

// RenderInputs renders dynamic inputs section
func RenderInputs(inputs Node, varsArray []*Vars) (Node, error) {
	l, ok := inputs.Value().(*List)
	if !ok {
		return nil, fmt.Errorf("inputs must be an array")
	}
	nodes := []*Dict{}
	nodesMap := map[string]*Dict{}
	for _, vars := range varsArray {
		for _, node := range l.Value().([]Node) {
			dict, ok := node.Clone().(*Dict)
			if !ok {
				continue
			}
			hadStreams := false
			if streams := getStreams(dict); streams != nil {
				hadStreams = true
			}
			n, err := dict.Apply(vars)
			if errors.Is(err, ErrNoMatch) {
				// has a variable that didn't exist, so we ignore it
				continue
			}
			if err != nil {
				// another error that needs to be reported
				return nil, err
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
			hash := string(dict.Hash())
			_, exists := nodesMap[hash]
			if !exists {
				nodesMap[hash] = dict
				nodes = append(nodes, dict)
			}
		}
	}
	nInputs := []Node{}
	for _, node := range nodes {
		nInputs = append(nInputs, promoteProcessors(node))
	}
	return NewList(nInputs), nil
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
