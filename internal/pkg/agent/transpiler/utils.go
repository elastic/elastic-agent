// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package transpiler

import (
	"errors"
	"fmt"
)

// RenderInputs renders dynamic inputs section
func RenderInputs(inputs Node, varsArray []*Vars) (Node, error) {
	l, ok := inputs.Value().(*List)
	if !ok {
		return nil, fmt.Errorf("inputs must be an array")
	}
	var nodes []varIDMap
	nodesMap := map[string]*Dict{}
	for _, vars := range varsArray {
		for _, node := range l.Value().([]Node) {
			dict, ok := node.Clone().(*Dict)
			if !ok {
				continue
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
			hash := string(dict.Hash())
			_, exists := nodesMap[hash]
			if !exists {
				nodesMap[hash] = dict
				nodes = append(nodes, varIDMap{vars.ID(), dict})
			}
		}
	}
	var nInputs []Node
	for _, node := range nodes {
		if node.id != "" {
			// vars has unique ID, concat ID onto existing ID
			idNode, ok := node.d.Find("id")
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
					return nil, fmt.Errorf("id field type invalid, expected string, int, uint, or float got: %T", idKey.value)
				}
			} else {
				node.d.Insert(NewKey("id", NewStrVal(node.id)))
			}
		}
		nInputs = append(nInputs, promoteProcessors(node.d))
	}
	return NewList(nInputs), nil
}

type varIDMap struct {
	id string
	d  *Dict
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
