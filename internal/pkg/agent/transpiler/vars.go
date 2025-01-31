// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/core/composable"
)

const varsSeperator = "."

var varsRegex = regexp.MustCompile(`\$\$?{([\p{L}\d\s\\\-_|.'":\/]*)}`)

// ErrNoMatch is return when the replace didn't fail, just that no vars match to perform the replace.
var ErrNoMatch = errors.New("no matching vars")

// Vars is a context of variables that also contain a list of processors that go with the mapping.
type Vars struct {
	id                    string
	tree                  *AST
	processorsKey         string
	processors            Processors
	fetchContextProviders mapstr.M
	defaultProvider       string
}

// NewVars returns a new instance of vars.
func NewVars(id string, mapping map[string]interface{}, fetchContextProviders mapstr.M, defaultProvider string) (*Vars, error) {
	return NewVarsWithProcessors(id, mapping, "", nil, fetchContextProviders, defaultProvider)
}

// NewVarsFromAst returns a new instance of vars. It takes the mapping as an *AST.
func NewVarsFromAst(id string, tree *AST, fetchContextProviders mapstr.M, defaultProvider string) *Vars {
	return &Vars{id, tree, "", nil, fetchContextProviders, defaultProvider}
}

// NewVarsWithProcessors returns a new instance of vars with attachment of processors.
func NewVarsWithProcessors(id string, mapping map[string]interface{}, processorKey string, processors Processors, fetchContextProviders mapstr.M, defaultProvider string) (*Vars, error) {
	tree, err := NewAST(mapping)
	if err != nil {
		return nil, err
	}
	return &Vars{id, tree, processorKey, processors, fetchContextProviders, defaultProvider}, nil
}

// NewVarsWithProcessorsFromAst returns a new instance of vars with attachment of processors. It takes the mapping as an *AST.
func NewVarsWithProcessorsFromAst(id string, tree *AST, processorKey string, processors Processors, fetchContextProviders mapstr.M, defaultProvider string) *Vars {
	return &Vars{id, tree, processorKey, processors, fetchContextProviders, defaultProvider}
}

// Replace returns a new value based on variable replacement.
func (v *Vars) Replace(value string) (Node, error) {
	return replaceVars(value, func(variable string) (Node, Processors, bool) {
		var processors Processors
		node, ok := v.lookupNode(variable)
		if ok && v.processorsKey != "" && varPrefixMatched(variable, v.processorsKey) {
			processors = v.processors
		}
		return node, processors, ok
	}, true, v.defaultProvider)
}

// ID returns the unique ID for the vars.
func (v *Vars) ID() string {
	return v.id
}

// Lookup returns the value from the vars.
func (v *Vars) Lookup(name string) (interface{}, bool) {
	// lookup in the AST tree
	return v.tree.Lookup(name)
}

// Map transforms the variables into a map[string]interface{} and will abort and return any errors related
// to type conversion.
func (v *Vars) Map() (map[string]interface{}, error) {
	return v.tree.Map()
}

// lookupNode performs a lookup on the AST, but keeps the result as a `Node`.
//
// This is different from `Lookup` which returns the actual type, not the AST type.
func (v *Vars) lookupNode(name string) (Node, bool) {
	// check if the value can be retrieved from a FetchContextProvider
	for providerName, provider := range v.fetchContextProviders {
		if varPrefixMatched(name, providerName) {
			fetchProvider, ok := provider.(composable.FetchContextProvider)
			if !ok {
				return &StrVal{value: ""}, false
			}
			fval, found := fetchProvider.Fetch(name)
			if found {
				return &StrVal{value: fval}, true
			}
			return &StrVal{value: ""}, false
		}
	}
	// lookup in the AST tree
	return Lookup(v.tree, name)
}

func replaceVars(value string, replacer func(variable string) (Node, Processors, bool), reqMatch bool, defaultProvider string) (Node, error) {
	var processors Processors
	matchIdxs := varsRegex.FindAllSubmatchIndex([]byte(value), -1)
	if !validBrackets(value, matchIdxs) {
		return nil, fmt.Errorf("starting ${ is missing ending }")
	}
	result := ""
	lastIndex := 0
	for _, r := range matchIdxs {
		for i := 0; i < len(r); i += 4 {
			if value[r[i]+1] == '$' {
				// match on an escaped var, append the raw string with the '$' prefix removed
				result += value[lastIndex:r[0]] + value[r[i]+1:r[i+1]]
				lastIndex = r[1]
				continue
			}
			// match on a non-escaped var
			vars, err := extractVars(value[r[i+2]:r[i+3]], defaultProvider)
			if err != nil {
				return nil, fmt.Errorf(`error parsing variable "%s": %w`, value[r[i]:r[i+1]], err)
			}
			set := false
			for _, val := range vars {
				switch val.(type) {
				case *constString:
					result += value[lastIndex:r[0]] + val.Value()
					set = true
				case *varString:
					node, nodeProcessors, ok := replacer(val.Value())
					if ok {
						node := nodeToValue(node)
						if nodeProcessors != nil {
							processors = nodeProcessors
						}
						if r[i] == 0 && r[i+1] == len(value) {
							// possible for complete replacement of object, because the variable
							// is not inside of a string
							return attachProcessors(node, processors), nil
						}
						result += value[lastIndex:r[0]] + node.String()
						set = true
					}
				}
				if set {
					break
				}
			}
			if !set && reqMatch {
				return NewStrVal(""), fmt.Errorf("%w: %s", ErrNoMatch, toRepresentation(vars))
			}
			lastIndex = r[1]
		}
	}
	return NewStrValWithProcessors(result+value[lastIndex:], processors), nil
}

func toRepresentation(vars []varI) string {
	var sb strings.Builder
	sb.WriteString("${")
	for i, val := range vars {
		switch val.(type) {
		case *constString:
			sb.WriteString(`'`)
			sb.WriteString(val.Value())
			sb.WriteString(`'`)
		case *varString:
			sb.WriteString(val.Value())
			if i < len(vars)-1 {
				sb.WriteString("|")
			}
		}
	}
	sb.WriteString("}")
	return sb.String()
}

// nodeToValue ensures that the node is an actual value.
func nodeToValue(node Node) Node {
	switch n := node.(type) {
	case *Key:
		return n.value
	}
	return node
}

// validBrackets returns true when all starting {$ have a matching ending }.
func validBrackets(s string, matchIdxs [][]int) bool {
	result := ""
	lastIndex := 0
	match := false
	for _, r := range matchIdxs {
		match = true
		for i := 0; i < len(r); i += 4 {
			result += s[lastIndex:r[0]]
			lastIndex = r[1]
		}
	}
	if !match {
		return !strings.Contains(s, "${")
	}
	return !strings.Contains(result, "${")
}

type varI interface {
	Value() string
}

type varString struct {
	value string
}

func (v *varString) Value() string {
	return v.value
}

type constString struct {
	value string
}

func (v *constString) Value() string {
	return v.value
}

func extractVars(i string, defaultProvider string) ([]varI, error) {
	const out = rune(0)

	quote := out
	constant := false
	escape := false
	is := make([]rune, 0, len(i))
	res := make([]varI, 0)
	for _, r := range i {
		if r == '|' {
			if escape {
				return nil, fmt.Errorf(`variable pipe cannot be escaped; remove \ before |`)
			}
			if quote == out {
				if constant {
					res = append(res, &constString{string(is)})
				} else if len(is) > 0 {
					if is[len(is)-1] == '.' {
						return nil, fmt.Errorf("variable cannot end with '.'")
					}
					res = append(res, &varString{maybeAddDefaultProvider(string(is), defaultProvider)})
				}
				is = is[:0] // slice to zero length; to keep allocated memory
				constant = false
			} else {
				is = append(is, r)
			}
			continue
		}
		if !escape && (r == '"' || r == '\'') {
			if quote == out {
				// start of unescaped quote
				quote = r
				constant = true
			} else if quote == r {
				// end of unescaped quote
				quote = out
			} else {
				is = append(is, r)
			}
			continue
		}
		// escape because of backslash (\); except when it is the second backslash of a pair
		escape = !escape && r == '\\'
		if r == '\\' {
			if !escape {
				is = append(is, r)
			}
		} else if quote != out || !unicode.IsSpace(r) {
			is = append(is, r)
		}
	}
	if quote != out {
		return nil, fmt.Errorf(`starting %s is missing ending %s`, string(quote), string(quote))
	}
	if constant {
		res = append(res, &constString{string(is)})
	} else if len(is) > 0 {
		if is[len(is)-1] == '.' {
			return nil, fmt.Errorf("variable cannot end with '.'")
		}
		res = append(res, &varString{maybeAddDefaultProvider(string(is), defaultProvider)})
	}
	return res, nil
}

func varPrefixMatched(val string, key string) bool {
	s := strings.SplitN(val, varsSeperator, 2)
	return s[0] == key
}

func maybeAddDefaultProvider(val string, defaultProvider string) string {
	if defaultProvider == "" || strings.Contains(val, varsSeperator) {
		// no default set or already has a provider in the variable name
		return val
	}
	// at this point they variable doesn't have a provider
	return fmt.Sprintf("%s.%s", defaultProvider, val)
}
