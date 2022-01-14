// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package transpiler

type injector interface {
	Inject(target []Node, source interface{}) []Node
	InjectItem(target []Node, source Node) []Node
	InjectCollection(target []Node, source []Node) []Node
}

func mergeStrategy(strategy string) injector {

	switch strategy {
	case "insert_before":
		return injectBeforeInjector{}
	case "insert_after":
		return injectAfterInjector{}
	case "replace":
		return replaceInjector{}
	case "noop":
		return noopInjector{}
	}

	return injectAfterInjector{}
}

type noopInjector struct{}

func (i noopInjector) Inject(target []Node, source interface{}) []Node {
	return inject(i, target, source)
}

func (noopInjector) InjectItem(target []Node, source Node) []Node { return target }

func (noopInjector) InjectCollection(target []Node, source []Node) []Node { return target }

type injectAfterInjector struct{}

func (i injectAfterInjector) Inject(target []Node, source interface{}) []Node {
	return inject(i, target, source)
}

func (injectAfterInjector) InjectItem(target []Node, source Node) []Node {
	return append(target, source)
}

func (injectAfterInjector) InjectCollection(target []Node, source []Node) []Node {
	return append(target, source...)
}

type injectBeforeInjector struct{}

func (i injectBeforeInjector) Inject(target []Node, source interface{}) []Node {
	return inject(i, target, source)
}

func (injectBeforeInjector) InjectItem(target []Node, source Node) []Node {
	return append([]Node{source}, target...)
}

func (injectBeforeInjector) InjectCollection(target []Node, source []Node) []Node {
	return append(source, target...)
}

type replaceInjector struct{}

func (i replaceInjector) Inject(target []Node, source interface{}) []Node {
	return inject(i, target, source)
}

func (replaceInjector) InjectItem(target []Node, source Node) []Node {
	return []Node{source}
}

func (replaceInjector) InjectCollection(target []Node, source []Node) []Node {
	return source
}

func inject(i injector, target []Node, source interface{}) []Node {
	if sourceCollection, ok := source.([]Node); ok {
		return i.InjectCollection(target, sourceCollection)
	}

	if node, ok := source.(Node); ok {
		return i.InjectItem(target, node)
	}

	return target
}
