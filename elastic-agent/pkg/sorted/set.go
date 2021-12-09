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

package sorted

import (
	"sort"
	"sync"
)

// Set is a sorted set that allow to iterate on they keys in an ordered manner, when
// items are added or removed from the Set the keys are sorted.
type Set struct {
	mapped map[string]interface{}
	keys   []string
	rwlock sync.RWMutex
}

// NewSet returns an ordered set.
func NewSet() *Set {
	return &Set{
		mapped: make(map[string]interface{}),
	}
}

// Add adds an items to the set.
func (s *Set) Add(k string, v interface{}) {
	s.rwlock.Lock()
	defer s.rwlock.Unlock()

	_, ok := s.mapped[k]
	if !ok {
		s.keys = append(s.keys, k)
		sort.Strings(s.keys)
	}

	s.mapped[k] = v
}

// Remove removes an items from the Set.
func (s *Set) Remove(k string) {
	s.rwlock.Lock()
	defer s.rwlock.Unlock()

	_, ok := s.mapped[k]
	if !ok {
		return
	}

	delete(s.mapped, k)

	pos := sort.SearchStrings(s.keys, k)
	if pos < len(s.keys) && s.keys[pos] == k {
		s.keys = append(s.keys[:pos], s.keys[pos+1:]...)
	}
}

// Get retrieves a specific values from the map and will return false if the key is not found.
func (s *Set) Get(k string) (interface{}, bool) {
	s.rwlock.RLock()
	defer s.rwlock.RUnlock()

	v, ok := s.mapped[k]
	return v, ok
}

// Keys returns slice of keys where the keys are ordered alphabetically.
func (s *Set) Keys() []string {
	s.rwlock.RLock()
	defer s.rwlock.RUnlock()

	return append(s.keys[:0:0], s.keys...)
}
