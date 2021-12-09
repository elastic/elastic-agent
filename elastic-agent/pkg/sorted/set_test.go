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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSet(t *testing.T) {
	type kv struct {
		k string
		v interface{}
	}
	t.Run("adding items and keep it ordered", func(t *testing.T) {
		input := []kv{
			kv{k: "a", v: 1},
			kv{k: "x", v: 1},
			kv{k: "c", v: 1},
			kv{k: "b", v: 1},
		}

		s := NewSet()

		for _, kv := range input {
			s.Add(kv.k, kv.v)
		}

		expected := []string{
			"a", "b", "c", "x",
		}

		require.Equal(t, expected, s.Keys())
	})

	t.Run("order is preserved when items are removed", func(t *testing.T) {
		input := []kv{
			kv{k: "a", v: 1},
			kv{k: "x", v: 1},
			kv{k: "c", v: 1},
			kv{k: "b", v: 1},
		}

		s := NewSet()

		for _, kv := range input {
			s.Add(kv.k, kv.v)
		}

		expected := []string{
			"a", "b", "x",
		}

		s.Remove("c")

		require.Equal(t, expected, s.Keys())
	})

	t.Run("return true when the key exist", func(t *testing.T) {
		s := NewSet()
		s.Add("hello", "world")
		v, ok := s.Get("hello")
		require.True(t, ok)
		require.Equal(t, "world", v)
	})

	t.Run("return false when the key dont exist", func(t *testing.T) {
		s := NewSet()
		v, ok := s.Get("hello")
		require.False(t, ok)
		require.Equal(t, nil, v)
	})

	t.Run("return false when the key dont exist", func(t *testing.T) {
		s := NewSet()
		s.Remove("dont-exist")
	})

	t.Run("can remove the last item", func(t *testing.T) {
		input := []kv{
			kv{k: "a", v: 1},
			kv{k: "x", v: 1},
			kv{k: "c", v: 1},
			kv{k: "b", v: 1},
		}

		s := NewSet()

		for _, kv := range input {
			s.Add(kv.k, kv.v)
		}

		expected := []string{
			"a", "b", "c",
		}

		s.Remove("x")

		require.Equal(t, expected, s.Keys())
	})

	t.Run("can remove the only item", func(t *testing.T) {
		s := NewSet()
		s.Add("hello", "world")
		v, ok := s.Get("hello")
		require.True(t, ok)
		require.Equal(t, "world", v)
		s.Remove("hello")

		require.Equal(t, []string{}, s.Keys())
	})

	t.Run("can remove multiple items", func(t *testing.T) {
		input := []kv{
			kv{k: "a", v: 1},
			kv{k: "x", v: 1},
			kv{k: "c", v: 1},
			kv{k: "b", v: 1},
		}

		s := NewSet()

		for _, kv := range input {
			s.Add(kv.k, kv.v)
		}

		require.Equal(t, []string{"a", "b", "c", "x"}, s.Keys())
		s.Remove("a")
		require.Equal(t, []string{"b", "c", "x"}, s.Keys())
		s.Remove("b")
		require.Equal(t, []string{"c", "x"}, s.Keys())
		s.Remove("c")
		require.Equal(t, []string{"x"}, s.Keys())
		s.Remove("x")
		require.Equal(t, []string{}, s.Keys())
	})

	t.Run("make sure keys() returns a copy", func(t *testing.T) {
		input := []kv{
			kv{k: "a", v: 1},
			kv{k: "x", v: 1},
			kv{k: "c", v: 1},
			kv{k: "b", v: 1},
		}

		s := NewSet()

		for _, kv := range input {
			s.Add(kv.k, kv.v)
		}

		keys := s.Keys()
		for _, k := range keys {
			require.Equal(t, []string{"a", "b", "c", "x"}, keys)
			s.Remove(k)
		}
	})
}
