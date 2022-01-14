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

package id

import (
	"math/rand"
	"sync"
	"time"

	"github.com/oklog/ulid"
)

// ID represents a unique ID.
type ID = ulid.ULID

// rand.New is not threadsafe, so we create a pool of rand to speed up the id generation.
var randPool = sync.Pool{
	New: func() interface{} {
		t := time.Now()
		return rand.New(rand.NewSource(t.UnixNano()))
	},
}

// Generate returns and ID or an error if we cannot generate an ID.
func Generate() (ID, error) {
	r := randPool.Get().(*rand.Rand)
	defer randPool.Put(r)

	t := time.Now()
	entropy := ulid.Monotonic(r, 0)
	return ulid.New(ulid.Timestamp(t), entropy)
}
