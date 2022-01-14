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

package app

// Tag is a tag for specifying metadata related
// to a process.
type Tag string

// TagSidecar tags a sidecar process
const TagSidecar = "sidecar"

// Taggable is an object containing tags.
type Taggable interface {
	Tags() map[Tag]string
}

// IsSidecar returns true if tags contains sidecar flag.
func IsSidecar(descriptor Taggable) bool {
	tags := descriptor.Tags()
	_, isSidecar := tags[TagSidecar]
	return isSidecar
}
