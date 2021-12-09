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

package cli

import (
	"bytes"
	"io"
	"os"
)

// IOStreams encapsulate the interaction with the OS pipes: STDIN, STDOUT and STDERR.
// Simplifies the access to the streams without having to pass around multiples PIPES and allow
// for a more uniform testing of the application.
type IOStreams struct {
	// In represents the STDIN of the CLI.
	In io.Reader

	// Out represents the STDOUT of the CLI.
	Out io.Writer

	// Err represents the STDERR of the CLI.
	Err io.Writer
}

// NewIOStreams returns an IOStreams with the OS defaults pipes.
func NewIOStreams() *IOStreams {
	return &IOStreams{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
}

// NewTestingIOStreams returns a IOStream and the raw bytes buffers so we can interact with them.
// Note: mostly used for testing.
func NewTestingIOStreams() (*IOStreams, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	in := &bytes.Buffer{}
	out := &bytes.Buffer{}
	err := &bytes.Buffer{}
	return &IOStreams{In: in, Out: out, Err: err}, in, out, err
}
