// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cli

import (
	"bytes"
	"io"
	"os"
	"sync"
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
// The returned bytes buffers are goroutine safe
// Note: mostly used for testing.
func NewTestingIOStreams() (*IOStreams, *SyncBuffer, *SyncBuffer, *SyncBuffer) {
	in := &SyncBuffer{}
	out := &SyncBuffer{}
	err := &SyncBuffer{}
	return &IOStreams{In: in, Out: out, Err: err}, in, out, err
}

// SyncBuffer is a goroutine safe bytes.Buffer
type SyncBuffer struct {
	buffer bytes.Buffer
	mutex  sync.RWMutex
}

// Write appends the contents of p to the buffer, growing the buffer as needed. It returns
// the number of bytes written.
func (s *SyncBuffer) Write(p []byte) (n int, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.buffer.Write(p)
}

// Read reads the next len(p) bytes from the buffer or until the buffer
// is drained. The return value n is the number of bytes read. If the
// buffer has no data to return, err is io.EOF (unless len(p) is zero);
// otherwise it is nil.
func (s *SyncBuffer) Read(p []byte) (n int, err error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.buffer.Read(p)
}

// String returns the contents of the unread portion of the buffer
// as a string.  If the Buffer is a nil pointer, it returns "<nil>".
func (s *SyncBuffer) String() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.buffer.String()
}
