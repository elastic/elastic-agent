// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cproto

const (
	// StateWatchBufferSizeLatestOnly configures a StateWatch subscription to
	// always deliver the most recent state at each read, skipping any
	// intermediate transitions that accumulated since the previous read.
	StateWatchBufferSizeLatestOnly int32 = 0

	// StateWatchBufferSizeAllAvailable configures a StateWatch subscription to
	// receive all buffered transitions in order, up to the server's internal
	// maximum (currently 32). This matches the server default for subscribers
	// that send no explicit buffer_size.
	StateWatchBufferSizeAllAvailable int32 = 32
)
