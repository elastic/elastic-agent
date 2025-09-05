// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package agentservice

var (
	StopChanBeat chan bool
)

func init() {
	StopChanBeat = make(chan bool)
}
