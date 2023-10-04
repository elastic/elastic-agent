// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

type State string

const (
	StateRequested   State = "UPG_REQUESTED"
	StateScheduled   State = "UPG_SCHEDULED"
	StateDownloading State = "UPG_DOWNLOADING"
	StateExtracting  State = "UPG_EXTRACTING"
	StateReplacing   State = "UPG_REPLACING"
	StateRestarting  State = "UPG_RESTARTING"
	StateWatching    State = "UPG_WATCHING"
	StateRollback    State = "UPG_ROLLBACK"
	StateCompleted   State = "UPG_COMPLETED"
	StateFailed      State = "UPG_FAILED"
)

func (s State) String() string {
	return string(s)
}
