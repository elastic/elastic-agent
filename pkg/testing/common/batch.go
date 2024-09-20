package common

import (
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// OSBatch defines the mapping between a SupportedOS and a define.Batch.
type OSBatch struct {
	// ID is the unique ID for the batch.
	ID string
	// LayoutOS provides all the OS information to create an instance.
	OS SupportedOS
	// Batch defines the batch of tests to run on this layout.
	Batch define.Batch
	// Skip defines if this batch will be skipped because no supported layout exists yet.
	Skip bool
}
