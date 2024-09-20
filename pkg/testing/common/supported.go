package common

import "github.com/elastic/elastic-agent/pkg/testing/define"

// SupportedOS maps a OS definition to a OSRunner.
type SupportedOS struct {
	define.OS

	// Runner is the runner to use for the OS.
	Runner OSRunner
}
