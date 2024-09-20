// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"io"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/term"
)

// CreateAndStartNewSpinner starts a new spinner that will update every 40ms.
// when finished, it should be closed with Finish()
func CreateAndStartNewSpinner(stream io.Writer, initialMessage string) *progressbar.ProgressBar {
	progBar := progressbar.NewOptions(-1,
		progressbar.OptionSetWriter(stream),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSpinnerType(51),
		progressbar.OptionSetDescription(initialMessage),
	)

	// don't bother with the spinner refresh if we're not connected to stdout
	if term.IsTerminal(int(os.Stdout.Fd())) {
		// This keeps the progress spinner running while we're idling
		// Otherwise, the spinner would freeze until it got an update
		go func() {
			for {
				if progBar.IsFinished() {
					return
				}
				_ = progBar.RenderBlank()
				time.Sleep(time.Millisecond * 40)
			}
		}()
	}

	return progBar
}
