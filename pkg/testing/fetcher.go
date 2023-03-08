package testing

import (
	"context"
	"errors"
)

var (
	// ErrVersionMismatch returned when the version doesn't match.
	ErrVersionMismatch = errors.New("version doesn't match")
)

// Fetcher provides a path for fetching the Elastic Agent compressed archive
// to extract and run for the integration test.
type Fetcher interface {
	// Fetch fetches the Elastic Agent compressed archive to extract and run for the integration test.
	//
	// The extraction is handled by the caller. This should only download the file
	// and place it into the directory.
	Fetch(ctx context.Context, operatingSystem string, architecture string, version string, dir string) (string, error)
}
