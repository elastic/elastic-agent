// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manifest

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/magefile/mage/mg"

	artifactdownload "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
)

type fetchFunc func(ctx context.Context, url, target string) error

// DownloadArtifactWithChecksum downloads a DRA artifact together with its
// sha512 checksum file and verifies they match, retrying on a mismatch.
//
// The checksum file is fetched first, before the much larger artifact, to
// minimize the chance that the artifact is republished mid-download and no
// longer matches the checksum already on hand.
func DownloadArtifactWithChecksum(ctx context.Context, artifactURL, artifactPath, shaURL, shaPath string) error {
	return downloadArtifactWithChecksum(ctx, DownloadPackage, artifactURL, artifactPath, shaURL, shaPath)
}

func downloadArtifactWithChecksum(ctx context.Context, fetch fetchFunc, artifactURL, artifactPath, shaURL, shaPath string) error {
	var lastErr error
	for attempt, backoff := range backoffSchedule {
		if err := fetch(ctx, shaURL, shaPath); err != nil {
			return fmt.Errorf("downloading sha512 file: %w", err)
		}
		if err := fetch(ctx, artifactURL, artifactPath); err != nil {
			return fmt.Errorf("downloading artifact: %w", err)
		}

		err := artifactdownload.VerifyChecksum(sha512.New(), artifactPath, shaPath)
		if err == nil {
			return nil
		}

		var mismatchErr *artifactdownload.ChecksumMismatchError
		if !errors.As(err, &mismatchErr) {
			return err
		}

		lastErr = err

		// Remove the mismatched files so the retry re-fetches both from scratch.
		_ = os.Remove(artifactPath)
		_ = os.Remove(shaPath)

		if mg.Verbose() {
			log.Printf("checksum mismatch downloading %q (attempt %d/%d), retrying in %v: %v", artifactPath, attempt+1, len(backoffSchedule), backoff, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}

	return fmt.Errorf("checksum mismatch persisted after %d attempts: %w", len(backoffSchedule), lastErr)
}
