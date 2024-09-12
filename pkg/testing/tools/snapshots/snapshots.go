// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package snapshots

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/elastic/elastic-agent/pkg/version"
)

const (
	snapshotsBaseURL = "https://snapshots.elastic.co"
)

var (
	errNoSnapshot = errors.New("snapshot not found")
)

type response struct {
	// Version contains the actual semantic version, e.g. `8.12.1-SNAPSHOT`
	Version string `json:"version"`
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type SnapshotsClientOpt func(pvc *SnapshotsClient)

func WithUrl(url string) SnapshotsClientOpt {
	return func(pvc *SnapshotsClient) { pvc.url = url }
}

func WithHttpClient(client httpDoer) SnapshotsClientOpt {
	return func(pvc *SnapshotsClient) { pvc.c = client }
}

type SnapshotsClient struct {
	c   httpDoer
	url string
}

// NewSnapshotsClient creates a new client applying all the given options.
// If not set by the options, the new client will use the default HTTP client and
// the default URL from `snapshotsBaseURL`.
//
// All the timeout/retry/backoff behavior must be implemented by the `httpDoer` interface
// and set by the `WithClient` option.
func NewSnapshotsClient(opts ...SnapshotsClientOpt) *SnapshotsClient {
	c := &SnapshotsClient{
		url: snapshotsBaseURL,
		c:   http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// FindLatestSnapshots returns a sortable list of parsed semantic versions that point
// to the latest snapshot for each given branch.
// Takes `branches` as a list of known active release branches to check for the presence of a snapshot.
// The `branches` list should not contain duplicates to avoid redundant requests.
func (sc *SnapshotsClient) FindLatestSnapshots(ctx context.Context, branches []string) (version.SortableParsedVersions, error) {
	var versionList version.SortableParsedVersions
	for _, b := range branches {
		ssVersion, err := sc.findLatestSnapshot(ctx, b)
		if errors.Is(err, errNoSnapshot) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to request snapshot for branch %s: %w", b, err)
		}
		versionList = append(versionList, ssVersion)
	}

	return versionList, nil
}

func (sc *SnapshotsClient) findLatestSnapshot(ctx context.Context, branch string) (snapshot *version.ParsedSemVer, err error) {
	// TODO: find a proper fix.
	if branch == "8.x" {
		branch = "master"
	}

	url := sc.url + fmt.Sprintf("/latest/%s.json", branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		err = fmt.Errorf("failed to create request: %w", err)
		return nil, err
	}

	resp, err := sc.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		d := json.NewDecoder(resp.Body)
		var snapshotInfo response
		err = d.Decode(&snapshotInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to decode JSON: %w", err)
		}
		parsed, err := version.ParseVersion(snapshotInfo.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to parse version %s: %w", snapshotInfo.Version, err)
		}
		return parsed, nil

	case http.StatusNotFound:
		return nil, fmt.Errorf("branch %s has no snapshot: %w", branch, errNoSnapshot)

	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
