// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/docker/go-units"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

func TestDetailsProgressObserver(t *testing.T) {
	upgradeDetails := details.NewDetails("8.11.0", details.StateRequested, "")
	detailsObs := newDetailsProgressObserver(upgradeDetails)

	detailsObs.Report("http://some/uri", 20*time.Second, 400*units.MiB, 500*units.MiB, 0.8, 4455)
	require.Equal(t, details.StateDownloading, upgradeDetails.State)
	require.Equal(t, 0.8, upgradeDetails.Metadata.DownloadPercent)

	detailsObs.ReportCompleted("http://some/uri", 30*time.Second, 3333)
	require.Equal(t, details.StateDownloading, upgradeDetails.State)
	require.Equal(t, 1.0, upgradeDetails.Metadata.DownloadPercent)

	err := errors.New("some download error")
	detailsObs.ReportFailed("http://some/uri", 30*time.Second, 450*units.MiB, 500*units.MiB, 0.9, 1122, err)
	require.Equal(t, details.StateFailed, upgradeDetails.State)
	require.Equal(t, details.StateDownloading, upgradeDetails.Metadata.FailedState)
	require.Equal(t, err.Error(), upgradeDetails.Metadata.ErrorMsg)
}
