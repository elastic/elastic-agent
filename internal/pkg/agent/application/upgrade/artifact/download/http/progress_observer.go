// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package http

import (
	"sync"
	"time"

	"github.com/docker/go-units"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type progressObserver interface {
	// Report is called on a periodic basis with information about the download's progress so far.
	Report(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64)

	// ReportCompleted is called when the download completes successfully.
	ReportCompleted(sourceURI string, timePast time.Duration, downloadRate float64)

	// ReportFailed is called if the download does not complete successfully.
	ReportFailed(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64, err error)
}

type loggingProgressObserver struct {
	log         *logger.Logger
	warnTimeout time.Duration
}

func newLoggingProgressObserver(log *logger.Logger, downloadTimeout time.Duration) *loggingProgressObserver {
	return &loggingProgressObserver{
		log:         log,
		warnTimeout: time.Duration(float64(downloadTimeout) * warningProgressIntervalPercentage),
	}
}

func (lpObs *loggingProgressObserver) Report(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64) {
	var msg string
	var args []interface{}
	if totalBytes > 0 {
		// length of the download is known, so more detail can be provided
		msg = "download progress from %s is %s/%s (%.2f%% complete) @ %sps"
		args = []interface{}{
			sourceURI, units.HumanSize(downloadedBytes), units.HumanSize(totalBytes), percentComplete, units.HumanSize(downloadRate),
		}
	} else {
		// length unknown so provide the amount downloaded and the speed
		msg = "download progress from %s has fetched %s @ %sps"
		args = []interface{}{
			sourceURI, units.HumanSize(downloadedBytes), units.HumanSize(downloadRate),
		}
	}

	lpObs.log.Infof(msg, args...)
	if timePast >= lpObs.warnTimeout {
		// duplicate to warn when over the warnTimeout; this still has it logging to info that way if
		// they are filtering the logs to info they still see the messages when over the warnTimeout, but
		// when filtering only by warn they see these messages only
		lpObs.log.Warnf(msg, args...)
	}
}

func (lpObs *loggingProgressObserver) ReportCompleted(sourceURI string, timePast time.Duration, downloadRate float64) {
	msg := "download from %s completed in %s @ %sps"
	args := []interface{}{
		sourceURI, units.HumanDuration(timePast), units.HumanSize(downloadRate),
	}
	lpObs.log.Infof(msg, args...)
	if timePast >= lpObs.warnTimeout {
		// see reason in `Report`
		lpObs.log.Warnf(msg, args...)
	}
}

func (lpObs *loggingProgressObserver) ReportFailed(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64, err error) {
	var msg string
	var args []interface{}
	if totalBytes > 0 {
		// length of the download is known, so more detail can be provided
		msg = "download from %s failed at %s/%s (%.2f%% complete) @ %sps: %s"
		args = []interface{}{
			sourceURI, units.HumanSize(downloadedBytes), units.HumanSize(totalBytes), percentComplete, units.HumanSize(downloadRate), err,
		}
	} else {
		// length unknown so provide the amount downloaded and the speed
		msg = "download from %s failed at %s @ %sps: %s"
		args = []interface{}{
			sourceURI, units.HumanSize(downloadedBytes), units.HumanSize(downloadRate), err,
		}
	}
	lpObs.log.Infof(msg, args...)
	if timePast >= lpObs.warnTimeout {
		// see reason in `Report`
		lpObs.log.Warnf(msg, args...)
	}
}

type detailsProgressObserver struct {
	upgradeDetails *details.Details
	mu             sync.RWMutex
}

func newDetailsProgressObserver(upgradeDetails *details.Details) *detailsProgressObserver {
	upgradeDetails.SetState(details.StateDownloading)
	return &detailsProgressObserver{
		upgradeDetails: upgradeDetails,
	}
}

func (dpObs *detailsProgressObserver) Report(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRateBytesPerSecond float64) {
	dpObs.mu.Lock()
	defer dpObs.mu.Unlock()

	dpObs.upgradeDetails.SetDownloadProgress(percentComplete, downloadRateBytesPerSecond)
}

func (dpObs *detailsProgressObserver) ReportCompleted(sourceURI string, timePast time.Duration, downloadRateBytesPerSecond float64) {
	dpObs.mu.Lock()
	defer dpObs.mu.Unlock()

	dpObs.upgradeDetails.SetDownloadProgress(1, downloadRateBytesPerSecond)
}

func (dpObs *detailsProgressObserver) ReportFailed(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRateBytesPerSecond float64, err error) {
	dpObs.mu.Lock()
	defer dpObs.mu.Unlock()

	dpObs.upgradeDetails.Fail(err)
}
