// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"time"

	"github.com/docker/go-units"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type progressObserver interface {
	// Report is called on a periodic basis with information about the download's progress so far.
	Report(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64)

	// ReportComplete is called when the download completes successfully.
	ReportComplete(sourceURI string, timePast time.Duration, downloadRate float64)

	// ReportFailed is called if the download does not complete successfully.
	ReportFailed(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64, err error)
}

type loggerProgressObserver struct {
	log         *logger.Logger
	warnTimeout time.Duration
}

func newLoggerProgressObserver(log *logger.Logger, downloadTimeout time.Duration) *loggerProgressObserver {
	return &loggerProgressObserver{
		log:         log,
		warnTimeout: time.Duration(float64(downloadTimeout) * warningProgressIntervalPercentage),
	}
}

func (plo *loggerProgressObserver) Report(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64) {
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

	plo.log.Infof(msg, args...)
	if timePast >= plo.warnTimeout {
		// duplicate to warn when over the warnTimeout; this still has it logging to info that way if
		// they are filtering the logs to info they still see the messages when over the warnTimeout, but
		// when filtering only by warn they see these messages only
		plo.log.Warnf(msg, args...)
	}
}

func (plo *loggerProgressObserver) ReportComplete(sourceURI string, timePast time.Duration, downloadRate float64) {
	msg := "download from %s completed in %s @ %sps"
	args := []interface{}{
		sourceURI, units.HumanDuration(timePast), units.HumanSize(downloadRate),
	}
	plo.log.Infof(msg, args...)
	if timePast >= plo.warnTimeout {
		// see reason in `Report`
		plo.log.Warnf(msg, args...)
	}
}

func (plo *loggerProgressObserver) ReportFailed(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64, err error) {
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
	plo.log.Infof(msg, args...)
	if timePast >= plo.warnTimeout {
		// see reason in `Report`
		plo.log.Warnf(msg, args...)
	}
}
