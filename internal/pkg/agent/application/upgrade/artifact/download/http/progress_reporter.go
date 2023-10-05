// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"context"
	"time"

	"github.com/elastic/elastic-agent-libs/atomic"
)

type downloadProgressReporter struct {
	sourceURI   string
	interval    time.Duration
	warnTimeout time.Duration
	length      float64

	downloaded atomic.Int
	started    time.Time

	progressObservers []progressObserver
}

func newDownloadProgressReporter(sourceURI string, timeout time.Duration, length int, progressObservers ...progressObserver) *downloadProgressReporter {
	interval := time.Duration(float64(timeout) * downloadProgressIntervalPercentage)
	if interval == 0 {
		interval = downloadProgressMinInterval
	}

	return &downloadProgressReporter{
		sourceURI:         sourceURI,
		interval:          interval,
		warnTimeout:       time.Duration(float64(timeout) * warningProgressIntervalPercentage),
		length:            float64(length),
		progressObservers: progressObservers,
	}
}

func (dp *downloadProgressReporter) Write(b []byte) (int, error) {
	n := len(b)
	dp.downloaded.Add(n)
	return n, nil
}

func (dp *downloadProgressReporter) Report(ctx context.Context) {
	started := time.Now()
	dp.started = started
	sourceURI := dp.sourceURI
	length := dp.length
	interval := dp.interval

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now()
				timePast := now.Sub(started)
				downloaded := float64(dp.downloaded.Load())
				bytesPerSecond := downloaded / float64(timePast/time.Second)
				var percentComplete float64
				if length > 0 {
					percentComplete = downloaded / length * 100.0
				}

				for _, obs := range dp.progressObservers {
					obs.Report(sourceURI, timePast, downloaded, length, percentComplete, bytesPerSecond)
				}
			}
		}
	}()
}

func (dp *downloadProgressReporter) ReportComplete() {
	now := time.Now()
	timePast := now.Sub(dp.started)
	downloaded := float64(dp.downloaded.Load())
	bytesPerSecond := downloaded / float64(timePast/time.Second)

	for _, obs := range dp.progressObservers {
		obs.ReportCompleted(dp.sourceURI, timePast, bytesPerSecond)
	}
}

func (dp *downloadProgressReporter) ReportFailed(err error) {
	now := time.Now()
	timePast := now.Sub(dp.started)
	downloaded := float64(dp.downloaded.Load())
	bytesPerSecond := downloaded / float64(timePast/time.Second)
	var percentComplete float64
	if dp.length > 0 {
		percentComplete = downloaded / dp.length * 100.0
	}

	for _, obs := range dp.progressObservers {
		obs.ReportFailed(dp.sourceURI, timePast, downloaded, dp.length, percentComplete, bytesPerSecond, err)
	}
}
