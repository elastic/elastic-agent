package http

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type mockProgressObserver struct {
	reportFailedCalls []reportFailedCall
}

type reportFailedCall struct {
	sourceURI       string
	timePast        time.Duration
	downloadedBytes float64
	totalBytes      float64
	percentComplete float64
	downloadRate    float64
	err             error
}

func (m *mockProgressObserver) Report(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64) {
	// noop
}

func (m *mockProgressObserver) ReportCompleted(sourceURI string, timePast time.Duration, downloadRate float64) {
	// noop
}

func (m *mockProgressObserver) ReportFailed(sourceURI string, timePast time.Duration, downloadedBytes, totalBytes, percentComplete, downloadRate float64, err error) {
	m.reportFailedCalls = append(m.reportFailedCalls, reportFailedCall{
		sourceURI:       sourceURI,
		timePast:        timePast,
		downloadedBytes: downloadedBytes,
		totalBytes:      totalBytes,
		percentComplete: percentComplete,
		downloadRate:    downloadRate,
		err:             err,
	})
}

func TestReportFailed(t *testing.T) {
	t.Run("should call ReportFailed on all observers with correct parameters", func(t *testing.T) {
		testErr := errors.New("test error")

		observer1 := &mockProgressObserver{}
		observer2 := &mockProgressObserver{}
		observers := []progressObserver{observer1, observer2}

		dp := &downloadProgressReporter{}
		dp.Prepare("mockurl", 10*time.Second, 1000, observers...)

		dp.Report(t.Context())

		dp.downloaded.Store(500)
		dp.started = time.Now().Add(-2 * time.Second)

		testCtx, cnFn := context.WithTimeout(t.Context(), 10*time.Second)
		defer cnFn()

		dp.ReportFailed(testErr)

		select {
		case <-testCtx.Done():
			t.Error("expected done channel to be closed")
		case <-dp.done:
			t.Log("done channel closed")
		}

		for _, obs := range observers {
			mockObs, ok := obs.(*mockProgressObserver)
			require.True(t, ok, "expected mockProgressObserver, got %T", obs)

			require.Equal(t, 1, len(mockObs.reportFailedCalls))

			call := mockObs.reportFailedCalls[0]

			expected := reportFailedCall{
				sourceURI:       "mockurl",
				timePast:        time.Now().Add(-2 * time.Second).Sub(dp.started),
				downloadedBytes: 500,
				totalBytes:      1000,
				percentComplete: 50.0,
				downloadRate:    250.0,
				err:             testErr,
			}

			require.NotEqual(t, expected, call)
		}
	})
}
