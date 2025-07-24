package http

import (
	"fmt"
	"testing"
	"time"
)

func TestReportFailed(t *testing.T) {
	t.Run("should call diskSpaceErrorFunc with the provided error", func(t *testing.T) {
		count := 0
		diskSpaceErrorFunc := func(err error) error {
			count++
			return err
		}
		dp := newDownloadProgressReporter("test", 10*time.Second, 100, diskSpaceErrorFunc)
		dp.ReportFailed(fmt.Errorf("test"))

		if count != 1 {
			t.Errorf("expected diskSpaceErrorFunc to be called once, got %d", count)
		}
	})
}
