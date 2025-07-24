//go:build windows

package upgrade

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	winSys "golang.org/x/sys/windows"
)

func TestToDiskSpaceError(t *testing.T) {
	tests := map[string]struct {
		err  error
		want error
	}{
		"ERROR_DISK_FULL":                {err: winSys.ERROR_DISK_FULL, want: errors.New(insufficientDiskSpaceErrorStr)},
		"ERROR_HANDLE_DISK_FULL":         {err: winSys.ERROR_HANDLE_DISK_FULL, want: errors.New(insufficientDiskSpaceErrorStr)},
		"wrapped ERROR_DISK_FULL":        {err: fmt.Errorf("wrapped: %w", winSys.ERROR_DISK_FULL), want: errors.New(insufficientDiskSpaceErrorStr)},
		"wrapped ERROR_HANDLE_DISK_FULL": {err: fmt.Errorf("wrapped: %w", winSys.ERROR_HANDLE_DISK_FULL), want: errors.New(insufficientDiskSpaceErrorStr)},
		"other error":                    {err: errors.New("some other error"), want: errors.New("some other error")},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := ToDiskSpaceError(test.err)
			require.Equal(t, test.want, got)
		})
	}
}
