//go:build windows

package upgrade

import (
	"fmt"
	"testing"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/stretchr/testify/require"
	winSys "golang.org/x/sys/windows"
)

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

func (e *mockError) Is(target error) bool {
	_, ok := target.(*mockError)
	return ok
}
func TestToDiskSpaceError(t *testing.T) {
	tests := map[string]struct {
		err  error
		want error
	}{
		"ERROR_DISK_FULL":                {err: winSys.ERROR_DISK_FULL, want: ErrInsufficientDiskSpace},
		"ERROR_HANDLE_DISK_FULL":         {err: winSys.ERROR_HANDLE_DISK_FULL, want: ErrInsufficientDiskSpace},
		"wrapped ERROR_DISK_FULL":        {err: fmt.Errorf("wrapped: %w", winSys.ERROR_DISK_FULL), want: ErrInsufficientDiskSpace},
		"wrapped ERROR_HANDLE_DISK_FULL": {err: fmt.Errorf("wrapped: %w", winSys.ERROR_HANDLE_DISK_FULL), want: ErrInsufficientDiskSpace},
		"other error":                    {err: &mockError{msg: "some other error"}, want: &mockError{msg: "some other error"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			log, err := logger.New("test", true)
			require.NoError(t, err)

			got := ToDiskSpaceErrorFunc(log)(test.err)

			require.ErrorIs(t, got, test.want)
		})
	}
}
