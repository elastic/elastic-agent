//go:build windows

package upgrade

import (
	"fmt"
	"testing"

	"github.com/cenkalti/backoff/v4"
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
		err            error
		want           error
		permanentError bool
	}{
		"ERROR_DISK_FULL":                {err: winSys.ERROR_DISK_FULL, want: insufficientDiskSpaceErr, permanentError: true},
		"ERROR_HANDLE_DISK_FULL":         {err: winSys.ERROR_HANDLE_DISK_FULL, want: insufficientDiskSpaceErr, permanentError: true},
		"wrapped ERROR_DISK_FULL":        {err: fmt.Errorf("wrapped: %w", winSys.ERROR_DISK_FULL), want: insufficientDiskSpaceErr, permanentError: true},
		"wrapped ERROR_HANDLE_DISK_FULL": {err: fmt.Errorf("wrapped: %w", winSys.ERROR_HANDLE_DISK_FULL), want: insufficientDiskSpaceErr, permanentError: true},
		"other error":                    {err: &mockError{msg: "some other error"}, want: &mockError{msg: "some other error"}, permanentError: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := ToDiskSpaceError(test.err)

			if test.permanentError {
				require.ErrorIs(t, got, &backoff.PermanentError{})
			}
			require.ErrorIs(t, got, test.want)
		})
	}
}
