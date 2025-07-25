//go:build !windows

package upgrade

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/cenkalti/backoff/v4"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/stretchr/testify/require"
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
		"ENOSPC":         {err: syscall.ENOSPC, want: ErrInsufficientDiskSpace, permanentError: true},
		"EDQUOT":         {err: syscall.EDQUOT, want: ErrInsufficientDiskSpace, permanentError: true},
		"wrapped ENOSPC": {err: fmt.Errorf("wrapped: %w", syscall.ENOSPC), want: ErrInsufficientDiskSpace, permanentError: true},
		"wrapped EDQUOT": {err: fmt.Errorf("wrapped: %w", syscall.EDQUOT), want: ErrInsufficientDiskSpace, permanentError: true},
		"other error":    {err: &mockError{msg: "some other error"}, want: &mockError{msg: "some other error"}, permanentError: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			log, err := logger.New("test", true)
			require.NoError(t, err)

			got := ToDiskSpaceErrorFunc(log)(test.err)
			if test.permanentError {
				require.ErrorIs(t, got, &backoff.PermanentError{})
			}
			require.ErrorIs(t, got, test.want)
		})
	}
}
