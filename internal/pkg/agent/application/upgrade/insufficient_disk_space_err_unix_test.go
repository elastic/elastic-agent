//go:build !windows

package upgrade

import (
	"fmt"
	"syscall"
	"testing"

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
		err  error
		want error
	}{
		"ENOSPC":         {err: syscall.ENOSPC, want: ErrInsufficientDiskSpace},
		"EDQUOT":         {err: syscall.EDQUOT, want: ErrInsufficientDiskSpace},
		"wrapped ENOSPC": {err: fmt.Errorf("wrapped: %w", syscall.ENOSPC), want: ErrInsufficientDiskSpace},
		"wrapped EDQUOT": {err: fmt.Errorf("wrapped: %w", syscall.EDQUOT), want: ErrInsufficientDiskSpace},
		"other error":    {err: &mockError{msg: "some other error"}, want: &mockError{msg: "some other error"}},
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
