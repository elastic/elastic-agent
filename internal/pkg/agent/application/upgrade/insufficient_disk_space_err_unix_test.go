//go:build !windows

package upgrade

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToDiskSpaceError(t *testing.T) {
	tests := map[string]struct {
		err  error
		want error
	}{
		"ENOSPC":         {err: syscall.ENOSPC, want: errors.New(insufficientDiskSpaceErrorStr)},
		"EDQUOT":         {err: syscall.EDQUOT, want: errors.New(insufficientDiskSpaceErrorStr)},
		"wrapped ENOSPC": {err: fmt.Errorf("wrapped: %w", syscall.ENOSPC), want: errors.New(insufficientDiskSpaceErrorStr)},
		"wrapped EDQUOT": {err: fmt.Errorf("wrapped: %w", syscall.EDQUOT), want: errors.New(insufficientDiskSpaceErrorStr)},
		"other error":    {err: errors.New("some other error"), want: errors.New("some other error")},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := ToDiskSpaceError(test.err)
			require.Equal(t, test.want, got)
		})
	}
}
