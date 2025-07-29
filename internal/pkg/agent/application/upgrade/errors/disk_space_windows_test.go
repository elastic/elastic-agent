//go:build windows

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package errors

import (
	"fmt"
	"testing"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
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
	t.Run("return ErrInsufficientDiskSpace for disk space errors and pass through others", func(t *testing.T) {
		tests := map[string]struct {
			err  error
			want error
		}{
			"ERROR_DISK_FULL":                {err: windows.ERROR_DISK_FULL, want: ErrInsufficientDiskSpace},
			"ERROR_HANDLE_DISK_FULL":         {err: windows.ERROR_HANDLE_DISK_FULL, want: ErrInsufficientDiskSpace},
			"wrapped ERROR_DISK_FULL":        {err: fmt.Errorf("wrapped: %w", windows.ERROR_DISK_FULL), want: ErrInsufficientDiskSpace},
			"wrapped ERROR_HANDLE_DISK_FULL": {err: fmt.Errorf("wrapped: %w", windows.ERROR_HANDLE_DISK_FULL), want: ErrInsufficientDiskSpace},
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
	})
	t.Run("does not panic when logger is nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("expected no panic, but got: %v", r)
			}
		}()
		_ = ToDiskSpaceErrorFunc(nil)(windows.ERROR_DISK_FULL)
		_ = ToDiskSpaceErrorFunc(nil)(fmt.Errorf("wrapped: %w", windows.ERROR_HANDLE_DISK_FULL))
		_ = ToDiskSpaceErrorFunc(nil)(&mockError{msg: "not disk space"})
	})
}
