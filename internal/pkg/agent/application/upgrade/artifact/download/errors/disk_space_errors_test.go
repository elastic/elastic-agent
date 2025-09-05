// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package errors

import (
	goerrors "errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	agentErrors "github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

func TestIsDiskSpaceError(t *testing.T) {
	for _, err := range OS_DiskSpaceErrors {
		testCases := map[string]struct {
			err  error
			want bool
		}{
			"os_error":         {err: err, want: true},
			"wrapped_os_error": {err: fmt.Errorf("wrapped: %w", err), want: true},
			"joined_error":     {err: goerrors.Join(err, goerrors.New("test")), want: true},
			"new_error":        {err: agentErrors.New(err, fmt.Errorf("test")), want: false},
		}
		for name, tc := range testCases {
			t.Run(fmt.Sprintf("%s_%s", err.Error(), name), func(t *testing.T) {
				require.Equal(t, tc.want, IsDiskSpaceError(tc.err))
			})
		}
	}
}
