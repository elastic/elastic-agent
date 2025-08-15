// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

type MockStdLibFuncName string

const (
	CopyFuncName     MockStdLibFuncName = "copy"
	OpenFileFuncName MockStdLibFuncName = "openFile"
	MkdirAllFuncName MockStdLibFuncName = "mkdirAll"
)

type StdLibMocks struct {
	CopyMock     func(dst io.Writer, src io.Reader) (int64, error)
	OpenFileMock func(name string, flag int, perm os.FileMode) (*os.File, error)
	MkdirAllMock func(path string, perm os.FileMode) error
}

// PrepareStdLibMocks is a helper function that can be used to mock the stdlib
// wrappers. Replaces the wrapper with the mock and cleans up after the test.
func PrepareStdLibMocks(mocks StdLibMocks) func(t *testing.T, funcName MockStdLibFuncName) {
	setters := map[MockStdLibFuncName]func(t *testing.T){
		CopyFuncName:     func(t *testing.T) { setMock(t, &Copy, mocks.CopyMock) },
		OpenFileFuncName: func(t *testing.T) { setMock(t, &OpenFile, mocks.OpenFileMock) },
		MkdirAllFuncName: func(t *testing.T) { setMock(t, &MkdirAll, mocks.MkdirAllMock) },
	}

	return func(t *testing.T, funcName MockStdLibFuncName) {
		setter, ok := setters[funcName]
		require.True(t, ok, "mock setter for stdlib func %s not found", funcName)
		setter(t)
	}
}

func setMock[T any](t *testing.T, target *T, mock T) {
	if reflect.ValueOf(mock).IsZero() {
		return
	}

	original := *target
	*target = mock
	t.Cleanup(func() {
		*target = original
	})
}
