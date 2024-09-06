// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"golang.org/x/exp/maps"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func Test_distinctPaths(t *testing.T) {
	firstParentDir := t.TempDir()
	secondParentDir := t.TempDir()

	childDir := filepath.Join(secondParentDir, "child")

	childChildDir := filepath.Join(childDir, "child")

	pathsToChown := distinctPaths{}
	pathsToChown.addPath(childDir)
	pathsToChown.addPath(secondParentDir)
	pathsToChown.addPath(childChildDir)
	pathsToChown.addPath(firstParentDir)

	require.EqualValues(t, distinctPaths{firstParentDir: {}, secondParentDir: {}}, pathsToChown)

	err := pathsToChown.chown(os.Getuid(), os.Getgid())
	require.NoError(t, err)
}

func Test_chownPaths(t *testing.T) {
	t.Cleanup(func() {
		capProcFunc = func() capProc {
			return cap.GetProc()
		}
	})

	tc := []struct {
		name           string
		mockedProcCaps *mockCapProc
		expectErr      bool
		expectedCaps   []cap.Value
	}{
		{
			name: "has CHOWN capability",
			mockedProcCaps: &mockCapProc{
				effectiveCaps: map[cap.Value]struct{}{cap.CHOWN: {}},
			},
			expectErr: false,
		},
		{
			name: "has DAC_OVERRIDE capability",
			mockedProcCaps: &mockCapProc{
				effectiveCaps: map[cap.Value]struct{}{cap.DAC_OVERRIDE: {}},
			},
			expectErr: false,
		},
		{
			name: "has neither CHOWN nor DAC_OVERRIDE capabilities",
			mockedProcCaps: &mockCapProc{
				effectiveCaps: map[cap.Value]struct{}{cap.BPF: {}, cap.SETFCAP: {}},
			},
			expectErr: true,
		},
		{
			name: "get flag error",
			mockedProcCaps: &mockCapProc{
				getFlagErr: errors.New("error"),
			},
			expectErr: true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			capProcFunc = func() capProc {
				return tt.mockedProcCaps
			}

			err := chownPaths(t.TempDir())
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func Test_raiseEffectiveCapabilities(t *testing.T) {
	t.Cleanup(func() {
		capProcFunc = func() capProc {
			return cap.GetProc()
		}
	})

	tc := []struct {
		name           string
		mockedProcCaps *mockCapProc
		expectErr      bool
		expectedCaps   []cap.Value
	}{
		{
			name: "set effective and inheritable",
			mockedProcCaps: &mockCapProc{
				effectiveCaps:   map[cap.Value]struct{}{},
				inheritableCaps: map[cap.Value]struct{}{},
				permittedCaps:   map[cap.Value]struct{}{cap.CHOWN: {}, cap.BPF: {}},
			},
			expectedCaps: []cap.Value{cap.CHOWN, cap.BPF},
			expectErr:    false,
		},
		{
			name: "no caps to set",
			mockedProcCaps: &mockCapProc{
				effectiveCaps:   map[cap.Value]struct{}{},
				inheritableCaps: map[cap.Value]struct{}{},
				permittedCaps:   map[cap.Value]struct{}{},
				setProcErr:      errors.New("error"),
			},
			expectedCaps: []cap.Value{},
			expectErr:    false,
		},
		{
			name: "no caps to set - already set",
			mockedProcCaps: &mockCapProc{
				effectiveCaps:   map[cap.Value]struct{}{cap.CHOWN: {}, cap.BPF: {}},
				inheritableCaps: map[cap.Value]struct{}{cap.CHOWN: {}, cap.BPF: {}},
				permittedCaps:   map[cap.Value]struct{}{cap.CHOWN: {}, cap.BPF: {}},
				setProcErr:      errors.New("error"),
			},
			expectedCaps: []cap.Value{cap.CHOWN, cap.BPF},
			expectErr:    false,
		},
		{
			name: "set effective and inheritable with different caps",
			mockedProcCaps: &mockCapProc{
				effectiveCaps:   map[cap.Value]struct{}{cap.CHOWN: {}},
				inheritableCaps: map[cap.Value]struct{}{cap.BPF: {}},
				permittedCaps:   map[cap.Value]struct{}{cap.CHOWN: {}, cap.BPF: {}},
			},
			expectedCaps: []cap.Value{cap.CHOWN, cap.BPF},
			expectErr:    false,
		},
		{
			name: "set effective and inheritable get flag error",
			mockedProcCaps: &mockCapProc{
				getFlagErr: errors.New("error"),
			},
			expectErr: true,
		},
		{
			name: "set effective and inheritable set flag error",
			mockedProcCaps: &mockCapProc{
				effectiveCaps:   map[cap.Value]struct{}{},
				inheritableCaps: map[cap.Value]struct{}{},
				permittedCaps:   map[cap.Value]struct{}{cap.CHOWN: {}, cap.BPF: {}},
				setFlagErr:      errors.New("error"),
			},
			expectErr: true,
		},
		{
			name: "set effective and inheritable set proc error",
			mockedProcCaps: &mockCapProc{
				effectiveCaps:   map[cap.Value]struct{}{},
				inheritableCaps: map[cap.Value]struct{}{},
				permittedCaps:   map[cap.Value]struct{}{cap.CHOWN: {}, cap.BPF: {}},
				setProcErr:      errors.New("error"),
			},
			expectErr: true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			capProcFunc = func() capProc {
				return tt.mockedProcCaps
			}

			err := raiseEffectiveCapabilities()
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.ElementsMatch(t, tt.expectedCaps, maps.Keys(tt.mockedProcCaps.effectiveCaps))
				require.ElementsMatch(t, tt.expectedCaps, maps.Keys(tt.mockedProcCaps.inheritableCaps))
			}
		})
	}
}

func Test_raiseAmbientCapabilities(t *testing.T) {
	t.Cleanup(func() {
		capProcFunc = func() capProc {
			return cap.GetProc()
		}
		capBoundFunc = func() capBound {
			return cap.NewIAB()
		}
	})

	tc := []struct {
		name                string
		mockedProcCaps      *mockCapProc
		mockedBoundCaps     *mockCapBound
		expectErr           bool
		expectedAmbientCaps []cap.Value
	}{
		{
			name: "no ambient caps to set due to cap exclusion",
			mockedProcCaps: &mockCapProc{
				effectiveCaps: map[cap.Value]struct{}{cap.SETPCAP: {}, cap.SETFCAP: {}},
			},
			mockedBoundCaps:     &mockCapBound{},
			expectErr:           false,
			expectedAmbientCaps: []cap.Value{},
		},
		{
			name: "no ambient caps to set",
			mockedProcCaps: &mockCapProc{
				effectiveCaps: map[cap.Value]struct{}{},
			},
			mockedBoundCaps:     &mockCapBound{},
			expectErr:           false,
			expectedAmbientCaps: []cap.Value{},
		},
		{
			name: "ambient caps to set",
			mockedProcCaps: &mockCapProc{
				effectiveCaps: map[cap.Value]struct{}{cap.SETPCAP: {}, cap.SETFCAP: {}, cap.CHOWN: {}, cap.BPF: {}},
			},
			mockedBoundCaps: &mockCapBound{
				ambientCaps: map[cap.Value]struct{}{},
			},
			expectErr: false,
			expectedAmbientCaps: []cap.Value{
				cap.CHOWN, cap.BPF,
			},
		},
		{
			name: "ambient caps get flag err",
			mockedProcCaps: &mockCapProc{
				getFlagErr: errors.New("error"),
			},
			expectErr: true,
		},
		{
			name: "ambient caps set vector err",
			mockedProcCaps: &mockCapProc{
				effectiveCaps: map[cap.Value]struct{}{cap.SETPCAP: {}, cap.SETFCAP: {}, cap.CHOWN: {}, cap.BPF: {}},
			},
			mockedBoundCaps: &mockCapBound{
				setVectorErr: errors.New("error"),
			},
			expectErr: true,
		},
		{
			name: "ambient caps set proc err",
			mockedProcCaps: &mockCapProc{
				effectiveCaps: map[cap.Value]struct{}{cap.SETPCAP: {}, cap.SETFCAP: {}, cap.CHOWN: {}, cap.BPF: {}},
			},
			mockedBoundCaps: &mockCapBound{
				ambientCaps: map[cap.Value]struct{}{},
				setProcErr:  errors.New("error"),
			},
			expectErr: true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			capProcFunc = func() capProc {
				return tt.mockedProcCaps
			}
			capBoundFunc = func() capBound {
				return tt.mockedBoundCaps
			}

			err := raiseAmbientCapabilities()
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.ElementsMatch(t, tt.expectedAmbientCaps, maps.Keys(tt.mockedBoundCaps.ambientCaps))
			}
		})
	}
}

var _ capProc = &mockCapProc{}

type mockCapProc struct {
	effectiveCaps   map[cap.Value]struct{}
	inheritableCaps map[cap.Value]struct{}
	permittedCaps   map[cap.Value]struct{}
	setFlagErr      error
	getFlagErr      error
	setProcErr      error
}

func (m *mockCapProc) GetFlag(vec cap.Flag, val cap.Value) (bool, error) {
	if m.getFlagErr != nil {
		return false, m.getFlagErr
	}

	switch vec {
	case cap.Effective:
		_, ok := m.effectiveCaps[val]
		return ok, nil
	case cap.Inheritable:
		_, ok := m.inheritableCaps[val]
		return ok, nil
	case cap.Permitted:
		_, ok := m.permittedCaps[val]
		return ok, nil
	default:
		return false, nil
	}
}
func (m *mockCapProc) SetFlag(vec cap.Flag, enable bool, val ...cap.Value) error {
	if m.setFlagErr != nil {
		return m.setFlagErr
	}

	var targetMap map[cap.Value]struct{}
	switch vec {
	case cap.Effective:
		targetMap = m.effectiveCaps
	case cap.Inheritable:
		targetMap = m.inheritableCaps
	case cap.Permitted:
		targetMap = m.permittedCaps
	default:
		return nil
	}

	for _, v := range val {
		if enable {
			targetMap[v] = struct{}{}
		} else {
			delete(targetMap, v)
		}
	}
	return nil
}

func (m *mockCapProc) SetProc() error {
	return m.setProcErr
}

var _ capBound = &mockCapBound{}

type mockCapBound struct {
	ambientCaps  map[cap.Value]struct{}
	setVectorErr error
	setProcErr   error
}

func (m *mockCapBound) SetVector(vec cap.Vector, raised bool, vals ...cap.Value) error {
	if m.setVectorErr != nil {
		return m.setVectorErr
	}

	var targetMap map[cap.Value]struct{}
	switch vec {
	case cap.Amb:
		targetMap = m.ambientCaps
	default:
		return nil
	}

	for _, v := range vals {
		if raised {
			targetMap[v] = struct{}{}
		} else {
			delete(targetMap, v)
		}
	}
	return nil
}

func (m *mockCapBound) SetProc() error {
	return m.setProcErr
}
