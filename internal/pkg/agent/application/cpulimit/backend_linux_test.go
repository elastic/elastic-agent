// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package cpulimit

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/require"
)

func TestUnitError(t *testing.T) {
	require.ErrorIs(t, unitError(dbus.Error{Name: "org.freedesktop.systemd1.NoSuchUnit"}), errUnitNotFound)
	require.ErrorIs(t, unitError(dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownObject"}), errUnitNotFound)
	require.NotErrorIs(t, unitError(dbus.Error{Name: "org.freedesktop.DBus.Error.AccessDenied"}), errUnitNotFound)
	require.NotErrorIs(t, unitError(errors.New("timeout")), errUnitNotFound)
}

// fakeProperties returns property maps with the Go types that go-systemd gives for the D-Bus types of systemd.
type fakeProperties struct {
	t          *testing.T
	unit       map[string]any
	service    map[string]any
	unitErr    error
	serviceErr error

	serviceReads int
}

func (f *fakeProperties) GetUnitPropertiesContext(_ context.Context, unit string) (map[string]any, error) {
	require.Equal(f.t, testUnit, unit)
	return f.unit, f.unitErr
}

func (f *fakeProperties) GetUnitTypePropertiesContext(_ context.Context, unit string, unitType string) (map[string]any, error) {
	require.Equal(f.t, testUnit, unit)
	require.Equal(f.t, "Service", unitType)
	f.serviceReads++
	return f.service, f.serviceErr
}

func newFakeProperties(t *testing.T) *fakeProperties {
	return &fakeProperties{
		t: t,
		unit: map[string]any{
			"Id":          "real.service",
			"LoadState":   "loaded",
			"DropInPaths": []string{testDropIn},
			"Description": "Elastic Agent",
		},
		service: map[string]any{
			"ControlGroup":       testCgroup,
			"CPUQuotaPerSecUSec": uint64(500000),
			"MemoryMax":          uint64(quotaInfinity),
		},
	}
}

func TestReadUnit(t *testing.T) {
	t.Run("a loaded unit", func(t *testing.T) {
		info, err := readUnit(t.Context(), newFakeProperties(t), testUnit)
		require.NoError(t, err)
		require.Equal(t, unitInfo{
			id:           "real.service",
			loadState:    "loaded",
			controlGroup: testCgroup,
			cpuQuota:     500000,
			dropInPaths:  []string{testDropIn},
		}, info)
	})

	t.Run("a unit that is not loaded", func(t *testing.T) {
		f := newFakeProperties(t)
		f.unit = map[string]any{"Id": testUnit, "LoadState": "not-found"}
		info, err := readUnit(t.Context(), f, testUnit)
		require.NoError(t, err)
		require.Equal(t, unitInfo{id: testUnit, loadState: "not-found"}, info)
		require.Zero(t, f.serviceReads)
	})

	for _, name := range []string{"Id", "LoadState", "DropInPaths", "ControlGroup", "CPUQuotaPerSecUSec"} {
		t.Run("missing "+name, func(t *testing.T) {
			f := newFakeProperties(t)
			delete(f.unit, name)
			delete(f.service, name)
			_, err := readUnit(t.Context(), f, testUnit)
			require.ErrorContains(t, err, name)
		})
	}

	wrongTypes := map[string]any{
		"Id":                 dbus.ObjectPath("/org/freedesktop/systemd1/unit/elastic_2dagent_2eservice"),
		"LoadState":          []string{"loaded"},
		"DropInPaths":        testDropIn,
		"ControlGroup":       []byte(testCgroup),
		"CPUQuotaPerSecUSec": int64(500000),
	}
	for _, name := range []string{"Id", "LoadState", "DropInPaths", "ControlGroup", "CPUQuotaPerSecUSec"} {
		t.Run("wrong type of "+name, func(t *testing.T) {
			f := newFakeProperties(t)
			if _, ok := f.unit[name]; ok {
				f.unit[name] = wrongTypes[name]
			} else {
				f.service[name] = wrongTypes[name]
			}
			_, err := readUnit(t.Context(), f, testUnit)
			require.ErrorContains(t, err, name)
		})
	}

	t.Run("a failed unit read", func(t *testing.T) {
		f := newFakeProperties(t)
		readErr := errors.New("read failed")
		f.unitErr = readErr
		_, err := readUnit(t.Context(), f, testUnit)
		require.ErrorIs(t, err, readErr)
		require.NotErrorIs(t, err, errUnitNotFound)
	})

	t.Run("an unknown unit", func(t *testing.T) {
		f := newFakeProperties(t)
		f.unitErr = dbus.Error{Name: "org.freedesktop.systemd1.NoSuchUnit"}
		_, err := readUnit(t.Context(), f, testUnit)
		require.ErrorIs(t, err, errUnitNotFound)
	})

	t.Run("a failed service read", func(t *testing.T) {
		f := newFakeProperties(t)
		readErr := errors.New("read failed")
		f.serviceErr = readErr
		_, err := readUnit(t.Context(), f, testUnit)
		require.ErrorIs(t, err, readErr)
	})
}
