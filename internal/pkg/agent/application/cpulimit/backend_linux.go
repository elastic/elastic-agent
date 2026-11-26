// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package cpulimit

import (
	"context"
	"errors"
	"fmt"
	"os"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
)

// NewBackend returns the Backend for this platform. On Linux it changes the runtime CPU quota of the systemd service
// serviceName and reports hosts without systemd, cgroup v2 or root as unsupported.
func NewBackend(serviceName string) Backend {
	return &systemdBackend{
		unit:        serviceName + ".service",
		root:        "/",
		runtimeDirs: systemRuntimeDirs,
		euid:        os.Geteuid,
		connect:     connectSystemd,
	}
}

// dbusConn is the systemd D-Bus API.
type dbusConn struct {
	conn *sddbus.Conn
}

// connectSystemd opens a direct connection to the systemd private socket, so no D-Bus daemon is needed.
func connectSystemd(ctx context.Context) (systemdConn, error) {
	conn, err := sddbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return nil, err
	}
	return dbusConn{conn: conn}, nil
}

// unitPropertyReader is the part of *sddbus.Conn that readUnit uses.
type unitPropertyReader interface {
	GetUnitPropertiesContext(ctx context.Context, unit string) (map[string]any, error)
	GetUnitTypePropertiesContext(ctx context.Context, unit string, unitType string) (map[string]any, error)
}

func (d dbusConn) unit(ctx context.Context, name string) (unitInfo, error) {
	return readUnit(ctx, d.conn, name)
}

// readUnit reads the unit properties of name. For a unit that is not loaded it reads only id and loadState, because
// the backend needs nothing more then.
func readUnit(ctx context.Context, r unitPropertyReader, name string) (unitInfo, error) {
	props, err := r.GetUnitPropertiesContext(ctx, name)
	if err != nil {
		return unitInfo{}, unitError(err)
	}
	var info unitInfo
	if info.id, err = property[string](props, "Id"); err != nil {
		return unitInfo{}, err
	}
	if info.loadState, err = property[string](props, "LoadState"); err != nil {
		return unitInfo{}, err
	}
	if info.loadState != "loaded" {
		return info, nil
	}
	if info.dropInPaths, err = property[[]string](props, "DropInPaths"); err != nil {
		return unitInfo{}, err
	}
	props, err = r.GetUnitTypePropertiesContext(ctx, name, "Service")
	if err != nil {
		return unitInfo{}, unitError(err)
	}
	if info.controlGroup, err = property[string](props, "ControlGroup"); err != nil {
		return unitInfo{}, err
	}
	if info.cpuQuota, err = property[uint64](props, "CPUQuotaPerSecUSec"); err != nil {
		return unitInfo{}, err
	}
	return info, nil
}

func property[T any](props map[string]any, name string) (T, error) {
	v, ok := props[name].(T)
	if !ok {
		return v, fmt.Errorf("invalid %s property", name)
	}
	return v, nil
}

func (d dbusConn) setCPUQuota(ctx context.Context, name string, usec uint64) error {
	return d.conn.SetUnitPropertiesContext(ctx, name, true, sddbus.Property{
		Name:  "CPUQuotaPerSecUSec",
		Value: dbus.MakeVariant(usec),
	})
}

func (d dbusConn) reload(ctx context.Context) error {
	return d.conn.ReloadContext(ctx)
}

func (d dbusConn) close() {
	d.conn.Close()
}

// unitError wraps errUnitNotFound when systemd reports that it does not know the unit.
func unitError(err error) error {
	var dbusErr dbus.Error
	if errors.As(err, &dbusErr) &&
		(dbusErr.Name == "org.freedesktop.systemd1.NoSuchUnit" || dbusErr.Name == "org.freedesktop.DBus.Error.UnknownObject") {
		return fmt.Errorf("%w: %w", errUnitNotFound, err)
	}
	return err
}
