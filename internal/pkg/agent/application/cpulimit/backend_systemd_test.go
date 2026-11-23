// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package cpulimit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

const (
	testUnit       = "elastic-agent.service"
	testCgroup     = "/system.slice/elastic-agent.service"
	testCPUMax     = "/sys/fs/cgroup" + testCgroup + "/cpu.max"
	testDropIn     = "/run/systemd/system.control/" + testUnit + ".d/50-CPUQuota.conf"
	testTransient  = "/run/systemd/transient/" + testUnit + ".d/50-CPUQuota.conf"
	testPersistent = "/etc/systemd/system.control/" + testUnit + ".d/50-CPUQuota.conf"
	testStatic     = "/etc/systemd/system/" + testUnit + ".d/override.conf"
)

// fakeDropInDirs returns the drop-in directories of the unit id, from the highest priority to the lowest.
func fakeDropInDirs(id string) []string {
	return []string{
		"/etc/systemd/system.control/" + id + ".d",
		"/run/systemd/system.control/" + id + ".d",
		"/run/systemd/transient/" + id + ".d",
		"/etc/systemd/system/" + id + ".d",
	}
}

// fakeConn models systemd. The unit file has no quota.
//
// The live quota is in cpu.max of the unit cgroup. A quota write creates the runtime override <runtime dir>/<unit id>.d/50-CPUQuota.conf, lists it and changes the quota
// and cpu.max at once, also when a persistent file with the same name exists.
//
// A reload reads the *.conf files of fakeDropInDirs again: the listed drop-ins, the quota and cpu.max follow the files.
// Of two files with the same name only the one in the directory with the higher priority counts. A symbolic link is
// followed and a dangling one is skipped. The files are read with quotaSetting, and the last CPUQuota= assignment in
// file-name order wins. The fake reads only values in percent with at most two decimals, the values that the tests
// write, and fails the test on any other value. Without a quota the fake deletes cpu.max. A real host can also keep
// cpu.max as "max" when the cpu controller stays on. The backend treats both as no kernel quota, so the fake uses the missing file and the
// Inspect tests cover "max".
type fakeConn struct {
	t         *testing.T
	b         *systemdBackend
	info      unitInfo
	unitErr   error
	setErr    error
	reloadErr error
	// transient is true for a transient unit, whose runtime override is in /run/systemd/transient.
	transient bool
	// onUnit runs at the start of each unit read.
	onUnit func()

	connects int
	closes   int
	reloads  int
	sets     []uint64
}

func (f *fakeConn) unit(_ context.Context, name string) (unitInfo, error) {
	if f.onUnit != nil {
		f.onUnit()
	}
	if name != testUnit {
		return unitInfo{}, errors.New("unknown unit")
	}
	info := f.info
	info.dropInPaths = slices.Clone(f.info.dropInPaths)
	return info, f.unitErr
}

func (f *fakeConn) setCPUQuota(_ context.Context, name string, usec uint64) error {
	if f.setErr != nil {
		return f.setErr
	}
	if name != testUnit {
		return errors.New("unknown unit")
	}
	f.sets = append(f.sets, usec)
	dir := "/run/systemd/system.control"
	if f.transient {
		dir = "/run/systemd/transient"
	}
	p := dir + "/" + f.info.id + ".d/50-CPUQuota.conf"
	writeFile(f.t, f.b, p, fmt.Sprintf("[Service]\nCPUQuota=%d.%02d%%\n", usec/10000, usec%10000/100))
	if !slices.Contains(f.info.dropInPaths, p) {
		f.info.dropInPaths = append(f.info.dropInPaths, p)
	}
	f.setLive(usec)
	return nil
}

func (f *fakeConn) reload(ctx context.Context) error {
	f.reloads++
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.reloadErr != nil {
		return f.reloadErr
	}
	byName := map[string]string{}
	for _, dir := range fakeDropInDirs(f.info.id) {
		entries, err := os.ReadDir(f.b.path(dir))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		require.NoError(f.t, err)
		for _, e := range entries {
			if _, ok := byName[e.Name()]; ok || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			fi, err := os.Stat(f.b.path(dir + "/" + e.Name()))
			if errors.Is(err, fs.ErrNotExist) || (err == nil && fi.IsDir()) {
				continue
			}
			require.NoError(f.t, err)
			byName[e.Name()] = dir + "/" + e.Name()
		}
	}
	f.info.dropInPaths = nil
	usec := uint64(quotaInfinity)
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		p := byName[name]
		f.info.dropInPaths = append(f.info.dropInPaths, p)
		data, err := os.ReadFile(f.b.path(p))
		require.NoError(f.t, err)
		if v, ok := quotaSetting(data); ok {
			usec = parseQuota(f.t, v)
		}
	}
	f.setLive(usec)
	return nil
}

// parseQuota converts a CPUQuota value such as "50%" to microseconds per second. An empty value means no quota.
func parseQuota(t *testing.T, v string) uint64 {
	if v == "" {
		return quotaInfinity
	}
	usec, ok := quotaUSec(v)
	require.Truef(t, ok, "the fake does not read the CPUQuota value %q", v)
	return usec
}

func (f *fakeConn) setLive(usec uint64) {
	f.info.cpuQuota = usec
	cpuMax := cgroupCPUMax(f.info.controlGroup)
	if usec == quotaInfinity {
		require.NoError(f.t, os.RemoveAll(f.b.path(cpuMax)))
		return
	}
	writeFile(f.t, f.b, cpuMax, fmt.Sprintf("%d 100000\n", usec/10))
}

func cgroupCPUMax(group string) string {
	return "/sys/fs/cgroup" + group + "/cpu.max"
}

func (f *fakeConn) close() {
	f.closes++
}

// newTestBackend returns a backend on a fake supported host with 14 CPUs and no CPU quota.
func newTestBackend(t *testing.T) (*systemdBackend, *fakeConn) {
	// The root has no symbolic link, so the backend sees only the links of the test.
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	conn := &fakeConn{
		t:    t,
		info: unitInfo{id: testUnit, loadState: "loaded", controlGroup: testCgroup, cpuQuota: quotaInfinity},
	}
	b := &systemdBackend{
		unit:        testUnit,
		root:        root,
		runtimeDirs: systemRuntimeDirs,
		euid:        func() int { return 0 },
		connect: func(context.Context) (systemdConn, error) {
			conn.connects++
			return conn, nil
		},
	}
	conn.b = b
	require.NoError(t, os.MkdirAll(b.path("/run/systemd/system"), 0o755))
	writeFile(t, b, "/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids\n")
	writeFile(t, b, "/proc/self/cgroup", "0::"+testCgroup+"\n")
	writeFile(t, b, "/sys/devices/system/cpu/online", "0-13\n")
	return b, conn
}

func writeFile(t *testing.T, b *systemdBackend, path, content string) {
	t.Helper()
	p := b.path(path)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

// symlink creates link that points to target, both below the root.
func symlink(t *testing.T, b *systemdBackend, target, link string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(b.path(link)), 0o755))
	require.NoError(t, os.Symlink(b.path(target), b.path(link)))
}

// fileExists reports whether path exists. It does not follow a symbolic link at the end of path.
func fileExists(t *testing.T, b *systemdBackend, path string) bool {
	t.Helper()
	_, err := os.Lstat(b.path(path))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	require.NoError(t, err)
	return true
}

// setStatic gives the unit a quota from a drop-in that is not the runtime override.
func setStatic(t *testing.T, b *systemdBackend, conn *fakeConn, percent int) {
	t.Helper()
	writeFile(t, b, testStatic, fmt.Sprintf("[Service]\nCPUQuota=%d%%\n", percent))
	require.NoError(t, conn.reload(t.Context()))
	conn.reloads = 0
}

func reasonOf(err error) string {
	var unsupported *UnsupportedError
	if errors.As(err, &unsupported) {
		return unsupported.Reason
	}
	return ""
}

func TestSystemdBackendSupport(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, b *systemdBackend, conn *fakeConn)
		reason string
		// hostLevel is true when the reason is found without a connection to systemd.
		hostLevel bool
		wantErr   bool
	}{
		{
			name:  "supported",
			setup: func(*testing.T, *systemdBackend, *fakeConn) {},
		},
		{
			name: "the agent is in a cgroup below the unit cgroup",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				writeFile(t, b, "/proc/self/cgroup", "0::"+testCgroup+"/sub\n")
			},
		},
		{
			name: "systemd is not running",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				require.NoError(t, os.Remove(b.path("/run/systemd/system")))
			},
			reason:    reasonNoSystemd,
			hostLevel: true,
		},
		{
			name: "the systemd marker is not a directory",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				require.NoError(t, os.Remove(b.path("/run/systemd/system")))
				writeFile(t, b, "/run/systemd/system", "")
			},
			reason:    reasonNoSystemd,
			hostLevel: true,
		},
		{
			name: "cgroup v1",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				require.NoError(t, os.Remove(b.path("/sys/fs/cgroup/cgroup.controllers")))
			},
			reason:    reasonCgroupV1,
			hostLevel: true,
		},
		{
			name: "no cpu controller",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				writeFile(t, b, "/sys/fs/cgroup/cgroup.controllers", "cpuset io memory pids\n")
			},
			reason:    reasonNoCPUController,
			hostLevel: true,
		},
		{
			name: "not root",
			setup: func(_ *testing.T, b *systemdBackend, _ *fakeConn) {
				b.euid = func() int { return 1000 }
			},
			reason:    reasonNotRoot,
			hostLevel: true,
		},
		{
			name: "the unit is not found",
			setup: func(_ *testing.T, _ *systemdBackend, conn *fakeConn) {
				conn.info = unitInfo{loadState: "not-found"}
			},
			reason: reasonNotService,
		},
		{
			name: "the unit is masked",
			setup: func(_ *testing.T, _ *systemdBackend, conn *fakeConn) {
				conn.info = unitInfo{loadState: "masked"}
			},
			wantErr: true,
		},
		{
			name: "the unit failed to load",
			setup: func(_ *testing.T, _ *systemdBackend, conn *fakeConn) {
				conn.info = unitInfo{loadState: "error"}
			},
			wantErr: true,
		},
		{
			name: "the unit has no cgroup",
			setup: func(_ *testing.T, _ *systemdBackend, conn *fakeConn) {
				conn.info.controlGroup = ""
			},
			reason: reasonNotService,
		},
		{
			name: "the agent is outside the unit cgroup",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				writeFile(t, b, "/proc/self/cgroup", "0::/user.slice/user-1000.slice/session-2.scope\n")
			},
			reason: reasonNotService,
		},
		{
			name: "the agent is in a cgroup with the same name prefix",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				writeFile(t, b, "/proc/self/cgroup", "0::"+testCgroup+"-other\n")
			},
			reason: reasonNotService,
		},
		{
			name: "the agent cgroup has no cgroup v2 entry",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				writeFile(t, b, "/proc/self/cgroup", "1:name=systemd:"+testCgroup+"\n")
			},
			reason: reasonNotService,
		},
		{
			name: "the systemd socket is missing",
			setup: func(_ *testing.T, b *systemdBackend, _ *fakeConn) {
				b.connect = func(context.Context) (systemdConn, error) {
					return nil, &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ENOENT)}
				}
			},
			wantErr: true,
		},
		{
			name: "the systemd socket refuses the connection",
			setup: func(_ *testing.T, b *systemdBackend, _ *fakeConn) {
				b.connect = func(context.Context) (systemdConn, error) {
					return nil, &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
				}
			},
			wantErr: true,
		},
		{
			name: "systemd does not know the unit",
			setup: func(_ *testing.T, _ *systemdBackend, conn *fakeConn) {
				conn.unitErr = fmt.Errorf("%w: no such unit", errUnitNotFound)
			},
			reason: reasonNotService,
		},
		{
			name: "the cgroup controllers cannot be read",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				require.NoError(t, os.Remove(b.path("/sys/fs/cgroup/cgroup.controllers")))
				writeFile(t, b, "/sys/fs/cgroup/cgroup.controllers/x", "")
			},
			wantErr: true,
		},
		{
			name: "the agent cgroup cannot be read",
			setup: func(t *testing.T, b *systemdBackend, _ *fakeConn) {
				require.NoError(t, os.Remove(b.path("/proc/self/cgroup")))
				writeFile(t, b, "/proc/self/cgroup/x", "")
			},
			wantErr: true,
		},
		{
			name: "the connection fails",
			setup: func(_ *testing.T, b *systemdBackend, _ *fakeConn) {
				b.connect = func(context.Context) (systemdConn, error) { return nil, errors.New("no socket") }
			},
			wantErr: true,
		},
		{
			name: "the unit properties cannot be read",
			setup: func(_ *testing.T, _ *systemdBackend, conn *fakeConn) {
				conn.unitErr = errors.New("read failed")
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, conn := newTestBackend(t)
			tc.setup(t, b, conn)

			_, inspectErr := b.Inspect(t.Context())
			applyErr := b.Apply(t.Context(), 2)
			removeErr := b.Remove(t.Context())
			switch {
			case tc.reason != "":
				require.Equal(t, tc.reason, reasonOf(inspectErr))
				require.Equal(t, tc.reason, reasonOf(applyErr))
				require.Equal(t, tc.reason, reasonOf(removeErr))
				require.Empty(t, conn.sets)
				require.Zero(t, conn.reloads)
				if tc.hostLevel {
					require.Zero(t, conn.connects)
				}
			case tc.wantErr:
				for _, err := range []error{inspectErr, applyErr, removeErr} {
					require.Error(t, err)
					require.Empty(t, reasonOf(err))
				}
				require.Empty(t, conn.sets)
				require.Zero(t, conn.reloads)
			default:
				require.NoError(t, inspectErr)
				require.NoError(t, applyErr)
				require.NoError(t, removeErr)
			}
			require.Equal(t, conn.connects, conn.closes)
		})
	}
}

func TestSystemdBackendLogicalCPUs(t *testing.T) {
	cases := []struct {
		content string
		exp     int
		wantErr bool
	}{
		{content: "0", exp: 1},
		{content: "0-13\n", exp: 14},
		{content: "0-3,5,8-11\n", exp: 9},
		{content: "2,4", exp: 2},
		{content: "", wantErr: true},
		{content: "\n", wantErr: true},
		{content: "abc", wantErr: true},
		{content: "3-1", wantErr: true},
		{content: "0-", wantErr: true},
		{content: "0,,1", wantErr: true},
		{content: "-1", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.content, func(t *testing.T) {
			b, _ := newTestBackend(t)
			writeFile(t, b, "/sys/devices/system/cpu/online", tc.content)
			n, err := b.LogicalCPUs(t.Context())
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.exp, n)
		})
	}

	t.Run("missing file", func(t *testing.T) {
		b, _ := newTestBackend(t)
		require.NoError(t, os.Remove(b.path("/sys/devices/system/cpu/online")))
		_, err := b.LogicalCPUs(t.Context())
		require.Error(t, err)
	})

	t.Run("an unsupported host reports its reason", func(t *testing.T) {
		b, _ := newTestBackend(t)
		require.NoError(t, os.Remove(b.path("/sys/fs/cgroup/cgroup.controllers")))
		require.NoError(t, os.Remove(b.path("/sys/devices/system/cpu/online")))
		_, err := b.LogicalCPUs(t.Context())
		require.Equal(t, reasonCgroupV1, reasonOf(err))
	})

	t.Run("a cancelled context", func(t *testing.T) {
		b, _ := newTestBackend(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := b.LogicalCPUs(ctx)
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestSystemdBackendInspect(t *testing.T) {
	ins := func(service, effective Quota) Inspection { return Inspection{Service: service, Effective: effective} }
	unknown := Quota{}
	cases := []struct {
		name string
		usec uint64
		// runtime is what the runtime override holds: "" nothing, "file" a regular file that sets usec, "listed" no
		// file but DropInPaths lists it.
		runtime string
		// path is the runtime override. It is testDropIn when empty.
		path string
		// cpuMax is the content of cpu.max. An empty value means the file does not exist.
		cpuMax  string
		exp     Inspection
		wantErr bool
	}{
		{name: "no quota", usec: quotaInfinity, exp: ins(quotaNone, quotaNone)},
		{name: "no quota and the kernel still has the old one", usec: quotaInfinity, cpuMax: "700000 100000\n", exp: ins(quotaNone, quotaSet(7))},
		{name: "an empty runtime override", usec: quotaInfinity, runtime: "file", cpuMax: "700000 100000\n", exp: ins(quotaNone, quotaSet(7))},

		{name: "static quota", usec: 500000, cpuMax: "50000 100000\n", exp: ins(quotaSet(0.5), quotaSet(0.5))},
		{name: "static quota that the kernel rounds down", usec: 1234567, cpuMax: "123456 100000\n", exp: ins(quotaSet(1.234567), quotaSet(1.23456))},
		{name: "static quota with another kernel quota", usec: 500000, cpuMax: "350000 100000\n", exp: ins(quotaNone, quotaSet(3.5))},
		{name: "static quota without a kernel quota", usec: 500000, cpuMax: "max 100000\n", exp: ins(quotaNone, quotaNone)},
		{name: "static quota without cpu.max", usec: 500000, exp: ins(quotaNone, quotaNone)},
		{name: "static quota with an invalid cpu.max", usec: 500000, cpuMax: "50000\n", wantErr: true},
		{name: "static quota one microsecond of the period away from the kernel quota", usec: 500000, cpuMax: "49999 100000\n", exp: ins(quotaSet(0.5), quotaSet(0.49999))},
		{name: "static quota just over the margin from the kernel quota", usec: 500000, cpuMax: "49998 100000\n", exp: ins(quotaNone, quotaSet(0.49998))},

		{name: "runtime quota", usec: 7000000, runtime: "file", cpuMax: "700000 100000\n", exp: ins(quotaSet(7), quotaSet(7))},
		{name: "runtime quota of a transient unit", usec: 7000000, runtime: "file", path: testTransient, cpuMax: "700000 100000\n", exp: ins(quotaSet(7), quotaSet(7))},
		{name: "runtime quota that the kernel rounds down", usec: 1234567, runtime: "file", cpuMax: "123456 100000\n", exp: ins(quotaSet(1.234567), quotaSet(1.23456))},
		{name: "runtime quota with another period", usec: 50000, runtime: "file", cpuMax: "10000 200000\n", exp: ins(quotaSet(0.05), quotaSet(0.05))},
		{name: "runtime quota without a kernel quota", usec: 7000000, runtime: "file", cpuMax: "max 100000\n", exp: ins(unknown, quotaNone)},
		{name: "runtime quota with another kernel quota", usec: 7000000, runtime: "file", cpuMax: "350000 100000\n", exp: ins(unknown, quotaSet(3.5))},
		{name: "runtime quota without cpu.max", usec: 7000000, runtime: "file", exp: ins(unknown, quotaNone)},
		{name: "runtime quota with an invalid cpu.max", usec: 7000000, runtime: "file", cpuMax: "700000\n", wantErr: true},
		{name: "runtime quota with a zero period", usec: 7000000, runtime: "file", cpuMax: "700000 0\n", wantErr: true},
		{name: "runtime quota with a cpu.max that is not a number", usec: 7000000, runtime: "file", cpuMax: "a b\n", wantErr: true},
		{name: "runtime quota one microsecond of the period away from the kernel quota", usec: 7000000, runtime: "file", cpuMax: "699999 100000\n", exp: ins(quotaSet(7), quotaSet(6.99999))},
		{name: "runtime quota one microsecond of a longer period away from the kernel quota", usec: 7000000, runtime: "file", cpuMax: "6999999 1000000\n", exp: ins(quotaSet(7), quotaSet(6.999999))},
		{name: "runtime quota just over the margin from the kernel quota", usec: 7000000, runtime: "file", cpuMax: "699998 100000\n", exp: ins(unknown, quotaSet(6.99998))},

		{name: "runtime override deleted but not reloaded", usec: 7000000, runtime: "listed", cpuMax: "700000 100000\n", exp: ins(unknown, quotaSet(7))},
		{name: "transient override deleted but not reloaded", usec: 7000000, runtime: "listed", path: testTransient, cpuMax: "700000 100000\n", exp: ins(unknown, quotaSet(7))},
		{name: "a deleted override that is not listed", usec: 7000000, cpuMax: "700000 100000\n", exp: ins(quotaSet(7), quotaSet(7))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, conn := newTestBackend(t)
			p := tc.path
			if p == "" {
				p = testDropIn
			}
			switch tc.runtime {
			case "file":
				// systemd truncates the value to hundredths of a percent.
				writeFile(t, b, p, fmt.Sprintf("[Service]\nCPUQuota=%d.%02d%%\n", tc.usec/10000, tc.usec%10000/100))
				conn.info.dropInPaths = []string{p}
			case "listed":
				conn.info.dropInPaths = []string{p}
			}
			conn.info.cpuQuota = tc.usec
			if tc.cpuMax != "" {
				writeFile(t, b, testCPUMax, tc.cpuMax)
			}

			got, err := b.Inspect(t.Context())
			if tc.wantErr {
				require.Error(t, err)
				require.Empty(t, reasonOf(err))
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.exp, got)
		})
	}
}

// setCgroup moves the unit and the agent process to the cgroup group.
func setCgroup(t *testing.T, b *systemdBackend, conn *fakeConn, group string) {
	t.Helper()
	conn.info.controlGroup = group
	writeFile(t, b, "/proc/self/cgroup", "0::"+group+"\n")
}

// TestSystemdBackendEffective checks that the effective quota is the lowest cpu.max of the unit cgroup and its parents
// up to the top, and that a level that cannot be read makes it unknown without a failure of Inspect.
func TestSystemdBackendEffective(t *testing.T) {
	const deep = "/a.slice/a-b.slice/elastic-agent.service"
	unknown := Quota{}
	cases := []struct {
		name string
		// group is the unit cgroup. It is testCgroup when empty.
		group string
		// usec is the static unit quota. The fake writes it to cpu.max of the unit cgroup.
		usec uint64
		// cpuMax is the content of cpu.max per cgroup. It is written after the unit quota, so it can replace that file.
		cpuMax map[string]string
		// unreadable is a cgroup whose cpu.max is a directory, so it cannot be read.
		unreadable string
		service    Quota
		effective  Quota
	}{
		{name: "no limit anywhere", usec: quotaInfinity, service: quotaNone, effective: quotaNone},
		{
			name:    "max at every level",
			usec:    quotaInfinity,
			cpuMax:  map[string]string{testCgroup: "max 100000\n", "/system.slice": "max 100000\n"},
			service: quotaNone, effective: quotaNone,
		},
		{name: "only the unit limit", usec: 2000000, service: quotaSet(2), effective: quotaSet(2)},
		{
			name:    "a lower parent limit",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "50000 100000\n"},
			service: quotaSet(2), effective: quotaSet(0.5),
		},
		{
			name:    "a higher parent limit",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "400000 100000\n"},
			service: quotaSet(2), effective: quotaSet(2),
		},
		{
			name:    "a parent limit equal to the unit limit",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "200000 100000\n"},
			service: quotaSet(2), effective: quotaSet(2),
		},
		{
			name:    "only a parent limit",
			usec:    quotaInfinity,
			cpuMax:  map[string]string{"/system.slice": "150000 100000\n"},
			service: quotaNone, effective: quotaSet(1.5),
		},
		{
			name:    "several parents with the lowest limit in the middle",
			group:   deep,
			usec:    2000000,
			cpuMax:  map[string]string{"/a.slice": "300000 100000\n", "/a.slice/a-b.slice": "100000 100000\n"},
			service: quotaSet(2), effective: quotaSet(1),
		},
		{
			name:    "several parents with the lowest limit at the top",
			group:   deep,
			usec:    2000000,
			cpuMax:  map[string]string{"/a.slice": "80000 100000\n", "/a.slice/a-b.slice": "100000 100000\n"},
			service: quotaSet(2), effective: quotaSet(0.8),
		},
		{
			name:    "a level without cpu.max",
			group:   deep,
			usec:    2000000,
			cpuMax:  map[string]string{"/a.slice": "60000 100000\n"},
			service: quotaSet(2), effective: quotaSet(0.6),
		},
		{
			name:    "max at some levels",
			group:   deep,
			usec:    quotaInfinity,
			cpuMax:  map[string]string{deep: "max 100000\n", "/a.slice/a-b.slice": "max 100000\n", "/a.slice": "60000 100000\n"},
			service: quotaNone, effective: quotaSet(0.6),
		},
		{
			name:    "a parent with a shorter period",
			usec:    500000,
			cpuMax:  map[string]string{"/system.slice": "20000 50000\n"},
			service: quotaSet(0.5), effective: quotaSet(0.4),
		},
		{
			name:    "a parent with a longer period",
			usec:    500000,
			cpuMax:  map[string]string{"/system.slice": "300000 1000000\n"},
			service: quotaSet(0.5), effective: quotaSet(0.3),
		},
		{
			name:    "a parent with invalid content",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "abc\n"},
			service: quotaSet(2), effective: unknown,
		},
		{
			name:    "a parent with a zero period",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "100000 0\n"},
			service: quotaSet(2), effective: unknown,
		},
		{
			name:    "a parent with a negative quota",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "-1 100000\n"},
			service: quotaSet(2), effective: unknown,
		},
		{
			name:    "a parent with max",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "max 100000\n"},
			service: quotaSet(2), effective: quotaSet(2),
		},
		{
			name:    "a parent with max and a zero period",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "max 0\n"},
			service: quotaSet(2), effective: unknown,
		},
		{
			name:    "a parent with max and a period that is not a number",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "max garbage\n"},
			service: quotaSet(2), effective: unknown,
		},
		{
			name:    "a lower limit at the top level",
			usec:    2000000,
			cpuMax:  map[string]string{"/system.slice": "150000 100000\n", "/": "30000 100000\n"},
			service: quotaSet(2), effective: quotaSet(0.3),
		},
		{name: "the top level without cpu.max", usec: 2000000, service: quotaSet(2), effective: quotaSet(2)},
		{name: "a top level that cannot be read", usec: 2000000, unreadable: "/", service: quotaSet(2), effective: unknown},
		{name: "a parent that cannot be read", usec: 2000000, unreadable: "/system.slice", service: quotaSet(2), effective: unknown},
		{
			name:    "invalid unit content without a unit quota",
			usec:    quotaInfinity,
			cpuMax:  map[string]string{testCgroup: "abc\n"},
			service: quotaNone, effective: unknown,
		},
		{name: "a unit cpu.max that cannot be read without a unit quota", usec: quotaInfinity, unreadable: testCgroup, service: quotaNone, effective: unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, conn := newTestBackend(t)
			if tc.group != "" {
				setCgroup(t, b, conn, tc.group)
			}
			conn.setLive(tc.usec)
			for group, content := range tc.cpuMax {
				writeFile(t, b, cgroupCPUMax(group), content)
			}
			if tc.unreadable != "" {
				require.NoError(t, os.MkdirAll(b.path(cgroupCPUMax(tc.unreadable)), 0o755))
			}

			ins, err := b.Inspect(t.Context())
			require.NoError(t, err)
			require.Equal(t, Inspection{Service: tc.service, Effective: tc.effective}, ins)
		})
	}

	t.Run("cgroup depth", func(t *testing.T) {
		for _, tc := range []struct {
			levels    int
			effective Quota
		}{
			{levels: maxCgroupDepth, effective: quotaSet(0.4)},
			{levels: maxCgroupDepth + 1, effective: unknown},
		} {
			t.Run(fmt.Sprint(tc.levels), func(t *testing.T) {
				b, conn := newTestBackend(t)
				group := ""
				for i := range tc.levels {
					group += fmt.Sprintf("/l%d", i)
				}
				setCgroup(t, b, conn, group)
				writeFile(t, b, cgroupCPUMax("/l0"), "50000 100000\n")
				writeFile(t, b, cgroupCPUMax("/"), "40000 100000\n")

				ins, err := b.Inspect(t.Context())
				require.NoError(t, err)
				require.Equal(t, Inspection{Service: quotaNone, Effective: tc.effective}, ins)
			})
		}
	})
}

// TestSystemdBackendOverridePath checks that Remove deletes only the regular file
// <runtime dir>/<unit id>.d/50-CPUQuota.conf. The live quota is the one of the files, so Inspect reports it either way.
func TestSystemdBackendOverridePath(t *testing.T) {
	const quota = "[Service]\nCPUQuota=700%\n"
	listed := func(conn *fakeConn, p string) { conn.info.dropInPaths = append(conn.info.dropInPaths, p) }
	cases := []struct {
		name  string
		setup func(t *testing.T, b *systemdBackend, conn *fakeConn)
		// deleted is the override that Remove deletes. It is empty when Remove must change nothing.
		deleted string
		// kept are the paths that must stay.
		kept []string
	}{
		{
			name: "runtime override",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, testDropIn, quota)
				listed(conn, testDropIn)
			},
			deleted: testDropIn,
		},
		{
			name: "runtime override of a transient unit",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, testTransient, quota)
				listed(conn, testTransient)
			},
			deleted: testTransient,
		},
		{
			name: "the unit is an alias: the override of the unit id",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				conn.info.id = "real.service"
				writeFile(t, b, "/run/systemd/system.control/real.service.d/50-CPUQuota.conf", quota)
			},
			deleted: "/run/systemd/system.control/real.service.d/50-CPUQuota.conf",
		},
		{
			name: "the unit is an alias: a directory of the alias name",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				conn.info.id = "real.service"
				writeFile(t, b, testDropIn, quota)
				listed(conn, testDropIn)
			},
			kept: []string{testDropIn},
		},
		{
			name: "prefix drop-in",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, "/run/systemd/system.control/elastic-.service.d/50-CPUQuota.conf", quota)
				listed(conn, "/run/systemd/system.control/elastic-.service.d/50-CPUQuota.conf")
			},
			kept: []string{"/run/systemd/system.control/elastic-.service.d/50-CPUQuota.conf"},
		},
		{
			name: "type drop-in",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, "/run/systemd/system.control/service.d/50-CPUQuota.conf", quota)
				listed(conn, "/run/systemd/system.control/service.d/50-CPUQuota.conf")
			},
			kept: []string{"/run/systemd/system.control/service.d/50-CPUQuota.conf"},
		},
		{
			name: "persistent override of set-property",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, testPersistent, quota)
				listed(conn, testPersistent)
			},
			kept: []string{testPersistent},
		},
		{
			name: "drop-in with the same name in /etc/systemd/system",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				p := "/etc/systemd/system/" + testUnit + ".d/50-CPUQuota.conf"
				writeFile(t, b, p, quota)
				listed(conn, p)
			},
			kept: []string{"/etc/systemd/system/" + testUnit + ".d/50-CPUQuota.conf"},
		},
		{
			name: "another runtime property",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				p := filepath.Dir(testDropIn) + "/50-MemoryMax.conf"
				writeFile(t, b, p, quota)
				listed(conn, p)
			},
			kept: []string{filepath.Dir(testDropIn) + "/50-MemoryMax.conf"},
		},
		{
			name: "the override is a symbolic link",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, "/var/lib/other.conf", quota)
				symlink(t, b, "/var/lib/other.conf", testDropIn)
				listed(conn, testDropIn)
			},
			kept: []string{testDropIn, "/var/lib/other.conf"},
		},
		{
			name: "the override is a dangling symbolic link",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				symlink(t, b, "/var/lib/missing.conf", testDropIn)
				listed(conn, testDropIn)
			},
			kept: []string{testDropIn},
		},
		{
			name: "the override is a directory",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, testDropIn+"/x", "")
				listed(conn, testDropIn)
			},
			kept: []string{testDropIn + "/x"},
		},
		{
			name: "the unit directory is a symbolic link",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, "/var/lib/other/50-CPUQuota.conf", quota)
				symlink(t, b, "/var/lib/other", filepath.Dir(testDropIn))
				listed(conn, testDropIn)
			},
			kept: []string{filepath.Dir(testDropIn), "/var/lib/other/50-CPUQuota.conf"},
		},
		{
			name: "the runtime directory is a symbolic link",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, "/var/lib/control/"+testUnit+".d/50-CPUQuota.conf", quota)
				symlink(t, b, "/var/lib/control", "/run/systemd/system.control")
				listed(conn, testDropIn)
			},
			kept: []string{"/run/systemd/system.control", "/var/lib/control/" + testUnit + ".d/50-CPUQuota.conf"},
		},
		{
			name: "files in both runtime directories: the first one is used",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, testDropIn, quota)
				writeFile(t, b, testTransient, quota)
				listed(conn, testDropIn)
			},
			deleted: testDropIn,
			kept:    []string{testTransient},
		},
		{
			name: "a symbolic link in the first runtime directory hides the file in the second",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, "/var/lib/other.conf", quota)
				symlink(t, b, "/var/lib/other.conf", testDropIn)
				writeFile(t, b, testTransient, quota)
				listed(conn, testDropIn)
			},
			kept: []string{testDropIn, "/var/lib/other.conf", testTransient},
		},
		{
			name: "a symbolic link as the unit directory in the first runtime directory hides the file in the second",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, "/var/lib/other/50-CPUQuota.conf", quota)
				symlink(t, b, "/var/lib/other", filepath.Dir(testDropIn))
				writeFile(t, b, testTransient, quota)
				listed(conn, testDropIn)
			},
			kept: []string{"/var/lib/other/50-CPUQuota.conf", testTransient},
		},
		{
			name: "a directory in the first runtime directory hides the file in the second",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, testDropIn+"/x", "")
				writeFile(t, b, testTransient, quota)
				listed(conn, testTransient)
			},
			kept: []string{testDropIn + "/x", testTransient},
		},
		{
			name: "a FIFO in the first runtime directory hides the file in the second",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				require.NoError(t, os.MkdirAll(b.path(filepath.Dir(testDropIn)), 0o755))
				require.NoError(t, syscall.Mkfifo(b.path(testDropIn), 0o644))
				writeFile(t, b, testTransient, quota)
				listed(conn, testDropIn)
			},
			kept: []string{testDropIn, testTransient},
		},
		{
			name: "no file in the first runtime directory: the second one is used",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				require.NoError(t, os.MkdirAll(b.path(filepath.Dir(testDropIn)), 0o755))
				writeFile(t, b, testTransient, quota)
				listed(conn, testTransient)
			},
			deleted: testTransient,
		},
		{
			name: "files in both runtime directories: the first one does not set the quota",
			setup: func(t *testing.T, b *systemdBackend, conn *fakeConn) {
				writeFile(t, b, testDropIn, "[Service]\n")
				writeFile(t, b, testTransient, quota)
				listed(conn, testDropIn)
			},
			kept: []string{testDropIn, testTransient},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, conn := newTestBackend(t)
			tc.setup(t, b, conn)
			conn.setLive(7000000)

			ins, err := b.Inspect(t.Context())
			require.NoError(t, err)
			require.Equal(t, Inspection{Service: quotaSet(7), Effective: quotaSet(7)}, ins)

			require.NoError(t, b.Remove(t.Context()))
			if tc.deleted != "" {
				require.Equal(t, 1, conn.reloads)
				require.False(t, fileExists(t, b, tc.deleted))
			} else {
				require.Zero(t, conn.reloads)
			}
			for _, p := range tc.kept {
				require.True(t, fileExists(t, b, p), p)
			}
		})
	}
}

func TestSystemdBackendApply(t *testing.T) {
	cases := []struct {
		name string
		cpus float64
		usec uint64
	}{
		{name: "whole CPUs", cpus: 7, usec: 7000000},
		{name: "rounded up", cpus: 2.636, usec: 2640000},
		{name: "rounded down", cpus: 2.634, usec: 2630000},
		{name: "the smallest floor", cpus: 0.05, usec: 50000},
		{name: "4096 CPUs", cpus: 4096, usec: 4096000000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, conn := newTestBackend(t)
			require.NoError(t, b.Apply(t.Context(), tc.cpus))
			require.Equal(t, []uint64{tc.usec}, conn.sets)
			ins, err := b.Inspect(t.Context())
			require.NoError(t, err)
			require.Equal(t, QuotaSet, ins.Service.Kind)
			require.InDelta(t, float64(tc.usec)/1e6, ins.Service.CPUs, 1e-9)

			require.NoError(t, b.Remove(t.Context()))
			require.False(t, fileExists(t, b, testDropIn))
			require.Equal(t, 1, conn.reloads)
		})
	}

	for _, cpus := range []float64{math.NaN(), 0, -1, 0.004, math.Inf(1), 1e300} {
		t.Run(fmt.Sprintf("invalid value %v", cpus), func(t *testing.T) {
			b, conn := newTestBackend(t)
			require.Error(t, b.Apply(t.Context(), cpus))
			require.Empty(t, reasonOf(b.Apply(t.Context(), cpus)))
			require.Zero(t, conn.connects)
		})
	}

	t.Run("a failed write is returned", func(t *testing.T) {
		b, conn := newTestBackend(t)
		writeErr := errors.New("write failed")
		conn.setErr = writeErr
		require.ErrorIs(t, b.Apply(t.Context(), 7), writeErr)
		require.Equal(t, conn.connects, conn.closes)
	})

	t.Run("repeated calls", func(t *testing.T) {
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		require.NoError(t, b.Apply(t.Context(), 7))
		require.Equal(t, []uint64{7000000, 7000000}, conn.sets)
		require.Zero(t, conn.reloads)
		require.Equal(t, conn.connects, conn.closes)
	})

	t.Run("replaces a static quota", func(t *testing.T) {
		b, conn := newTestBackend(t)
		setStatic(t, b, conn, 50)
		require.NoError(t, b.Apply(t.Context(), 7))
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaSet(7), Effective: quotaSet(7)}, ins)
	})
}

func TestSystemdBackendRemove(t *testing.T) {
	t.Run("a static quota is kept", func(t *testing.T) {
		b, conn := newTestBackend(t)
		setStatic(t, b, conn, 50)
		require.NoError(t, b.Remove(t.Context()))
		require.Empty(t, conn.sets)
		require.Zero(t, conn.reloads)
		require.True(t, fileExists(t, b, testStatic))
		require.Equal(t, conn.connects, conn.closes)
	})

	t.Run("deletes the runtime override and reloads", func(t *testing.T) {
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		writeFile(t, b, filepath.Dir(testDropIn)+"/50-MemoryMax.conf", "[Service]\nMemoryMax=1G\n")

		require.NoError(t, b.Remove(t.Context()))
		require.Equal(t, 1, conn.reloads)
		require.False(t, fileExists(t, b, testDropIn))
		require.True(t, fileExists(t, b, filepath.Dir(testDropIn)+"/50-MemoryMax.conf"))
		require.Equal(t, []uint64{7000000}, conn.sets)
		require.Equal(t, conn.connects, conn.closes)

		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaNone, Effective: quotaNone}, ins)

		require.NoError(t, b.Remove(t.Context()))
		require.Equal(t, 1, conn.reloads)
	})

	t.Run("the static quota applies again", func(t *testing.T) {
		b, conn := newTestBackend(t)
		setStatic(t, b, conn, 50)
		require.NoError(t, b.Apply(t.Context(), 7))

		require.NoError(t, b.Remove(t.Context()))
		require.True(t, fileExists(t, b, testStatic))
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaSet(0.5), Effective: quotaSet(0.5)}, ins)
	})

	t.Run("a runtime override of an administrator is removed", func(t *testing.T) {
		b, conn := newTestBackend(t)
		writeFile(t, b, testDropIn, "[Service]\nCPUQuota=200.00%\n")
		require.NoError(t, conn.reload(t.Context()))
		conn.reloads = 0
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaSet(2), Effective: quotaSet(2)}, ins)

		require.NoError(t, b.Remove(t.Context()))
		require.False(t, fileExists(t, b, testDropIn))
		require.Equal(t, 1, conn.reloads)
		ins, err = b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaNone, Effective: quotaNone}, ins)
	})

	t.Run("a persistent file with the same name", func(t *testing.T) {
		b, conn := newTestBackend(t)
		writeFile(t, b, testPersistent, "[Service]\nCPUQuota=30%\n")
		require.NoError(t, b.Apply(t.Context(), 7))
		require.NoError(t, b.Remove(t.Context()))
		require.False(t, fileExists(t, b, testDropIn))
		require.True(t, fileExists(t, b, testPersistent))
		require.Equal(t, 1, conn.reloads)
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaSet(0.3), Effective: quotaSet(0.3)}, ins)
	})

	t.Run("a persistent file with the same name wins after a daemon-reload of the host", func(t *testing.T) {
		b, conn := newTestBackend(t)
		writeFile(t, b, testPersistent, "[Service]\nCPUQuota=30%\n")
		require.NoError(t, b.Apply(t.Context(), 7))
		require.NoError(t, conn.reload(t.Context()))
		conn.reloads = 0

		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaSet(0.3), Effective: quotaSet(0.3)}, ins)
		require.NoError(t, b.Remove(t.Context()))
		require.True(t, fileExists(t, b, testDropIn))
		require.Zero(t, conn.reloads)
	})

	t.Run("a listed override without a file only reloads", func(t *testing.T) {
		b, conn := newTestBackend(t)
		conn.info.dropInPaths = []string{testDropIn}
		conn.setLive(7000000)
		require.NoError(t, b.Remove(t.Context()))
		require.Equal(t, 1, conn.reloads)
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaNone, Effective: quotaNone}, ins)
	})

	t.Run("a failed reload is returned and a retry finishes the removal", func(t *testing.T) {
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		reloadErr := errors.New("reload failed")
		conn.reloadErr = reloadErr

		require.ErrorIs(t, b.Remove(t.Context()), reloadErr)
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: Quota{}, Effective: quotaSet(7)}, ins)

		conn.reloadErr = nil
		require.NoError(t, b.Remove(t.Context()))
		ins, err = b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaNone, Effective: quotaNone}, ins)
	})

	t.Run("a cancel after the unit read does not delete", func(t *testing.T) {
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		ctx, cancel := context.WithCancel(t.Context())
		conn.onUnit = cancel

		require.ErrorIs(t, b.Remove(ctx), context.Canceled)
		require.True(t, fileExists(t, b, testDropIn))
		require.Zero(t, conn.reloads)
		conn.onUnit = nil
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, quotaSet(7), ins.Service)
	})

	t.Run("a cancel at the reload is finished by the next removal", func(t *testing.T) {
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		ctx, cancel := context.WithCancel(t.Context())
		b.connect = func(context.Context) (systemdConn, error) {
			conn.connects++
			return cancelOnReload{fakeConn: conn, cancel: cancel}, nil
		}

		require.ErrorIs(t, b.Remove(ctx), context.Canceled)
		require.False(t, fileExists(t, b, testDropIn))

		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: Quota{}, Effective: quotaSet(7)}, ins)

		require.NoError(t, b.Remove(t.Context()))
		ins, err = b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaNone, Effective: quotaNone}, ins)
	})

	t.Run("an empty runtime override over a static quota is kept", func(t *testing.T) {
		b, conn := newTestBackend(t)
		writeFile(t, b, "/etc/systemd/system/"+testUnit+".d/10-quota.conf", "[Service]\nCPUQuota=50%\n")
		writeFile(t, b, testDropIn, "[Service]\nCPUQuota=\n")
		require.NoError(t, conn.reload(t.Context()))
		conn.reloads = 0
		require.Equal(t, uint64(quotaInfinity), conn.info.cpuQuota)

		require.NoError(t, b.Remove(t.Context()))
		require.Zero(t, conn.reloads)
		require.True(t, fileExists(t, b, testDropIn))
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaNone, Effective: quotaNone}, ins)
	})

	t.Run("a failed delete does not reload", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can delete in a read-only directory")
		}
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		dir := b.path(filepath.Dir(testDropIn))
		require.NoError(t, os.Chmod(dir, 0o555))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		require.Error(t, b.Remove(t.Context()))
		require.Zero(t, conn.reloads)
		require.True(t, fileExists(t, b, testDropIn))
	})

	t.Run("the delete does not follow a symbolic link that appears after the check", func(t *testing.T) {
		b, _ := newTestBackend(t)
		writeFile(t, b, "/var/lib/other/50-CPUQuota.conf", "")
		symlink(t, b, "/var/lib/other", filepath.Dir(testDropIn))
		require.Error(t, b.removeNoFollow(testDropIn))
		require.True(t, fileExists(t, b, "/var/lib/other/50-CPUQuota.conf"))
	})

	t.Run("the delete does not remove a directory that appears after the check", func(t *testing.T) {
		b, _ := newTestBackend(t)
		writeFile(t, b, testDropIn+"/x", "")
		err := b.removeNoFollow(testDropIn)
		require.ErrorIs(t, err, syscall.EISDIR)
		require.ErrorContains(t, err, testDropIn)
		require.True(t, fileExists(t, b, testDropIn+"/x"))
	})

	t.Run("an override that cannot be read is an error", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read a directory without permissions")
		}
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		dir := b.path(filepath.Dir(testDropIn))
		require.NoError(t, os.Chmod(dir, 0))
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		_, err := b.Inspect(t.Context())
		require.ErrorIs(t, err, syscall.EACCES)
		require.ErrorContains(t, err, testDropIn)
		err = b.Remove(t.Context())
		require.ErrorIs(t, err, syscall.EACCES)
		require.Empty(t, reasonOf(err))
		require.Zero(t, conn.reloads)
		require.NoError(t, os.Chmod(dir, 0o755))
		require.True(t, fileExists(t, b, testDropIn))
	})

	t.Run("an unsupported host", func(t *testing.T) {
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		b.euid = func() int { return 1000 }
		require.Equal(t, reasonNotRoot, reasonOf(b.Remove(t.Context())))
		require.True(t, fileExists(t, b, testDropIn))
		require.Zero(t, conn.reloads)
	})
}

// TestSystemdBackendHeldQuota checks that Remove deletes the runtime override only when it holds the live quota.
func TestSystemdBackendHeldQuota(t *testing.T) {
	const static = "[Service]\nCPUQuota=50%\n"
	cases := []struct {
		name     string
		override string
		// static is the content of a drop-in that sorts after the override. It is not written when empty.
		static  string
		service Quota
		// held is true when the override holds the live quota, so Remove deletes it and reloads.
		held bool
	}{
		{name: "the override sets the quota", override: "[Service]\nCPUQuota=200%\n", service: quotaSet(2), held: true},
		{name: "an empty override and a static quota", override: "", static: static, service: quotaSet(0.5)},
		{name: "an override that clears the quota and a static quota", override: "[Service]\nCPUQuota=\n", static: static, service: quotaSet(0.5)},
		{name: "an override with other settings and a static quota", override: "[Service]\nMemoryMax=1G\n", static: static, service: quotaSet(0.5)},
		{name: "an override with another value than a later static quota", override: "[Service]\nCPUQuota=200%\n", static: static, service: quotaSet(0.5)},
		{name: "an override that is too large to read", override: "[Service]\nCPUQuota=200%\n" + strings.Repeat("# comment\n", 7000), service: quotaSet(2)},
		{name: "an override with hundredths of a percent", override: "[Service]\nCPUQuota=50.50%\n", service: quotaSet(0.505), held: true},
		{name: "an override close to a later static quota", override: "[Service]\nCPUQuota=699.5%\n", static: "[Service]\nCPUQuota=700%\n", service: quotaSet(7)},
		{name: "spaces around the equal sign", override: "[Service]\nCPUQuota = 200%\n", service: quotaSet(2), held: true},
		{name: "a space before the value", override: "[Service]\nCPUQuota= 200%\n", service: quotaSet(2), held: true},
		{name: "a later static quota with spaces around the equal sign", override: "[Service]\nCPUQuota=200%\n", static: "[Service]\nCPUQuota = 50%\n", service: quotaSet(0.5)},
		{name: "a quota text that continues another assignment and the same static quota", override: "[Service]\nMemoryMax=1G\nEnvironment=\\\nCPUQuota=700%\n", static: "[Service]\nCPUQuota=700%\n", service: quotaSet(7)},
		{name: "a quota after a continued assignment", override: "[Service]\nEnvironment=A=1 \\\n B=2\nCPUQuota=700%\n", service: quotaSet(7), held: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, conn := newTestBackend(t)
			writeFile(t, b, testDropIn, tc.override)
			if tc.static != "" {
				writeFile(t, b, testStatic, tc.static)
			}
			require.NoError(t, conn.reload(t.Context()))
			conn.reloads = 0

			ins, err := b.Inspect(t.Context())
			require.NoError(t, err)
			require.Equal(t, Inspection{Service: tc.service, Effective: tc.service}, ins)

			require.NoError(t, b.Remove(t.Context()))
			require.Equal(t, !tc.held, fileExists(t, b, testDropIn))
			if tc.held {
				require.Equal(t, 1, conn.reloads)
			} else {
				require.Zero(t, conn.reloads)
			}
		})
	}
}

func TestSetsQuota(t *testing.T) {
	cases := []struct {
		name string
		data string
		usec uint64
		exp  bool
	}{
		{name: "same value", data: "[Service]\nCPUQuota=50%\n", usec: 500000, exp: true},
		{name: "a value with decimals", data: "[Service]\nCPUQuota=12.50%\n", usec: 125000, exp: true},
		{name: "systemd truncates to hundredths of a percent", data: "[Service]\nCPUQuota=123.45%\n", usec: 1234567, exp: true},
		{name: "a value with one decimal", data: "[Service]\nCPUQuota=50.5%\n", usec: 505000, exp: true},
		{name: "two decimals of zero", data: "[Service]\nCPUQuota=700.00%\n", usec: 7000000, exp: true},
		{name: "a live quota 99 microseconds above the value", data: "[Service]\nCPUQuota=700.00%\n", usec: 7000099, exp: true},
		{name: "a live quota 100 microseconds above the value", data: "[Service]\nCPUQuota=700.00%\n", usec: 7000100},
		{name: "one hundredth of a percent below the live quota", data: "[Service]\nCPUQuota=699.99%\n", usec: 7000000},
		{name: "half a percent below the live quota", data: "[Service]\nCPUQuota=699.5%\n", usec: 7000000},
		{name: "above the live quota", data: "[Service]\nCPUQuota=700.01%\n", usec: 7000000},
		{name: "more than two decimals", data: "[Service]\nCPUQuota=700.009%\n", usec: 7000000},
		{name: "a dot without decimals", data: "[Service]\nCPUQuota=700.%\n", usec: 7000000},
		{name: "no digits before the dot", data: "[Service]\nCPUQuota=.5%\n", usec: 5000},
		{name: "a value too large for microseconds", data: "[Service]\nCPUQuota=1844674407370956%\n", usec: 8384},
		{name: "a value that continues another assignment", data: "[Service]\nMemoryMax=1G\nEnvironment=\\\nCPUQuota=50%\n", usec: 500000},
		{name: "a comment inside a continued assignment", data: "[Service]\nEnvironment=\\\n# comment\nCPUQuota=50%\n", usec: 500000},
		{name: "a value after a continued assignment", data: "[Service]\nEnvironment=A=1 \\\n B=2\nCPUQuota=50%\n", usec: 500000, exp: true},
		{name: "a continued value", data: "[Service]\nCPUQuota=\\\n50%\n", usec: 500000, exp: true},
		{name: "a backslash at the end of the file", data: "[Service]\nCPUQuota=50%\\", usec: 500000, exp: true},
		{name: "whole percent of an old systemd for a quota with decimals", data: "[Service]\nCPUQuota=12%\n", usec: 125000},
		{name: "spaces around the equal sign", data: "[Service]\nCPUQuota = 50%\n", usec: 500000, exp: true},
		{name: "a space before the value", data: "[Service]\nCPUQuota= 50%\n", usec: 500000, exp: true},
		{name: "the header that systemd writes", data: "# This is a drop-in unit file extension, created via \"systemctl set-property\"\n# or an equivalent operation. Do not edit.\n[Service]\nCPUQuota=50%\n", usec: 500000, exp: true},
		{name: "one percent away", data: "[Service]\nCPUQuota=51%\n", usec: 500000},
		{name: "another value", data: "[Service]\nCPUQuota=200%\n", usec: 500000},
		{name: "the last line wins", data: "[Service]\nCPUQuota=50%\nCPUQuota=\n", usec: 500000},
		{name: "another section", data: "[Unit]\nCPUQuota=50%\n", usec: 500000},
		{name: "a comment", data: "[Service]\n#CPUQuota=50%\n", usec: 500000},
		{name: "no percent sign", data: "[Service]\nCPUQuota=50\n", usec: 500000},
		{name: "not a number", data: "[Service]\nCPUQuota=NaN%\n", usec: 500000},
		{name: "empty", data: "", usec: 500000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.exp, setsQuota([]byte(tc.data), tc.usec))
		})
	}
}

// cancelOnReload cancels the context of the call when the reload starts, like a shutdown at that moment.
type cancelOnReload struct {
	*fakeConn
	cancel context.CancelFunc
}

func (c cancelOnReload) reload(ctx context.Context) error {
	c.cancel()
	return c.fakeConn.reload(ctx)
}

// TestSystemdBackendPendingRemovalAfterRestart covers a removal at exit whose reload failed before the agent restarted:
// systemd still has the quota in memory, but its override is gone.
func TestSystemdBackendPendingRemovalAfterRestart(t *testing.T) {
	restart := func(t *testing.T) (*Controller, *systemdBackend, *fakeConn) {
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		conn.reloadErr = errors.New("reload failed")
		require.Error(t, b.Remove(t.Context()))
		require.False(t, fileExists(t, b, testDropIn))
		conn.reloadErr = nil
		conn.sets, conn.reloads, conn.connects, conn.closes = nil, 0, 0, 0

		restarted := &systemdBackend{unit: b.unit, root: b.root, runtimeDirs: b.runtimeDirs, euid: b.euid, connect: b.connect}
		log, _ := loggertest.New(t.Name())
		return NewController(log, restarted), restarted, conn
	}

	t.Run("the cap is on with the same target", func(t *testing.T) {
		c, b, conn := restart(t)
		c.Set(cpuLimit(t, 50))
		require.Equal(t, recheckInterval, c.reconcile(t.Context()))
		require.Equal(t, []uint64{7000000}, conn.sets)
		require.True(t, fileExists(t, b, testDropIn))
		require.Equal(t, StateApplied, c.Snapshot().State)
		require.Equal(t, quotaSet(7), c.Snapshot().ActiveQuota)

		c.removeOwnQuota()
		require.False(t, fileExists(t, b, testDropIn))
		require.Equal(t, 1, conn.reloads)
		ins, err := b.Inspect(t.Context())
		require.NoError(t, err)
		require.Equal(t, Inspection{Service: quotaNone, Effective: quotaNone}, ins)
	})

	t.Run("no cap is set", func(t *testing.T) {
		c, _, conn := restart(t)
		c.Set(capOff)
		require.Zero(t, c.reconcile(t.Context()))
		c.removeOwnQuota()
		require.Zero(t, conn.connects)
		require.Zero(t, conn.reloads)
		require.Empty(t, conn.sets)
		require.Equal(t, uint64(7000000), conn.info.cpuQuota)
		require.Equal(t, StateDisabled, c.Snapshot().State)
	})
}

// TestSystemdBackendCapOff covers a cap that goes off while the agent runs.
func TestSystemdBackendCapOff(t *testing.T) {
	applied := func(t *testing.T) (*Controller, *systemdBackend, *fakeConn) {
		b, conn := newTestBackend(t)
		log, _ := loggertest.New(t.Name())
		c := NewController(log, b)
		c.Set(cpuLimit(t, 50))
		require.Equal(t, recheckInterval, c.reconcile(t.Context()))
		require.Equal(t, StateApplied, c.Snapshot().State)
		conn.sets, conn.reloads = nil, 0
		return c, b, conn
	}

	t.Run("the agent quota is removed", func(t *testing.T) {
		c, b, conn := applied(t)
		c.Set(capOff)
		require.Zero(t, c.reconcile(t.Context()))
		require.False(t, fileExists(t, b, testDropIn))
		require.Equal(t, 1, conn.reloads)
		require.Equal(t, uint64(quotaInfinity), conn.info.cpuQuota)
		require.Equal(t, StateDisabled, c.Snapshot().State)
	})

	t.Run("a quota changed by an administrator is kept", func(t *testing.T) {
		c, b, conn := applied(t)
		// Like systemctl set-property --runtime CPUQuota=300%.
		require.NoError(t, conn.setCPUQuota(t.Context(), testUnit, 3000000))
		conn.sets = nil
		c.Set(capOff)
		require.Zero(t, c.reconcile(t.Context()))
		require.True(t, fileExists(t, b, testDropIn))
		require.Zero(t, conn.reloads)
		require.Equal(t, uint64(3000000), conn.info.cpuQuota)
		require.Equal(t, StateDisabled, c.Snapshot().State)
	})

	t.Run("a quota left by an earlier run is kept", func(t *testing.T) {
		b, conn := newTestBackend(t)
		require.NoError(t, b.Apply(t.Context(), 7))
		conn.sets, conn.connects = nil, 0
		log, _ := loggertest.New(t.Name())
		c := NewController(log, b)
		c.Set(capOff)
		require.Zero(t, c.reconcile(t.Context()))
		c.removeOwnQuota()
		require.Zero(t, conn.connects)
		require.True(t, fileExists(t, b, testDropIn))
		require.Equal(t, uint64(7000000), conn.info.cpuQuota)
		require.Equal(t, StateDisabled, c.Snapshot().State)
	})
}

// TestSystemdBackendStaticQuotaUnenforced covers a static quota equal to the target that the kernel does not enforce.
func TestSystemdBackendStaticQuotaUnenforced(t *testing.T) {
	b, conn := newTestBackend(t)
	setStatic(t, b, conn, 700)
	require.NoError(t, os.Remove(b.path(testCPUMax)))
	log, _ := loggertest.New(t.Name())
	c := NewController(log, b)

	c.Set(cpuLimit(t, 50))
	require.Equal(t, recheckInterval, c.reconcile(t.Context()))
	require.Equal(t, []uint64{7000000}, conn.sets)
	require.Equal(t, StateApplied, c.Snapshot().State)
}

func TestFakeConnReload(t *testing.T) {
	b, conn := newTestBackend(t)
	dir := "/etc/systemd/system/" + testUnit + ".d"
	writeFile(t, b, dir+"/10-unit.conf", "[Unit]\nCPUQuota=10%\n")
	writeFile(t, b, dir+"/20-off.conf.disabled", "[Service]\nCPUQuota=20%\n")
	symlink(t, b, "/var/lib/missing.conf", dir+"/30-dangling.conf")
	writeFile(t, b, "/var/lib/linked.conf", "[Service]\nCPUQuota=40%\n")
	symlink(t, b, "/var/lib/linked.conf", dir+"/40-linked.conf")
	require.NoError(t, conn.reload(t.Context()))
	require.Equal(t, []string{dir + "/10-unit.conf", dir + "/40-linked.conf"}, conn.info.dropInPaths)
	require.Equal(t, uint64(400000), conn.info.cpuQuota)
	require.True(t, fileExists(t, b, testCPUMax))

	require.NoError(t, os.Remove(b.path(dir+"/40-linked.conf")))
	require.NoError(t, conn.reload(t.Context()))
	require.Equal(t, uint64(quotaInfinity), conn.info.cpuQuota)
	require.False(t, fileExists(t, b, testCPUMax))
}
