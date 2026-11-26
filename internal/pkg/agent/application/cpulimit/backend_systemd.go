// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package cpulimit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The reasons are sent to Fleet, so they must stay short fixed texts without host details.
const (
	reasonNoSystemd       = "not running under systemd"
	reasonCgroupV1        = "cgroup v1 is not supported"
	reasonNoCPUController = "the cpu cgroup controller is not available"
	reasonNotRoot         = "requires root"
	reasonNotService      = "not running as the Elastic Agent service"
)

const (
	// quotaInfinity is the CPUQuotaPerSecUSec value of a unit without a CPU quota.
	quotaInfinity = math.MaxUint64
	// quotaDropIn is the name of the drop-in file that systemd writes for CPUQuotaPerSecUSec.
	quotaDropIn = "50-CPUQuota.conf"
	// maxDropInSize is the largest runtime override that is read. systemd writes a few lines.
	maxDropInSize = 64 << 10
	// maxCgroupDepth is the deepest cgroup, in levels below the top, whose limits are read for the effective quota.
	// Real hosts have a few levels.
	maxCgroupDepth = 64
)

// systemRuntimeDirs hold the runtime drop-ins that the system manager writes for SetUnitProperties with runtime set:
// the first for units with a unit file, the second for transient units.
var systemRuntimeDirs = []string{"/run/systemd/system.control", "/run/systemd/transient"}

// errUnitNotFound reports that systemd does not know the unit.
var errUnitNotFound = errors.New("the unit is not known to systemd")

// unitInfo holds the systemd properties of a service unit that the backend reads.
type unitInfo struct {
	// id is the primary name of the unit, also when the backend asks by an alias name.
	id           string
	loadState    string
	controlGroup string
	// cpuQuota is CPUQuotaPerSecUSec: CPU time in microseconds per second, or quotaInfinity.
	cpuQuota uint64
	// dropInPaths are the drop-in files that systemd loaded for the unit.
	dropInPaths []string
}

// systemdConn is the part of the systemd D-Bus API that the backend uses.
type systemdConn interface {
	// unit returns an error that wraps errUnitNotFound when systemd does not know the unit.
	unit(ctx context.Context, name string) (unitInfo, error)
	// setCPUQuota sets CPUQuotaPerSecUSec until the next reboot.
	setCPUQuota(ctx context.Context, name string, usec uint64) error
	// reload loads all unit files again, like systemctl daemon-reload. It returns when the reload is done.
	reload(ctx context.Context) error
	close()
}

// systemdBackend sets the runtime CPUQuota of the agent's systemd service. It needs root and cgroup v2.
// The quota is held by the Agent's mechanism when the runtime override <runtime dir>/<unit>.d/50-CPUQuota.conf, which
// the agent writes, or an administrator with set-property --runtime, sets it. The file must set CPUQuota= to the live
// quota, so a file that a later drop-in overrides does not hold it. Remove deletes that file and reloads systemd, so a
// static CPUQuota from the unit file or a drop-in applies again. The backend never changes other files.
// The reload is the same as systemctl daemon-reload: it loads every unit file again but does not restart units.
//
// Inspect also reads cpu.max of the unit cgroup and of every parent cgroup, up to the top of the cgroup tree that is
// visible, to report the effective quota. These reads are only reported. The backend never changes a parent and never
// uses its limit to decide anything.
//
// Only the agent process is checked to be in the unit cgroup. Command runtime components, such as Beats and the EDOT
// collector, are its child processes and share the cgroup. Service runtime components, such as Endpoint, run in their
// own service and are outside the budget by design.
//
// Known limits:
//   - While the cap is on, the agent's runtime value replaces a static quota of an administrator, also a lower one.
//     systemd does not show the static quota under the override, so neither the service quota nor the effective quota
//     can report it.
//   - A static quota in a drop-in that sorts after 50-CPUQuota.conf, for example override.conf, or a persistent file
//     with the same name, such as /etc/systemd/system.control/<unit>.d/50-CPUQuota.conf, wins again after the next
//     daemon-reload of the host. The next check, within a minute, sets the quota of the Agent again. Until then the
//     runtime override does not set the live quota, so Remove keeps it and a stop or a cap that goes off keeps it.
//   - A crash, or a stop that times out before the delete, leaves the runtime override and its quota until the next
//     reboot. A stop that times out after the delete leaves no file, but systemd keeps the quota in memory until the
//     next daemon-reload. In both cases the next start with a cap replaces or keeps that quota, and removes it when the
//     cap goes off or at the next stop. A start without a cap leaves it.
//   - A kernel without CPU bandwidth control never enforces the quota. The service quota is then reported as unknown,
//     and the controller writes it again.
//   - Filesystem calls do not honour the context deadline.
//   - When systemd cannot write the override, for example because the runtime directory is read-only, the quota can
//     be live without a file. Remove keeps it until the next daemon-reload, restart or reboot.
type systemdBackend struct {
	unit string
	// root is the prefix for /proc, /sys and /run paths.
	root string
	// runtimeDirs are the directories of the runtime overrides, such as systemRuntimeDirs.
	runtimeDirs []string
	euid        func() int
	connect     func(ctx context.Context) (systemdConn, error)
}

func (b *systemdBackend) path(p string) string {
	return filepath.Join(b.root, p)
}

func (b *systemdBackend) readFile(ctx context.Context, p string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return os.ReadFile(b.path(p))
}

// overrideState tells what is on disk for the runtime override of the unit quota.
type overrideState int

const (
	// overrideNone means there is no runtime override, or it is not a regular file, or its path has a symbolic link,
	// or it does not set the live quota. Such a file is never deleted.
	overrideNone overrideState = iota
	// overrideFile means the runtime override is a regular file that sets the live quota.
	overrideFile
	// overridePending means systemd lists the runtime override but the file is gone. systemd keeps its quota in
	// memory until the next reload.
	overridePending
)

// runtimeOverride finds the runtime override <runtime dir>/<unit id>.d/50-CPUQuota.conf of the unit quota. The quota
// is held by the Agent's mechanism when the state is not overrideNone. Remove deletes only an override that holds the
// quota. Inspect reports a held quota that is not confirmed as unknown, and a quota that is not held and not enforced
// as no quota. DropInPaths is used only to find a deleted override that systemd still has in memory: a persistent file
// with the same name hides the runtime one from it.
func (b *systemdBackend) runtimeOverride(ctx context.Context, info unitInfo) (string, overrideState, error) {
	// Without a live quota there is nothing to hold.
	if info.cpuQuota == quotaInfinity {
		return "", overrideNone, nil
	}
	pending := ""
	for _, dir := range b.runtimeDirs {
		if err := ctx.Err(); err != nil {
			return "", overrideNone, err
		}
		p := path.Join(dir, info.id+".d", quotaDropIn)
		data, regular, err := b.readRegular(p)
		switch {
		case errors.Is(err, unix.ENOENT):
			if pending == "" && slices.Contains(info.dropInPaths, p) {
				pending = p
			}
			continue
		case errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR):
			// The path has a symbolic link or a file where a directory belongs. systemd follows links, so it can use
			// this name.
		case err != nil:
			return "", overrideNone, fmt.Errorf("failed to read the runtime CPU quota file: %w", err)
		case regular && setsQuota(data, info.cpuQuota):
			return p, overrideFile, nil
		}
		// systemd uses only the first existing file of this name, so a file in a later runtime directory has no effect.
		return "", overrideNone, nil
	}
	if pending != "" {
		return pending, overridePending, nil
	}
	return "", overrideNone, nil
}

// openDir opens the directory dir below the root. It opens each part of dir with O_NOFOLLOW, so it fails with ELOOP
// or ENOTDIR on a symbolic link.
func (b *systemdBackend) openDir(dir string) (int, error) {
	fd, err := unix.Open(b.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for part := range strings.SplitSeq(strings.Trim(dir, "/"), "/") {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// readRegular reads the file p below the root without following a symbolic link anywhere in p. regular is false when
// p is not a regular file. data is nil when the file is larger than maxDropInSize.
func (b *systemdBackend) readRegular(p string) (data []byte, regular bool, err error) {
	dir, err := b.openDir(path.Dir(p))
	if err != nil {
		return nil, false, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	// O_NONBLOCK keeps the open from waiting on a FIFO.
	fd, err := unix.Openat(dir, path.Base(p), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	_ = unix.Close(dir)
	if err != nil {
		return nil, false, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, err
	}
	data, err = io.ReadAll(io.LimitReader(f, maxDropInSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxDropInSize {
		return nil, true, nil
	}
	return data, true, nil
}

// quotaSetting returns the value of the last CPUQuota= assignment in the [Service] section of the drop-in data. ok is
// false when the data has none. Like systemd, it joins a line that ends in a backslash with the next line, also at the
// end of the file, and skips comment lines. A CPUQuota= text inside a joined line is not an assignment. Where systemd
// could read the data in another way, for example a blank line after a backslash or a line that ends in two
// backslashes, the parser joins the lines. So it can miss an assignment, but it never finds one that systemd does not
// see. It does not check the value: systemd skips a CPUQuota= line that it cannot parse and keeps the value before it,
// but here the last line wins. setsQuota then rejects the value, so such a file does not hold the quota.
func quotaSetting(data []byte) (value string, ok bool) {
	section := ""
	handle := func(line string) {
		if strings.HasPrefix(line, "[") {
			section = line
			return
		}
		key, v, found := strings.Cut(line, "=")
		if found && section == "[Service]" && strings.TrimSpace(key) == "CPUQuota" {
			value, ok = strings.TrimSpace(v), true
		}
	}
	joined := ""
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if start, found := strings.CutSuffix(line, `\`); found {
			joined += start + " "
			continue
		}
		handle(joined + line)
		joined = ""
	}
	if joined != "" {
		handle(joined)
	}
	return value, ok
}

// quotaUSec converts a CPUQuota= value in percent with at most two decimals, such as 12.34%, to microseconds per
// second. ok is false for any other value. systemd writes only this form. It also reads other forms, such as per mille,
// but a file with such a value never holds the quota.
func quotaUSec(value string) (usec uint64, ok bool) {
	number, found := strings.CutSuffix(value, "%")
	if !found {
		return 0, false
	}
	whole, decimals, hasDot := strings.Cut(number, ".")
	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil || w >= math.MaxUint64/10_000 {
		return 0, false
	}
	hundredths := uint64(0)
	if hasDot {
		if len(decimals) < 1 || len(decimals) > 2 {
			return 0, false
		}
		hundredths, err = strconv.ParseUint(decimals, 10, 64)
		if err != nil {
			return 0, false
		}
		if len(decimals) == 1 {
			hundredths *= 10
		}
	}
	return w*10_000 + hundredths*100, true
}

// setsQuota reports whether the drop-in data sets CPUQuota= to the live quota of usec microseconds per second.
// systemd writes the value truncated to hundredths of a percent, which is steps of 100 microseconds per second. So the
// live quota must be the file value or less than 100 microseconds above it. Older systemd versions write whole
// percent: their files match only when the live quota is less than 100 microseconds above a whole percent.
func setsQuota(data []byte, usec uint64) bool {
	value, _ := quotaSetting(data)
	file, ok := quotaUSec(value)
	return ok && usec >= file && usec-file < 100
}

// removeNoFollow deletes the file p below the root. A symbolic link anywhere in p, also one created after the check,
// cannot redirect the delete: the directories are opened without following links, and unlinkat does not follow one.
func (b *systemdBackend) removeNoFollow(p string) error {
	fd, err := b.openDir(path.Dir(p))
	if err != nil {
		return &fs.PathError{Op: "open", Path: p, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Unlinkat(fd, path.Base(p), 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &fs.PathError{Op: "unlinkat", Path: p, Err: err}
	}
	return nil
}

func (b *systemdBackend) LogicalCPUs(ctx context.Context) (int, error) {
	if err := b.checkHost(ctx); err != nil {
		return 0, err
	}
	data, err := b.readFile(ctx, "/sys/devices/system/cpu/online")
	if err != nil {
		return 0, err
	}
	return parseCPUList(string(data))
}

// parseCPUList counts the CPUs in a kernel CPU list such as "0-3,5,8-11".
func parseCPUList(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty CPU list")
	}
	count := 0
	for part := range strings.SplitSeq(s, ",") {
		first, last, isRange := strings.Cut(part, "-")
		if !isRange {
			last = first
		}
		lo, err1 := strconv.Atoi(first)
		hi, err2 := strconv.Atoi(last)
		if err1 != nil || err2 != nil || lo < 0 || hi < lo {
			return 0, fmt.Errorf("invalid CPU list %q", s)
		}
		count += hi - lo + 1
	}
	return count, nil
}

// Inspect reports the unit quota, checked against the kernel, and the effective quota.
// The service quota is unknown when the quota of the runtime override is not confirmed: the override is deleted and
// systemd still has its quota in memory, or the kernel does not enforce it. The controller then writes it again. A
// quota that does not come from the runtime override and that the kernel does not enforce is reported as no quota, so
// the controller writes its own.
// The effective quota does not change the service quota, and a failure to read it never makes Inspect fail.
func (b *systemdBackend) Inspect(ctx context.Context) (Inspection, error) {
	conn, info, err := b.check(ctx)
	if err != nil {
		return Inspection{}, err
	}
	conn.close()

	service, err := b.serviceQuota(ctx, info)
	if err != nil {
		return Inspection{}, err
	}
	return Inspection{Service: service, Effective: b.effectiveQuota(ctx, info.controlGroup)}, nil
}

func (b *systemdBackend) serviceQuota(ctx context.Context, info unitInfo) (Quota, error) {
	if info.cpuQuota == quotaInfinity {
		return Quota{Kind: QuotaNone}, nil
	}
	quota := Quota{Kind: QuotaSet, CPUs: float64(info.cpuQuota) / 1e6}
	_, state, err := b.runtimeOverride(ctx, info)
	if err != nil {
		return Quota{}, err
	}
	if state == overridePending {
		return Quota{}, nil
	}
	enforced, err := b.kernelEnforces(ctx, info.controlGroup, quota.CPUs)
	if err != nil {
		return Quota{}, err
	}
	switch {
	case enforced:
		return quota, nil
	case state == overrideNone:
		return Quota{Kind: QuotaNone}, nil
	default:
		return Quota{}, nil
	}
}

// kernelEnforces reports whether cpu.max of the cgroup holds a quota of cpus CPUs. cpu.max does not exist when the
// cpu controller is not enabled for the cgroup or the kernel has no CPU bandwidth control.
func (b *systemdBackend) kernelEnforces(ctx context.Context, controlGroup string, cpus float64) (bool, error) {
	data, err := b.readFile(ctx, path.Join("/sys/fs/cgroup", controlGroup, "cpu.max"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read the kernel CPU quota: %w", err)
	}
	limit, period, limited, err := parseCPUMax(data)
	if err != nil || !limited {
		return false, err
	}
	// systemd rounds the kernel quota down to whole microseconds of the period, so the accepted difference is one
	// microsecond of the period. The small extra margin is for float rounding.
	return math.Abs(limit-cpus) <= 1/float64(period)+1e-9, nil
}

// effectiveQuota returns the lowest quota in cpu.max of the cgroup controlGroup and its parents, up to the top of the
// cgroup tree that is visible. The top is read too: in a container with its own cgroup namespace it is a cgroup that
// holds the container limit. The root cgroup of a host has no cpu.max. A missing cpu.max or the value max means no
// limit at that level. It returns an unknown quota when a level cannot be read or parsed, or when the cgroup is deeper
// than maxCgroupDepth.
func (b *systemdBackend) effectiveQuota(ctx context.Context, controlGroup string) Quota {
	effective := Quota{Kind: QuotaNone}
	dir := path.Clean(controlGroup)
	for depth := 0; ; depth++ {
		if depth > maxCgroupDepth {
			return Quota{}
		}
		data, err := b.readFile(ctx, path.Join("/sys/fs/cgroup", dir, "cpu.max"))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return Quota{}
		default:
			limit, _, limited, err := parseCPUMax(data)
			if err != nil {
				return Quota{}
			}
			if limited && (effective.Kind == QuotaNone || limit < effective.CPUs) {
				effective = Quota{Kind: QuotaSet, CPUs: limit}
			}
		}
		if dir == "/" {
			return effective
		}
		dir = path.Dir(dir)
	}
}

// parseCPUMax parses the content of a cgroup v2 cpu.max file: "<quota> <period>" or "max <period>", in microseconds.
// limited is false for max. Otherwise cpus is quota/period.
func parseCPUMax(data []byte) (cpus float64, period uint64, limited bool, err error) {
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, 0, false, fmt.Errorf("invalid cpu.max content %q", data)
	}
	period, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil || period == 0 {
		return 0, 0, false, fmt.Errorf("invalid cpu.max content %q", data)
	}
	if fields[0] == "max" {
		return 0, period, false, nil
	}
	quota, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, false, fmt.Errorf("invalid cpu.max content %q", data)
	}
	return float64(quota) / float64(period), period, true, nil
}

func (b *systemdBackend) Apply(ctx context.Context, cpus float64) error {
	// systemd writes the runtime override in hundredths of a percent of one CPU, older versions in whole percent. A
	// whole percent value is exact in both, and with the default period of 100 ms it is exact in cpu.max too. The
	// rounding error is at most 0.005 CPUs, below the controller tolerance.
	percent := math.Round(cpus * 100)
	if !(percent >= 1 && percent <= math.MaxUint64/10000) {
		return fmt.Errorf("invalid CPU quota of %v CPUs", cpus)
	}
	conn, _, err := b.check(ctx)
	if err != nil {
		return err
	}
	defer conn.close()
	return conn.setCPUQuota(ctx, b.unit, uint64(percent)*10000)
}

func (b *systemdBackend) Remove(ctx context.Context) error {
	conn, info, err := b.check(ctx)
	if err != nil {
		return err
	}
	defer conn.close()

	p, state, err := b.runtimeOverride(ctx, info)
	if err != nil || state == overrideNone {
		return err
	}
	// A pending override is already deleted. Then only the reload is left.
	if state == overrideFile {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := b.removeNoFollow(p); err != nil {
			return fmt.Errorf("failed to delete the runtime CPU quota: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := conn.reload(ctx); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	return nil
}

// checkHost returns an error that wraps *UnsupportedError when the host has no systemd, cgroup v2 or cpu controller.
func (b *systemdBackend) checkHost(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Stat(b.path("/run/systemd/system"))
	if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.IsDir()) {
		return &UnsupportedError{Reason: reasonNoSystemd}
	}
	if err != nil {
		return fmt.Errorf("failed to check for systemd: %w", err)
	}
	// Only cgroup v2 has cgroup.controllers in the root of the cgroup file system.
	controllers, err := b.readFile(ctx, "/sys/fs/cgroup/cgroup.controllers")
	if errors.Is(err, fs.ErrNotExist) {
		return &UnsupportedError{Reason: reasonCgroupV1}
	}
	if err != nil {
		return fmt.Errorf("failed to read the cgroup controllers: %w", err)
	}
	if !slices.Contains(strings.Fields(string(controllers)), "cpu") {
		return &UnsupportedError{Reason: reasonNoCPUController}
	}
	return nil
}

// check returns an error that wraps *UnsupportedError when the host or the process is not supported.
// On success it returns an open connection and the unit properties. The caller must close the connection.
func (b *systemdBackend) check(ctx context.Context) (systemdConn, unitInfo, error) {
	if err := b.checkHost(ctx); err != nil {
		return nil, unitInfo{}, err
	}
	// The systemd private socket accepts only root.
	if b.euid() != 0 {
		return nil, unitInfo{}, &UnsupportedError{Reason: reasonNotRoot}
	}
	own, err := b.readFile(ctx, "/proc/self/cgroup")
	if err != nil {
		return nil, unitInfo{}, fmt.Errorf("failed to read the process cgroup: %w", err)
	}

	// checkHost found /run/systemd/system, so a failed connection is unexpected.
	conn, err := b.connect(ctx)
	if err != nil {
		return nil, unitInfo{}, fmt.Errorf("failed to connect to systemd: %w", err)
	}
	info, err := conn.unit(ctx, b.unit)
	if errors.Is(err, errUnitNotFound) || (err == nil && info.loadState == "not-found") {
		conn.close()
		return nil, unitInfo{}, &UnsupportedError{Reason: reasonNotService}
	}
	if err != nil {
		conn.close()
		return nil, unitInfo{}, fmt.Errorf("failed to read the unit properties: %w", err)
	}
	if info.loadState != "loaded" {
		conn.close()
		return nil, unitInfo{}, fmt.Errorf("the unit load state is %q", info.loadState)
	}
	if info.controlGroup == "" || !inCgroup(own, info.controlGroup) {
		conn.close()
		return nil, unitInfo{}, &UnsupportedError{Reason: reasonNotService}
	}
	return conn, info, nil
}

// inCgroup reports whether the cgroup v2 entry in procCgroup, the content of /proc/<pid>/cgroup,
// is the cgroup group or below it.
func inCgroup(procCgroup []byte, group string) bool {
	scanner := bufio.NewScanner(bytes.NewReader(procCgroup))
	for scanner.Scan() {
		if p, ok := strings.CutPrefix(scanner.Text(), "0::"); ok {
			return p == group || strings.HasPrefix(p, group+"/")
		}
	}
	return false
}
