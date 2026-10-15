// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package customca

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

const (
	// IntervalEnv sets the check interval in seconds (or as a Go duration); 0 disables it.
	IntervalEnv = "ELASTIC_AGENT_CUSTOM_CA_RELOAD_INTERVAL"
	// BrowserUserEnv names the user the browser runs as when the agent starts as root.
	BrowserUserEnv = "BEAT_SETUID_AS"
)

// BrowserHome returns the home directory of the browser, whose .pki/nssdb Chromium
// reads, and whether HOME must be changed to it.
//
// As root, Heartbeat runs the browser as another user with that user's home, so
// that is beatHome. Arbitrary UIDs (e.g. on OpenShift) get a read-only "/" as HOME:
// then beatHome is used, and must be exported before the agent starts, because the
// browser inherits the environment of the process that launches it.
func BrowserHome(isRoot bool, home, beatHome string) (dir string, setHome bool) {
	if isRoot {
		return beatHome, false
	}
	if writable(home) {
		return home, false
	}
	return beatHome, true
}

func writable(dir string) bool {
	if dir == "" {
		return false
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false
	}
	defer root.Close()
	probe := fmt.Sprintf(".customca-%d", os.Getpid())
	f, err := root.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = root.Remove(probe)
	return true
}

// ParseInterval parses the value of IntervalEnv: whole seconds, or a Go duration.
func ParseInterval(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return DefaultInterval
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if d, err := time.ParseDuration(v); err == nil && d >= 0 {
		return d
	}
	return DefaultInterval
}

// Options are the inputs of Start.
type Options struct {
	// Dir is the directory with the CAs; DefaultDir when empty.
	Dir string
	// BeatHome is the browser user's home when it can't be looked up from BEAT_SETUID_AS.
	BeatHome string
	// Log receives progress and warnings.
	Log Logger
}

// Start imports the CAs mounted in the container and keeps them in sync until ctx
// is done. It does nothing unless the CA directory exists, and never returns an
// error: a failure only logs a warning, so it can't stop the agent from starting.
//
// It must run before the agent starts the browser, because it may change HOME.
func Start(ctx context.Context, opts Options) {
	dir := opts.Dir
	if dir == "" {
		dir = DefaultDir
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return
	}
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		if len((&Manager{cfg: Config{Dir: dir}}).files()) > 0 && opts.Log != nil {
			opts.Log.Warnf("certutil not found, custom CAs in %s are not imported", dir)
		}
		return
	}

	// The browser runs as this user when the agent starts as root, and its home is
	// where Heartbeat points HOME, so it is also the fallback for arbitrary UIDs.
	browserUser, owner, err := lookupBrowserUser(os.Getenv(BrowserUserEnv))
	if err != nil && opts.Log != nil {
		opts.Log.Warnf("the browser may not read the custom CAs: %v", err)
	}
	beatHome := opts.BeatHome
	if browserUser != nil && browserUser.HomeDir != "" {
		beatHome = browserUser.HomeDir
	}

	isRoot := os.Geteuid() == 0
	home, setHome := BrowserHome(isRoot, os.Getenv("HOME"), beatHome)
	if setHome {
		_ = os.Setenv("HOME", home)
	}
	if !isRoot {
		owner = nil // only root can give files away
	}

	m := New(Config{
		Dir:      dir,
		Home:     home,
		Interval: ParseInterval(os.Getenv(IntervalEnv)),
		Runner:   ExecRunner(certutil),
		Owner:    owner,
		Log:      opts.Log,
	})
	if m.HasWork() {
		// On failure Run retries it.
		if err := m.Sync(ctx); err != nil && opts.Log != nil {
			opts.Log.Warnf("custom CA certificates not imported, will retry: %v", err)
		}
	}
	if m.cfg.Interval > 0 {
		go m.Run(ctx)
	}
}

// lookupBrowserUser looks up the user the browser runs as. It returns nil, nil, nil when none is configured.
func lookupBrowserUser(name string) (*user.User, *Owner, error) {
	if name == "" {
		return nil, nil, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up %s: %w", BrowserUserEnv, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return u, nil, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return u, nil, err
	}
	return u, &Owner{UID: uid, GID: gid}, nil
}
