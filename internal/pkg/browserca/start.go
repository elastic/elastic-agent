// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package browserca

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"time"

	"github.com/elastic/beats/v7/pkg/transport/tlscommon"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// browserUserEnv names the user Heartbeat runs the browser as when it starts as root.
const browserUserEnv = "BEAT_SETUID_AS"

// Config is the agent.synthetics.browser section of the agent configuration.
type Config struct {
	// CertificateAuthorities are PEM files, or directories of *.crt and *.pem files,
	// whose CAs browser monitors trust.
	CertificateAuthorities []string `config:"certificate_authorities" yaml:"certificate_authorities,omitempty" json:"certificate_authorities,omitempty"`
	// CertificateReload keeps checking the CAs for changes, so none needs a restart.
	CertificateReload tlscommon.CertificateReload `config:"certificate_reload" yaml:"certificate_reload,omitempty" json:"certificate_reload,omitempty"`
}

// Start imports configured CAs before browsers start and keeps the store in sync.
// It returns a HOME override for browser components only, or an empty string to
// inherit the existing environment. It never changes the Agent environment.
// Startup waits at most reconcileTimeout, even if filesystem I/O stalls. A single
// worker owns setup and polling so stalled I/O cannot accumulate workers or races.
func Start(ctx context.Context, log *logger.Logger, cfg Config) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	return start(ctx, log, cfg, reconcileTimeout)
}

func start(ctx context.Context, log logs, cfg Config, timeout time.Duration) string {
	initialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ready := make(chan string)
	go func() {
		m := &manager{paths: cfg.CertificateAuthorities, log: log}
		var setHome, ok bool
		m.home, m.owner, setHome, ok = browserHome(log, len(m.paths) > 0)
		if !ok {
			// Nothing configured and no store of ours to clean up: never run certutil.
			close(ready)
			return
		}
		certutil, err := exec.LookPath("certutil")
		if err != nil {
			if len(m.paths) > 0 {
				log.Warnf("certutil not found, the custom CAs for browser monitors are not imported")
			}
			close(ready)
			return
		}
		m.certs = execRunner(certutil, m.owner)
		if setHome {
			// Do not continue with a fallback that the caller never received.
			select {
			case ready <- m.home:
			case <-initialCtx.Done():
				close(ready)
				return
			}
		}
		err = m.reconcile(initialCtx)
		if err != nil {
			log.Warnf("custom CA certificates not imported: %v", err)
		}
		reload := cfg.CertificateReload.IsEnabled() && (len(m.paths) > 0 || err != nil)
		var interval time.Duration
		if reload {
			interval = cfg.reloadInterval(log)
		}
		close(ready)
		if reload {
			m.run(ctx, interval)
		}
	}()
	var home string
	for {
		select {
		case resolved, ok := <-ready:
			if !ok {
				return home
			}
			home = resolved
		case <-initialCtx.Done():
			log.Warnf("browser CA startup did not finish within its time budget: %v", initialCtx.Err())
			return home
		}
	}
}

// reloadInterval bounds polling work for both YAML and container overrides.
func (cfg Config) reloadInterval(log logs) time.Duration {
	interval := cfg.CertificateReload.ReloadInterval
	if interval <= 0 {
		return defaultInterval
	}
	if interval < time.Second {
		log.Warnf("browser CA reload interval %s is below the minimum of 1s, using 1s", interval)
		return time.Second
	}
	return interval
}

func exists(path string) bool {
	_, err := os.Stat(path) //nolint:gosec // Configured CA locations and browser homes are intentional; this only checks existence.
	return err == nil
}

// browserHome returns the home directory whose .pki/nssdb the browser reads, the
// owner the database needs, and whether HOME must be changed to that directory.
// ok is false when no CA is configured and no home holds a store Agent manages, so
// there is nothing to do and no unrelated store is ever touched.
//
// As root, Heartbeat runs the browser as BEAT_SETUID_AS with that user's home, so
// the database goes there and is given to that user. Otherwise the browser uses
// HOME, unless HOME isn't writable (arbitrary UIDs on OpenShift get "/"): then HOME
// must be changed to that user's home, which the browser inherits when it starts.
//
// Without configured CAs the same homes are tried in the same order, but each is
// matched by the marker Agent leaves in a store it manages, not by a write probe, so
// cleanup finds the store that an earlier configured run used, fallback or not.
func browserHome(log logs, configured bool) (string, *owner, bool, bool) {
	home := os.Getenv("HOME")
	isRoot := os.Geteuid() == 0
	if !isRoot && ((configured && writable(home)) || (!configured && managedStore(home))) {
		return home, nil, false, true
	}
	userHome, o, err := lookupBrowserUser(os.Getenv(browserUserEnv))
	if err != nil && configured {
		log.Warnf("the browser may not read the custom CAs: %v", err)
	}
	if userHome == "" {
		return home, nil, false, configured || managedStore(home)
	}
	if !configured && !managedStore(userHome) {
		return "", nil, false, false
	}
	if isRoot {
		return userHome, o, false, true
	}
	return userHome, nil, configured, true
}

func writable(dir string) bool {
	if dir == "" {
		return false
	}
	// Probe through a Root: the directory comes from HOME, so stay inside it.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false
	}
	defer root.Close()
	probe := fmt.Sprintf(".browserca-%d", os.Getpid())
	f, err := root.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = root.Remove(probe)
	return true
}

// lookupUser is replaceable so tests can give the browser user a temporary home.
var lookupUser = user.Lookup

// lookupBrowserUser returns the home and the owner of the user the browser runs as,
// or nothing when none is configured.
func lookupBrowserUser(name string) (string, *owner, error) {
	if name == "" {
		return "", nil, nil
	}
	u, err := lookupUser(name)
	if err != nil {
		return "", nil, fmt.Errorf("looking up %s: %w", browserUserEnv, err)
	}
	uid, errUID := strconv.ParseUint(u.Uid, 10, 32)
	gid, errGID := strconv.ParseUint(u.Gid, 10, 32)
	if errUID != nil || errGID != nil {
		return u.HomeDir, nil, fmt.Errorf("user %s has an invalid uid %q or gid %q", name, u.Uid, u.Gid)
	}
	return u.HomeDir, &owner{uid: uint32(uid), gid: uint32(gid)}, nil
}
