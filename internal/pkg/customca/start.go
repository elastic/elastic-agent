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
	"runtime"
	"slices"
	"strconv"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
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

// Start imports the configured CAs into the browser's trust store and, unless
// certificate_reload is disabled, keeps it in sync until ctx is done. A store left
// by a previous run is cleaned up even when no CA is configured any more. It does
// nothing outside Linux, when there are neither configured paths that exist nor a
// store, or without certutil. It never returns an error: a failure only logs a
// warning, so it can't stop the agent from starting.
//
// It must run before the agent starts the browser, because it may change HOME.
func Start(ctx context.Context, log *logger.Logger, cfg Config) {
	if runtime.GOOS != "linux" {
		return
	}
	m := &manager{paths: cfg.CertificateAuthorities, log: log}
	var setHome bool
	m.home, m.owner, setHome = browserHome(log)
	if !slices.ContainsFunc(m.paths, exists) && !m.hasDB() {
		return
	}
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		if len(m.files()) > 0 {
			log.Warnf("certutil not found, the custom CAs for browser monitors are not imported")
		}
		return
	}
	if setHome {
		_ = os.Setenv("HOME", m.home)
	}
	m.certs = execRunner(certutil)

	reload := cfg.CertificateReload.IsEnabled() && len(m.paths) > 0
	if err := m.reconcile(ctx); err != nil {
		if reload {
			log.Warnf("custom CA certificates not imported, will retry: %v", err)
		} else {
			log.Warnf("custom CA certificates not imported: %v", err)
		}
	}
	if reload {
		interval := cfg.CertificateReload.ReloadInterval
		if interval <= 0 {
			interval = defaultInterval
		}
		go m.run(ctx, interval)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// browserHome returns the home directory whose .pki/nssdb the browser reads, the
// owner the database needs, and whether HOME must be changed to that directory.
//
// As root, Heartbeat runs the browser as BEAT_SETUID_AS with that user's home, so
// the database goes there and is given to that user. Otherwise the browser uses
// HOME, unless HOME isn't writable (arbitrary UIDs on OpenShift get "/"): then HOME
// must be changed to that user's home, which the browser inherits when it starts.
func browserHome(log logs) (string, *owner, bool) {
	home := os.Getenv("HOME")
	isRoot := os.Geteuid() == 0
	if !isRoot && writable(home) {
		return home, nil, false
	}
	userHome, o, err := lookupBrowserUser(os.Getenv(browserUserEnv))
	if err != nil {
		log.Warnf("the browser may not read the custom CAs: %v", err)
	}
	if userHome == "" {
		return home, nil, false
	}
	if isRoot {
		return userHome, o, false
	}
	return userHome, nil, true
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
	probe := fmt.Sprintf(".customca-%d", os.Getpid())
	f, err := root.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = root.Remove(probe)
	return true
}

// lookupBrowserUser returns the home and the owner of the user the browser runs as,
// or nothing when none is configured.
func lookupBrowserUser(name string) (string, *owner, error) {
	if name == "" {
		return "", nil, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return "", nil, fmt.Errorf("looking up %s: %w", browserUserEnv, err)
	}
	uid, errUID := strconv.Atoi(u.Uid)
	gid, errGID := strconv.Atoi(u.Gid)
	if errUID != nil || errGID != nil {
		return u.HomeDir, nil, fmt.Errorf("user %s has a non-numeric uid %q or gid %q", name, u.Uid, u.Gid)
	}
	return u.HomeDir, &owner{uid: uid, gid: gid}, nil
}
