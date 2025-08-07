// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// This is a simple program that will lock an applocker using a file passed using the -lockfile option, used for testing file lock works properly.
// os.Interrupt or signal.SIGTERM will make the program release the lock and exit
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
)

const AcquiredLockLogFmt = "Acquired lock on file %s\n"

const lockFileFlagName = "lockfile"
const ignoreSignalFlagName = "ignoresignals"

var lockFile = flag.String(lockFileFlagName, "", "path to lock file")
var ignoreSignals = flag.Bool(ignoreSignalFlagName, false, "ignore signals")

func main() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	flag.Parse()
	if *lockFile == "" {
		log.Fatalf("No lockfile specified. Please run %s -%s <path to lockfile>", os.Args[0], lockFileFlagName)
	}

	appLocker := filelock.NewAppLocker(filepath.Dir(*lockFile), filepath.Base(*lockFile))

	err := appLocker.TryLock()
	if err != nil {
		log.Fatalf("Error locking %s: %s", *lockFile, err.Error())
	}

	defer func(aLocker *filelock.AppLocker) {

		if unlockErr := aLocker.Unlock(); unlockErr != nil {
			log.Printf("Error unlocking %s: %s", *lockFile, unlockErr.Error())
		}
	}(appLocker)

	log.Printf(AcquiredLockLogFmt, *lockFile)

	for {

		s := <-signalChan
		if *ignoreSignals {
			log.Printf("Received signal %v , ignoring it...", s)
			continue
		}

		log.Printf("Received signal %v , exiting...", s)
		break
	}
}
