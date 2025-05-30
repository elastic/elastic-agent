// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// This is a simple program that will lock a file passed using the -lockfile option, used for testing file lock works properly.
// os.Interrupt or signal.SIGTERM will make the program release the lock and exit
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofrs/flock"
)

const AcquiredLockLogFmt = "Acquired lock on file %s\n"

const lockFileFlagName = "lockfile"

var lockFile = flag.String(lockFileFlagName, "", "path to lock file")

func main() {

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	flag.Parse()
	if *lockFile == "" {
		log.Fatalf("No lockfile specified. Please run %s -%s <path to lockfile>", os.Args[0], lockFileFlagName)
	}

	fLock := flock.New(*lockFile)

	locked, err := fLock.TryLock()
	if err != nil {
		log.Fatalf("Error locking %s: %s", *lockFile, err.Error())
	}

	if !locked {
		log.Fatalf("Failed acquiring lock on %s", *lockFile)
	}
	defer fLock.Unlock()

	log.Printf(AcquiredLockLogFmt, *lockFile)

	s := <-signalCh
	log.Printf("Received signal: %s, exiting", s.String())
}
