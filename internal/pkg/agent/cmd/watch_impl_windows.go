// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	gowindows "golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var (
	kernel32API = gowindows.NewLazySystemDLL("kernel32.dll")

	freeConsoleProc           = kernel32API.NewProc("FreeConsole")
	attachConsoleProc         = kernel32API.NewProc("AttachConsole")
	procGetConsoleProcessList = kernel32API.NewProc("GetConsoleProcessList")
	procSetConsoleHandler     = kernel32API.NewProc("SetConsoleCtrlHandler")
	allocConsoleProc          = kernel32API.NewProc("AllocConsole")
)

func takedownWatcher(log *logger.Logger, pidFetchFunc watcherPIDsFetcher) error {
	
	pids, err := pidFetchFunc()
	if err != nil {
		return fmt.Errorf("error listing watcher processes: %s", err)
	}

	ownPID := os.Getpid()

	var accumulatedSignalingErrors error
	for _, pid := range pids {

		if pid == ownPID {
			continue
		}

		log.Debugf("attempting to terminate watcher process with PID: %d", pid)
		accumulatedSignalingErrors = errors.Join(accumulatedSignalingErrors, signalPID(log, pid))
	}

	return accumulatedSignalingErrors
}

// GetConsoleProcessList retrieves the list of process IDs attached to the current console
func GetConsoleProcessList() ([]uint32, error) {
	// Allocate a buffer for PIDs
	const maxProcs = 64
	pids := make([]uint32, maxProcs)

	r1, _, err := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(maxProcs),
	)

	count := uint32(r1)
	if count == 0 {
		return nil, err
	}

	return pids[:count], nil
}

// signalPID takes care of signaling a given PID. It also leverages defer() for freeing console and other housekeeping
func signalPID(log *logger.Logger, pid int) error {
	r1, _, consoleErr := freeConsoleProc.Call()
	if r1 == 0 {
		log.Warnf("error preemptively detaching from console: %s", consoleErr)
	}

	r1, _, consoleErr = attachConsoleProc.Call(uintptr(pid))
	if r1 == 0 {
		return fmt.Errorf("error attaching console to watcher process with PID %d: %w", pid, consoleErr)
	}
	log.Infof("successfully attached console with PID: %d", pid)

	defer func() {
		r1, _, consoleErr = freeConsoleProc.Call()
		if r1 == 0 {
			log.Errorf("error detaching from console: %s", consoleErr)
		} else {
			log.Infof("successfully detached from console of PID: %d", pid)
		}
	}()

	if list, consoleProcessListErr := GetConsoleProcessList(); consoleProcessListErr != nil {
		log.Errorf("error listing console processes: %s", consoleProcessListErr)
	} else {
		log.Infof("Own PID: %d, Watcher pid %d, Process list on console: %v", os.Getpid(), pid, list)
	}

	// Normally we would want to send the Ctrl+Break event only to the watcher process but due to the fact that
	// the parent process of the watcher has already terminated, we have to hug it tightly and take it down with us
	// by specifying processGroupID=0
	killProcErr := gowindows.GenerateConsoleCtrlEvent(gowindows.CTRL_BREAK_EVENT, uint32(pid))

	if killProcErr != nil {
		return fmt.Errorf("error signaling process with PID: %d: %w", pid, killProcErr)
	}

	return nil
}
