// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package agentservice

import (
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

// couldNotConnect is the errno for ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.
const couldNotConnect syscall.Errno = 1063

type beatService struct {
	stopCallback    func()
	done            chan struct{}
	executeFinished chan struct{}
}

var serviceInstance = &beatService{
	stopCallback:    nil,
	done:            make(chan struct{}),
	executeFinished: make(chan struct{}),
}

func init() {
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		wg.Done()
		processWindowsControlEvents(stopBeat)
	}()
	// wait with subsequent execution so we don't starve us from resources when trying
	// to check with manager.
	// resources could be consumed in a way of additional init calls during startup
	// or when execution proceeds and spins up additional goroutine that could get priority
	// e.g starting beats, coordinator, dispatcher... other components
	wg.Wait()
}

func stopBeat() {
	if StopChanBeat != nil {
		// making sure select catches it by sending
		select {
		case StopChanBeat <- true:
		default:
		}
		close(StopChanBeat)

	}
}

// ProcessWindowsControlEvents on Windows machines creates a loop
// that only finishes when a Stop or Shutdown request is received.
// On non-windows platforms, the function does nothing. The
// stopCallback function is called when the Stop/Shutdown
// request is received.
func processWindowsControlEvents(stopCallback func()) {
	defer close(serviceInstance.executeFinished)

	//nolint:staticcheck // keep using the deprecated method in order to maintain the existing behavior
	isInteractive, err := svc.IsAnInteractiveSession()
	if err != nil {
		logp.L().Errorf("IsAnInteractiveSession: %v", err)
		return
	}
	logp.L().Debug("service", "Windows is interactive: %v", isInteractive)

	run := svc.Run
	if isInteractive {
		run = debug.Run
	}

	serviceInstance.stopCallback = stopCallback
	err = run(os.Args[0], serviceInstance)
	if err == nil {
		return
	}

	//nolint:errorlint // this system error is a special case
	if errnoErr, ok := err.(syscall.Errno); ok && errnoErr == couldNotConnect {
		/*
			 If, as in the case of Jenkins, the process is started as an interactive process, but the invoking process
			 is itself a service, beats will incorrectly try to register a service handler. We don't want to swallow
			 errors, so we should still log this, but only as Info. The only ill effect should be a couple extra
			 idle go routines.

			 Ideally we could detect this better, but the only reliable way is with StartServiceCtrlDispatcherW, which
			 is invoked in go with svc.Run. Unfortunately, this also starts some goroutines ahead of time for various
			 reasons. As the docs state for StartServiceCtrlDispatcherW when a 1063 errno is returned:

			 "This error is returned if the program is being run as a console application rather than as a service.
			  If the program will be run as a console application for debugging purposes, structure it such that
				service-specific code is not called when this error is returned."
		*/
		logp.L().Info("Attempted to register Windows service handlers, but this is not a service. No action necessary")
		return
	}

	logp.L().Errorf("Windows service setup failed: %+v", err)
}

// Execute runs the beat service with the arguments and manages changes that
// occur in the environment or runtime that may affect the beat.
func (m *beatService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	logp.L().Info("reported Running to Service manager")
	combinedChan := make(chan svc.ChangeRequest)
	go func() {
		for {
			select {
			case c := <-r:
				combinedChan <- c
			case <-m.done:
				// exits consumption loop on termination and reports stopping
				combinedChan <- svc.ChangeRequest{Cmd: svc.Shutdown}
				return
			}
		}
	}()

loop:
	for c := range combinedChan {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
			// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
			time.Sleep(100 * time.Millisecond)
			changes <- c.CurrentStatus

		// The svc.Cmd tye does not implement the Stringer interface and its
		// underlying type is an integer, therefore it's needed to manually log them.
		case svc.Stop:
			logp.L().Info("received state change 'svc.Stop' from windows service manager")
			break loop
		case svc.Shutdown:
			logp.L().Info("received state change 'svc.Shutdown' from windows service manager")
			break loop

		default:
			logp.L().Errorf("Unexpected control request: $%d. Ignored.", c)
		}
	}

	trySendState(svc.StopPending, changes)
	defer trySendState(svc.Stopped, changes)

	logp.L().Info("changed windows service state to svc.StopPending, invoking stopCallback")
	m.stopCallback()

	// Block until notifyWindowsServiceStopped below is called. This is required
	// as the windows/svc package will transition the service to STOPPED state
	// once this function returns.
	<-m.done
	logp.L().Debug("windows service state changed to svc.Stopped")
	return ssec, errno
}

func (m *beatService) stop() {
	close(m.done)
}

func NotifyTermination() {
	serviceInstance.stop()
}

func trySendState(s svc.State, changes chan<- svc.Status) {
	select {
	case changes <- svc.Status{State: s}:
	case <-time.After(500 * time.Millisecond): // should never happen, but don't make this blocking
	}
}

// WaitExecutionDone returns only after stop was reported to service manager.
// If response is not retrieved within 500 millisecond wait is aborted.
func WaitExecutionDone() {
	if isWinService, err := svc.IsWindowsService(); err != nil || !isWinService {
		// not a service, don't wait
		return
	}

	select {
	case <-serviceInstance.executeFinished:
	case <-time.After(500 * time.Millisecond):
	}
}
