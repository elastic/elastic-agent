// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build centry && cgo && windows

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "elastic-agent-windows-amd64.h"

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
int serviceExitCode = 0;

// ServiceCtrlHandler is called when the service is being controlled by Windows
void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            // report stop pending and then call `GoStop`.
            // `GoStop` is non-blocking it just signals the stop causing `GoRun` to return
            // once everything has been cleaned up.
            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            serviceStatus.dwWin32ExitCode = 0;
            serviceStatus.dwCheckPoint = 0;
            serviceStatus.dwWaitHint = 0;
            SetServiceStatus(serviceStatusHandle, &serviceStatus);
            GoStop();
            break;
        case SERVICE_CONTROL_INTERROGATE:
            // report the current service status
            SetServiceStatus(serviceStatusHandle, &serviceStatus);
            break;
        default:
            break;
    }
}

// ServiceMain is the main entry point when running as a Windows service
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    // register the control handler (argv[0] contains the service name)
    serviceStatusHandle = RegisterServiceCtrlHandler(argv[0], ServiceCtrlHandler);
    if (!serviceStatusHandle) {
        return;
    }

    // initialize service status with start pending
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    serviceStatus.dwWin32ExitCode = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    // immediately say its running (want to do this before the golang runtime starts)
    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    // run the golang runtime and capture exit code
    // GoRun maintains the golang boundary this will always return the exit code
    // and all cleanup has been performed
    serviceExitCode = GoRun();

    // mark stopped
    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

// main is the entry point of the elastic-agent.exe
int main(int argc, char *argv[]) {
    SERVICE_TABLE_ENTRY serviceTable[] = {
        {argv[0], ServiceMain},
        {NULL, NULL}
    };

    // try to start as a service (this is blocking and only returns when the service is stopped)
    if (!StartServiceCtrlDispatcher(serviceTable)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // not running as a service, so it can just call GoRun (which is also blocking)
            return GoRun();
        } else {
            // StartServiceCtrlDispatcher failed for another reason
            fprintf(stderr, "StartServiceCtrlDispatcher failed with error: %lu\n", error);
            return 1;
        }
    }

    return serviceExitCode;
}
