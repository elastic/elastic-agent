#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "elastic-agent-windows-amd64.h"

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;

// ServiceCleanup is an atexit handler that sets the service to stopped.
void ServiceCleanup(void) {
    if (serviceStatusHandle) {
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(serviceStatusHandle, &serviceStatus);
    }
}

// ServiceCtrlHandler is called when the service is being controlled by Windows
void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            serviceStatus.dwWin32ExitCode = 0;
            serviceStatus.dwCheckPoint = 0;
            serviceStatus.dwWaitHint = 0;
            SetServiceStatus(serviceStatusHandle, &serviceStatus);
            GoStop();
            break;
        default:
            break;
    }
}

// ServiceMain is the main entry point when running as a Windows service
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    // register the control handler
    serviceStatusHandle = RegisterServiceCtrlHandler(TEXT("elastic-agent"), ServiceCtrlHandler);
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

    // register the cleanup function to inform that it is stopped now
    //
    // atexit is used so no matter what happens in the goruntime the service is
    // marked as stopped
    atexit(ServiceCleanup);

    // run the golang runtime
    GoRun();
}

// main is the entry point of the elastic-agent.exe
int main() {
    SERVICE_TABLE_ENTRY serviceTable[] = {
        {TEXT("elastic-agent"), ServiceMain},
        {NULL, NULL}
    };

    // try to start as a service (this is blocking and only returns when the service is stopped)
    if (!StartServiceCtrlDispatcher(serviceTable)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // not running as a service, so it can just call GoRun (which is also blocking)
            GoRun();
            return 0;
        }
    }

    return 0;
}
