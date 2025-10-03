# Windows Entrypoint

This module provides a custom C entrypoint for executing Elastic Agent on Windows.

## Why it is needed

This is required because of the size of the dependency graph with Elastic Agent the amount of time that it
can take to start when a system is under heavy load (especially during startup) can cause the Elastic Agent to
not respond to the Windows service manager in-time. This causes the Elastic Agent to not enter the correct state
and it fails to work properly.

## How it works

This works by providing an entrypoint for the elastic-agent.exe to not be the go runtime, but instead be a C function.
This `int main()` in `main.c` being the entrypoint allows registering with Windows service manager as soon as it starts.
This is before the go runtime is even initialized or any of the `func init()` for all dependencies are called. Once
the application has registered with the Windows service manager (if its running as a service) then it calls `GoRun`
from `main.go`. At this point now the go runtime will start and all the `func init()` will be performed.

## How it is built

To build this first the `main.go` is compiled into a `c-archive` file. Then this file is used with the `main.c` file
and compiled together to provide a single statically compiled binary that will start at `int main()` and then run
the `GoRun` to start the main application.
