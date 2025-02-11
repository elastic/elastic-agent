// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package process

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Job is wrapper for windows JobObject
// https://docs.microsoft.com/en-us/windows/win32/procthread/job-objects
// This helper guarantees a clean process tree kill on job handler close
type Job windows.Handle

var (
	// Public global JobObject should be initialized once in main
	JobObject Job
)

// CreateJobObject creates JobObject on Windows, global per process
// Should only be initialized once in main function
func CreateJobObject() (pj Job, err error) {
	if pj, err = NewJob(); err != nil {
		return pj, err
	}
	JobObject = pj
	return pj, nil
}

// NewJob creates a instance of the JobObject
func NewJob() (Job, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}

	// From https://docs.microsoft.com/en-us/windows/win32/procthread/job-objects
	// ... if the job has the JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag specified,
	// closing the last job object handle terminates all associated processes
	// and then destroys the job object itself.
	// If a nested job has the JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag specified,
	// closing the last job object handle terminates all processes associated
	// with the job and its child jobs in the hierarchy.
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info))); err != nil {
		return 0, err
	}

	return Job(h), nil
}

// Close closes job handler
func (job Job) Close() error {
	if job == 0 {
		return nil
	}
	return windows.CloseHandle(windows.Handle(job))
}

// Assign assigns the process to the JobObject
func (job Job) Assign(p *os.Process) error {
	if job == 0 || p == nil {
		return nil
	}

	// To assign a process to a job, you need a handle to the process. Since os.Process provides no
	// way to obtain it's underlying handle safely, get one with OpenProcess().
	//   https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	// This requires at least the PROCESS_SET_QUOTA and PROCESS_TERMINATE access rights. Various
	// examples also add VM_READ or the safer PROCESS_QUERY_LIMITED_INFORMATION so include that too.
	//   https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject
	desiredAccess := uint32(windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_SET_QUOTA | windows.PROCESS_TERMINATE)
	processHandle, err := windows.OpenProcess(desiredAccess, false, uint32(p.Pid))
	if err != nil {
		return fmt.Errorf("opening process handle: %w", err)
	}
	defer windows.CloseHandle(processHandle)

	err = windows.AssignProcessToJobObject(windows.Handle(job), processHandle)
	if err != nil {
		return fmt.Errorf("assigning to job object: %w", err)
	}

	return nil
}
