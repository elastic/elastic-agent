# Draft: Windows-only GC-metadata corruption, Go 1.25.7–1.26.3 (not Green Tea)

Draft for a golang/go issue (or an addition to
[#77975](https://github.com/golang/go/issues/77975), noting our crash is **not**
Green Tea-specific and reproduces on 1.25). Not yet filed.

## Summary

On Windows/amd64, the Elastic Agent unit-test suite intermittently dies with a
**fatal Go runtime error indicating GC-managed memory/metadata corruption**.
The specific fatal message varies run to run, which is the central clue: it is
not one logic bug, it is a stray corruption detected at whatever check happens
to notice it first.

Observed fatal messages (all from the same workload/config):

- `runtime: marked free object in span ...` → `fatal error: found pointer to free object`
- `fatal error: checkmark found unmarked object`
- `fatal error: s.allocCount != s.nelems && freeIndex == s.nelems` (from `mcache.nextFree`)
- `fatal error: sweep increased allocation count`
- `fatal error: sync: Unlock of unlocked RWMutex`
- `fatal error: unexpected signal during runtime execution`

## Environment

- **OS:** Windows 11 Pro, build 26200 (Azure `Standard_D8s_v5`, 8 vCPU, 32 GB).
  Image: an internal CI gallery image; Defender real-time on but `C:\`/`D:\`
  excluded from scanning.
- **Go:** reproduces on **go1.25.10** and **go1.26.3** (amd64). We could not
  test < 1.25.7 (a dependency declares `go >= 1.25.7`, so the module graph will
  not build on 1.24).
- **Not reproduced on Linux** (same code, same CI system) — Windows-specific.
- **Not reproduced** on a quiet standalone VM built from the identical image
  (0/12 full-suite iterations); reproduces ~6/10 on the contended CI fleet.
  Appears to need host-level scheduling/contention to fire.

## Trigger / workload

Heavy, parallel, filesystem-bound unit tests (creating/symlinking/reading/
deleting many small files: `MkdirAll`, `WriteFile`, `Symlink`, `Readlink`,
`ReadFile`, `Readdirnames`, `RemoteAll`, plus JSON marshal/unmarshal), run with
`go test -race -coverpkg=./...`. Crash frequency is greatly increased by
`GOGC=1` (more frequent sweeping/recycling → corruption is detected sooner).

Diagnostic config that makes it most consistent:

```
GOGC=1
GOTRACEBACK=crash
GODEBUG=clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1
GOEXPERIMENT=cgocheck2
go test -race -covermode=atomic -coverpkg=./... ./...
```

## What is ruled out

| Hypothesis | Test | Result |
|---|---|---|
| Green Tea GC (default in 1.26) | `GOEXPERIMENT=nogreenteagc` | still crashes, same rate |
| Go 1.26 regression | bisect to go1.25.10 | still crashes (floor 1.25.7 due to deps) |
| Async preemption | `asyncpreemptoff=1` | still crashes |
| Stack shrinking | `gcshrinkstackoff=1` | still crashes, same rate |
| Stray external/IOCP write | file I/O is synchronous on Win (no `FILE_FLAG_OVERLAPPED`); Defender excludes the drive | no external writer found |

So: Windows-only, version-independent (1.25.7–1.26.3), not Green Tea, not async
preemption, not stack shrinking.

## Key evidence

### (1) Crash inside GC stack scan → copystack → unwinder (Go 1.25.10)

The clearest stack. The GC mark worker faulted while scanning a parked
goroutine's stack:

```
[signal 0xc0000005 code=0x0 addr=0xe0 pc=0x1400767a5]
runtime.sigpanic()                    signal_windows.go:387
runtime.(*unwinder).next(...)         traceback.go:458   ← AV at +0xe0
runtime.copystack(...)                stack.go:975
runtime.shrinkstack(...)              stack.go:1289
runtime.scanstack(...)                mgcmark.go:898
runtime.markroot.func1() / gcDrain / gcBgMarkWorker.func2()
```

The goroutine being scanned is an ordinary `[chan receive]` goroutine; the
unwinder follows a frame/func pointer and dereferences a bad value. This is the
**same symptom as #77975** ("corrupted return address … stack scanning /
copystack"), but here on **1.25.10 with `GOEXPERIMENT=nogreenteagc` and
`asyncpreemptoff=1`** — so it is not Green-Tea-specific and not async-preemption.
`gcshrinkstackoff=1` does not help, because `scanstack` and growth-driven
`copystack` still walk the corrupted stack.

### (2) Allocator metadata inconsistency (Go 1.26.3, symbolicated via matching binary)

```
runtime.throw("s.allocCount != s.nelems && freeIndex == s.nelems")
runtime.(*mcache).nextFree(...)   malloc.go:1004   ← throw, during a routine
runtime.mallocgc / growslice / strings.Builder.WriteString / filepath.Join
```

An ordinary string allocation pulls an `mspan` with internally inconsistent
bookkeeping.

**Working unification:** a stray write corrupts a goroutine's *stack contents*;
the GC then either faults unwinding that stack (1) or marks a bogus pointer from
it, surfacing later as `marked/found free object` / `checkmark` / span
bookkeeping throws (2 and the others).

## Artifacts available

Full minidumps (`*.dmp`) and matching source-rebuilt `-race -coverpkg` test
binaries for several crashes; per-run logs with `gctrace`/`schedtrace`; CI build
links. Happy to provide.

## Open question for the Go team

What concurrent actor corrupts `mspan`/heap-bitmap metadata on Windows under
heavy parallel allocation + filesystem syscalls, independent of GC
implementation (pre- and post-Green-Tea) and of async preemption / stack
shrinking? Is there a known Windows-specific runtime issue (syscall/stack/
signal interaction with the allocator or sweeper) in this range?
