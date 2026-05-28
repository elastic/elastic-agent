# Windows unit-test GC corruption — investigation notes

Tracking a Windows-only fatal crash in the Elastic Agent unit test suite.
Working branch: `worktree-test+diagnose-windows-gc-panic`.
Suspected upstream cause: <https://github.com/golang/go/issues/77975>.

> **Status:** Reproduced reliably in CI; root cause narrowed to memory
> corruption consistent with a stray kernel (IOCP) write into freed/recycled
> Go heap memory. Not yet reproduced in a standalone minimal test. No fix yet —
> this is diagnostic work toward a clean upstream report.

## Symptom

On the Windows 11 CI runners the unit test suite intermittently dies with a
fatal Go runtime error. The exact message varies (see below), but it is always
a *fatal* runtime throw, not a recoverable test failure, so it takes down the
whole `go test` process.

The crash is **not deterministic by message** — the same underlying condition
surfaces as several different fatal errors across runs. This is the single most
important observation: it is not a logic bug in any one data structure.

## Confirmed crash signatures

| Build | Fatal message | Corrupted structure | Span size class |
|-------|---------------|---------------------|-----------------|
| 40495 | `runtime: marked free object` → `fatal error: found pointer to free object` | GC mark bitmap | 16 B |
| 40511 | `found pointer to free object` (3 of 5 parallel jobs) | GC mark bitmap | 16 B, 64 B, 208 B |
| 40516 | `found pointer to free object` | GC mark bitmap | 112 B |
| 40519 | `fatal error: sync: Unlock of unlocked RWMutex` | `sync.RWMutex` internal state word | n/a |

Earlier observed (pre-procdump) secondary effect: a recoverable
`EXCEPTION_ACCESS_VIOLATION` reading a nil receiver in
`(*fleetapi.ActionUpgrade).String()` while `fmt` formatted a panic message —
i.e. a *pointer field that had been zeroed by the corruption*, surfacing during
the test framework's panic-recovery path.

Across all of these:

- The corruption hits **different size classes** (16/64/112/208 B) and
  **different kinds of memory** (GC mark bitmap, mutex state, pointer fields).
- That breadth is the signature of a **stray single-word write landing in
  whatever memory happens to be recycled at that address**, not a type-specific
  bug.

## Where and when it fires

- Always during a **`TestCleanup` subtest** in
  `internal/pkg/agent/application/upgrade` (`rollback_test.go`).
- Always within a few **milliseconds of `=== RUN`** for the subtest —
  specifically during the `setupAgents` → `createUpdateMarker` → `cleanup()`
  burst, *not* during any long-running activity.
- That burst is a tight sequence of Windows filesystem syscalls:
  `os.MkdirAll` ×4 per fake install (×2 installs), `os.WriteFile` ×2 each,
  `os.Symlink`, a JSON marker marshal+write+read, then `cleanup()` does
  `os.Open` + `Readdirnames` + recursive `os.RemoveAll`.
- On Windows every one of those goes through an **IO completion port (IOCP)**.

## What we have ruled out / established

- **Not async preemption.** `GODEBUG=asyncpreemptoff=1` does *not* suppress the
  crash. This points away from async preemption interrupting a syscall
  submission and toward a **synchronous** stack operation racing with the I/O —
  most likely `shrinkstack` during the GC mark phase freeing a goroutine stack
  whose memory then flows back to the heap while an in-flight IOCP completion
  still targets it.
- **`GOGC=1` makes it far more consistent.** Forcing a GC after effectively
  every allocation maximises `shrinkstack`/`scanstack` frequency and the rate
  at which freed memory is recycled, which is consistent with the
  shrinkstack-vs-IOCP-completion race hypothesis.
- **Environment-sensitive.** Reproduces reliably on the Azure `Standard_D8s_v5`
  Windows 11 runners but **not** on most local Windows machines. The trigger
  depends on IOCP completion timing relative to GC, which differs on the CI
  VMs (hypervisor I/O latency, Defender real-time scanning, cold FS cache, 8
  hyperthreads on contended host hardware are all candidates).

## Working hypothesis

A kernel-side IOCP completion writes into a buffer (or a goroutine stack
location) **after** the Go runtime has freed/recycled that memory during a GC
cycle. The write lands in a now-unrelated heap object or runtime metadata,
which the GC then detects on its next sweep (the "marked free object" /
"found pointer to free object" throws) or which corrupts a live structure
directly (the RWMutex state word, the zeroed `*ActionUpgrade` pointer). This
matches the shape of golang/go#77975.

## Diagnostic infrastructure built on this branch

The CI pipeline was reduced to two Windows 11 variants (see
`.buildkite/pipeline.yml`):

- **diagnostic run** (`unit-tests.ps1`): `GOGC=1`,
  `GODEBUG=clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1`,
  `GOEXPERIMENT=cgocheck2`, `GOTRACEBACK=crash`. Maximises GC pressure and
  sanity checks to make the crash consistent.
- **instrumented run** (`unit-tests-instrumented.ps1`):
  `GODEBUG=clobberfree=1,gctrace=1,schedtrace=10000`, plus WER + procdump to
  capture a full memory dump.

Key lessons baked into those scripts (each was a real dead end first):

1. **gotestsum eats the diagnostics.** `gotestsum`/`test2json` treats every
   non-JSON stderr line as a package error, so `gctrace=1` produced thousands
   of spurious "errors", and `schedtrace` lines blew its 64 KB scanner. Fix:
   bypass `mage unitTest`/gotestsum and run `go test` directly; only fail the
   job on a real runtime crash marker, ignoring ordinary test failures.
2. **PowerShell turns native-command stderr into terminating errors.** With
   `$ErrorActionPreference = "Stop"`, the first `SCHED`/`gctrace` line written
   by `go test`/`go list` via `2>&1` aborts the script. Fix: relax EAP around
   each native `go` call, and clear `GODEBUG`/`GOTRACEBACK` before the
   artifact-prep `go` invocations.
3. **WER alone never fires for Go crashes.** Go installs an
   `UnhandledExceptionFilter` that prints its traceback and `exit()`s, so the
   exception is "handled" before WER's LocalDumps sees it. Registering procdump
   via `AeDebug` (postmortem) *also* misses it because AeDebug is second-chance
   only. Fix: run the test binary as a **child of procdump** via
   `go test -exec`, with `-e 1` (first-chance) to catch the exception before
   Go's UEF, and `-f Breakpoint` to filter to the fatal `runtime.crash()` INT 3
   rather than the many recoverable nil-deref AVs `fmt` triggers.
4. **The work-tree test binary is stripped.** `go test -work`'s leftover
   `*.test.exe` has no `runtime.pclntab`/DWARF, so dlv can't symbolicate it.
   Fix: on crash, rebuild a fresh symbol-rich binary from source with the same
   `-race -covermode=atomic -coverpkg=./...` flags and upload that.
5. **OIDC plugin was needed for uploads.** Restored `google_oidc_plugin` so
   `buildkite-agent artifact upload` can write dumps to GCS.

## Dump analysis workflow (Linux)

The dumps are Windows minidumps; they can be analysed on Linux:

- `dlv core <matching-binary> <dump> --check-go-version=false` — threads,
  registers, and (with a byte-matching binary) symbolicated backtraces.
- A small custom parser walks the minidump streams directly (Exception record,
  ThreadList CONTEXT RIP/RSP, ModuleList, Memory64List) for raw stack/heap
  inspection and pointer scans — useful for confirming, e.g., that **no pointer
  to the corrupted slot exists anywhere in the dump** (which argued the mark
  bitmap itself was corrupted, not a missed reference).
- Binaries/dumps are fetched from Buildkite via `bk artifacts list` →
  resolve the GCS redirect → `gcloud storage cp`.

Confirmed from a dump: the freed slot still held the `clobberfree=1`
`0xdeadbeef` pattern while the GC had it marked, and the mark bitmap was
internally inconsistent with the per-slot dump — i.e. the corruption is of
runtime metadata, not application use-after-free.

## Minimal-reproduction attempt

`internal/pkg/iocprepro` is a standalone (stdlib + testify only) test that
mimics the `TestCleanup` filesystem burst, so it could be lifted into an
upstream issue without dragging in elastic-agent infrastructure.

- **v1 (create-only burst):** passed cleanly in CI — insufficient.
- **v2 (current):** adds the read+delete burst (`Readdirnames` +
  `os.RemoveAll`) that the real `cleanup()` does, plus background heap-churn
  goroutines (the real `upgrade.test.exe` has a large live heap so `GOGC=1`
  collects constantly; a tiny binary does not) and background filesystem-churn
  goroutines to keep the IOCP busy. Result pending CI.

If v2 still does not reproduce, the next suspect is the **import surface
itself**: the bug may need the specific heap layout/object population that the
upgrade package's transitive dependencies create. A blank-import shim pulling
in those deps would be the next experiment. Also worth trying: dialing the
background churn *down* (the bug may be suppressed by CPU over-subscription).

## Open questions / next steps

1. Does `iocprepro` v2 crash on the Azure runners? (pending)
2. With a byte-matching rebuilt binary, symbolicate the *fatal* crash thread
   (the `runtime.throw` caller, e.g. `gcBgMarkWorker`) to pin the exact
   operation whose buffer was corrupted.
3. Confirm whether `GODEBUG=gcshrinkstackoff=1` suppresses the crash — if so,
   that is strong, specific evidence for the shrinkstack-vs-IOCP race to attach
   to the upstream issue.
4. Optional: a full Process Monitor (procmon) trace during a run to see what
   else (Defender, indexer) touches the test files mid-syscall.

## Key files on this branch

- `.buildkite/pipeline.yml` — reduced 2-variant Windows 11 diagnostic pipeline.
- `.buildkite/scripts/steps/unit-tests.ps1` — diagnostic run.
- `.buildkite/scripts/steps/unit-tests-instrumented.ps1` — WER + procdump +
  binary rebuild.
- `internal/pkg/iocprepro/` — standalone minimal-reproduction attempt.
