# Windows unit-test GC corruption — investigation notes

Tracking a Windows-only fatal crash in the Elastic Agent unit test suite.
Working branch: `worktree-test+diagnose-windows-gc-panic`.
Upstream cause: <https://github.com/golang/go/issues/77975> — *"runtime:
Windows crash with Go 1.26.0, 1.26.1"*.

> **Status:** Reproduced reliably in CI. The crash is **GC-metadata corruption,
> Windows-only, and Go-version-independent** across the whole range the code can
> build. Confirmed NOT caused by: Green Tea GC, async preemption, stack
> shrinking, or a stray kernel IOCP write (see Falsified). It is also **not a
> Go 1.26 regression** — see the version bisect below. Current leading shape:
> a long-standing bug in the **Windows-specific Go runtime** (present 1.25.7 →
> 1.26.3) that needs the contended CI-host timing to fire, or a Windows
> kernel/driver interaction on the Azure image. Not reproduced on a quiet
> standalone VM or locally.
>
> **Version bisect result (builds 40583 @1.26.3 vs 40590 @1.25.10):**
> - 1.26.3: crashes ~6/10 jobs.
> - 1.25.10: crashes (≥3/10 jobs), same corruption (`unexpected signal during
>   runtime execution`), Go 1.25.10 confirmed in the logs, no build failures.
> - **Cannot test below 1.25.7:** a dependency (`sigs.k8s.io/e2e-framework
>   @v0.7.0`) declares `go >= 1.25.7`, so Go 1.24 refuses to build the module
>   graph. The bisect floor is therefore 1.25.7; the crash is present across the
>   entire buildable range. So it predates Green Tea-as-default and is not a
>   1.26 regression.

> **Correction (important):** Earlier revisions of this document hypothesized a
> stray *kernel IOCP write into freed memory* (overlapped-I/O buffer lifetime
> bug). That framing is now believed wrong on two counts: (1) the upstream
> issue go#77975 is about the **Green Tea GC**, not IOCP, and its crash is a
> corrupted return address consistent with **stack scanning / copystack**; and
> (2) regular `os.Open`/`ReadFile`/`WriteFile` on Windows do **not** use
> overlapped I/O unless the caller passes `O_FILE_FLAG_OVERLAPPED` (verified in
> the Go 1.26.3 source, `os/file_windows.go:162`) — so the agent's file ops are
> synchronous and there is no completion-after-return window to exploit. The
> filesystem-heavy tests matter only because they generate the allocation churn
> and goroutine stack growth that exercise the GC marker, not because of async
> I/O. The IOCP sections below are kept for history but should be read in that
> light.

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
| 40520 | `fatal error: s.allocCount != s.nelems && freeIndex == s.nelems` | `mspan` allocator bookkeeping | thrown from `mcache.nextFree` |

Earlier observed (pre-procdump) secondary effect: a recoverable
`EXCEPTION_ACCESS_VIOLATION` reading a nil receiver in
`(*fleetapi.ActionUpgrade).String()` while `fmt` formatted a panic message —
i.e. a *pointer field that had been zeroed by the corruption*, surfacing during
the test framework's panic-recovery path.

Across all of these:

- The corruption hits **different size classes** (16/64/112/208 B), **GC
  metadata** (mark bitmap and `mspan` allocator bookkeeping), and **live
  structures** (mutex state, pointer fields).
- That breadth is the signature of a **stray single-word write landing in
  whatever memory happens to be recycled at that address**, not a type-specific
  bug.

## Fully symbolicated crash (build 40520, `upgrade.test.exe`)

Once the binary-rebuild step produced a symbol-rich binary (see fix #4 below),
the throwing goroutine resolved cleanly:

```
goroutine 133 [running]:
runtime.throw("s.allocCount != s.nelems && freeIndex == s.nelems")  panic.go:1229
runtime.(*mcache).nextFree(...)            malloc.go:1004   ← throw site
runtime.mallocgcSmallNoscan(...)           malloc.go:1397
runtime.mallocgc(0x160, ...)               malloc.go:1143
runtime.growslice(...)                     slice.go:265
  strings.(*Builder).WriteString           builder.go:114
  filepath.Join                            path.go:131
upgrade.checkFilesAfterRollback(...)       rollback_test.go:707
upgrade.TestRollback.func1(...)            rollback_test.go:314
upgrade.TestRollback.func4(...)            rollback_test.go:389
```

This is the strongest evidence to date:

- The victim goroutine is doing nothing unsafe — `rollback_test.go:707` is
  `os.Readlink` followed by `filepath.Join(topDir, oldAgentHome)`, i.e. a
  filesystem read and a string build.
- The throw fires inside the **allocator** (`mcache.nextFree`): it pulled a
  span whose `freeIndex == s.nelems` (looks full) yet `s.allocCount != s.nelems`
  (bookkeeping says not full). The `mspan` metadata is internally inconsistent.
- So the corruption is of **runtime allocator metadata**, detected during a
  routine string allocation — not application use-after-free.

## Where and when it fires

- During filesystem-heavy tests in `internal/pkg/agent/application/upgrade`
  (`rollback_test.go`) — observed in both **`TestCleanup`** and
  **`TestRollback`**. It is *not* one specific test; it is the whole package's
  filesystem-burst workload.
- Always within a few **milliseconds of `=== RUN`** for the subtest —
  during the `setupAgents` / `createUpdateMarker` / `cleanup()` /
  `checkFilesAfterRollback` filesystem bursts, *not* during any long-running
  activity.
- Those bursts are tight sequences of Windows filesystem syscalls:
  `os.MkdirAll`, `os.WriteFile`, `os.Symlink`, `os.Readlink`, `os.ReadFile`,
  `os.Open` + `Readdirnames` + recursive `os.RemoveAll`, plus JSON marker
  marshal/write/read.
- On Windows every one of those goes through an **IO completion port (IOCP)**.

## What we have ruled out / established

- **Not async preemption.** `GODEBUG=asyncpreemptoff=1` does *not* suppress the
  crash.
- **Not stack shrinking (build 40538).** A dedicated `gcshrinkstackoff=1`
  pipeline variant was run side by side with the plain diagnostic variant
  (10 parallel jobs each). Both failed at the **same rate (7/10)**, and the
  shrinkstackoff jobs still crashed with the same GC-metadata corruption
  (`checkmark found unmarked object`, `unexpected signal during runtime
  execution`). The `GODEBUG` line in the logs confirms the flag took effect.
  **This falsifies the shrinkstack/copystack-vs-IOCP hypothesis** — disabling
  stack shrinking changes nothing. (An earlier crash that happened to fault
  *inside* `copystack` was just where one instance was detected, not the
  cause.)
- **`GOGC=1` makes it far more consistent.** Forcing a GC after effectively
  every allocation maximises the rate at which freed heap memory is swept and
  recycled — which is what raises the odds that a stray write lands in memory
  that has since become live metadata or a live object and is therefore
  *detected*. This points at recycled **heap** memory, not stacks.
- **Environment-sensitive.** Reproduces reliably on the Azure `Standard_D8s_v5`
  Windows 11 runners but **not** on most local Windows machines. The trigger
  depends on IOCP completion timing relative to GC, which differs on the CI
  VMs (hypervisor I/O latency, Defender real-time scanning, cold FS cache, 8
  hyperthreads on contended host hardware are all candidates).

### Full crash-signature spread (build 40538, 19 failed jobs)

| Signature | Count | Structure |
|-----------|-------|-----------|
| `checkmark found unmarked object` | 10 | GC mark bitmap |
| `unexpected signal during runtime execution` | 8 | raw fault in runtime code |
| `marked free object` / `found pointer to free object` | 4 / 4 | GC mark bitmap |
| `sweep increased allocation count` | 1 | `mspan` bookkeeping |

All are GC/allocator-metadata corruption, on both the plain and the
shrinkstackoff variants.

## Working hypothesis: Green Tea GC marking bug (golang/go#77975)

The upstream issue go#77975 ("Windows crash with Go 1.26.0, 1.26.1") points at
the **Green Tea garbage collector**, which became the default-on collector in
Go 1.26 (confirmed in this toolchain: `go list -f '{{context.ToolTags}}'
runtime` includes `goexperiment.greenteagc`). The upstream crash is a corrupted
return address consistent with a bug in **stack scanning / copystack** during
GC marking.

Every signature we have observed is consistent with a GC *marking* bug rather
than an external write:

- `checkmark found unmarked object` — checkmark mode (`gccheckmark=1`) found a
  live object the main mark phase failed to mark. This is a direct marker
  correctness failure.
- `marked free object` / `found pointer to free object` — mark bitmap vs. span
  state inconsistency.
- `s.allocCount != s.nelems`, `sweep increased allocation count` — span
  bookkeeping inconsistencies downstream of bad marking.
- `unexpected signal during runtime execution` / corrupted return address — a
  scan/copystack mishap landing a bad pointer where execution later resumes.

Why the filesystem-heavy upgrade tests trigger it: they generate a tight burst
of allocation churn and goroutine stack growth (deep `filepath`/`os` call
chains) concurrently with `GOGC=1`'s near-continuous GC — exactly the workload
that exercises the marker and stack scanner hardest. The filesystem aspect is
incidental load, not the mechanism.

This explains every prior observation, including the ones that killed the
earlier hypotheses: async preemption and stack *shrinking* being irrelevant
(the bug is in marking / growth-driven copystack / scanning, not in shrink or
in any kernel race), `GOGC=1` amplifying (more marking cycles), heap-metadata
victims (the marker corrupts its own bitmap), and poor local reproducibility
(a timing-sensitive parallel-marking race).

**Decisive test (in flight):** the `nogreenteagc` pipeline variant runs the
identical diagnostic config with `GOEXPERIMENT=...,nogreenteagc`. If it stops
crashing while the plain diagnostic variant keeps crashing, the agent's crashes
are confirmed to be the Green Tea GC bug.

## Diagnostic infrastructure built on this branch

The CI pipeline was reduced to a few Windows 11 variants (see
`.buildkite/pipeline.yml`):

- **diagnostic run** (`unit-tests.ps1`): `GOGC=1`,
  `GODEBUG=clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1`,
  `GOEXPERIMENT=cgocheck2`, `GOTRACEBACK=crash`. Maximises GC pressure and
  sanity checks to make the crash consistent.
- **nogreenteagc run** (`unit-tests.ps1` with `EXTRA_GOEXPERIMENT=nogreenteagc`):
  identical to the diagnostic run but with Green Tea GC disabled — the decisive
  A/B test for go#77975. (Replaced the retired `gcshrinkstackoff=1` variant.)
- **instrumented run** (`unit-tests-instrumented.ps1`):
  `GODEBUG=clobberfree=1,gctrace=1,schedtrace=10000`, plus WER + procdump to
  capture a full memory dump.

The script supports `EXTRA_GODEBUG` and `EXTRA_GOEXPERIMENT` env vars so the
pipeline can spin up single-variable A/B variants without script changes.

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

## CI environment (probed on a VM built from the same image)

A throwaway Azure `Standard_D8s_v5` VM was provisioned from the *same* gallery
image the CI uses (`platform-ingest-elastic-agent-windows-11-pro`
`1.0.1779464011`, Windows 11 Pro build 26200, 8 vCPU) and driven via
`az vm run-command`. Findings:

- **Defender real-time protection is ON, but `C:\` and `D:\` are entirely
  excluded** from scanning (`Get-MpPreference.ExclusionPath = C:\, D:\`). So
  Defender's `WdFilter` minifilter is in the I/O path but does not scan the
  test files. This weakens the "AV scanning interferes mid-syscall" idea.
- Filesystem minifilters loaded are otherwise stock Win11: `bindflt`, `UCPD`,
  `WdFilter`, `applockerfltr`, `FileInfo`, `luafv`, `Wof`, etc. Nothing exotic.
- **The standalone VM does not reproduce the crash**: 12/12 full-suite
  iterations under the diagnostic config (Green Tea on, 1.26.3) crashed 0
  times (all `exited 1` were ordinary test failures, no crash markers). The CI
  *fleet* hits ~6/10. The delta is almost certainly host-level contention /
  scheduling on the shared CI hosts that a freshly provisioned, idle VM lacks.
- **Procmon is not a useful tool here.** It monitors file/registry/process
  syscalls, not in-process memory writes, so it cannot see the GC-metadata
  corruption. A short capture during the test build/run was ~2 GB in seconds
  (the compile phase dominates), and headless PML→CSV conversion under
  `run-command` (session 0, no interactive desktop) does not work. Given
  Defender already excludes the drive, there is little external I/O to find.

## Open questions / next steps

Both the Green Tea A/B and the Go version bisect are now **done** (results in
the status banner and Falsified list). The hunt has narrowed to: a Windows-only,
version-independent (1.25.7–1.26.3) GC-metadata corruption that needs contended
CI-host timing to fire. Remaining avenues:

1. **Pin down the corrupting concurrent actor.** The victim goroutine is always
   innocent (e.g. a `filepath.Join` allocation tripping over already-corrupt
   `mspan`/bitmap metadata, build 40520). What we still lack is the *other*
   goroutine/thread whose write corrupts that metadata. A dump can't show a
   past write; the practical approach is `GODEBUG` GC-debug modes or a runtime
   built with extra mheap write instrumentation.
2. **Concurrency dependence.** Try `GOMAXPROCS=1` (or low) in CI: if the crash
   vanishes it's a runtime concurrency race; if it persists it points harder at
   the host/hypervisor. Cheap one-flag CI variant.
3. **Make a quiet box reproduce.** The standalone VM is idle and does not
   reproduce; try running several `go test ./...` instances concurrently (mimic
   the contended CI host) — if that reproduces, we get a live `dlv` platform.
4. **Upstream report.** We have enough for a solid golang/go issue (or an
   addition to go#77975 noting it is *not* Green Tea and reproduces on 1.25):
   Windows-only, version-independent GC-metadata corruption under heavy parallel
   filesystem test load on Azure D8s_v5; symbolicated throw at `mcache.nextFree`
   with internally-inconsistent `mspan` bookkeeping; dumps + matching binaries
   available.
5. `iocprepro` minimal repro still does not reproduce (upgrade-scope, and the
   tiny standalone binary); a minimal repro likely needs full-suite-scale
   heap/goroutine pressure on a contended host.

### Falsified hypotheses

- **A Go 1.26 regression** (build 40590: Go 1.25.10 crashes too, same
  corruption; bisect floor is 1.25.7 due to a dependency's go directive).
  The crash is version-independent across the buildable range.
- **Green Tea GC** (`GOEXPERIMENT=nogreenteagc` does not suppress; build 40583,
  ~6/10 failures with the flag active, same corruption signatures). The
  upstream go#77975 only *suspected* Green Tea; our A/B refutes it for the
  agent's crash.
- **Async preemption** (`asyncpreemptoff=1` does not suppress).
- **Stack shrinking** (`gcshrinkstackoff=1` does not suppress; build 40538,
  equal 7/10 failure rate vs the plain variant). Note: copystack on stack
  *growth* is not disabled by that flag, so growth-driven copystack remains in
  scope under the Green Tea hypothesis.
- **Stray kernel IOCP write into freed memory** (the earlier "overlapped-I/O
  buffer lifetime" theory). The agent's Windows file I/O is synchronous
  (`os.Open`/`ReadFile`/`WriteFile` don't set `O_FILE_FLAG_OVERLAPPED`), so
  there is no async completion-after-return window; and go#77975 implicates the
  GC, not I/O.

## Key files on this branch

- `.buildkite/pipeline.yml` — reduced 2-variant Windows 11 diagnostic pipeline.
- `.buildkite/scripts/steps/unit-tests.ps1` — diagnostic run.
- `.buildkite/scripts/steps/unit-tests-instrumented.ps1` — WER + procdump +
  binary rebuild.
- `internal/pkg/iocprepro/` — standalone minimal-reproduction attempt.
