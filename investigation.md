# Windows unit-test GC corruption — investigation notes

Tracking a Windows-only fatal crash in the Elastic Agent unit test suite.
Working branch: `worktree-test+diagnose-windows-gc-panic`.
Originally suspected upstream: <https://github.com/golang/go/issues/77975>
(*"runtime: Windows crash with Go 1.26.0, 1.26.1"*) — but that issue blames the
Green Tea GC, which we have **falsified** for this crash (see below).

> **Status:** Reproduced reliably in CI as **GC mark-metadata corruption**,
> **`windows/amd64`-only**, and **Go-version-independent** across the buildable
> range (1.25.7 → 1.26.3). The crash surfaces as several different fatal runtime
> throws that all trace to one root: the GC's marking/stack-scan machinery
> operating on corrupt state.
>
> **Leading hypothesis (build 40691): the crash is `-race`-GATED.** With the
> race detector off, it does not reproduce; with it on, it reproduces readily.
> The prime suspect is the **race-detector (tsan) runtime on `windows/amd64`**.
> A dump re-read (below) **rules out tsan corrupting via shadow-memory
> adjacency** — the corrupt arena is nowhere near the tsan shadow reservation —
> so the favoured form is now **tsan as a *catalyst*** (its instrumentation /
> extra memory traffic / `racecall` scheduling exposing a latent Go-runtime
> GC/stack-scan race, or a Win11/Ice-Lake hardware-timing sensitivity) rather
> than tsan directly writing the corrupt word. Needs the contended Azure CI-host
> timing + Windows 11 (not 10) to fire; does not reproduce on a quiet VM/locally.
> The crash is **test-logic-independent**: it hits even `test.test.exe`
> (`dev-tools/mage/target/test`, a package with *zero* test functions — just a
> coverage-instrumented startup), exactly as it hits `upgrade.test.exe`. So the
> trigger is the `-race` + `-coverpkg=./...` runtime startup, not any test.
>
> **Falsified:** Green Tea GC, async preemption, stack shrinking, stray kernel
> IOCP write, CET/ASLR process mitigations, and "a Go 1.26 regression" — all
> ruled out with side-by-side CI A/Bs (details in *Falsified hypotheses*).

## The decisive experiment: `-race` gates the crash (build 40691)

Four cohorts, same commit, same Azure fleet, `parallelism: 10` (instrumented 5):

| Cohort | `-race` | mitigations | crashed |
|--------|---------|-------------|---------|
| control | **on** | default | 2 / 10 |
| no-race | **off** | default | **0 / 10** |
| no-mitigations (IFEO) | on | **verified off** | 4 / 10 |
| instrumented | on | default | 5 / 5 |

- **no-race: 0/10 jobs (0/50 runs).** Every `-race` cohort crashed.
- Statistics (this build's hit rate was low/variable, so calibrate): pooling the
  procdump-free `-race` cohorts (control+no-mitigations = 6/20 ≈ 30%/job),
  no-race 0/10 gives **p ≈ 0.03**; including instrumented (11/25 ≈ 44%/job),
  **p ≈ 0.003**. Control alone (20%/job) → p ≈ 0.11, not significant on its own.
- **Defensible claim:** the crash is `-race`-**gated or strongly catalyzed**.
  Not yet proven strictly *required* (no-race could crash at a lower rate that
  10 jobs wouldn't catch). **A confirmatory re-run** (more no-race jobs) would
  settle it.

Why this is the best lead we have:

- It is consistent with the architecture data: **`windows/arm64` has no race
  detector at all** (`internal/platform`: race is `windows/amd64`-only), so a
  `-race`-gated crash can never fire there — which is exactly what's observed.
- The remaining wrinkle: **Win10-amd64** *has* the race detector yet reportedly
  doesn't crash. So `-race` is likely **necessary but not sufficient** — the
  Win11 / Ice-Lake (Xeon 8370C) host timing also contributes.

## Symptom

On the Windows 11 CI runners the unit test suite intermittently dies with a
*fatal* Go runtime throw (not a recoverable test failure), taking down the whole
`go test` process. **The crash is not deterministic by message** — the same
underlying condition surfaces as several different fatal errors. That breadth is
the signature of corrupt GC/allocator metadata being *detected* at different
points, not a type-specific logic bug.

### Confirmed crash signatures (spread, build 40538, 19 failed jobs)

| Signature | Count | Structure |
|-----------|-------|-----------|
| `checkmark found unmarked object` | 10 | GC mark bitmap (mark correctness) |
| `unexpected signal during runtime execution` | 8 | raw fault in runtime code (stack scan/unwind) |
| `marked free object` / `found pointer to free object` | 4 / 4 | GC mark bitmap vs span state |
| `sweep increased allocation count` / `s.allocCount != s.nelems` | 1 | `mspan` bookkeeping |

Also seen earlier: `sync: Unlock of unlocked RWMutex` (a zeroed/clobbered state
word), and a recoverable AV reading a nil receiver in
`(*fleetapi.ActionUpgrade).String()` during `fmt`'s panic-format path (a pointer
field zeroed by the corruption). Across builds the corruption hits multiple size
classes (16/64/112/208/224 B) and both GC metadata and live structures.

## Sharpest evidence: crash inside GC stack scan → copystack → unwinder (build 40590, Go 1.25.10)

The cleanest stack we have. The GC background mark worker, scanning a parked
goroutine's stack, faulted in the unwinder:

```
[signal 0xc0000005 code=0x0 addr=0xe0 pc=0x1400767a5]   (nil-ish ptr +0xe0)
runtime.sigpanic()                              signal_windows.go:387
runtime.(*unwinder).next(...)                   traceback.go:458   ← faults here
runtime.copystack(0xc000107180, ...)            stack.go:975
runtime.shrinkstack(0xc000107180)               stack.go:1289
runtime.scanstack(0xc000107180, ...)            mgcmark.go:898
runtime.markroot.func1()                        mgcmark.go:248
runtime.gcDrain(...) / gcBgMarkWorker.func2()   mgc.go:1541
```

The goroutine being scanned is an ordinary parked `[chan receive (scan)]`. The
unwinder follows a frame/func pointer and dereferences `+0xe0` off a bad value.
Reproduced on **Go 1.25.10 with Green Tea disabled and `asyncpreemptoff=1`**, so
the stack-scan/copystack corruption is real but is neither Green-Tea- nor
async-preemption-specific. `shrinkstack` is where *this* instance manifests, not
the cause (disabling it doesn't help — see Falsified).

**Working shape of the bug:** a stray write corrupts a goroutine's *stack
contents* (a saved frame/return pointer) or the GC's mark metadata; the GC then
either faults unwinding that stack (this crash) or marks a bogus pointer read
from it (the `marked free object` / `checkmark` throws). One root —
corrupt-state-during-GC-marking — accounts for the whole signature spread. With
the `-race` gate now established, the corrupting actor is most likely in the
**tsan runtime or tsan-perturbed GC/stack handling**.

## Where and when it fires

- Filesystem-heavy tests in `internal/pkg/agent/application/upgrade`
  (`rollback_test.go`) — both **`TestCleanup`** and **`TestRollback`**. Not one
  test; the package's filesystem-burst workload.
- Within a few **milliseconds of `=== RUN`** for a subtest, during the
  `setupAgents` / `createUpdateMarker` / `cleanup()` / `checkFilesAfterRollback`
  bursts (`os.MkdirAll`, `WriteFile`, `Symlink`, `Readlink`, `ReadFile`,
  `Open`+`Readdirnames`+`RemoveAll`, JSON marker I/O).
- **The filesystem aspect is incidental load, not the mechanism.** It generates
  the allocation churn and goroutine stack growth that exercise the GC marker
  and stack scanner hardest; that is why this package trips it. The file I/O
  itself is **synchronous** (see Falsified: IOCP).

## Falsified hypotheses

- **Stray kernel IOCP write into freed memory** (the original framing). Regular
  `os.Open`/`ReadFile`/`WriteFile` on Windows do **not** use overlapped I/O
  unless the caller passes `FILE_FLAG_OVERLAPPED` (Go 1.26.3
  `os/file_windows.go`). The tests' file ops are **synchronous** — the kernel
  fills buffers before the syscall returns, so there is no
  completion-after-return window to corrupt freed memory. go#77975 also
  implicates the GC, not I/O.
- **A Go 1.26 regression / Green Tea GC.** Version bisect: build 40583 @1.26.3
  ~6/10 crashed; build 40590 @1.25.10 crashed too (≥3/10, same `unexpected
  signal` corruption, Go version confirmed in logs). `GOEXPERIMENT=nogreenteagc`
  did **not** suppress it. Bisect floor is 1.25.7 (dependency
  `sigs.k8s.io/e2e-framework@v0.7.0` declares `go >= 1.25.7`, so 1.24 won't
  build the graph). Version-independent across the buildable range ⇒ predates
  Green-Tea-as-default; not a 1.26 regression.
- **Async preemption** — `asyncpreemptoff=1` does not suppress.
- **Stack shrinking** — `gcshrinkstackoff=1` (build 40538) failed at the same
  7/10 rate as the plain variant, same signatures.
- **CET / ASLR process mitigations** — *conclusively* ruled out (build 40691):
  the no-mitigations cohort had CET (`UserShadowStack`) + ASLR (`HighEntropy`,
  `BottomUp`, `ForceRelocateImages`) **verifiably disabled** via per-image IFEO
  (`Get-ProcessMitigation` confirmed `OFF` on the test binaries) and still
  crashed 4/10 — ~same as the control's 2/10. See the mitigation detour below.

## The mitigation detour (and the reboot lesson) — builds 40686 / 40690 / 40691

Worth recording because it cost two builds and produced a reusable lesson.

- **Build 40686 looked like a breakthrough:** the cohorts running `unit-tests.ps1`
  with a top-of-script `Set-ProcessMitigation -System -Disable HighEntropy,
  BottomUp, UserShadowStack, ForceRelocateImages` crashed **0/20**, while the
  instrumented cohort (no such line) crashed **5/5** on the same build.
- **Build 40690 (bisect) refuted it:** splitting the disable into CET-only vs
  ASLR-only, *all* arms crashed. A per-process posture probe revealed why: a
  child launched after the `Set` still showed `BottomUp=ON` (and
  `UserShadowStack=OFF` was just the default — CET is off by default on this
  image). **The toggles were no-ops.**
- **The reboot lesson (Microsoft docs):** process mitigation policies (DEP,
  SEHOP, ASLR `BottomUp`/`ForceRelocateImages`, CET `UserShadowStack`) are
  `PROCESS_CREATION_MITIGATION_POLICY_*` flags applied at *process creation*.
  `Set-ProcessMitigation -System` writes the system default in
  `…\Session Manager\kernel\MitigationOptions`, which is read **at boot** — so it
  needs a **reboot**. The only no-reboot lever is **per-image IFEO**
  (`Set-ProcessMitigation -Name <exe>`), applied at the next launch of that
  image. (Sources: MS Learn *Customize exploit protection*, *Override Process
  Mitigation Options*, *Kernel-mode Hardware-enforced Stack Protection*.)
- **Build 40691 tested it properly:** per-image IFEO across all 162 test-binary
  names, self-verified with `Get-ProcessMitigation`. Mitigations were genuinely
  off and the crash persisted (4/10). Ruled out.
- **Conclusion:** build 40686's 0/20 was an **anomalously quiet build** (this is
  a timing-sensitive race with high build-to-build variance), not a mitigation
  effect. Always confirm an all-clean cohort against a same-build positive
  control before believing a suppressor.

## Diagnostic infrastructure on this branch

CI pipeline = variance-controlled cofactor A/B (`.buildkite/pipeline.yml`), all
Azure `Standard_D8s_v5`, four cohorts in **one** build (shared host conditions),
each differing from `control` by exactly one variable, `parallelism: 10`:

- **control** (`unit-tests.ps1`): `GOGC=1`,
  `GODEBUG=clobberfree=1,gccheckmark=1,invalidptr=1,gctrace=1,asyncpreemptoff=1`,
  `GOEXPERIMENT=cgocheck2`, `GOTRACEBACK=crash`, `-race`, `-coverpkg=./...`.
  Known-crashing positive control.
- **no-race** (`NO_RACE=1`): control minus `-race` — confirms the `-race` gate /
  negative control (the doc's #1 open item, now folded into every build).
- **no-cover** (`NO_COVER=1`): control minus the coverage flags — is the
  `-coverpkg=./...` instrumentation footprint (the ~243 KB checkmark root) a
  cofactor?
- **gogc-default** (`GOGC_DEFAULT=1`): control minus `GOGC=1` (default 100), but
  the sanity-check GODEBUGs are kept so a crash is still *detected* — is the
  GC-pressure amplification *required* or just a catalyst?

(Earlier builds also used **no-mitigations** (`DISABLE_MITIGATIONS_IFEO=1`,
CET+ASLR off per test-binary, self-verified) and the **instrumented**
(`unit-tests-instrumented.ps1`, WER + procdump dumps) cohorts.)

The script honours `NO_RACE`, `NO_COVER`, `GOGC_DEFAULT`,
`DISABLE_MITIGATIONS_IFEO`, `TEST_PKG`, `EXTRA_GODEBUG`, and `EXTRA_GOEXPERIMENT`
so single-variable A/Bs need no script edits. `GOGC=1` amplifies the crash (more
mark cycles → more chances to hit/detect the corruption), which is why the
diagnostic config crashes more readily than a plain run.

Operational lessons (each a real dead end first):

1. **gotestsum eats the diagnostics.** `test2json` treats non-JSON stderr as
   package errors, so `gctrace=1` produced thousands of spurious "errors" and
   `schedtrace` blew its 64 KB scanner. Fix: bypass `mage unitTest`/gotestsum,
   run `go test` directly, fail only on a real runtime crash marker.
2. **PowerShell turns native stderr into terminating errors** under
   `$ErrorActionPreference = "Stop"` (the first `gctrace`/`SCHED` line aborts the
   script). Fix: relax EAP around each native `go` call; clear `GODEBUG`/
   `GOTRACEBACK` before artifact-prep `go` invocations.
3. **WER alone never fires for Go crashes** — Go's `UnhandledExceptionFilter`
   prints its traceback and `exit()`s before WER's LocalDumps sees it; AeDebug is
   second-chance only and also misses it. Fix: run the test binary as a child of
   procdump via `go test -exec`, `-e 1` (first-chance) to beat Go's UEF,
   `-f Breakpoint` to filter to the fatal `runtime.crash()` INT 3.
4. **The work-tree test binary is stripped** (no `pclntab`/DWARF). Fix: on crash,
   rebuild a symbol-rich binary from source with the same
   `-race -covermode=atomic -coverpkg=./...` flags and upload that.
5. **OIDC plugin needed for uploads** (`google_oidc_plugin`) so
   `buildkite-agent artifact upload` can write dumps to GCS.

## Dump analysis

Dumps are Windows minidumps; analysable with `dlv core <matching-binary> <dump>
--check-go-version=false` (threads, registers, symbolicated backtraces with a
byte-matching binary) and a small custom minidump-stream parser for raw
stack/heap inspection and pointer scans.

Confirmed from dumps (build 40529 instrumented `upgrade.test.exe`, analysed
locally):

- The corruption victim is consistently a **16-byte size-class span low in the
  first heap arena** (`0xc000058000`–`0xc00005a000`). Slot 0 there is a live
  `string` header pointing at the **GODEBUG value string** — i.e. an early,
  long-lived allocation. The binary has **ASLR off** (`DllCharacteristics=0x8100`,
  no `DYNAMIC_BASE`), so the arena base is deterministic — which is why the
  checkmark victim address (`0xc000058b6x`) and the `mspan` address (`0x99b170`,
  16 B) recur identically across independent runs/builds.
- The freed slots still held the `clobberfree=1` `0xdeadbeef` pattern while the
  GC had the span marked, and the mark bitmap was internally inconsistent with
  the per-slot dump — the corruption is of **runtime metadata, not application
  use-after-free**. A prior parser pass found **no pointer to the corrupted slot
  anywhere in the dump**, arguing the bitmap itself was corrupted rather than a
  missed reference.

**Every dump we have is from a `-race` binary** (only the instrumented cohort
captures dumps, and it uses `-race`).

### tsan-lens re-read result (build 40691 `test.test.exe` dump, memory map)

Parsed the minidump's `MemoryInfoList` (full VirtualQuery map) and thread
contexts:

- **The corrupt arena is NOT adjacent to tsan shadow.** The corruption locus
  (`0xc00005ab80`, inside the first committed heap chunk
  `0xc000000000–0xc000400000`) is bracketed entirely by *other Go heap regions*
  (`MEM_PRIVATE` commit/reserve). The only large reservations in the whole
  address space are 2× ~258 MB (`0x05a00000`, `0x25a00000`) and one **4 GB at
  `0x7ff4fdfc0000`** (the race/tsan shadow) — all far from `0xc000000000`. So
  the simplest tsan story — *a shadow write that aliases into the Go heap
  because shadow abuts the arena* — **is not supported**; tsan would need a
  grossly wrong address computation, not mere adjacency.
- **No thread caught mid-`racecall`.** All 12 threads are parked in `ntdll`
  (Go stops the world before `crash()`), so the dump cannot catch the
  corrupting actor in the act; and the dump's exception record is just Go's own
  `crash()`/`asmstdcall` path (`addr=0x140017909`), not the original fault
  (that lives in the job's printed traceback).

**Conclusion:** the dump argues against tsan *directly* corrupting memory via
its shadow. Combined with the rock-solid `-race` gate, this favours
**tsan-as-catalyst** (see status banner). The remaining discriminators are A/Bs
(coverage-off, GOGC-default), not more dumps — captured in the cofactor build.

Confirmed earlier dump facts still hold (build 40529 `upgrade.test.exe`): the
corrupt 16 B span recurs at a deterministic low-arena address because the binary
has **ASLR off**, and freed slots still carried the `clobberfree` `0xdeadbeef`
pattern while the GC had them marked — runtime metadata corruption, not
application use-after-free.

## CI environment (probed on a VM from the same image)

A throwaway Azure `Standard_D8s_v5` from the same gallery image
(`platform-ingest-elastic-agent-windows-11-pro` `1.0.1779464011`, Win11 Pro
26200, 8 vCPU, Xeon 8370C / Ice Lake):

- Defender real-time protection is ON but `C:\` and `D:\` are **excluded**, so
  `WdFilter` is in the I/O path but doesn't scan the test files.
- Filesystem minifilters are otherwise stock Win11; nothing exotic.
- **The standalone VM does not reproduce** (12/12 full-suite iterations, 0
  crashes) while the CI *fleet* hits ~variable rates. The delta is host-level
  contention/scheduling on shared CI hosts that an idle VM lacks.
- Procmon is not useful here (it sees syscalls, not in-process memory writes;
  the corruption is invisible to it, and the drive is Defender-excluded anyway).

## Minimal reproduction

`internal/pkg/iocprepro` is a standalone (stdlib + testify) test mimicking the
`TestCleanup` burst, intended to be liftable into an upstream issue. It does
**not** reproduce — and it was built around the now-dead IOCP premise. Any future
minimal repro must (a) use **`-race`** (the gate), and (b) likely include the
full-suite-scale heap/goroutine/import surface, since `-race` + a tight FS burst
alone (iocprepro, run under `-race` in the suite) was insufficient.

## Open questions / next steps

1. **The cofactor A/B build (current pipeline) settles three at once**, all
   against a same-build positive control:
   - **control vs no-race** → confirms the `-race` gate with fresh stats
     (the prior p≈0.01–0.11 item).
   - **control vs no-cover** → is the `-coverpkg=./...` instrumentation a
     cofactor? (the corrupt checkmark root was the coverage globals.)
   - **control vs gogc-default** → is `GOGC=1` GC-pressure required, or just a
     catalyst? Reading: if gogc-default still crashes (even rarer), pressure is
     an amplifier not a prerequisite; if no-cover stops crashing, coverage is a
     real cofactor; no-race staying clean re-confirms the gate.
2. **tsan shadow-adjacency is ruled out** (dump re-read above); the open tsan
   question is now catalyst-vs-corruptor, which the A/Bs target rather than more
   dumps. Still worth: search upstream for `windows/amd64` race-detector +
   GC/stack-scan corruption reports.
3. **Concurrency dependence** — `GOMAXPROCS=1` (or low) CI variant: if the crash
   vanishes it's a runtime concurrency race; if it persists it points at the
   host/hypervisor. Cheap one-flag test (next build after the cofactor A/B).
4. **Make a quiet box reproduce** — run several `go test -race ./...` instances
   concurrently on the standalone VM to mimic contended-host timing; success
   gives a live `dlv` platform.
5. **Upstream report** — we have enough for a strong golang/go issue (or an
   addition to go#77975 noting it is *not* Green Tea and reproduces on 1.25):
   `windows/amd64`-only, version-independent GC-metadata corruption under heavy
   parallel filesystem test load, **gated on `-race`**, on Azure D8s_v5;
   symbolicated GC-stack-scan fault and `mcache.nextFree`/`mspan` inconsistency;
   dumps + matching binaries available.

## Key files on this branch

- `.buildkite/pipeline.yml` — Windows 11 diagnostic pipeline (control / no-race
  / no-mitigations-IFEO / instrumented).
- `.buildkite/scripts/steps/unit-tests.ps1` — diagnostic/control run; honours
  `NO_RACE`, `DISABLE_MITIGATIONS_IFEO`, `EXTRA_GODEBUG`, `EXTRA_GOEXPERIMENT`.
- `.buildkite/scripts/steps/unit-tests-instrumented.ps1` — WER + procdump +
  symbol-rich binary rebuild.
- `internal/pkg/iocprepro/` — standalone minimal-reproduction attempt (does not
  reproduce; built on the dead IOCP premise — needs a `-race`/tsan rework).
