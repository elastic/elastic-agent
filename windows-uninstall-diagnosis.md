# Windows uninstall — diagnosis of the Go 1.25 regression

## TL;DR

Go 1.25 rewrote `os.RemoveAll` to walk directories with `unlinkat`, which on
Windows uses `NtSetInformationFile(FileDispositionInformationEx)` with the
`FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK` flag. That flag asks the kernel to
refuse the delete if the file is currently mapped as a running image — which is
always the case for the agent binary deleting itself. The legacy
`syscall.DeleteFile` path Go 1.24 used does not perform this check.

`removeBlockingExe`'s job is to apply the NTFS "ADS rename trick" to detach the
running binary. Empirically — and this is the surprise — the rename alone is
sufficient to make legacy `DeleteFile` succeed on the file, but it is *not*
sufficient to make `unlinkat` succeed. To make `unlinkat` succeed we have to
actually put the file into delete-pending state, which requires
`NtSetInformationFile(FileDispositionInformation, DeleteFile=true)` to succeed
on a handle. That call only succeeds when issued on the *same* handle that did
the rename — re-opening the path between rename and dispose makes dispose fail
with `STATUS_CANNOT_DELETE`. The OLD `removeBlockingExe` on `main` does
re-open, which is why it cannot recover Go 1.25's `os.RemoveAll`. The minimal
fix is to keep one handle open across both calls.

## Background — why `os.RemoveAll` was replaced by a Go 1.24 reimplementation

When the project bumped to Go 1.25 ([e653b4f1d2](https://github.com/elastic/elastic-agent/commit/e653b4f1d2)), the stdlib switched the directory-walk implementation of `RemoveAll` from `removeall_noat.go` (path-based, calls `syscall.DeleteFile` per child) to `removeall_at.go` (directory-relative, calls `removefileat(dirfd, name)`).

`removefileat` on Windows is in `internal/syscall/windows/at_windows.go::Deleteat`. The crucial bit is:

```go
// $GOROOT/src/internal/syscall/windows/at_windows.go (Go 1.25.8)
const FileDispositionInformationEx = 64

err = NtSetInformationFile(
    h,
    &IO_STATUS_BLOCK{},
    unsafe.Pointer(&FILE_DISPOSITION_INFORMATION_EX{
        Flags: FILE_DISPOSITION_DELETE |
            FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK |   // <-- the regression
            FILE_DISPOSITION_POSIX_SEMANTICS |
            FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    }),
    uint32(unsafe.Sizeof(FILE_DISPOSITION_INFORMATION_EX{})),
    FileDispositionInformationEx,
)
```

Per the Microsoft docs, `FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK` tells the kernel to fail the delete with `STATUS_CANNOT_DELETE` if there is any image section on the file — i.e. if any process is currently executing the binary. Uninstall always runs from inside the running `elastic-agent.exe`, so every `os.RemoveAll(topPath)` started failing on the agent binary.

The `Deleteat` fallback path (`deleteatFallback`) only runs on `STATUS_INVALID_INFO_CLASS` / `STATUS_INVALID_PARAMETER` / `STATUS_NOT_SUPPORTED`. `STATUS_CANNOT_DELETE` is *not* in that set, so the fallback is never hit.

The pragmatic fix that landed on `main` was to keep the Go 1.24 path-based behaviour by inlining it as `removeAll` in [`internal/pkg/agent/install/uninstall.go`](internal/pkg/agent/install/uninstall.go). Go 1.24's path-based code calls `syscall.DeleteFile` per child:

```go
// $GOROOT/src/os/file_windows.go (Go 1.25.8 still has this for path-based Remove)
func Remove(name string) error {
    p, e := syscall.UTF16PtrFromString(fixLongPath(name))
    ...
    e = syscall.DeleteFile(p)              // <-- Win32 DeleteFileW, no image-section check
    ...
}
```

`syscall.DeleteFile` is the bare Win32 `DeleteFileW` — `NtCreateFile(DELETE | FILE_DELETE_ON_CLOSE)` followed by `NtClose`. It does not call `NtSetInformationFile` at all, which means it does not perform the new image-section check.

## What `removeBlockingExe` is supposed to do

When the directory walk fails on a running `.exe`, `RemovePath` calls `removeBlockingExe(err)` and then loops back. `removeBlockingExe`'s job is the NTFS "ADS rename trick": rename the running binary's primary unnamed data stream into an alternate data stream so the loader's image section becomes orphaned and the next iteration of the directory walk can delete the (now stream-empty) file.

## Empirical findings — what state the OLD pattern actually leaves the file in

I ran a diagnostic harness (`internal/pkg/agent/install/rootcause_diag_test.go`, removed before commit) that drives the OLD pattern step by step against `testblocking.exe` and reports what every observer sees. Sequence and observations:

```
baseline (file exists, exe running)
  Lstat: size=2160640
  ReadDir(parent): [testblocking.exe]
  open(DELETE) probe: ok

step: os.RemoveAll(destDir) (Go 1.25 unlinkat path)
  -> unlinkat ...: Access is denied.

step 1: openDeleteHandle               -> ok
step 2: renameHandle (OLD pattern)     -> ok      (effective ADS target = ":age", FileNameLength=8)
report after rename, before close:
  Lstat: size=0                                       <-- primary stream is gone
  ReadDir(parent): [testblocking.exe]                 <-- directory entry remains
  open(DELETE) probe: "is being used by another process"  (sharing violation: OUR h is open with share=0)

step 3: close handle (the OLD pattern's mistake)
report after close, before reopen:
  Lstat: size=0
  open(DELETE) probe: ok                              <-- handle released

step 4: reopen DELETE                  -> ok
step 5: dispose (class 4 on FRESH h)   -> Access is denied   <-- THE REGRESSION

report after full OLD pattern (rename succeeded, dispose failed):
  Lstat: size=0
  ReadDir(parent): [testblocking.exe]
  open(DELETE) probe: ok
```

Now compare what each downstream deleter sees on the file in this state (renamed → ADS, dispose failed):

```
windows.DeleteFile(path)        -> SUCCESS at 0ms      (Win32 / Go 1.24 path)
os.Remove(path)                 -> SUCCESS at 0ms      (calls DeleteFile)
os.RemoveAll(path)   on file    -> SUCCESS at 0ms      (falls through to Remove)
os.RemoveAll(parentDir)         -> never succeeds      (Go 1.25 unlinkat path)
```

And the same comparison after only the rename — *no dispose attempt at all*:

```
windows.DeleteFile(path)        -> SUCCESS at 0ms
os.RemoveAll(parentDir)         -> never succeeds
```

So:

1. **The rename alone is sufficient to make the legacy `DeleteFile` API succeed.** The dispose call in the OLD `removeBlockingExe` never contributes anything to the legacy path — it always fails with ACCESS DENIED, but the rename has already done all the work the legacy path needs.

2. **The rename alone is *not* sufficient to make Go 1.25's `unlinkat` succeed.** The image section is still bound to the FCB, and `FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK` triggers regardless.

This is why the OLD `removeBlockingExe` works with the Go 1.24 reimplementation: the loop runs at least twice, the first iteration's rename leaves the file in a state where the second iteration's `os.Remove` → `DeleteFile` succeeds. The dispose call on the re-opened handle has been silently failing on every iteration this whole time — nobody noticed because `DeleteFile` doesn't need the file to be in delete-pending state, it just needs the image-section ambiguity removed (which the rename does).

```
iter 1: go124RemoveAll(destDir) -> "remove .../testblocking.exe: Access is denied."
iter 1: oldRemoveBlockingExe   -> dispose: Access is denied.    <-- always fails
iter 2: go124RemoveAll(destDir) -> nil                          <-- DeleteFile path succeeds
```

## Why dispose succeeds on the rename handle but fails after re-open

`FileDispositionInformation` (class 4) is documented to return `STATUS_CANNOT_DELETE` when the file has an image section — same condition as the new `Ex` variant, just without the explicit force-flag knob. Empirically:

| Handle used for dispose                          | Result        |
|--------------------------------------------------|---------------|
| Same handle that just did the ADS rename         | success       |
| Freshly opened handle to the same path           | ACCESS DENIED |

I do not have NT internals to cite, but the consistent pattern is that the rename leaves rename-pending state on the issuing FILE_OBJECT, and the kernel's image-section check on the same FILE_OBJECT walks "the stream this handle points at" (now the renamed `:age` ADS, no image section) and passes. A handle freshly opened on the path resolves to a FILE_OBJECT pointing at the original primary stream's identity, where the image-section check sees the loader's mapping and rejects the delete. Closing the handle "commits" the rename and discards the per-handle state that made the dispose succeed.

What matters operationally: keeping the same handle open across both `NtSetInformationFile` calls is the *only* way to make the dispose succeed against a running executable. PR #13606's other changes (share-mode flags, fixed rename buffer, direct syscall) are cleanup — they don't change whether dispose succeeds.

## Why the FIX has to use dispose at all (not just rename)

Could we replace `removeBlockingExe` with just the rename and rely on the next iteration of `os.RemoveAll` to finish the job? **No** — and that's the whole reason we can't just delete the workaround:

- With Go 1.24's path-based `RemoveAll` (legacy), rename-only works because the per-child call is `DeleteFile`.
- With Go 1.25's `unlinkat`-based `RemoveAll`, rename-only does not work because the per-child call is `Deleteat` with `FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK`. The image section is still mapped to the FCB regardless of the stream rename, and the call refuses.

So when `RemovePath` is using native `os.RemoveAll`, `removeBlockingExe` has to actually transition the file into delete-pending state itself. That requires the dispose call to succeed, which requires the same-handle pattern.

Once dispose succeeds, the file is in delete-pending state. The handle is then closed. The next iteration of `os.RemoveAll` walks the directory: `unlinkat` on a delete-pending file returns success (or "already gone"), the directory becomes empty, and the parent comes down with it.

## Verification matrix

Pairwise tests on Windows 11 + Go 1.25/1.26 (5/5 runs each):

| `RemovePath` body          | `removeBlockingExe` impl                | Outcome    |
|----------------------------|-----------------------------------------|------------|
| Go 1.24 reimpl `removeAll` | OLD (close + reopen)                    | **PASS** (current main) |
| native `os.RemoveAll`      | OLD (close + reopen)                    | **FAIL**   |
| native `os.RemoveAll`      | OLD + share modes                       | FAIL       |
| native `os.RemoveAll`      | OLD + correctly-sized rename buffer     | FAIL       |
| native `os.RemoveAll`      | OLD + keep handle open                  | **PASS**   |

The single load-bearing change in PR #13606 is the keep-handle-open change; the share-mode and rename-buffer changes are cleanup that does not change the outcome.

## Why the OLD code was harmless before Go 1.25

The OLD `removeBlockingExe`'s dispose has *always* been failing. Before the Go 1.25 bump, nobody noticed because the legacy `DeleteFile` path was tolerant of the rename-only state. The Go 1.25 `at`-based code path is strict — it explicitly asks for the image-section check and refuses to delete — so the latent dispose failure becomes load-bearing.

There is also a buffer bug in the OLD `renameHandle` that has been silently latent for the same reason: it sets `FileNameLength = unsafe.Sizeof(*uint16) = 8`, copies 8 bytes via `RtlCopyMemory`, and ends up renaming the primary stream to `:age` (whatever happens to be in 4 UTF-16 code units of stack near `&wRename[0]`). The rename succeeds because `:age` is a valid stream name and the legacy `DeleteFile` doesn't care what the stream is named — it only cares that the unnamed primary stream is gone. PR #13606's correct rename buffer is a hygiene fix; it is not load-bearing for the regression.

## Regression unit test

[`TestRemoveBlockingExe_DeletesRunningExecutable`](internal/pkg/agent/install/uninstall_windows_test.go) targets only `removeBlockingExe`:

1. Spawn `testblocking.exe` so the kernel installs an image section.
2. Call `os.RemoveAll(destDir)` to obtain the canonical `*fs.PathError` carrying `ERROR_ACCESS_DENIED` on the running exe — same shape as production.
3. Assert the error is the kind `removeBlockingExe` is meant to handle (`isBlockingOnExe == true`).
4. Call `removeBlockingExe(rmErr)`.
5. Require `os.RemoveAll(destDir)` to succeed within 5 seconds — what `RemovePath`'s loop does on the next iteration.

On the OLD `removeBlockingExe` it fails 5/5 runs in ~5s (`removeBlockingExe returned: failed to dispose handle ... Access is denied.`). With the minimal keep-handle-open change applied it passes 5/5 runs in ~0.14s.

## Procmon traces — kernel-level confirmation

Two traces were captured during failing fleet integration tests and parsed with the [`procmon-parser`](https://pypi.org/project/procmon-parser/) Python package.

### Trace 1: `build_diagnostics_procmon-fleet_sudo.pml`

This trace covers the build/compile phase (16:55–16:57, 2026-04-22, ~8.6M events) and does **not** contain the actual elastic-agent uninstall, but it happens to capture the Microsoft Edge updater (`MicrosoftEdge_X64_147.0.3912.72.exe`) performing the same self-delete-of-running-exe pattern. It hits `STATUS_CANNOT_DELETE` on `SetDispositionInformationFile` 263 times (and never recovers — Edge would need a reboot). Useful as independent corroboration of the kernel mechanism, not as primary evidence; superseded by trace 2.

### Trace 2: `build_diagnostics_procmon-fleet_sudo-1.pml` — the actual uninstall

Pid 1808 is `"C:\Program Files\Elastic\Agent\elastic-agent.exe" uninstall --force`. Its main thread (tid 4040) walks the install directory with `Deleteat`, hits `elastic-agent.exe`, calls `removeBlockingExe`, fails, and loops for 59.38 s before timing out. Every step is visible at NT-syscall granularity.

#### First iteration — Go 1.25's `Deleteat` fails on the running exe

```
[741082] CreateFile                     result=0    path=…\elastic-agent.exe
         Desired Access: Read Attributes, Delete
         ShareMode:      Read, Write, Delete
         Disposition:    Open
         OpenResult:     Opened
[741083] SetDispositionInformationEx    result=3221225761 (STATUS_CANNOT_DELETE)  path=…\elastic-agent.exe
[741084] CloseFile
[741085] IRP_MJ_CLOSE
```

This is `Deleteat` from Go 1.25's `removeall_at.go` calling `NtSetInformationFile(FileDispositionInformationEx, FILE_DISPOSITION_DELETE | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK | …)`. The kernel's image-section check fires and returns `STATUS_CANNOT_DELETE` (NTSTATUS `0xC0000121`). Win32 maps this to `ERROR_ACCESS_DENIED`, which is what our `RemovePath` loop catches and routes to `removeBlockingExe`.

#### `removeBlockingExe` — the OLD close+reopen pattern, captured live

```
[741645] CreateFile                     result=0    path=…\elastic-agent.exe
         Desired Access: Read Attributes, Delete, Synchronize
         ShareMode:      None                                    ← the OLD openDeleteHandle (share=0)
         Disposition:    Open
         OpenResult:     Opened
[741646] SetRenameInformationFile       result=0    path=…\elastic-agent.exe       ← rename succeeds
[741647] CloseFile                                  path=…\elastic-agent.exe:age   ← !! kernel logs the new stream
[741648] IRP_MJ_CLOSE                               path=…\elastic-agent.exe       ← close h1 (the bug)
[741649] CreateFile                     result=0    path=…\elastic-agent.exe       ← reopen as h2
         Desired Access: Read Attributes, Delete, Synchronize
         ShareMode:      None
         Disposition:    Open
         OpenResult:     Opened
[741650] SetDispositionInformationFile  result=3221225761 (STATUS_CANNOT_DELETE)  path=…\elastic-agent.exe
         Delete: True
[741651] CloseFile                      result=0    path=…\elastic-agent.exe       ← close h2; file still there
[741652] IRP_MJ_CLOSE
```

Direct empirical confirmation of every claim in the diagnosis above:

1. **The OLD `openDeleteHandle` opens with ShareMode `None`** (= 0). Visible in events 741645 and 741649.
2. **The rename succeeds.** Event 741646: `result=0`.
3. **The rename target is `:age`** — the kernel's `CloseFile` event (741647) reports the path as `…\elastic-agent.exe:age`, confirming that the OLD code's buggy 4-char `RtlCopyMemory` ends up writing precisely those four UTF-16 code units into the rename buffer.
4. **The OLD pattern closes the handle between rename and dispose** (events 741647–741648).
5. **The OLD pattern reopens the same path** (event 741649).
6. **`SetDispositionInformationFile` (class 4 / `FileDispositionInformation`, `Delete:True`) on the freshly-opened handle returns `STATUS_CANNOT_DELETE`** — the legacy class-4 dispose call DOES perform an image-section check, contradicting the original PR #13606 commit message which claimed it didn't. Event 741650.
7. **The handle is closed without the file actually being deleted.** Events 741651–741652.

#### Subsequent loop iterations — stuck forever

`removeBlockingExe` ignores the dispose error and returns. `RemovePath` sleeps 500 ms and retries. Each subsequent iteration shows:

```
SetDispositionInformationEx     result=STATUS_CANNOT_DELETE       on …\elastic-agent.exe
SetDispositionInformationEx     result=STATUS_DIRECTORY_NOT_EMPTY on …\elastic-agent-9.4.0-SNAPSHOT-543643
SetDispositionInformationEx     result=STATUS_DIRECTORY_NOT_EMPTY on …\Agent\data
SetDispositionInformationEx     result=STATUS_DIRECTORY_NOT_EMPTY on …\Agent
SetRenameInformationFile        result=STATUS_OBJECT_NAME_COLLISION  on …\elastic-agent.exe
```

`STATUS_OBJECT_NAME_COLLISION` (`0xC0000035`) is the kernel saying the rename target already exists — exactly because the first iteration's rename created `:age` and never undid it. This matches the unit test output verbatim:

```
removeBlockingExe failed: failed to dispose handle for "...": Access is denied.
removeBlockingExe failed: failed to rename handle for "...": Cannot create a file when that file already exists.
... (repeats)
```

#### Loop totals from the trace

Events on `…\elastic-agent.exe` from pid 1808 alone:

| Operation                          | Result                                  | Count |
|------------------------------------|-----------------------------------------|-------|
| `SetDispositionInformationEx`      | `STATUS_CANNOT_DELETE` (3221225761)     | 119   |
| `SetDispositionInformationFile`    | `STATUS_CANNOT_DELETE` (3221225761)     | 1     |
| `SetRenameInformationFile`         | success (rename to `:age`)              | 1     |
| `SetRenameInformationFile`         | `STATUS_OBJECT_NAME_COLLISION` (0xC0000035) | 118   |

Spanning 16:59:15.901612 → 17:00:15.281980 = **59.38 s**, which matches `RemovePath`'s `arbitraryTimeout = 60 * time.Second`. The first dispose succeeded the rename; from then on, every `removeBlockingExe` invocation failed at the rename step (because `:age` already existed), so the dispose never even ran. Net result: the file was never put into delete-pending state, `os.RemoveAll` never converged, and the uninstall failed.

### Trace 3: `fix_trace2.pml` — the FIX captured at the kernel level

A third trace was captured running a procmon-friendly diagnostic test against `testblocking.exe` (a small process whose only purpose is to block forever so the loader installs an image section). The test bypasses the production `os.RemoveAll` precondition (procmon's minifilter perturbs share state and can turn `ERROR_ACCESS_DENIED` into `ERROR_SHARING_VIOLATION`); it constructs the `*fs.PathError` directly and calls `removeBlockingExe`.

```
[667730] SetRenameInformationFile        result=0                 pid=23052 tid=6320
         path: ...\testblocking.exe                                                  ← rename succeeds

[667731] SetDispositionInformationFile   result=0                 pid=23052 tid=6320
         path: ...\testblocking.exe:age                                              ← same h1 — dispose succeeds
         details: Delete: True
```

Two events. No CloseFile/CreateFile between them — h1 is held across both calls — and the dispose returns `0`.

### Side-by-side comparison — failing trace vs. fixed trace

| Step                              | Failing trace (`-1.pml`)                                | Fixed trace (`fix_trace2.pml`)                  |
|-----------------------------------|---------------------------------------------------------|-------------------------------------------------|
| Open                              | CreateFile DELETE Synchronize, ShareMode None → Opened  | (same)                                          |
| Rename                            | `SetRenameInformationFile` → 0                          | `SetRenameInformationFile` → 0                  |
| Path reported on next event       | `…\elastic-agent.exe:age`                               | `…\testblocking.exe:age`                        |
| Between rename and dispose        | **CloseFile + IRP_MJ_CLOSE + CreateFile**               | (none — same handle held)                       |
| Dispose                           | `SetDispositionInformationFile{Delete:True}` → `STATUS_CANNOT_DELETE` (3221225761) | `SetDispositionInformationFile{Delete:True}` → `0` |
| Path the kernel reports for dispose | `…\elastic-agent.exe`                                 | `…\testblocking.exe:age`                        |

The decisive empirical observation is in the bottom row: **the path the kernel labels the dispose event with is different in the two cases**. After the rename, h1's FILE_OBJECT identity is `…:age`. A freshly opened handle to the same path resolves to a FILE_OBJECT identified by the unnamed primary stream. `SetDispositionInformationFile`'s image-section check inspects state associated with the FILE_OBJECT it is invoked on; on h1 that state is the renamed `:age` stream (no image section), on a fresh handle it is the unnamed stream (still bound to the loader's image section).

This is why keeping the same handle works. It is not a quirk of NT's per-handle caching of rename-pending state — it is straightforward: the rename moves the FILE_OBJECT to point at a different stream, and the dispose check is per-FILE_OBJECT.

### What is now conclusively proven

- Go 1.25's `Deleteat` is what fails first, with `STATUS_CANNOT_DELETE`, on `SetDispositionInformationEx`.
- The OLD `openDeleteHandle` opens with ShareMode 0.
- The OLD `renameHandle` renames to `:age` (visible in the kernel-reported post-rename path).
- The OLD pattern closes h1 and reopens h2 between rename and dispose (two CreateFile events bracketing the rename's CloseFile).
- `SetDispositionInformationFile` (class 4) **does** perform the image-section check; it returns `STATUS_CANNOT_DELETE` on a freshly opened handle to a running image, contradicting the original PR #13606 commit message that claimed it was exempt.
- `SetDispositionInformationFile` on the **same** handle that just did the rename succeeds with result 0 — the kernel labels that handle's identity as the renamed `:age` stream and the image-section check inspects state per-FILE_OBJECT, not per-FCB.
- The OLD pattern's loop runs to its 60 s timeout and accomplishes nothing past the first rename, while the fixed pattern completes in milliseconds.
