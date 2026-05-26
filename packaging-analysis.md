# Elastic Agent Packaging — Overview

This document describes the packaging system's external behaviour: what the
mage targets do, how CI invokes them, the current state on `main`, and the
intended end state after this branch. Implementation details (internal function
call graphs, settings loading, manifest internals) are in
[packaging-internals.md](./packaging-internals.md).

---

## 1. Concepts

**Core packaging** — produces archives that contain the binaries built in this
repository (`elastic-agent`, `elastic-otel-collector`, `osquery-extension`)
together with conditionally bundled osquery data files (certs, lenses,
`osqueryd` binary on Linux/Darwin/AIX, `osquery.app` on Darwin). No beats or
other data-collection integrations. Used as an input to full packaging and
published independently as the binary-DRA artifact set.

**Full packaging** — produces the complete agent: core binaries plus beats,
osquery, python wheels, and other external components. External components
are fetched either from a DRA manifest or from the artifacts API.

**DRA (Daily Release Artifacts)** — Elastic's internal build-and-promote
pipeline. Two workflows: `snapshot` (main branch) and `staging` (release
branches). Each DRA run publishes a *manifest*.

**Manifest** — a JSON document listing every package a DRA run produced,
with URLs, SHA512 checksums, and per-project commit hashes. The
`elastic-agent-core` project entry records the exact commit the core
binaries were compiled at.

**`.package-version`** — a JSON sidecar file at the repo root. Updated
automatically and committed. Contains the branch's current snapshot manifest
URL and version. Read when `USE_PACKAGE_VERSION=true`, which is now the
default.

---

## 2. Mage targets

### 2.1 `mage packageAgentCore`

Cross-compiles and packages `elastic-agent`, `elastic-otel-collector`, and
`osquery-extension` for every selected platform. Also bundles platform-specific
osquery data from `build/data/install/`: certs (all platforms), lenses and
`osqueryd` (Linux/Darwin/AIX), `osquery.app` (Darwin). Produces per-platform
archives in `build/distributions/`. Does **not** include beats or other
data-collection integrations.

The commit embedded in every binary is always git HEAD. The package directory
layout also uses git HEAD as the commit identifier. This target is never
appropriate to call when a pre-built core binary (with a different commit)
has already been downloaded.

Key env vars:

| Env | Default | Effect |
|---|---|---|
| `SNAPSHOT` | `""` | Adds `-SNAPSHOT` suffix and sets the snapshot build flag |
| `PLATFORMS` | host platform (after this branch; all defaults before) | Platforms to build for (see §4) |
| `PACKAGES` | host type (after this branch; `tar.gz` before) | Archive types to produce |
| `FIPS` | `false` | FIPS build tag + `-fips` suffix |
| `WINDOWS_NPCAP` | `false` | Bundle npcap on windows/amd64 |
| `USE_PACKAGE_VERSION` | `false` (build-agent-core.sh sets this explicitly) | Read `.package-version`; must NOT be set for binary-DRA builds |

### 2.2 `mage package` — full packaging (on `main`)

Produces the complete agent. On `main`, this target **always compiles core
locally** via `PackageAgentCore`. The manifest (if any) is used only for:
- Determining version and snapshot flag.
- Downloading external components (beats, osquery, etc.).

The commit stamped into package metadata is always **git HEAD**, regardless
of whether a manifest is set.

Key env vars (in addition to those above):

| Env | Default | Effect |
|---|---|---|
| `MANIFEST_URL` | `""` | Manifest URL for version/snapshot/external components |
| `USE_PACKAGE_VERSION` | `false` (default on `main`; `true` after this branch) | Read `.package-version` to set `MANIFEST_URL`, version, snapshot |
| `AGENT_DROP_PATH` | `""` | Directory where external archives are staged; set from `.package-version` when `USE_PACKAGE_VERSION=true` |
| `EXTERNAL` | `false` | Download external components from the artifacts API instead of the manifest |
| `KEEP_ARCHIVE` | `false` | Keep temporary archives after packaging |
| `DOCKER_VARIANTS` | `""` | Docker variant names (comma-separated) |
| `VERSION_QUALIFIER` | `""` | Appended to version string (e.g. `rc1`) |

### 2.3 `mage packageUsingDRA` — DRA-manifest full packaging (on `main`, removed after this branch)

Produces the complete agent, consuming a pre-published core from a DRA
manifest. When `MANIFEST_URL` is set, this target:
- Downloads elastic-agent-core archives from the manifest.
- Uses the manifest's `elastic-agent-core.commit_hash` as the packaging
  commit identifier (not git HEAD).
- Uses `dependenciesVersion` from the manifest for external component
  filenames.

When `MANIFEST_URL` is **not** set, `WithManifestInfo` is a no-op and the
target falls back to reading core from `build/distributions/` (previously
built by `packageAgentCore`). This is the regime `package.sh` exploits
(see §3.2).

---

## 3. CI usage (on `main`)

### 3.1 Full packaging — `package.sh`

Triggered by `pipeline.elastic-agent-package.yml` (main branch CI and DRA).

```
mage clean
if MANIFEST_URL not set:
    export SNAPSHOT=true
    export USE_PACKAGE_VERSION=true
    mage packageAgentCore               # build core from this checkout
    export MANIFEST_URL=$(jq -r .manifest_url .package-version)
    _UNSET_MANIFEST_URL=true
fi
export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p $AGENT_DROP_PATH
mage downloadManifest                   # fetch external components
if _UNSET_MANIFEST_URL:
    unset MANIFEST_URL
mage packageUsingDRA [helm:package] [ironbank] fixDRADockerArtifacts
```

**The `_UNSET_MANIFEST_URL` dance:** `MANIFEST_URL` is set to download
external components, then unset before calling `packageUsingDRA`. Because
`packageUsingDRA` calls `WithManifestInfo` internally, unsetting first makes
it a no-op — so the target reads core from `build/distributions/` (the
locally-built one) and derives the commit from git HEAD, matching the
behaviour of `mage package`. The script exists because neither `package`
nor `packageUsingDRA` alone supports "build core locally, fetch components
via manifest" in a single invocation.

**When `MANIFEST_URL` is pre-set by the pipeline** (real DRA full-package
run): `package.sh` skips `packageAgentCore` and the unset dance entirely.
`packageUsingDRA` then downloads core from the manifest and stamps the
manifest's core commit. This is the path that produces DRA-published full
packages.

### 3.2 Integration test packaging — `integration-package.sh`

Triggered by `integration.pipeline.yml`.

```
export SNAPSHOT="true"
export EXTERNAL="true"
export USE_PACKAGE_VERSION="true"
export WINDOWS_NPCAP="true"
mage package
```

Uses `mage package` (always local core). `EXTERNAL=true` causes
`collectPackageDependencies` to fetch external components from the
artifacts API rather than via a manifest. `USE_PACKAGE_VERSION=true` reads
`.package-version` to get the manifest URL and branch version (used for the
artifacts API lookup). `SNAPSHOT=true` is redundant when
`USE_PACKAGE_VERSION=true` reads a snapshot `.package-version`, but set
explicitly for safety.

### 3.3 Binary DRA — `build-agent-core.sh`

Triggered by `pipeline.elastic-agent-binary-dra.yml`.

```
SNAPSHOT=$SNAPSHOT WINDOWS_NPCAP="true" mage packageAgentCore
```

`SNAPSHOT` and `BEAT_VERSION` are set by the pipeline from DRA workflow
parameters (`DRA_WORKFLOW`, `BEAT_VERSION`). `USE_PACKAGE_VERSION` is
intentionally **not** set — this build stamps `version/version.go`'s version
(the authoritative source) rather than `.package-version`'s version.

---

## 4. Platform and package type selection

`PLATFORMS` is a whitespace-separated list of `GOOS[/GOARCH]` tokens:
- Bare `linux` — all Linux architectures.
- `linux/amd64` — a single arch.
- `!windows` prefix — exclude.
- Special: `defaults`, `xbuild` (cross-build-supported arches), `+all`.
- `linux/386` and `windows/386` are always filtered out.

`PACKAGES` is a comma-separated list of `tar.gz`, `zip`, `deb`, `rpm`,
`docker`.

`DOCKER_VARIANTS` is a comma-separated list of variant names (`basic`, `ubi`,
`wolfi`, `complete`, `cloud`, `slim`, etc.).

---

## 5. Key invariant: commit hash authority

The commit hash stamped into package metadata (`version.yml`, docker image
labels, `data/elastic-agent-<version>-<commit>/` directory name) must match
the commit that was compiled into the binary. Mismatches break downstream
consumers that key off commit hash (dashboards, DRA promotion, diagnostic
bundles, image labels).

| Regime | Core source | Authoritative commit |
|---|---|---|
| Locally compiled | `packageAgentCore` → `build/distributions/` | git HEAD |
| Downloaded from manifest | DRA artifact download | manifest's `elastic-agent-core.commit_hash` |

Mixing the two — e.g. downloading a pre-built binary but stamping git HEAD —
produces packages whose metadata disagrees with their binary content. On
`main`, this invariant is maintained by convention: `package` always compiles
locally (so it always uses git HEAD), and `packageUsingDRA` downloads from
the manifest when `MANIFEST_URL` is set (so it always uses the manifest
commit).

---

## 6. State on `main` — the packaging duality

On `main`, full packaging requires choosing between two mage targets with
subtly different semantics:

| | `mage package` | `mage packageUsingDRA` |
|---|---|---|
| Core source | Always local (`packageAgentCore`) | Manifest (when MANIFEST_URL set); local fallback |
| Commit stamped | git HEAD | Manifest's core commit (or git HEAD if no MANIFEST_URL) |
| Version/snapshot source | Manifest (Snapshot+BeatVersion only) | Manifest (all fields) |
| `dependenciesVersion` | Re-derived from BeatVersion | From manifest |

`package.sh` works around the gap by running `packageAgentCore` and
`downloadManifest` manually, then calling `packageUsingDRA` with `MANIFEST_URL`
unset. This is brittle: a pipeline that pre-sets `MANIFEST_URL` and calls
`mage package` will produce an artifact with a different commit stamp than
one that calls `mage packageUsingDRA` with the same URL.

The `AgentCommitHashOverride` field in `BuildSettings` exists solely to let
`packageUsingDRA` propagate the manifest's core commit into the packaging
templates. It is the only field that differs between the two targets after
`WithManifestInfo` returns.

---

## 7. Intended changes (this branch)

### 7.1 Unified `Package` target with `AGENT_CORE_SOURCE`

`mage packageUsingDRA` is removed. `mage package` accepts a new
`AGENT_CORE_SOURCE` env var:

| `AGENT_CORE_SOURCE` | Core source | Commit authority |
|---|---|---|
| `local` (default) | Compiled from current checkout (`PackageAgentCore`) | git HEAD |
| `manifest` | Downloaded from `MANIFEST_URL` | Manifest's `elastic-agent-core.commit_hash` |

Both modes converge in the same `packageAgent` function. The checksum
strategy (`ChecksumsWithManifest` vs `ChecksumsWithoutManifest`) and the
core extraction path are also gated on `AGENT_CORE_SOURCE`.

`AgentCommitHashOverride` is replaced by `Build.AgentCoreCommitHash` (set
by `WithManifestInfo` from the manifest's core commit). The method
`Settings.AgentCoreCommitHash()` returns that field when set, or git HEAD
when not set. For `AGENT_CORE_SOURCE=local`, only `Snapshot` and `BeatVersion`
are propagated from the manifest — the commit field is never set, so
`AgentCoreCommitHash()` returns git HEAD. For `AGENT_CORE_SOURCE=manifest`,
the full `WithManifestInfo` result is applied, including the commit field.

### 7.2 Simplified CI scripts

**`package.sh`** (after this branch):
```
mage clean
if MANIFEST_URL not set:
    export AGENT_CORE_SOURCE=local
    export USE_PACKAGE_VERSION=true
else:
    export AGENT_CORE_SOURCE=manifest
    export USE_PACKAGE_VERSION=false   # MANIFEST_URL and USE_PACKAGE_VERSION are mutually exclusive
fi
export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p "$AGENT_DROP_PATH"
mage package [helm:package] [ironbank] fixDRADockerArtifacts
```

No `_UNSET_MANIFEST_URL` dance. No separate `downloadManifest` or
`packageAgentCore` invocations from the script — `Package` handles them
internally based on `AGENT_CORE_SOURCE`.

**`integration-package.sh`** (after this branch):
```
export USE_PACKAGE_VERSION="true"
export WINDOWS_NPCAP="true"
export AGENT_CORE_SOURCE=local
mage package
```

`SNAPSHOT=true` removed (redundant: `.package-version` sets it).
`EXTERNAL=true` removed (redundant: `USE_PACKAGE_VERSION=true` sets
`AgentDropPath`, which makes the external-fetch branch unreachable in
`collectPackageDependencies`).

**`build-agent-core.sh`** (after this branch):
```
SNAPSHOT=$SNAPSHOT WINDOWS_NPCAP="true" USE_PACKAGE_VERSION=false mage packageAgentCore
```

`USE_PACKAGE_VERSION=false` added explicitly: the new default is `true`, but
binary-DRA builds must use `version/version.go`'s version, not
`.package-version`'s.

### 7.3 Better developer defaults

After this branch, `mage package` works from a fresh checkout with no env
vars set:
- `USE_PACKAGE_VERSION=true` (default): reads `.package-version` for manifest
  URL, version, and snapshot flag.
- `EXTERNAL=true` (default): enables external component fetching.
- `PLATFORMS` defaults to the host platform (`runtime.GOOS/runtime.GOARCH`).
- `PACKAGES` defaults to `tar.gz` (Linux/macOS) or `zip` (Windows).

CI scripts that need different behaviour set env vars explicitly.

### 7.4 What is NOT changing

- `mage packageAgentCore` is unchanged in semantics.
- `build-agent-core.sh` logic is unchanged (only `USE_PACKAGE_VERSION=false`
  is added to preserve the existing behaviour against the new default).
- The DRA publish pipeline (`dra-publish.sh`) is unchanged.
- The internal `packageAgent` function, `flattenDependencies`,
  `extractAgentCoreForPackage`, and related helpers are unchanged in their
  overall structure — see [packaging-internals.md](./packaging-internals.md).

---

## 8. Change: `USE_PACKAGE_VERSION` defaults to `true`

**Before:** `USE_PACKAGE_VERSION` defaulted to `false`. A bare `mage package`
used `version/version.go`'s version and produced a snapshot build only if
`SNAPSHOT=true` was set explicitly.

**After:** `setPackagingDefaults()` in `dev-tools/mage/settings.go` sets
`Packaging.UsePackageVersion = true`. A bare `mage package` now reads
`.package-version` and automatically picks up the branch's manifest URL,
version, and snapshot flag — no env vars required.

**Callers that must opt out:**

| Script / target | Why | Action |
|---|---|---|
| `build-agent-core.sh` | Binary-DRA must stamp `version/version.go`'s version | `USE_PACKAGE_VERSION=false` already added |
| `package.sh` (MANIFEST_URL branch) | `MANIFEST_URL` and `USE_PACKAGE_VERSION=true` are mutually exclusive | `USE_PACKAGE_VERSION=false` already added |
