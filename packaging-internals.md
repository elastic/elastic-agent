# Elastic Agent Packaging — Internals

This document covers the implementation details of the packaging system:
settings loading, function call graphs, manifest handling, checksum strategy,
and the `build/` artifact layout. For the external behaviour, env vars, CI
usage, and intended changes see
[packaging-analysis.md](./packaging-analysis.md).

---

## 1. Settings loading

`devtools.LoadSettings()` in `dev-tools/mage/settings.go` initialises the
`Settings` struct:

1. `setDefaults()` — sets non-zero defaults, including
   `Packaging.UsePackageVersion = true`.
2. `loadBuildSettingsFromEnv()` — reads `SNAPSHOT`, `EXTERNAL`, `FIPS`,
   `BEAT_VERSION`, `VERSION_QUALIFIER`, etc. into `BuildSettings`.
3. `loadPackagingSettingsFromEnv()` — reads `MANIFEST_URL`,
   `USE_PACKAGE_VERSION`, `AGENT_DROP_PATH`, `KEEP_ARCHIVE`,
   `AGENT_CORE_SOURCE` into `PackagingSettings`. `MANIFEST_URL` and
   `USE_PACKAGE_VERSION=true` are mutually exclusive: the latter reads
   `.package-version` to set the manifest URL, so providing both is an
   error. If `UsePackageVersion` is set (and `MANIFEST_URL` is not), calls
   `GetPackageVersionInfo()` to read `.package-version` and propagates
   `ManifestURL`, `AgentPackageVersion`, `BeatVersion`, `Snapshot=true`,
   and a default `AgentDropPath`.
4. `initRepoInfo()`, `initElasticBeatsDir()`, `initBuildVariables()`,
   `initCommitHash()` — filesystem/git probes.

`initCommitHash()` runs `git rev-parse HEAD` and stores the result in the
unexported `Build.commitHash` field. It handles the golang-crossbuild
container case by configuring `safe.directory` when needed.

### 1.1 Key `Settings` fields for packaging

```
Settings
├── Build (BuildSettings)
│   ├── commitHash          — git HEAD, set by initCommitHash(); never overridden
│   ├── Snapshot            — from SNAPSHOT env or .package-version
│   ├── BeatVersion         — from BEAT_VERSION env or manifest/package-version
│   ├── AgentCoreCommitHash — empty (local builds) or manifest's core commit
│   └── DependenciesVersion — from manifest's VersionWithPrerelease; else derived
│
└── Packaging (PackagingSettings)
    ├── ManifestURL         — from MANIFEST_URL or .package-version
    ├── Manifest            — *manifest.Build, populated by WithManifestInfo
    ├── UsePackageVersion   — from USE_PACKAGE_VERSION (default: true)
    ├── AgentDropPath       — from AGENT_DROP_PATH or .package-version
    ├── CoreSource          — from AGENT_CORE_SOURCE (default: CoreSourceLocal)
    └── KeepArchive         — from KEEP_ARCHIVE
```

### 1.2 `WithManifestInfo`

```go
func (s *Settings) WithManifestInfo(ctx context.Context) (*Settings, error)
```

- Returns the receiver unchanged if `ManifestURL` is empty.
- Downloads and parses the manifest JSON from `ManifestURL`.
- On success, returns a clone with:
  - `Packaging.Manifest = &resp`
  - `Build.Snapshot` — from manifest's version (`-SNAPSHOT` suffix)
  - `Build.BeatVersion` — core semver from manifest's version
  - `Build.AgentCoreCommitHash` — `resp.Projects["elastic-agent-core"].CommitHash`
  - `Build.DependenciesVersion` — `resp.Version` (VersionWithPrerelease)

### 1.3 Commit hash methods

Two distinct concepts share the word "commit":

| Method | Returns | Used for |
|--------|---------|---------|
| `BuildSettings.CommitHash()` | git HEAD (`commitHash`) | Embedding in compiled binaries |
| `Settings.AgentCoreCommitHash()` | `Build.AgentCoreCommitHash` if set, else `CommitHash()` | Package metadata (directory names, templates) |

Template functions exposed via `FuncMap`:
- `core_commit` → `AgentCoreCommitHash()`
- `core_commit_short` → `AgentCoreCommitHashShort()` (first 6 chars)

---

## 2. `Package` call graph

```
Package(ctx)
├── cfg.WithManifestInfo(ctx)          [CoreSourceLocal: partial apply]
│   └── manifest.DownloadManifest()
├── mg.CtxDeps(ctx, PackageAgentCore)  [CoreSourceLocal only]
│   └── PackageAgentCore(ctx)
│       ├── mg.CtxDeps: Update, Otel.Prepare, Otel.CrossBuild, CrossBuild,
│       │               Build.WindowsArchiveRootBinary
│       └── devtools.Package(ctx, cfg, coreSpec)
│
├── cfg.WithManifestInfo(ctx)          [CoreSourceManifest: full apply]
│   └── manifest.DownloadManifest()
│
├── devtools.LoadElasticAgentPackageSpec()
├── downloadManifest(ctx, cfg, pkgSpec, filters...)  [if ManifestURL != ""]
│   └── manifest.DownloadComponents()
└── packageAgent(ctx, cfg, pkgSpec)
    ├── collectPackageDependencies()
    ├── flattenDependencies()
    ├── extractAgentCoreForPackage()
    └── devtools.Package(ctx, cfg, pkgSpecs)
```

---

## 3. `packageAgent`

Signature: `packageAgent(ctx, cfg *Settings, pkgSpecs []OSPackageArgs) error`

1. Resolves `dependenciesVersion`:
   - Uses `cfg.Build.DependenciesVersion` if set (populated by manifest).
   - Otherwise derives from `BeatQualifiedVersion()` (or `bversion.GetDefaultVersion()`)
     plus snapshot suffix.

2. Calls `extractComponentsFromSelectedPkgSpecs` — walks all `pkgSpecs`
   selected by the current platforms/FIPS/docker-variant settings and
   collects `BinarySpec` entries from `pkg.Spec.Components` into a
   deduplicated map.

3. Calls `collectPackageDependencies` — see §4.

4. Calls `flattenDependencies` — see §5.

5. Calls `extractAgentCoreForPackage` — see §6.

6. Calls `devtools.Package` — the beats-inherited packaging engine that runs
   `fpm`, docker build, cross-build, etc. against the prepared drop path.

---

## 4. `collectPackageDependencies`

```go
func collectPackageDependencies(cfg *Settings, platforms []string, packageVersion string,
    dependencies []BinarySpec) (archivePath, dropPath string, d []BinarySpec)
```

- If `AgentDropPath` is already set (e.g. from `AGENT_DROP_PATH` or
  `.package-version`): uses it as `dropPath` and moves any pre-existing
  archives into an `archives/` subdir.
- If `AgentDropPath` is **not** set: creates
  `build/distributions/elastic-agent-drop` as `dropPath`, then if
  `ExternalBuild` is true downloads all dependency packages concurrently
  via `downloads.FetchProjectBinary` (artifact API).
- `archivePath = movePackagesToArchive(dropPath, ...)` — creates
  `<dropPath>/archives/<platform>/` and moves any pre-existing archives there
  so `flattenDependencies` has a consistent directory to untar from.
- Filters `dependencies` to only those that support at least one selected
  package type before returning.

---

## 5. `flattenDependencies`

For each platform:
1. Untars/unzips all `*.tar.gz` and `*.zip` archives from
   `archivePath/<platform>/` into a `flatPath/<platform>/` directory (python
   wheels are excluded — they are handled by the docker packaging spec
   separately).
2. Computes component checksums:
   - `CoreSourceManifest`: uses `ChecksumsWithManifest` — takes SHA512 hashes
     from the manifest's component entries (correct only when every binary
     came from the manifest).
   - All other `CoreSource` values: uses `ChecksumsWithoutManifest` — computes
     SHA512 hashes from the files on disk.
3. Calls `appendComponentChecksums` which adds per-binary checksums from the
   `.spec.yml` sidecars and writes a `checksums.yml` to `dropPath/<platform>/`.

---

## 6. `extractAgentCoreForPackage`

```go
func extractAgentCoreForPackage(ctx context.Context, cfg *Settings, version string) error
```

1. Calls `packaging.Components()` to load all component specs, then
   `FilterComponents` to find the single `elastic-agent-core` spec matching
   the current FIPS flag.

2. Determines `coreDownloadDir`:
   - `CoreSourceManifest`: calls `downloadDRAArtifacts(ctx, manifest, version,
     build/core/<buildID>, platforms, component)` to download the pre-built
     core archives and sets `coreDownloadDir = build/core/<buildID>`.
   - `CoreSourceLocal` (or empty): uses
     `coreDownloadDir = build/distributions` (written by `PackageAgentCore`).

3. For each platform, extracts
   `<coreDownloadDir>/<expectedPackageName>` into
   `build/core/extracted/<goos>-<arch>/` (renaming the extracted root
   directory to match the platform path format expected by the packaging
   templates).

---

## 7. `devtools.Package` (beats packaging engine)

`devtools.Package(ctx, cfg, pkgSpecs)` lives in the beats submodule. It
iterates over `pkgSpecs` filtered to selected platforms/types, then for each:
- **`tar.gz` / `zip`**: calls the cross-build packaging path (builds inside
  the `golang-crossbuild` docker image for non-host platforms).
- **`deb` / `rpm`**: calls the `fpm` docker image.
- **`docker`**: calls `docker buildx` or the beats docker builder.

Templates in `_meta/packaging/` expand fields from `FuncMap(cfg)`, which
includes `core_commit`, `core_commit_short`, `agent_package_version`,
`snapshot_suffix`, etc.

---

## 8. Cross-build

`CrossBuild(ctx)` calls `devtools.CrossBuild(ctx, cfg)` from the beats
library. For each selected platform that differs from the host:
- Spawns `docker.elastic.co/beats-dev/golang-crossbuild:<version>` with
  `GOLANG_CROSSBUILD=1`.
- The container re-invokes `mage crossBuild` inside itself (the `LoadSettings`
  crossbuild path configures `safe.directory` so `initCommitHash` works).
- Output binaries land in `build/golang-crossbuild/<goos>-<goarch>/`.

---

## 9. Manifest internals

The manifest JSON format (deserialized by `dev-tools/mage/manifest/`):

```json
{
  "version": "8.19.0-SNAPSHOT",
  "build_id": "8.19.0-abcd1234",
  "projects": {
    "elastic-agent-core": {
      "commit_hash": "abcdef1234...",
      "packages": { ... }
    },
    "beats": { ... }
  }
}
```

Key fields consumed by settings:
- `version` → `Build.Snapshot`, `Build.BeatVersion`, `Build.DependenciesVersion`
- `projects["elastic-agent-core"].commit_hash` → `Build.AgentCoreCommitHash`
- `build_id` → used as a directory suffix in `build/core/<buildID>/`

`manifest.DownloadComponents` resolves each `BinarySpec`'s package name
against `projects[spec.ProjectName].packages` in the manifest to get the
download URL and SHA512, then downloads into `<dropPath>/<platform>/`.

---

## 10. `.package-version` file

Located at the repo root. JSON format (deserialized by `GetPackageVersionInfo`):

```json
{
  "version": "8.19.0-SNAPSHOT+build20250509",
  "core_version": "8.19.0",
  "manifest_url": "https://artifacts.elastic.co/manifests/elastic-agent-8.19.0-SNAPSHOT.json",
  "stack_version": "8.19.0-SNAPSHOT"
}
```

Read when `UsePackageVersion=true` (the default). The loader in
`loadPackagingSettingsFromEnv` propagates:
- `ManifestURL = pv.ManifestURL`
- `AgentPackageVersion = pv.CoreVersion`
- `BeatVersion = pv.CoreVersion`
- `Snapshot = true`
- `AgentDropPath` defaulted to `build/distributions/elastic-agent-drop`

The file is committed to git and updated by release automation (the
`elastic-agent-changelog-tool` equivalent for version bumps).

---

## 11. `build/` artifact layout

After `PackageAgentCore` completes:

```
build/distributions/
  elastic-agent-core-<version>-<commit>-linux-x86_64.tar.gz
  elastic-agent-core-<version>-<commit>-linux-arm64.tar.gz
  elastic-agent-core-<version>-<commit>-windows-x86_64.zip
  ...
```

After `packageAgent` (full packaging) completes:

```
build/distributions/
  elastic-agent-<version>-linux-x86_64.tar.gz
  elastic-agent-<version>-linux-x86_64.deb
  elastic-agent-<version>-linux-x86_64.rpm
  elastic-agent-<version>-docker-linux-amd64.tar.gz    (before FixDRADockerArtifacts)
  elastic-agent-<version>-image-docker-linux-amd64.tar.gz  (after rename)
  ...
  reports/
    dependencies-<version>.csv
```

Temporary directories created and cleaned up during packaging:
- `build/distributions/elastic-agent-drop/` — dependency staging (`dropPath`)
- `build/distributions/elastic-agent-drop/archives/` — original archives
  (`archivePath`)
- `build/distributions/elastic-agent-drop/.elastic-agent_flat/` — extracted
  component binaries (`flatPath`)
- `build/core/<buildID>/` — downloaded core archives (manifest mode)
- `build/core/extracted/` — per-platform extracted core directories
