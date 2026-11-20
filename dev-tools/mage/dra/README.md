# elastic-agent-package DRA plumbing

`elastic-agent-package` publishes a DRA product that it does not build from its
own source alone: every component binary in the package comes out of another
product's DRA build. Nothing in unified-release tells it when those inputs move,
so it watches them itself and triggers its own build.

That work is split in two deliberately.

**Packaging logic lives here, in Go**, because it decides what ends up in the
package and therefore has to be reproducible on a laptop:

| Target | What it does |
|---|---|
| `mage dra:dependencies` | Prints the DRA products the package is assembled from |
| `mage dra:mergeManifests` | Resolves the current DRA build of each, and writes the merged manifest `mage package` consumes |

**CI plumbing stays in bash**, in `.buildkite/scripts/`, because none of it can
run locally anyway: the GCS reads and writes and the Buildkite API calls in
[`poll-agent-package-deps.sh`](../../../.buildkite/scripts/poll-agent-package-deps.sh),
and the `buildkite-agent artifact download` in
[`stage-agent-package-artifacts.sh`](../../../.buildkite/scripts/stage-agent-package-artifacts.sh).

The contract between the halves is the merged manifest's `build_id`. It is a
content hash of the dependency build IDs (see `DependencySetID`), so merging the
same inputs twice yields the same id, and the poller can use it both as the
path it publishes under and as the answer to "have these inputs been built
already?".

## Running a DRA packaging build locally

```bash
# Resolve today's dependency builds and merge their manifests.
mage dra:mergeManifests

# Package exactly what CI would package from them.
MANIFEST_PATH=build/dra/agent-artifacts-merged.json \
  AGENT_CORE_SOURCE=manifest \
  PLATFORMS="linux/amd64" PACKAGES="tar.gz" \
  mage package
```

`MANIFEST_PATH` is `MANIFEST_URL` pointed at a file on disk — the manifest is
read locally instead of downloaded, which is the only reason a merged manifest
had to be published somewhere before. The component archives the manifest names
are still fetched over HTTPS and are still checked against
`manifest.AllowedManifestHosts`, so this does not widen what packaging will
download. `mage downloadManifest` does just the download half if you only want
the drop path populated.

`AGENT_CORE_SOURCE=manifest` makes the run use the `elastic-agent-core` build
from the manifest, as the DRA pipeline does. Drop it to compile core from your
checkout and take only the components from the manifest.

Environment read by `dra:mergeManifests`:

| Variable | Default | Meaning |
|---|---|---|
| `DRA_WORKFLOW` | `snapshot` | `snapshot` or `staging` |
| `DRA_VERSION` | the branch's current build | Pin an exact stack version instead |
| `BUILDKITE_BRANCH` | current git branch | Branch to resolve, and recorded in the manifest |
| `DRA_MERGED_MANIFEST_OUT` | `build/dra/agent-artifacts-merged.json` | Output path |
| `DRA_ALLOW_MISSING_DEPS` | `false` | Merge even if a product has not published this version |

## Where the dependency list comes from

`Dependencies()` reads the `projectName` of every component in
[`dev-tools/packaging/packages.yml`](../../packaging/packages.yml) — the same
file the packaging code reads to decide which archives to pull out of the
manifest. Adding a component there is all it takes for the poller to start
watching its product; there is no second list to keep in sync.

Products whose source reaches the package by another route are deliberately
absent. `agentbeat` is compiled from the `beats` submodule of this checkout, so
a beats bump reaches `elastic-agent-package` as a new `elastic-agent-core`
build, not as a beats DRA build.

## How dependency builds are resolved

DRA publishes two "latest" pointers per product for the same build, and they
agree:

```
https://artifacts-snapshot.elastic.co/<product>/latest/master.json
https://artifacts-snapshot.elastic.co/<product>/latest/9.7.0-SNAPSHOT.json
```

`dra:mergeManifests` prefers the **branch** pointer, because it follows a branch
across version bumps without this repository having to agree with DRA about the
version. Note the key for the default branch is `master`, never `main` — asking
for `main.json` resolves nothing, which is what the poller originally did.

A branch DRA does not publish a pointer for — every feature branch — falls back
to the **version** pointer for `version.Agent`, so a local run on a feature
branch resolves the same builds CI would. `DRA_VERSION` overrides both and pins
an exact version.

The version written into the merged manifest, and passed on as `DRA_VERSION`, is
the one the dependencies themselves report rather than anything this repository
asserts. When they disagree — normal for a while after a version bump —
`elastic-agent-core` wins, because it is the DRA build of this repository, and
the odd ones out are logged.

## What the poller script does with it

1. `mage dra:mergeManifests` — writes `build/dra/agent-artifacts-merged.json`.
2. If `gs://<bucket>/elastic-agent-package/poller-merged/<branch>/<build_id>/triggered.json`
   exists, these inputs were already built; stop.
3. If a build is in flight on the branch, stand down; the next poll picks up
   whatever is current then.
4. Upload the merged manifest, trigger `elastic-agent-package` with
   `MANIFEST_URL` pointing at it, and only then write `triggered.json`.

Writing the record last means a failed trigger is retried on the next tick. It
also means a build that was triggered and then *failed* is not retriggered —
the inputs were already built. Restart it from Buildkite, or run the poller with
`DRA_POLL_FORCE=true`.
