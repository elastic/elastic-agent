## Agent Upgrades

### Communications amongst components
The following sequence diagram illustrates the process of upgrading a
Fleet-managed Agent. The diagram focusses on the communications that occur
amongst the various components involved in the upgrade process.

This diagram is accurate as of version `8.9.0` of every component shown.

```mermaid
sequenceDiagram
    actor U as User
    participant UI as Fleet UI
    participant ES
    participant FS as Fleet Server
    participant A as Agent
    participant UW as Upgrade Watcher
    participant UM as Upgrader Marker

    U->>UI: Initiate upgrade
    UI->>ES: Update Agent doc in `.fleet-agents`<br />set `upgrade_started_at`
    UI->>UI: Show Agent status as "updating"
    UI->>ES: Create new doc in `.fleet-actions` for `UPGRADE` action
    A->>FS: Check-in request
    FS->>ES: Read pending actions from .fleet-actions
    FS->>A: Check-in response
    A->>A: Queue upgrade action
    alt If upgrade start fails
       A->>FS: Ack failed upgrade
       FS->>ES: Update Agent doc in `.fleet-agents`<br />set `upgrade_status` = "failed"
       UI->>UI: Agent status remains as "updating" (bug)
    else
       opt If previous upgrades found
          A->>FS: Ack previous upgrades
          A->>A: Remove previous upgrades from queue
       end
       A->>A: Download new Agent artifact
       A->>A: Extract new Agent artifact
       A->>A: Change symlink from current Agent binary to new one
       A->>UM: Create
       A->>A: Update active commit file
       A->>UW: Start
       A->>A: Rexec to start new Agent artifact
       A->>FS: Ack successful upgrade
       FS->>ES: Write successful ack in `.fleet-actions-results`
       FS->>ES: Update Agent doc in `.fleet-agents`<br />set `upgrade_status` = null<br />`upgraded_at` = <now><br />`upgrade_started_at` = null
       UI->>UI: Show Agent status as "healthy"
       UW->>UW: Start watching new Agent
       alt New Agent is OK
         UW->>UM: Remove
         UW->>UW: Cleanup old Agent files
       else Rollback
         UW->>UW: Change symlink from current Agent binary to new one
         UW->>UW: Update active commit file
         UW->>A: Rexec to start old Agent artifact
         A->>FS: Ack failed upgrade
         FS->>ES: Update Agent doc in `.fleet-agents`<br />set `upgrade_status` = null<br />`upgraded_at = <now>
         UI->>UI: Show Agent status as "healthy"
         UW->>UM: Remove
         UW->>UW: Cleanup new Agent files
       end
    end
```

### Introducing package manifest

Starting from version 8.13.0 an additional file `manifest.yaml` is present in elastic-agent packages.
The purpose of this file is to present some metadata and package information to be used during install/upgrade operations.

The first enhancement that makes use of this package manifest is [#2579](https://github.com/elastic/elastic-agent/issues/2579)
as we use the manifest to map the package directory structure (based on agent commit hash) into one that takes also the
agent version into account. This allows releasing versions of the agent package where only the component versions change,
with the agent commit unchanged.


The [structure](../pkg/api/v1/manifest.go) of such manifest is defined in the [api/v1 package](../pkg/api/v1/).
The manifest data is generated during packaging and the file is added to the package files. This is an example of a
complete manifest:

```yaml
version: co.elastic.agent/v1
kind: PackageManifest
package:
  version: 8.13.0
  snapshot: true
  hash: 15658b38b48ba4487afadc5563b1576b85ce0264
  versioned-home: data/elastic-agent-15658b
  path-mappings:
    - data/elastic-agent-15658b: data/elastic-agent-8.13.0-SNAPSHOT-15658b
      manifest.yaml: data/elastic-agent-8.13.0-SNAPSHOT-15658b/manifest.yaml
```

The package information describes the package version, whether it's a snapshot build, the elastic-agent commit hash it
has been built from and where to find the versioned home of the elastic agent within the package.

Another section lists the path mappings that must be applied by an elastic-agent that is aware of the package manifest
(version >8.13.0): these path mappings allow the incoming agent version to have some control over where the files in
package will be stored on disk.

#### Upgrading without the manifest

Legacy elastic-agent upgrade is a pretty straightforward affair:
- Download the agent package to use for upgrade
- Open the .zip or .tar.gz archive and iterate over the files
  - Look for the elastic-agent commit file to retrieve the actual hash of the agent version we want to install
  - Extract any package file under `/data` under the installed agent `/data` directory
- After extraction check if the hash we read from the package matches with the one from the current agent:
  - if it's the same hash the upgrade fails because we are trying to upgrade to the same version
  - if we extracted a package with a different hash, the upgrade keeps going
- Copy the elastic agent action store and components run directory into the new agent directories `elastic-agent-<hash>`
- Rotate the symlink in the top directory to point to the new agent executable `data/elastic-agent-<hash>/elastic-agent`
- Write the update marker containing the information about the new and old agent versions/hashes in `data` directory
- Invoke the watcher `elastic-agent watch` command to ensure that the new version of agent works correctly after restart
- Shutdown current agent and its command components, copy components state once again and restart

#### Upgrading using the manifest

Upgrading using the manifest allows for the new version to pass along some information about the package to the upgrading agent.
The new process looks like this:
- Download the elastic-agent package to use for upgrade
- Extract package metadata from the new elastic-agent package (`version`, `snapshot` and `hash`):
  - if the package has a manifest we extract `version` and `snapshot` flag as declared by the package manifest
  - if there is no manifest for the package we extract `version` and `snapshot` from the version string passed to the upgrader
  - the `hash` is always retrieved from the agent commit file (this is always present in the package)
- compare the tuple of new `(version, snapshot, hash)` to the current `(version, snapshot, hash)`: if they are the same
  the upgrade fails because we are trying to upgrade to the same version as current
- Extract any package file (after mapping it using file mappings in manifest if present) that should go under `/data`.
  Return the new versionedHome (where the new version of agent has its files, returned as path relative to the top directory)
- Copy the elastic agent action store and components run directory into the new agent in `<versionedHome>/run`
- Write the update marker containing the information about the new and old agent version, hash and home in `data` directory
- Invoke the watcher `elastic-agent watch` command to ensure that the new version of agent works correctly after restart:
  - we invoke the current agent binary if the new version < 8.13.0 (needed to make sure it supports the paths written in the update marker)
  - we invoke the new agent binary if the new version > 8.13.0
- Shutdown current agent and its command components, copy components state once again and restart
