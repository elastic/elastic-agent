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
