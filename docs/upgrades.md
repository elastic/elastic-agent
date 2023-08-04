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
       A->>A: Replace current Agent artifact with new one
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
         UW->>UW: Replace current Agent artifact with old one
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
