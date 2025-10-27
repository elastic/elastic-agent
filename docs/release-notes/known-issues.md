---
navigation_title: Known issues
products:
  - id: elastic-agent
applies_to:
  stack: ga
sub:
  product: Elastic Agent
---

# {{product}} known issues

Known issues are significant defects or limitations that may impact your implementation. These issues are actively being worked on and will be addressed in a future release. Review the {{product}} known issues to help you make informed decisions, such as upgrading to a new version.

% Use the following template to add entries to this page.

% :::{dropdown} Title of known issue
% **Applicable versions for the known issue and the version for when the known issue was fixed**
% On [Month Day, Year], a known issue was discovered that [description of known issue].
% For more information, check [Issue #](Issue link).

% **Workaround**
% Workaround description.
% :::


:::{dropdown} Failed upgrades leave {{agent}} stuck until restart

**Applies to: {{agent}} 8.18.7, 9.0.7** 

On September 17, 2025, a known issue was discovered that can cause {{agent}} upgrades to get stuck if an upgrade attempt fails under specific conditions. This happens because the coordinator’s `overrideState` remains set, leaving the agent in a state that appears to be upgrading.

**Conditions**

This issue is triggered if the upgrade fails during one of the early checks inside `Coordinator.Upgrade`, for example:

- The agent is not upgradeable
- Capabilities check denies the upgrade
- When {{agent}} is tamper-protected, Endpoint must validate that the upgrade action was correctly signed by Kibana to allow the upgrade. If the signature is missing, invalid, or the connection between {{agent}} and Endpoint was interrupted, the validation fails. This causes the agent coordinator's override state to become stuck until the agent is restarted.

**Symptoms**

- {{fleet}} shows the upgrade action in progress, even though the upgrade remains stuck
- No further upgrade attempts succeed 
- Elastic Agent status shows an override state indicating upgrade 

**Workaround**

Restart the {{agent}} to clear the coordinator’s `overrideState` and allow new upgrade attempts to proceed.

**Resolution**
This issue was fixed in [#9992](https://github.com/elastic/elastic-agent/pull/9992), which ensures that the coordinator clears its override state whenever an early failure occurs.

The fix is included in versions 9.1.4 and 8.19.4, and planned for versions 9.0.8 and 8.18.8.
:::

:::{dropdown} [Windows] {{agent}} does not process Windows security events

**Applies to: {{agent}} 8.19.0, 9.1.0 (Windows only)**

On August 1, 2025, a known issue was discovered where {{agent}} does not process Windows security events on hosts running Windows 10, Windows 11, and Windows Server 2022.

For more information, check [Issue #45693](https://github.com/elastic/beats/issues/45693).

**Workaround**

No workaround is available at the moment, but a fix is expected to be available in {{agent}} 8.19.1 and 9.1.1.
:::

:::{dropdown} {{agents}} remain in an "Upgrade scheduled" state

**Applies to: {{agent}} 8.18.0, 8.18.1, 8.18.2, 8.18.3, 8.18.4, 8.19.0, 9.0.0, 9.0.1, 9.0.2, 9.0.3, 9.1.0**

On July 2, 2025, a known issue was discovered where {{agent}} remains in an `Upgrade scheduled` state when a scheduled {{agent}} upgrade is cancelled. Attempting to restart the upgrade on the UI returns an error: `The selected agent is not upgradeable: agent is already being upgraded.`.

For more information, check [Issue #8778](https://github.com/elastic/elastic-agent/issues/8778).

**Workaround**

Call the [Upgrade an agent](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-fleet-agents-agentid-upgrade) endpoint of the Kibana Fleet API with the `force` parameter set to `true` to force-upgrade the {{agent}}:

```powershell
curl --request POST \
  --url https://<KIBANA_HOST>/api/fleet/agents/<AGENT_ID>/upgrade \
  --user "<SUPERUSER_NAME>:<SUPERUSER_PASSWORD>" \
  --header 'Content-Type: application/json' \
  --header 'kbn-xsrf: true' \
  --data '{"version": "<VERSION>","force": true}'
```

To force-upgrade multiple {{agents}}, call the [Bulk upgrade agents](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-fleet-agents-bulk-upgrade) endpoint of the Kibana Fleet API with the `force` parameter set to `true`:

```powershell
curl --request POST \
  --url https://<KIBANA_HOST>/api/fleet/agents/bulk_upgrade \
  --user "<SUPERUSER_NAME>:<SUPERUSER_PASSWORD>" \
  --header 'Content-Type: application/json' \
  --header 'kbn-xsrf: true' \
  --data '{"version": "<VERSION>","force": true,"agents":["<AGENT_IDS>"]}'
```
:::

:::{dropdown} [Windows] {{agent}} is unable to re-enroll into {{fleet}}

**Applies to: {{agent}} 9.0.0, 9.0.1, 9.0.2 (Windows only)**

On April 9, 2025, a known issue was discovered where an {{agent}} installed on Windows and previously enrolled into {{fleet}} is unable to re-enroll. Attempting to enroll the {{agent}} fails with the following error:

```shell
Error: the command is executed as root but the program files are not owned by the root user.
```

For more information, check [Issue #7794](https://github.com/elastic/elastic-agent/issues/7794).

**Workaround**

Until a bug fix is available in a later release, you can resolve the issue temporarily using the following workaround:

1. Change the ownership of the {{agent}} directory:

  ```shell
  icacls "C:\Program Files\Elastic\Agent" /setowner "NT AUTHORITY\SYSTEM" /t /l
  ```

2. After the output confirms all files were successfully processed, run the `enroll` command again.

:::

:::{dropdown} [macOS] Osquery integration fails to start on fresh agent installs

**Applies to: {{agent}} 9.0.0 and 9.0.1 (macOS only)**

On May 26th, 2025, a known issue was discovered that causes the `osquery` integration to fail on new {{agent}} installations on macOS. During the installation process, the required `osquery.app/` directory is removed, which prevents the integration from starting.

For more information, check [Issue #8245](https://github.com/elastic/elastic-agent/issues/8245).

**Workaround**

As a workaround, you can manually restore the `osquery.app/` directory as follows:

1. Extract the {{agent}} package, but do not install it yet.

2. Open the following file in the extracted directory:

   ```
   data/elastic-agent-68f3ed/components/agentbeat.spec.yml
   ```

3. Locate the `component_files` section at the top of the file. It should look similar to this:

   ```yaml
   version: 2
   component_files:
     - certs/*
     - lenses/*
     - module/*
     - "osquery-extension.ext"
     - "osquery-extension.exe"
     - osqueryd
     - "osqueryd.exe"
   ```

4. Add the following entry to the end of the list:

   ```yaml
     - "osquery.app/*"
   ```

   The updated section should now look like this:

   ```yaml
   version: 2
   component_files:
     - certs/*
     - lenses/*
     - module/*
     - "osquery-extension.ext"
     - "osquery-extension.exe"
     - osqueryd
     - "osqueryd.exe"
     - "osquery.app/*"
   ```

5. Proceed to install {{agent}} from the extracted directory as usual.

:::

:::{dropdown} Failed to start {{agent}} in OTel mode for Hosts onboarding

**Applies to: {{agent}} 9.1.6 to 9.2.0**

On October 24, 2025, a known issue was discovered where {{agent}} fails to start
in OTel mode when deployed through the guided Observability onboarding flow in Kibana. The issue occurs because the sample configuration used by the {{agent}} was using incorrect configuration key.

The Error looks like this in the logs:

```shell
Starting in otel mode
failed to get config: cannot unmarshal the configuration: decoding failed due to the following error(s):

'exporters' error reading configuration for "otlp/ingest": decoding failed due to the following error(s):

'sending_queue' decoding failed due to the following error(s):

'batch' decoding failed due to the following error(s):

'' has invalid keys: flush_interval
```

**Workaround**

To work around this issue, manually update the configuration of the generated `otel.yaml` file to replace the incorrect key `flush_interval` with the correct key `flush_timeout`.

```yaml
batch:
  flush_timeout: 1s
```

:::
