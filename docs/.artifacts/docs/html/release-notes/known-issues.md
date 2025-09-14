---
title: Elastic Agent known issues
description: Known issues are significant defects or limitations that may impact your implementation. These issues are actively being worked on and will be addressed...
url: https://docs-v3-preview.elastic.dev/release-notes/known-issues
products:
  - Elastic Agent
---

# Elastic Agent known issues

Known issues are significant defects or limitations that may impact your implementation. These issues are actively being worked on and will be addressed in a future release. Review the Elastic Agent known issues to help you make informed decisions, such as upgrading to a new version.
<dropdown title="[Windows] Elastic Agent does not process Windows security events">
  **Applies to: Elastic Agent 8.19.0, 9.1.0 (Windows only)**On August 1, 2025, a known issue was discovered where Elastic Agent does not process Windows security events on hosts running Windows 10, Windows 11, and Windows Server 2022.For more information, check [Issue #45693](https://github.com/elastic/beats/issues/45693).**Workaround**No workaround is available at the moment, but a fix is expected to be available in Elastic Agent 8.19.1 and 9.1.1.
</dropdown>

<dropdown title="Elastic Agents remain in an "Upgrade scheduled" state">
  **Applies to: Elastic Agent 8.18.0, 8.18.1, 8.18.2, 8.18.3, 8.18.4, 8.19.0, 9.0.0, 9.0.1, 9.0.2, 9.0.3, 9.1.0**On July 2, 2025, a known issue was discovered where Elastic Agent remains in an `Upgrade scheduled` state when a scheduled Elastic Agent upgrade is cancelled. Attempting to restart the upgrade on the UI returns an error: `The selected agent is not upgradeable: agent is already being upgraded.`.For more information, check [Issue #8778](https://github.com/elastic/elastic-agent/issues/8778).**Workaround**Call the [Upgrade an agent](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-fleet-agents-agentid-upgrade) endpoint of the Kibana Fleet API with the `force` parameter set to `true` to force-upgrade the Elastic Agent:
  ```powershell
  curl --request POST \
    --url https://<KIBANA_HOST>/api/fleet/agents/<AGENT_ID>/upgrade \
    --user "<SUPERUSER_NAME>:<SUPERUSER_PASSWORD>" \
    --header 'Content-Type: application/json' \
    --header 'kbn-xsrf: true' \
    --data '{"version": "<VERSION>","force": true}'
  ```
  To force-upgrade multiple Elastic Agents, call the [Bulk upgrade agents](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-fleet-agents-bulk-upgrade) endpoint of the Kibana Fleet API with the `force` parameter set to `true`:
  ```powershell
  curl --request POST \
    --url https://<KIBANA_HOST>/api/fleet/agents/bulk_upgrade \
    --user "<SUPERUSER_NAME>:<SUPERUSER_PASSWORD>" \
    --header 'Content-Type: application/json' \
    --header 'kbn-xsrf: true' \
    --data '{"version": "<VERSION>","force": true,"agents":["<AGENT_IDS>"]}'
  ```
</dropdown>

<dropdown title="[Windows] Elastic Agent is unable to re-enroll into Fleet">
  **Applies to: Elastic Agent 9.0.0, 9.0.1, 9.0.2 (Windows only)**On April 9, 2025, a known issue was discovered where an Elastic Agent installed on Windows and previously enrolled into Fleet is unable to re-enroll. Attempting to enroll the Elastic Agent fails with the following error:
  ```shell
  Error: the command is executed as root but the program files are not owned by the root user.
  ```
  For more information, check [Issue #7794](https://github.com/elastic/elastic-agent/issues/7794).**Workaround**Until a bug fix is available in a later release, you can resolve the issue temporarily using the following workaround:
  1. Change the ownership of the Elastic Agent directory:

  ```shell
  icacls "C:\Program Files\Elastic\Agent" /setowner "NT AUTHORITY\SYSTEM" /t /l
  ```

  1. After the output confirms all files were successfully processed, run the `enroll` command again.
</dropdown>

<dropdown title="[macOS] Osquery integration fails to start on fresh agent installs">
  **Applies to: Elastic Agent 9.0.0 and 9.0.1 (macOS only)**On May 26th, 2025, a known issue was discovered that causes the `osquery` integration to fail on new Elastic Agent installations on macOS. During the installation process, the required `osquery.app/` directory is removed, which prevents the integration from starting.For more information, check [Issue #8245](https://github.com/elastic/elastic-agent/issues/8245).**Workaround**As a workaround, you can manually restore the `osquery.app/` directory as follows:
  1. Extract the Elastic Agent package, but do not install it yet.
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
     ```   The updated section should now look like this:   
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
  5. Proceed to install Elastic Agent from the extracted directory as usual.
</dropdown>
