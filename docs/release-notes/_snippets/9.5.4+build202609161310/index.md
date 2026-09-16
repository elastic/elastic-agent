## 9.5.4+build202609161310 [elastic-agent-release-notes-9.5.4+build202609161310]

:::{note}
This is an independent Elastic Agent release. Independent Elastic Agent releases deliver critical fixes and updates for Elastic Agent and Elastic Defend independently of a full Elastic Stack release. Read more in [Elastic Agent release process](docs-content://reference/fleet/fleet-agent-release-process.md).
:::


### Fixes [elastic-agent-9.5.4+build202609161310-fixes]

* Adds experimental macOS 27 (Golden Gate) support to {elastic-defend}.
* Adds a workaround to {elastic-defend} on macOS for a Golden Gate bug that broke network connections from apps using Network.framework.
* Fixes unsuccessful macOS updates when {elastic-defend} Device Control is enabled.
* {elastic-defend} on Linux now uses c-ares 1.34.8, fixing CVE-2024-25629 (out-of-bounds read in DNS config parsing).
* Fixes `host.name` exception list and trusted app rule matching to be case-insensitive in {elastic-defend}.
* Hardens how {elastic-defend} restores file ownership and permissions during malware quarantine on Linux and macOS.
* Fixes a crash in {elastic-defend} on Windows when processing files or processes whose paths contain CJK (Chinese, Japanese, Korean) characters.
* Makes {elastic-defend} upgrade more robust on slow machines.
* {elastic-defend} diagnostics bundles are no longer readable by unprivileged local users.
