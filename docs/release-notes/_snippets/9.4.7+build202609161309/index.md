## 9.4.7+build202609161309 [elastic-agent-release-notes-9.4.7+build202609161309]

:::{note}
This is an independent Elastic Agent release. Independent Elastic Agent releases deliver critical fixes and updates for Elastic Agent and Elastic Defend independently of a full Elastic Stack release. Read more in [Elastic Agent release process](docs-content://reference/fleet/fleet-agent-release-process.md).
:::


### Fixes [elastic-agent-9.4.7+build202609161309-fixes]

* Add experimental macOS 27 (Golden Gate) support to Elastic Defend.
* Add a workaround to Elastic Defend on macOS for a Golden Gate bug that broke network connections from apps using Network.framework.
* Fix unsuccessful macOS updates when Elastic Defend Device Control is enabled.
* Elastic Defend on Linux now uses c-ares 1.34.8, fixing CVE-2024-25629 (out-of-bounds read in DNS config parsing).
* Fix `host.name` exception list and trusted app rule matching to be case-insensitive in Elastic Defend.
* Harden how Elastic Defend restores file ownership and permissions during malware quarantine on Linux and macOS.
* Fix a crash in Elastic Defend on Windows when processing files or processes whose paths contain CJK (Chinese, Japanese, Korean) characters.
* Make the Elastic Defend upgrade more robust on slow machines.
* Elastic Defend diagnostics bundles are no longer readable by unprivileged local users.
