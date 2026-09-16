## 9.5.4+build202609161310 [elastic-agent-release-notes-9.5.4+build202609161310]

:::{note}
This is an independent Elastic Agent release. Independent Elastic Agent releases deliver critical fixes and updates for Elastic Agent and Elastic Defend independently of a full Elastic Stack release. Read more in [Elastic Agent release process](docs-content://reference/fleet/fleet-agent-release-process.md).
:::


### Fixes [elastic-agent-9.5.4+build202609161310-fixes]

* Adds experimental macOS 27 (Golden Gate) support in {elastic-defend}.
* Fixes a macOS 27 (Golden Gate) network filter kernel bug in {elastic-defend}.
* Fixes an issue that prevented macOS OS updates when a Device Control policy was active.
* Upgrades c-ares to 1.34.8 to fix CVE-2024-25629 in {elastic-defend}.
* Fixes `host.name` exception matching to be case-insensitive in {elastic-defend}.
* Fixes a POSIX quarantine `chown`/`chmod` symlink race condition in {elastic-defend}.
* Fixes uncaught file system exceptions on Windows that could cause process terminations in {elastic-defend}.
* Fixes a network cache scan inefficiency that caused CPU and lock contention on Linux in {elastic-defend}.
