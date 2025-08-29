## 9.0.2 [elastic-agent-release-notes-9.0.2]




### Fixes [elastic-agent-9.0.2-fixes]

* Upgrade Go version to 1.24.3. [#8109](https://github.com/elastic/elastic-agent/pull/8109) 
* Preserve agent run state on DEB and RPM upgrades. [#7999](https://github.com/elastic/elastic-agent/pull/7999) [#3832](https://github.com/elastic/elastic-agent/issues/3832)

  Improves the upgrade process for Elastic Agent installed using DEB or RPM packages by copying the run directory from the previous installation into the new version&#39;s folder
  

