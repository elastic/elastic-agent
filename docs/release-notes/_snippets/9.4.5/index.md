## 9.4.5 [elastic-agent-release-notes-9.4.5]



### Features and enhancements [elastic-agent-9.4.5-features-enhancements]


* Add environment variables to collector diagnostics. [#15659](https://github.com/elastic/elastic-agent/pull/15659) 
* Update OTel Collector components to v0.156.0. [#15813](https://github.com/elastic/elastic-agent/pull/15813) 


### Fixes [elastic-agent-9.4.5-fixes]


* Fix orphaned filelog receiver in edot collector helm charts. [#15731](https://github.com/elastic/elastic-agent/pull/15731) 

* Sensitive values in JSON diagnostic files are now redacted. [#15902](https://github.com/elastic/elastic-agent/pull/15902) 

  When collecting diagnostics, files with a JSON content type were not having
  sensitive values (such as passwords and private keys) redacted before being
  included in the diagnostic bundle. Only YAML files were redacted. JSON files
  are now redacted in the same way as YAML files.
  
* Stop upgrade rollback from being triggered by slow service component restarts. [#15863](https://github.com/elastic/elastic-agent/pull/15863) 

  Elastic Defend restarting slowly after an upgrade could be mistaken for a
  broken Agent build and trigger an unnecessary rollback. Agent now gives
  service-managed components more time to check in before treating them as
  failed, while keeping a safe margin below the upgrade watcher&#39;s grace
  period so a truly failed component is still caught.
  
* Fix getting current user failing on Windows when no profile directory is present. [#16006](https://github.com/elastic/elastic-agent/pull/16006) 
* Fix continuous container restarts after Fleet policy updates. [#15843](https://github.com/elastic/elastic-agent/pull/15843) 

  In containers, Elastic Agent could restart indefinitely after a Fleet policy
  changed the log level. Settings missing from the policy were reset to
  defaults instead of keeping the startup values, causing the same mismatch
  after each restart. Elastic Agent now uses startup logging as the baseline
  and changes only settings included in the Fleet policy.
  
* Add Synthetics browser binaries to the elastic-agent-complete image. [#16016](https://github.com/elastic/elastic-agent/pull/16016) [#15993](https://github.com/elastic/elastic-agent/issues/15993)

  npm 12 no longer runs a dependency&#39;s `install` lifecycle script during `npm i` by
  default, so the transitive playwright-chromium `install` hook that used to download
  the Playwright browsers into the elastic-agent-complete image during build stopped
  running. As a result the 9.5.0 complete image shipped with no browsers and all
  Synthetics browser monitors on Fleet-managed Private Locations failed with
  &#34;browserType.launch: Executable doesn&#39;t exist at .../chromium_headless_shell-&lt;rev&gt;/...&#34;.
  The image build now installs the browsers explicitly with the bundled Playwright CLI
  after `npm i`, independent of npm&#39;s install-script policy.
  

