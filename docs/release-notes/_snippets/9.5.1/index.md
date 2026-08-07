## 9.5.1 [elastic-agent-release-notes-9.5.1]



### Features and enhancements [elastic-agent-9.5.1-features-enhancements]


* Rename EDOT Collector to Elastic Agent and EDOT Cloud Forwarder to Elastic Cloud Forwarder. [#15924](https://github.com/elastic/elastic-agent/pull/15924) [#15989](https://github.com/elastic/elastic-agent/pull/15989) [#16012](https://github.com/elastic/elastic-agent/pull/16012) [#16033](https://github.com/elastic/elastic-agent/pull/16033) [#16032](https://github.com/elastic/elastic-agent/pull/16032) [#15976](https://github.com/elastic/elastic-agent/pull/15976) [#16053](https://github.com/elastic/elastic-agent/pull/16053) [#16061](https://github.com/elastic/elastic-agent/pull/16061) [#16069](https://github.com/elastic/elastic-agent/pull/16069) [#16072](https://github.com/elastic/elastic-agent/pull/16072) [#16080](https://github.com/elastic/elastic-agent/pull/16080) [#16081](https://github.com/elastic/elastic-agent/pull/16081) [#15964](https://github.com/elastic/elastic-agent/issues/15964)

  The EDOT Collector is now built into Elastic Agent as its OpenTelemetry mode. Deploy
  Elastic Agent and run it in OpenTelemetry mode to collect and forward traces, metrics,
  and logs to Elastic Observability. Configuration and components are unchanged.
  
  The EDOT Cloud Forwarder has been renamed to the Elastic Cloud Forwarder.
  


### Fixes [elastic-agent-9.5.1-fixes]


* Sensitive values in JSON diagnostic files are now redacted. [#15924](https://github.com/elastic/elastic-agent/pull/15924) [#15989](https://github.com/elastic/elastic-agent/pull/15989) [#16012](https://github.com/elastic/elastic-agent/pull/16012) [#16033](https://github.com/elastic/elastic-agent/pull/16033) [#16032](https://github.com/elastic/elastic-agent/pull/16032) [#15976](https://github.com/elastic/elastic-agent/pull/15976) [#16053](https://github.com/elastic/elastic-agent/pull/16053) [#16061](https://github.com/elastic/elastic-agent/pull/16061) [#16069](https://github.com/elastic/elastic-agent/pull/16069) [#16072](https://github.com/elastic/elastic-agent/pull/16072) [#16080](https://github.com/elastic/elastic-agent/pull/16080) [#16081](https://github.com/elastic/elastic-agent/pull/16081) [#15964](https://github.com/elastic/elastic-agent/issues/15964)

  When collecting diagnostics, files with a JSON content type were not having
  sensitive values (such as passwords and private keys) redacted before being
  included in the diagnostic bundle. Only YAML files were redacted. JSON files
  are now redacted in the same way as YAML files.
  
* Fix OTel heartbeat runtime breaking Synthetics browser monitors on Private Locations. [#15924](https://github.com/elastic/elastic-agent/pull/15924) [#15989](https://github.com/elastic/elastic-agent/pull/15989) [#16012](https://github.com/elastic/elastic-agent/pull/16012) [#16033](https://github.com/elastic/elastic-agent/pull/16033) [#16032](https://github.com/elastic/elastic-agent/pull/16032) [#15976](https://github.com/elastic/elastic-agent/pull/15976) [#16053](https://github.com/elastic/elastic-agent/pull/16053) [#16061](https://github.com/elastic/elastic-agent/pull/16061) [#16069](https://github.com/elastic/elastic-agent/pull/16069) [#16072](https://github.com/elastic/elastic-agent/pull/16072) [#16080](https://github.com/elastic/elastic-agent/pull/16080) [#16081](https://github.com/elastic/elastic-agent/pull/16081) [#15968](https://github.com/elastic/elastic-agent/issues/15968)

  When heartbeat runs via the OTel heartbeatreceiver, a Synthetics browser monitor
  compiles into a single synthetics/browser input with three streams: the scheduled
  &#34;browser&#34; monitor stream plus schedule-less &#34;browser.network&#34; and &#34;browser.screenshot&#34;
  auxiliary streams used only for data-stream routing. The beat-receiver translation
  emitted one monitor per stream, so the schedule-less auxiliary streams were rejected
  (&#34;missing required field accessing &#39;heartbeat.monitors.0.schedule&#39;&#34;) and the whole
  browser component failed to start. The auxiliary streams are now dropped during
  translation, matching classic process-runtime heartbeat behavior.
  
* Bake Synthetics browser binaries into the elastic-agent-complete image. [#15924](https://github.com/elastic/elastic-agent/pull/15924) [#15989](https://github.com/elastic/elastic-agent/pull/15989) [#16012](https://github.com/elastic/elastic-agent/pull/16012) [#16033](https://github.com/elastic/elastic-agent/pull/16033) [#16032](https://github.com/elastic/elastic-agent/pull/16032) [#15976](https://github.com/elastic/elastic-agent/pull/15976) [#16053](https://github.com/elastic/elastic-agent/pull/16053) [#16061](https://github.com/elastic/elastic-agent/pull/16061) [#16069](https://github.com/elastic/elastic-agent/pull/16069) [#16072](https://github.com/elastic/elastic-agent/pull/16072) [#16080](https://github.com/elastic/elastic-agent/pull/16080) [#16081](https://github.com/elastic/elastic-agent/pull/16081) [#15993](https://github.com/elastic/elastic-agent/issues/15993)

  npm 12 no longer runs a dependency&#39;s `install` lifecycle script during `npm i` by
  default, so the transitive playwright-chromium `install` hook that used to download
  the Playwright browsers into the elastic-agent-complete image during build stopped
  running. As a result the 9.5.0 complete image shipped with no browsers and all
  Synthetics browser monitors on Fleet-managed Private Locations failed with
  &#34;browserType.launch: Executable doesn&#39;t exist at .../chromium_headless_shell-&lt;rev&gt;/...&#34;.
  The image build now installs the browsers explicitly with the bundled Playwright CLI
  after `npm i`, independent of npm&#39;s install-script policy.
  

* Fix ordering of streams for osquerybeat receiver. [#15924](https://github.com/elastic/elastic-agent/pull/15924) [#15989](https://github.com/elastic/elastic-agent/pull/15989) [#16012](https://github.com/elastic/elastic-agent/pull/16012) [#16033](https://github.com/elastic/elastic-agent/pull/16033) [#16032](https://github.com/elastic/elastic-agent/pull/16032) [#15976](https://github.com/elastic/elastic-agent/pull/15976) [#16053](https://github.com/elastic/elastic-agent/pull/16053) [#16061](https://github.com/elastic/elastic-agent/pull/16061) [#16069](https://github.com/elastic/elastic-agent/pull/16069) [#16072](https://github.com/elastic/elastic-agent/pull/16072) [#16080](https://github.com/elastic/elastic-agent/pull/16080) [#16081](https://github.com/elastic/elastic-agent/pull/16081) [#15964](https://github.com/elastic/elastic-agent/issues/15964)

