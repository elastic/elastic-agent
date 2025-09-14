---
title: Elastic Agent breaking changes
description: Breaking changes can impact your Elastic applications, potentially disrupting normal operations. Before you upgrade, carefully review the Elastic Agent...
url: https://docs-v3-preview.elastic.dev/release-notes/breaking-changes
products:
  - Elastic Agent
---

# Elastic Agent breaking changes

Breaking changes can impact your Elastic applications, potentially disrupting normal operations. Before you upgrade, carefully review the Elastic Agent breaking changes and take the necessary steps to mitigate any issues. To learn how to upgrade, check [Upgrade](https://docs-v3-preview.elastic.dev/elastic/docs-content/tree/main/deploy-manage/upgrade).

## 9.1.3

_No breaking changes._

## 9.1.2

_No breaking changes._

## 9.1.1

_No breaking changes._

## 9.1.0

_No breaking changes._

## 9.0.6

_No breaking changes._

## 9.0.5

_No breaking changes._

## 9.0.4

_No breaking changes._

## 9.0.3

_No breaking changes._

## 9.0.2

_No breaking changes._

## 9.0.1

<dropdown title="[otel] Disable process scraper of hostmetrics receiver.">
  The process scraper collects metrics for all available processes of a host without an easy way to limit
  this to only report top N process for example. This results in quite big amount of timeseries.
  Since this is not quite critical for any of the available UIs or dashboards we decide to disable
  it temporarily until we find a better solution. Users that specifically need these metrics
  can also enable it back manually.
  Related to https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/39423.For more information, check [#7894](https://github.com/elastic/elastic-agent/pull/7894).
</dropdown>


## 9.0.0

<dropdown title="Removed cloud defend support for Elastic Agent">
  Support for `cloud-defend` (Defend for Containers) has been removed. The package has been removed from the Elastic Agent packaging scripts and template Kubernetes files.For more information, check [#5481](https://github.com/elastic/elastic-agent/pull/5481).
</dropdown>

<dropdown title="Removed username and password default values for Elastic Agent">
  The default values for `username` and `password` have been removed for when Elastic Agent is running in container mode. The Elasticsearch `api_key` can now be set in that mode using the `ELASTICSEARCH_API_KEY` environment variable.For more information, check [#5536](https://github.com/elastic/elastic-agent/pull/5536).
</dropdown>

<dropdown title="Changed Ubuntu-based Docker images for Elastic Agent">
  The default Ubuntu-based Docker images used for Elastic Agent have been changed to UBI-minimal-based images, to reduce the overall footprint of the agent Docker images and to improve compliance with enterprise standards.For more information, check [#6427](https://github.com/elastic/elastic-agent/pull/6427).
</dropdown>

<dropdown title="Removed --path.install flag declaration from Elastic Agent paths command">
  The deprecated `--path.install` flag declaration has been removed from the Elastic Agent `paths` command and its use removed from the `container` and `enroll` commands.For more information, check [#6461](https://github.com/elastic/elastic-agent/pull/6461) and [#2489](https://github.com/elastic/elastic-agent/pull/2489).
</dropdown>

<dropdown title="Changed the default Elastic Agent installation and upgrade">
  The default Elastic Agent installation and ugprade have been changed to include only the `agentbeat`, `endpoint-security` and `pf-host-agent` components.Additional components such as `apm` or `fleet` require passing the `--install-servers` flag or setting the `ELASTIC_AGENT_FLAVOR=servers` environment variable.For more information, check [#6542](https://github.com/elastic/elastic-agent/pull/6542).
</dropdown>
