## 9.0.1 [elastic-agent-9.0.1-breaking-changes]

::::{dropdown} [otel] Disable process scraper of hostmetrics receiver.
The process scraper collects metrics for all available processes of a host without an easy way to limit
this to only report top N process for example. This results in quite big amount of timeseries.
Since this is not quite critical for any of the available UIs or dashboards we decide to disable
it temporarily until we find a better solution. Users that specifically need these metrics
can also enable it back manually.
Related to https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/39423.


For more information, check [#7894](https://github.com/elastic/elastic-agent/pull/7894).

% **Impact**<br>_Add a description of the impact_

% **Action**<br>_Add a description of the what action to take_
::::
